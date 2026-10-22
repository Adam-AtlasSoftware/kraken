//! AI activity and asking before spending.
//!
//! Every button that starts AI work (a rewrite run, Suggest names, an explanation, Automate)
//! goes through [`ViewModel::ai_gate`]: it refuses when today's budget is used up, and otherwise
//! shows an estimate (most model calls, the model, the cost range or "billed by your
//! subscription") and waits for the person's answer unless the run stays under the threshold
//! they set. The window draws the question from [`AiState::confirm`].
//!
//! While AI work runs, [`ViewModel::ai_chip`] says what, on which model, and what it has used so
//! far; the AI Activity tab lists the work ([`ViewModel::ai_rows`]) with a Stop button each.
//! The daemon's work (rewrite jobs started from here, the command line or by agents) comes from
//! `ai_jobs` and the `ai_*` events; the assistant's own runs in this window are metered here.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_assist::{
    AiPolicy, AssistBackend, AutomateGoal, Meter, MeterSpec, ModelChoice, RewriteModel,
    SelectionKind, rewrite_choice, rewrite_max_calls,
};
use kraken_model::{DailyLedger, ProjectLedger};
use kraken_proto::{
    AiEstimate, AiFeature, AiJobStatus, AiJobView, AiOrigin, AiProviderKind, AiUsageTotals, money,
};
use serde_json::{Value, json};

use crate::rewrite::{RewriteMode, WizardScope};
use crate::state::{Connection, ToastLevel};
use crate::vm::ViewModel;

/// How often the AI work list is asked for while something runs.
const POLL_RUNNING: Duration = Duration::from_millis(1500);
/// Finished work of this window kept in the list.
const LOCAL_KEPT: usize = 20;

/// Something that starts AI work, waiting for the person's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum AiAction {
    /// Rewrite one function.
    RewriteFunction {
        /// The function.
        address: u64,
        /// How.
        mode: RewriteMode,
    },
    /// Run a function again.
    RetryFunction(u64),
    /// Rewrite the function in the decompiler.
    RewriteCurrent,
    /// Translate every planned function.
    TranslatePlanned(RewriteMode),
    /// Retry every failed function.
    RetryFailed,
    /// Rewrite the whole program.
    RewriteProgram,
    /// The wizard's Start button.
    WizardStart,
    /// Write a spec (of a function, or of the program for `None`).
    WriteSpec(Option<u64>),
    /// Explain a function.
    ExplainFunction(u64),
    /// Explain a selection.
    ExplainSelection {
        /// What it is.
        kind: SelectionKind,
        /// The selected text.
        text: String,
        /// Where.
        address: Option<u64>,
    },
    /// The program overview.
    Overview,
    /// Suggest names for up to this many functions.
    AutoName(usize),
    /// Automate towards a goal.
    Automate(AutomateGoal),
    /// Plan a byte patch from the edited code of the function at this address.
    PatchFromSource(u64),
}

impl AiAction {
    /// What the question's title says.
    pub fn title(&self) -> &'static str {
        match self {
            AiAction::RewriteFunction { .. }
            | AiAction::RetryFunction(_)
            | AiAction::RewriteCurrent => "Rewrite this function in Rust?",
            AiAction::TranslatePlanned(_) => "Translate every planned function?",
            AiAction::RetryFailed => "Retry every failed function?",
            AiAction::RewriteProgram => "Rewrite the whole program?",
            AiAction::WizardStart => "Start the rewrite?",
            AiAction::WriteSpec(_) => "Write a spec?",
            AiAction::ExplainFunction(_) | AiAction::ExplainSelection { .. } => {
                "Ask the assistant to explain?"
            }
            AiAction::Overview => "Ask the assistant for an overview?",
            AiAction::AutoName(_) => "Suggest names?",
            AiAction::Automate(_) => "Start Automate?",
            AiAction::PatchFromSource(_) => "Plan a patch from your edit?",
        }
    }
}

/// The question shown before AI work starts.
#[derive(Debug, Clone, PartialEq)]
pub struct AiConfirm {
    /// What would start.
    pub action: AiAction,
    /// The estimate.
    pub estimate: AiEstimate,
    /// Extra lines (the daily budget left, what the work also starts).
    pub notes: Vec<String>,
    /// Skip the question from now on for runs below this many dollars (the person's choice in
    /// the dialog, saved by the window).
    pub skip_under: Option<f64>,
}

/// The model the next rewrite runs use instead of the configured one (the wizard's Check step);
/// kept for this window only, never saved unless the person saves it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunOverride {
    /// Which configured model.
    pub which: RewriteModel,
    /// A model name to use instead, empty for the configured one.
    pub model: String,
}

/// What the top-bar chip says while AI work runs.
#[derive(Debug, Clone, PartialEq)]
pub struct AiChip {
    /// Pieces of work running.
    pub running: usize,
    /// "Rust rewrite" (the newest running work).
    pub feature: String,
    /// The model of that work.
    pub model: String,
    /// Calls so far, all running work together.
    pub calls: u64,
    /// "about $0.12 (estimate)" or "billed by the agent's subscription".
    pub cost: String,
}

impl AiChip {
    /// "AI: Rust rewrite, claude-sonnet-5-5, 12 calls, about $0.31".
    pub fn text(&self) -> String {
        let more = if self.running > 1 {
            format!(" (+{} more)", self.running - 1)
        } else {
            String::new()
        };
        let cost = self.cost.replace(" (estimate)", "");
        format!(
            "AI: {}{more}, {}, {} call{}, {cost}",
            self.feature,
            if self.model.is_empty() {
                "model not reported"
            } else {
                &self.model
            },
            self.calls,
            if self.calls == 1 { "" } else { "s" }
        )
    }
}

/// All AI state of the window.
#[derive(Default)]
pub struct AiState {
    /// Models, prices and limits, from `config.toml` (the window loads them).
    pub policy: AiPolicy,
    /// The config file, for the rewrite model of a per-run override.
    pub config_path: Option<PathBuf>,
    /// The daily totals (the window sets it; tests leave it off).
    pub daily: Option<DailyLedger>,
    /// The daemon's AI work.
    pub jobs: Vec<AiJobView>,
    /// The assistant's runs in this window.
    pub local: Vec<AiJobView>,
    /// The question waiting for an answer.
    pub confirm: Option<AiConfirm>,
    /// The wizard's model for this run.
    pub run_override: Option<RunOverride>,
    /// The AI Activity tab should come to the front.
    pub show_requested: bool,
    pub(crate) bypass: bool,
    pub(crate) next_local: u64,
    pub(crate) last_poll: Option<Instant>,
    pub(crate) inflight: bool,
    /// Something AI may have started: poll soon.
    pub(crate) wake: bool,
    /// The daemon answered `ai_jobs` with an error (an old daemon): stop asking.
    pub(crate) unsupported: bool,
    pub(crate) toasted: HashSet<String>,
}

impl AiState {
    /// Work running now, daemon and window together.
    pub fn running(&self) -> impl Iterator<Item = &AiJobView> {
        self.jobs
            .iter()
            .chain(self.local.iter())
            .filter(|j| !j.status.is_terminal())
    }

    /// True while any AI work runs.
    pub fn busy(&self) -> bool {
        self.running().next().is_some()
    }

    /// Today's estimated spending, all projects.
    pub fn today(&self) -> AiUsageTotals {
        self.daily.as_ref().map(|d| d.today()).unwrap_or_default()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Words for a finished piece of work, for its toast.
pub fn finished_text(j: &AiJobView) -> String {
    let what = if j.label.is_empty() {
        j.feature.label().to_string()
    } else {
        j.label.clone()
    };
    let how = match j.status {
        AiJobStatus::Succeeded => "finished",
        AiJobStatus::Failed => "failed",
        AiJobStatus::Cancelled => "was stopped",
        AiJobStatus::Limited => "stopped at its limit",
        AiJobStatus::Running => "is running",
    };
    format!("{what} {how}: {}.", j.usage.line())
}

impl ViewModel {
    /// Reads the models, prices and limits from the config file at `config_path`, and adds
    /// usage to the daily totals of `daily` (none for screenshots and tests).
    pub fn ai_configure(&mut self, config_path: Option<PathBuf>, daily: Option<DailyLedger>) {
        self.ai.policy = AiPolicy::load(config_path.as_deref());
        self.ai.config_path = config_path;
        self.ai.daily = daily;
    }

    /// Reads the config file again (it may have changed in Settings or by hand).
    pub fn ai_reload(&mut self) {
        if self.ai.config_path.is_some() {
            self.ai.policy = AiPolicy::load(self.ai.config_path.as_deref());
        }
    }

    // ---------------------------------------------------------------- asking first

    /// The rewrite model of the next run: the per-run override, else the configured one.
    pub fn ai_rewrite_choice(&self) -> Option<ModelChoice> {
        match &self.ai.run_override {
            Some(o) => {
                let model = (!o.model.trim().is_empty()).then_some(o.model.as_str());
                rewrite_choice(self.ai.config_path.as_deref(), o.which, model)
                    .ok()
                    .or_else(|| self.ai.policy.rewrite.clone())
            }
            None => self.ai.policy.rewrite.clone(),
        }
    }

    /// The `provider` and `model` arguments of a rewrite job when this run overrides the model.
    pub(crate) fn ai_rewrite_args(&self, args: &mut Value) {
        if let Some(o) = &self.ai.run_override {
            if o.which == RewriteModel::Assistant {
                args["provider"] = json!("assistant");
            }
            if !o.model.trim().is_empty() {
                args["model"] = json!(o.model.trim());
            }
        }
    }

    /// The feature and the fewest and most model calls of `a`.
    fn ai_calls(&self, a: &AiAction) -> (AiFeature, u64, u64) {
        let attempts = kraken_assist::REWRITE_ATTEMPTS;
        let rewrite = |n: u64, spec: bool, rounds: u32| {
            (
                AiFeature::Rewrite,
                n.min(1),
                rewrite_max_calls(n, attempts, spec, rounds),
            )
        };
        let spec_of = |m: &RewriteMode| *m == RewriteMode::Spec;
        match a {
            AiAction::RewriteFunction { mode, .. } => rewrite(1, spec_of(mode), 0),
            AiAction::RetryFunction(_) | AiAction::RewriteCurrent => rewrite(1, false, 0),
            AiAction::TranslatePlanned(mode) => {
                let n = self.rewrite_planned_count() as u64;
                let (f, _, max) = rewrite(n, spec_of(mode), 0);
                (f, n, max)
            }
            AiAction::RetryFailed => {
                let n = self.rewrite_failed_count() as u64;
                let (f, _, max) = rewrite(n, false, 0);
                (f, n, max)
            }
            AiAction::RewriteProgram => {
                let n = self.rewrite_program_functions();
                let (f, _, max) = rewrite(n, false, self.rewrite.program.repair_rounds);
                (f, n, max)
            }
            AiAction::WizardStart => {
                let (functions, calls) = self.rewrite_wizard_estimate();
                (AiFeature::Rewrite, u64::from(functions), u64::from(calls))
            }
            AiAction::WriteSpec(_) => (AiFeature::Rewrite, 1, 1),
            AiAction::ExplainFunction(_) => (AiFeature::Assistant, 1, 8),
            AiAction::ExplainSelection { .. } => (AiFeature::Assistant, 1, 6),
            AiAction::Overview => (AiFeature::Assistant, 2, 14),
            AiAction::AutoName(limit) => {
                (AiFeature::AutoName, 2, (10 + *limit as u64 * 3).min(100))
            }
            AiAction::PatchFromSource(_) => (
                AiFeature::Patch,
                2,
                2 * u64::from(kraken_registry::commands::DEFAULT_SOURCE_PATCH_ATTEMPTS),
            ),
            AiAction::Automate(goal) => (
                AiFeature::Automate,
                5,
                match goal {
                    AutomateGoal::Understand => 60,
                    AutomateGoal::Rewrite => 50,
                    AutomateGoal::Both => 90,
                },
            ),
        }
    }

    /// Functions a whole-program rewrite works on: the plan, or the program's functions.
    pub(crate) fn rewrite_program_functions(&self) -> u64 {
        let planned = self
            .rewrite
            .plan_summary
            .as_ref()
            .map_or(0, |p| p.functions_planned);
        (self.rewrite.rows.len() as u64).max(planned).max(1)
    }

    /// The estimate of `a` on the model it would use; `None` when no model is set up.
    pub fn ai_estimate(&self, a: &AiAction) -> Option<AiEstimate> {
        let (feature, min, max) = self.ai_calls(a);
        let choice = match feature {
            AiFeature::Rewrite => self.ai_rewrite_choice(),
            _ => self.ai.policy.assistant.clone(),
        }?;
        Some(
            self.ai
                .policy
                .estimate_with(feature, &choice, min.min(max), max),
        )
    }

    /// True when `a` may start now. Otherwise the reason is shown (the daily budget) or the
    /// question waits in [`AiState::confirm`], and the action runs once it is answered yes.
    pub(crate) fn ai_gate(&mut self, a: AiAction) -> bool {
        if self.ai.bypass {
            return true;
        }
        self.ai_reload();
        let today = self.ai.today();
        if let Some(msg) = self.ai.policy.daily_refusal(today.cost_usd) {
            self.toast(ToastLevel::Warning, msg);
            return false;
        }
        let Some(estimate) = self.ai_estimate(&a) else {
            // No model is set up: the action explains that itself.
            return true;
        };
        if !self.ai.policy.needs_confirm(&estimate) {
            return true;
        }
        let mut notes = Vec::new();
        if let Some(b) = self.ai.policy.limits.daily_budget {
            notes.push(format!(
                "Today's budget: {} of {} used (estimate).",
                money(today.cost_usd),
                money(b)
            ));
        }
        if let Some(n) = self.ai.policy.limits.max_calls_per_run {
            notes.push(format!("The run stops by itself after {n} model calls."));
        }
        if let Some(c) = self.ai.policy.limits.max_cost_per_run {
            notes.push(format!(
                "The run stops by itself once it reaches about {}.",
                money(c)
            ));
        }
        match &a {
            AiAction::Automate(g) if g.rewrites() => notes.push(
                "Automate can also start rewrite jobs; each asks again before it runs the program."
                    .into(),
            ),
            AiAction::RewriteProgram | AiAction::WizardStart
                if self.rewrite.wizard.scope == WizardScope::Program
                    || a == AiAction::RewriteProgram =>
            {
                notes.push(
                    "Repairing a failed program asks the model again; that is counted above."
                        .into(),
                );
            }
            _ => {}
        }
        if estimate.provider_kind == AiProviderKind::Api {
            notes.push(
                "Money is an estimate from list prices; your provider's bill is what counts."
                    .into(),
            );
        }
        self.ai.confirm = Some(AiConfirm {
            action: a,
            estimate,
            notes,
            skip_under: None,
        });
        false
    }

    /// The person said yes: runs the waiting action.
    pub fn ai_confirm_yes(&mut self) {
        let Some(c) = self.ai.confirm.take() else {
            return;
        };
        self.ai.bypass = true;
        self.ai_perform(c.action);
        self.ai.bypass = false;
        self.ai.wake = true;
    }

    /// The person said no: nothing starts.
    pub fn ai_confirm_no(&mut self) {
        self.ai.confirm = None;
    }

    fn ai_perform(&mut self, a: AiAction) {
        match a {
            AiAction::RewriteFunction { address, mode } => self.rewrite_run(address, mode),
            AiAction::RetryFunction(address) => self.rewrite_retry(address),
            AiAction::RewriteCurrent => {
                self.rewrite_run_current();
            }
            AiAction::TranslatePlanned(mode) => self.rewrite_bulk_translate_planned(mode),
            AiAction::RetryFailed => self.rewrite_bulk_retry_failed(),
            AiAction::RewriteProgram => self.rewrite_program_run(),
            AiAction::WizardStart => self.rewrite_wizard_start(),
            AiAction::WriteSpec(a) => self.rewrite_write_spec(a),
            AiAction::ExplainFunction(a) => self.assist_explain_function(a),
            AiAction::ExplainSelection {
                kind,
                text,
                address,
            } => self.assist_explain_selection(kind, &text, address),
            AiAction::Overview => self.assist_overview(),
            AiAction::AutoName(limit) => self.assist_auto_name(limit),
            AiAction::Automate(goal) => self.assist_automate(goal),
            AiAction::PatchFromSource(_) => self.plan_source_edit_now(),
        }
    }

    // ---------------------------------------------------------------- the window's own work

    /// `engine` metered for an assistant run of `feature`, put on the activity list as work
    /// started by the person in this window.
    pub(crate) fn ai_meter_local(
        &mut self,
        feature: AiFeature,
        label: &str,
        seq: u64,
        engine: Arc<dyn AssistBackend>,
    ) -> Arc<dyn AssistBackend> {
        self.ai.next_local += 1;
        let id = format!("window-{}", self.ai.next_local);
        let info = engine.provider_info();
        let kind = match engine.info().kind {
            kraken_assist::BackendKind::TerminalAgent => AiProviderKind::TerminalAgent,
            kraken_assist::BackendKind::Api => self
                .ai
                .policy
                .assistant
                .as_ref()
                .map_or(AiProviderKind::Api, |c| c.kind),
        };
        self.ai.local.push(AiJobView {
            id: id.clone(),
            job_id: Some(format!("assist:{seq}")),
            feature,
            label: label.to_string(),
            provider_kind: kind,
            provider: info.id.clone(),
            model: info.model.clone(),
            origin: AiOrigin::Gui,
            started_by: "you".into(),
            status: AiJobStatus::Running,
            started_ms: now_ms(),
            ended_ms: None,
            usage: AiUsageTotals::default(),
            message: None,
        });
        while self.ai.local.len() > LOCAL_KEPT {
            match self.ai.local.iter().position(|j| j.status.is_terminal()) {
                Some(i) => self.ai.local.remove(i),
                None => break,
            };
        }
        let mut b = Meter::builder(MeterSpec::new(feature, AiOrigin::Gui).run(&id))
            .pricing(self.ai.policy.pricing.clone())
            .limits(self.ai.policy.limits.clone())
            .daily(self.ai.daily.clone())
            .kind(kind);
        if let Some(p) = &self.project {
            b = b.sink(Arc::new(ProjectLedger::new(
                std::path::Path::new(&p.project_dir).join(kraken_registry::session::DB_FILE),
            )));
        }
        let poster = self.poster();
        let id2 = id.clone();
        b = b.observer(Arc::new(move |rec, totals| {
            let (id, totals, model) = (id2.clone(), *totals, rec.model.clone());
            poster.post(move |vm| {
                if let Some(j) = vm.ai.local.iter_mut().find(|j| j.id == id) {
                    j.usage = totals;
                    if !model.is_empty() {
                        j.model = model;
                    }
                }
            });
        }));
        b.build().wrap(engine)
    }

    /// Ends the window's work of assistant run `seq`.
    pub(crate) fn ai_local_finished(
        &mut self,
        seq: u64,
        status: AiJobStatus,
        message: Option<String>,
    ) {
        let key = format!("assist:{seq}");
        if let Some(j) = self
            .ai
            .local
            .iter_mut()
            .find(|j| j.job_id.as_deref() == Some(key.as_str()) && !j.status.is_terminal())
        {
            j.status = status;
            j.ended_ms = Some(now_ms());
            j.message = message;
        }
    }

    // ---------------------------------------------------------------- the daemon's work

    /// A daemon `ai_*` event.
    pub(crate) fn ai_on_event(&mut self, view: AiJobView) {
        match self.ai.jobs.iter_mut().find(|j| j.id == view.id) {
            Some(j) => *j = view,
            None => self.ai.jobs.insert(0, view),
        }
        self.ai_announce();
    }

    /// Asks for the AI work list now.
    pub fn ai_refresh(&mut self) {
        if self.ai.inflight || self.ai.unsupported || self.connection != Connection::Open {
            return;
        }
        self.ai.inflight = true;
        self.ai.last_poll = Some(Instant::now());
        self.call("ai_jobs", json!({}), |vm, res| {
            vm.ai.inflight = false;
            match res {
                Ok(v) => {
                    if let Some(jobs) = v
                        .get("jobs")
                        .cloned()
                        .and_then(|j| serde_json::from_value::<Vec<AiJobView>>(j).ok())
                    {
                        vm.ai.jobs = jobs;
                        vm.ai_announce();
                    }
                }
                // A daemon from before `ai_jobs` (or a backend without it): stop asking.
                Err(e)
                    if matches!(
                        e.code,
                        kraken_proto::ErrorCode::NotFound | kraken_proto::ErrorCode::Unsupported
                    ) =>
                {
                    vm.ai.unsupported = true;
                }
                Err(_) => {}
            }
        });
    }

    /// Keeps the list fresh: often while work runs, now and then otherwise (an agent may start
    /// work). Called from [`poll`](ViewModel::poll).
    pub(crate) fn ai_tick(&mut self) {
        // The window's runs end with the assistant run.
        let live = self.assist.run.as_ref().map(|r| (r.seq, r.stopping));
        let ended: Vec<u64> = self
            .ai
            .local
            .iter()
            .filter(|j| !j.status.is_terminal())
            .filter_map(|j| {
                j.job_id
                    .as_deref()
                    .and_then(|k| k.strip_prefix("assist:"))
                    .and_then(|n| n.parse::<u64>().ok())
            })
            .filter(|seq| live.is_none_or(|(s, _)| s != *seq))
            .collect();
        for seq in ended {
            self.ai_local_finished(seq, AiJobStatus::Succeeded, None);
        }
        self.ai_announce();
        if self.connection != Connection::Open || self.ai.unsupported || self.ai.inflight {
            return;
        }
        // Work started elsewhere arrives as daemon events (or rewrite job events in this
        // process), which wake this; while work runs the list is refreshed for its usage.
        let running = self.ai.jobs.iter().any(|j| !j.status.is_terminal()) || self.rewrite.busy();
        let due = running
            && self
                .ai
                .last_poll
                .is_none_or(|t| t.elapsed() >= POLL_RUNNING);
        if std::mem::take(&mut self.ai.wake) || due {
            self.ai_refresh();
        }
    }

    /// Toasts each piece of work once when it ends.
    fn ai_announce(&mut self) {
        let done: Vec<AiJobView> = self
            .ai
            .jobs
            .iter()
            .chain(self.ai.local.iter())
            .filter(|j| j.status.is_terminal() && !self.ai.toasted.contains(&j.id))
            .cloned()
            .collect();
        for j in done {
            self.ai.toasted.insert(j.id.clone());
            // Work that ended before this window looked is history, not news.
            let fresh = j
                .ended_ms
                .is_some_and(|t| now_ms().saturating_sub(t) < 60_000);
            if !fresh || j.usage.calls == 0 {
                continue;
            }
            let level = match j.status {
                AiJobStatus::Succeeded => ToastLevel::Info,
                AiJobStatus::Limited | AiJobStatus::Failed => ToastLevel::Warning,
                _ => ToastLevel::Info,
            };
            let mut text = finished_text(&j);
            if j.status == AiJobStatus::Limited
                && let Some(m) = &j.message
            {
                text.push(' ');
                text.push_str(m);
            }
            self.toast_with(level, text, Some(crate::state::ToastAction::OpenAiActivity));
        }
    }

    /// What the top-bar chip says, while any AI work runs.
    pub fn ai_chip(&self) -> Option<AiChip> {
        let running: Vec<&AiJobView> = self.ai.running().collect();
        let newest = running.iter().max_by_key(|j| j.started_ms)?;
        let mut usage = AiUsageTotals::default();
        for j in &running {
            usage.merge(&j.usage);
        }
        Some(AiChip {
            running: running.len(),
            feature: newest.feature.label().to_string(),
            model: newest.model_label(),
            calls: usage.calls,
            cost: usage.cost_text(),
        })
    }

    /// Rows of the AI Activity tab: running work first, then the latest finished work.
    pub fn ai_rows(&self) -> Vec<AiJobView> {
        let mut rows: Vec<AiJobView> = self
            .ai
            .jobs
            .iter()
            .chain(self.ai.local.iter())
            .cloned()
            .collect();
        rows.sort_by_key(|j| (j.status.is_terminal(), -j.started_ms));
        rows
    }

    /// The AI work behind daemon job `job_id`, if any.
    pub fn ai_for_job(&self, job_id: &str) -> Option<&AiJobView> {
        self.ai
            .jobs
            .iter()
            .find(|j| j.job_id.as_deref() == Some(job_id))
    }

    /// Stops one piece of work: a daemon job through `job_cancel`, the window's own run
    /// through the assistant's Stop.
    pub fn ai_stop(&mut self, id: &str) {
        let Some(j) = self.ai_rows().into_iter().find(|j| j.id == id) else {
            return;
        };
        if j.status.is_terminal() {
            return;
        }
        match j.job_id.as_deref() {
            Some(k) if k.starts_with("assist:") => self.assist_stop(),
            Some(job) => {
                let job = job.to_string();
                self.call("job_cancel", json!({ "job_id": job }), |vm, res| {
                    if let Err(e) = res {
                        vm.toast_error(&e);
                    }
                    vm.ai.wake = true;
                });
                // A bulk rewrite would start the next function: stop it too.
                if self.rewrite.bulk.active() {
                    self.rewrite.bulk.queue.clear();
                }
            }
            None => {}
        }
    }

    /// Stops every piece of AI work that runs (closing the project or quitting).
    pub fn ai_stop_all(&mut self) {
        let ids: Vec<String> = self.ai.running().map(|j| j.id.clone()).collect();
        for id in ids {
            self.ai_stop(&id);
        }
        // Work the daemon has not reported yet: the rewrite jobs this window started.
        let jobs: Vec<String> = self
            .rewrite
            .jobs
            .iter()
            .filter(|j| j.running() && j.kind != crate::rewrite::JobKind::Export)
            .filter_map(|j| j.job_id.clone())
            .collect();
        for job in jobs {
            self.call("job_cancel", json!({ "job_id": job }), |_, _| {});
        }
        self.rewrite.bulk.queue.clear();
    }

    /// True while AI work runs that closing the project would stop (or leave running).
    pub fn ai_work_running(&self) -> bool {
        self.ai.busy()
            || self.assist.run.is_some()
            || self.rewrite.jobs.iter().any(|j| {
                j.running()
                    && matches!(
                        j.kind,
                        crate::rewrite::JobKind::Function { .. }
                            | crate::rewrite::JobKind::Spec { .. }
                            | crate::rewrite::JobKind::Program
                    )
            })
    }

    /// Asks for the AI Activity tab.
    pub fn ai_show_activity(&mut self) {
        self.ai.show_requested = true;
        self.ai.wake = true;
    }
}

//! The rewrite wizard: the steps from "which function" to "open the Rust project", with what each
//! step does, what blocks it, and the calls behind each button.
//!
//! The window only draws this state. Every step uses the same commands as the Rewrite tab, so
//! what the wizard does can be done by hand, and by an agent with the `rewrite_*` tools.

use super::{JobKind, RewriteMode, UnitItem, UnitStatus};
use crate::state::{AnalysisPhase, ToastLevel};
use crate::vm::ViewModel;

/// Model attempts per function (`max_attempts` of the commands defaults to this).
const ATTEMPTS: u32 = 3;
/// Functions a program-level repair round translates again.
const REPAIR_FUNCTIONS: u32 = 2;

/// A step of the wizard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardStep {
    /// What to rewrite.
    #[default]
    Scope,
    /// How to rewrite it.
    Mode,
    /// Whether everything needed is there.
    Check,
    /// The rewrite job.
    Run,
    /// The results.
    Review,
    /// Accepting verified functions.
    Accept,
    /// Writing the Rust project.
    Export,
    /// Building and testing it.
    Build,
    /// Looking at it.
    Open,
}

impl WizardStep {
    /// Every step, in order.
    pub const ALL: [WizardStep; 9] = [
        WizardStep::Scope,
        WizardStep::Mode,
        WizardStep::Check,
        WizardStep::Run,
        WizardStep::Review,
        WizardStep::Accept,
        WizardStep::Export,
        WizardStep::Build,
        WizardStep::Open,
    ];

    /// Position in [`WizardStep::ALL`].
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    /// The step after this one.
    pub fn next(self) -> Option<WizardStep> {
        Self::ALL.get(self.index() + 1).copied()
    }

    /// The step before this one.
    pub fn prev(self) -> Option<WizardStep> {
        self.index().checked_sub(1).map(|i| Self::ALL[i])
    }

    /// Short name for the stepper.
    pub fn label(self) -> &'static str {
        match self {
            WizardStep::Scope => "Scope",
            WizardStep::Mode => "Mode",
            WizardStep::Check => "Check",
            WizardStep::Run => "Run",
            WizardStep::Review => "Review",
            WizardStep::Accept => "Accept",
            WizardStep::Export => "Export",
            WizardStep::Build => "Build",
            WizardStep::Open => "Open",
        }
    }

    /// One plain sentence: what this step does.
    pub fn sentence(self) -> &'static str {
        match self {
            WizardStep::Scope => "Choose how much of the program to rewrite in Rust.",
            WizardStep::Mode => {
                "Choose whether the Rust is translated from the code or written from a description."
            }
            WizardStep::Check => {
                "Make sure everything the rewrite needs is in place before it starts."
            }
            WizardStep::Run => {
                "KRAKEN asks the assistant for Rust and checks it against the original program."
            }
            WizardStep::Review => "See which functions matched the original and which did not.",
            WizardStep::Accept => {
                "Mark the results you trust. Only accepted functions are exported. This step is yours."
            }
            WizardStep::Export => "Write the accepted Rust as a project in a folder.",
            WizardStep::Build => "Compile the project and run its tests in the sandbox.",
            WizardStep::Open => "Look at the finished project.",
        }
    }
}

/// How much of the program is rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WizardScope {
    /// One function.
    #[default]
    Function,
    /// Every function of the plan, one at a time.
    Plan,
    /// The whole program as one crate, compared with the original as a program.
    Program,
}

impl WizardScope {
    /// Every scope.
    pub const ALL: [WizardScope; 3] = [
        WizardScope::Function,
        WizardScope::Plan,
        WizardScope::Program,
    ];

    /// Short name.
    pub fn label(self) -> &'static str {
        match self {
            WizardScope::Function => "This function",
            WizardScope::Plan => "The plan",
            WizardScope::Program => "The whole program",
        }
    }
}

/// What a scope means, in plain words.
pub fn wizard_scope_explain(s: WizardScope) -> &'static str {
    match s {
        WizardScope::Function => {
            "Rewrite one function and check it against the original. The best way to start: it is quick, and you see how the checking works."
        }
        WizardScope::Plan => {
            "Rewrite every function in the plan, callees first, one after the other. Each is checked on its own. You accept the ones you trust, and they are exported as a library with a shim that can stand in for the originals."
        }
        WizardScope::Program => {
            "Rewrite everything the program uses as one standalone Rust program, then run the original and the Rust program on the same inputs and compare what they print."
        }
    }
}

/// How serious a check result is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckLevel {
    /// Fine.
    Ok,
    /// Worth knowing; does not stop the run.
    Warn,
    /// The run cannot start.
    Blocked,
}

/// One line of the Check step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// What is checked.
    pub title: &'static str,
    /// How it came out.
    pub level: CheckLevel,
    /// What was found, and what to do about it.
    pub detail: String,
}

/// State of the wizard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WizardState {
    /// The window is showing.
    pub open: bool,
    /// The step on show.
    pub step: WizardStep,
    /// How much to rewrite.
    pub scope: WizardScope,
    /// How to rewrite it.
    pub mode: RewriteMode,
    /// The function of the Function scope.
    pub function: Option<u64>,
    /// Run was pressed in this pass.
    pub started: bool,
}

impl ViewModel {
    // ---------------------------------------------------------------- opening and moving

    /// Opens the wizard at the first step, with the function in the decompiler (or the one
    /// selected in the Rewrite tab) as the function to rewrite.
    pub fn rewrite_wizard_open(&mut self) {
        let function = self
            .current
            .as_ref()
            .map(|c| c.address)
            .or(self.rewrite.selected);
        self.rewrite_ensure_loaded();
        self.rewrite_program_ensure_loaded();
        let w = &mut self.rewrite.wizard;
        w.open = true;
        w.step = WizardStep::Scope;
        w.function = function;
        w.scope = if function.is_some() {
            WizardScope::Function
        } else {
            WizardScope::Plan
        };
        w.started = false;
        self.rewrite.export.result = None;
        self.rewrite.build.result = None;
        self.rewrite.build.error = None;
        self.rewrite.build.declined = None;
    }

    /// Closes the window. Jobs that are running keep running.
    pub fn rewrite_wizard_close(&mut self) {
        self.rewrite.wizard.open = false;
    }

    /// Chooses the scope.
    pub fn rewrite_wizard_set_scope(&mut self, scope: WizardScope) {
        let w = &mut self.rewrite.wizard;
        if w.scope != scope {
            w.scope = scope;
            w.started = false;
            if scope == WizardScope::Program {
                w.mode = RewriteMode::Incremental;
            }
        }
    }

    /// Chooses the mode.
    pub fn rewrite_wizard_set_mode(&mut self, mode: RewriteMode) {
        if self.rewrite.wizard.scope == WizardScope::Program && mode == RewriteMode::Spec {
            return;
        }
        let w = &mut self.rewrite.wizard;
        if w.mode != mode {
            w.mode = mode;
            w.started = false;
        }
    }

    /// Chooses the function of the Function scope.
    pub fn rewrite_wizard_set_function(&mut self, address: u64) {
        let w = &mut self.rewrite.wizard;
        if w.function != Some(address) {
            w.function = Some(address);
            w.started = false;
        }
    }

    /// Goes to the next step when this one is not blocked.
    pub fn rewrite_wizard_next(&mut self) {
        if self.rewrite_wizard_blocker().is_some() {
            return;
        }
        if let Some(n) = self.rewrite.wizard.step.next() {
            self.rewrite.wizard.step = self.rewrite_wizard_skip_forward(n);
        }
    }

    /// Steps that make no sense for the scope are passed over.
    fn rewrite_wizard_skip_forward(&self, mut step: WizardStep) -> WizardStep {
        while self.rewrite_wizard_skips(step) {
            match step.next() {
                Some(n) => step = n,
                None => break,
            }
        }
        step
    }

    fn rewrite_wizard_skip_back(&self, mut step: WizardStep) -> WizardStep {
        while self.rewrite_wizard_skips(step) {
            match step.prev() {
                Some(p) => step = p,
                None => break,
            }
        }
        step
    }

    /// The Export step of a whole-program rewrite is done by the run itself: the crate is already
    /// written to the folder chosen before it.
    pub fn rewrite_wizard_skips(&self, step: WizardStep) -> bool {
        self.rewrite.wizard.scope == WizardScope::Program && step == WizardStep::Export
    }

    /// Goes back one step.
    pub fn rewrite_wizard_back(&mut self) {
        if let Some(p) = self.rewrite.wizard.step.prev() {
            self.rewrite.wizard.step = self.rewrite_wizard_skip_back(p);
        }
    }

    /// Moves forward by itself when the run finishes.
    pub fn rewrite_wizard_tick(&mut self) {
        let w = &self.rewrite.wizard;
        if w.open && w.step == WizardStep::Run && w.started && !self.rewrite_wizard_running() {
            self.rewrite.wizard.step = WizardStep::Review;
        }
    }

    // ---------------------------------------------------------------- what the scope covers

    /// The function of the Function scope, as a row.
    pub fn rewrite_wizard_row(&self) -> Option<&UnitItem> {
        self.rewrite.row(self.rewrite.wizard.function?)
    }

    /// The name of the function of the Function scope.
    pub fn rewrite_wizard_function_name(&self) -> Option<String> {
        let a = self.rewrite.wizard.function?;
        Some(
            self.rewrite
                .row(a)
                .map(|r| r.name.clone())
                .or_else(|| {
                    self.functions
                        .items
                        .iter()
                        .find(|f| f.address == a)
                        .map(|f| f.name.clone())
                })
                .unwrap_or_else(|| crate::vm::hex(a)),
        )
    }

    /// The rows the wizard's results are about.
    pub fn rewrite_wizard_rows(&self) -> Vec<&UnitItem> {
        match self.rewrite.wizard.scope {
            WizardScope::Function => self.rewrite_wizard_row().into_iter().collect(),
            WizardScope::Plan | WizardScope::Program => self.rewrite.rows.iter().collect(),
        }
    }

    /// The scope's run is going.
    pub fn rewrite_wizard_running(&self) -> bool {
        match self.rewrite.wizard.scope {
            WizardScope::Function => self
                .rewrite
                .wizard
                .function
                .is_some_and(|a| self.rewrite.running_for(a).is_some()),
            WizardScope::Plan => {
                self.rewrite.bulk.active()
                    || self
                        .rewrite
                        .jobs
                        .iter()
                        .any(|j| j.running() && matches!(j.kind, JobKind::Function { .. }))
            }
            WizardScope::Program => self.rewrite_program_running(),
        }
    }

    /// The folder holding the Rust project: the one the export wrote, or the crate the
    /// whole-program run wrote.
    pub fn rewrite_wizard_crate_dir(&self) -> Option<String> {
        match self.rewrite.wizard.scope {
            WizardScope::Program => self
                .rewrite
                .program
                .detail
                .as_ref()
                .map(|d| d.crate_dir.clone())
                .filter(|d| !d.is_empty()),
            _ => self.rewrite.export.result.as_ref().map(|r| r.dir.clone()),
        }
    }

    // ---------------------------------------------------------------- the check step

    /// Functions the run will work on, and the most model calls it can make.
    pub fn rewrite_wizard_estimate(&self) -> (u32, u32) {
        let w = &self.rewrite.wizard;
        let spec_extra = u32::from(w.mode == RewriteMode::Spec);
        match w.scope {
            WizardScope::Function => (1, ATTEMPTS + spec_extra),
            WizardScope::Plan => {
                let n = u32::try_from(self.rewrite_planned_count()).unwrap_or(u32::MAX);
                (n, n.saturating_mul(ATTEMPTS + spec_extra))
            }
            WizardScope::Program => {
                let n = u32::try_from(self.rewrite.rows.len())
                    .unwrap_or(u32::MAX)
                    .max(
                        self.rewrite
                            .plan_summary
                            .as_ref()
                            .map_or(0, |p| u32::try_from(p.functions_planned).unwrap_or(0)),
                    );
                let repair = self
                    .rewrite
                    .program
                    .repair_rounds
                    .saturating_mul(REPAIR_FUNCTIONS * ATTEMPTS);
                (n, n.saturating_mul(ATTEMPTS).saturating_add(repair))
            }
        }
    }

    /// The Check step's list.
    pub fn rewrite_wizard_checks(&self) -> Vec<Check> {
        let mut out = Vec::new();
        out.push(match self.assist.badge() {
            Some(b) => Check {
                title: "Assistant",
                level: CheckLevel::Ok,
                detail: format!("{}. {}", b.title(), b.privacy()),
            },
            None => Check {
                title: "Assistant",
                level: CheckLevel::Warn,
                detail: "No assistant is set up in this window. The rewrite uses the provider named in your KRAKEN config file, and stops with a message when there is none. Choose one in Settings.".into(),
            },
        });
        out.push(match self.rewrite.blocked_note() {
            None => Check {
                title: "Sandbox",
                level: CheckLevel::Ok,
                detail: "Generated code is built and run in a sandbox: no network, files read-only, limited time and memory.".into(),
            },
            Some(n) => Check {
                title: "Sandbox",
                level: CheckLevel::Blocked,
                detail: n.to_string(),
            },
        });
        let analysed = self.analysis.phase == AnalysisPhase::Complete
            || !self.functions.items.is_empty()
            || self.functions.total.is_some_and(|t| t > 0);
        out.push(if analysed {
            Check {
                title: "Analysis",
                level: CheckLevel::Ok,
                detail: match self.functions.total.or(self.analysis.function_count) {
                    Some(n) => format!("Done. The program has {n} functions."),
                    None => "Done.".into(),
                },
            }
        } else if self.analysis.running() {
            Check {
                title: "Analysis",
                level: CheckLevel::Blocked,
                detail: "Analysis is still running. Wait for it to finish.".into(),
            }
        } else {
            Check {
                title: "Analysis",
                level: CheckLevel::Blocked,
                detail: "The program has not been analyzed yet, so there are no functions to rewrite. Choose Analysis > Analyze program first.".into(),
            }
        });
        let (functions, calls) = self.rewrite_wizard_estimate();
        out.push(match (self.rewrite.wizard.scope, functions) {
            (WizardScope::Function, _) if self.rewrite.wizard.function.is_none() => Check {
                title: "Size of the job",
                level: CheckLevel::Blocked,
                detail: "No function is chosen. Go back to Scope and pick one.".into(),
            },
            (WizardScope::Plan, 0) => Check {
                title: "Size of the job",
                level: CheckLevel::Blocked,
                detail: if self.rewrite.rows.is_empty() {
                    "There is no plan yet. Go back to Scope and plan the rewrite.".into()
                } else {
                    "Every function in the plan has already been translated. Go to Review to see the results.".into()
                },
            },
            _ => Check {
                title: "Size of the job",
                level: CheckLevel::Ok,
                detail: format!(
                    "{functions} function{}, up to {calls} request{} to the assistant. A request sends decompiled code to the assistant's service.",
                    if functions == 1 { "" } else { "s" },
                    if calls == 1 { "" } else { "s" },
                ),
            },
        });
        out
    }

    // ---------------------------------------------------------------- blockers

    /// Why "Next" is off at the current step, in a sentence; `None` when it is on.
    pub fn rewrite_wizard_blocker(&self) -> Option<String> {
        let w = &self.rewrite.wizard;
        match w.step {
            WizardStep::Scope => match w.scope {
                WizardScope::Function if w.function.is_none() => Some(
                    "Choose a function. Open one in the Decompiler first, or pick one from the list.".into(),
                ),
                WizardScope::Plan if self.rewrite.rows.is_empty() => Some(
                    "There is no plan yet. Press \"Plan the rewrite\" to list the functions, callees first.".into(),
                ),
                _ => None,
            },
            WizardStep::Mode => None,
            WizardStep::Check => self
                .rewrite_wizard_checks()
                .into_iter()
                .find(|c| c.level == CheckLevel::Blocked)
                .map(|c| format!("{}: {}", c.title, c.detail)),
            WizardStep::Run => {
                if self.rewrite_wizard_running() {
                    Some("The rewrite is running. This step moves on by itself when it ends.".into())
                } else if !w.started {
                    Some("Press Start to run the rewrite.".into())
                } else {
                    None
                }
            }
            WizardStep::Review => self.rewrite_wizard_review_blocker(),
            WizardStep::Accept => match w.scope {
                WizardScope::Program => None,
                _ if self.rewrite.counts.accepted == 0 => Some(
                    "Accept at least one verified function. Only accepted functions are exported.".into(),
                ),
                _ => None,
            },
            WizardStep::Export => {
                if self.rewrite.exporting() {
                    Some("The export is running.".into())
                } else {
                    self.rewrite_wizard_crate_dir()
                        .is_none()
                        .then(|| "Export the accepted functions first. Press Export.".into())
                }
            }
            WizardStep::Build => {
                if self.rewrite.building() {
                    Some("The build is running.".into())
                } else if self.rewrite.build.result.is_none() {
                    Some("Build the project first. Press Build and test.".into())
                } else {
                    None
                }
            }
            WizardStep::Open => Some("This is the last step.".into()),
        }
    }

    fn rewrite_wizard_review_blocker(&self) -> Option<String> {
        let w = &self.rewrite.wizard;
        match w.scope {
            WizardScope::Function => match self.rewrite_wizard_row().map(|r| r.status) {
                Some(UnitStatus::Verified | UnitStatus::Accepted) => None,
                Some(UnitStatus::Failed) => Some(
                    "This function failed. Open it in the Rewrite tab to see where the Rust differs, or go back and run again.".into(),
                ),
                Some(UnitStatus::Translated) => Some(
                    "The test could not decide whether the Rust matches the original, so there is nothing to accept. Open it in the Rewrite tab for the reason.".into(),
                ),
                _ => Some("The function has not been translated yet. Go back to Run.".into()),
            },
            WizardScope::Plan => {
                let c = &self.rewrite.counts;
                (c.verified + c.accepted == 0).then(|| {
                    "No function matched the original yet. Go back to Run, or open the failed ones in the Rewrite tab.".into()
                })
            }
            WizardScope::Program => match &self.rewrite.program.detail {
                None => Some(
                    self.rewrite
                        .program
                        .error
                        .clone()
                        .or_else(|| self.rewrite.program.declined.clone())
                        .unwrap_or_else(|| "The whole-program run has no result yet. Go back to Run.".into()),
                ),
                Some(_) => None,
            },
        }
    }

    // ---------------------------------------------------------------- the buttons

    /// Starts the rewrite for the scope.
    pub fn rewrite_wizard_start(&mut self) {
        if self.rewrite_wizard_running() {
            return;
        }
        let (scope, mode, function) = {
            let w = &self.rewrite.wizard;
            (w.scope, w.mode, w.function)
        };
        match scope {
            WizardScope::Function => {
                if let Some(a) = function {
                    self.rewrite_select(a);
                    self.rewrite_run(a, mode);
                }
            }
            WizardScope::Plan => self.rewrite_bulk_translate_planned(mode),
            WizardScope::Program => self.rewrite_program_run(),
        }
        self.rewrite.wizard.started = true;
    }

    /// Stops the run (after the function in progress for the plan).
    pub fn rewrite_wizard_cancel(&mut self) {
        match self.rewrite.wizard.scope {
            WizardScope::Plan => self.rewrite_bulk_cancel(),
            _ => {
                let ids: Vec<String> = self
                    .rewrite
                    .jobs
                    .iter()
                    .filter(|j| j.running())
                    .filter_map(|j| j.job_id.clone())
                    .collect();
                for id in ids {
                    self.call("job_cancel", serde_json::json!({ "job_id": id }), |_, _| {});
                }
            }
        }
    }

    /// Accepts what the scope covers: the function, or every verified function.
    pub fn rewrite_wizard_accept(&mut self) {
        match self.rewrite.wizard.scope {
            WizardScope::Function => {
                if let Some(a) = self.rewrite.wizard.function {
                    self.rewrite_select(a);
                    self.rewrite_accept_row(a);
                }
            }
            _ => self.rewrite_bulk_accept_verified(),
        }
    }

    /// Accepts the newest version of `address` from the plan row, without needing its detail.
    pub fn rewrite_accept_row(&mut self, address: u64) {
        let Some(unit) = self
            .rewrite
            .row(address)
            .filter(|r| r.status == UnitStatus::Verified && !r.unit.is_empty())
            .map(|r| r.unit.clone())
        else {
            return;
        };
        self.call(
            "rewrite_accept",
            serde_json::json!({ "unit": unit }),
            move |vm, res| match res {
                Ok(_) => {
                    let name = vm.rewrite_wizard_name_of(address);
                    vm.toast(
                        ToastLevel::Success,
                        format!("Accepted {name}. It will be part of the export."),
                    );
                    vm.rewrite_refresh();
                }
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    fn rewrite_wizard_name_of(&self, address: u64) -> String {
        self.rewrite
            .row(address)
            .map_or_else(|| crate::vm::hex(address), |r| r.name.clone())
    }

    /// Why "Accept" is off, when it is.
    pub fn rewrite_wizard_accept_blocker(&self) -> Option<String> {
        match self.rewrite.wizard.scope {
            WizardScope::Function => {
                let r = self.rewrite_wizard_row()?;
                match r.status {
                    UnitStatus::Verified if !r.unit.is_empty() => None,
                    UnitStatus::Accepted => Some("This function is already accepted.".into()),
                    _ => Some(format!(
                        "This function is {}. Only a verified function can be accepted.",
                        r.status.as_str()
                    )),
                }
            }
            _ => self.rewrite_bulk_accept_blocker(),
        }
    }

    /// Writes the accepted functions with the export dialog's settings.
    pub fn rewrite_wizard_export(&mut self) {
        self.rewrite_export_start();
    }

    /// Builds and tests the project the scope produced.
    pub fn rewrite_wizard_build(&mut self) {
        if let Some(dir) = self.rewrite_wizard_crate_dir() {
            self.rewrite_build_start(&dir);
        }
    }
}

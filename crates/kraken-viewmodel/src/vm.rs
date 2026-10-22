//! The view-model: every piece of GUI state and the logic that changes it.
//!
//! All backend calls run on a tokio runtime. A finished call sends a closure through a queue;
//! [`ViewModel::poll`] applies the queued closures on the UI thread once per frame, so the UI never
//! blocks and never sees a half-applied result.

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kraken_proto::{CommentKind, Completeness, DecompileResult, ErrorCode, ProtoError, Untrusted};
use kraken_registry::EngineChoice;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::runtime::Handle;
use tokio::sync::broadcast::error::RecvError;

use crate::backend::{Backend, BackendEvent, ChangeInfo, CommandInfo, JobInfo, JobState};
use crate::errors::plain_error;
use crate::loading::LoadingState;
use crate::nav::NavHistory;
use crate::palette::{AppAction, PaletteState, PaletteTarget, UiRequest};
use crate::state::*;
use crate::tokens::tokenize;
use crate::views::ProgramViews;
use crate::wire::*;

/// Page size requested for the function list.
pub const FUNCTION_PAGE: u32 = 200;
/// Longest accepted function name (matches the registry).
pub const MAX_NAME_LEN: usize = 200;

type ApplyFn = Box<dyn FnOnce(&mut ViewModel) + Send>;
type Repaint = Arc<dyn Fn() + Send + Sync>;
type RepaintCell = Arc<Mutex<Option<Repaint>>>;

fn kick(cell: &RepaintCell) {
    let f = cell.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(f) = f {
        f();
    }
}

struct Msg {
    counted: bool,
    apply: ApplyFn,
}

/// Queues work for the UI thread from background tasks.
#[derive(Clone)]
pub(crate) struct Poster {
    tx: Sender<Msg>,
    repaint: RepaintCell,
    rt: Handle,
}

impl Poster {
    /// Runs `apply` on the UI thread at the next poll.
    pub(crate) fn post(&self, apply: impl FnOnce(&mut ViewModel) + Send + 'static) {
        let _ = self.tx.send(Msg {
            counted: false,
            apply: Box::new(apply),
        });
        kick(&self.repaint);
    }

    /// The runtime tasks run on.
    pub(crate) fn runtime(&self) -> &Handle {
        &self.rt
    }
}

/// All GUI state. Fields are public for reading; change them through the methods.
pub struct ViewModel {
    backend: Arc<dyn Backend>,
    rt: Handle,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    repaint: RepaintCell,
    pending: usize,
    event_task: Option<tokio::task::JoinHandle<()>>,
    next_toast: u64,
    revision: u64,
    detail_seq: u64,
    decompile_seq: u64,

    /// Whether a project is open.
    pub connection: Connection,
    /// The project being created or opened, for the loading screen.
    pub loading: Option<LoadingState>,
    /// The open project.
    pub project: Option<ProjectInfo>,
    /// The Functions panel.
    pub functions: FunctionList,
    /// Address highlighted in the function list.
    pub selected: Option<u64>,
    /// The module id (MVID) of a .NET project, learned from its function list. A managed
    /// function's "address" is its metadata token; this names the module the token is in, and is
    /// sent with every request that names a function.
    pub module: Option<String>,
    /// The function in the Decompiler panel.
    pub current: Option<CurrentFunction>,
    /// Back/forward history.
    pub nav: NavHistory,
    /// The rename dialog, when open.
    pub rename: Option<RenameDialog>,
    /// The comment dialog, when open.
    pub comment: Option<CommentDialog>,
    /// The History tab.
    pub history: HistoryPanel,
    /// The Proposals tab.
    pub proposals: ProposalsPanel,
    /// Analysis progress.
    pub analysis: AnalysisState,
    /// The command palette.
    pub palette: PaletteState,
    /// Live notifications, oldest first.
    pub toasts: Vec<Toast>,
    /// Whether the daemon connection is up.
    pub link: LinkState,
    /// Listing, hex, graph, cross-references, strings and symbols.
    pub views: ProgramViews,
    /// The AI assistant: chat, explanations, overview, auto-naming, learn mode.
    pub assist: crate::assist::AssistState,
    announced: std::collections::HashSet<u64>,
    /// Undoing an older edit with the edits that depend on it, and stale functions.
    pub undo: crate::history::UndoFlow,
    job_watch: JobWatch,
    /// The Rewrite tab: plan, jobs, generated Rust, spec and export.
    pub rewrite: crate::rewrite::RewriteState,
    /// What agents did lately, for the status bar.
    pub agent_activity: crate::activity::AgentActivity,
    focus_request: Option<String>,
    /// GUI action ids agents asked for (`ui_action`), waiting for the window.
    ui_actions: Vec<String>,
    /// Tabs or widgets agents asked to flash, with their notes (`ui_highlight`).
    ui_highlights: Vec<(String, String)>,
    /// Tab ids open and the tab in front, as the window last reported them (`ui_state`).
    ui_info: Option<(Vec<String>, Option<String>)>,
    /// A window the person has open that agents may drive (the model setup), in a sentence.
    ui_dialog: Option<String>,
    /// Go to, Search, Bookmarks, the type and function dialogs and generated command forms.
    pub tools: crate::navtools::NavTools,
    /// AI work: what runs and what it costs, and the question asked before it starts.
    pub ai: crate::ai::AiState,
}

/// Bookkeeping of the analysis fallback poll (see [`ViewModel::watch_analysis`]).
struct JobWatch {
    /// Last time an event or status reply about the analysis arrived.
    last_activity: Instant,
    /// Last time a fallback `job_status` was sent.
    last_poll: Instant,
    /// A fallback `job_status` is on its way.
    inflight: bool,
}

/// Quiet time after which a running analysis is checked with `job_status`.
const JOB_QUIET_POLL: Duration = Duration::from_secs(1);
/// Minimum gap between fallback polls once the last stage reports done.
const JOB_FINAL_POLL: Duration = Duration::from_millis(250);

pub(crate) fn parse<T: DeserializeOwned>(v: Value) -> Result<T, ProtoError> {
    serde_json::from_value(v).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("unexpected reply from the backend: {e}"),
        )
    })
}

/// Entity key of a function's name, as the model names it (`kraken-model` `entity_key`).
fn name_key(addr: u64) -> String {
    format!("native:ram:{addr:#x}:name")
}

/// Entity key of one comment slot.
fn comment_key(addr: u64, kind: CommentKind) -> String {
    let slot = serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    format!("native:ram:{addr:#x}:comment:{slot}")
}

/// `expect_versions` for an edit that writes `key`: the version the person last saw, 0 when the
/// key was never written.
fn expect(versions: &BTreeMap<String, u64>, key: String) -> Value {
    let v = versions.get(&key).copied().unwrap_or(0);
    json!({ key: v })
}

pub(crate) fn hex(addr: u64) -> String {
    format!("{addr:#x}")
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

fn function_item(w: &FunctionWire) -> FunctionItem {
    FunctionItem {
        address: w.address.0,
        name: w.name.0.clone(),
        size: w.size,
        signature: w.signature.as_ref().map(|s| s.0.clone()),
        partial: !matches!(w.completeness, Completeness::Complete),
        stub: crate::state::is_library_stub(
            &w.name.0,
            w.size,
            w.signature.as_ref().map(|s| s.0.as_str()),
        ),
    }
}

fn kind_of(v: &Value) -> String {
    v.get("kind")
        .and_then(Value::as_str)
        .or_else(|| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// "Agent renamed old -> new" and friends, from a history row.
fn agent_edit_text(author: &str, op: &str, description: &str) -> String {
    let suffix = if author.is_empty() {
        String::new()
    } else {
        format!(" ({author})")
    };
    let words: Vec<&str> = description.split_whitespace().collect();
    match (op, words.as_slice()) {
        ("rename", [_, _, old, "->", new, ..]) => {
            format!("Agent renamed {old} \u{2192} {new}{suffix}")
        }
        ("set_comment", [_, addr, ..]) => format!("Agent commented on {addr}{suffix}"),
        ("set_patch", [_, addr, ..]) => format!("Agent patched the bytes at {addr}{suffix}"),
        (_, [_, addr, ..]) => format!("Agent changed {addr} ({op}){suffix}"),
        _ => format!("Agent edited the project ({op}){suffix}"),
    }
}

pub(crate) fn who(a: &AuthorWire) -> String {
    if a.kind == "user" {
        "you".to_string()
    } else {
        a.id.clone()
    }
}

impl RenameDialog {
    /// Checks the typed name; `Ok` holds the trimmed name to send.
    pub fn validate(&self) -> Result<String, String> {
        validate_name(&self.input, &self.old_name)
    }
}

/// Local name rules, the same ones the registry applies to people.
pub fn validate_name(input: &str, old_name: &str) -> Result<String, String> {
    let name = input.trim();
    if name.is_empty() {
        return Err("Type a name first.".into());
    }
    if name.chars().any(char::is_whitespace) {
        return Err("A name cannot contain spaces. Use underscores instead.".into());
    }
    if name.chars().any(char::is_control) {
        return Err("A name cannot contain control characters.".into());
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(format!("A name can be at most {MAX_NAME_LEN} characters."));
    }
    if name == old_name {
        return Err("That is already the name.".into());
    }
    Ok(name.to_string())
}

impl ViewModel {
    /// The runtime the calls run on, for dialogs the window opens (a folder chooser).
    pub fn runtime_handle(&self) -> Handle {
        self.rt.clone()
    }

    /// Creates a view-model over `backend`; calls run on `rt`.
    pub fn new(backend: Arc<dyn Backend>, rt: Handle) -> Self {
        let (tx, rx) = channel();
        let mut vm = ViewModel {
            backend,
            rt,
            tx,
            rx,
            repaint: RepaintCell::default(),
            pending: 0,
            event_task: None,
            next_toast: 1,
            revision: 0,
            detail_seq: 0,
            decompile_seq: 0,
            connection: Connection::NoProject,
            project: None,
            functions: FunctionList::default(),
            selected: None,
            module: None,
            current: None,
            nav: NavHistory::new(),
            rename: None,
            comment: None,
            history: HistoryPanel::default(),
            proposals: ProposalsPanel::default(),
            analysis: AnalysisState::default(),
            loading: None,
            palette: PaletteState::default(),
            toasts: Vec::new(),
            link: LinkState::Connected,
            views: ProgramViews::default(),
            assist: crate::assist::AssistState::default(),
            announced: std::collections::HashSet::new(),
            undo: crate::history::UndoFlow::default(),
            job_watch: JobWatch {
                last_activity: Instant::now(),
                last_poll: Instant::now(),
                inflight: false,
            },
            rewrite: crate::rewrite::RewriteState::default(),
            agent_activity: crate::activity::AgentActivity::default(),
            focus_request: None,
            ui_actions: Vec::new(),
            ui_highlights: Vec::new(),
            ui_info: None,
            ui_dialog: None,
            tools: crate::navtools::NavTools::default(),
            ai: crate::ai::AiState::default(),
        };
        vm.start_event_forwarder();
        vm
    }

    /// A handle for background tasks to queue closures that run on the UI thread in
    /// [`poll`](Self::poll).
    pub(crate) fn poster(&self) -> Poster {
        Poster {
            tx: self.tx.clone(),
            repaint: self.repaint.clone(),
            rt: self.rt.clone(),
        }
    }

    /// Called from worker threads whenever a result is queued, so the window can repaint.
    pub fn set_repaint(&mut self, f: Arc<dyn Fn() + Send + Sync>) {
        *self.repaint.lock().unwrap_or_else(PoisonError::into_inner) = Some(f);
    }

    /// The backend this view-model talks to.
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// The backend's commands.
    pub fn commands(&self) -> Vec<CommandInfo> {
        self.backend.commands()
    }

    fn start_event_forwarder(&mut self) {
        let mut events = self.backend.events();
        let tx = self.tx.clone();
        let repaint = self.repaint.clone();
        let task = self.rt.spawn(async move {
            loop {
                let ev = match events.recv().await {
                    Ok(ev) => Some(ev),
                    Err(RecvError::Lagged(_)) => None,
                    Err(RecvError::Closed) => break,
                };
                let apply: ApplyFn = Box::new(move |vm| match ev {
                    Some(ev) => vm.on_event(ev),
                    None => vm.refresh_job(),
                });
                if tx
                    .send(Msg {
                        counted: false,
                        apply,
                    })
                    .is_err()
                {
                    break;
                }
                kick(&repaint);
            }
        });
        self.event_task = Some(task);
    }

    // ---------------------------------------------------------------- plumbing

    pub(crate) fn call<F>(&mut self, command: impl Into<String>, args: Value, apply: F)
    where
        F: FnOnce(&mut ViewModel, Result<Value, ProtoError>) + Send + 'static,
    {
        self.pending += 1;
        let command = command.into();
        let backend = self.backend.clone();
        let tx = self.tx.clone();
        let repaint = self.repaint.clone();
        self.rt.spawn(async move {
            let res = backend.call(&command, args).await;
            let _ = tx.send(Msg {
                counted: true,
                apply: Box::new(move |vm| apply(vm, res)),
            });
            kick(&repaint);
        });
    }

    /// Applies finished backend results and expires old toasts. Call once per frame; returns
    /// true when anything changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            if m.counted {
                self.pending = self.pending.saturating_sub(1);
            }
            (m.apply)(self);
            changed = true;
        }
        self.watch_analysis();
        self.ai_tick();
        changed | self.expire_toasts(Instant::now())
    }

    /// Safety net for a missed `job_done`: while an analysis runs, ask `job_status` when nothing
    /// was heard for a second, and at once (rate limited) when the last stage reports done.
    fn watch_analysis(&mut self) {
        if !self.analysis.running() || self.analysis.job_id.is_none() || self.job_watch.inflight {
            return;
        }
        let now = Instant::now();
        let since_poll = now.saturating_duration_since(self.job_watch.last_poll);
        let quiet = now.saturating_duration_since(self.job_watch.last_activity);
        let last_stage = self
            .analysis
            .progress
            .as_ref()
            .is_some_and(|p| p.total > 0 && p.done >= p.total);
        if (last_stage && since_poll >= JOB_FINAL_POLL)
            || (quiet >= JOB_QUIET_POLL && since_poll >= JOB_QUIET_POLL)
        {
            let Some(id) = self.analysis.job_id.clone() else {
                return;
            };
            self.job_watch.inflight = true;
            self.job_watch.last_poll = now;
            self.call("job_status", json!({ "job_id": id }), |vm, res| {
                vm.job_watch.inflight = false;
                if let Ok(info) = res.and_then(parse::<JobInfo>) {
                    vm.on_job(info);
                }
            });
        }
    }

    /// Calls still running.
    pub fn pending_calls(&self) -> usize {
        self.pending
    }

    /// True while any call is running.
    pub fn busy(&self) -> bool {
        self.pending > 0
    }

    /// Polls until no call is running or `timeout` passes. Blocks; for tests and screenshot mode,
    /// never for the UI thread.
    pub fn block_until_idle(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.poll();
            if self.pending == 0 {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Polls until `cond` holds or `timeout` passes. Blocks; for tests and screenshot mode.
    pub fn block_until(&mut self, timeout: Duration, cond: impl Fn(&ViewModel) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.poll();
            if cond(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    // ---------------------------------------------------------------- toasts

    /// Shows a notification.
    pub fn toast(&mut self, level: ToastLevel, text: impl Into<String>) {
        self.toast_with(level, text, None);
    }

    /// Shows a notification with a button.
    pub fn toast_with(
        &mut self,
        level: ToastLevel,
        text: impl Into<String>,
        action: Option<ToastAction>,
    ) {
        let id = self.next_toast;
        self.next_toast += 1;
        self.toasts.push(Toast {
            id,
            level,
            text: text.into(),
            action,
            created: Instant::now(),
        });
        if self.toasts.len() > 6 {
            self.toasts.remove(0);
        }
    }

    pub(crate) fn toast_error(&mut self, e: &ProtoError) {
        let text = plain_error(e);
        self.toast(ToastLevel::Error, text);
    }

    /// Runs the button of toast `id` and closes the toast.
    pub fn run_toast_action(&mut self, id: u64) {
        let action = self
            .toasts
            .iter()
            .find(|t| t.id == id)
            .and_then(|t| t.action.clone());
        self.dismiss_toast(id);
        match action {
            Some(ToastAction::UndoRun { run_id }) => self.undo_run(run_id),
            Some(ToastAction::OpenHistory) => {
                self.tools.request_tab(crate::navtools::NavTab::History);
            }
            Some(ToastAction::OpenAiActivity) => self.ai_show_activity(),
            None => {}
        }
    }

    /// Closes one notification.
    pub fn dismiss_toast(&mut self, id: u64) {
        self.toasts.retain(|t| t.id != id);
    }

    /// Drops notifications older than their lifetime as of `now`.
    pub fn expire_toasts(&mut self, now: Instant) -> bool {
        let before = self.toasts.len();
        self.toasts
            .retain(|t| now.saturating_duration_since(t.created) < t.lifetime());
        self.toasts.len() != before
    }

    // ---------------------------------------------------------------- project

    fn reset_for_new_project(&mut self) {
        self.project = None;
        self.functions = FunctionList::default();
        self.selected = None;
        self.module = None;
        self.current = None;
        self.nav.clear();
        self.rename = None;
        self.comment = None;
        self.history = HistoryPanel::default();
        self.undo = crate::history::UndoFlow::default();
        self.rewrite = self.rewrite.reset();
        self.proposals = ProposalsPanel::default();
        self.analysis = AnalysisState::default();
        self.assist.reset_for_project();
        self.detail_seq += 1;
        self.decompile_seq += 1;
        self.views.reset();
        self.tools = crate::navtools::NavTools::default();
    }

    /// Opens the project in `dir`.
    pub fn open_project(&mut self, dir: impl Into<String>) {
        let dir = dir.into();
        self.connection = Connection::Opening(format!("Opening {dir}..."));
        self.loading = Some(LoadingState::new(file_name(&dir), false));
        self.call("project_open", json!({ "project_dir": dir }), |vm, res| {
            vm.project_opened(res)
        });
    }

    /// Creates a project in `project_dir` for `binary`, with the engine the configuration
    /// names.
    pub fn create_project(&mut self, binary: impl Into<String>, project_dir: impl Into<String>) {
        self.create_project_with(binary, project_dir, None);
    }

    /// Creates a project in `project_dir` for `binary` on the engine `engine` (`None`: the
    /// configured default). The daemon records the engine in the project.
    pub fn create_project_with(
        &mut self,
        binary: impl Into<String>,
        project_dir: impl Into<String>,
        engine: Option<EngineChoice>,
    ) {
        let binary = binary.into();
        self.connection = Connection::Opening(format!("Loading {}...", file_name(&binary)));
        self.loading = Some(LoadingState::new(file_name(&binary), true));
        let mut args = json!({ "binary": binary, "project_dir": project_dir.into() });
        if let Some(e) = engine {
            args["engine"] = json!(e.as_str());
        }
        self.call("project_create", args, |vm, res| vm.project_opened(res));
    }

    fn project_opened(&mut self, res: Result<Value, ProtoError>) {
        self.loading = None;
        match res {
            Err(e) if e.code == ErrorCode::Cancelled => {
                self.connection = Connection::NoProject;
                self.toast(
                    ToastLevel::Info,
                    "Opening was cancelled. Nothing was changed.",
                );
            }
            Ok(v) => {
                self.reset_for_new_project();
                self.connection = Connection::Open;
                self.apply_project(v);
                self.refresh_functions();
                self.refresh_history();
                self.refresh_proposals();
                self.refresh_tainted();
                self.views_project_opened();
            }
            Err(e) => {
                self.connection = Connection::Failed(plain_error(&e));
                self.toast_error(&e);
            }
        }
    }

    fn apply_project(&mut self, v: Value) {
        let w: ProjectWire = match parse(v) {
            Ok(w) => w,
            Err(e) => {
                self.toast_error(&e);
                return;
            }
        };
        self.project = Some(ProjectInfo {
            name: file_name(&w.binary_path),
            project_dir: w.project_dir,
            binary_path: w.binary_path,
            arch: w.program.arch,
            format: w.program.format,
            size: w.program.size,
            engine_build: w.engine_build,
            engine: w.engine.kind,
            engine_choice: w.engine.choice,
            engine_reason: w.engine.reason,
            epoch_stale: w.epoch_stale,
            pending_entries: w.pending_entries,
            log_entries: w.log_entries,
            open_proposals: w.open_proposals,
        });
        let phase = AnalysisPhase::parse(&w.analysis.phase);
        if !(self.analysis.running() && phase != AnalysisPhase::Running) {
            self.analysis.phase = phase;
        }
        if w.analysis.job_id.is_some() {
            self.analysis.job_id = w.analysis.job_id;
        }
        self.analysis.function_count = w.analysis.function_count.or(self.analysis.function_count);
        self.analysis.error = w.analysis.error;
        if phase == AnalysisPhase::Running && self.analysis.progress.is_none() {
            self.refresh_job();
        }
    }

    /// Reloads the project facts (counts, analysis phase).
    pub fn refresh_project(&mut self) {
        self.call("project_info", json!({}), |vm, res| match res {
            Ok(v) => vm.apply_project(v),
            Err(e) => vm.toast_error(&e),
        });
    }

    /// Reloads every panel from the backend.
    pub fn refresh_all(&mut self) {
        self.refresh_project();
        self.refresh_functions();
        self.refresh_history();
        self.refresh_proposals();
        self.refresh_tainted();
        self.refresh_current();
    }

    pub(crate) fn refresh_after_edit(&mut self) {
        self.refresh_project();
        self.refresh_functions();
        self.refresh_history();
        self.refresh_proposals();
        self.refresh_tainted();
        self.refresh_current();
        if self.tools.bookmarks.loaded {
            self.refresh_bookmarks();
        }
        // patches are log entries: an undo can remove or restore one
        if self.tools.patches.loaded {
            self.refresh_patches();
        }
    }

    /// Status bar text for the current state.
    pub fn status_text(&self) -> String {
        match &self.connection {
            Connection::NoProject => return "No project open".into(),
            Connection::Opening(m) => return m.clone(),
            Connection::Failed(m) => return format!("Could not open the project: {m}"),
            Connection::Open => {}
        }
        match self.analysis.phase {
            AnalysisPhase::Running => {
                return match &self.analysis.progress {
                    Some(p) if p.total > 0 => {
                        format!("Analyzing: {} ({} of {})", p.phase, p.done, p.total)
                    }
                    Some(p) => format!("Analyzing: {}", p.phase),
                    None => "Analyzing...".into(),
                };
            }
            AnalysisPhase::Failed => return "Analysis failed".into(),
            AnalysisPhase::Cancelled => return "Analysis cancelled; partial results kept".into(),
            AnalysisPhase::NotStarted => {
                return "Not analyzed yet. Run Analyze to find functions".into();
            }
            AnalysisPhase::Complete => {}
        }
        if self.busy() {
            return "Working...".into();
        }
        match self.analysis.function_count.or(self.functions.total) {
            Some(n) => format!("Ready: {n} functions"),
            None => "Ready".into(),
        }
    }

    // ---------------------------------------------------------------- analysis

    /// Starts staged analysis.
    pub fn start_analysis(&mut self) {
        if self.analysis.running() {
            self.toast(ToastLevel::Info, "Analysis is already running.");
            return;
        }
        self.analysis.error = None;
        self.analysis.progress = None;
        self.call("analyze", json!({}), |vm, res| {
            match res.and_then(parse::<AnalyzeWire>) {
                Ok(a) => {
                    // `job_done` may already have been handled by the time this reply is.
                    let already_done = vm.analysis.job_id.as_deref() == Some(a.job_id.as_str())
                        && vm.analysis.is_finished();
                    if !already_done {
                        vm.analysis.phase = AnalysisPhase::Running;
                        vm.analysis.job_id = Some(a.job_id);
                        vm.job_watch.last_activity = Instant::now();
                        vm.refresh_job();
                    }
                }
                Err(e) => vm.toast_error(&e),
            }
        });
    }

    /// Asks the engine to stop the running analysis.
    pub fn cancel_analysis(&mut self) {
        let Some(id) = self
            .analysis
            .job_id
            .clone()
            .filter(|_| self.analysis.running())
        else {
            self.toast(ToastLevel::Info, "No analysis is running.");
            return;
        };
        self.call("job_cancel", json!({ "job_id": id }), |vm, res| {
            match res.and_then(parse::<JobInfo>) {
                Ok(info) => vm.on_job(info),
                Err(e) => vm.toast_error(&e),
            }
        });
    }

    fn refresh_job(&mut self) {
        let Some(id) = self.analysis.job_id.clone() else {
            return;
        };
        self.call("job_status", json!({ "job_id": id }), |vm, res| {
            match res.and_then(parse::<JobInfo>) {
                Ok(info) => vm.on_job(info),
                Err(e) => vm.toast_error(&e),
            }
        });
    }

    /// Applies one backend event, as [`poll`](Self::poll) does for the ones it receives.
    pub fn on_event(&mut self, ev: BackendEvent) {
        match ev {
            BackendEvent::Job(info) => {
                if info.command.starts_with("rewrite_") {
                    self.ai.wake = true;
                }
                self.rewrite_on_job(&info);
                self.on_job(*info);
            }
            BackendEvent::ProjectChanged => self.refresh_after_edit(),
            BackendEvent::EntryApplied(change) => {
                self.agent_activity.applied(&change, Instant::now());
                self.refresh_after_edit();
                if change.by_agent {
                    self.announce_agent_edit(change);
                }
            }
            BackendEvent::ProposalCreated(change) => {
                self.agent_activity.proposed(&change, Instant::now());
                self.refresh_proposals();
                self.refresh_project();
                self.refresh_history();
                let who = if change.author.is_empty() {
                    "An agent".to_string()
                } else {
                    format!("Agent {}", change.author)
                };
                self.toast(
                    ToastLevel::Info,
                    format!("{who} proposed a change. Review it in the Proposals tab."),
                );
            }
            BackendEvent::SidecarExited { restart_failed } => {
                if restart_failed {
                    self.toast(
                        ToastLevel::Error,
                        "The analysis engine stopped and could not be restarted. Your edits are saved and will be applied when it comes back.",
                    );
                } else {
                    self.toast(
                        ToastLevel::Warning,
                        "The analysis engine stopped. Restarting it...",
                    );
                }
            }
            BackendEvent::SidecarRestarted { replayed, rejected } => {
                let mut text = String::from("The analysis engine is back.");
                if replayed > 0 {
                    text.push_str(&format!(" {replayed} saved edit(s) were applied again."));
                }
                if rejected > 0 {
                    text.push_str(&format!(" The engine refused {rejected}."));
                }
                self.toast(ToastLevel::Info, text);
                self.refresh_all();
            }
            BackendEvent::Ai(view) => self.ai_on_event(*view),
            BackendEvent::JobStarted(change) => {
                self.ai.wake = true;
                self.agent_activity.job_started(&change, Instant::now());
            }
            BackendEvent::OpenProgress(p) => self.on_open_progress(*p),
            BackendEvent::Ui {
                action,
                tab,
                address,
                target,
                note,
                author,
            } => {
                if self.connection == Connection::Open {
                    if let Some(a) = address {
                        self.navigate_to(a);
                        self.focus_request =
                            Some(tab.clone().unwrap_or_else(|| "decompiler".into()));
                    } else if let Some(t) = tab {
                        self.focus_request = Some(t);
                    }
                    if let Some(a) = action {
                        self.ui_actions.push(a);
                    }
                    if let (Some(t), Some(n)) = (target, note) {
                        self.ui_highlights.push((t, n));
                    }
                    let who = if author.is_empty() {
                        "An agent".to_string()
                    } else {
                        format!("Agent {author}")
                    };
                    self.toast(ToastLevel::Info, format!("{who} is driving the window."));
                }
            }
            BackendEvent::Navigate {
                address,
                tab,
                author,
            } => {
                if self.connection == Connection::Open {
                    self.navigate_to(address);
                    self.focus_request = Some(tab.unwrap_or_else(|| "decompiler".into()));
                    let who = if author.is_empty() {
                        "An agent".to_string()
                    } else {
                        format!("Agent {author}")
                    };
                    self.toast(
                        ToastLevel::Info,
                        format!("{who} is showing you {address:#x}."),
                    );
                }
            }
            BackendEvent::SessionOpened | BackendEvent::SessionClosed(_) => {}
            BackendEvent::Disconnected(why) => {
                if self.link == LinkState::Connected {
                    self.toast(
                        ToastLevel::Error,
                        format!("Lost the connection to the engine: {why}. Reconnecting..."),
                    );
                }
                self.link = LinkState::Disconnected(why);
            }
            BackendEvent::Reconnected => {
                self.link = LinkState::Connected;
                self.toast(ToastLevel::Success, "Reconnected to the engine.");
                if self.connection == Connection::Open {
                    self.refresh_all();
                    self.refresh_job();
                }
            }
        }
    }

    /// The tab an agent asked the window to focus with `gui_navigate`, once. The window maps the
    /// name (`decompiler`, `listing`, `graph`, `hex`, `xrefs`, `functions`) to a tab.
    pub fn take_focus_request(&mut self) -> Option<String> {
        self.focus_request.take()
    }

    /// The GUI action ids agents asked for since the last call.
    pub fn take_ui_actions(&mut self) -> Vec<String> {
        std::mem::take(&mut self.ui_actions)
    }

    /// The tabs or widgets agents asked to flash, with their notes, since the last call.
    pub fn take_ui_highlights(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.ui_highlights)
    }

    /// The window reports its open tabs and the one in front; a change is published to the
    /// daemon so agents can read it with `ui_state`.
    pub fn set_ui_info(&mut self, tabs: Vec<String>, active: Option<String>) {
        let info = Some((tabs, active));
        if self.ui_info != info {
            self.ui_info = info;
            self.publish_selection();
        }
    }

    /// The window reports a dialog that agents can drive, described in a sentence (`None`: no
    /// such dialog is open); a change is published like the open tabs.
    pub fn set_ui_dialog(&mut self, dialog: Option<String>) {
        if self.ui_dialog != dialog {
            self.ui_dialog = dialog;
            self.publish_selection();
        }
    }

    /// Looks the agent's new log entries up and tells the person what changed, with an Undo.
    fn announce_agent_edit(&mut self, change: ChangeInfo) {
        let wanted: Vec<u64> = change
            .entry_ids
            .iter()
            .copied()
            .filter(|id| self.announced.insert(*id))
            .collect();
        if wanted.is_empty() {
            return;
        }
        self.call("history", json!({ "limit": 30 }), move |vm, res| {
            let Ok(page) = res.and_then(parse::<kraken_proto::Page<HistoryWire>>) else {
                return;
            };
            for h in page.items.into_iter().filter(|h| wanted.contains(&h.id)) {
                let text = agent_edit_text(&change.author, &h.op, &h.description.0);
                let run = h.run_id.clone().or_else(|| change.run_id.clone());
                let action = run.map(|run_id| ToastAction::UndoRun { run_id });
                vm.toast_with(ToastLevel::Info, text, action);
            }
        });
    }

    fn on_job(&mut self, info: JobInfo) {
        if info.command != "analyze" {
            return;
        }
        let new_phase = match info.status {
            JobState::Running => AnalysisPhase::Running,
            JobState::Succeeded => AnalysisPhase::Complete,
            JobState::Failed => AnalysisPhase::Failed,
            JobState::Cancelled => AnalysisPhase::Cancelled,
        };
        self.job_watch.last_activity = Instant::now();
        let same_job = self.analysis.job_id.as_deref() == Some(info.job_id.as_str());
        if info.status.is_terminal() && same_job && self.analysis.phase == new_phase {
            return;
        }
        // A `job_status` reply that was in flight when `job_done` arrived is older than it: a
        // finished job never goes back to running.
        if same_job && !info.status.is_terminal() && self.analysis.is_finished() {
            return;
        }
        self.analysis.job_id = Some(info.job_id.clone());
        self.analysis.phase = new_phase;
        match info.status {
            JobState::Running => {
                if info.progress.is_some() {
                    self.analysis.progress = info.progress;
                }
            }
            JobState::Succeeded => {
                self.analysis.progress = None;
                let n = info
                    .result
                    .as_ref()
                    .and_then(|r| r.get("function_count"))
                    .and_then(Value::as_u64);
                self.analysis.function_count = n.or(self.analysis.function_count);
                let text = match n {
                    Some(n) => format!("Analysis finished: {n} functions found."),
                    None => "Analysis finished.".to_string(),
                };
                self.toast(ToastLevel::Success, text);
                self.refresh_after_edit();
                self.assist_analysis_finished();
            }
            JobState::Failed => {
                self.analysis.progress = None;
                let why = info
                    .error
                    .as_ref()
                    .map_or_else(|| "unknown reason".to_string(), plain_error);
                self.analysis.error = Some(why.clone());
                self.toast(ToastLevel::Error, format!("Analysis failed: {why}"));
            }
            JobState::Cancelled => {
                self.analysis.progress = None;
                self.toast(
                    ToastLevel::Warning,
                    "Analysis cancelled. What it found so far is kept.",
                );
                self.refresh_after_edit();
            }
        }
    }

    // ---------------------------------------------------------------- functions list

    /// Reloads the function list from the first page.
    pub fn refresh_functions(&mut self) {
        self.fetch_functions(true);
    }

    /// Sets the name filter and reloads from the first page. Matching is case-insensitive
    /// substring, done by the backend.
    pub fn set_filter(&mut self, filter: impl Into<String>) {
        let filter = filter.into();
        if filter == self.functions.filter {
            return;
        }
        self.functions.filter = filter;
        self.fetch_functions(true);
    }

    /// Loads the next page if the list is near its end. `visible_end` is one past the last row on
    /// screen.
    pub fn ensure_loaded(&mut self, visible_end: usize) {
        if self.functions.has_more() && visible_end + 40 >= self.functions.items.len() {
            self.fetch_functions(false);
        }
    }

    fn fetch_functions(&mut self, reset: bool) {
        let l = &mut self.functions;
        if reset {
            l.generation += 1;
            l.next_cursor = None;
        } else if l.loading || l.next_cursor.is_none() {
            return;
        }
        l.loading = true;
        l.error = None;
        let generation = l.generation;
        let mut args = json!({ "limit": FUNCTION_PAGE });
        if !reset && let Some(c) = &l.next_cursor {
            args["cursor"] = json!(c);
        }
        if !l.filter.is_empty() {
            args["name_filter"] = json!(l.filter);
        }
        let filtered = !l.filter.is_empty();
        self.call("list_functions", args, move |vm, res| {
            if vm.functions.generation != generation {
                return;
            }
            vm.functions.loading = false;
            match res.and_then(parse::<FunctionPage>) {
                Ok(page) => {
                    if let Some(m) = page.items.iter().find_map(|f| f.module.clone()) {
                        vm.module = Some(m);
                    }
                    let rows: Vec<FunctionItem> = page.items.iter().map(function_item).collect();
                    let empty = rows.is_empty();
                    if reset {
                        vm.functions.items = rows;
                    } else {
                        vm.functions.items.extend(rows);
                    }
                    vm.functions.next_cursor = page.next_cursor;
                    vm.functions.total = page.total;
                    if filtered && empty && vm.functions.has_more() {
                        vm.fetch_functions(false);
                    }
                }
                Err(e) => vm.functions.error = Some(plain_error(&e)),
            }
        });
    }

    // ---------------------------------------------------------------- current function

    /// Shows the function at `addr` and records it in the back/forward history.
    pub fn navigate_to(&mut self, addr: u64) {
        self.nav.visit(addr);
        self.show(addr);
    }

    /// Alias of [`navigate_to`](Self::navigate_to) for list clicks.
    pub fn select_function(&mut self, addr: u64) {
        self.navigate_to(addr);
    }

    /// Goes to the previous function in the history.
    pub fn go_back(&mut self) {
        if let Some(a) = self.nav.back() {
            self.show(a);
        }
    }

    /// Goes to the next function in the history.
    pub fn go_forward(&mut self) {
        if let Some(a) = self.nav.forward() {
            self.show(a);
        }
    }

    fn show(&mut self, addr: u64) {
        self.show_place(addr);
    }

    /// Shows the function whose entry is `addr` in the decompiler.
    pub(crate) fn show_function(&mut self, addr: u64) {
        let name = self
            .functions
            .find(addr)
            .map_or_else(|| hex(addr), |f| f.name.clone());
        self.selected = Some(addr);
        self.current = Some(CurrentFunction {
            address: addr,
            name,
            detail: None,
            decompiled: Load::Loading,
            refreshing: false,
        });
        self.request_current();
        self.publish_selection();
    }

    /// Tells agents (through the daemon; the MCP resource `kraken://gui/selection`) which
    /// function and address the person is looking at. Fire and forget: a backend without a
    /// daemon ignores it, and a failure changes nothing on screen.
    pub(crate) fn publish_selection(&self) {
        let mut selection = match &self.current {
            Some(cur) => json!({
                "kind": "function",
                "function": hex(cur.address),
                "function_name": cur.name,
                "address": hex(self.views.cursor.unwrap_or(cur.address)),
            }),
            None if self.ui_info.is_some() => json!({"kind": "ui"}),
            None => return,
        };
        if let Some((tabs, active)) = &self.ui_info {
            selection["tabs"] = json!(tabs);
            selection["active_tab"] = json!(active);
            selection["actions"] = json!(
                crate::AppAction::ALL
                    .into_iter()
                    .chain(crate::AppAction::SETUP_STEPS)
                    .filter(|a| a.agent_allowed())
                    .map(|a| a.id())
                    .collect::<Vec<_>>()
            );
            if let Some(d) = &self.ui_dialog {
                selection["dialog"] = json!(d);
            }
        }
        let backend = self.backend.clone();
        self.rt.spawn(async move {
            let _ = backend.publish_selection(Some(selection)).await;
        });
    }

    /// Reloads the detail and decompilation of the function being viewed.
    pub fn refresh_current(&mut self) {
        if let Some(c) = &mut self.current {
            c.refreshing = true;
            self.request_current();
        }
    }

    fn request_current(&mut self) {
        let Some(addr) = self.current.as_ref().map(|c| c.address) else {
            return;
        };
        self.detail_seq += 1;
        self.decompile_seq += 1;
        let (dseq, cseq) = (self.detail_seq, self.decompile_seq);
        self.views_on_request(addr);
        let args = self.function_args(addr);
        self.call("get_function", args.clone(), move |vm, res| {
            if vm.detail_seq != dseq {
                return;
            }
            match res.and_then(parse::<DetailWire>) {
                Ok(d) => vm.apply_detail(addr, d),
                Err(e) => vm.toast_error(&e),
            }
        });
        self.call("decompile", args, move |vm, res| {
            if vm.decompile_seq != cseq {
                return;
            }
            let Some(cur) = vm.current.as_mut().filter(|c| c.address == addr) else {
                return;
            };
            cur.refreshing = false;
            match res.and_then(parse::<DecompileWire>) {
                Ok(w) => {
                    let name = cur.name.clone();
                    if let Some(m) = w.module.clone() {
                        vm.module = Some(m);
                    }
                    let d = vm.build_decompiled(addr, &name, w);
                    vm.note_decompiled(addr);
                    if let Some(cur) = vm.current.as_mut() {
                        cur.decompiled = Load::Ready(d);
                    }
                }
                Err(e) => cur.decompiled = Load::Failed(plain_error(&e)),
            }
        });
    }

    /// The arguments naming the function at `addr`: its address, plus the module for a .NET one.
    fn function_args(&self, addr: u64) -> Value {
        let mut args = json!({ "address": hex(addr) });
        if let Some(m) = &self.module {
            args["module"] = json!(m);
        }
        args
    }

    fn apply_detail(&mut self, addr: u64, d: DetailWire) {
        let detail = FunctionDetail {
            address: addr,
            name: d.function.name.0.clone(),
            signature: d.function.signature.as_ref().map(|s| s.0.clone()),
            calling_convention: d.calling_convention,
            size: d.function.size,
            comments: d
                .comments
                .into_iter()
                .map(|c| Comment {
                    kind: c.kind,
                    text: c.text.0,
                })
                .collect(),
            versions: d.versions,
        };
        if let Some(r) = self.rename.as_mut().filter(|r| r.address == addr) {
            r.versions = Some(detail.versions.clone());
            if !r.submitting {
                r.old_name = detail.name.clone();
            }
        }
        if let Some(c) = self.comment.as_mut().filter(|c| c.address == addr) {
            c.versions = Some(detail.versions.clone());
        }
        self.views_detail(addr, detail.size);
        if let Some(cur) = self.current.as_mut().filter(|c| c.address == addr) {
            cur.name = detail.name.clone();
            cur.detail = Some(detail);
        }
    }

    fn build_decompiled(&mut self, addr: u64, name: &str, w: DecompileWire) -> Decompiled {
        let mut targets: HashMap<String, u64> = w
            .references
            .iter()
            .map(|r| (r.name.0.clone(), r.address.0))
            .collect();
        targets.entry(name.to_string()).or_insert(addr);
        let text = w.text.0;
        let mut result = DecompileResult {
            function: crate::views::target_locator(addr, self.module.as_deref()),
            language: if w.language.is_empty() {
                "c".into()
            } else {
                w.language
            },
            tokens: if w.tokens.is_empty() {
                tokenize(&text, &targets)
            } else {
                crate::views::server_tokens(&text, &w.tokens)
            },
            text,
            warnings: Vec::new(),
            completeness: w.completeness.clone(),
        };
        if result.validate_tokens().is_err() {
            result.tokens.clear();
        }
        self.revision += 1;
        Decompiled {
            result,
            revision: self.revision,
            warnings: w
                .warnings
                .into_iter()
                .map(|w: Untrusted<String>| w.0)
                .collect(),
            truncated: w.truncated,
            partial_reason: match w.completeness {
                Completeness::Complete => None,
                Completeness::Partial { reason } => Some(reason),
                Completeness::NotAnalyzed => Some("this function has not been analyzed yet".into()),
            },
        }
    }

    // ---------------------------------------------------------------- rename

    /// Opens the rename dialog for `address`.
    pub fn begin_rename(&mut self, address: u64, name_hint: Option<&str>) {
        let name = name_hint
            .map(str::to_string)
            .or_else(|| self.functions.find(address).map(|f| f.name.clone()))
            .or_else(|| {
                self.current
                    .as_ref()
                    .filter(|c| c.address == address)
                    .map(|c| c.name.clone())
            })
            .unwrap_or_else(|| hex(address));
        let versions = self
            .current
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .filter(|d| d.address == address)
            .map(|d| d.versions.clone());
        let need_versions = versions.is_none();
        self.rename = Some(RenameDialog {
            address,
            input: name.clone(),
            old_name: name,
            error: None,
            notice: None,
            submitting: false,
            versions,
        });
        if need_versions {
            let args = self.function_args(address);
            self.call("get_function", args, move |vm, res| {
                if let Ok(d) = res.and_then(parse::<DetailWire>) {
                    vm.apply_rename_versions(address, d);
                }
            });
        }
    }

    fn apply_rename_versions(&mut self, address: u64, d: DetailWire) {
        if let Some(r) = self
            .rename
            .as_mut()
            .filter(|r| r.address == address && !r.submitting)
        {
            r.versions = Some(d.versions);
            // An address inside a function names a label, not the function around it.
            if d.function.address.0 == address {
                r.old_name = d.function.name.0;
            }
        }
    }

    /// Opens the rename dialog for the function being viewed.
    pub fn begin_rename_current(&mut self) {
        match self.current.as_ref().map(|c| (c.address, c.name.clone())) {
            Some((a, n)) => self.begin_rename(a, Some(&n)),
            None => self.toast(ToastLevel::Info, "Pick a function first, then rename it."),
        }
    }

    /// Updates the text in the rename dialog.
    pub fn set_rename_input(&mut self, text: impl Into<String>) {
        if let Some(r) = &mut self.rename {
            r.input = text.into();
            r.error = None;
        }
    }

    /// Closes the rename dialog without saving.
    pub fn cancel_rename(&mut self) {
        self.rename = None;
    }

    /// Sends the rename. Validation problems and server errors land in the dialog.
    pub fn submit_rename(&mut self) {
        let Some(r) = self.rename.as_mut().filter(|r| !r.submitting) else {
            return;
        };
        let name = match r.validate() {
            Ok(n) => n,
            Err(e) => {
                r.error = Some(e);
                return;
            }
        };
        r.submitting = true;
        r.error = None;
        r.notice = None;
        let address = r.address;
        let mut args = json!({ "address": hex(address), "new_name": name });
        if let Some(v) = &r.versions {
            args["expect_versions"] = expect(v, name_key(address));
        }
        self.call("rename_symbol", args, move |vm, res| {
            vm.rename_done(address, name, res);
        });
    }

    fn rename_done(&mut self, address: u64, name: String, res: Result<Value, ProtoError>) {
        match res.and_then(parse::<MutationWire>) {
            Ok(m) => {
                self.rename = None;
                self.toast_mutation(&m, &format!("Renamed to {name}."), "Rename");
                self.refresh_after_edit();
            }
            Err(e) => {
                let conflict = e.code == ErrorCode::ConflictStaleRead;
                if let Some(r) = self.rename.as_mut().filter(|r| r.address == address) {
                    r.submitting = false;
                    if conflict {
                        r.error = None;
                        r.notice = Some(
                            "Someone changed this name while you were typing. KRAKEN reloaded it; \
                             review the current name and press Rename again."
                                .into(),
                        );
                    } else {
                        r.error = Some(plain_error(&e));
                    }
                }
                if conflict {
                    let args = self.function_args(address);
                    self.call("get_function", args, move |vm, res| {
                        if let Ok(d) = res.and_then(parse::<DetailWire>) {
                            vm.apply_rename_versions(address, d);
                        }
                    });
                    self.refresh_functions();
                    self.refresh_current();
                    self.refresh_history();
                }
            }
        }
    }

    pub(crate) fn toast_mutation(&mut self, m: &MutationWire, done: &str, what: &str) {
        match m.status.as_str() {
            "queued" => self.toast(
                ToastLevel::Info,
                format!("{what} saved. It reaches the engine when analysis finishes."),
            ),
            "proposed" => self.toast(
                ToastLevel::Info,
                format!(
                    "{what} was sent as a proposal for review{}",
                    m.reason
                        .as_deref()
                        .map_or(".".to_string(), |r| format!(": {r}"))
                ),
            ),
            _ => self.toast(ToastLevel::Success, done),
        }
    }

    // ---------------------------------------------------------------- comments

    /// Opens the comment dialog for `address`.
    pub fn begin_comment(&mut self, address: u64, kind: CommentKind) {
        let detail = self
            .current
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .filter(|d| d.address == address);
        let input = detail
            .and_then(|d| d.comments.iter().find(|c| c.kind == kind))
            .map(|c| c.text.clone())
            .unwrap_or_default();
        self.comment = Some(CommentDialog {
            address,
            kind,
            input,
            error: None,
            submitting: false,
            versions: detail.map(|d| d.versions.clone()),
        });
    }

    /// Opens the comment dialog for the function being viewed.
    pub fn begin_comment_current(&mut self) {
        match self.current.as_ref().map(|c| c.address) {
            Some(a) => self.begin_comment(a, CommentKind::Plate),
            None => self.toast(
                ToastLevel::Info,
                "Pick a function first, then comment on it.",
            ),
        }
    }

    /// Updates the text in the comment dialog.
    pub fn set_comment_input(&mut self, text: impl Into<String>) {
        if let Some(c) = &mut self.comment {
            c.input = text.into();
            c.error = None;
        }
    }

    /// Switches the comment slot, loading that slot's existing text.
    pub fn set_comment_kind(&mut self, kind: CommentKind) {
        let existing = self
            .current
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .and_then(|d| d.comments.iter().find(|c| c.kind == kind))
            .map(|c| c.text.clone())
            .unwrap_or_default();
        if let Some(c) = &mut self.comment {
            c.kind = kind;
            c.input = existing;
            c.error = None;
        }
    }

    /// Closes the comment dialog without saving.
    pub fn cancel_comment(&mut self) {
        self.comment = None;
    }

    /// Saves the comment; empty text clears it.
    pub fn submit_comment(&mut self) {
        let Some(c) = self.comment.as_mut().filter(|c| !c.submitting) else {
            return;
        };
        if c.input.chars().count() > 4096 {
            c.error = Some("A comment can be at most 4096 characters.".into());
            return;
        }
        c.submitting = true;
        c.error = None;
        let (address, kind, text) = (c.address, c.kind, c.input.clone());
        let cleared = text.trim().is_empty();
        let mut args = json!({ "address": hex(address), "kind": kind, "text": text });
        if let Some(v) = &c.versions {
            args["expect_versions"] = expect(v, comment_key(address, kind));
        }
        self.call("set_comment", args, move |vm, res| {
            match res.and_then(parse::<MutationWire>) {
                Ok(m) => {
                    vm.comment = None;
                    let done = if cleared {
                        "Comment cleared."
                    } else {
                        "Comment saved."
                    };
                    vm.toast_mutation(&m, done, "Comment");
                    vm.refresh_current();
                    vm.refresh_history();
                    vm.refresh_project();
                }
                Err(e) => {
                    let conflict = e.code == ErrorCode::ConflictStaleRead;
                    if let Some(c) = vm.comment.as_mut().filter(|c| c.address == address) {
                        c.submitting = false;
                        c.error = Some(plain_error(&e));
                    }
                    if conflict {
                        vm.refresh_current();
                    }
                }
            }
        });
    }

    // ---------------------------------------------------------------- history

    /// Reloads the History tab from the newest entry.
    pub fn refresh_history(&mut self) {
        self.history.generation += 1;
        self.history.next_cursor = None;
        self.fetch_history(true);
    }

    /// Loads older history entries.
    pub fn load_more_history(&mut self) {
        if !self.history.loading && self.history.next_cursor.is_some() {
            self.fetch_history(false);
        }
    }

    fn fetch_history(&mut self, reset: bool) {
        self.history.loading = true;
        self.history.error = None;
        let generation = self.history.generation;
        let mut args = json!({ "limit": 100 });
        if !reset && let Some(c) = &self.history.next_cursor {
            args["cursor"] = json!(c);
        }
        self.call("history", args, move |vm, res| {
            if vm.history.generation != generation {
                return;
            }
            vm.history.loading = false;
            match res.and_then(parse::<kraken_proto::Page<HistoryWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(|h| HistoryEntry {
                        id: h.id,
                        op: h.op,
                        address: h.address.map(|a| a.0),
                        description: h.description.0,
                        by_agent: h.author.kind != "user",
                        who: who(&h.author),
                        run_id: h.run_id,
                        status: kind_of(&h.status),
                        sync: kind_of(&h.sync),
                        undone: h.undone_by.is_some(),
                        is_undo: h.undoes_entry_id.is_some(),
                        ts_ms: h.ts_ms,
                    });
                    if reset {
                        vm.history.entries = rows.collect();
                    } else {
                        vm.history.entries.extend(rows);
                    }
                    vm.history.next_cursor = page.next_cursor;
                }
                Err(e) => vm.history.error = Some(plain_error(&e)),
            }
        });
    }

    /// Undoes the user's most recent edit.
    pub fn undo_last(&mut self) {
        self.call("undo", json!({}), |vm, res| {
            vm.undo_done(res, "your last change")
        });
    }

    /// Undoes every edit of an agent run, newest first.
    pub fn undo_run(&mut self, run_id: impl Into<String>) {
        let run_id = run_id.into();
        let what = format!("run {run_id}");
        self.call("undo_run", json!({ "run_id": run_id }), move |vm, res| {
            vm.undo_done(res, &what);
        });
    }

    pub(crate) fn undo_done(&mut self, res: Result<Value, ProtoError>, what: &str) {
        match res.and_then(parse::<UndoWire>) {
            Ok(u) if u.undone_entry_ids.is_empty() => {
                self.toast(ToastLevel::Info, "There was nothing to undo.");
            }
            Ok(u) => {
                self.undo.note_stale(&u.tainted);
                let n = u.undone_entry_ids.len();
                let text = if u.status == "queued" {
                    format!("Undo of {what} is queued until analysis finishes.")
                } else if n == 1 {
                    format!("Undid {what}.")
                } else {
                    format!("Undid {n} changes from {what}.")
                };
                self.toast(ToastLevel::Success, text);
                if !u.failed.is_empty() {
                    self.toast(
                        ToastLevel::Warning,
                        format!(
                            "The engine refused {} part(s) of the undo; the project log still records them as undone.",
                            u.failed.len()
                        ),
                    );
                }
                self.refresh_after_edit();
            }
            Err(e) => self.toast_error(&e),
        }
    }

    // ---------------------------------------------------------------- proposals

    /// Reloads the open proposals.
    pub fn refresh_proposals(&mut self) {
        self.proposals.loading = true;
        self.proposals.error = None;
        self.call("proposals_list", json!({ "limit": 100 }), |vm, res| {
            vm.proposals.loading = false;
            match res.and_then(parse::<kraken_proto::Page<ProposalWire>>) {
                Ok(page) => {
                    vm.proposals.items = page
                        .items
                        .into_iter()
                        .map(|p| ProposalItem {
                            id: p.id,
                            op: p.op,
                            address: p.address.map(|a| a.0),
                            description: p.description.0,
                            reason: p.reason,
                            who: who(&p.author),
                            run_id: p.run_id,
                            ts_ms: p.ts_ms,
                        })
                        .collect();
                }
                Err(e) => vm.proposals.error = Some(plain_error(&e)),
            }
        });
    }

    /// Accepts a proposal; it is applied as the current user.
    pub fn accept_proposal(&mut self, id: u64) {
        self.call(
            "proposal_accept",
            json!({ "id": id }),
            |vm, res| match res {
                Ok(_) => {
                    vm.toast(ToastLevel::Success, "Proposal accepted and applied.");
                    vm.refresh_after_edit();
                }
                Err(e) => {
                    vm.toast_error(&e);
                    vm.refresh_proposals();
                }
            },
        );
    }

    /// Rejects a proposal.
    pub fn reject_proposal(&mut self, id: u64) {
        self.call(
            "proposal_reject",
            json!({ "id": id }),
            |vm, res| match res {
                Ok(_) => {
                    vm.toast(ToastLevel::Info, "Proposal rejected.");
                    vm.refresh_proposals();
                    vm.refresh_history();
                    vm.refresh_project();
                }
                Err(e) => {
                    vm.toast_error(&e);
                    vm.refresh_proposals();
                }
            },
        );
    }

    // ---------------------------------------------------------------- palette and actions

    /// Opens the command palette with fresh rows.
    pub fn open_palette(&mut self) {
        let cmds = self.backend.commands();
        self.palette.open_with(&cmds);
    }

    /// Closes the command palette.
    pub fn close_palette(&mut self) {
        self.palette.close();
    }

    /// Runs the highlighted palette row and closes the palette.
    pub fn activate_palette(&mut self) -> Option<UiRequest> {
        let item = self.palette.selected_item()?;
        self.palette.close();
        match item.target {
            PaletteTarget::Action(a) => self.perform(a),
            PaletteTarget::Command(name) => {
                self.open_command_form(&name);
                None
            }
        }
    }

    /// Runs an app action. Window-level actions come back as a [`UiRequest`].
    pub fn perform(&mut self, action: AppAction) -> Option<UiRequest> {
        let needs_project = matches!(
            action,
            AppAction::Analyze
                | AppAction::CancelAnalysis
                | AppAction::UndoLast
                | AppAction::RefreshAll
                | AppAction::Back
                | AppAction::Forward
                | AppAction::RenameCurrent
                | AppAction::CommentCurrent
                | AppAction::CloseProject
                | AppAction::GoToMain
                | AppAction::ExplainProgram
                | AppAction::RewriteWizard
                | AppAction::Automate
                | AppAction::GoTo
                | AppAction::Search
                | AppAction::Retype
                | AppAction::EditSignature
                | AppAction::CommentHere
                | AppAction::ShowReferences
                | AppAction::AddBookmark
                | AppAction::ShowBookmarks
                | AppAction::PatchHere
                | AppAction::ShowPatches
                | AppAction::ExportPatched
                | AppAction::CreateFunctionHere
                | AppAction::DeleteFunction
        );
        if needs_project && self.connection != Connection::Open {
            self.toast(ToastLevel::Info, "Open a project first.");
            return None;
        }
        match action {
            AppAction::Analyze => self.start_analysis(),
            AppAction::CancelAnalysis => self.cancel_analysis(),
            AppAction::UndoLast => self.undo_last_described(),
            AppAction::RefreshAll => self.refresh_all(),
            AppAction::Back => self.go_back(),
            AppAction::Forward => self.go_forward(),
            AppAction::RenameCurrent => self.begin_rename_current(),
            AppAction::CommentCurrent => self.begin_comment_current(),
            AppAction::ToggleTheme => return Some(UiRequest::ToggleTheme),
            AppAction::FocusFunctionFilter => return Some(UiRequest::FocusFunctionFilter),
            AppAction::ShowHistory => return Some(UiRequest::ShowHistory),
            AppAction::ShowProposals => return Some(UiRequest::ShowProposals),
            AppAction::OpenProject => return Some(UiRequest::OpenProject),
            AppAction::NewProject => return Some(UiRequest::NewProject),
            AppAction::OpenDemo => return Some(UiRequest::OpenDemo),
            AppAction::OpenSettings => return Some(UiRequest::OpenSettings),
            AppAction::CloseProject => return Some(UiRequest::CloseProject),
            AppAction::ClearRecent => return Some(UiRequest::ClearRecent),
            AppAction::Quit => return Some(UiRequest::Quit),
            AppAction::OpenPalette => self.open_palette(),
            AppAction::ToggleLearnMode => self.assist.learn_mode = !self.assist.learn_mode,
            AppAction::ShowShortcuts => return Some(UiRequest::ShowShortcuts),
            AppAction::OpenDocs => return Some(UiRequest::OpenDocs),
            AppAction::ShowHelp => return Some(UiRequest::ShowHelp),
            AppAction::TakeTour => return Some(UiRequest::TakeTour),
            AppAction::GoToMain => self.go_to_main(),
            AppAction::ExplainProgram => self.assist_overview(),
            AppAction::RewriteWizard => self.rewrite_wizard_open(),
            AppAction::Automate => return Some(UiRequest::OpenAutomate),
            AppAction::AskAboutKraken => return Some(UiRequest::AskAboutKraken),
            AppAction::SetUpLocalModel => return Some(UiRequest::SetUpLocalModel),
            AppAction::LocalSetupNext => {
                return Some(UiRequest::LocalSetup(crate::SetupButton::Next));
            }
            AppAction::LocalSetupBack => {
                return Some(UiRequest::LocalSetup(crate::SetupButton::Back));
            }
            AppAction::LocalSetupCancel => {
                return Some(UiRequest::LocalSetup(crate::SetupButton::Cancel));
            }
            AppAction::ShowAiActivity => {
                self.ai.wake = true;
                return Some(UiRequest::ShowAiActivity);
            }
            AppAction::GoTo => self.open_goto(),
            AppAction::Search => self.open_search(),
            AppAction::Retype => self.begin_retype_here(),
            AppAction::EditSignature => self.begin_edit_signature_current(),
            AppAction::CommentHere => self.begin_comment_here(),
            AppAction::ShowReferences => self.references_to_cursor(),
            AppAction::AddBookmark => self.begin_bookmark_here(),
            AppAction::ShowBookmarks => self.show_bookmarks(),
            AppAction::PatchHere => {
                if self.views.listing.selected_row().is_none() && self.views.hex.selection.is_some()
                {
                    self.begin_patch_bytes();
                } else {
                    self.begin_patch_instruction();
                }
            }
            AppAction::ShowPatches => self.show_patches(),
            AppAction::ExportPatched => self.begin_patch_export(),
            AppAction::CreateFunctionHere => self.begin_create_function_here(),
            AppAction::DeleteFunction => self.begin_delete_current(),
        }
        None
    }

    /// The function to open first: `main`, else the entry point, else the first function.
    pub fn main_function(&self) -> Option<u64> {
        let items = &self.functions.items;
        items
            .iter()
            .find(|f| f.name == "main")
            .or_else(|| {
                items
                    .iter()
                    .find(|f| matches!(f.name.as_str(), "_main" | "wmain" | "WinMain"))
            })
            .or_else(|| {
                items
                    .iter()
                    .find(|f| matches!(f.name.as_str(), "entry" | "_start" | "start"))
            })
            .or_else(|| items.first())
            .map(|f| f.address)
    }

    /// Opens [`main_function`](Self::main_function).
    pub fn go_to_main(&mut self) {
        match self.main_function() {
            Some(addr) => self.navigate_to(addr),
            None => self.toast(
                ToastLevel::Info,
                "No functions yet. Run Analyze to find them.",
            ),
        }
    }

    /// Asks the backend to release the open project (the daemon stops its engine). The answer
    /// is not waited for: the window drops this view-model right after.
    pub fn close_project(&mut self) {
        if self.connection != Connection::Open {
            return;
        }
        let backend = self.backend.clone();
        self.rt.spawn(async move {
            let _ = backend.call("project_close", json!({})).await;
        });
        self.connection = Connection::NoProject;
    }

    /// Entity versions of the function being viewed, as sent with edits.
    pub fn current_versions(&self) -> Option<&BTreeMap<String, u64>> {
        self.current
            .as_ref()
            .and_then(|c| c.detail.as_ref())
            .map(|d| &d.versions)
    }
}

impl Drop for ViewModel {
    fn drop(&mut self) {
        if let Some(t) = self.event_task.take() {
            t.abort();
        }
    }
}

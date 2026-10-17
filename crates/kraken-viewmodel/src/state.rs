//! Plain data the GUI renders. Everything here is owned, `Clone` and free of backend types.

use std::collections::BTreeMap;
use std::time::Instant;

use kraken_proto::{CommentKind, DecompileResult};

use crate::backend::JobProgress;

/// A function row in the Functions panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionItem {
    /// Entry address.
    pub address: u64,
    /// Display name (already sanitised by the registry).
    pub name: String,
    /// Body size in bytes.
    pub size: Option<u64>,
    /// Rendered signature.
    pub signature: Option<String>,
    /// True when analysis behind this row is incomplete.
    pub partial: bool,
    /// A library stub: an import thunk, PLT entry or C runtime startup stub, not program code.
    pub stub: bool,
}

/// True for functions that are plumbing rather than program code: import thunks, PLT entries
/// and the C runtime's `_init` / `_fini`. The engine reports no kind yet, so this goes by name,
/// signature and size.
pub fn is_library_stub(name: &str, size: Option<u64>, signature: Option<&str>) -> bool {
    let n = name.trim_start_matches('_');
    if matches!(n, "init" | "fini") {
        return true;
    }
    if ["thunk_", "j_", "imp_", "plt_"]
        .iter()
        .any(|p| n.starts_with(p))
        || name.ends_with("@plt")
        || name.ends_with("@PLT")
    {
        return true;
    }
    if signature.is_some_and(|s| s.to_ascii_lowercase().contains("thunk")) {
        return true;
    }
    // The size of a jump stub and the name of a runtime or libc entry: an import's PLT slot.
    // A tiny function with any other name may well be the program's own (a getter, say).
    size.is_some_and(|s| (1..=16).contains(&s))
        && (name.starts_with("__") || COMMON_IMPORTS.contains(&name))
}

/// Imports that show up as PLT stubs in most native programs.
const COMMON_IMPORTS: [&str; 48] = [
    "abort", "atoi", "calloc", "close", "exit", "fclose", "fflush", "fgets", "fopen", "fprintf",
    "fputs", "fread", "free", "fwrite", "getenv", "malloc", "memchr", "memcmp", "memcpy",
    "memmove", "memset", "open", "perror", "printf", "putchar", "puts", "qsort", "read", "realloc",
    "recv", "send", "snprintf", "socket", "sprintf", "strcat", "strchr", "strcmp", "strcpy",
    "strdup", "strlen", "strncmp", "strncpy", "strrchr", "strstr", "strtol", "usleep", "write",
    "sleep",
];

/// The paged, filterable function list.
#[derive(Debug, Clone, Default)]
pub struct FunctionList {
    /// Rows loaded so far, ordered by address.
    pub items: Vec<FunctionItem>,
    /// Cursor of the next page; `None` once everything is loaded.
    pub next_cursor: Option<String>,
    /// A page request is in flight.
    pub loading: bool,
    /// The filter the loaded rows match.
    pub filter: String,
    /// Total count when the backend knows it (unfiltered lists only).
    pub total: Option<u64>,
    /// Why the last load failed.
    pub error: Option<String>,
    pub(crate) generation: u64,
}

impl FunctionList {
    /// True when more pages can be fetched.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Position of `address` among the loaded rows.
    pub fn index_of(&self, address: u64) -> Option<usize> {
        self.items.iter().position(|f| f.address == address)
    }

    /// Indices of the rows to show, in order; with `hide_stubs` the library stubs are left out.
    pub fn visible(&self, hide_stubs: bool) -> Vec<usize> {
        (0..self.items.len())
            .filter(|&i| !(hide_stubs && self.items[i].stub))
            .collect()
    }

    /// Looks a loaded row up by address.
    pub fn find(&self, address: u64) -> Option<&FunctionItem> {
        self.items.iter().find(|f| f.address == address)
    }
}

/// Facts about the open project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectInfo {
    /// Short name (the binary's file name).
    pub name: String,
    /// Project directory.
    pub project_dir: String,
    /// Path of the analysed binary.
    pub binary_path: String,
    /// Architecture / language id.
    pub arch: String,
    /// Container format.
    pub format: String,
    /// Binary size in bytes.
    pub size: u64,
    /// Engine build string.
    pub engine_build: String,
    /// The engine behind the project: `ghidra`, `native` or `dotnet` (empty when unknown).
    pub engine: String,
    /// What was asked for at creation: `ghidra`, `native` or `auto`.
    pub engine_choice: Option<String>,
    /// Why that engine was picked, when the project recorded it.
    pub engine_reason: Option<String>,
    /// The engine cache no longer matches the project.
    pub epoch_stale: bool,
    /// Edits waiting to reach the engine.
    pub pending_entries: u64,
    /// Total edits in the log.
    pub log_entries: u64,
    /// Proposals waiting for a decision.
    pub open_proposals: u64,
}

/// Whether a project is open.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Connection {
    /// Nothing open: the welcome screen.
    #[default]
    NoProject,
    /// Opening or creating a project.
    Opening(String),
    /// A project is open.
    Open,
    /// Opening failed; the text says why.
    Failed(String),
}

/// A value that is fetched asynchronously.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Load<T> {
    /// Not requested.
    #[default]
    Idle,
    /// Request in flight.
    Loading,
    /// Loaded.
    Ready(T),
    /// Failed; plain-language reason.
    Failed(String),
}

impl<T> Load<T> {
    /// The loaded value.
    pub fn ready(&self) -> Option<&T> {
        match self {
            Load::Ready(v) => Some(v),
            _ => None,
        }
    }
}

/// Decompiler output ready to draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decompiled {
    /// Text and tokens.
    pub result: DecompileResult,
    /// Changes whenever the content changes; use as a render cache key.
    pub revision: u64,
    /// Decompiler warnings.
    pub warnings: Vec<String>,
    /// The text was cut at the size cap.
    pub truncated: bool,
    /// Set while analysis behind this result is incomplete.
    pub partial_reason: Option<String>,
}

/// A comment on a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// Which slot.
    pub kind: CommentKind,
    /// Text.
    pub text: String,
}

/// Details of the function being viewed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDetail {
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Signature.
    pub signature: Option<String>,
    /// Calling convention set through KRAKEN.
    pub calling_convention: Option<String>,
    /// Size in bytes.
    pub size: Option<u64>,
    /// Comments.
    pub comments: Vec<Comment>,
    /// Entity versions to send back as `expect_versions`.
    pub versions: BTreeMap<String, u64>,
}

/// The function in the Decompiler panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentFunction {
    /// Entry address.
    pub address: u64,
    /// Name (from the list or the detail, else the address).
    pub name: String,
    /// Detail once loaded.
    pub detail: Option<FunctionDetail>,
    /// Decompiler output.
    pub decompiled: Load<Decompiled>,
    /// A refresh is running while the old output stays visible.
    pub refreshing: bool,
}

/// State of the rename dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameDialog {
    /// Address being renamed.
    pub address: u64,
    /// Name when the dialog opened (or after the last refresh).
    pub old_name: String,
    /// What the person typed.
    pub input: String,
    /// Validation or server error, shown under the field.
    pub error: Option<String>,
    /// A friendly note, e.g. after a conflict refresh.
    pub notice: Option<String>,
    /// The request is in flight.
    pub submitting: bool,
    pub(crate) versions: Option<BTreeMap<String, u64>>,
}

/// State of the comment dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentDialog {
    /// Address being commented.
    pub address: u64,
    /// Comment slot.
    pub kind: CommentKind,
    /// What the person typed.
    pub input: String,
    /// Server error.
    pub error: Option<String>,
    /// The request is in flight.
    pub submitting: bool,
    pub(crate) versions: Option<BTreeMap<String, u64>>,
}

/// One edit in the History tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// Entry id.
    pub id: u64,
    /// Operation such as `rename`.
    pub op: String,
    /// Address edited.
    pub address: Option<u64>,
    /// One-line description.
    pub description: String,
    /// "you" or the agent's id.
    pub who: String,
    /// True for agent edits.
    pub by_agent: bool,
    /// Agent run the edit belongs to.
    pub run_id: Option<String>,
    /// `applied`, `rejected` or `orphaned`.
    pub status: String,
    /// `pending`, `pushed`, `engine_rejected`, ...
    pub sync: String,
    /// Reversed by a later entry.
    pub undone: bool,
    /// This entry is itself an undo.
    pub is_undo: bool,
    /// Milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

/// The History tab.
#[derive(Debug, Clone, Default)]
pub struct HistoryPanel {
    /// Newest first.
    pub entries: Vec<HistoryEntry>,
    /// Cursor for older entries.
    pub next_cursor: Option<String>,
    /// A request is in flight.
    pub loading: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    pub(crate) generation: u64,
}

/// One agent proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalItem {
    /// Proposal id.
    pub id: u64,
    /// Operation such as `rename`.
    pub op: String,
    /// Address concerned.
    pub address: Option<u64>,
    /// One-line description.
    pub description: String,
    /// Why it was not applied automatically.
    pub reason: String,
    /// Who proposed it.
    pub who: String,
    /// Run it came from.
    pub run_id: Option<String>,
    /// Milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

/// The Proposals tab.
#[derive(Debug, Clone, Default)]
pub struct ProposalsPanel {
    /// Open proposals, oldest first.
    pub items: Vec<ProposalItem>,
    /// A request is in flight.
    pub loading: bool,
    /// Why the last load failed.
    pub error: Option<String>,
}

/// Where analysis stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AnalysisPhase {
    /// Never run.
    #[default]
    NotStarted,
    /// Running now.
    Running,
    /// Finished.
    Complete,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

impl AnalysisPhase {
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "running" => AnalysisPhase::Running,
            "complete" => AnalysisPhase::Complete,
            "failed" => AnalysisPhase::Failed,
            "cancelled" => AnalysisPhase::Cancelled,
            _ => AnalysisPhase::NotStarted,
        }
    }
}

/// Analysis job progress for the top bar and status bar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnalysisState {
    /// Phase.
    pub phase: AnalysisPhase,
    /// The running or last job.
    pub job_id: Option<String>,
    /// Latest progress report.
    pub progress: Option<JobProgress>,
    /// Functions known after a finished run.
    pub function_count: Option<u64>,
    /// Why the run failed.
    pub error: Option<String>,
}

impl AnalysisState {
    /// Fraction done in the current stage, if running with a report.
    pub fn fraction(&self) -> Option<f32> {
        let p = self.progress.as_ref()?;
        (self.phase == AnalysisPhase::Running && p.total > 0)
            .then(|| (p.done as f32 / p.total as f32).clamp(0.0, 1.0))
    }

    /// True while a run is in progress.
    pub fn running(&self) -> bool {
        self.phase == AnalysisPhase::Running
    }

    /// True once the run ended, however it ended.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.phase,
            AnalysisPhase::Complete | AnalysisPhase::Failed | AnalysisPhase::Cancelled
        )
    }
}

/// How loud a toast is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastLevel {
    /// Neutral news.
    Info,
    /// Something worked.
    Success,
    /// Something to be careful about.
    Warning,
    /// Something failed.
    Error,
}

/// A button on a toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToastAction {
    /// Reverse every edit of an agent run.
    UndoRun {
        /// The run to undo.
        run_id: String,
    },
}

impl ToastAction {
    /// Button text.
    pub fn label(&self) -> &'static str {
        match self {
            ToastAction::UndoRun { .. } => "Undo",
        }
    }
}

/// Whether the connection to the daemon is up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LinkState {
    /// Working (also the state of backends that cannot disconnect).
    #[default]
    Connected,
    /// The daemon connection is gone and being re-established.
    Disconnected(String),
}

/// A transient notification.
#[derive(Debug, Clone)]
pub struct Toast {
    /// Id for dismissal.
    pub id: u64,
    /// Level.
    pub level: ToastLevel,
    /// Plain-language text.
    pub text: String,
    /// A button shown on the toast.
    pub action: Option<ToastAction>,
    pub(crate) created: Instant,
}

impl Toast {
    pub(crate) fn lifetime(&self) -> std::time::Duration {
        if self.action.is_some() {
            return std::time::Duration::from_secs(12);
        }
        match self.level {
            ToastLevel::Error => std::time::Duration::from_secs(12),
            ToastLevel::Warning => std::time::Duration::from_secs(8),
            _ => std::time::Duration::from_secs(4),
        }
    }
}

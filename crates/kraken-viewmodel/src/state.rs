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

    /// The loaded function whose body (entry plus size) holds `address`.
    pub fn containing(&self, address: u64) -> Option<&FunctionItem> {
        self.items.iter().find(|f| {
            f.size
                .is_some_and(|n| (f.address..f.address.saturating_add(n.max(1))).contains(&address))
        })
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
    /// Fraction done, if running with a count: the stage's when it counts functions, else the
    /// current step's (a Ghidra analyzer's) when it gives one. A stage that only counts its
    /// sub-stages ("0 of 2") has no meaningful fraction.
    pub fn fraction(&self) -> Option<f32> {
        let p = self.progress.as_ref()?;
        if self.phase != AnalysisPhase::Running {
            return None;
        }
        let f = |d: u64, t: u64| (d as f32 / t as f32).clamp(0.0, 1.0);
        if p.total > 3 {
            return Some(f(p.done, p.total));
        }
        p.step
            .as_ref()
            .filter(|s| s.total > 0)
            .map(|s| f(s.done, s.total))
    }

    /// The step running inside the stage: `GCC Exception Handlers  31,200 of 58,000`.
    pub fn step_text(&self) -> Option<String> {
        let s = self.progress.as_ref()?.step.as_ref()?;
        let name = s.name.trim();
        if name.is_empty() {
            return None;
        }
        Some(if s.total > 0 {
            format!(
                "{name}  {} of {}",
                crate::loading::thousands(s.done.min(s.total)),
                crate::loading::thousands(s.total)
            )
        } else {
            name.to_string()
        })
    }

    /// How long the run has taken: `45s`, `6m 40s`, `1h 12m`.
    pub fn elapsed_text(&self) -> Option<String> {
        let ms = self.progress.as_ref()?.elapsed_ms?;
        Some(duration_words(ms / 1000))
    }

    /// Whether the engine is visibly working, from its processor use.
    pub fn liveness(&self) -> Option<Liveness> {
        let a = self.progress.as_ref()?.activity?;
        Some(if a.quiet_secs >= QUIET_WARNING_SECS {
            Liveness::Quiet { secs: a.quiet_secs }
        } else {
            Liveness::Busy {
                cpu_percent: a.cpu_percent,
            }
        })
    }

    /// The stages with where the run is: done, running or waiting.
    pub fn stage_list(&self) -> Vec<(&'static str, StageState)> {
        const STAGES: [(&str, &str); 3] = [
            ("load", "Load the program"),
            ("core", "Analyze (find functions, references, types)"),
            ("expensive", "Decompile every function"),
        ];
        let current = self.progress.as_ref().map(|p| p.phase.as_str());
        let at = current.and_then(|c| STAGES.iter().position(|(k, _)| *k == c));
        STAGES
            .iter()
            .enumerate()
            .map(|(i, (_, label))| {
                let state = match at {
                    Some(a) if i < a => StageState::Done,
                    Some(a) if i == a => StageState::Running,
                    _ => StageState::Waiting,
                };
                (*label, state)
            })
            .collect()
    }

    /// True while a run is in progress.
    pub fn running(&self) -> bool {
        self.phase == AnalysisPhase::Running
    }

    /// The running stage in words, such as `Decompiling every function`.
    pub fn stage_label(&self) -> Option<String> {
        let p = self.progress.as_ref()?;
        Some(
            match p.phase.as_str() {
                "load" => "Loading the program",
                "core" => "Finding references and strings",
                "expensive" => "Decompiling every function",
                other => other,
            }
            .to_string(),
        )
    }

    /// `1,234 of 11,270`, when the stage counts functions (more than a handful of steps).
    pub fn counts_text(&self) -> Option<String> {
        let p = self.progress.as_ref()?;
        (p.total > 3).then(|| {
            format!(
                "{} of {}",
                crate::loading::thousands(p.done),
                crate::loading::thousands(p.total)
            )
        })
    }

    /// True once the run ended, however it ended.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.phase,
            AnalysisPhase::Complete | AnalysisPhase::Failed | AnalysisPhase::Cancelled
        )
    }
}

/// Seconds without processor use or progress after which the engine is said to be quiet.
pub const QUIET_WARNING_SECS: u64 = 60;

/// Whether the engine is visibly working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// It is using the processor (or reported progress lately).
    Busy {
        /// Percent of one core.
        cpu_percent: u32,
    },
    /// No processor use and no progress for this long: stuck, or waiting on something.
    Quiet {
        /// Seconds.
        secs: u64,
    },
}

/// Where the run is with one stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageState {
    /// Finished.
    Done,
    /// Running now.
    Running,
    /// Not started yet.
    Waiting,
}

/// `45s`, `6m 40s`, `1h 12m`.
pub fn duration_words(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {:02}s", s / 60, s % 60),
        s => format!("{}h {:02}m", s / 3600, (s % 3600) / 60),
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
    /// Bring the History tab forward.
    OpenHistory,
    /// Bring the AI Activity tab forward.
    OpenAiActivity,
}

impl ToastAction {
    /// Button text.
    pub fn label(&self) -> &'static str {
        match self {
            ToastAction::UndoRun { .. } => "Undo",
            ToastAction::OpenHistory => "Open History",
            ToastAction::OpenAiActivity => "AI activity",
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

#[cfg(test)]
mod analysis_progress_tests {
    use super::*;
    use crate::backend::{EngineActivity, JobProgress, JobStep};

    fn running(p: JobProgress) -> AnalysisState {
        AnalysisState {
            phase: AnalysisPhase::Running,
            job_id: Some("job-1".into()),
            progress: Some(p),
            function_count: None,
            error: None,
        }
    }

    #[test]
    fn a_ghidra_stage_shows_its_analyzer_time_and_activity() {
        let a = running(JobProgress {
            phase: "core".into(),
            done: 0,
            total: 2,
            message: "GCC Exception Handlers".into(),
            step: Some(JobStep {
                name: "GCC Exception Handlers".into(),
                done: 31_200,
                total: 58_000,
            }),
            elapsed_ms: Some(400_000),
            activity: Some(EngineActivity {
                cpu_percent: 97,
                quiet_secs: 0,
            }),
        });
        assert_eq!(
            a.step_text().as_deref(),
            Some("GCC Exception Handlers  31,200 of 58,000")
        );
        let f = a.fraction().expect("the step's count");
        assert!((f - 31_200.0 / 58_000.0).abs() < 1e-4);
        assert_eq!(a.elapsed_text().as_deref(), Some("6m 40s"));
        assert_eq!(a.liveness(), Some(Liveness::Busy { cpu_percent: 97 }));
        let stages = a.stage_list();
        assert_eq!(stages[0].1, StageState::Done);
        assert_eq!(stages[1].1, StageState::Running);
        assert_eq!(stages[2].1, StageState::Waiting);
    }

    #[test]
    fn a_silent_engine_is_called_quiet_and_a_stage_count_is_no_fraction() {
        let a = running(JobProgress {
            phase: "core".into(),
            total: 2,
            activity: Some(EngineActivity {
                cpu_percent: 0,
                quiet_secs: 125,
            }),
            ..Default::default()
        });
        assert_eq!(a.fraction(), None);
        assert_eq!(a.step_text(), None);
        assert_eq!(a.liveness(), Some(Liveness::Quiet { secs: 125 }));
        assert_eq!(duration_words(125), "2m 05s");
        assert_eq!(duration_words(4000), "1h 06m");
    }
}

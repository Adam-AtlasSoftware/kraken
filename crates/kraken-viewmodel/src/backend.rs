//! The seam between the view-model and whatever runs KRAKEN commands.
//!
//! The in-process backend ([`crate::InProcessBackend`]) runs the registry inside the GUI process;
//! the daemon client implements the same trait over the IPC socket.

use async_trait::async_trait;
use kraken_proto::ProtoError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

/// How a command behaves; mirrors the registry's command kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    /// Reads state.
    Query,
    /// Edits the project.
    Mutation,
    /// Starts long work and returns a job id.
    Job,
    /// Produces a stream of events.
    Stream,
}

/// Who may run a command without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read-only.
    Safe,
    /// Changes the project.
    Mutating,
    /// Always asks for approval first.
    Dangerous,
}

/// One command a backend offers, as shown in the command palette.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandInfo {
    /// snake_case command name.
    pub name: String,
    /// One-line summary.
    pub summary: String,
    /// Command kind.
    pub kind: CommandKind,
    /// Permission class.
    pub permission: Permission,
}

/// Where a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Still working.
    Running,
    /// Finished with a result.
    Succeeded,
    /// Finished with an error.
    Failed,
    /// Ended because it was cancelled.
    Cancelled,
}

impl JobState {
    /// True once the job has ended.
    pub fn is_terminal(self) -> bool {
        self != JobState::Running
    }
}

/// Latest progress report of a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobProgress {
    /// Phase name such as an analysis stage.
    pub phase: String,
    /// Work units done in the phase.
    pub done: u64,
    /// Work units in the phase.
    pub total: u64,
    /// Human-readable status.
    #[serde(default)]
    pub message: String,
}

/// A job as the `job_status` command shows it; also the payload of [`BackendEvent::Job`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobInfo {
    /// Job id such as `job-1`.
    pub job_id: String,
    /// Command that started it.
    pub command: String,
    /// Current state.
    pub status: JobState,
    /// Latest progress.
    #[serde(default)]
    pub progress: Option<JobProgress>,
    /// Command-specific result once succeeded.
    #[serde(default)]
    pub result: Option<Value>,
    /// Why the job failed or was cancelled.
    #[serde(default)]
    pub error: Option<ProtoError>,
}

/// Who made a change another client reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeInfo {
    /// Command that made the change (`rename_symbol`, ...).
    pub command: String,
    /// True when an agent (not a person) made it.
    pub by_agent: bool,
    /// User name or agent id.
    pub author: String,
    /// Agent run the change belongs to.
    pub run_id: Option<String>,
    /// Log entries the change created or undid; empty for a proposal.
    pub entry_ids: Vec<u64>,
    /// Entity key such as `native:ram:0x401000:name`.
    pub key: Option<String>,
}

/// Something that happened outside a call the view-model made itself.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendEvent {
    /// A job made progress or ended.
    Job(JobInfo),
    /// Another client changed the project; panels should refresh.
    ProjectChanged,
    /// Somebody (a person in another window, an agent over MCP) edited the open project.
    EntryApplied(ChangeInfo),
    /// An agent edit was held back as a proposal for review.
    ProposalCreated(ChangeInfo),
    /// The analysis engine behind the project ended.
    SidecarExited {
        /// True when it also could not be restarted.
        restart_failed: bool,
    },
    /// The analysis engine came back; queued edits were replayed.
    SidecarRestarted {
        /// Edits pushed again.
        replayed: u64,
        /// Edits the engine refused on replay.
        rejected: u64,
    },
    /// The daemon opened a session for the open project.
    SessionOpened,
    /// The daemon closed the project's session (`idle`, `evicted`, `shutdown`).
    SessionClosed(String),
    /// The connection to the engine or daemon is gone; the backend keeps trying to reconnect.
    Disconnected(String),
    /// The connection is back; everything shown should be reloaded.
    Reconnected,
    /// A client started a job; `by_agent` says whether it was an agent (`key` is the job id).
    JobStarted(ChangeInfo),
    /// The project being created or opened made progress.
    OpenProgress(Box<kraken_proto::OpenProgress>),
    /// AI work in the daemon started, made model calls or ended.
    Ai(Box<kraken_proto::AiJobView>),
    /// An agent drove the GUI (`ui_action`, `ui_highlight`).
    Ui {
        /// GUI action id to run.
        action: Option<String>,
        /// Tab to open and focus.
        tab: Option<String>,
        /// Address to show.
        address: Option<u64>,
        /// Tab or widget to flash.
        target: Option<String>,
        /// Note to show with the flash.
        note: Option<String>,
        /// Agent id that asked.
        author: String,
    },
    /// An agent asked the GUI to show an address (`gui_navigate`).
    Navigate {
        /// Address to show.
        address: u64,
        /// Tab to focus (`decompiler`, `listing`, `graph`, `hex`, `xrefs`, `functions`).
        tab: Option<String>,
        /// Agent id that asked.
        author: String,
    },
}

/// A dangerous command waiting for the person's decision.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalPrompt {
    /// Command name.
    pub command: String,
    /// One-line summary of the command.
    pub summary: String,
    /// The arguments it will run with.
    pub args: Value,
}

/// Asks the person whether a dangerous command may run (decision 16: the client asks, the
/// daemon never decides).
#[async_trait]
pub trait Approver: Send + Sync {
    /// True when the person allowed `prompt`.
    async fn approve(&self, prompt: ApprovalPrompt) -> bool;
}

/// Who a command runs for when it is not the GUI user: the built-in assistant's tool calls are
/// logged under its own agent id and run id, never as the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallAs {
    /// True for an agent, false for a person.
    pub agent: bool,
    /// Agent id or user name.
    pub id: String,
    /// Agent run the call belongs to.
    pub run_id: Option<String>,
    /// The caller already has the person's (or the danger mode's) yes for a dangerous command;
    /// false means a dangerous command is refused.
    pub approved: bool,
}

/// Runs KRAKEN commands for the GUI.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Runs `command` with JSON `args` as the GUI user and returns its JSON output.
    async fn call(&self, command: &str, args: Value) -> Result<Value, ProtoError>;

    /// Runs `command` as somebody other than the GUI user (the assistant). Backends that cannot
    /// attribute a call refuse it, so an agent edit is never recorded as the person's.
    async fn call_as(&self, who: &CallAs, command: &str, args: Value) -> Result<Value, ProtoError> {
        let _ = (command, args);
        Err(ProtoError::new(
            kraken_proto::ErrorCode::Unsupported,
            format!("this backend cannot run commands as `{}`", who.id),
        ))
    }

    /// Tells agents what the person is looking at (a `GuiSelection` as JSON, or `None` for
    /// nothing). Only a backend that reaches a daemon can; others ignore it.
    async fn publish_selection(&self, selection: Option<Value>) -> Result<(), ProtoError> {
        let _ = selection;
        Ok(())
    }

    /// The commands this backend offers.
    fn commands(&self) -> Vec<CommandInfo>;

    /// A fresh receiver of backend events.
    fn events(&self) -> broadcast::Receiver<BackendEvent>;
}

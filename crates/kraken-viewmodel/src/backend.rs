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

/// Something that happened outside a call the view-model made itself.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendEvent {
    /// A job made progress or ended.
    Job(JobInfo),
    /// Another client changed the project; panels should refresh.
    ProjectChanged,
    /// The connection to the engine or daemon is gone.
    Disconnected(String),
}

/// Runs KRAKEN commands for the GUI.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Runs `command` with JSON `args` as the GUI user and returns its JSON output.
    async fn call(&self, command: &str, args: Value) -> Result<Value, ProtoError>;

    /// The commands this backend offers.
    fn commands(&self) -> Vec<CommandInfo>;

    /// A fresh receiver of backend events.
    fn events(&self) -> broadcast::Receiver<BackendEvent>;
}

//! Per-call context: who calls, from where, and how dangerous commands get approved.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_engine::CancellationToken;
use kraken_model::{Author, RunId};
use serde::{Deserialize, Serialize};

/// The client surface a call arrives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// The command line.
    Cli,
    /// An MCP server.
    Mcp,
    /// The GUI.
    Gui,
    /// Tests and embedding code.
    Test,
}

/// What a surface shows the person when a dangerous command asks for approval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Command name.
    pub command: String,
    /// One-line description of the command.
    pub summary: String,
    /// The arguments the command would run with.
    pub args: serde_json::Value,
    /// Who asks.
    pub author: Author,
    /// Where the call came from.
    pub surface: Surface,
}

/// Answer of an [`ApprovalRequester`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecision {
    /// Run the command.
    Allow,
    /// Refuse; the reason is shown to the caller.
    Deny {
        /// Why the command was refused.
        reason: String,
    },
}

/// Asks a person (GUI dialog, CLI prompt, MCP elicitation) whether a dangerous command may run
/// (decisions 37, 77).
#[async_trait]
pub trait ApprovalRequester: Send + Sync {
    /// Decides on `req`. Must not hang forever; surfaces time out into a denial.
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision;
}

/// The default requester: denies with an explanation, as when no GUI or CLI prompt is attached.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyApprover;

#[async_trait]
impl ApprovalRequester for DenyApprover {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Deny {
            reason: format!(
                "`{}` is a dangerous command and no approval channel is attached on the {:?} surface; \
                 attach a GUI or run it from an interactive CLI to approve it",
                req.command, req.surface
            ),
        }
    }
}

/// Approves everything; for `--yes` style CLI flags and tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoApprove;

#[async_trait]
impl ApprovalRequester for AutoApprove {
    async fn request(&self, _req: ApprovalRequest) -> ApprovalDecision {
        ApprovalDecision::Allow
    }
}

/// Everything a command needs to know about its caller.
#[derive(Clone)]
pub struct CallContext {
    /// Who makes the call; edits are logged under this author.
    pub author: Author,
    /// The agent run the call belongs to, if any. Agents without a run share a per-agent run.
    pub run_id: Option<RunId>,
    /// Where the call came from.
    pub surface: Surface,
    /// Asked before a dangerous command runs.
    pub approval: Arc<dyn ApprovalRequester>,
    /// Fires when the caller gives up.
    pub cancel: CancellationToken,
    /// Identity the auto-apply cap of an agent is counted under, across runs and connections.
    /// The daemon sets it from the agent credential, so reconnecting does not start a fresh
    /// quota; without one the cap counts per run id only.
    pub quota_key: Option<String>,
    /// True once the call went through `project_gate` (the daemon runs it before it creates a
    /// session), so `project_create` and `project_open` do not ask a second time.
    pub gate_passed: bool,
    /// Hears the progress of `project_create` and `project_open` while they run.
    pub open_progress: Option<OpenProgressSink>,
}

/// Receives the progress of opening a project.
pub type OpenProgressSink = Arc<dyn Fn(&kraken_proto::OpenProgress) + Send + Sync>;

impl CallContext {
    /// A context for a human on `surface`, with the default deny-by-default approval.
    pub fn user(id: impl Into<String>, surface: Surface) -> Self {
        CallContext {
            author: Author::user(id),
            run_id: None,
            surface,
            approval: Arc::new(DenyApprover),
            cancel: CancellationToken::new(),
            quota_key: None,
            gate_passed: false,
            open_progress: None,
        }
    }

    /// A context for an agent run on `surface`.
    pub fn agent(id: impl Into<String>, run_id: impl Into<String>, surface: Surface) -> Self {
        CallContext {
            author: Author::agent(id),
            run_id: Some(RunId(run_id.into())),
            surface,
            approval: Arc::new(DenyApprover),
            cancel: CancellationToken::new(),
            quota_key: None,
            gate_passed: false,
            open_progress: None,
        }
    }

    /// True when an agent or the MCP surface is calling: whoever it is, they act on a person's
    /// behalf and a person must approve what reaches outside the open project.
    pub fn needs_user_approval(&self) -> bool {
        self.author.kind == kraken_model::AuthorKind::Agent || self.surface == Surface::Mcp
    }

    /// Marks the call as having passed `project_gate`.
    pub fn with_gate_passed(mut self) -> Self {
        self.gate_passed = true;
        self
    }

    /// Sets the identity the agent's auto-apply cap is counted under.
    pub fn with_quota_key(mut self, key: impl Into<String>) -> Self {
        self.quota_key = Some(key.into());
        self
    }

    /// Asks for approval of `command` when [`needs_user_approval`](Self::needs_user_approval);
    /// a person (GUI, CLI) is never asked.
    pub async fn require_approval(
        &self,
        command: &str,
        summary: String,
        args: serde_json::Value,
    ) -> Result<(), kraken_proto::ProtoError> {
        if !self.needs_user_approval() {
            return Ok(());
        }
        let decision = self
            .approval
            .request(ApprovalRequest {
                command: command.to_string(),
                summary,
                args,
                author: self.author.clone(),
                surface: self.surface,
            })
            .await;
        match decision {
            ApprovalDecision::Allow => Ok(()),
            ApprovalDecision::Deny { reason } => Err(kraken_proto::ProtoError::new(
                kraken_proto::ErrorCode::Unsupported,
                format!("approval denied: {reason}"),
            )
            .with_details(serde_json::json!({ "approval": "denied" }))),
        }
    }

    /// Replaces the approval requester.
    pub fn with_approval(mut self, approval: Arc<dyn ApprovalRequester>) -> Self {
        self.approval = approval;
        self
    }

    /// Replaces the cancellation token.
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Sends the progress of `project_create` and `project_open` to `sink`.
    pub fn with_open_progress(mut self, sink: OpenProgressSink) -> Self {
        self.open_progress = Some(sink);
        self
    }
}

impl std::fmt::Debug for CallContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallContext")
            .field("author", &self.author)
            .field("run_id", &self.run_id)
            .field("surface", &self.surface)
            .finish_non_exhaustive()
    }
}

//! Tool host abstraction. The command registry implements [`ToolHost`] later.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

/// How dangerous a tool is. Decided by the host, never by the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read-only.
    Safe,
    /// Writes that the host turns into additive proposals/log entries.
    Mutating,
    /// Never auto-called: requires explicit user approval each time.
    Dangerous,
}

/// What the host decides about one call, before it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run it.
    Allow,
    /// Ask the person first.
    Ask,
    /// Refuse it; the reason goes to the model as the tool's error.
    Deny(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub permission: Permission,
}

/// Per-call context passed to the host.
#[derive(Debug, Clone)]
pub struct ToolCtx {
    pub run_id: String,
    pub call_id: String,
    pub cancel: CancellationToken,
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("unknown tool `{0}`")]
    NotFound(String),
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
    #[error("{0}")]
    Failed(String),
    #[error("cancelled")]
    Cancelled,
}

#[async_trait]
pub trait ToolHost: Send + Sync {
    fn tools(&self) -> Vec<ToolSpec>;
    /// Whether this call runs, needs approval, or is refused. The default follows the tool's
    /// [`Permission`]: `Safe` and `Mutating` run, `Dangerous` asks. A host that can tell a
    /// harmless call from a risky one of the same tool overrides it. Wrappers forward it.
    fn decide(&self, name: &str, _args: &Value) -> Decision {
        match self.tools().iter().find(|t| t.name == name) {
            Some(t) if t.permission == Permission::Dangerous => Decision::Ask,
            _ => Decision::Allow,
        }
    }
    async fn call(&self, name: &str, args: Value, ctx: &ToolCtx) -> Result<Value, ToolError>;
}

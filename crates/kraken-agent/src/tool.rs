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
    async fn call(&self, name: &str, args: Value, ctx: &ToolCtx) -> Result<Value, ToolError>;
}

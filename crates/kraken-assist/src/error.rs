//! Errors of the assistant core.

use kraken_agent::AgentError;
use kraken_proto::ProtoError;

/// Why an assistant task could not start or finish.
#[derive(Debug, thiserror::Error)]
pub enum AssistError {
    /// No `[provider]` table is configured; the message explains how to add one.
    #[error("{0}")]
    NoProvider(String),
    /// The provider configuration is unusable.
    #[error("provider configuration: {0}")]
    Config(String),
    /// The provider could not be built or failed.
    #[error("provider: {0}")]
    Provider(#[from] AgentError),
    /// The task input is not valid (bad address, empty selection, ...).
    #[error("{0}")]
    BadInput(String),
    /// A registry command failed outside the agent loop.
    #[error("{}", .0.message)]
    Command(ProtoError),
}

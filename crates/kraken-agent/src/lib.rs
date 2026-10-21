//! KRAKEN built-in agent: provider abstraction, tool host abstraction and the agent loop.
//!
//! Safety model (decision 61): tool output is always passed to the model inside a delimited
//! `<tool_result>` block and never interpolated into the system prompt; which tools may run
//! is decided by the host's [`ToolSpec::permission`], never by model or tool output; dangerous
//! tools need explicit approval each call; text shown to users is run through
//! [`kraken_proto::sanitize`].
//!
//! Known limitation: streamed text is sanitised per chunk, so an ANSI escape sequence split
//! across two chunks can leave its tail visible. The final history copy is sanitised whole.

pub mod agent;
pub mod config;
pub mod error;
pub mod low_context;
pub mod models;
pub mod provider;
pub mod safety;
pub mod thinking;
pub mod tool;
pub mod types;

pub use agent::{
    Agent, AgentConfig, AgentEvent, AgentRun, ApprovalDecision, ApprovalHandle, StopReason,
};
pub use config::{EnvSecrets, Keyring, LayeredSecrets, ProviderConfig, SecretRef, SecretResolver};
pub use error::AgentError;
pub use low_context::{LowContextHost, TOOL_HELP};
pub use models::{ModelList, ModelSource, builtin_models, model_choices};
pub use provider::ChatProvider;
pub use provider::local::{LocalEndpoint, LocalProvider, LocalResolver};
pub use provider::replay::{
    Cassette, CassetteEntry, Fingerprint, RecordingProvider, ReplayProvider,
};
pub use thinking::{Effort, ThinkingConfig};
pub use tool::{Permission, ToolCtx, ToolError, ToolHost, ToolSpec};
pub use types::{
    ChatRequest, ChatStream, Completion, FinishReason, Message, ProviderInfo, StreamAssembler,
    StreamEvent, ToolCall, Usage,
};

#[cfg(test)]
mod tests;

//! Provider-neutral chat types.

use std::pin::Pin;

use futures_util::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AgentError;
use crate::tool::ToolSpec;

/// A fully assembled tool call requested by the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// One conversation message. The system prompt travels separately in [`ChatRequest`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum Message {
    User {
        content: String,
    },
    Assistant {
        #[serde(default)]
        content: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tool_calls: Vec<ToolCall>,
    },
    ToolResult {
        tool_call_id: String,
        name: String,
        /// Already delimited text (see [`crate::safety::wrap_tool_result`]).
        content: String,
        #[serde(default)]
        is_error: bool,
    },
}

impl Message {
    pub fn user(content: impl Into<String>) -> Self {
        Message::User {
            content: content.into(),
        }
    }
}

/// A request to a chat provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChatRequest {
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

/// Token usage reported by a provider.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

impl Usage {
    pub fn total(&self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }

    pub fn add(&mut self, other: Usage) {
        self.input_tokens = self.input_tokens.saturating_add(other.input_tokens);
        self.output_tokens = self.output_tokens.saturating_add(other.output_tokens);
    }
}

/// Static description of a configured provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub id: String,
    pub model: String,
    pub supports_tools: bool,
    pub context_window: Option<u32>,
}

/// Why a model turn ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolCalls,
    Length,
    Other,
}

/// One streaming delta. Tool calls arrive as fragments keyed by `index`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamEvent {
    TextDelta {
        text: String,
    },
    ToolCallDelta {
        index: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default)]
        arguments: String,
    },
    Usage(Usage),
    Finish {
        reason: FinishReason,
    },
}

pub type ChatStream = Pin<Box<dyn Stream<Item = Result<StreamEvent, AgentError>> + Send>>;

/// A completed model turn.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Completion {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub finish: Option<FinishReason>,
}

/// Assembles [`StreamEvent`]s into a [`Completion`].
#[derive(Debug, Default)]
pub struct StreamAssembler {
    text: String,
    calls: Vec<PartialCall>,
    usage: Usage,
    finish: Option<FinishReason>,
}

#[derive(Debug, Default)]
struct PartialCall {
    id: Option<String>,
    name: String,
    args: String,
}

impl StreamAssembler {
    pub fn push(&mut self, ev: &StreamEvent) {
        match ev {
            StreamEvent::TextDelta { text } => self.text.push_str(text),
            StreamEvent::ToolCallDelta {
                index,
                id,
                name,
                arguments,
            } => {
                if self.calls.len() <= *index {
                    self.calls.resize_with(index + 1, PartialCall::default);
                }
                let c = &mut self.calls[*index];
                if let Some(id) = id {
                    c.id = Some(id.clone());
                }
                if let Some(n) = name {
                    c.name.push_str(n);
                }
                c.args.push_str(arguments);
            }
            // Providers may report usage in several events (start and end); the latest
            // non-zero field wins so input tokens from the start are kept.
            StreamEvent::Usage(u) => {
                if u.input_tokens > 0 {
                    self.usage.input_tokens = u.input_tokens;
                }
                if u.output_tokens > 0 {
                    self.usage.output_tokens = u.output_tokens;
                }
            }
            StreamEvent::Finish { reason } => self.finish = Some(*reason),
        }
    }

    /// Finishes assembly. Arguments that fail to parse become a JSON string so the caller can
    /// report the problem to the model; empty arguments become `{}`.
    pub fn finish(self) -> Completion {
        let tool_calls = self
            .calls
            .into_iter()
            .enumerate()
            .filter(|(_, c)| !c.name.is_empty())
            .map(|(i, c)| {
                let arguments = if c.args.trim().is_empty() {
                    Value::Object(Default::default())
                } else {
                    serde_json::from_str(&c.args).unwrap_or(Value::String(c.args))
                };
                ToolCall {
                    id: c.id.unwrap_or_else(|| format!("call_{i}")),
                    name: c.name,
                    arguments,
                }
            })
            .collect();
        Completion {
            text: self.text,
            tool_calls,
            usage: self.usage,
            finish: self.finish,
        }
    }
}

//! The agent loop.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::{Stream, StreamExt};
use kraken_proto::sanitize;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::AgentError;
use crate::provider::ChatProvider;
use crate::safety::{summarize, system_prompt, wrap_tool_error, wrap_tool_result};
use crate::tool::{Permission, ToolCtx, ToolError, ToolHost, ToolSpec};
use crate::types::{ChatRequest, Message, StreamAssembler, StreamEvent, ToolCall, Usage};

const SUMMARY_CHARS: usize = 200;

#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Maximum number of model calls.
    pub max_steps: usize,
    /// Maximum number of tool calls over the whole run.
    pub max_tool_calls: usize,
    /// Stop once input plus output tokens reach this many. `None` means unlimited.
    pub token_budget: Option<u64>,
    pub run_id: String,
    /// Trusted operator text appended to the system prompt. Never put binary-derived text here.
    pub system_extra: Option<String>,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_steps: 20,
            max_tool_calls: 50,
            token_budget: None,
            run_id: "run".into(),
            system_extra: None,
            max_tokens: None,
            temperature: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Completed,
    MaxSteps,
    MaxToolCalls,
    TokenBudget,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    /// Sanitised assistant text.
    TextDelta {
        text: String,
    },
    ToolCallStarted {
        id: String,
        name: String,
        arguments: Value,
    },
    /// A dangerous tool is waiting for [`ApprovalHandle::decide`].
    ApprovalRequired {
        id: String,
        name: String,
        arguments: Value,
    },
    ToolCallFinished {
        id: String,
        name: String,
        /// Sanitised, truncated, single-line.
        summary: String,
        is_error: bool,
    },
    /// A tool result carried a `"proposal"` field.
    ProposalCreated {
        tool: String,
        call_id: String,
        proposal: Value,
    },
    Error {
        message: String,
    },
    Done {
        usage: Usage,
        stop: StopReason,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// Clonable handle for answering [`AgentEvent::ApprovalRequired`].
#[derive(Debug, Clone)]
pub struct ApprovalHandle(mpsc::UnboundedSender<(String, ApprovalDecision)>);

impl ApprovalHandle {
    pub fn decide(&self, call_id: impl Into<String>, decision: ApprovalDecision) {
        let _ = self.0.send((call_id.into(), decision));
    }
}

/// A running agent: a stream of events plus approval and cancel controls.
pub struct AgentRun {
    events: mpsc::Receiver<AgentEvent>,
    approvals: ApprovalHandle,
    cancel: CancellationToken,
}

impl AgentRun {
    pub fn approvals(&self) -> ApprovalHandle {
        self.approvals.clone()
    }

    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub async fn next_event(&mut self) -> Option<AgentEvent> {
        self.events.recv().await
    }
}

impl Stream for AgentRun {
    type Item = AgentEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<AgentEvent>> {
        self.events.poll_recv(cx)
    }
}

impl Drop for AgentRun {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub struct Agent;

impl Agent {
    /// Starts a run on the current tokio runtime.
    pub fn run(
        messages: Vec<Message>,
        host: Arc<dyn ToolHost>,
        provider: Arc<dyn ChatProvider>,
        config: AgentConfig,
    ) -> AgentRun {
        let (tx, rx) = mpsc::channel(64);
        let (atx, arx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let state = Loop {
            tx,
            approvals: arx,
            cancel: cancel.clone(),
            host,
            provider,
            config,
        };
        tokio::spawn(state.run(messages));
        AgentRun {
            events: rx,
            approvals: ApprovalHandle(atx),
            cancel,
        }
    }

    /// Convenience for a single user goal.
    pub fn run_goal(
        goal: impl Into<String>,
        host: Arc<dyn ToolHost>,
        provider: Arc<dyn ChatProvider>,
        config: AgentConfig,
    ) -> AgentRun {
        Self::run(vec![Message::user(goal)], host, provider, config)
    }
}

struct Loop {
    tx: mpsc::Sender<AgentEvent>,
    approvals: mpsc::UnboundedReceiver<(String, ApprovalDecision)>,
    cancel: CancellationToken,
    host: Arc<dyn ToolHost>,
    provider: Arc<dyn ChatProvider>,
    config: AgentConfig,
}

fn sanitize_value(v: &Value) -> Value {
    match v {
        Value::String(s) => Value::String(sanitize(s)),
        Value::Array(a) => Value::Array(a.iter().map(sanitize_value).collect()),
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (sanitize(k), sanitize_value(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

enum Flow {
    Continue,
    Stop(StopReason, String),
}

impl Loop {
    async fn emit(&self, ev: AgentEvent) {
        if self.tx.send(ev).await.is_err() {
            self.cancel.cancel();
        }
    }

    async fn run(mut self, mut messages: Vec<Message>) {
        let mut usage = Usage::default();
        let (stop, message) = self.drive(&mut messages, &mut usage).await;
        if stop == StopReason::Error {
            self.emit(AgentEvent::Error {
                message: message.clone(),
            })
            .await;
        }
        self.emit(AgentEvent::Done {
            usage,
            stop,
            message,
        })
        .await;
    }

    async fn drive(
        &mut self,
        messages: &mut Vec<Message>,
        usage: &mut Usage,
    ) -> (StopReason, String) {
        let specs: Vec<ToolSpec> = self.host.tools();
        let by_name: HashMap<&str, &ToolSpec> =
            specs.iter().map(|s| (s.name.as_str(), s)).collect();
        let system = system_prompt(self.config.system_extra.as_deref());
        let supports_tools = self.provider.info().supports_tools;
        let mut steps = 0usize;
        let mut tool_calls_made = 0usize;

        loop {
            if self.cancel.is_cancelled() {
                return (StopReason::Cancelled, "Run cancelled.".into());
            }
            if steps >= self.config.max_steps {
                return (
                    StopReason::MaxSteps,
                    format!(
                        "Stopped: reached the limit of {} model steps. Ask again to continue.",
                        self.config.max_steps
                    ),
                );
            }
            if let Some(b) = self.config.token_budget
                && usage.total() >= b
            {
                return (
                    StopReason::TokenBudget,
                    format!(
                        "Stopped: token budget of {b} exhausted ({} used).",
                        usage.total()
                    ),
                );
            }
            steps += 1;

            let req = ChatRequest {
                system: system.clone(),
                messages: messages.clone(),
                tools: if supports_tools {
                    specs.clone()
                } else {
                    vec![]
                },
                max_tokens: self.config.max_tokens,
                temperature: self.config.temperature,
            };
            let mut stream = match self.provider.complete(req, self.cancel.clone()).await {
                Ok(s) => s,
                Err(AgentError::Cancelled) => {
                    return (StopReason::Cancelled, "Run cancelled.".into());
                }
                Err(e) => return (StopReason::Error, sanitize(&e.to_string())),
            };
            let mut asm = StreamAssembler::default();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(ev) => {
                        if let StreamEvent::TextDelta { text } = &ev {
                            let t = sanitize(text);
                            if !t.is_empty() {
                                self.emit(AgentEvent::TextDelta { text: t }).await;
                            }
                        }
                        asm.push(&ev);
                    }
                    Err(AgentError::Cancelled) => {
                        return (StopReason::Cancelled, "Run cancelled.".into());
                    }
                    Err(e) => return (StopReason::Error, sanitize(&e.to_string())),
                }
            }
            let done = asm.finish();
            usage.add(done.usage);
            messages.push(Message::Assistant {
                content: sanitize(&done.text),
                tool_calls: done.tool_calls.clone(),
            });

            if done.tool_calls.is_empty() {
                return (StopReason::Completed, "Finished.".into());
            }
            if tool_calls_made + done.tool_calls.len() > self.config.max_tool_calls {
                return (
                    StopReason::MaxToolCalls,
                    format!(
                        "Stopped: reached the limit of {} tool calls.",
                        self.config.max_tool_calls
                    ),
                );
            }
            for call in &done.tool_calls {
                tool_calls_made += 1;
                match self.handle_call(call, &by_name, messages).await {
                    Flow::Continue => {}
                    Flow::Stop(r, m) => return (r, m),
                }
            }
        }
    }

    async fn handle_call(
        &mut self,
        call: &ToolCall,
        specs: &HashMap<&str, &ToolSpec>,
        messages: &mut Vec<Message>,
    ) -> Flow {
        let name = sanitize(&call.name);
        let Some(spec) = specs.get(call.name.as_str()) else {
            self.finish_call(messages, call, Err(format!("unknown tool `{name}`")))
                .await;
            return Flow::Continue;
        };
        if !call.arguments.is_object() {
            self.finish_call(
                messages,
                call,
                Err("tool arguments were not a valid JSON object".into()),
            )
            .await;
            return Flow::Continue;
        }
        if spec.permission == Permission::Dangerous {
            self.emit(AgentEvent::ApprovalRequired {
                id: call.id.clone(),
                name: name.clone(),
                arguments: sanitize_value(&call.arguments),
            })
            .await;
            match self.wait_approval(&call.id).await {
                Some(ApprovalDecision::Approve) => {}
                Some(ApprovalDecision::Deny) => {
                    self.finish_call(messages, call, Err("denied by the user".into()))
                        .await;
                    return Flow::Continue;
                }
                None => return Flow::Stop(StopReason::Cancelled, "Run cancelled.".into()),
            }
        }
        self.emit(AgentEvent::ToolCallStarted {
            id: call.id.clone(),
            name: name.clone(),
            arguments: sanitize_value(&call.arguments),
        })
        .await;
        let ctx = ToolCtx {
            run_id: self.config.run_id.clone(),
            call_id: call.id.clone(),
            cancel: self.cancel.clone(),
        };
        let result = tokio::select! {
            _ = self.cancel.cancelled() => Err(ToolError::Cancelled),
            r = self.host.call(&call.name, call.arguments.clone(), &ctx) => r,
        };
        match result {
            Err(ToolError::Cancelled) => Flow::Stop(StopReason::Cancelled, "Run cancelled.".into()),
            Err(e) => {
                self.finish_call(messages, call, Err(e.to_string())).await;
                Flow::Continue
            }
            Ok(v) => {
                if let Some(p) = v.get("proposal") {
                    self.emit(AgentEvent::ProposalCreated {
                        tool: name.clone(),
                        call_id: call.id.clone(),
                        proposal: sanitize_value(p),
                    })
                    .await;
                }
                self.finish_call(messages, call, Ok(v)).await;
                Flow::Continue
            }
        }
    }

    /// Returns `None` if cancelled (or the controller went away) while waiting.
    async fn wait_approval(&mut self, id: &str) -> Option<ApprovalDecision> {
        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => return None,
                d = self.approvals.recv() => match d {
                    Some((cid, d)) if cid == id => return Some(d),
                    Some(_) => {}
                    None => return Some(ApprovalDecision::Deny),
                }
            }
        }
    }

    async fn finish_call(
        &self,
        messages: &mut Vec<Message>,
        call: &ToolCall,
        result: Result<Value, String>,
    ) {
        let name = sanitize(&call.name);
        let (content, summary, is_error) = match &result {
            Ok(v) => (
                wrap_tool_result(&call.id, &call.name, v),
                summarize(v, SUMMARY_CHARS),
                false,
            ),
            Err(m) => (
                wrap_tool_error(&call.id, &call.name, m),
                summarize(&Value::String(m.clone()), SUMMARY_CHARS),
                true,
            ),
        };
        self.emit(AgentEvent::ToolCallFinished {
            id: call.id.clone(),
            name,
            summary,
            is_error,
        })
        .await;
        messages.push(Message::ToolResult {
            tool_call_id: call.id.clone(),
            name: call.name.clone(),
            content,
            is_error,
        });
    }
}

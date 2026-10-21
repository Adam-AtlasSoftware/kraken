//! The assistant backend: what answers a run.
//!
//! Two implementations stand behind one trait (decision 94):
//!
//! - [`ApiBackend`]: a chat model API (Ollama, Anthropic, ...) driven by the `kraken-agent`
//!   loop over a [`RegistryToolHost`](crate::RegistryToolHost).
//! - [`AcpBackend`](crate::AcpBackend): a terminal agent (Claude Code, Codex, Gemini CLI) driven
//!   over ACP, which reaches KRAKEN's tools through the `kraken mcp` server it is launched with.
//!
//! Both turn a [`RunSpec`] into an [`AgentRun`], the same stream of [`AgentEvent`]s, so tasks,
//! chat, the CLI and the GUI do not care which one is selected.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::StreamExt;
use kraken_agent::{
    Agent, AgentConfig, AgentError, AgentRun, ChatProvider, ChatRequest, LowContextHost, Message,
    ProviderInfo, StreamAssembler, ToolHost, Usage,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::host::HostStats;

/// Which kind of backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// A chat model API (cloud or local).
    #[default]
    Api,
    /// A terminal agent over ACP.
    TerminalAgent,
}

/// What the UI shows about the backend in use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendInfo {
    /// Which kind.
    pub kind: BackendKind,
    /// Provider id (API) or agent id (terminal agent).
    pub id: String,
    /// Display name: the model service, or the agent ("Claude Code").
    pub name: String,
    /// The model, when known. A terminal agent may only say after it has started.
    pub model: Option<String>,
}

impl BackendInfo {
    /// `Anthropic (Claude) / claude-sonnet-5-5`, or just the name when no model is known.
    pub fn title(&self) -> String {
        match self.model.as_deref().filter(|m| !m.is_empty()) {
            Some(m) => format!("{} / {m}", self.name),
            None => self.name.clone(),
        }
    }
}

/// What a run is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// A turn of the conversation; a terminal agent keeps its session between turns.
    Chat,
    /// A one-shot task in a fresh session.
    Task {
        /// The task must not change the project.
        read_only: bool,
    },
}

/// Everything a backend needs to start a run.
pub struct RunSpec {
    /// The conversation; the last message is the new one. A terminal agent keeps its own
    /// history, so it only reads this to catch up when its session is new.
    pub messages: Vec<Message>,
    /// Budgets, the run id and the trusted instructions (`system_extra`).
    pub config: AgentConfig,
    /// The tools of the API loop. A terminal agent ignores it: it uses the `kraken mcp` server.
    pub tools: Arc<dyn ToolHost>,
    /// What the run is for.
    pub purpose: Purpose,
}

/// What a text-only completion returns.
#[derive(Debug, Clone)]
pub struct TextReply {
    /// The reply text, as the model or agent wrote it.
    pub text: String,
    /// Token usage; zero for a terminal agent, which does not report it.
    pub usage: Usage,
    /// Who answered.
    pub provider: ProviderInfo,
}

/// The future of [`AssistBackend::complete_text`].
pub type TextFuture<'a> = Pin<Box<dyn Future<Output = Result<TextReply, AgentError>> + Send + 'a>>;

/// Something that answers runs. Implementations must be cheap to share.
pub trait AssistBackend: Send + Sync {
    /// What to show about the backend.
    fn info(&self) -> BackendInfo;

    /// The facts the task results carry (`TaskResult::provider`).
    fn provider_info(&self) -> ProviderInfo;

    /// Starts a run on the current tokio runtime. The stream ends after `Done`.
    fn start(&self, spec: RunSpec) -> AgentRun;

    /// What the backend did for run `run_id`, when it saw the tool calls itself (a terminal agent
    /// calls the tools in another process). `None`: ask the tool host.
    fn take_stats(&self, _run_id: &str) -> Option<HostStats> {
        None
    }

    /// Things worth telling the person that came up since the last call (the agent runs outside
    /// KRAKEN's confinement, ...).
    fn take_notes(&self) -> Vec<String> {
        Vec::new()
    }

    /// Ends anything kept between runs (a terminal agent's session).
    fn close(&self) {}

    /// The chat model API behind the backend, when it is one; the meter wraps it to count every
    /// request with its tokens.
    fn chat_provider(&self) -> Option<Arc<dyn ChatProvider>> {
        None
    }

    /// One text-only request: `req.system` and `req.messages` in, the reply text out. No KRAKEN
    /// tools are offered (`req.tools` is ignored) and nothing is run on the backend's side: the
    /// rewrite pipeline sends everything the model needs in the prompt and builds and tests the
    /// answer itself, in its own sandbox. A terminal agent is started in an empty scratch
    /// directory without the KRAKEN MCP server, and every permission request for its own tools
    /// is denied.
    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_>;
}

/// A chat model API behind the `kraken-agent` loop.
pub struct ApiBackend {
    provider: Arc<dyn ChatProvider>,
    low_context: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

impl ApiBackend {
    /// A backend over `provider`.
    pub fn new(provider: Arc<dyn ChatProvider>) -> Self {
        ApiBackend {
            provider,
            low_context: None,
        }
    }

    /// Asks `on` at the start of every run whether to use low context mode: the model gets each
    /// tool's name and a short line, and asks for the rest through `tool_help`
    /// ([`LowContextHost`]).
    pub fn with_low_context(mut self, on: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.low_context = Some(Arc::new(on));
        self
    }
}

impl AssistBackend for ApiBackend {
    fn info(&self) -> BackendInfo {
        let i = self.provider.info();
        BackendInfo {
            kind: BackendKind::Api,
            name: i.id.clone(),
            id: i.id,
            model: (!i.model.is_empty()).then_some(i.model),
        }
    }

    fn provider_info(&self) -> ProviderInfo {
        self.provider.info()
    }

    fn chat_provider(&self) -> Option<Arc<dyn ChatProvider>> {
        Some(self.provider.clone())
    }

    fn start(&self, spec: RunSpec) -> AgentRun {
        let tools: Arc<dyn ToolHost> = match &self.low_context {
            Some(on) if on() => Arc::new(LowContextHost::new(spec.tools)),
            _ => spec.tools,
        };
        Agent::run(spec.messages, tools, self.provider.clone(), spec.config)
    }

    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_> {
        Box::pin(async move {
            let req = ChatRequest {
                tools: Vec::new(),
                ..req
            };
            let mut stream = self.provider.complete(req, cancel).await?;
            let mut asm = StreamAssembler::default();
            while let Some(ev) = stream.next().await {
                asm.push(&ev?);
            }
            let done = asm.finish();
            Ok(TextReply {
                text: done.text,
                usage: done.usage,
                provider: self.provider.info(),
            })
        })
    }
}

/// A command backend that refuses every call. A terminal agent reaches the registry through its
/// own `kraken mcp` server, so a run on it never uses the API path's tool host; this fills the
/// slot where an [`Assistant`](crate::Assistant) wants one.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnusedBackend;

#[async_trait::async_trait]
impl kraken_host::backend::CommandBackend for UnusedBackend {
    async fn call(
        &self,
        name: &str,
        _ctx: &kraken_registry::CallContext,
        _args: serde_json::Value,
    ) -> Result<serde_json::Value, kraken_proto::ProtoError> {
        Err(kraken_proto::ProtoError::new(
            kraken_proto::ErrorCode::Unsupported,
            format!("`{name}` is not served here; a terminal agent uses its own KRAKEN tools"),
        ))
    }

    fn take_warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

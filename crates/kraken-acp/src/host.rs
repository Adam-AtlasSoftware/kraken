//! `AcpHost`: KRAKEN as an ACP client.
//!
//! The host starts the agent process, speaks ACP over its stdio, opens one session whose
//! `mcpServers` list points the agent at KRAKEN's own MCP server, and turns everything the agent
//! reports into [`AcpEvent`]s that a UI or the CLI can show. KRAKEN advertises no file-system and
//! no terminal capability: the agent keeps using its own tools for those (see [`crate::notice`]).

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use agent_client_protocol::schema::ProtocolVersion;
use agent_client_protocol::schema::v1::{
    CancelNotification, ClientCapabilities, ContentBlock, CreateTerminalRequest, EnvVariable,
    Implementation, InitializeRequest, McpServer, McpServerStdio, NewSessionRequest, PromptRequest,
    ReadTextFileRequest, RequestPermissionOutcome, RequestPermissionRequest,
    RequestPermissionResponse, SelectedPermissionOutcome, SessionNotification, SessionUpdate,
    TextContent, WriteTextFileRequest,
};
use agent_client_protocol::{Agent, ByteStreams, Client, ConnectionTo};
use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use crate::agents::LaunchSpec;
use crate::process::{AgentProcess, ExitInfo, SpawnSpec, StderrTail, spawn};
use crate::profile::AgentProfile;

/// The name KRAKEN's MCP server gets in the agent's tool list.
pub const MCP_SERVER_NAME: &str = "kraken";

/// How long the agent has to answer `initialize` and `session/new`.
pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(60);

/// Failure of the host.
#[derive(Debug, thiserror::Error)]
pub enum AcpError {
    /// The agent could not be started.
    #[error(transparent)]
    Spawn(#[from] crate::process::SpawnError),
    /// The agent did not finish the handshake in time.
    #[error("{agent} did not answer within {secs} seconds{stderr}")]
    StartTimeout {
        /// The agent.
        agent: String,
        /// Seconds waited.
        secs: u64,
        /// The end of the agent's stderr, with a leading newline, or empty.
        stderr: String,
    },
    /// The agent needs the person to sign in first.
    #[error(
        "{agent} needs you to sign in first: {message}. Sign in with the agent's own command line \
         (for example `claude`, `codex login` or `gemini`), then try again"
    )]
    AuthRequired {
        /// The agent.
        agent: String,
        /// What the agent said.
        message: String,
    },
    /// The agent answered with a protocol error.
    #[error("{agent} reported an error: {message}")]
    Agent {
        /// The agent.
        agent: String,
        /// The error text.
        message: String,
    },
    /// The agent process or the connection ended.
    #[error("the connection to {agent} ended{stderr}")]
    Disconnected {
        /// The agent.
        agent: String,
        /// The end of the agent's stderr, with a leading newline, or empty.
        stderr: String,
    },
    /// A prompt is already running.
    #[error("a prompt is already running; cancel it or wait for it to finish")]
    Busy,
}

/// How the agent should reach KRAKEN's tools: a stdio MCP server the agent starts itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpServerConfig {
    /// Name in the agent's tool list.
    pub name: String,
    /// The `kraken` executable.
    pub command: PathBuf,
    /// Its arguments (`mcp --project <dir>`).
    pub args: Vec<String>,
    /// Environment for the server process (names and values).
    pub env: Vec<(String, String)>,
}

impl McpServerConfig {
    /// `kraken mcp --project <dir>`: a server with its own in-process session (or one that joins
    /// a running `krakend`).
    pub fn project(kraken_exe: impl Into<PathBuf>, project_dir: &Path) -> Self {
        McpServerConfig {
            name: MCP_SERVER_NAME.into(),
            command: kraken_exe.into(),
            args: vec![
                "mcp".into(),
                "--project".into(),
                project_dir.to_string_lossy().into_owned(),
            ],
            env: vec![],
        }
    }

    /// `kraken mcp --daemon [--project <dir>]`: every tool call runs in `krakend`, sharing the
    /// project and the Ghidra sidecar with the CLI and the GUI.
    pub fn daemon(kraken_exe: impl Into<PathBuf>, project_dir: Option<&Path>) -> Self {
        let mut args = vec!["mcp".to_string(), "--daemon".into()];
        if let Some(p) = project_dir {
            args.push("--project".into());
            args.push(p.to_string_lossy().into_owned());
        }
        McpServerConfig {
            name: MCP_SERVER_NAME.into(),
            command: kraken_exe.into(),
            args,
            env: vec![],
        }
    }

    /// Builder: one more variable for the MCP server process (for example `KRAKEN_RUNTIME_DIR`).
    #[must_use]
    pub fn with_env(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((name.into(), value.into()));
        self
    }

    fn to_acp(&self) -> McpServer {
        McpServer::Stdio(
            McpServerStdio::new(self.name.clone(), self.command.clone())
                .args(self.args.clone())
                .env(
                    self.env
                        .iter()
                        .map(|(k, v)| EnvVariable::new(k.clone(), v.clone()))
                        .collect(),
                ),
        )
    }
}

/// One choice offered by a permission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionOptionInfo {
    /// Id to answer with.
    pub id: String,
    /// Label (`Allow once`, `Reject`, ...).
    pub name: String,
    /// `allow_once`, `allow_always`, `reject_once` or `reject_always`.
    pub kind: String,
}

/// The agent asks to do something and wants an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PermissionRequest {
    /// Id to answer with ([`AcpHost::answer_permission`]).
    pub request_id: u64,
    /// What the agent wants to do, in its words.
    pub title: String,
    /// `read`, `edit`, `delete`, `execute`, ... when the agent says.
    pub tool_kind: Option<String>,
    /// The tool's input as JSON text, shortened.
    pub input: Option<String>,
    /// Files involved.
    pub paths: Vec<String>,
    /// The choices.
    pub options: Vec<PermissionOptionInfo>,
}

/// The answer to a permission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PermissionDecision {
    /// Pick this option id.
    Select(String),
    /// Decline without picking (also what a cancelled turn answers).
    Cancel,
}

impl PermissionRequest {
    fn pick(&self, kinds: &[&str]) -> PermissionDecision {
        for k in kinds {
            if let Some(o) = self.options.iter().find(|o| o.kind == *k) {
                return PermissionDecision::Select(o.id.clone());
            }
        }
        PermissionDecision::Cancel
    }

    /// Allows once (or always when only that is offered); `Cancel` when nothing allows.
    pub fn allow(&self) -> PermissionDecision {
        self.pick(&["allow_once", "allow_always"])
    }

    /// Rejects once (or always); `Cancel` when nothing rejects.
    pub fn reject(&self) -> PermissionDecision {
        self.pick(&["reject_once", "reject_always"])
    }
}

/// Decides permission requests. The CLI implements this with a terminal prompt.
#[async_trait]
pub trait PermissionHandler: Send + Sync {
    /// Answers `request`. May take as long as a person needs; a cancelled turn drops the call.
    async fn decide(&self, request: &PermissionRequest) -> PermissionDecision;
}

/// Declines everything.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

#[async_trait]
impl PermissionHandler for DenyAll {
    async fn decide(&self, request: &PermissionRequest) -> PermissionDecision {
        request.reject()
    }
}

/// Allows everything. Only for tests and for people who pass `--auto-approve`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

#[async_trait]
impl PermissionHandler for AllowAll {
    async fn decide(&self, request: &PermissionRequest) -> PermissionDecision {
        request.allow()
    }
}

/// Who answers permission requests.
#[derive(Clone, Default)]
pub enum PermissionPolicy {
    /// Ask the person through the UI: an [`AcpEvent::PermissionRequested`] is emitted and the
    /// turn waits for [`AcpHost::answer_permission`]. The default.
    #[default]
    AskUser,
    /// Call this handler.
    Handler(Arc<dyn PermissionHandler>),
}

impl std::fmt::Debug for PermissionPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionPolicy::AskUser => f.write_str("AskUser"),
            PermissionPolicy::Handler(_) => f.write_str("Handler(..)"),
        }
    }
}

/// A tool call the agent started.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolCallInfo {
    /// Id, stable across updates.
    pub id: String,
    /// What it is doing.
    pub title: String,
    /// `read`, `edit`, `execute`, `search`, `fetch`, `think`, `other`, ...
    pub kind: String,
    /// `pending`, `in_progress`, `completed` or `failed`.
    pub status: String,
    /// Files involved.
    pub paths: Vec<String>,
    /// The tool's input as JSON text, shortened.
    pub input: Option<String>,
}

/// A change to a tool call. Only the fields the agent sent are set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ToolCallChange {
    /// Id of the tool call.
    pub id: String,
    /// New title.
    pub title: Option<String>,
    /// New status.
    pub status: Option<String>,
    /// Text the tool produced.
    pub output: Option<String>,
}

/// One step of the agent's plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanStep {
    /// What the step is.
    pub content: String,
    /// `pending`, `in_progress` or `completed`.
    pub status: String,
    /// `high`, `medium` or `low`.
    pub priority: String,
}

/// What the agent said about itself in `initialize`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentInfo {
    /// Name, when given.
    pub name: Option<String>,
    /// Version, when given.
    pub version: Option<String>,
    /// ACP protocol version agreed.
    pub protocol_version: u16,
    /// Sign-in methods the agent lists.
    pub auth_methods: Vec<String>,
}

/// Why a turn ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnEnd {
    /// The agent finished its answer.
    EndTurn,
    /// The agent hit its length limit.
    MaxTokens,
    /// The agent hit its step limit.
    MaxTurnRequests,
    /// The agent refused.
    Refusal,
    /// The turn was cancelled.
    Cancelled,
    /// Something this version does not know.
    Other,
}

/// Everything the host reports. Serialises to JSON for the GUI and `--json` output.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AcpEvent {
    /// The session is open.
    Started {
        /// What the agent said about itself.
        agent: AgentInfo,
        /// ACP session id.
        session_id: String,
    },
    /// A piece of the agent's answer.
    AgentText {
        /// The text.
        text: String,
    },
    /// A piece of the agent's reasoning.
    AgentThought {
        /// The text.
        text: String,
    },
    /// The agent started a tool call.
    ToolCall(ToolCallInfo),
    /// A tool call changed.
    ToolCallUpdate(ToolCallChange),
    /// The agent's plan (always the complete list).
    Plan {
        /// The steps.
        steps: Vec<PlanStep>,
    },
    /// The agent wants permission (only with [`PermissionPolicy::AskUser`] does it wait for you;
    /// with a handler this is informational).
    PermissionRequested(PermissionRequest),
    /// A permission request was answered.
    PermissionResolved {
        /// Which request.
        request_id: u64,
        /// The option chosen, or `None` when declined or cancelled.
        selected: Option<String>,
    },
    /// Other session news (mode changes, available commands, usage).
    Info {
        /// Kind of update.
        kind: String,
    },
    /// A line the agent wrote to stderr.
    AgentStderr {
        /// The line.
        line: String,
    },
    /// The turn finished.
    TurnEnded {
        /// Why.
        reason: TurnEnd,
    },
    /// The agent process ended.
    Exited {
        /// Exit code.
        code: Option<i32>,
        /// Terminating signal.
        signal: Option<i32>,
    },
}

/// How to start a session.
#[derive(Clone)]
pub struct HostConfig {
    /// The agent.
    pub profile: AgentProfile,
    /// How to start it.
    pub launch: LaunchSpec,
    /// The agent's working directory and the session's `cwd`.
    pub project_dir: PathBuf,
    /// KRAKEN's MCP server entry. `None` starts a session without KRAKEN tools.
    pub mcp: Option<McpServerConfig>,
    /// Who answers permission requests.
    pub permission: PermissionPolicy,
    /// The environment to filter for the agent; `None` uses this process's.
    pub parent_env: Option<Vec<(OsString, OsString)>>,
    /// Handshake timeout.
    pub start_timeout: Duration,
}

impl HostConfig {
    /// A config with defaults: ask the user, 60 seconds to start.
    pub fn new(
        profile: AgentProfile,
        launch: LaunchSpec,
        project_dir: PathBuf,
        mcp: Option<McpServerConfig>,
    ) -> Self {
        HostConfig {
            profile,
            launch,
            project_dir,
            mcp,
            permission: PermissionPolicy::AskUser,
            parent_env: None,
            start_timeout: DEFAULT_START_TIMEOUT,
        }
    }
}

type ReadyCell = Arc<Mutex<Option<oneshot::Sender<Result<Ready, AcpError>>>>>;

type PendingMap = Arc<Mutex<HashMap<u64, oneshot::Sender<PermissionDecision>>>>;

struct Ready {
    cx: ConnectionTo<Agent>,
    session_id: agent_client_protocol::schema::v1::SessionId,
    info: AgentInfo,
}

/// A running agent session.
pub struct AcpHost {
    agent_name: String,
    cx: ConnectionTo<Agent>,
    session_id: agent_client_protocol::schema::v1::SessionId,
    info: AgentInfo,
    pending: PendingMap,
    events: mpsc::UnboundedSender<AcpEvent>,
    prompting: Arc<Mutex<bool>>,
    cancelled: Arc<Mutex<bool>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    process: AgentProcess,
    stderr: StderrTail,
}

impl std::fmt::Debug for AcpHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcpHost")
            .field("agent", &self.agent_name)
            .field("session_id", &self.session_id.to_string())
            .finish_non_exhaustive()
    }
}

fn enum_text<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(Value::String(s)) => s,
        _ => "other".into(),
    }
}

fn shorten(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let cut: String = text.chars().take(max).collect();
    format!("{cut}...")
}

fn input_text(v: Option<&Value>) -> Option<String> {
    let v = v?;
    if v.is_null() {
        return None;
    }
    Some(shorten(v.to_string(), 600))
}

fn location_paths(v: &Value) -> Vec<String> {
    v.get("locations")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|l| l.get("path").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn content_text(v: &Value) -> Option<String> {
    let items = v.get("content").and_then(Value::as_array)?;
    let mut parts = Vec::new();
    for item in items {
        match item.get("type").and_then(Value::as_str) {
            Some("content") => {
                if let Some(t) = item.pointer("/content/text").and_then(Value::as_str) {
                    parts.push(t.to_string());
                }
            }
            Some("diff") => {
                let path = item.get("path").and_then(Value::as_str).unwrap_or("a file");
                parts.push(format!("changes to {path}"));
            }
            Some("terminal") => parts.push("terminal output".into()),
            _ => {}
        }
    }
    (!parts.is_empty()).then(|| shorten(parts.join("\n"), 2000))
}

fn translate(update: SessionUpdate) -> Option<AcpEvent> {
    let as_json = serde_json::to_value(&update).unwrap_or(Value::Null);
    let text_of = |c: &Value| {
        c.pointer("/content/text")
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    match update {
        SessionUpdate::AgentMessageChunk(_) => {
            text_of(&as_json).map(|text| AcpEvent::AgentText { text })
        }
        SessionUpdate::AgentThoughtChunk(_) => {
            text_of(&as_json).map(|text| AcpEvent::AgentThought { text })
        }
        // The user's own message is echoed only when a session is replayed.
        SessionUpdate::UserMessageChunk(_) => None,
        SessionUpdate::ToolCall(tc) => Some(AcpEvent::ToolCall(ToolCallInfo {
            id: tc.tool_call_id.to_string(),
            title: tc.title.clone(),
            kind: enum_text(&tc.kind),
            status: enum_text(&tc.status),
            paths: location_paths(&as_json),
            input: input_text(as_json.get("rawInput")),
        })),
        SessionUpdate::ToolCallUpdate(u) => Some(AcpEvent::ToolCallUpdate(ToolCallChange {
            id: u.tool_call_id.to_string(),
            title: u.fields.title.clone(),
            status: u.fields.status.as_ref().map(enum_text),
            output: content_text(&as_json),
        })),
        SessionUpdate::Plan(p) => Some(AcpEvent::Plan {
            steps: p
                .entries
                .iter()
                .map(|e| PlanStep {
                    content: e.content.clone(),
                    status: enum_text(&e.status),
                    priority: enum_text(&e.priority),
                })
                .collect(),
        }),
        _ => {
            let kind = as_json
                .get("sessionUpdate")
                .and_then(Value::as_str)
                .unwrap_or("update")
                .to_string();
            Some(AcpEvent::Info { kind })
        }
    }
}

fn permission_request(id: u64, req: &RequestPermissionRequest) -> PermissionRequest {
    let json = serde_json::to_value(&req.tool_call).unwrap_or(Value::Null);
    PermissionRequest {
        request_id: id,
        title: req
            .tool_call
            .fields
            .title
            .clone()
            .unwrap_or_else(|| "The agent asks for permission".into()),
        tool_kind: req.tool_call.fields.kind.as_ref().map(enum_text),
        input: input_text(json.get("rawInput")),
        paths: location_paths(&json),
        options: req
            .options
            .iter()
            .map(|o| PermissionOptionInfo {
                id: o.option_id.to_string(),
                name: o.name.clone(),
                kind: enum_text(&o.kind),
            })
            .collect(),
    }
}

fn to_outcome(d: &PermissionDecision, req: &PermissionRequest) -> RequestPermissionOutcome {
    match d {
        PermissionDecision::Select(id) if req.options.iter().any(|o| o.id == *id) => {
            RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new(id.clone()))
        }
        _ => RequestPermissionOutcome::Cancelled,
    }
}

fn map_error(agent: &str, e: &agent_client_protocol::Error) -> AcpError {
    let message = e.to_string();
    let lower = message.to_ascii_lowercase();
    let needs_login = [
        "auth",
        "log in",
        "login",
        "sign in",
        "api key",
        "credential",
        "not configured",
    ]
    .iter()
    .any(|w| lower.contains(w));
    if needs_login {
        AcpError::AuthRequired {
            agent: agent.to_string(),
            message,
        }
    } else {
        AcpError::Agent {
            agent: agent.to_string(),
            message,
        }
    }
}

/// The error an agent gets when it asks for a capability KRAKEN does not offer.
fn declined(what: &str) -> agent_client_protocol::Error {
    agent_client_protocol::Error::method_not_found().data(format!(
        "KRAKEN does not offer {what} to agents; use your own tools or KRAKEN's MCP tools"
    ))
}

fn stderr_suffix(tail: &StderrTail) -> String {
    let t = tail.text();
    if t.is_empty() {
        String::new()
    } else {
        format!("\nthe agent said:\n{t}")
    }
}

impl AcpHost {
    /// Starts the agent, performs the ACP handshake and opens a session.
    ///
    /// Returns the host and the stream of [`AcpEvent`]s. The first event is
    /// [`AcpEvent::Started`].
    pub async fn start(
        config: HostConfig,
    ) -> Result<(AcpHost, mpsc::UnboundedReceiver<AcpEvent>), AcpError> {
        let agent_name = config.profile.display_name.clone();
        let parent: Vec<(OsString, OsString)> = config
            .parent_env
            .clone()
            .unwrap_or_else(|| std::env::vars_os().collect());
        let mut env = config.profile.child_env(parent.clone());
        if let Some(extra) = &config.launch.path_prepend {
            let mut path = OsString::from(extra.as_os_str());
            if let Some((_, old)) = env.iter().find(|(k, _)| k == "PATH") {
                path.push(if cfg!(windows) { ";" } else { ":" });
                path.push(old);
            }
            env.retain(|(k, _)| k != "PATH");
            env.push((OsString::from("PATH"), path));
        }
        let (events_tx, events_rx) = mpsc::unbounded_channel::<AcpEvent>();
        let (stderr_tx, mut stderr_rx) = mpsc::unbounded_channel::<String>();
        let spawned = spawn(
            SpawnSpec {
                program: config.launch.program.clone(),
                args: config.launch.args.clone(),
                env,
                cwd: config.project_dir.clone(),
            },
            Some(stderr_tx),
        )
        .await?;
        let crate::process::Spawned {
            mut process,
            stdin,
            stdout,
            stderr,
        } = spawned;

        let fwd = events_tx.clone();
        tokio::spawn(async move {
            while let Some(line) = stderr_rx.recv().await {
                if fwd.send(AcpEvent::AgentStderr { line }).is_err() {
                    break;
                }
            }
        });

        let pending: PendingMap = Arc::default();
        let next_request = Arc::new(AtomicU64::new(1));
        let (ready_tx, ready_rx) = oneshot::channel::<Result<Ready, AcpError>>();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let task = tokio::spawn(run_connection(ConnectionArgs {
            agent_name: agent_name.clone(),
            stdin,
            stdout,
            events: events_tx.clone(),
            pending: pending.clone(),
            next_request,
            policy: config.permission.clone(),
            project_dir: config.project_dir.clone(),
            mcp: config.mcp.clone(),
            ready: ready_tx,
            shutdown: shutdown_rx,
            stderr: stderr.clone(),
        }));

        let ready = match tokio::time::timeout(config.start_timeout, ready_rx).await {
            Ok(Ok(Ok(r))) => r,
            Ok(Ok(Err(e))) => {
                let _ = process.terminate(Duration::from_millis(500)).await;
                task.abort();
                return Err(e);
            }
            Ok(Err(_)) => {
                let _ = process.terminate(Duration::from_millis(500)).await;
                task.abort();
                return Err(AcpError::Disconnected {
                    agent: agent_name,
                    stderr: stderr_suffix(&stderr),
                });
            }
            Err(_) => {
                let _ = process.terminate(Duration::from_millis(500)).await;
                task.abort();
                return Err(AcpError::StartTimeout {
                    agent: agent_name,
                    secs: config.start_timeout.as_secs(),
                    stderr: stderr_suffix(&stderr),
                });
            }
        };
        let _ = events_tx.send(AcpEvent::Started {
            agent: ready.info.clone(),
            session_id: ready.session_id.to_string(),
        });
        let host = AcpHost {
            agent_name,
            cx: ready.cx,
            session_id: ready.session_id,
            info: ready.info,
            pending,
            events: events_tx,
            prompting: Arc::default(),
            cancelled: Arc::default(),
            shutdown: Some(shutdown_tx),
            task: Some(task),
            process,
            stderr,
        };
        Ok((host, events_rx))
    }

    /// The agent's name as shown to people.
    pub fn agent_name(&self) -> &str {
        &self.agent_name
    }

    /// What the agent said about itself.
    pub fn agent_info(&self) -> &AgentInfo {
        &self.info
    }

    /// The ACP session id.
    pub fn session_id(&self) -> String {
        self.session_id.to_string()
    }

    /// The agent's process id.
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    /// The end of the agent's stderr.
    pub fn stderr_tail(&self) -> String {
        self.stderr.text()
    }

    /// Sends one user message and waits for the turn to end. Streaming happens through the event
    /// channel; [`AcpEvent::TurnEnded`] is emitted last.
    pub async fn prompt(&self, text: &str) -> Result<TurnEnd, AcpError> {
        {
            let mut busy = self
                .prompting
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *busy {
                return Err(AcpError::Busy);
            }
            *busy = true;
        }
        *self
            .cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = false;
        let request = PromptRequest::new(
            self.session_id.clone(),
            vec![ContentBlock::Text(TextContent::new(text.to_string()))],
        );
        let result = self.cx.send_request(request).block_task().await;
        *self
            .prompting
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = false;
        match result {
            Ok(resp) => {
                let reason = match enum_text(&resp.stop_reason).as_str() {
                    "end_turn" => TurnEnd::EndTurn,
                    "max_tokens" => TurnEnd::MaxTokens,
                    "max_turn_requests" => TurnEnd::MaxTurnRequests,
                    "refusal" => TurnEnd::Refusal,
                    "cancelled" => TurnEnd::Cancelled,
                    _ => TurnEnd::Other,
                };
                let _ = self.events.send(AcpEvent::TurnEnded { reason });
                Ok(reason)
            }
            Err(e) => {
                if *self
                    .cancelled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                {
                    let _ = self.events.send(AcpEvent::TurnEnded {
                        reason: TurnEnd::Cancelled,
                    });
                    return Ok(TurnEnd::Cancelled);
                }
                Err(if self.process_ended() {
                    AcpError::Disconnected {
                        agent: self.agent_name.clone(),
                        stderr: stderr_suffix(&self.stderr),
                    }
                } else {
                    map_error(&self.agent_name, &e)
                })
            }
        }
    }

    fn process_ended(&self) -> bool {
        self.cx.is_incoming_closed()
    }

    /// Asks the agent to stop the running turn. Permission requests still waiting are answered
    /// as cancelled, as the protocol requires.
    pub fn cancel(&self) -> Result<(), AcpError> {
        *self
            .cancelled
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = true;
        let waiting: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for (_, tx) in waiting {
            let _ = tx.send(PermissionDecision::Cancel);
        }
        self.cx
            .send_notification(CancelNotification::new(self.session_id.clone()))
            .map_err(|e| map_error(&self.agent_name, &e))
    }

    /// Answers a permission request shown by an [`AcpEvent::PermissionRequested`]. Returns false
    /// when the request is not (or no longer) waiting.
    pub fn answer_permission(&self, request_id: u64, decision: PermissionDecision) -> bool {
        let tx = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&request_id);
        match tx {
            Some(tx) => tx.send(decision).is_ok(),
            None => false,
        }
    }

    /// Ends the session: cancels waiting requests, closes the connection and stops the agent
    /// (SIGTERM, then SIGKILL after a short grace period; the whole process group).
    pub async fn shutdown(mut self) -> Option<ExitInfo> {
        self.close().await
    }

    async fn close(&mut self) -> Option<ExitInfo> {
        let waiting: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .collect();
        for (_, tx) in waiting {
            let _ = tx.send(PermissionDecision::Cancel);
        }
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        // Closing stdin (the connection task owns it) lets a well-behaved agent exit by itself.
        if let Some(t) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), t).await;
        }
        let info = self.process.terminate(Duration::from_secs(2)).await;
        if let Some(i) = info {
            let _ = self.events.send(AcpEvent::Exited {
                code: i.code,
                signal: i.signal,
            });
        }
        info
    }
}

impl Drop for AcpHost {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        // The process handle kills the agent (group) when it is dropped; do it now.
        self.process.kill();
    }
}

struct ConnectionArgs {
    agent_name: String,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::process::ChildStdout,
    events: mpsc::UnboundedSender<AcpEvent>,
    pending: PendingMap,
    next_request: Arc<AtomicU64>,
    policy: PermissionPolicy,
    project_dir: PathBuf,
    mcp: Option<McpServerConfig>,
    ready: oneshot::Sender<Result<Ready, AcpError>>,
    shutdown: oneshot::Receiver<()>,
    stderr: StderrTail,
}

async fn run_connection(args: ConnectionArgs) {
    let ConnectionArgs {
        agent_name,
        stdin,
        stdout,
        events,
        pending,
        next_request,
        policy,
        project_dir,
        mcp,
        ready,
        shutdown,
        stderr,
    } = args;
    let transport = ByteStreams::new(stdin.compat_write(), stdout.compat());
    let note_events = events.clone();
    let perm_events = events.clone();
    let name_for_main = agent_name.clone();
    let ready_cell = Arc::new(Mutex::new(Some(ready)));
    let ready_for_main = ready_cell.clone();

    let result = Client
        .builder()
        .name("kraken")
        .on_receive_notification(
            async move |n: SessionNotification, _cx| {
                if let Some(ev) = translate(n.update) {
                    let _ = note_events.send(ev);
                }
                Ok(())
            },
            agent_client_protocol::on_receive_notification!(),
        )
        .on_receive_request(
            async move |req: RequestPermissionRequest, responder, cx: ConnectionTo<Agent>| {
                let id = next_request.fetch_add(1, Ordering::Relaxed);
                let info = permission_request(id, &req);
                let events = perm_events.clone();
                let pending = pending.clone();
                let policy = policy.clone();
                // Answering may take a person minutes; keep the connection serving meanwhile.
                cx.spawn(async move {
                    let _ = events.send(AcpEvent::PermissionRequested(info.clone()));
                    let decision = match policy {
                        PermissionPolicy::Handler(h) => h.decide(&info).await,
                        PermissionPolicy::AskUser => {
                            let (tx, rx) = oneshot::channel();
                            pending
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner)
                                .insert(id, tx);
                            rx.await.unwrap_or(PermissionDecision::Cancel)
                        }
                    };
                    let outcome = to_outcome(&decision, &info);
                    let selected = match &outcome {
                        RequestPermissionOutcome::Selected(s) => Some(s.option_id.to_string()),
                        _ => None,
                    };
                    let _ = events.send(AcpEvent::PermissionResolved {
                        request_id: id,
                        selected,
                    });
                    responder.respond(RequestPermissionResponse::new(outcome))
                })
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_req: WriteTextFileRequest, responder, _cx: ConnectionTo<Agent>| {
                responder.respond_with_error(declined("writing files"))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_req: ReadTextFileRequest, responder, _cx: ConnectionTo<Agent>| {
                responder.respond_with_error(declined("reading files"))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .on_receive_request(
            async move |_req: CreateTerminalRequest, responder, _cx: ConnectionTo<Agent>| {
                responder.respond_with_error(declined("terminals"))
            },
            agent_client_protocol::on_receive_request!(),
        )
        .connect_with(transport, async move |cx: ConnectionTo<Agent>| {
            let agent = name_for_main;
            let init = cx
                .send_request(
                    InitializeRequest::new(ProtocolVersion::V1)
                        .client_capabilities(ClientCapabilities::new())
                        .client_info(Implementation::new("kraken", env!("CARGO_PKG_VERSION"))),
                )
                .block_task()
                .await?;
            let info = AgentInfo {
                name: init.agent_info.as_ref().map(|i| i.name.clone()),
                version: init.agent_info.as_ref().map(|i| i.version.clone()),
                protocol_version: init.protocol_version.as_u16(),
                auth_methods: init
                    .auth_methods
                    .iter()
                    .filter_map(|m| {
                        serde_json::to_value(m)
                            .ok()
                            .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
                    })
                    .collect(),
            };
            let servers: Vec<McpServer> = mcp.iter().map(McpServerConfig::to_acp).collect();
            let session = cx
                .send_request(NewSessionRequest::new(project_dir).mcp_servers(servers))
                .block_task()
                .await;
            let session = match session {
                Ok(s) => s,
                Err(e) => {
                    let mapped = map_error(&agent, &e);
                    let mapped = match mapped {
                        AcpError::Agent { message, .. }
                            if !info.auth_methods.is_empty()
                                && message.to_ascii_lowercase().contains("required") =>
                        {
                            AcpError::AuthRequired { agent, message }
                        }
                        other => other,
                    };
                    send_ready(&ready_for_main, Err(mapped));
                    return Ok(());
                }
            };
            send_ready(
                &ready_for_main,
                Ok(Ready {
                    cx: cx.clone(),
                    session_id: session.session_id,
                    info,
                }),
            );
            // Keep the connection open until the host shuts down or the agent goes away.
            let _ = shutdown.await;
            Ok(())
        })
        .await;
    if let Err(e) = result {
        tracing::debug!(error = %e, "ACP connection ended with an error");
        send_ready(
            &ready_cell,
            Err(AcpError::Disconnected {
                agent: agent_name,
                stderr: format!("\n{e}{}", stderr_suffix(&stderr)),
            }),
        );
    }
}

fn send_ready(cell: &ReadyCell, v: Result<Ready, AcpError>) {
    if let Some(tx) = cell.lock().unwrap_or_else(PoisonError::into_inner).take() {
        let _ = tx.send(v);
    }
}

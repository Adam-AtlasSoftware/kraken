//! The terminal-agent backend: Claude Code, Codex or Gemini CLI over ACP as the assistant.
//!
//! The agent is launched by [`kraken_acp::AcpHost`] with the `kraken mcp` server as its MCP
//! server, so it reads and edits the project through the same command registry as every other
//! client, as an agent (additive edits apply, overwrites become proposals). This module maps
//! what the agent reports onto the event stream the API path emits:
//!
//! | ACP                          | [`AgentEvent`]                                   |
//! |------------------------------|--------------------------------------------------|
//! | message chunk                | `TextDelta`                                      |
//! | tool call started            | `ToolCallStarted` (KRAKEN tools by command name) |
//! | tool call completed / failed | `ToolCallFinished`, plus `ProposalCreated`       |
//! | permission request           | `ApprovalRequired` (answered with the handle)    |
//! | turn ended                   | `Done` with a [`StopReason`]                     |
//!
//! Permission requests for KRAKEN's own tools are answered here (the registry's policy is what
//! guards them); requests for the agent's own tools go to the person.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_acp::{
    AcpEvent, AcpHost, AgentProfile, AgentStatus, DenyAll, HostConfig, LaunchSpec, McpServerConfig,
    PermissionDecision, PermissionPolicy, PermissionRequest, Resolver, ToolCallChange,
    ToolCallInfo, TurnEnd,
};
use kraken_agent::{
    AgentError, AgentEvent, AgentRun, ApprovalDecision, ApprovalHandle, ChatRequest, Message,
    ProviderInfo, StopReason, Usage,
};
use kraken_proto::sanitize;
use kraken_registry::{CommandKind, Permission as RegPermission, Registry};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::backend::{
    AssistBackend, BackendInfo, BackendKind, Purpose, RunSpec, TextFuture, TextReply,
};
use crate::host::{CallRecord, HostStats, shape_output};

/// How the assistant addresses the agent before the task or chat text.
const PREAMBLE: &str = "\
You are running inside KRAKEN, a reverse engineering workbench, as its assistant. The program \
under analysis is open in KRAKEN, and KRAKEN's tools are available from the MCP server named \
`kraken` (tool names look like mcp__kraken__decompile). Use those tools to look at the program \
and, only when asked, to change the project. Where the instructions below name a tool such as \
decompile or rename_symbol, they mean the KRAKEN tool. Do not read the binary or the project \
files with shell commands or your own file tools, and do not run commands of your own unless the \
person asks you to.";

/// How a text-only request addresses the agent (see [`AssistBackend::complete_text`]). The fake
/// agent of `kraken-acp` recognises the first sentence.
pub const COMPLETION_PREAMBLE: &str = "\
KRAKEN text-only request. You are used here as a plain text model: everything you need is in \
this message. Do not use any tools. Do not read, write, create or delete files, do not run \
commands, and do not build or test anything: KRAKEN builds and checks your answer itself, in \
its own sandbox, and every request for permission to use your tools is denied. Reply with the \
answer in exactly the format asked for below.";

/// The agent the person chose, from the `[provider]` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentChoice {
    /// Agent id: `claude`, `codex`, `gemini`, or an id from `agents.toml`.
    pub agent: String,
    /// The model to ask the agent for.
    pub model: Option<String>,
    /// Extra command-line arguments for the agent.
    pub args: Vec<String>,
}

impl AgentChoice {
    /// The choice a `kind = "terminal_agent"` table describes; `None` for any other kind.
    pub fn from_config(cfg: &kraken_agent::ProviderConfig) -> Option<AgentChoice> {
        match cfg {
            kraken_agent::ProviderConfig::TerminalAgent { agent, model, args } => {
                Some(AgentChoice {
                    agent: agent.clone(),
                    model: model.clone().filter(|m| !m.trim().is_empty()),
                    args: args.clone(),
                })
            }
            _ => None,
        }
    }
}

/// Everything needed to start the agent on a project.
#[derive(Clone)]
pub struct AcpSettings {
    /// The agent, with the chosen model and arguments applied.
    pub profile: AgentProfile,
    /// How to start it.
    pub launch: LaunchSpec,
    /// The agent's working directory.
    pub project_dir: PathBuf,
    /// How it reaches KRAKEN's tools.
    pub mcp: McpServerConfig,
    /// The environment the agent's own is filtered from (`None`: this process's).
    pub parent_env: Option<Vec<(OsString, OsString)>>,
    /// How long it has to start.
    pub start_timeout: Duration,
    /// The model that was asked for, shown until the agent says which it uses.
    pub model: Option<String>,
}

/// Why an agent cannot be started, in words for the person.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    /// Not set up yet.
    #[error(
        "{name} is not set up yet ({reason}). Run `kraken agents setup {id}` or press Set up in Settings > AI"
    )]
    NeedsSetup {
        /// Agent id.
        id: String,
        /// Agent name.
        name: String,
        /// What is missing.
        reason: String,
    },
    /// Cannot run here.
    #[error("{name} cannot run: {reason}")]
    Unavailable {
        /// Agent name.
        name: String,
        /// Why.
        reason: String,
    },
}

/// Works out how to start `choice` on `project_dir`: finds the profile, applies the model and
/// arguments, and checks that it can run.
pub fn plan_agent(
    resolver: &Resolver,
    profiles: &[AgentProfile],
    choice: &AgentChoice,
    project_dir: &Path,
    mcp: McpServerConfig,
) -> Result<AcpSettings, PlanError> {
    let Some(base) = profiles.iter().find(|p| p.id == choice.agent) else {
        let known: Vec<&str> = profiles.iter().map(|p| p.id.as_str()).collect();
        return Err(PlanError::Unavailable {
            name: choice.agent.clone(),
            reason: format!(
                "there is no agent called `{}`; known agents: {}",
                choice.agent,
                known.join(", ")
            ),
        });
    };
    let profile = base
        .clone()
        .with_choice(choice.model.as_deref(), &choice.args);
    match resolver.status(&profile) {
        AgentStatus::Detected(launch) => Ok(AcpSettings {
            profile,
            launch,
            project_dir: project_dir.to_path_buf(),
            mcp,
            parent_env: None,
            start_timeout: Duration::from_secs(60),
            model: choice.model.clone(),
        }),
        AgentStatus::Available { reason, .. } => Err(PlanError::NeedsSetup {
            id: profile.id.clone(),
            name: profile.display_name.clone(),
            reason,
        }),
        AgentStatus::Missing { reason } | AgentStatus::Unsupported { reason } => {
            Err(PlanError::Unavailable {
                name: profile.display_name.clone(),
                reason,
            })
        }
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "kraken.exe"
    } else {
        "kraken"
    }
}

/// The `kraken` executable an agent should run as its MCP server: `KRAKEN_EXE`, else next to
/// the running program, else on `PATH`.
pub fn find_kraken_exe(path_env: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EXE") {
        return Some(PathBuf::from(p));
    }
    if let Ok(me) = std::env::current_exe()
        && let Some(sibling) = me.parent().map(|d| d.join(exe_name()))
        && sibling.is_file()
    {
        return Some(sibling);
    }
    kraken_acp::node::find_in_path(exe_name(), path_env)
}

/// Splits a tool title into a short name and whether it is a KRAKEN tool. Agents name MCP tools
/// `mcp__kraken__decompile` (Claude Code), `kraken.decompile`, `kraken:decompile` or
/// `kraken/decompile`.
pub fn classify_tool(title: &str) -> (String, bool) {
    let t = title.trim();
    for prefix in ["mcp__kraken__", "kraken__", "kraken.", "kraken:", "kraken/"] {
        if let Some(rest) = t.strip_prefix(prefix)
            && !rest.is_empty()
        {
            let name = rest.split_whitespace().next().unwrap_or(rest);
            return (name.to_string(), true);
        }
    }
    (t.to_string(), false)
}

fn parse_input(input: Option<&str>) -> Value {
    match input {
        None => Value::Null,
        Some(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string())),
    }
}

fn has_content(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Object(m) => !m.is_empty(),
        _ => true,
    }
}

fn one_line(s: &str, max: usize) -> String {
    let flat = sanitize(s).split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > max {
        let cut: String = flat.chars().take(max).collect();
        format!("{cut}...")
    } else {
        flat
    }
}

struct ToolState {
    name: String,
    kraken: bool,
    args: Value,
    started: bool,
    finished: bool,
}

/// Turns what the agent reports into [`AgentEvent`]s and a record of its KRAKEN tool calls.
struct Mapper {
    registry: Arc<Registry>,
    tools: HashMap<String, ToolState>,
    stats: HostStats,
}

impl Mapper {
    fn new(registry: Arc<Registry>) -> Self {
        Mapper {
            registry,
            tools: HashMap::new(),
            stats: HostStats::default(),
        }
    }

    fn event(&mut self, ev: AcpEvent) -> Vec<AgentEvent> {
        match ev {
            AcpEvent::AgentText { text } => {
                vec![AgentEvent::TextDelta {
                    text: sanitize(&text),
                }]
            }
            AcpEvent::ToolCall(info) => self.tool_call(info),
            AcpEvent::ToolCallUpdate(change) => self.tool_update(change),
            _ => Vec::new(),
        }
    }

    fn tool_call(&mut self, info: ToolCallInfo) -> Vec<AgentEvent> {
        let (name, kraken) = classify_tool(&info.title);
        let args = parse_input(info.input.as_deref());
        let status = info.status.clone();
        self.tools.insert(
            info.id.clone(),
            ToolState {
                name,
                kraken,
                args,
                started: false,
                finished: false,
            },
        );
        self.advance(&info.id, &status, None)
    }

    fn tool_update(&mut self, c: ToolCallChange) -> Vec<AgentEvent> {
        let Some(t) = self.tools.get_mut(&c.id) else {
            return Vec::new();
        };
        if let Some(title) = &c.title {
            let (name, kraken) = classify_tool(title);
            t.name = name;
            t.kraken = kraken;
        }
        if let Some(input) = c.input.as_deref() {
            let args = parse_input(Some(input));
            if has_content(&args) {
                t.args = args;
            }
        }
        let status = c.status.clone().unwrap_or_default();
        self.advance(&c.id, &status, c.output.as_deref())
    }

    /// Emits the events a tool call has earned: started once its input is known (or it moved
    /// on), finished when it completed or failed.
    fn advance(&mut self, id: &str, status: &str, output: Option<&str>) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        let Some(t) = self.tools.get_mut(id) else {
            return out;
        };
        let moved_on = matches!(status, "in_progress" | "completed" | "failed");
        if !t.started && (has_content(&t.args) || moved_on) {
            t.started = true;
            out.push(AgentEvent::ToolCallStarted {
                id: id.to_string(),
                name: sanitize(&t.name),
                arguments: t.args.clone(),
            });
        }
        if t.finished || !matches!(status, "completed" | "failed") {
            return out;
        }
        t.finished = true;
        let is_error = status == "failed";
        let summary = match output {
            Some(o) if !o.trim().is_empty() => one_line(o, 200),
            _ => (if is_error { "failed" } else { "done" }).to_string(),
        };
        let (name, kraken, args) = (t.name.clone(), t.kraken, t.args.clone());
        out.push(AgentEvent::ToolCallFinished {
            id: id.to_string(),
            name: sanitize(&name),
            summary,
            is_error,
        });
        if kraken {
            let result: Option<Value> = output.and_then(|o| serde_json::from_str(o.trim()).ok());
            let status_word = result
                .as_ref()
                .and_then(|v| v.get("status"))
                .and_then(Value::as_str)
                .map(str::to_string);
            let is_write = self
                .registry
                .get(&name)
                .is_some_and(|e| e.spec().kind == CommandKind::Mutation);
            self.stats.calls.push(CallRecord {
                tool: name.clone(),
                args,
                ok: !is_error,
                status: status_word,
                error_code: is_error.then(|| "failed".to_string()),
                is_write,
            });
            if let Some(v) = result {
                let shaped = shape_output(v);
                if let Some(proposal) = shaped.get("proposal") {
                    out.push(AgentEvent::ProposalCreated {
                        tool: name,
                        call_id: id.to_string(),
                        proposal: proposal.clone(),
                    });
                }
            }
        }
        out
    }

    /// Starts any call that never got going, so the stream is complete when the turn ends.
    fn flush(&mut self) -> Vec<AgentEvent> {
        let mut out = Vec::new();
        let mut ids: Vec<String> = self
            .tools
            .iter()
            .filter(|(_, t)| !t.started)
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        for id in ids {
            if let Some(t) = self.tools.get_mut(&id) {
                t.started = true;
                out.push(AgentEvent::ToolCallStarted {
                    id: id.clone(),
                    name: sanitize(&t.name),
                    arguments: t.args.clone(),
                });
            }
        }
        out
    }
}

/// The text the agent is prompted with.
fn compose_prompt(spec: &RunSpec, fresh: bool) -> String {
    let last = spec
        .messages
        .iter()
        .rev()
        .find_map(|m| match m {
            Message::User { content } => Some(content.as_str()),
            _ => None,
        })
        .unwrap_or_default();
    let mut text = String::new();
    if fresh {
        text.push_str(PREAMBLE);
        if let Some(extra) = spec.config.system_extra.as_deref()
            && !extra.trim().is_empty()
        {
            text.push_str("\n\n");
            text.push_str(extra);
        }
        let earlier: Vec<String> = spec
            .messages
            .iter()
            .take(spec.messages.len().saturating_sub(1))
            .filter_map(|m| match m {
                Message::User { content } => Some(format!("Person: {content}")),
                Message::Assistant { content, .. } if !content.trim().is_empty() => {
                    Some(format!("You: {content}"))
                }
                _ => None,
            })
            .collect();
        if !earlier.is_empty() {
            text.push_str("\n\nThe conversation so far:\n");
            text.push_str(&earlier.join("\n"));
        }
        text.push_str("\n\n---\n\n");
    }
    text.push_str(last);
    text
}

fn stop_for(end: TurnEnd) -> (StopReason, Option<&'static str>) {
    match end {
        TurnEnd::EndTurn => (StopReason::Completed, None),
        TurnEnd::MaxTokens => (StopReason::TokenBudget, None),
        TurnEnd::MaxTurnRequests => (StopReason::MaxSteps, None),
        TurnEnd::Cancelled => (StopReason::Cancelled, None),
        TurnEnd::Refusal => (StopReason::Error, Some("the agent declined to answer")),
        TurnEnd::Other => (StopReason::Error, Some("the agent stopped early")),
    }
}

struct Live {
    host: AcpHost,
    rx: mpsc::UnboundedReceiver<AcpEvent>,
}

#[derive(Default)]
struct Shared {
    notes: Mutex<Vec<String>>,
    model: Mutex<Option<String>>,
    stats: Mutex<HashMap<String, HostStats>>,
    chat: Mutex<Option<Live>>,
    active: Mutex<Option<CancellationToken>>,
    closed: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A terminal agent as the assistant.
pub struct AcpBackend {
    settings: AcpSettings,
    registry: Arc<Registry>,
    shared: Arc<Shared>,
}

impl AcpBackend {
    /// A backend that starts the agent described by `settings` on demand.
    pub fn new(settings: AcpSettings, registry: Arc<Registry>) -> Self {
        AcpBackend {
            settings,
            registry,
            shared: Arc::default(),
        }
    }

    /// The agent's settings.
    pub fn settings(&self) -> &AcpSettings {
        &self.settings
    }

    /// A text-only request in a fresh session: no KRAKEN MCP server, an empty scratch directory
    /// as the working directory, every permission request denied. The reply is what the agent
    /// said; whatever it did or tried to do besides is not used.
    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<TextReply, AgentError> {
        let fail = |m: String| AgentError::Provider(m);
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(fail("the assistant was closed".into()));
        }
        let scratch = tempfile::Builder::new()
            .prefix("kraken-agent-text-")
            .tempdir()
            .map_err(|e| {
                fail(format!(
                    "cannot make a scratch directory for the agent: {e}"
                ))
            })?;
        let mut cfg = HostConfig::new(
            self.settings.profile.clone(),
            self.settings.launch.clone(),
            scratch.path().to_path_buf(),
            None,
        );
        cfg.permission = PermissionPolicy::Handler(Arc::new(DenyAll));
        cfg.parent_env = self.settings.parent_env.clone();
        cfg.start_timeout = self.settings.start_timeout;
        let started = tokio::select! {
            r = AcpHost::start(cfg) => r,
            () = cancel.cancelled() => return Err(AgentError::Cancelled),
        };
        let (host, mut rx) = started.map_err(|e| fail(e.to_string()))?;

        let prompt = compose_completion(&req);
        let mut text = String::new();
        let mut denied = 0usize;
        let mut own_calls = 0usize;
        let mut cancelled = false;
        let mut absorb = |ev: AcpEvent| match ev {
            AcpEvent::Started { agent, .. } => {
                if let Some(m) = agent.model {
                    *lock(&self.shared.model) = Some(m);
                }
            }
            AcpEvent::AgentText { text: t } => text.push_str(&t),
            AcpEvent::ToolCall(_) => own_calls += 1,
            AcpEvent::PermissionRequested(_) => denied += 1,
            AcpEvent::Info { kind } => {
                if let Some(w) = kind.strip_prefix("warning: ") {
                    lock(&self.shared.notes).push(w.to_string());
                }
            }
            _ => {}
        };
        let result = {
            let fut = host.prompt(&prompt);
            tokio::pin!(fut);
            loop {
                tokio::select! {
                    Some(ev) = rx.recv() => absorb(ev),
                    () = cancel.cancelled(), if !cancelled => {
                        cancelled = true;
                        let _ = host.cancel();
                    }
                    res = &mut fut => break res,
                }
            }
        };
        while let Ok(ev) = rx.try_recv() {
            absorb(ev);
        }
        host.shutdown().await;
        drop(scratch);
        if denied > 0 || own_calls > 0 {
            lock(&self.shared.notes).push(format!(
                "{} was given a text-only request but tried to use its own tools ({own_calls} \
                 calls, {denied} permission requests); every permission request was denied and only its \
                 text reply was used, but tools its own settings allow without asking may have \
                 run",
                self.settings.profile.display_name
            ));
        }
        if cancelled {
            return Err(AgentError::Cancelled);
        }
        match result {
            Ok(end) => match stop_for(end) {
                (StopReason::Completed | StopReason::TokenBudget | StopReason::MaxSteps, None) => {}
                (StopReason::Cancelled, _) => return Err(AgentError::Cancelled),
                (_, why) => {
                    return Err(fail(why.unwrap_or("the agent stopped early").to_string()));
                }
            },
            Err(e) => return Err(fail(e.to_string())),
        }
        if text.trim().is_empty() {
            return Err(fail("the agent returned no text".into()));
        }
        Ok(TextReply {
            text,
            usage: Usage::default(),
            provider: self.provider_info(),
        })
    }
}

/// The prompt of a text-only request: the fixed instructions, then the request's system text and
/// messages (a conversation is shown with who said what, as a fresh agent session has no memory).
fn compose_completion(req: &ChatRequest) -> String {
    let mut out = String::from(COMPLETION_PREAMBLE);
    if !req.system.trim().is_empty() {
        out.push_str("\n\n");
        out.push_str(req.system.trim());
    }
    out.push_str("\n\n---\n\n");
    let single = req.messages.len() == 1;
    let mut parts: Vec<String> = Vec::new();
    for m in &req.messages {
        match m {
            Message::User { content } if single => parts.push(content.clone()),
            Message::User { content } => parts.push(format!("Request:\n{content}")),
            Message::Assistant { content, .. } if !content.trim().is_empty() => {
                parts.push(format!("Your earlier answer:\n{content}"));
            }
            _ => {}
        }
    }
    out.push_str(&parts.join("\n\n"));
    out
}

impl AssistBackend for AcpBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            kind: BackendKind::TerminalAgent,
            id: self.settings.profile.id.clone(),
            name: self.settings.profile.display_name.clone(),
            model: lock(&self.shared.model)
                .clone()
                .or_else(|| self.settings.model.clone()),
        }
    }

    fn provider_info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.settings.profile.id.clone(),
            model: self.info().model.unwrap_or_default(),
            supports_tools: true,
            context_window: None,
        }
    }

    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_> {
        Box::pin(self.complete(req, cancel))
    }

    fn start(&self, spec: RunSpec) -> AgentRun {
        let (tx, rx) = mpsc::channel(64);
        let (handle, approvals) = ApprovalHandle::channel();
        let cancel = CancellationToken::new();
        let job = Job {
            settings: self.settings.clone(),
            registry: self.registry.clone(),
            shared: self.shared.clone(),
            spec,
            tx,
            approvals,
            cancel: cancel.clone(),
        };
        tokio::spawn(job.run());
        AgentRun::from_parts(rx, handle, cancel)
    }

    fn take_stats(&self, run_id: &str) -> Option<HostStats> {
        lock(&self.shared.stats).remove(run_id)
    }

    fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *lock(&self.shared.notes))
    }

    fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Some(c) = lock(&self.shared.active).as_ref() {
            c.cancel();
        }
        // Dropping the host kills the agent.
        drop(lock(&self.shared.chat).take());
    }
}

struct Job {
    settings: AcpSettings,
    registry: Arc<Registry>,
    shared: Arc<Shared>,
    spec: RunSpec,
    tx: mpsc::Sender<AgentEvent>,
    approvals: mpsc::UnboundedReceiver<(String, ApprovalDecision)>,
    cancel: CancellationToken,
}

fn approval_arguments(req: &PermissionRequest) -> Value {
    json!({
        "title": req.title,
        "kind": req.tool_kind,
        "input": req.input,
        "paths": req.paths,
        "options": req.options.iter().map(|o| o.name.clone()).collect::<Vec<_>>(),
    })
}

impl Job {
    async fn send(&self, ev: AgentEvent) -> bool {
        self.tx.send(ev).await.is_ok()
    }

    async fn finish_with_error(&self, message: String) {
        let _ = self
            .send(AgentEvent::Error {
                message: message.clone(),
            })
            .await;
        let _ = self
            .send(AgentEvent::Done {
                usage: Usage::default(),
                stop: StopReason::Error,
                message,
            })
            .await;
    }

    async fn start_session(&self) -> Result<Live, kraken_acp::AcpError> {
        let mut mcp = self.settings.mcp.clone();
        // Edits made through the agent's MCP server are logged under this run, so
        // `undo_run` and the task result's run id mean the same thing on both backends.
        mcp.args.push("--run-id".into());
        mcp.args.push(self.spec.config.run_id.clone());
        let mut cfg = HostConfig::new(
            self.settings.profile.clone(),
            self.settings.launch.clone(),
            self.settings.project_dir.clone(),
            Some(mcp),
        );
        cfg.permission = PermissionPolicy::AskUser;
        cfg.parent_env = self.settings.parent_env.clone();
        cfg.start_timeout = self.settings.start_timeout;
        let (host, rx) = AcpHost::start(cfg).await?;
        Ok(Live { host, rx })
    }

    /// The answer KRAKEN can give without asking the person: its own tools are guarded by the
    /// registry's policy.
    fn auto_decision(
        &self,
        req: &PermissionRequest,
        read_only: bool,
    ) -> Option<PermissionDecision> {
        let (name, kraken) = classify_tool(&req.title);
        if !kraken {
            return None;
        }
        // A task names the tools it may use; the agent's MCP server offers all of them, so
        // anything else is refused here.
        if matches!(self.spec.purpose, Purpose::Task { .. })
            && !self.spec.tools.tools().iter().any(|t| t.name == name)
        {
            return Some(req.reject());
        }
        let entry = self.registry.get(&name)?;
        let spec = entry.spec();
        if spec.permission == RegPermission::Dangerous {
            return None;
        }
        if read_only && spec.kind == CommandKind::Mutation {
            return Some(req.reject());
        }
        Some(req.allow())
    }

    async fn run(mut self) {
        let chat = matches!(self.spec.purpose, Purpose::Chat);
        let read_only = matches!(self.spec.purpose, Purpose::Task { read_only: true });
        if self.shared.closed.load(Ordering::SeqCst) {
            self.finish_with_error("the assistant was closed".to_string())
                .await;
            return;
        }
        *lock(&self.shared.active) = Some(self.cancel.clone());

        let kept = if chat {
            lock(&self.shared.chat).take()
        } else {
            None
        };
        let fresh = kept.is_none();
        let live = match kept {
            Some(l) => l,
            None => {
                let started = tokio::select! {
                    r = self.start_session() => r,
                    () = self.cancel.cancelled() => {
                        let _ = self.send(AgentEvent::Done {
                            usage: Usage::default(),
                            stop: StopReason::Cancelled,
                            message: String::new(),
                        }).await;
                        return;
                    }
                };
                match started {
                    Ok(l) => l,
                    Err(e) => {
                        self.finish_with_error(e.to_string()).await;
                        return;
                    }
                }
            }
        };
        let Live { host, mut rx } = live;
        let prompt = compose_prompt(&self.spec, fresh);
        let mut mapper = Mapper::new(self.registry.clone());
        let mut waiting: HashMap<String, PermissionRequest> = HashMap::new();
        let mut cancelled = false;
        let mut last_step = String::new();
        let mut after_tool = false;
        let mut gone = false;

        let result = {
            let fut = host.prompt(&prompt);
            tokio::pin!(fut);
            loop {
                tokio::select! {
                    Some(ev) = rx.recv() => {
                        if !self.handle(&host, ev, &mut mapper, &mut waiting, read_only,
                                        &mut last_step, &mut after_tool).await
                        {
                            gone = true;
                            if !cancelled {
                                cancelled = true;
                                let _ = host.cancel();
                            }
                        }
                    }
                    Some((id, decision)) = self.approvals.recv() => {
                        if let Some(req) = waiting.remove(&id) {
                            let d = match decision {
                                ApprovalDecision::Approve => req.allow(),
                                ApprovalDecision::Deny => req.reject(),
                            };
                            host.answer_permission(req.request_id, d);
                        }
                    }
                    () = self.cancel.cancelled(), if !cancelled => {
                        cancelled = true;
                        let _ = host.cancel();
                    }
                    res = &mut fut => break res,
                }
            }
        };
        while let Ok(ev) = rx.try_recv() {
            self.handle(
                &host,
                ev,
                &mut mapper,
                &mut waiting,
                read_only,
                &mut last_step,
                &mut after_tool,
            )
            .await;
        }
        for ev in mapper.flush() {
            let _ = self.send(ev).await;
        }
        lock(&self.shared.stats).insert(self.spec.config.run_id.clone(), mapper.stats.clone());

        let mut keep = chat && !gone;
        match result {
            Ok(end) => {
                let (stop, why) = stop_for(end);
                if let Some(why) = why {
                    let _ = self
                        .send(AgentEvent::Error {
                            message: why.to_string(),
                        })
                        .await;
                }
                let _ = self
                    .send(AgentEvent::Done {
                        usage: Usage::default(),
                        stop,
                        message: last_step.trim().to_string(),
                    })
                    .await;
            }
            Err(e) => {
                keep = false;
                self.finish_with_error(e.to_string()).await;
            }
        }
        *lock(&self.shared.active) = None;
        if keep && !self.shared.closed.load(Ordering::SeqCst) {
            *lock(&self.shared.chat) = Some(Live { host, rx });
        } else {
            host.shutdown().await;
        }
    }

    /// Maps one ACP event. False when nobody listens to the run any more.
    #[allow(clippy::too_many_arguments)]
    async fn handle(
        &self,
        host: &AcpHost,
        ev: AcpEvent,
        mapper: &mut Mapper,
        waiting: &mut HashMap<String, PermissionRequest>,
        read_only: bool,
        last_step: &mut String,
        after_tool: &mut bool,
    ) -> bool {
        match &ev {
            AcpEvent::Started { agent, .. } => {
                if let Some(m) = &agent.model {
                    *lock(&self.shared.model) = Some(m.clone());
                }
                return true;
            }
            AcpEvent::Info { kind } => {
                if let Some(w) = kind.strip_prefix("warning: ") {
                    lock(&self.shared.notes).push(w.to_string());
                }
                return true;
            }
            AcpEvent::PermissionRequested(req) => {
                if let Some(d) = self.auto_decision(req, read_only) {
                    host.answer_permission(req.request_id, d);
                    return true;
                }
                let id = req.request_id.to_string();
                waiting.insert(id.clone(), req.clone());
                return self
                    .send(AgentEvent::ApprovalRequired {
                        id,
                        name: sanitize(&req.title),
                        arguments: approval_arguments(req),
                    })
                    .await;
            }
            AcpEvent::PermissionResolved { request_id, .. } => {
                waiting.remove(&request_id.to_string());
                return true;
            }
            _ => {}
        }
        let mut alive = true;
        for out in mapper.event(ev) {
            match &out {
                AgentEvent::TextDelta { text } => {
                    if *after_tool {
                        last_step.clear();
                        *after_tool = false;
                    }
                    last_step.push_str(text);
                }
                AgentEvent::ToolCallStarted { .. } => *after_tool = true,
                _ => {}
            }
            alive &= self.send(out).await;
        }
        alive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapper() -> Mapper {
        Mapper::new(Arc::new(Registry::standard()))
    }

    fn call(id: &str, title: &str, status: &str, input: Option<&str>) -> AcpEvent {
        AcpEvent::ToolCall(ToolCallInfo {
            id: id.into(),
            title: title.into(),
            kind: "other".into(),
            status: status.into(),
            paths: vec![],
            input: input.map(str::to_string),
        })
    }

    fn update(id: &str, status: Option<&str>, input: Option<&str>, out: Option<&str>) -> AcpEvent {
        AcpEvent::ToolCallUpdate(ToolCallChange {
            id: id.into(),
            title: None,
            status: status.map(str::to_string),
            output: out.map(str::to_string),
            input: input.map(str::to_string),
        })
    }

    #[test]
    fn tool_titles_are_classified_like_each_agent_names_them() {
        for title in [
            "mcp__kraken__decompile",
            "kraken.decompile",
            "kraken:decompile",
            "kraken/decompile",
            "kraken__decompile",
        ] {
            assert_eq!(
                classify_tool(title),
                ("decompile".to_string(), true),
                "{title}"
            );
        }
        assert_eq!(
            classify_tool("Run rm -rf build"),
            ("Run rm -rf build".to_string(), false)
        );
        assert_eq!(
            classify_tool("mcp__kraken__"),
            ("mcp__kraken__".to_string(), false)
        );
    }

    #[test]
    fn a_call_waits_for_its_input_and_is_started_exactly_once() {
        let mut m = mapper();
        // Agents often announce a call before its input is known.
        assert!(
            m.event(call("a", "mcp__kraken__decompile", "pending", None))
                .is_empty()
        );
        let started = m.event(update(
            "a",
            Some("pending"),
            Some(r#"{"address":"0x401000"}"#),
            None,
        ));
        assert_eq!(started.len(), 1);
        match &started[0] {
            AgentEvent::ToolCallStarted {
                id,
                name,
                arguments,
            } => {
                assert_eq!((id.as_str(), name.as_str()), ("a", "decompile"));
                assert_eq!(arguments["address"], "0x401000");
            }
            other => panic!("{other:?}"),
        }
        let done = m.event(update("a", Some("completed"), None, Some("int f(void) {}")));
        assert!(matches!(
            done.as_slice(),
            [AgentEvent::ToolCallFinished { is_error: false, summary, .. }] if summary == "int f(void) {}"
        ));
        // A repeated completion changes nothing.
        assert!(
            m.event(update("a", Some("completed"), None, None))
                .is_empty()
        );
        assert_eq!(m.stats.calls.len(), 1);
        assert_eq!(m.stats.calls[0].tool, "decompile");
        assert!(!m.stats.calls[0].is_write);
    }

    #[test]
    fn a_call_that_never_got_going_is_started_when_the_turn_ends() {
        let mut m = mapper();
        assert!(m.event(call("a", "Run ls", "pending", None)).is_empty());
        let rest = m.flush();
        assert!(matches!(
            rest.as_slice(),
            [AgentEvent::ToolCallStarted { name, .. }] if name == "Run ls"
        ));
    }

    #[test]
    fn writes_are_recorded_with_their_status_and_proposals_are_announced() {
        let mut m = mapper();
        m.event(call(
            "w",
            "mcp__kraken__rename_symbol",
            "in_progress",
            Some(r#"{"address":"0x401040","new_name":"x"}"#),
        ));
        let out = m.event(update(
            "w",
            Some("completed"),
            None,
            Some(r#"{"status":"proposed","proposal_id":3,"key":"k","reason":"overwrites"}"#),
        ));
        assert!(out.iter().any(
            |e| matches!(e, AgentEvent::ProposalCreated { tool, proposal, .. }
                if tool == "rename_symbol" && proposal["proposal_id"] == 3)
        ));
        let rec = &m.stats.calls[0];
        assert!(rec.is_write && rec.ok);
        assert_eq!(rec.status.as_deref(), Some("proposed"));
        assert_eq!(m.stats.writes_with_status("proposed"), 1);

        // The agent's own tools are shown but never counted as KRAKEN calls.
        m.event(call(
            "s",
            "Run strings",
            "completed",
            Some(r#"{"command":"strings x"}"#),
        ));
        assert_eq!(m.stats.calls.len(), 1);
    }

    #[test]
    fn failed_calls_are_errors_and_text_is_sanitised() {
        let mut m = mapper();
        m.event(call(
            "f",
            "mcp__kraken__decompile",
            "in_progress",
            Some("{}"),
        ));
        let out = m.event(update(
            "f",
            Some("failed"),
            None,
            Some("not_found: no such function"),
        ));
        assert!(matches!(
            out.as_slice(),
            [AgentEvent::ToolCallFinished { is_error: true, .. }]
        ));
        assert!(!m.stats.calls[0].ok);
        let t = m.event(AcpEvent::AgentText {
            text: "hi \u{1b}[31mred".into(),
        });
        assert!(matches!(&t[0], AgentEvent::TextDelta { text } if !text.contains('\u{1b}')));
    }

    fn spec(messages: Vec<Message>, extra: &str) -> RunSpec {
        RunSpec {
            messages,
            config: kraken_agent::AgentConfig {
                system_extra: Some(extra.into()),
                ..Default::default()
            },
            tools: Arc::new(crate::host::RegistryToolHost::new(
                Arc::new(Registry::standard()),
                Arc::new(crate::backend::UnusedBackend),
                crate::host::HostOptions::default(),
            )),
            purpose: Purpose::Chat,
        }
    }

    #[test]
    fn the_first_prompt_carries_the_instructions_and_a_catch_up_and_later_ones_do_not() {
        let history = vec![
            Message::user("first question"),
            Message::Assistant {
                content: "first answer".into(),
                tool_calls: vec![],
            },
            Message::user("second question"),
        ];
        let first = compose_prompt(&spec(history.clone(), "BE PLAIN"), true);
        assert!(first.starts_with(PREAMBLE));
        assert!(first.contains("BE PLAIN"));
        assert!(first.contains("Person: first question") && first.contains("You: first answer"));
        assert!(first.ends_with("second question"));
        let later = compose_prompt(&spec(history, "BE PLAIN"), false);
        assert_eq!(later, "second question");
        // A one-message conversation has nothing to catch up on.
        let single = compose_prompt(&spec(vec![Message::user("hi")], "X"), true);
        assert!(!single.contains("conversation so far"));
    }

    #[test]
    fn turn_ends_map_onto_stop_reasons() {
        assert_eq!(stop_for(TurnEnd::EndTurn).0, StopReason::Completed);
        assert_eq!(stop_for(TurnEnd::Cancelled).0, StopReason::Cancelled);
        assert_eq!(stop_for(TurnEnd::MaxTurnRequests).0, StopReason::MaxSteps);
        assert_eq!(stop_for(TurnEnd::MaxTokens).0, StopReason::TokenBudget);
        let (stop, why) = stop_for(TurnEnd::Refusal);
        assert_eq!(stop, StopReason::Error);
        assert!(why.is_some());
    }
}

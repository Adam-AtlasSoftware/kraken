//! One terminal-agent session: start, prompt, stream, permission requests, stop.

use std::path::PathBuf;

use kraken_acp::{
    AcpError, AcpEvent, AcpHost, HostConfig, McpServerConfig, PermissionDecision, PermissionPolicy,
    PermissionRequest, PlanStep, ToolCallChange, ToolCallInfo, TurnEnd,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::Availability;
use crate::vm::ViewModel;

/// How a session is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPhase {
    /// The agent is starting (this can take a few seconds).
    Starting,
    /// Ready for a prompt, or working on one.
    Ready,
    /// Over (plain-language reason).
    Ended(String),
}

/// A tool call, shown as a compact chip.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentTool {
    /// The agent's id for the call.
    pub id: String,
    /// The agent's title for it.
    pub title: String,
    /// A short name: the KRAKEN command for KRAKEN tools, else the title.
    pub name: String,
    /// A call to one of KRAKEN's own tools (through its MCP server). Anything else is one of the
    /// agent's own tools, which KRAKEN does not sandbox.
    pub is_kraken: bool,
    /// `read`, `edit`, `execute`, `other`, ...
    pub kind: String,
    /// `pending`, `in_progress`, `completed` or `failed`.
    pub status: String,
    /// Files involved.
    pub paths: Vec<String>,
    /// The input, shortened.
    pub input: Option<String>,
    /// What the tool produced, shortened.
    pub output: Option<String>,
}

impl AgentTool {
    /// Waiting or running.
    pub fn working(&self) -> bool {
        matches!(self.status.as_str(), "pending" | "in_progress")
    }

    /// Ended with an error.
    pub fn failed(&self) -> bool {
        self.status == "failed"
    }
}

/// Where a permission request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    /// Waiting for the person.
    Waiting,
    /// Allowed.
    Allowed,
    /// Denied.
    Denied,
    /// Withdrawn (the turn was stopped).
    Withdrawn,
}

/// A permission request, shown inline.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionCard {
    /// What the agent wants to do.
    pub request: PermissionRequest,
    /// Where it stands.
    pub state: PermissionState,
}

/// One line of the agent's plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanLine {
    /// The step.
    pub text: String,
    /// `pending`, `in_progress` or `completed`.
    pub status: String,
}

/// One entry of the session.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentItem {
    /// What the person asked.
    User(String),
    /// What the agent said; `streaming` while words still arrive.
    Text {
        /// Text so far.
        text: String,
        /// More is coming.
        streaming: bool,
    },
    /// The agent's reasoning.
    Thought(String),
    /// A tool call.
    Tool(AgentTool),
    /// A permission request.
    Permission(PermissionCard),
    /// The agent's plan (always the whole list).
    Plan(Vec<PlanLine>),
    /// A neutral line ("Stopped.").
    Notice(String),
    /// Something went wrong (plain language).
    Error(String),
}

/// The session shown in the Agents tab.
#[derive(Debug)]
pub struct AgentSession {
    pub(crate) seq: u64,
    pub(crate) cmds: UnboundedSender<Cmd>,
    /// Agent id.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// What the agent says it is ("claude-agent-acp 0.89.1"), once connected.
    pub agent_label: Option<String>,
    /// The model it uses, when it says.
    pub model: Option<String>,
    /// The project directory the agent works in.
    pub project_dir: String,
    /// How the agent reaches KRAKEN's tools, for the header.
    pub tools_via: &'static str,
    /// Where it stands.
    pub phase: SessionPhase,
    /// The conversation, oldest first.
    pub items: Vec<AgentItem>,
    /// A prompt is running.
    pub busy: bool,
    /// Stop was pressed and the agent has not yet confirmed.
    pub stopping: bool,
    /// The last lines the agent wrote to its error output.
    pub stderr_tail: Vec<String>,
    pub(crate) used_kraken_tools: bool,
}

impl AgentSession {
    /// Permission requests that wait for an answer.
    pub fn waiting_permissions(&self) -> usize {
        self.items
            .iter()
            .filter(
                |i| matches!(i, AgentItem::Permission(c) if c.state == PermissionState::Waiting),
            )
            .count()
    }

    fn close_stream(&mut self) {
        for item in self.items.iter_mut().rev() {
            if let AgentItem::Text { streaming, .. } = item {
                *streaming = false;
                break;
            }
        }
    }

    fn push(&mut self, item: AgentItem) {
        self.close_stream();
        self.items.push(item);
    }
}

#[derive(Debug)]
pub(crate) enum Cmd {
    Prompt(String),
    Cancel,
    Answer(u64, PermissionDecision),
    Shutdown,
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

fn tool_from(info: ToolCallInfo) -> AgentTool {
    let (name, is_kraken) = classify_tool(&info.title);
    AgentTool {
        id: info.id,
        title: info.title,
        name,
        is_kraken,
        kind: info.kind,
        status: info.status,
        paths: info.paths,
        input: info.input,
        output: None,
    }
}

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "kraken.exe"
    } else {
        "kraken"
    }
}

/// The `kraken` executable the agent should run as its MCP server.
fn find_kraken_exe(cfg: &super::AgentsConfig) -> Option<PathBuf> {
    if let Some(p) = &cfg.kraken_exe {
        return Some(p.clone());
    }
    if let Some(p) = std::env::var_os("KRAKEN_EXE") {
        return Some(PathBuf::from(p));
    }
    if let Ok(me) = std::env::current_exe()
        && let Some(sibling) = me.parent().map(|d| d.join(exe_name()))
        && sibling.is_file()
    {
        return Some(sibling);
    }
    kraken_acp::node::find_in_path(exe_name(), cfg.resolver.path_env.as_deref())
}

fn end_text(code: Option<i32>, signal: Option<i32>) -> String {
    match (code, signal) {
        (Some(0), _) => "The agent has finished.".to_string(),
        (Some(c), _) => format!("The agent stopped unexpectedly (exit code {c})."),
        (None, Some(s)) => format!("The agent was stopped by signal {s}."),
        (None, None) => "The agent stopped.".to_string(),
    }
}

impl ViewModel {
    /// Starts `id` on the open project. Shows the one-time warning first when it was not yet
    /// acknowledged; [`agents_acknowledge`](Self::agents_acknowledge) then continues.
    pub fn agents_start(&mut self, id: &str) {
        self.agents.error = None;
        if self.agents.in_session() {
            self.agents.error = Some("An agent is already running; stop it first.".into());
            return;
        }
        let Some(row) = self.agents.row(id).cloned() else {
            return;
        };
        let Some(launch) = row.launch.clone().filter(|_| row.is_ready()) else {
            let why = match &row.availability {
                Availability::Ready { .. } => "it is not ready".to_string(),
                other => other.detail().to_string(),
            };
            self.agents.error = Some(format!("{} cannot start: {why}", row.name));
            return;
        };
        if !self.agents.notice.acknowledged {
            self.agents.pending_notice = Some(id.to_string());
            return;
        }
        let Some(project) = self.project.as_ref().map(|p| p.project_dir.clone()) else {
            self.agents.error = Some("Open a project first; the agent works on it.".into());
            return;
        };
        let Some(cfg) = self.agents.config.clone() else {
            return;
        };
        let Some(exe) = find_kraken_exe(&cfg) else {
            self.agents.error = Some(
                "KRAKEN cannot find its own `kraken` command, which the agent needs to reach KRAKEN's tools. Put it next to the window or on PATH, or set KRAKEN_EXE."
                    .into(),
            );
            return;
        };
        let project_path = PathBuf::from(&project);
        let mut mcp = if cfg.use_daemon {
            McpServerConfig::daemon(exe, Some(&project_path))
        } else {
            McpServerConfig::project(exe, &project_path)
        };
        for (k, v) in &cfg.mcp_env {
            mcp = mcp.with_env(k.clone(), v.clone());
        }
        let mut host_cfg = HostConfig::new(row.profile.clone(), launch, project_path, Some(mcp));
        host_cfg.permission = PermissionPolicy::AskUser;
        host_cfg.parent_env = cfg.parent_env.clone();
        host_cfg.start_timeout = cfg.start_timeout;

        self.agents.seq += 1;
        let seq = self.agents.seq;
        let (tx, rx) = unbounded_channel();
        self.agents.session = Some(AgentSession {
            seq,
            cmds: tx,
            agent_id: row.id.clone(),
            agent_name: row.name.clone(),
            agent_label: None,
            model: None,
            project_dir: project,
            tools_via: if cfg.use_daemon {
                "through the analysis engine, so edits appear here as they happen"
            } else {
                "through its own KRAKEN session on this project"
            },
            phase: SessionPhase::Starting,
            items: Vec::new(),
            busy: false,
            stopping: false,
            stderr_tail: Vec::new(),
            used_kraken_tools: false,
        });
        let post = self.poster();
        let rt = post.runtime().clone();
        rt.spawn(run_session(host_cfg, seq, post, rx));
    }

    /// Sends a prompt to the agent.
    pub fn agents_send(&mut self, text: &str) {
        let text = text.trim();
        let Some(s) = self.agents.session.as_mut() else {
            return;
        };
        if text.is_empty() || s.busy || s.phase != SessionPhase::Ready {
            return;
        }
        s.push(AgentItem::User(text.to_string()));
        s.busy = true;
        s.stopping = false;
        let _ = s.cmds.send(Cmd::Prompt(text.to_string()));
    }

    /// Stops what the agent is doing now. Waiting permission requests are withdrawn.
    pub fn agents_stop(&mut self) {
        if let Some(s) = self.agents.session.as_mut()
            && s.busy
            && !s.stopping
        {
            s.stopping = true;
            let _ = s.cmds.send(Cmd::Cancel);
        }
    }

    /// Answers a permission request: allow it once, or deny it.
    pub fn agents_answer_permission(&mut self, request_id: u64, allow: bool) {
        let Some(s) = self.agents.session.as_mut() else {
            return;
        };
        let Some(card) = s.items.iter().find_map(|i| match i {
            AgentItem::Permission(c)
                if c.request.request_id == request_id && c.state == PermissionState::Waiting =>
            {
                Some(c)
            }
            _ => None,
        }) else {
            return;
        };
        let decision = if allow {
            card.request.allow()
        } else {
            card.request.reject()
        };
        let _ = s.cmds.send(Cmd::Answer(request_id, decision));
    }

    /// Ends the session and the agent's process, and returns to the list.
    pub fn agents_close_session(&mut self) {
        if let Some(s) = self.agents.session.take() {
            let _ = s.cmds.send(Cmd::Shutdown);
        }
    }

    /// The project changed under the session: end it.
    pub(crate) fn agents_project_changed(&mut self) {
        self.agents_close_session();
        self.agents.pending_notice = None;
    }

    fn agents_start_failed(&mut self, seq: u64, message: String) {
        if let Some(s) = self.agents.session.as_mut().filter(|s| s.seq == seq) {
            s.phase = SessionPhase::Ended(message);
            s.busy = false;
        }
    }

    fn agents_turn_result(&mut self, seq: u64, result: Result<TurnEnd, AcpError>) {
        let refresh = {
            let Some(s) = self.agents.session.as_mut().filter(|s| s.seq == seq) else {
                return;
            };
            s.busy = false;
            s.stopping = false;
            s.close_stream();
            match result {
                Ok(_) => {}
                Err(AcpError::Disconnected { agent, .. }) => {
                    if !matches!(s.phase, SessionPhase::Ended(_)) {
                        let why = format!("{agent} stopped unexpectedly.");
                        s.push(AgentItem::Error(why.clone()));
                        s.phase = SessionPhase::Ended(why);
                    }
                }
                Err(e) => s.push(AgentItem::Error(e.to_string())),
            }
            s.used_kraken_tools
        };
        // Without the daemon nothing tells the window what the agent changed: look again.
        let live = self.agents.config.as_ref().is_some_and(|c| c.use_daemon);
        if refresh && !live && self.connection == crate::state::Connection::Open {
            self.refresh_after_edit();
        }
    }

    fn agents_event(&mut self, seq: u64, ev: AcpEvent) {
        let Some(s) = self.agents.session.as_mut().filter(|s| s.seq == seq) else {
            return;
        };
        match ev {
            AcpEvent::Started { agent, .. } => {
                s.phase = SessionPhase::Ready;
                s.agent_label = match (agent.name, agent.version) {
                    (Some(n), Some(v)) => Some(format!("{n} {v}")),
                    (Some(n), None) => Some(n),
                    _ => None,
                };
                s.model = agent.model;
            }
            AcpEvent::AgentText { text } => {
                if let Some(AgentItem::Text {
                    text: t,
                    streaming: true,
                }) = s.items.last_mut()
                {
                    t.push_str(&text);
                } else {
                    s.items.push(AgentItem::Text {
                        text,
                        streaming: true,
                    });
                }
            }
            AcpEvent::AgentThought { text } => {
                if let Some(AgentItem::Thought(t)) = s.items.last_mut() {
                    t.push_str(&text);
                } else {
                    s.push(AgentItem::Thought(text));
                }
            }
            AcpEvent::ToolCall(info) => {
                let tool = tool_from(info);
                s.used_kraken_tools |= tool.is_kraken;
                let existing = s.items.iter_mut().find_map(|i| match i {
                    AgentItem::Tool(t) if t.id == tool.id => Some(t),
                    _ => None,
                });
                match existing {
                    Some(t) => *t = tool,
                    None => s.push(AgentItem::Tool(tool)),
                }
            }
            AcpEvent::ToolCallUpdate(ToolCallChange {
                id,
                title,
                status,
                output,
            }) => {
                let found = s.items.iter_mut().find_map(|i| match i {
                    AgentItem::Tool(t) if t.id == id => Some(t),
                    _ => None,
                });
                if let Some(t) = found {
                    if let Some(title) = title {
                        let (name, is_kraken) = classify_tool(&title);
                        t.title = title;
                        t.name = name;
                        t.is_kraken = is_kraken;
                    }
                    if let Some(st) = status {
                        t.status = st;
                    }
                    if output.is_some() {
                        t.output = output;
                    }
                    let k = t.is_kraken;
                    s.used_kraken_tools |= k;
                }
            }
            AcpEvent::Plan { steps } => {
                let lines: Vec<PlanLine> = steps
                    .into_iter()
                    .map(
                        |PlanStep {
                             content, status, ..
                         }| PlanLine {
                            text: content,
                            status,
                        },
                    )
                    .collect();
                match s.items.iter_mut().find(|i| matches!(i, AgentItem::Plan(_))) {
                    Some(slot) => *slot = AgentItem::Plan(lines),
                    None => s.push(AgentItem::Plan(lines)),
                }
            }
            AcpEvent::PermissionRequested(request) => {
                s.push(AgentItem::Permission(PermissionCard {
                    request,
                    state: PermissionState::Waiting,
                }));
            }
            AcpEvent::PermissionResolved {
                request_id,
                selected,
            } => {
                for item in &mut s.items {
                    if let AgentItem::Permission(c) = item
                        && c.request.request_id == request_id
                    {
                        c.state = match &selected {
                            None => PermissionState::Withdrawn,
                            Some(id)
                                if c.request.allow() == PermissionDecision::Select(id.clone()) =>
                            {
                                PermissionState::Allowed
                            }
                            Some(_) => PermissionState::Denied,
                        };
                    }
                }
            }
            AcpEvent::Info { .. } => {}
            AcpEvent::AgentStderr { line } => {
                s.stderr_tail.push(line);
                let extra = s.stderr_tail.len().saturating_sub(20);
                s.stderr_tail.drain(..extra);
            }
            AcpEvent::TurnEnded { reason } => {
                s.close_stream();
                let note = match reason {
                    TurnEnd::EndTurn => None,
                    TurnEnd::Cancelled => Some("Stopped."),
                    TurnEnd::MaxTokens => Some("The agent ran out of room for one answer."),
                    TurnEnd::MaxTurnRequests => Some("The agent reached its step limit."),
                    TurnEnd::Refusal => Some("The agent declined to answer."),
                    TurnEnd::Other => Some("The agent stopped early."),
                };
                if let Some(n) = note {
                    s.push(AgentItem::Notice(n.to_string()));
                }
            }
            AcpEvent::Exited { .. } if matches!(s.phase, SessionPhase::Ended(_)) => {}
            AcpEvent::Exited { code, signal } => {
                let why = end_text(code, signal);
                s.push(AgentItem::Error(why.clone()));
                s.phase = SessionPhase::Ended(why);
                s.busy = false;
                s.stopping = false;
            }
        }
    }
}

async fn run_session(
    config: HostConfig,
    seq: u64,
    post: crate::vm::Poster,
    mut cmds: UnboundedReceiver<Cmd>,
) {
    let (host, mut rx) = match AcpHost::start(config).await {
        Ok(x) => x,
        Err(e) => {
            let message = e.to_string();
            post.post(move |vm| vm.agents_start_failed(seq, message));
            return;
        }
    };
    let forward = |ev: AcpEvent| {
        post.post(move |vm| vm.agents_event(seq, ev));
    };
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(ev) => forward(ev),
                None => break,
            },
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Prompt(text)) => {
                    let keep_going = turn(&host, &mut rx, &mut cmds, &post, seq, &text).await;
                    if !keep_going {
                        break;
                    }
                }
                Some(Cmd::Cancel) => {
                    let _ = host.cancel();
                }
                Some(Cmd::Answer(id, d)) => {
                    host.answer_permission(id, d);
                }
                Some(Cmd::Shutdown) | None => break,
            },
        }
    }
    while let Ok(ev) = rx.try_recv() {
        forward(ev);
    }
    host.shutdown().await;
}

/// Runs one prompt, passing events on and acting on commands meanwhile. False when the session
/// should end.
async fn turn(
    host: &AcpHost,
    rx: &mut UnboundedReceiver<AcpEvent>,
    cmds: &mut UnboundedReceiver<Cmd>,
    post: &crate::vm::Poster,
    seq: u64,
    text: &str,
) -> bool {
    let fut = host.prompt(text);
    tokio::pin!(fut);
    let mut keep_going = true;
    let result = loop {
        tokio::select! {
            Some(ev) = rx.recv() => {
                post.post(move |vm| vm.agents_event(seq, ev));
            }
            cmd = cmds.recv() => match cmd {
                Some(Cmd::Cancel) => {
                    let _ = host.cancel();
                }
                Some(Cmd::Answer(id, d)) => {
                    host.answer_permission(id, d);
                }
                Some(Cmd::Prompt(_)) => {}
                Some(Cmd::Shutdown) | None => {
                    keep_going = false;
                    let _ = host.cancel();
                    break Ok(TurnEnd::Cancelled);
                }
            },
            res = &mut fut => break res,
        }
    };
    while let Ok(ev) = rx.try_recv() {
        post.post(move |vm| vm.agents_event(seq, ev));
    }
    if keep_going {
        post.post(move |vm| vm.agents_turn_result(seq, result));
    }
    keep_going
}

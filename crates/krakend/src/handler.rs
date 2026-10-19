//! The RPC methods of the daemon (see `kraken_host::daemon` for the table).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_host::daemon::{
    CallParams, CallResult, GUI_SELECTION_FRESH_SECS, GuiSelection, GuiSelectionReply,
    GuiSelectionSetParams, METHOD_APPROVAL_DECIDE, METHOD_APPROVALS, METHOD_CALL, METHOD_COMMANDS,
    METHOD_EVENTS, METHOD_GUI_SELECTION, METHOD_GUI_SELECTION_SET, METHOD_SHUTDOWN, METHOD_STATUS,
    event_kind,
};
use kraken_host::infer::{Holder, InferApi, InferManager, serve_rpc, serve_serving_rpc};
use kraken_ipc::{ClientKind, ConnInfo, Counter, CredentialClass, RpcHandler, Shutdown};
use kraken_model::{AuthorKind, RunId};
use kraken_proto::{ErrorCode, ProtoError, sanitize_capped};
use kraken_registry::commands::project_gate;
use kraken_registry::{
    ApprovalRequest, AutoApprove, CallContext, CommandKind, DenyApprover, Registry, Surface,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::approvals::{ApprovalBoard, BoardApprover};
use crate::host::{SessionHost, canonical_key};

/// The quota every agent-class connection shares: reconnecting does not start a new budget.
const AGENT_QUOTA_KEY: &str = "agent-credential";

/// Facts about the running daemon for the `status` method.
#[derive(Debug, Clone)]
pub struct DaemonFacts {
    /// Process id.
    pub pid: u32,
    /// Build string.
    pub build: String,
    /// IPC protocol version.
    pub protocol: u32,
    /// Runtime directory.
    pub runtime_dir: PathBuf,
    /// Daemon idle timeout.
    pub idle_timeout: Duration,
    /// When the daemon started.
    pub started: Instant,
}

/// Serves `call`, `commands`, `status`, `events` and `shutdown`.
pub struct DaemonHandler {
    host: SessionHost,
    registry: Arc<Registry>,
    facts: DaemonFacts,
    clients: Counter,
    jobs: Counter,
    shutdown: Shutdown,
    infer: Arc<InferManager>,
    approvals: ApprovalBoard,
    /// Projects a person has worked on or approved for agents. Agent-class connections reach
    /// only these, or ask first.
    granted: Arc<Mutex<HashSet<PathBuf>>>,
    /// What the GUI shows, per project, and when it said so.
    gui_selection: Mutex<HashMap<PathBuf, (GuiSelection, Instant)>>,
}

impl DaemonHandler {
    /// A handler over `host`. `clients` and `jobs` are the idle monitor's counters, shown in
    /// `status`; `shutdown` is triggered by the `shutdown` method.
    pub fn new(
        host: SessionHost,
        registry: Arc<Registry>,
        facts: DaemonFacts,
        clients: Counter,
        jobs: Counter,
        shutdown: Shutdown,
    ) -> Self {
        let approvals = ApprovalBoard::new(host.hub().clone());
        DaemonHandler {
            host,
            registry,
            facts,
            clients,
            jobs,
            shutdown,
            infer: Arc::new(InferManager::with_registry(Default::default())),
            approvals,
            granted: Arc::default(),
            gui_selection: Mutex::default(),
        }
    }

    /// The approvals waiting for a person.
    pub fn approvals(&self) -> &ApprovalBoard {
        &self.approvals
    }

    fn is_granted(&self, key: &Path) -> bool {
        self.granted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(key)
    }

    fn grant(&self, key: &Path) {
        self.granted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_path_buf());
    }

    /// Serves the `infer_*` methods with `infer` (the default manager has no engines).
    #[must_use]
    pub fn with_infer(mut self, infer: Arc<InferManager>) -> Self {
        self.infer = infer;
        self
    }
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn internal(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg)
}

fn surface_for(kind: ClientKind) -> Surface {
    match kind {
        ClientKind::Cli => Surface::Cli,
        ClientKind::Gui => Surface::Gui,
        ClientKind::Mcp => Surface::Mcp,
    }
}

/// An id taken from a client: no invisible or control characters, short.
fn clean_id(raw: &str) -> String {
    let s: String = sanitize_capped(raw, 64)
        .chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .collect();
    s.trim().to_string()
}

/// Who a call is made as, and who may approve it. Everything that matters here comes from the
/// credential the connection presented: an agent-class connection is an agent on the MCP surface
/// whatever its `author_kind`, `surface` and `approved` say, and its approvals go to the board
/// where only a person's connection can answer them. A user-class connection (GUI, CLI) is
/// trusted for those fields, since it holds the user's token.
fn context(
    p: &CallParams,
    conn: &ConnInfo,
    board: &ApprovalBoard,
    project_dir: &Path,
) -> CallContext {
    let claimed = p
        .author_id
        .as_deref()
        .map(clean_id)
        .filter(|s| !s.is_empty());
    let mut ctx = match conn.class {
        CredentialClass::Agent => {
            let id = claimed.unwrap_or_else(|| "mcp-client".to_string());
            let approver = BoardApprover::new(board.clone(), project_dir.to_path_buf(), id.clone());
            CallContext::agent(id, "", Surface::Mcp)
                .with_approval(Arc::new(approver))
                .with_quota_key(AGENT_QUOTA_KEY)
        }
        CredentialClass::User => {
            let surface = p.surface.unwrap_or_else(|| surface_for(conn.client_kind));
            let id = claimed.unwrap_or_else(|| match p.author_kind {
                AuthorKind::User => "user".to_string(),
                AuthorKind::Agent => format!("{:?}-client", conn.client_kind).to_lowercase(),
            });
            let ctx = match p.author_kind {
                AuthorKind::User => CallContext::user(id, surface),
                AuthorKind::Agent => CallContext::agent(id, "", surface),
            };
            ctx.with_approval(if p.approved {
                Arc::new(AutoApprove)
            } else {
                Arc::new(DenyApprover)
            })
        }
    };
    ctx.run_id = p.run_id.as_deref().map(|r| RunId(clean_id(r)));
    ctx
}

/// Everything in a selection comes from the GUI's view of the binary: clean it and bound it.
fn clean_selection(mut s: GuiSelection) -> GuiSelection {
    let clean = |v: Option<String>, max: usize| v.map(|t| sanitize_capped(&t, max));
    s.kind = sanitize_capped(&s.kind, 32);
    s.function = clean(s.function, 32);
    s.function_name = clean(s.function_name, 256);
    s.address = clean(s.address, 32);
    s.text = clean(s.text, 8 * 1024);
    s.active_tab = clean(s.active_tab, 32);
    s.tabs = s
        .tabs
        .into_iter()
        .take(40)
        .map(|t| sanitize_capped(&t, 32))
        .collect();
    s.actions = s
        .actions
        .into_iter()
        .take(80)
        .map(|t| sanitize_capped(&t, 48))
        .collect();
    s
}

fn denied_to_agents(method: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::Unsupported,
        format!(
            "`{method}` is not available on an agent connection; it is for the person's GUI \
             and CLI"
        ),
    )
    .with_details(json!({"reason": "agent_credential"}))
}

fn approval_denied(reason: &str) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, format!("approval denied: {reason}"))
        .with_details(json!({"approval": "denied"}))
}

/// Events caused by a successful command.
fn events_for(
    name: &str,
    kind: CommandKind,
    result: &Value,
    ctx: &CallContext,
) -> Vec<(&'static str, Value)> {
    if matches!(name, "ui_action" | "ui_highlight") {
        let mut ev = json!({"author_kind": ctx.author.kind, "author_id": ctx.author.id});
        for k in ["action", "tab", "address", "target", "note"] {
            if let Some(v) = result.get(k) {
                ev[k] = v.clone();
            }
        }
        return vec![(event_kind::GUI_UI, ev)];
    }
    if name == "gui_navigate" {
        let mut ev = json!({"author_kind": ctx.author.kind, "author_id": ctx.author.id});
        for k in ["address", "tab"] {
            if let Some(v) = result.get(k) {
                ev[k] = v.clone();
            }
        }
        return vec![(event_kind::GUI_NAVIGATE, ev)];
    }
    if kind == CommandKind::Job && name != "job_cancel" {
        let mut ev = json!({
            "command": name,
            "author_kind": ctx.author.kind,
            "author_id": ctx.author.id,
        });
        if let Some(r) = &ctx.run_id {
            ev["run_id"] = json!(r.0);
        }
        if let Some(id) = result.get("job_id") {
            ev["job_id"] = id.clone();
        }
        return vec![(event_kind::JOB_STARTED, ev)];
    }
    if kind != CommandKind::Mutation
        || matches!(
            name,
            "project_create" | "project_open" | "job_cancel" | "tainted_clear"
        )
    {
        return Vec::new();
    }
    let mut ev = json!({
        "command": name,
        "author_kind": ctx.author.kind,
        "author_id": ctx.author.id,
    });
    if let Some(r) = &ctx.run_id {
        ev["run_id"] = json!(r.0);
    }
    for k in [
        "status",
        "entry_id",
        "entry_ids",
        "undone_entry_ids",
        "key",
        "proposal_id",
        "versions",
        "reason",
    ] {
        if let Some(v) = result.get(k) {
            ev[k] = v.clone();
        }
    }
    let proposed = result.get("status").and_then(Value::as_str) == Some("proposed");
    vec![(
        if proposed {
            event_kind::PROPOSAL_CREATED
        } else {
            event_kind::ENTRY_APPLIED
        },
        ev,
    )]
}

#[derive(Deserialize, Default)]
struct EventsParams {
    #[serde(default)]
    after_seq: u64,
    #[serde(default)]
    limit: Option<u32>,
}

impl DaemonHandler {
    async fn call_command(&self, conn: &ConnInfo, params: Value) -> Result<Value, ProtoError> {
        let p: CallParams =
            serde_json::from_value(params).map_err(|e| invalid(format!("bad call params: {e}")))?;
        let registry = self.registry.clone();
        let entry = registry.get(&p.command).ok_or_else(|| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!("unknown command `{}`", p.command),
            )
        })?;
        let spec = entry.spec().clone();
        if matches!(
            p.command.as_str(),
            "binary_probe" | "kraken_help" | "local_model_recommend" | "local_model_setup"
        ) {
            // About a file, not a project: no session is made for it. The command applies the
            // agent path policy itself.
            let ctx = context(&p, conn, &self.approvals, Path::new(&p.project_dir));
            let mut session = kraken_registry::Session::new(self.host.factory().clone());
            if let Some(lm) = &self.host.config().local_models {
                session = session.with_local_models(lm.clone());
            }
            let result = registry
                .call_json(&p.command, &session, &ctx, p.args.clone())
                .await?;
            return serde_json::to_value(CallResult {
                result,
                warnings: Vec::new(),
            })
            .map_err(|e| internal(format!("cannot encode the reply: {e}")));
        }
        let dir = PathBuf::from(&p.project_dir);
        if !dir.is_absolute() {
            return Err(invalid(format!(
                "project_dir {} must be absolute: the daemon does not share the client's working directory",
                p.project_dir
            )));
        }
        let key = canonical_key(&dir)?;
        if p.command == "project_close" {
            return self.close_project(conn, &key).await;
        }
        let mut ctx = context(&p, conn, &self.approvals, &key);
        let creating = matches!(p.command.as_str(), "project_create" | "project_open");
        let agent = conn.class == CredentialClass::Agent;
        // Before any session is created for a directory the client named: a person's own work
        // makes a project available to agents; for anything else an agent has to ask.
        if agent {
            let granted = self.is_granted(&key);
            if creating && !(p.command == "project_open" && granted) {
                project_gate(&p.command, &p.args, &ctx).await?;
                ctx = ctx.with_gate_passed();
            } else if !creating && !granted {
                let decision = ctx
                    .approval
                    .request(ApprovalRequest {
                        command: p.command.clone(),
                        summary: format!(
                            "let the agent work on the project in {}",
                            kraken_proto::sanitize(&key.display().to_string())
                        ),
                        args: json!({"project_dir": kraken_proto::sanitize(&key.display().to_string())}),
                        author: ctx.author.clone(),
                        surface: ctx.surface,
                    })
                    .await;
                if let kraken_registry::ApprovalDecision::Deny { reason } = decision {
                    return Err(approval_denied(&reason));
                }
                self.grant(&key);
            }
        } else {
            self.grant(&key);
        }
        let lease = self.host.acquire(&key, &dir).await?;
        let queued = matches!(spec.kind, CommandKind::Mutation | CommandKind::Job)
            && spec.name != "job_cancel";
        let queue_guard = if queued {
            Some(lease.entry().lock_queue().await)
        } else {
            None
        };

        let mut name = p.command.clone();
        let mut args = p.args.clone();
        let mut warnings = Vec::new();
        if name == "project_open"
            && lease.entry().session().project().is_ok()
            && (!agent || self.is_granted(&key))
        {
            // Already open here: report instead of reopening (which would restart the sidecar).
            name = "project_info".into();
            args = Value::Null;
        } else if name.starts_with("job_") && lease.entry().session().project().is_err() {
            // the job table needs no project: an open in progress is watched and cancelled
            // through its job without starting a second open
        } else if !matches!(name.as_str(), "project_create" | "project_open") {
            match self.host.ensure_open(&lease).await {
                Ok(w) => {
                    warnings = w
                        .iter()
                        .map(|m| kraken_proto::sanitize_capped(m, kraken_proto::MAX_UNTRUSTED_LEN))
                        .collect();
                }
                Err(e) => {
                    self.host.discard_unopened(&lease).await;
                    return Err(e);
                }
            }
        }

        // The command runs in its own task: a client that disconnects mid-call must not leave a
        // half-finished mutation or free the write queue early.
        if creating {
            ctx = ctx.with_open_progress(self.host.open_sink(&key));
        }
        let cancel = ctx.cancel.clone();
        let guard = (spec.kind == CommandKind::Query).then(|| cancel.drop_guard());
        let host = self.host.clone();
        let kind = spec.kind;
        let task = tokio::spawn(async move {
            let _queue = queue_guard;
            let entry = lease.entry().clone();
            let result = registry.call_json(&name, entry.session(), &ctx, args).await;
            match &result {
                Ok(v) => {
                    if creating && name != "project_info" {
                        host.note_opened(&lease);
                    }
                    for (k, fields) in events_for(&name, kind, v, &ctx) {
                        host.hub().publish(entry.key(), k, fields);
                    }
                }
                Err(_) if creating => host.discard_unopened(&lease).await,
                Err(_) => {}
            }
            result
        });
        let result = task
            .await
            .map_err(|e| internal(format!("command task failed: {e}")))?;
        if let Some(g) = guard {
            g.disarm();
        }
        let mut result = result?;
        if p.command == "ui_state" {
            result = self.ui_state(&key);
        }
        if creating {
            // The person approved it (or is the person): agents may work on it from now on.
            self.grant(&key);
        }
        serde_json::to_value(CallResult { result, warnings })
            .map_err(|e| internal(format!("cannot encode the reply: {e}")))
    }

    /// `project_close`: ends the daemon's session for `key` without opening it first. An agent
    /// may close only a project it was allowed to work on.
    async fn close_project(&self, conn: &ConnInfo, key: &Path) -> Result<Value, ProtoError> {
        if conn.class == CredentialClass::Agent && !self.is_granted(key) {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                "an agent may close only a project it was allowed to work on",
            ));
        }
        let closed = self.host.close_project(key).await;
        let result = serde_json::to_value(kraken_registry::commands::ProjectCloseOut {
            closed,
            project_dir: closed.then(|| key.to_string_lossy().into_owned()),
        })
        .map_err(|e| internal(e.to_string()))?;
        serde_json::to_value(CallResult {
            result,
            warnings: Vec::new(),
        })
        .map_err(|e| internal(format!("cannot encode the reply: {e}")))
    }

    fn set_gui_selection(&self, params: Value) -> Result<Value, ProtoError> {
        let p: GuiSelectionSetParams =
            serde_json::from_value(params).map_err(|e| invalid(format!("bad params: {e}")))?;
        let key = canonical_key(Path::new(&p.project_dir))?;
        let mut map = self
            .gui_selection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match p.selection {
            Some(sel) => {
                map.insert(key, (clean_selection(sel), Instant::now()));
            }
            None => {
                map.remove(&key);
            }
        }
        Ok(json!({"stored": true}))
    }

    /// The reply of `ui_state`: what the GUI of `key` last published.
    fn ui_state(&self, key: &Path) -> Value {
        let entry = self
            .gui_selection
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned();
        let Some((s, at)) = entry else {
            return json!({"attached": false, "stale": false, "tabs": [], "actions": []});
        };
        json!({
            "attached": true,
            "stale": at.elapsed().as_secs() > GUI_SELECTION_FRESH_SECS,
            "tabs": s.tabs,
            "active_tab": s.active_tab,
            "function": s.function,
            "function_name": s.function_name,
            "address": s.address,
            "selection": s.text,
            "actions": s.actions,
        })
    }

    fn gui_selection(&self, conn: &ConnInfo, params: Value) -> Result<Value, ProtoError> {
        #[derive(Deserialize)]
        struct P {
            project_dir: String,
        }
        let p: P =
            serde_json::from_value(params).map_err(|e| invalid(format!("bad params: {e}")))?;
        let key = canonical_key(Path::new(&p.project_dir))?;
        // An agent sees the selection only of a project it may work on.
        let visible = conn.class != CredentialClass::Agent || self.is_granted(&key);
        let entry = visible
            .then(|| {
                self.gui_selection
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&key)
                    .cloned()
            })
            .flatten();
        let reply = match entry {
            Some((selection, at)) => {
                let age = at.elapsed().as_secs();
                GuiSelectionReply {
                    attached: true,
                    stale: age > GUI_SELECTION_FRESH_SECS,
                    age_secs: age,
                    selection: Some(selection),
                }
            }
            None => GuiSelectionReply {
                attached: false,
                stale: false,
                age_secs: 0,
                selection: None,
            },
        };
        serde_json::to_value(reply).map_err(|e| internal(e.to_string()))
    }

    fn commands(&self) -> Value {
        Value::Array(
            self.registry
                .iter()
                .map(|e| {
                    json!({
                        "spec": e.spec(),
                        "args_schema": e.args_schema(),
                        "output_schema": e.output_schema(),
                    })
                })
                .collect(),
        )
    }

    async fn status(&self) -> Value {
        let engines: Vec<Value> = self
            .host
            .factory()
            .diagnostics()
            .into_iter()
            .map(|d| json!({"engine_dir": d.engine_dir, "diagnostics": d.value}))
            .collect();
        let cfg = self.host.config();
        let model = self.infer.status().await.ok();
        json!({
            "daemon": {
                "pid": self.facts.pid,
                "build": self.facts.build,
                "protocol": self.facts.protocol,
                "runtime_dir": self.facts.runtime_dir,
                "uptime_secs": self.facts.started.elapsed().as_secs(),
                "idle_timeout_secs": self.facts.idle_timeout.as_secs(),
                "session_idle_secs": cfg.session_idle.as_secs(),
                "max_sessions": cfg.max_sessions,
                "clients": self.clients.get(),
                "running_jobs": self.jobs.get(),
                "loaded_models": self.infer.loaded_models(),
            },
            "model": model,
            "models": self.infer.model_statuses().models,
            "sessions": self.host.session_status().await,
            "engines": engines,
            "last_event_seq": self.host.hub().last_seq(),
        })
    }
}

#[async_trait]
impl RpcHandler for DaemonHandler {
    async fn call(
        &self,
        conn: &ConnInfo,
        method: &str,
        params: Value,
    ) -> Result<Value, ProtoError> {
        if conn.class == CredentialClass::Agent
            && !matches!(
                method,
                METHOD_CALL | METHOD_COMMANDS | METHOD_EVENTS | METHOD_GUI_SELECTION
            )
        {
            return Err(denied_to_agents(method));
        }
        match method {
            METHOD_CALL => self
                .call_command(conn, params)
                .await
                .map_err(ProtoError::sanitized),
            METHOD_COMMANDS => Ok(self.commands()),
            METHOD_GUI_SELECTION_SET => self.set_gui_selection(params),
            METHOD_GUI_SELECTION => self.gui_selection(conn, params),
            METHOD_APPROVALS => Ok(json!({"pending": self.approvals.pending()})),
            METHOD_APPROVAL_DECIDE => {
                #[derive(Deserialize)]
                struct Decide {
                    id: u64,
                    allow: bool,
                }
                let d: Decide = serde_json::from_value(params)
                    .map_err(|e| invalid(format!("bad params: {e}")))?;
                Ok(json!({"decided": self.approvals.decide(d.id, d.allow)}))
            }
            METHOD_STATUS => Ok(self.status().await),
            METHOD_EVENTS => {
                let p: EventsParams = if params.is_null() {
                    EventsParams::default()
                } else {
                    serde_json::from_value(params)
                        .map_err(|e| invalid(format!("bad params: {e}")))?
                };
                let limit = p.limit.map_or(256, |l| l.clamp(1, 1024)) as usize;
                let (events, last_seq) = self.host.hub().since(p.after_seq, limit);
                Ok(json!({"events": events, "last_seq": last_seq}))
            }
            METHOD_SHUTDOWN => {
                let s = self.shutdown.clone();
                // Let the reply reach the caller before the connections are torn down.
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    s.trigger();
                });
                Ok(json!({"stopping": true}))
            }
            other => {
                if let Some(r) = serve_rpc(self.infer.as_ref(), other, params.clone()).await {
                    return r;
                }
                // Holds made here belong to this connection and end with it.
                let held = self.infer.holder(Holder::Connection(conn.id));
                match serve_serving_rpc(&held, other, params).await {
                    Some(r) => r,
                    None => Err(ProtoError::new(
                        ErrorCode::NotFound,
                        format!("unknown method `{other}`"),
                    )),
                }
            }
        }
    }

    fn disconnected(&self, conn: &ConnInfo) {
        self.infer.release_connection(conn.id);
    }
}

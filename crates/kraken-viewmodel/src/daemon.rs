//! [`Backend`] over a `krakend` connection (decisions 13, 17, 34).
//!
//! Commands go to the daemon's `call` method as the GUI user; the daemon's `event` notifications
//! become [`BackendEvent`]s, so the window refreshes live when another client (an agent over
//! MCP, the CLI) edits the open project. When the connection drops the backend reports
//! [`BackendEvent::Disconnected`], keeps trying to reconnect (starting the daemon when the
//! connector allows it) with exponential backoff and then reports [`BackendEvent::Reconnected`].

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_host::daemon::{
    CallParams, DaemonClient, METHOD_APPROVAL_DECIDE, METHOD_APPROVALS, METHOD_EVENT, StartOptions,
    absolute, event_kind,
};
use kraken_ipc::{ClientKind, RuntimeDir};
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::Value;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::backend::{
    ApprovalPrompt, Approver, Backend, BackendEvent, CallAs, ChangeInfo, CommandInfo, JobInfo,
    JobProgress, JobState, Permission,
};

/// A boxed future, as returned by a [`Connector`].
pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Makes a fresh daemon connection; called for the first connection and for every reconnect.
pub type Connector = Arc<dyn Fn() -> BoxFut<Result<DaemonClient, String>> + Send + Sync>;

/// The build string announced to the daemon.
pub const BUILD: &str = env!("CARGO_PKG_VERSION");

/// How long to wait between reconnect attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// First delay.
    pub initial: Duration,
    /// Delay cap; each failed attempt doubles the delay up to this.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: Duration::from_millis(250),
            max: Duration::from_secs(5),
        }
    }
}

/// Options of [`DaemonClientBackend::connect`].
#[derive(Clone)]
pub struct BackendOptions {
    /// Author id the GUI's edits are logged under (`user_id()` by default).
    pub author: String,
    /// Reconnect pacing.
    pub backoff: Backoff,
}

impl Default for BackendOptions {
    fn default() -> Self {
        BackendOptions {
            author: kraken_host::user_id(),
            backoff: Backoff::default(),
        }
    }
}

/// A connector that connects to the daemon of `runtime`, starting `krakend` when none runs.
pub fn start_connector(runtime: RuntimeDir, start: StartOptions) -> Connector {
    Arc::new(move || {
        let runtime = runtime.clone();
        let start = start.clone();
        Box::pin(async move {
            DaemonClient::connect_or_start(&runtime, ClientKind::Gui, BUILD, &start)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

/// A connector for the default per-user runtime directory (`KRAKEN_RUNTIME_DIR` wins), resolved
/// on every attempt; it starts `krakend` when none runs.
pub fn default_connector(start: StartOptions) -> Connector {
    Arc::new(move || {
        let start = start.clone();
        Box::pin(async move {
            let runtime = RuntimeDir::resolve().map_err(|e| e.to_string())?;
            DaemonClient::connect_or_start(&runtime, ClientKind::Gui, BUILD, &start)
                .await
                .map_err(|e| e.to_string())
        })
    })
}

/// A connector that only attaches to a running daemon (tests, tools that must not start one).
pub fn attach_connector(runtime: RuntimeDir) -> Connector {
    Arc::new(move || {
        let runtime = runtime.clone();
        Box::pin(async move {
            match DaemonClient::connect_running(&runtime, ClientKind::Gui, BUILD).await {
                Ok(Some(c)) => Ok(c),
                Ok(None) => Err("krakend is not running".to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    })
}

struct Inner {
    client: Mutex<Option<DaemonClient>>,
    connector: Connector,
    backoff: Backoff,
    author: String,
    /// Project the GUI works on: the absolute path commands are sent with, and its canonical
    /// form the daemon labels events with.
    project: Mutex<Option<(PathBuf, PathBuf)>>,
    commands: Mutex<Vec<CommandInfo>>,
    events: broadcast::Sender<BackendEvent>,
    approver: Mutex<Option<Arc<dyn Approver>>>,
    connected: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs the GUI's commands in `krakend`.
pub struct DaemonClientBackend {
    inner: Arc<Inner>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for DaemonClientBackend {
    fn drop(&mut self) {
        if let Some(t) = lock(&self.task).take() {
            t.abort();
        }
    }
}

fn not_connected() -> ProtoError {
    ProtoError::new(
        ErrorCode::Internal,
        "not connected to krakend; trying to reconnect",
    )
}

impl DaemonClientBackend {
    /// Connects through `connector` and starts the event pump. Must run inside a tokio runtime.
    pub async fn connect(connector: Connector, opts: BackendOptions) -> Result<Self, String> {
        let client = connector().await?;
        let (events, _) = broadcast::channel(256);
        let inner = Arc::new(Inner {
            client: Mutex::new(None),
            connector,
            backoff: opts.backoff,
            author: opts.author,
            project: Mutex::new(None),
            commands: Mutex::new(Vec::new()),
            events,
            approver: Mutex::new(None),
            connected: AtomicBool::new(false),
        });
        let rx = inner.adopt(client).await;
        let pump = inner.clone();
        let task = tokio::spawn(async move { pump.run(rx).await });
        Ok(DaemonClientBackend {
            inner,
            task: Mutex::new(Some(task)),
        })
    }

    /// Connects to the default per-user daemon (`KRAKEN_RUNTIME_DIR` wins), starting `krakend`
    /// when none runs.
    pub async fn connect_default(start: StartOptions) -> Result<Self, String> {
        Self::connect(default_connector(start), BackendOptions::default()).await
    }

    /// Sets who is asked before a dangerous command runs. Without one, such commands are
    /// refused.
    pub fn set_approver(&self, approver: Arc<dyn Approver>) {
        *lock(&self.inner.approver) = Some(approver);
    }

    /// True while a daemon connection is up.
    pub fn is_connected(&self) -> bool {
        self.inner.connected.load(Ordering::SeqCst)
    }

    /// The project commands currently run against.
    pub fn current_project(&self) -> Option<PathBuf> {
        lock(&self.inner.project).as_ref().map(|(p, _)| p.clone())
    }

    /// Daemon and session status (the `status` method).
    pub async fn status(&self) -> Result<Value, ProtoError> {
        self.inner.client()?.status().await
    }

    /// The current daemon connection, for features outside the command registry (local models).
    pub fn daemon_client(&self) -> Result<DaemonClient, ProtoError> {
        self.inner.client()
    }

    /// Asks the daemon to exit; the backend then reconnects, which starts a fresh daemon when
    /// the connector can.
    pub async fn shutdown_daemon(&self) -> Result<(), ProtoError> {
        self.inner.client()?.shutdown().await
    }
}

impl Inner {
    fn client(&self) -> Result<DaemonClient, ProtoError> {
        lock(&self.client).clone().ok_or_else(not_connected)
    }

    fn emit(&self, ev: BackendEvent) {
        let _ = self.events.send(ev);
    }

    /// Installs `client`, refreshes the command list and returns its event stream.
    async fn adopt(
        &self,
        client: DaemonClient,
    ) -> tokio::sync::mpsc::UnboundedReceiver<kraken_ipc::Notification> {
        let rx = client.take_events().unwrap_or_else(|| {
            let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
            rx
        });
        if let Ok(v) = client.commands().await {
            let list = parse_commands(&v);
            if !list.is_empty() {
                *lock(&self.commands) = list;
            }
        }
        *lock(&self.client) = Some(client);
        self.connected.store(true, Ordering::SeqCst);
        rx
    }

    /// Pumps events until the connection ends, then reconnects, forever.
    async fn run(
        self: Arc<Self>,
        mut rx: tokio::sync::mpsc::UnboundedReceiver<kraken_ipc::Notification>,
    ) {
        self.clone().pull_pending_approvals();
        loop {
            while let Some(n) = rx.recv().await {
                if n.method != METHOD_EVENT {
                    continue;
                }
                if str_field(&n.params, "kind") == Some(event_kind::APPROVAL_REQUESTED) {
                    self.clone().ask_about(&n.params);
                    continue;
                }
                let key = lock(&self.project).as_ref().map(|(_, k)| k.clone());
                if let Some(ev) = map_event(&n.params, key.as_deref()) {
                    self.emit(ev);
                }
            }
            *lock(&self.client) = None;
            self.connected.store(false, Ordering::SeqCst);
            self.emit(BackendEvent::Disconnected(
                "the connection to krakend ended".into(),
            ));
            let mut delay = self.backoff.initial;
            rx = loop {
                tokio::time::sleep(delay).await;
                match (self.connector)().await {
                    Ok(client) => break self.adopt(client).await,
                    Err(_) => delay = (delay * 2).min(self.backoff.max),
                }
            };
            self.emit(BackendEvent::Reconnected);
            self.clone().pull_pending_approvals();
        }
    }

    /// An agent waits for the person (it asked to open a project, or to work on one the person
    /// has not opened): shows the question through the approver and sends the answer to the
    /// daemon. Without an approver nothing is answered, and the daemon denies on timeout.
    fn ask_about(self: Arc<Self>, ev: &Value) {
        let Some(id) = ev
            .get("approval_id")
            .or_else(|| ev.get("id"))
            .and_then(Value::as_u64)
        else {
            return;
        };
        let Some(approver) = lock(&self.approver).clone() else {
            return;
        };
        let prompt = ApprovalPrompt {
            command: str_field(ev, "command").unwrap_or_default().to_string(),
            summary: format!(
                "An agent ({}) asks: {}",
                str_field(ev, "author_id").unwrap_or("unknown"),
                str_field(ev, "summary").unwrap_or_default()
            ),
            args: ev.get("args").cloned().unwrap_or(Value::Null),
        };
        tokio::spawn(async move {
            let allow = approver.approve(prompt).await;
            if let Ok(client) = self.client() {
                let _ = client
                    .rpc(
                        METHOD_APPROVAL_DECIDE,
                        serde_json::json!({"id": id, "allow": allow}),
                    )
                    .await;
            }
        });
    }

    /// Questions that were already waiting when this window connected.
    fn pull_pending_approvals(self: Arc<Self>) {
        tokio::spawn(async move {
            let Ok(client) = self.client() else { return };
            let Ok(v) = client.rpc(METHOD_APPROVALS, Value::Null).await else {
                return;
            };
            for p in v["pending"].as_array().cloned().unwrap_or_default() {
                self.clone().ask_about(&p);
            }
        });
    }

    fn permission(&self, command: &str) -> Option<(Permission, String)> {
        lock(&self.commands)
            .iter()
            .find(|c| c.name == command)
            .map(|c| (c.permission, c.summary.clone()))
    }

    async fn approved(&self, command: &str, args: &Value) -> Result<bool, ProtoError> {
        // `rewrite_program` runs the original binary natively (confined) unless it is only
        // asked to write the crate: it is not `dangerous` for the CLI, whose user typed it, but
        // the GUI asks first like it does for a dangerous command.
        let runs_original = command == "rewrite_program"
            && args.get("build").and_then(Value::as_bool).unwrap_or(true);
        let summary = if runs_original {
            let mut s = kraken_registry::commands::RUN_ORIGINAL_SUMMARY.to_string();
            if let Some(first) = s.get_mut(0..1) {
                first.make_ascii_uppercase();
            }
            s
        } else {
            match self.permission(command) {
                Some((Permission::Dangerous, summary)) => summary,
                _ => return Ok(false),
            }
        };
        let approver = lock(&self.approver).clone();
        let allowed = match approver {
            Some(a) => {
                a.approve(ApprovalPrompt {
                    command: command.to_string(),
                    summary,
                    args: args.clone(),
                })
                .await
            }
            None => false,
        };
        if allowed {
            Ok(true)
        } else {
            Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("approval denied: `{command}` was not approved"),
            )
            .with_details(serde_json::json!({ "approval": "denied" })))
        }
    }
}

/// Makes the path arguments of the project commands absolute: the daemon does not share the
/// GUI's working directory.
fn absolutize(command: &str, args: &mut Value) {
    let keys: &[&str] = match command {
        "project_create" => &["binary", "project_dir"],
        "project_open" => &["project_dir"],
        _ => &[],
    };
    let Some(obj) = args.as_object_mut() else {
        return;
    };
    for k in keys {
        if let Some(Value::String(s)) = obj.get_mut(*k)
            && !s.is_empty()
        {
            *s = absolute(Path::new(s.as_str()))
                .to_string_lossy()
                .into_owned();
        }
    }
}

#[async_trait]
impl Backend for DaemonClientBackend {
    async fn call(&self, command: &str, args: Value) -> Result<Value, ProtoError> {
        let approved = self.inner.approved(command, &args).await?;
        let who = Identity {
            kind: AuthorKind::User,
            id: self.inner.author.clone(),
            run_id: None,
        };
        self.send(command, args, who, approved).await
    }

    async fn call_as(&self, who: &CallAs, command: &str, args: Value) -> Result<Value, ProtoError> {
        // An agent never gets a dangerous command through: nobody was asked.
        let who = Identity {
            kind: if who.agent {
                AuthorKind::Agent
            } else {
                AuthorKind::User
            },
            id: who.id.clone(),
            run_id: who.run_id.clone(),
        };
        self.send(command, args, who, false).await
    }

    fn commands(&self) -> Vec<CommandInfo> {
        lock(&self.inner.commands).clone()
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.inner.events.subscribe()
    }
}

/// Who a call is sent as.
struct Identity {
    kind: AuthorKind,
    id: String,
    run_id: Option<String>,
}

impl DaemonClientBackend {
    async fn send(
        &self,
        command: &str,
        mut args: Value,
        who: Identity,
        approved: bool,
    ) -> Result<Value, ProtoError> {
        let client = self.inner.client()?;
        absolutize(command, &mut args);
        let creating = matches!(command, "project_create" | "project_open");
        let project_dir = if creating {
            args.get("project_dir")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .ok_or_else(|| ProtoError::new(ErrorCode::InvalidArgument, "missing project_dir"))?
        } else {
            self.current_project().ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::NotFound,
                    "no project is open; run project_create or project_open first",
                )
            })?
        };
        let params = CallParams {
            project_dir: project_dir.to_string_lossy().into_owned(),
            command: command.to_string(),
            args,
            author_kind: who.kind,
            author_id: Some(who.id),
            run_id: who.run_id,
            surface: None,
            approved,
        };
        let reply = client.call(&params).await?;
        if creating {
            let key = std::fs::canonicalize(&project_dir).unwrap_or_else(|_| project_dir.clone());
            *lock(&self.inner.project) = Some((project_dir, key));
        }
        Ok(reply.result)
    }
}

/// Reads the `commands` reply (`[{spec, args_schema, output_schema}]`).
pub fn parse_commands(v: &Value) -> Vec<CommandInfo> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| serde_json::from_value(e.get("spec")?.clone()).ok())
                .collect()
        })
        .unwrap_or_default()
}

fn str_field<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

fn ids(v: &Value) -> Vec<u64> {
    let mut out: Vec<u64> = v
        .get("entry_ids")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    if let Some(id) = v.get("entry_id").and_then(Value::as_u64) {
        out.push(id);
    }
    out
}

fn change(v: &Value) -> ChangeInfo {
    ChangeInfo {
        command: str_field(v, "command").unwrap_or_default().to_string(),
        by_agent: str_field(v, "author_kind") == Some("agent"),
        author: str_field(v, "author_id").unwrap_or_default().to_string(),
        run_id: str_field(v, "run_id").map(str::to_string),
        entry_ids: ids(v),
        key: str_field(v, "key").map(str::to_string),
    }
}

fn job_state(s: &str) -> JobState {
    match s {
        "succeeded" => JobState::Succeeded,
        "failed" => JobState::Failed,
        "cancelled" => JobState::Cancelled,
        _ => JobState::Running,
    }
}

/// Maps one daemon `event` payload to a [`BackendEvent`]. Events of other projects than
/// `project_key` (the canonical directory of the open project) are dropped; with no project
/// open nothing is reported.
pub fn map_event(v: &Value, project_key: Option<&Path>) -> Option<BackendEvent> {
    let dir = str_field(v, "project_dir")?;
    if project_key != Some(Path::new(dir)) {
        return None;
    }
    let u64_of = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    Some(match str_field(v, "kind")? {
        event_kind::ENTRY_APPLIED => BackendEvent::EntryApplied(change(v)),
        event_kind::PROPOSAL_CREATED => BackendEvent::ProposalCreated(change(v)),
        event_kind::JOB_PROGRESS => BackendEvent::Job(JobInfo {
            job_id: str_field(v, "job_id")?.to_string(),
            command: str_field(v, "command").unwrap_or_default().to_string(),
            status: JobState::Running,
            progress: Some(JobProgress {
                phase: str_field(v, "phase").unwrap_or_default().to_string(),
                done: u64_of("done"),
                total: u64_of("total"),
                message: str_field(v, "message").unwrap_or_default().to_string(),
            }),
            result: None,
            error: None,
        }),
        event_kind::JOB_DONE => BackendEvent::Job(JobInfo {
            job_id: str_field(v, "job_id")?.to_string(),
            command: str_field(v, "command").unwrap_or_default().to_string(),
            status: job_state(str_field(v, "status").unwrap_or("succeeded")),
            progress: None,
            result: v.get("result").cloned(),
            error: v
                .get("error")
                .and_then(|e| serde_json::from_value::<ProtoError>(e.clone()).ok()),
        }),
        event_kind::SIDECAR_EXITED => BackendEvent::SidecarExited {
            restart_failed: v.get("restart_failed").is_some(),
        },
        event_kind::SIDECAR_RESTARTED => BackendEvent::SidecarRestarted {
            replayed: u64_of("replayed"),
            rejected: v
                .get("rejected")
                .map(|r| {
                    r.as_u64()
                        .unwrap_or_else(|| r.as_array().map_or(0, |a| a.len() as u64))
                })
                .unwrap_or(0),
        },
        event_kind::SESSION_OPENED => BackendEvent::SessionOpened,
        event_kind::SESSION_CLOSED => {
            BackendEvent::SessionClosed(str_field(v, "reason").unwrap_or("closed").to_string())
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn events_map_and_other_projects_are_dropped() {
        let key = Path::new("/p");
        let applied = json!({
            "seq": 1, "project_dir": "/p", "kind": "entry_applied", "command": "rename_symbol",
            "author_kind": "agent", "author_id": "claude", "run_id": "run-1", "entry_id": 7,
            "key": "native:ram:0x10:name"
        });
        match map_event(&applied, Some(key)) {
            Some(BackendEvent::EntryApplied(c)) => {
                assert!(c.by_agent);
                assert_eq!(c.author, "claude");
                assert_eq!(c.entry_ids, vec![7]);
                assert_eq!(c.run_id.as_deref(), Some("run-1"));
            }
            other => panic!("{other:?}"),
        }
        let mut elsewhere = applied.clone();
        elsewhere["project_dir"] = json!("/q");
        assert!(map_event(&elsewhere, Some(key)).is_none());
        assert!(map_event(&applied, None).is_none());

        let done = json!({"project_dir": "/p", "kind": "job_done", "job_id": "job-1",
            "command": "analyze", "status": "failed",
            "error": {"code": "internal", "message": "boom"}});
        match map_event(&done, Some(key)) {
            Some(BackendEvent::Job(j)) => {
                assert_eq!(j.status, JobState::Failed);
                assert_eq!(j.error.map(|e| e.message), Some("boom".into()));
            }
            other => panic!("{other:?}"),
        }
        let restarted = json!({"project_dir": "/p", "kind": "sidecar_restarted",
            "replayed": 2, "rejected": []});
        assert_eq!(
            map_event(&restarted, Some(key)),
            Some(BackendEvent::SidecarRestarted {
                replayed: 2,
                rejected: 0
            })
        );
        let closed = json!({"project_dir": "/p", "kind": "session_closed", "reason": "idle"});
        assert_eq!(
            map_event(&closed, Some(key)),
            Some(BackendEvent::SessionClosed("idle".into()))
        );
        assert!(
            map_event(
                &json!({"project_dir": "/p", "kind": "future_thing"}),
                Some(key)
            )
            .is_none()
        );
    }

    #[test]
    fn command_lists_parse_from_the_daemon_reply() {
        let v = json!([{"spec": {"name": "analyze", "summary": "Run", "kind": "job",
            "permission": "mutating", "doc": "x"}, "args_schema": {}, "output_schema": {}}]);
        let list = parse_commands(&v);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "analyze");
        assert_eq!(list[0].permission, Permission::Mutating);
    }

    #[test]
    fn project_command_paths_become_absolute() {
        let mut a = json!({"binary": "prog", "project_dir": "proj"});
        absolutize("project_create", &mut a);
        assert!(Path::new(a["binary"].as_str().unwrap_or("")).is_absolute());
        let mut b = json!({"address": "0x1"});
        absolutize("rename_symbol", &mut b);
        assert_eq!(b, json!({"address": "0x1"}));
    }
}

#[cfg(test)]
mod live_tests;

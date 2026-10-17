//! Client side of the `krakend` protocol, and the wire types both sides share.
//!
//! The daemon speaks `kraken-ipc` (framed JSON-RPC over a per-user socket) and offers these
//! methods:
//!
//! | method | params | result |
//! |---|---|---|
//! | `call` | [`CallParams`] | [`CallResult`] or the command's `ProtoError` |
//! | `commands` | none | list of `{spec, args_schema, output_schema}` |
//! | `status` | none | daemon info, open sessions, engine diagnostics |
//! | `events` | `{after_seq?, limit?}` | `{events: [...], last_seq}` (catch-up for a missed stream) |
//! | `shutdown` | none | `{"stopping": true}` |
//! | `approvals` | none | `{pending: [PendingApproval]}` (user credential only) |
//! | `approval_decide` | `{id, allow}` | `{decided: bool}` (user credential only) |
//! | `gui_selection_set` | [`GuiSelectionSetParams`] | `{stored: bool}` (user credential only) |
//! | `gui_selection` | `{project_dir}` | [`GuiSelectionReply`] |
//! | `infer_list` /`infer_start` / `infer_status` / `infer_stop` / `infer_logs` | see [`crate::infer`] | local model hosting |
//!
//! A connection is either user-class (GUI, CLI: the `daemon.token`) or agent-class (MCP servers:
//! the `agent.token`). The daemon takes author kind, surface and approval from that class: an
//! agent-class connection always acts as an agent on the MCP surface, its `approved` claim is
//! ignored, it may only use `call`, `commands` and `events`, and what needs a person's approval
//! waits on the daemon's approval list, which only a user-class connection can answer.
//!
//! Every connected client also receives `event` notifications ([`METHOD_EVENT`]) whose params
//! are an object with a monotonically increasing `seq`, the `project_dir` and a `kind`
//! ([`event_kind`]).

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use kraken_ipc::{
    Client, ClientError, ClientHello, ClientKind, DaemonInfo, EnsureError, IpcError, Notification,
    RuntimeDir, ensure_daemon,
};
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::Surface;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// Run a registry command.
pub const METHOD_CALL: &str = "call";
/// List the commands with their schemas.
pub const METHOD_COMMANDS: &str = "commands";
/// Daemon and session status.
pub const METHOD_STATUS: &str = "status";
/// Replay events after a cursor.
pub const METHOD_EVENTS: &str = "events";
/// Ask the daemon to exit.
pub const METHOD_SHUTDOWN: &str = "shutdown";
/// List the approvals waiting for a person (user credential only).
pub const METHOD_APPROVALS: &str = "approvals";
/// Answer a waiting approval (user credential only).
pub const METHOD_APPROVAL_DECIDE: &str = "approval_decide";
/// Publish what the person has selected in the GUI (user credential only).
pub const METHOD_GUI_SELECTION_SET: &str = "gui_selection_set";
/// Read what the person has selected in the GUI (any credential).
pub const METHOD_GUI_SELECTION: &str = "gui_selection";
/// Notification method of change events.
pub const METHOD_EVENT: &str = "event";

/// How long a GUI selection counts as fresh. After this the daemon still returns it, marked
/// `stale`: a person can look at one function for a long time.
pub const GUI_SELECTION_FRESH_SECS: u64 = 600;

/// What the GUI shows the person: published by the GUI, read by agents through the MCP resource
/// `kraken://gui/selection`. Names and text come from the binary, so the daemon treats every
/// string as untrusted (it sanitises and caps them).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiSelection {
    /// `function`, `instruction`, `decompile` or `type`.
    pub kind: String,
    /// Entry address of the function in view, as `0x...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    /// Name of that function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
    /// The selected address, as `0x...`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The selected text (a decompiler range, an instruction, a type).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Params of `gui_selection_set`: `selection: null` clears it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiSelectionSetParams {
    /// Absolute project directory the selection belongs to.
    pub project_dir: String,
    /// The selection, or `None` when the GUI shows nothing.
    pub selection: Option<GuiSelection>,
}

/// Result of `gui_selection`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuiSelectionReply {
    /// True when a GUI has published a selection for this project and not cleared it.
    pub attached: bool,
    /// True when it was published more than [`GUI_SELECTION_FRESH_SECS`] ago.
    #[serde(default)]
    pub stale: bool,
    /// Seconds since it was published.
    #[serde(default)]
    pub age_secs: u64,
    /// The selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<GuiSelection>,
}

/// Names of the `kind` field of change events.
pub mod event_kind {
    /// A mutation was applied (or queued) in a project.
    pub const ENTRY_APPLIED: &str = "entry_applied";
    /// An agent edit became a proposal.
    pub const PROPOSAL_CREATED: &str = "proposal_created";
    /// A job reported new progress.
    pub const JOB_PROGRESS: &str = "job_progress";
    /// A job ended.
    pub const JOB_DONE: &str = "job_done";
    /// The sidecar behind a project came back; pending log entries were replayed.
    pub const SIDECAR_RESTARTED: &str = "sidecar_restarted";
    /// The sidecar behind a project ended.
    pub const SIDECAR_EXITED: &str = "sidecar_exited";
    /// A project session was opened.
    pub const SESSION_OPENED: &str = "session_opened";
    /// A project session was closed (idle or evicted).
    pub const SESSION_CLOSED: &str = "session_closed";
    /// An agent asks for something that needs a person's approval; answer with
    /// `approval_decide`.
    pub const APPROVAL_REQUESTED: &str = "approval_requested";
    /// A waiting approval ended (`allowed`, `denied`, `timed_out` or `abandoned`).
    pub const APPROVAL_RESOLVED: &str = "approval_resolved";
}

/// Params of the `call` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallParams {
    /// Absolute project directory the command works on (for `project_create` / `project_open`
    /// the directory being created / opened).
    pub project_dir: String,
    /// Registry command name (`rename_symbol`).
    pub command: String,
    /// Command arguments; `null` means none.
    #[serde(default)]
    pub args: Value,
    /// Who the edit is attributed to. A user-class connection may label its calls `agent` (the
    /// assistant does); an agent-class connection is always an agent whatever this says.
    pub author_kind: AuthorKind,
    /// User name or agent id; defaults from the connection when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
    /// Agent run the call belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Surface the call comes from; defaults from the connection's client kind (always `mcp`
    /// for an agent-class connection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// True when the client already asked its user to approve a dangerous command. Honoured on a
    /// user-class connection only; the daemon ignores it from an agent.
    #[serde(default)]
    pub approved: bool,
}

/// Result of the `call` method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallResult {
    /// Exactly what the registry command returned.
    pub result: Value,
    /// Non-fatal notices for the person (a stale engine cache, ...).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Why no daemon connection could be made.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// The runtime directory is unusable.
    #[error("{0}")]
    Runtime(#[from] IpcError),
    /// Starting or reaching the daemon failed.
    #[error("{0}")]
    Ensure(#[from] EnsureError),
    /// The daemon is running but refused or dropped the connection.
    #[error("{0}")]
    Client(#[from] ClientError),
    /// There is no `krakend` binary to start.
    #[error(
        "cannot find the krakend binary ({0}); install it next to `kraken` or set KRAKEN_KRAKEND"
    )]
    NoBinary(String),
}

impl DaemonError {
    /// True when the daemon is from another build/protocol and must be restarted.
    pub fn restart_required(&self) -> bool {
        match self {
            DaemonError::Client(e) | DaemonError::Ensure(EnsureError::Client(e)) => {
                e.restart_required()
            }
            _ => false,
        }
    }
}

/// How `krakend` is found and started.
#[derive(Debug, Clone)]
pub struct StartOptions {
    /// The `krakend` binary; default `$KRAKEN_KRAKEND`, else next to the running executable.
    pub krakend: Option<PathBuf>,
    /// Extra command-line arguments for `krakend`.
    pub extra_args: Vec<OsString>,
    /// Extra environment variables for `krakend` (it inherits the caller's environment).
    pub env: Vec<(OsString, OsString)>,
    /// Longest wait for the daemon to accept connections.
    pub timeout: Duration,
}

impl Default for StartOptions {
    fn default() -> Self {
        StartOptions {
            krakend: None,
            extra_args: Vec::new(),
            env: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Environment variable naming the `krakend` binary.
pub const ENV_KRAKEND: &str = "KRAKEN_KRAKEND";

fn exe_name() -> &'static str {
    if cfg!(windows) {
        "krakend.exe"
    } else {
        "krakend"
    }
}

/// Finds `krakend`: `$KRAKEN_KRAKEND`, else the directory of the running executable (and, for
/// test binaries in `target/<profile>/deps`, its parent).
pub fn find_krakend() -> Result<PathBuf, DaemonError> {
    if let Some(p) = std::env::var_os(ENV_KRAKEND).filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe().map_err(|e| DaemonError::NoBinary(e.to_string()))?;
    let dir = exe
        .parent()
        .ok_or_else(|| DaemonError::NoBinary("executable has no directory".into()))?;
    let mut candidates = vec![dir.join(exe_name())];
    if dir.file_name().is_some_and(|n| n == "deps")
        && let Some(up) = dir.parent()
    {
        candidates.push(up.join(exe_name()));
    }
    candidates
        .iter()
        .find(|c| c.is_file())
        .cloned()
        .ok_or_else(|| {
            DaemonError::NoBinary(format!(
                "looked for {}",
                candidates
                    .iter()
                    .map(|c| c.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// Starts `krakend` detached from the caller's terminal and process group.
pub fn spawn_krakend(opts: &StartOptions) -> Result<Child, DaemonError> {
    let path = match &opts.krakend {
        Some(p) => p.clone(),
        None => find_krakend()?,
    };
    let mut cmd = Command::new(&path);
    cmd.args(&opts.extra_args)
        .envs(opts.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn()
        .map_err(|e| DaemonError::NoBinary(format!("{}: {e}", path.display())))
}

fn to_proto(e: ClientError) -> ProtoError {
    match e {
        ClientError::Proto(p) => p,
        other => ProtoError::new(
            ErrorCode::Internal,
            format!("lost the connection to krakend: {other}; run `kraken daemon start`"),
        ),
    }
}

/// A connection to a running `krakend`.
#[derive(Clone)]
pub struct DaemonClient {
    client: Client,
    build: String,
}

impl DaemonClient {
    /// Wraps an already connected client (tests connect over their own sockets).
    pub fn from_client(client: Client, build: impl Into<String>) -> Self {
        DaemonClient {
            client,
            build: build.into(),
        }
    }

    /// Connects to the running daemon; `Ok(None)` when none is running.
    pub async fn connect_running(
        dir: &RuntimeDir,
        kind: ClientKind,
        build: &str,
    ) -> Result<Option<Self>, DaemonError> {
        match Client::connect(dir, &ClientHello::new(kind, build)).await {
            Ok(c) => Ok(Some(Self::from_client(c, build))),
            Err(ClientError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Connects to the daemon, starting `krakend` when none runs. Safe against concurrent
    /// starters (see `kraken_ipc::ensure_daemon`).
    pub async fn connect_or_start(
        dir: &RuntimeDir,
        kind: ClientKind,
        build: &str,
        opts: &StartOptions,
    ) -> Result<Self, DaemonError> {
        let hello = ClientHello::new(kind, build);
        let client = ensure_daemon(
            dir,
            &hello,
            || spawn_krakend(opts).map_err(|e| io::Error::other(e.to_string())),
            opts.timeout,
        )
        .await?;
        Ok(Self::from_client(client, build))
    }

    /// The daemon's build string from the handshake.
    pub fn daemon_build(&self) -> &str {
        &self.client.server_info().build
    }

    /// The daemon's process id.
    pub fn daemon_pid(&self) -> u32 {
        self.client.server_info().daemon_pid
    }

    /// A notice when the daemon is from a different build than this client.
    pub fn build_mismatch_warning(&self) -> Option<String> {
        (self.daemon_build() != self.build).then(|| {
            format!(
                "krakend is build {} but this client is {}; run `kraken daemon stop` to restart it",
                self.daemon_build(),
                self.build
            )
        })
    }

    /// Takes the stream of `event` notifications (only the first caller gets it).
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<Notification>> {
        self.client.take_notifications()
    }

    /// Runs a registry command in the daemon.
    pub async fn call(&self, params: &CallParams) -> Result<CallResult, ProtoError> {
        let v = serde_json::to_value(params)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        let r = self.client.call(METHOD_CALL, v).await.map_err(to_proto)?;
        serde_json::from_value(r).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("malformed reply from krakend: {e}"),
            )
        })
    }

    /// The command list with schemas.
    pub async fn commands(&self) -> Result<Value, ProtoError> {
        self.client
            .call(METHOD_COMMANDS, Value::Null)
            .await
            .map_err(to_proto)
    }

    /// Daemon status.
    pub async fn status(&self) -> Result<Value, ProtoError> {
        self.client
            .call(METHOD_STATUS, Value::Null)
            .await
            .map_err(to_proto)
    }

    /// Events after `after_seq` still held by the daemon (at most `limit`).
    pub async fn events_since(
        &self,
        after_seq: u64,
        limit: Option<u32>,
    ) -> Result<Value, ProtoError> {
        self.client
            .call(
                METHOD_EVENTS,
                json!({"after_seq": after_seq, "limit": limit}),
            )
            .await
            .map_err(to_proto)
    }

    /// What the person has selected in the GUI for the project in `project_dir`. An older daemon
    /// does not know the method; that reads as "no GUI attached".
    pub async fn gui_selection(&self, project_dir: &Path) -> Result<GuiSelectionReply, ProtoError> {
        let params = json!({"project_dir": absolute(project_dir).to_string_lossy()});
        match self.client.call(METHOD_GUI_SELECTION, params).await {
            Ok(v) => serde_json::from_value(v).map_err(|e| {
                ProtoError::new(
                    ErrorCode::Internal,
                    format!("malformed reply from krakend: {e}"),
                )
            }),
            Err(e) => {
                let e = to_proto(e);
                if e.code == ErrorCode::NotFound {
                    Ok(GuiSelectionReply {
                        attached: false,
                        stale: false,
                        age_secs: 0,
                        selection: None,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Publishes (or with `None` clears) the GUI's selection for the project in `project_dir`.
    /// The daemon accepts this from a user-credential connection only.
    pub async fn set_gui_selection(
        &self,
        project_dir: &Path,
        selection: Option<GuiSelection>,
    ) -> Result<(), ProtoError> {
        let params = serde_json::to_value(GuiSelectionSetParams {
            project_dir: absolute(project_dir).to_string_lossy().into_owned(),
            selection,
        })
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        self.client
            .call(METHOD_GUI_SELECTION_SET, params)
            .await
            .map(|_| ())
            .map_err(to_proto)
    }

    /// Calls any daemon method by name (the `infer_*` methods go through here).
    pub async fn rpc(&self, method: &str, params: Value) -> Result<Value, ProtoError> {
        self.client.call(method, params).await.map_err(to_proto)
    }

    /// Asks the daemon to exit.
    pub async fn shutdown(&self) -> Result<(), ProtoError> {
        self.client
            .call(METHOD_SHUTDOWN, Value::Null)
            .await
            .map(|_| ())
            .map_err(to_proto)
    }
}

/// Waits until the daemon of `dir` has published its exit (its `daemon.json` is gone).
pub async fn wait_until_stopped(dir: &RuntimeDir, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if !matches!(DaemonInfo::read(&dir.info_path()), Ok(Some(_))) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The `KRAKEN_RUNTIME_DIR` setting to give the MCP server of a terminal agent that talks to
/// the daemon. The agent itself is not given the runtime directory (see `kraken-acp`), so the
/// MCP server it starts needs it spelled out; the server connects with the agent credential,
/// which cannot approve anything. `None` when no runtime directory can be resolved.
pub fn mcp_runtime_env() -> Option<(String, String)> {
    let dir = RuntimeDir::resolve().ok()?;
    Some((
        kraken_ipc::ENV_RUNTIME_DIR.to_string(),
        dir.path().to_string_lossy().into_owned(),
    ))
}

/// Makes `p` absolute against the current directory (no symlink resolution).
pub fn absolute(p: &Path) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_params_round_trip_and_defaults() {
        let p: CallParams = serde_json::from_value(json!({
            "project_dir": "/p", "command": "list_functions", "author_kind": "user"
        }))
        .unwrap();
        assert_eq!(p.author_kind, AuthorKind::User);
        assert!(p.args.is_null() && !p.approved && p.run_id.is_none());
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("run_id").is_none());
    }

    #[test]
    fn find_krakend_honours_the_override_shape() {
        let opts = StartOptions {
            krakend: Some("/nonexistent/krakend".into()),
            ..Default::default()
        };
        let err = spawn_krakend(&opts).unwrap_err();
        assert!(matches!(err, DaemonError::NoBinary(_)));
        assert!(err.to_string().contains("/nonexistent/krakend"));
    }
}

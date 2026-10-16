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
//! | `infer_list` / `infer_start` / `infer_status` / `infer_stop` / `infer_logs` | see [`crate::infer`] | local model hosting |
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
/// Notification method of change events.
pub const METHOD_EVENT: &str = "event";

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
    /// Who the edit is attributed to.
    pub author_kind: AuthorKind,
    /// User name or agent id; defaults from the connection when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
    /// Agent run the call belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Surface the call comes from; defaults from the connection's client kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// True when the client already asked its user to approve a dangerous command.
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

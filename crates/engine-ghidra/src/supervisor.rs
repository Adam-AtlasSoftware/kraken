//! Sidecar lifecycle: start, handshake, death detection, bounded restart, events.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_proto::{ErrorCode, Handshake, PROTOCOL_VERSION, ProtoError};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{broadcast, watch};

use crate::launch::{LaunchPlan, Launched, Launcher, Session};
use crate::log::LogSink;
use crate::rpc::{RpcClient, SIDECAR_EXITED};
use crate::sandbox::{ConfinementReport, ExitInfo};

/// Sidecar capabilities this crate cannot work without.
pub const REQUIRED_SIDECAR_CAPABILITIES: &[&str] = &[
    "open_binary",
    "analyze.staged",
    "list_functions",
    "decompile.tokens",
    "apply_op.v1",
    "types.roundtrip",
    "save",
    "memory_map",
    "read_bytes",
    "disassemble",
    "xrefs",
    "cfg",
    "strings",
    "imports",
    "exports",
];

/// Lifecycle events for the registry (decision 40).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarEvent {
    /// A sidecar process finished its handshake and is serving requests.
    Started,
    /// The sidecar process ended (`code` is `None` when it was killed by a signal).
    Exited {
        /// Exit code.
        code: Option<i32>,
    },
    /// [`Supervisor::restart`] brought a new sidecar up and reopened the binary. The in-memory
    /// state of the old one (unsaved edits) is gone: replay the log.
    Restarted,
}

/// Supervision parameters.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    /// Attempts per [`Supervisor::restart`] call.
    pub max_restarts: u32,
    /// Wait for `ready` and for the handshake.
    pub startup_timeout: Duration,
    /// Base delay between restart attempts.
    pub restart_backoff: Duration,
    /// Deadline of the `open_binary` replayed by a restart.
    pub open_timeout: Duration,
    /// Ghidra version the JVM must report.
    pub expected_ghidra_version: Option<String>,
}

/// How to reopen the program after a restart.
#[derive(Debug, Clone)]
pub struct OpenParams {
    /// The `open_binary` request parameters that succeeded.
    pub request: Value,
    /// The launch plan they ran under.
    pub plan: LaunchPlan,
}

/// One live (or dead) sidecar process and its channel.
pub struct Running {
    /// Request channel.
    pub client: RpcClient,
    /// What it was started for.
    pub plan: LaunchPlan,
    /// Captured stdout/stderr.
    pub log: LogSink,
    /// Applied confinement.
    pub report: ConfinementReport,
    /// Process id.
    pub pid: Option<u32>,
    /// Ghidra version reported by `ready`.
    pub ghidra_version: String,
    /// Build string from the handshake.
    pub sidecar_build: String,
    exit: watch::Receiver<Option<ExitInfo>>,
    session: Box<dyn Session>,
}

impl Running {
    /// Whether the process is still serving.
    pub fn is_alive(&self) -> bool {
        self.exit.borrow().is_none() && !self.client.is_closed()
    }

    /// How the process ended, if it has.
    pub fn exit_info(&self) -> Option<ExitInfo> {
        *self.exit.borrow()
    }

    /// Kills the process.
    pub fn kill(&self) {
        self.session.kill();
    }

    /// Adds the exit status and the log tail to a `sidecar exited` error.
    pub fn enrich(&self, mut e: ProtoError) -> ProtoError {
        if e.code == ErrorCode::Internal && e.message == SIDECAR_EXITED {
            e = e.with_details(json!({
                "exit": self.exit_info().map(|x| json!({"code": x.code, "signal": x.signal})),
                "log_tail": self.log.tail(20),
                "hint": "call restart() to bring the sidecar back",
            }));
        }
        e
    }
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("pid", &self.pid)
            .field("alive", &self.is_alive())
            .finish_non_exhaustive()
    }
}

/// What a diagnostics call knows about the sidecar.
#[derive(Debug, Clone, Serialize)]
pub struct Diagnostics {
    /// `not_started`, `running` or `exited`.
    pub state: &'static str,
    /// Process id of the latest sidecar.
    pub pid: Option<u32>,
    /// Exit status of the latest sidecar, if it ended.
    pub exit: Option<ExitInfo>,
    /// Confinement applied to the latest sidecar.
    pub confinement: Option<ConfinementReport>,
    /// Ghidra version reported by the latest sidecar.
    pub ghidra_version: Option<String>,
    /// Sidecar build string from the handshake.
    pub sidecar_build: Option<String>,
    /// JVM heap the latest sidecar was started with.
    pub heap_mb: Option<u64>,
    /// Successful restarts so far.
    pub restarts: u32,
    /// The last lines of the sidecar's stdout/stderr.
    pub log_tail: Vec<String>,
}

/// Owns the sidecar: at most one process at a time.
pub struct Supervisor {
    launcher: Arc<dyn Launcher>,
    cfg: SupervisorConfig,
    events: broadcast::Sender<SidecarEvent>,
    lifecycle: tokio::sync::Mutex<()>,
    current: Mutex<Option<Arc<Running>>>,
    last_open: Mutex<Option<OpenParams>>,
    restarts: AtomicU32,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Supervisor {
    /// A supervisor that starts sidecars with `launcher`.
    pub fn new(launcher: Arc<dyn Launcher>, cfg: SupervisorConfig) -> Self {
        Supervisor {
            launcher,
            cfg,
            events: broadcast::channel(64).0,
            lifecycle: tokio::sync::Mutex::new(()),
            current: Mutex::new(None),
            last_open: Mutex::new(None),
            restarts: AtomicU32::new(0),
        }
    }

    /// Subscribes to lifecycle events.
    pub fn subscribe(&self) -> broadcast::Receiver<SidecarEvent> {
        self.events.subscribe()
    }

    /// The live sidecar, or `internal: sidecar exited` (with exit status and log tail) when it
    /// died, or `invalid_argument` when nothing was opened yet.
    pub fn current(&self) -> Result<Arc<Running>, ProtoError> {
        match lock(&self.current).clone() {
            None => Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "no binary is open: call open_binary first",
            )),
            Some(r) if r.is_alive() => Ok(r),
            Some(r) => Err(r.enrich(ProtoError::new(ErrorCode::Internal, SIDECAR_EXITED))),
        }
    }

    /// Ensures a live sidecar started for `plan`, restarting it when the plan changed (a
    /// different binary needs different confinement and heap) or when it died.
    pub async fn ensure(&self, plan: LaunchPlan) -> Result<Arc<Running>, ProtoError> {
        let _l = self.lifecycle.lock().await;
        let existing = lock(&self.current).clone();
        if let Some(r) = existing {
            if r.is_alive() && r.plan == plan {
                return Ok(r);
            }
            self.stop(&r).await;
        }
        self.start(&plan).await
    }

    /// Remembers how to reopen the program after a restart.
    pub fn remember_open(&self, params: OpenParams) {
        *lock(&self.last_open) = Some(params);
    }

    /// Replaces the sidecar by a fresh one and reopens the last binary. Makes up to
    /// `max_restarts` attempts; emits [`SidecarEvent::Restarted`] on success.
    pub async fn restart(&self) -> Result<Arc<Running>, ProtoError> {
        let _l = self.lifecycle.lock().await;
        let open = lock(&self.last_open).clone().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                "nothing to restart: no binary has been opened",
            )
        })?;
        let old = lock(&self.current).clone();
        if let Some(old) = old {
            self.stop(&old).await;
        }
        let attempts = self.cfg.max_restarts.max(1);
        let mut last = None;
        for attempt in 1..=attempts {
            if attempt > 1 {
                tokio::time::sleep(self.cfg.restart_backoff * attempt).await;
            }
            match self.start_and_reopen(&open).await {
                Ok(r) => {
                    self.restarts.fetch_add(1, Ordering::Relaxed);
                    let _ = self.events.send(SidecarEvent::Restarted);
                    return Ok(r);
                }
                Err(e) => {
                    tracing::warn!("sidecar restart attempt {attempt}/{attempts} failed: {e}");
                    last = Some(e);
                }
            }
        }
        let last = last.map(|e| e.to_string()).unwrap_or_default();
        Err(ProtoError::new(
            ErrorCode::Internal,
            format!("the sidecar could not be restarted after {attempts} attempts: {last}"),
        ))
    }

    /// Asks the sidecar to shut down, then kills it.
    pub async fn shutdown(&self) {
        let _l = self.lifecycle.lock().await;
        let r = lock(&self.current).clone();
        if let Some(r) = r {
            self.stop(&r).await;
        }
    }

    /// A snapshot for diagnostics.
    pub fn diagnostics(&self) -> Diagnostics {
        let restarts = self.restarts.load(Ordering::Relaxed);
        match lock(&self.current).clone() {
            None => Diagnostics {
                state: "not_started",
                pid: None,
                exit: None,
                confinement: None,
                ghidra_version: None,
                sidecar_build: None,
                heap_mb: None,
                restarts,
                log_tail: Vec::new(),
            },
            Some(r) => Diagnostics {
                state: if r.is_alive() { "running" } else { "exited" },
                pid: r.pid,
                exit: r.exit_info(),
                confinement: Some(r.report.clone()),
                ghidra_version: Some(r.ghidra_version.clone()),
                sidecar_build: Some(r.sidecar_build.clone()),
                heap_mb: Some(r.plan.heap_mb),
                restarts,
                log_tail: r.log.tail(50),
            },
        }
    }

    async fn stop(&self, r: &Running) {
        if r.is_alive() {
            let _ = r
                .client
                .call("shutdown", json!({}), Some(Duration::from_secs(5)), None)
                .await;
        }
        r.kill();
        let mut exit = r.exit.clone();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while exit.borrow_and_update().is_none() {
                if exit.changed().await.is_err() {
                    break;
                }
            }
        })
        .await;
    }

    async fn start_and_reopen(&self, open: &OpenParams) -> Result<Arc<Running>, ProtoError> {
        let r = self.start(&open.plan).await?;
        let reopened = r
            .client
            .call(
                "open_binary",
                open.request.clone(),
                Some(self.cfg.open_timeout),
                None,
            )
            .await;
        match reopened {
            Ok(_) => Ok(r),
            Err(e) => {
                let e = r.enrich(e);
                r.kill();
                Err(e)
            }
        }
    }

    /// Launches, waits for `ready`, checks the handshake and publishes the new process.
    async fn start(&self, plan: &LaunchPlan) -> Result<Arc<Running>, ProtoError> {
        let Launched {
            reader,
            writer,
            exit,
            log,
            report,
            pid,
            session,
        } = self.launcher.launch(plan).await?;
        let client = RpcClient::new(reader, writer);
        let running = match self.handshake(&client, &log, &exit).await {
            Ok((ghidra_version, sidecar_build)) => Running {
                client,
                plan: plan.clone(),
                log,
                report,
                pid,
                ghidra_version,
                sidecar_build,
                exit: exit.clone(),
                session,
            },
            Err(e) => {
                session.kill();
                return Err(e);
            }
        };
        let running = Arc::new(running);
        *lock(&self.current) = Some(running.clone());
        let events = self.events.clone();
        let mut exit = exit;
        tokio::spawn(async move {
            loop {
                if let Some(info) = *exit.borrow_and_update() {
                    let _ = events.send(SidecarEvent::Exited { code: info.code });
                    break;
                }
                if exit.changed().await.is_err() {
                    break;
                }
            }
        });
        let _ = self.events.send(SidecarEvent::Started);
        Ok(running)
    }

    async fn handshake(
        &self,
        client: &RpcClient,
        log: &LogSink,
        exit: &watch::Receiver<Option<ExitInfo>>,
    ) -> Result<(String, String), ProtoError> {
        let startup = |e: ProtoError| {
            let status = *exit.borrow();
            ProtoError::new(
                e.code,
                format!(
                    "sidecar startup failed: {}{}; last output: {:?}",
                    e.message,
                    status.map_or(String::new(), |s| format!(
                        " (exit code {:?}, signal {:?})",
                        s.code, s.signal
                    )),
                    log.tail(10)
                ),
            )
        };
        let ready = client
            .wait_ready(self.cfg.startup_timeout)
            .await
            .map_err(startup)?;
        if let Some(want) = &self.cfg.expected_ghidra_version
            && &ready.ghidra_version != want
        {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "the sidecar runs Ghidra {} but {want} was expected",
                    ready.ghidra_version
                ),
            ));
        }
        let hs: Handshake = client
            .call_typed("handshake", json!({}), Some(self.cfg.startup_timeout), None)
            .await
            .map_err(startup)?;
        check_handshake(&hs)?;
        Ok((ready.ghidra_version, hs.build))
    }
}

/// Validates a sidecar handshake: same protocol version, all required capabilities.
pub fn check_handshake(hs: &Handshake) -> Result<(), ProtoError> {
    if hs.protocol != PROTOCOL_VERSION {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "protocol mismatch: the sidecar ({}) speaks {}.{} but this build speaks {}.{}; restart the daemon so both come from the same build",
                hs.build,
                hs.protocol.major,
                hs.protocol.minor,
                PROTOCOL_VERSION.major,
                PROTOCOL_VERSION.minor
            ),
        ));
    }
    let missing: Vec<&str> = REQUIRED_SIDECAR_CAPABILITIES
        .iter()
        .copied()
        .filter(|c| !hs.capabilities.iter().any(|h| h.name == *c))
        .collect();
    if !missing.is_empty() {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "the sidecar ({}) lacks capabilities: {}",
                hs.build,
                missing.join(", ")
            ),
        ));
    }
    Ok(())
}

/// Paths a restart needs to reproduce an `open_binary`.
pub fn open_request(
    binary: &std::path::Path,
    project_dir: &std::path::Path,
    spec: Option<&str>,
) -> Value {
    let mut v = json!({
        "path": binary,
        "project_dir": project_dir,
    });
    if let (Some(spec), Some(obj)) = (spec, v.as_object_mut()) {
        obj.insert("loader_spec".into(), Value::String(spec.to_string()));
    }
    v
}

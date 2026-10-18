//! The parent side: starts the worker under confinement and watches every request.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_engine::Watermark;
use kraken_engine::{AnalysisSummary, OpenReporter, Progress, ProgressSender, Stage};
use kraken_proto::{ErrorCode, OpenStage, OpenUpdate, ProtoError, TypeDef, VersionedLogOp};
use kraken_sidecar::rpc::{JobSubscription, SIDECAR_EXITED, WireProgress};
use kraken_sidecar::sandbox::Sandbox;
use kraken_sidecar::{ConfinementReport, LogSink, RpcClient, SpawnSpec};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

use super::{CORE_DUMPS_ARG, OpenParams, TEST_HOOKS_ARG, WorkerOptions, duration_ms};
use crate::engine::{NativeConfig, NativeStats, cancelled};
use crate::mutate::Journaled;

/// How long a new worker may take to report ready.
const READY_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for the exit status of a worker whose channel closed.
const EXIT_WAIT: Duration = Duration::from_secs(2);
/// Log lines attached to a crash report.
const LOG_TAIL: usize = 20;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One running worker. Field order is drop order: the channel closes, then the process is
/// killed, then its home is removed.
struct Live {
    client: RpcClient,
    sandbox: Sandbox,
    log: LogSink,
    /// Set when the watchdog killed this worker.
    killed: AtomicBool,
    _home: TempDir,
}

impl Live {
    fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        self.sandbox.kill();
    }

    fn usable(&self) -> bool {
        !self.killed.load(Ordering::SeqCst) && !self.client.is_closed()
    }
}

/// The engine state kept on the parent side: what to re-open after a restart.
pub(crate) struct WorkerEngine {
    config: NativeConfig,
    opts: WorkerOptions,
    live: tokio::sync::Mutex<Option<Arc<Live>>>,
    program: Mutex<Option<OpenParams>>,
    /// Edit-log operations and type definitions the worker accepted since the program was
    /// opened, in order; the worker's journal is the `base` entries it replayed from the state
    /// directory followed by these.
    journal: Mutex<Vec<Journaled>>,
    /// Journal entries the first worker restored from `native-state.json` when the program was
    /// opened.
    base: AtomicUsize,
    /// Serializes edits and saves, so the journal here and the worker's stay in the same order.
    edit_gate: tokio::sync::Mutex<()>,
    next_op: AtomicU64,
    restarts: AtomicU64,
    report: Mutex<Option<ConfinementReport>>,
    pid: AtomicU64,
}

/// Where the progress events of a request go.
#[derive(Clone, Copy)]
pub(crate) enum Forward<'a> {
    /// Nowhere: they only keep the request alive.
    Drop,
    /// To an analysis job.
    Job(&'a ProgressSender),
    /// To the report of an open.
    Open(&'a OpenReporter),
}

/// What a request is allowed while it runs.
pub(crate) struct Limits<'a> {
    deadline: Duration,
    /// Progress events of the request: each one restarts the deadline, and is passed on.
    progress: Option<(&'a mut JobSubscription, Forward<'a>)>,
}

impl WorkerEngine {
    pub(crate) fn new(config: NativeConfig, opts: WorkerOptions) -> WorkerEngine {
        WorkerEngine {
            config,
            opts,
            live: tokio::sync::Mutex::new(None),
            program: Mutex::new(None),
            journal: Mutex::new(Vec::new()),
            base: AtomicUsize::new(0),
            edit_gate: tokio::sync::Mutex::new(()),
            next_op: AtomicU64::new(0),
            restarts: AtomicU64::new(0),
            report: Mutex::new(None),
            pid: AtomicU64::new(0),
        }
    }

    pub(crate) fn restarts(&self) -> u64 {
        self.restarts.load(Ordering::SeqCst)
    }

    pub(crate) fn confinement(&self) -> Option<ConfinementReport> {
        lock(&self.report).clone()
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        u32::try_from(self.pid.load(Ordering::SeqCst))
            .ok()
            .filter(|p| *p != 0)
    }

    pub(crate) async fn log_tail(&self, n: usize) -> Vec<String> {
        match self.live.lock().await.as_ref() {
            Some(l) => l.log.tail(n),
            None => Vec::new(),
        }
    }

    /// The hard deadline of an ordinary request.
    pub(crate) fn request_limits(&self) -> Limits<'static> {
        Limits {
            deadline: self.opts.request_timeout,
            progress: None,
        }
    }

    /// The hard deadline of a decompile: the cooperative limit plus grace.
    pub(crate) fn decompile_limits(&self) -> Limits<'static> {
        Limits {
            deadline: self
                .config
                .decompile_timeout
                .map_or(self.opts.request_timeout, |t| t + self.opts.decompile_grace),
            progress: None,
        }
    }

    /// Opens `path` in a fresh worker (an open worker is replaced), telling `report` how it is
    /// getting on.
    pub(crate) async fn open(
        &self,
        path: PathBuf,
        spec: kraken_engine::LoaderSpec,
        cancel: &CancellationToken,
        report: Option<&OpenReporter>,
    ) -> Result<kraken_engine::ProgramInfo, ProtoError> {
        let open = OpenParams {
            path,
            spec,
            spec_root: self.config.spec_root.clone(),
            use_symbols: self.config.use_symbols,
            decompile_timeout_ms: self.config.decompile_timeout.map(duration_ms),
            state_dir: self.state_dir()?,
            threads: Some(
                self.config
                    .discovery_threads
                    .unwrap_or_else(crate::discover::default_threads),
            ),
        };
        let _gate = self.edit_gate.lock().await;
        let mut slot = self.live.lock().await;
        drop(slot.take());
        lock(&self.journal).clear();
        *lock(&self.program) = None;
        let (live, info) = self.start(&open, true, cancel, report).await?;
        *lock(&self.program) = Some(open);
        *slot = Some(live);
        Ok(info)
    }

    /// The running worker, restarted (re-opening the program) when the last one died or was
    /// killed.
    async fn ensure(&self, cancel: &CancellationToken) -> Result<Arc<Live>, ProtoError> {
        let mut slot = self.live.lock().await;
        if let Some(l) = slot.as_ref().filter(|l| l.usable()) {
            return Ok(l.clone());
        }
        let Some(open) = lock(&self.program).clone() else {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "no binary is open",
            ));
        };
        let had = slot.take().is_some();
        let (live, _) = self.start(&open, false, cancel, None).await?;
        if had {
            self.restarts.fetch_add(1, Ordering::SeqCst);
        }
        *slot = Some(live.clone());
        Ok(live)
    }

    /// The state directory, created (the confinement can only grant an existing directory) and
    /// resolved.
    fn state_dir(&self) -> Result<Option<PathBuf>, ProtoError> {
        let Some(dir) = &self.config.state_dir else {
            return Ok(None);
        };
        std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::canonicalize(dir))
            .map(Some)
            .map_err(|e| {
                internal(format!(
                    "cannot create the engine state directory {}: {e}",
                    dir.display()
                ))
            })
    }

    /// Spawns a worker and opens the program in it, which replays the saved state. A first open
    /// records how many entries that restored; a restart replays the entries accepted since that
    /// the state file does not hold yet.
    async fn start(
        &self,
        open: &OpenParams,
        first: bool,
        cancel: &CancellationToken,
        report: Option<&OpenReporter>,
    ) -> Result<(Arc<Live>, kraken_engine::ProgramInfo), ProtoError> {
        if let Some(r) = report {
            r(OpenUpdate::stage(
                OpenStage::StartEngine,
                "Starting the engine worker",
            ));
        }
        let live = Arc::new(self.spawn(open).await?);
        // the deadline is for the gap between two reports of the discovery, not for the whole
        // open: the first open of a big binary takes a long time
        let job_id = format!(
            "native-open-{}",
            self.next_op.fetch_add(1, Ordering::Relaxed) + 1
        );
        let mut sub = live.client.subscribe_progress(&job_id);
        let info = self
            .exec(
                &live,
                "open",
                json!({ "open": open, "job_id": job_id }),
                Limits {
                    deadline: self.opts.open_timeout,
                    progress: Some((&mut sub, report.map_or(Forward::Drop, Forward::Open))),
                },
                cancel,
            )
            .await?;
        drop(sub);
        let info = decode("open", info)?;
        let restored = decode::<NativeStats>(
            "stats",
            self.exec(&live, "stats", json!({}), self.request_limits(), cancel)
                .await?,
        )?
        .edits;
        if first {
            self.base.store(restored, Ordering::SeqCst);
            return Ok((live, info));
        }
        // the state file holds the opening entries plus the first `saved` of ours
        let saved = restored.saturating_sub(self.base.load(Ordering::SeqCst));
        let pending: Vec<Journaled> = lock(&self.journal).iter().skip(saved).cloned().collect();
        for entry in pending {
            let (method, params) = match entry {
                Journaled::Op(op) => ("apply", json!({ "log_op": op })),
                Journaled::TypeDef(def) => ("define_type", json!({ "def": def })),
            };
            self.exec(&live, method, params, self.request_limits(), cancel)
                .await?;
        }
        Ok((live, info))
    }

    async fn spawn(&self, open: &OpenParams) -> Result<Live, ProtoError> {
        let program = self.opts.locate()?;
        let opts = self.opts.clone();
        let spec_root = open.spec_root.clone();
        let binary = open.path.clone();
        let state_dir = open.state_dir.clone();
        let (sandbox, home, log, channel) = tokio::task::spawn_blocking(move || {
            let root = opts.temp_root.clone().unwrap_or_else(std::env::temp_dir);
            let home = tempfile::Builder::new()
                .prefix("kraken-native-")
                .tempdir_in(&root)
                .map_err(|e| {
                    internal(format!(
                        "creating the worker home in {}: {e}",
                        root.display()
                    ))
                })?;
            let tmp = home.path().join("tmp");
            std::fs::create_dir_all(&tmp)
                .map_err(|e| internal(format!("creating the worker tmp dir: {e}")))?;
            let mut args: Vec<OsString> = Vec::new();
            if opts.test_hooks {
                args.push(TEST_HOOKS_ARG.into());
            }
            if opts.core_dumps {
                args.push(CORE_DUMPS_ARG.into());
            }
            let spec = SpawnSpec {
                program: program.clone(),
                args,
                env: vec![
                    ("HOME".into(), home.path().into()),
                    ("TMPDIR".into(), tmp.into()),
                    ("LANG".into(), "C.UTF-8".into()),
                ],
                cwd: home.path().to_path_buf(),
                read_only: vec![program, spec_root, binary],
                // the memory figures let the sessions of a first open wait for each other when
                // little is free
                optional_read_only: vec!["/etc/ld.so.cache".into(), "/proc/meminfo".into()],
                proc_self_read: false,
                // besides its home, the worker may write the engine directory and nothing else
                read_write: std::iter::once(home.path().to_path_buf())
                    .chain(state_dir)
                    .collect(),
                options: opts.confinement.clone(),
            };
            let log = LogSink::default();
            let (sandbox, channel) = Sandbox::spawn(spec, &log).map_err(ProtoError::from)?;
            Ok::<_, ProtoError>((sandbox, home, log, channel))
        })
        .await
        .map_err(|e| internal(format!("worker launch task failed: {e}")))??;
        channel
            .set_nonblocking(true)
            .map_err(|e| internal(format!("configuring the worker channel: {e}")))?;
        let stream = tokio::net::UnixStream::from_std(channel)
            .map_err(|e| internal(format!("registering the worker channel: {e}")))?;
        let (reader, writer) = stream.into_split();
        let client = RpcClient::new(reader, writer);
        *lock(&self.report) = Some(sandbox.report().clone());
        self.pid.store(u64::from(sandbox.pid()), Ordering::SeqCst);
        let live = Live {
            client,
            sandbox,
            log,
            killed: AtomicBool::new(false),
            _home: home,
        };
        if let Err(e) = live.client.wait_ready(READY_TIMEOUT).await {
            live.kill();
            let tail = live.log.tail(LOG_TAIL);
            return Err(ProtoError::new(
                ErrorCode::Internal,
                format!("the native worker did not start: {}", e.message),
            )
            .with_details(json!({ "worker": "start_failed", "log_tail": tail })));
        }
        Ok(live)
    }

    /// Runs one request on the current worker (restarting it first when needed).
    pub(crate) async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        limits: Limits<'_>,
        cancel: &CancellationToken,
    ) -> Result<T, ProtoError> {
        let live = self.ensure(cancel).await?;
        let v = self.exec(&live, method, params, limits, cancel).await?;
        decode(method, v)
    }

    /// Runs an analysis job in the worker, forwarding its progress. The hard deadline applies
    /// to the gap between two progress events, so every function of the expensive stage gets
    /// the full deadline.
    pub(crate) async fn analyze(
        &self,
        req: kraken_engine::AnalyzeRequest,
        tx: ProgressSender,
        cancel: CancellationToken,
    ) -> Result<AnalysisSummary, ProtoError> {
        let live = self.ensure(&cancel).await?;
        let job_id = format!(
            "native-{}",
            self.next_op.fetch_add(1, Ordering::Relaxed) + 1
        );
        let mut sub = live.client.subscribe_progress(&job_id);
        let limits = Limits {
            deadline: self
                .decompile_limits()
                .deadline
                .max(self.opts.request_timeout),
            progress: Some((&mut sub, Forward::Job(&tx))),
        };
        let v = self
            .exec(
                &live,
                "analyze",
                json!({ "job_id": job_id, "req": req }),
                limits,
                &cancel,
            )
            .await?;
        while let Ok(p) = sub.events.try_recv() {
            forward(&tx, p);
        }
        decode("analyze", v)
    }

    /// Defines a type in the worker and records it for replay after a restart.
    pub(crate) async fn define_type(
        &self,
        def: TypeDef,
        cancel: &CancellationToken,
    ) -> Result<(), ProtoError> {
        let _gate = self.edit_gate.lock().await;
        self.call::<()>(
            "define_type",
            json!({ "def": &def }),
            self.request_limits(),
            cancel,
        )
        .await?;
        lock(&self.journal).push(Journaled::TypeDef(def));
        Ok(())
    }

    /// Applies an edit-log operation in the worker and records it for replay after a restart.
    pub(crate) async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), ProtoError> {
        let _gate = self.edit_gate.lock().await;
        self.call::<()>(
            "apply",
            json!({ "log_op": op }),
            self.request_limits(),
            cancel,
        )
        .await?;
        lock(&self.journal).push(Journaled::Op(op.clone()));
        Ok(())
    }

    /// Saves the worker's journal to the state directory (when there is one).
    pub(crate) async fn save(&self, cancel: &CancellationToken) -> Result<Watermark, ProtoError> {
        let _gate = self.edit_gate.lock().await;
        self.call("save", json!({}), self.request_limits(), cancel)
            .await
    }

    /// Sends one request to `live` under the watchdog.
    async fn exec(
        &self,
        live: &Live,
        method: &str,
        mut params: Value,
        limits: Limits<'_>,
        cancel: &CancellationToken,
    ) -> Result<Value, ProtoError> {
        if cancel.is_cancelled() {
            return Err(cancelled());
        }
        let op = self.next_op.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(obj) = params.as_object_mut() {
            obj.insert("op".into(), json!(op));
        }
        let Limits { deadline, progress } = limits;
        let (mut sub, to) = match progress {
            Some((sub, to)) => (Some(sub), to),
            None => (None, Forward::Drop),
        };
        let call = live.client.call(method, params, None, None);
        tokio::pin!(call);
        let sleep = tokio::time::sleep(deadline);
        tokio::pin!(sleep);
        let reply = loop {
            let next_event = async {
                match sub.as_mut() {
                    Some(sub) => sub.events.recv().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                r = &mut call => break r,
                Some(p) = next_event => {
                    match to {
                        Forward::Drop => {}
                        Forward::Job(tx) => forward(tx, p),
                        Forward::Open(r) => {
                            if let Some(u) = p.detail.and_then(|d| serde_json::from_value(d).ok()) {
                                r(u);
                            }
                        }
                    }
                    sleep.as_mut().reset(tokio::time::Instant::now() + deadline);
                }
                () = &mut sleep => {
                    live.kill();
                    return Err(ProtoError::new(
                        ErrorCode::Timeout,
                        format!(
                            "native worker: `{method}` ran past its hard deadline of {deadline:?}; \
                             the worker was killed and restarts on the next request"
                        ),
                    )
                    .with_details(json!({
                        "worker": "killed",
                        "method": method,
                        "deadline_ms": duration_ms(deadline),
                    })));
                }
                () = cancel.cancelled() => {
                    let grace = self.opts.cancel_grace;
                    let _ = live
                        .client
                        .call("cancel", json!({ "target": op }), Some(grace), None)
                        .await;
                    if tokio::time::timeout(grace, &mut call).await.is_err() {
                        live.kill();
                        return Err(ProtoError::new(
                            ErrorCode::Cancelled,
                            format!(
                                "`{method}` cancelled; it did not stop within {grace:?}, so the \
                                 worker was killed and restarts on the next request"
                            ),
                        )
                        .with_details(json!({ "worker": "killed", "method": method })));
                    }
                    return Err(cancelled());
                }
            }
        };
        match reply {
            Err(e) if e.code == ErrorCode::Internal && e.message == SIDECAR_EXITED => {
                Err(self.exited(live, method).await)
            }
            r => r,
        }
    }

    /// The error for a request whose worker went away.
    async fn exited(&self, live: &Live, method: &str) -> ProtoError {
        if live.killed.load(Ordering::SeqCst) {
            return ProtoError::new(
                ErrorCode::Internal,
                format!(
                    "native worker: `{method}` was lost when the watchdog killed the worker; it \
                     restarts on the next request"
                ),
            )
            .with_details(json!({ "worker": "killed", "method": method }));
        }
        let mut exit = live.sandbox.exit_watch();
        let status = tokio::time::timeout(EXIT_WAIT, exit.wait_for(Option::is_some))
            .await
            .ok()
            .and_then(Result::ok)
            .and_then(|s| *s);
        // a worker that is still around without a channel is useless
        live.sandbox.kill();
        let how = match status {
            Some(s) => match (s.code, s.signal) {
                (_, Some(sig)) => format!("killed by signal {sig}"),
                (Some(code), None) => format!("exit code {code}"),
                (None, None) => "unknown status".to_string(),
            },
            None => "no exit status".to_string(),
        };
        ProtoError::new(
            ErrorCode::Internal,
            format!(
                "native worker crashed during `{method}` ({how}); it restarts on the next request"
            ),
        )
        .with_details(json!({
            "worker": "crashed",
            "method": method,
            "exit_code": status.and_then(|s| s.code),
            "signal": status.and_then(|s| s.signal),
            "log_tail": live.log.tail(LOG_TAIL),
        }))
    }
}

fn forward(tx: &ProgressSender, p: WireProgress) {
    let Ok(stage) = serde_json::from_value::<Stage>(json!(p.stage)) else {
        return;
    };
    tx.send(Progress {
        stage,
        done: p.done,
        total: p.total,
        message: p.message,
    });
}

fn decode<T: DeserializeOwned>(method: &str, v: Value) -> Result<T, ProtoError> {
    serde_json::from_value(v).map_err(|e| {
        internal(format!(
            "malformed `{method}` result from the native worker: {e}"
        ))
    })
}

fn internal(m: String) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, m)
}

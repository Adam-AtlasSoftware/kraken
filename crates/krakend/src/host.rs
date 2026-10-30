//! Project sessions owned by the daemon.
//!
//! One [`Session`] per canonical project directory, opened on demand, closed after its own idle
//! time, at most `max_sessions` at once (the least recently used idle one is evicted for a new
//! one). Each session has a single ordered write queue (decision 34): mutations and job starts
//! take it in arrival order, queries do not. A maintenance tick turns job progress into events,
//! counts running jobs for the idle monitor and sweeps idle sessions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kraken_engine::CancellationToken;
use kraken_host::daemon::event_kind;
use kraken_host::{EngineEvent, FactoryEvent, ManagedFactory};
use kraken_ipc::Clock;
use kraken_proto::{ErrorCode, OpenProgress, OpenStage, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{
    CallContext, JobProgress, JobStatus, OpenOptions, OpenProgressSink, Registry, Session,
    SessionConfig, Surface,
};
use serde_json::{Value, json};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::events::EventHub;

/// Largest job result copied into a `job_done` event.
const MAX_EVENT_RESULT_BYTES: usize = 4096;
/// Least time between two `open_progress` events of one open in the same stage.
const OPEN_EVENT_INTERVAL: Duration = Duration::from_millis(500);
/// How long closing a session may spend saving its engine.
const CLOSE_SAVE_TIMEOUT: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Keeps the `open_progress` events of one open to a few per second.
struct OpenThrottle {
    hub: EventHub,
    key: PathBuf,
    state: Mutex<ThrottleState>,
}

#[derive(Default)]
struct ThrottleState {
    last: Option<(OpenStage, std::time::Instant)>,
    pending: Option<OpenProgress>,
}

impl OpenThrottle {
    fn publish(&self, p: &OpenProgress) {
        let mut fields = serde_json::to_value(p).unwrap_or(Value::Null);
        if let Some(m) = fields.get_mut("message") {
            *m = json!(kraken_proto::sanitize(m.as_str().unwrap_or_default()));
        }
        self.hub
            .publish(&self.key, event_kind::OPEN_PROGRESS, fields);
    }
}

/// Tunables of the session host.
#[derive(Debug, Clone)]
pub struct HostConfig {
    /// Configuration handed to every new [`Session`].
    pub session_config: SessionConfig,
    /// Idle time after which a session without work is closed.
    pub session_idle: Duration,
    /// Most sessions open at once.
    pub max_sessions: usize,
    /// The rewrite pipeline attached to every new [`Session`], if any.
    pub rewrite: Option<Arc<dyn RewriteBackend>>,
    /// What `local_model_setup` downloads and configures with, if any.
    pub local_models: Option<Arc<dyn kraken_registry::commands::LocalModelBackend>>,
    /// The integrations catalogue (emulators and tools), if any.
    pub integrations: Option<Arc<dyn kraken_registry::commands::IntegrationsBackend>>,
    /// What `setup_status` probes and the `setup_*` jobs install, if any.
    pub setup: Option<Arc<dyn kraken_registry::commands::SetupBackend>>,
    /// The assistant behind the `assist_*` jobs, if any.
    pub assist: Option<Arc<dyn kraken_registry::commands::AssistJobs>>,
    /// The configuration file behind `config_get` and `config_set`, if any.
    pub config_store: Option<Arc<dyn kraken_registry::commands::ConfigStore>>,
}

impl Default for HostConfig {
    fn default() -> Self {
        HostConfig {
            session_config: SessionConfig::default(),
            session_idle: Duration::from_secs(1800),
            max_sessions: 4,
            rewrite: None,
            local_models: None,
            integrations: None,
            setup: None,
            assist: None,
            config_store: None,
        }
    }
}

struct SeenJob {
    progress: Option<JobProgress>,
    done: bool,
}

/// One open (or opening) project.
pub struct SessionEntry {
    key: PathBuf,
    dir: PathBuf,
    session: Arc<Session>,
    queue: Arc<AsyncMutex<()>>,
    opening: AsyncMutex<()>,
    inflight: AtomicUsize,
    last_active: Mutex<Duration>,
    jobs_seen: Mutex<HashMap<String, SeenJob>>,
    /// The AI board version last published, and what each piece of work looked like then.
    ai_seen: Mutex<(u64, HashMap<String, kraken_proto::AiJobView>)>,
}

impl SessionEntry {
    /// The session.
    pub fn session(&self) -> &Arc<Session> {
        &self.session
    }

    /// The directory the project was opened with.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The canonical project directory (symlinks resolved): what events are published under, so
    /// every client compares against the same form whatever path it used to open the project.
    pub fn key(&self) -> &Path {
        &self.key
    }

    /// Takes the write queue; the guard can move into a task that outlives the caller.
    pub async fn lock_queue(&self) -> OwnedMutexGuard<()> {
        self.queue.clone().lock_owned().await
    }

    fn running_jobs(&self) -> usize {
        self.session
            .jobs()
            .list()
            .iter()
            .filter(|j| j.status == JobStatus::Running)
            .count()
    }
}

/// A claim on a session for the duration of one call: it cannot be evicted or swept meanwhile.
pub struct Lease {
    entry: Arc<SessionEntry>,
    clock: Arc<dyn Clock>,
}

impl Lease {
    /// The leased session entry.
    pub fn entry(&self) -> &Arc<SessionEntry> {
        &self.entry
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        *lock(&self.entry.last_active) = self.clock.now();
        self.entry.inflight.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Inner {
    factory: Arc<dyn ManagedFactory>,
    registry: Arc<Registry>,
    cfg: HostConfig,
    clock: Arc<dyn Clock>,
    hub: EventHub,
    sessions: Mutex<HashMap<PathBuf, Arc<SessionEntry>>>,
    stopping: AtomicBool,
}

/// The daemon's sessions. Cheap to clone.
#[derive(Clone)]
pub struct SessionHost {
    inner: Arc<Inner>,
}

fn proto(code: ErrorCode, msg: impl Into<String>) -> ProtoError {
    ProtoError::new(code, msg)
}

/// The key sessions are stored under: the path with symlinks resolved as far as it exists.
pub fn canonical_key(path: &Path) -> Result<PathBuf, ProtoError> {
    use std::path::Component;
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(proto(
            ErrorCode::InvalidArgument,
            format!(
                "project_dir {} must not contain . or .. elements",
                path.display()
            ),
        ));
    }
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&existing) {
            Ok(mut c) => {
                for part in tail.iter().rev() {
                    c.push(part);
                }
                return Ok(c);
            }
            Err(_) => {
                let Some(name) = existing.file_name().map(|n| n.to_os_string()) else {
                    return Ok(path.to_path_buf());
                };
                tail.push(name);
                if !existing.pop() {
                    return Ok(path.to_path_buf());
                }
            }
        }
    }
}

impl SessionHost {
    /// A host without sessions.
    pub fn new(
        factory: Arc<dyn ManagedFactory>,
        registry: Arc<Registry>,
        cfg: HostConfig,
        clock: Arc<dyn Clock>,
        hub: EventHub,
    ) -> Self {
        SessionHost {
            inner: Arc::new(Inner {
                factory,
                registry,
                cfg,
                clock,
                hub,
                sessions: Mutex::new(HashMap::new()),
                stopping: AtomicBool::new(false),
            }),
        }
    }

    /// The event hub.
    pub fn hub(&self) -> &EventHub {
        &self.inner.hub
    }

    /// The engine factory.
    pub fn factory(&self) -> &Arc<dyn ManagedFactory> {
        &self.inner.factory
    }

    /// The configuration.
    pub fn config(&self) -> &HostConfig {
        &self.inner.cfg
    }

    /// Number of sessions in the table (open or opening).
    pub fn session_count(&self) -> usize {
        lock(&self.inner.sessions).len()
    }

    fn new_entry(&self, key: &Path, dir: &Path) -> Arc<SessionEntry> {
        let mut session = Session::new(self.inner.factory.clone())
            .with_config(self.inner.cfg.session_config.clone());
        if let Some(rewrite) = &self.inner.cfg.rewrite {
            session = session.with_rewrite(rewrite.clone());
        }
        if let Some(a) = &self.inner.cfg.assist {
            session = session.with_assist(a.clone());
        }
        if let Some(i) = &self.inner.cfg.integrations {
            session = session.with_integrations(i.clone());
        }
        if let Some(lm) = &self.inner.cfg.local_models {
            session = session.with_local_models(lm.clone());
        }
        Arc::new(SessionEntry {
            key: key.to_path_buf(),
            dir: dir.to_path_buf(),
            session: Arc::new(session),
            queue: Arc::new(AsyncMutex::new(())),
            opening: AsyncMutex::new(()),
            inflight: AtomicUsize::new(0),
            last_active: Mutex::new(self.inner.clock.now()),
            jobs_seen: Mutex::new(HashMap::new()),
            ai_seen: Mutex::new((0, HashMap::new())),
        })
    }

    /// Claims the session for `key`, creating it (and evicting the least recently used idle
    /// session when the limit is reached). `dir` is the path to open the project with.
    pub async fn acquire(&self, key: &Path, dir: &Path) -> Result<Lease, ProtoError> {
        if self.inner.stopping.load(Ordering::SeqCst) {
            return Err(proto(ErrorCode::Unsupported, "the daemon is shutting down"));
        }
        let (entry, victim) = {
            let mut map = lock(&self.inner.sessions);
            if let Some(e) = map.get(key) {
                e.inflight.fetch_add(1, Ordering::SeqCst);
                (e.clone(), None)
            } else {
                let mut victim = None;
                if map.len() >= self.inner.cfg.max_sessions {
                    let lru = map
                        .iter()
                        .filter(|(_, e)| {
                            e.inflight.load(Ordering::SeqCst) == 0 && e.running_jobs() == 0
                        })
                        .min_by_key(|(_, e)| *lock(&e.last_active))
                        .map(|(k, _)| k.clone());
                    match lru {
                        Some(k) => victim = map.remove(&k),
                        None => {
                            return Err(proto(
                                ErrorCode::Unsupported,
                                format!(
                                    "too many open projects (limit {}) and none is idle; wait \
                                     for a running job to finish or raise daemon.max_sessions",
                                    self.inner.cfg.max_sessions
                                ),
                            ));
                        }
                    }
                }
                let e = self.new_entry(key, dir);
                e.inflight.fetch_add(1, Ordering::SeqCst);
                map.insert(key.to_path_buf(), e.clone());
                (e, victim)
            }
        };
        if let Some(v) = victim {
            self.close_entry(&v, "evicted").await;
        }
        Ok(Lease {
            entry,
            clock: self.inner.clock.clone(),
        })
    }

    /// Publishes the progress of an open of the project `key` as `open_progress` events: every
    /// change of stage, else at most one per [`OPEN_EVENT_INTERVAL`].
    pub fn open_sink(&self, key: &Path) -> OpenProgressSink {
        let throttle = Arc::new(OpenThrottle {
            hub: self.inner.hub.clone(),
            key: key.to_path_buf(),
            state: Mutex::default(),
        });
        let handle = tokio::runtime::Handle::try_current().ok();
        Arc::new(move |p: &OpenProgress| {
            let flush_in = {
                let mut st = lock(&throttle.state);
                let due = match st.last {
                    Some((stage, at)) => stage != p.stage || at.elapsed() >= OPEN_EVENT_INTERVAL,
                    None => true,
                };
                if due {
                    st.last = Some((p.stage, std::time::Instant::now()));
                    st.pending = None;
                    None
                } else {
                    // held back, and sent when the interval is over unless a newer one comes:
                    // the last report before a long quiet step is never lost
                    let first = st.pending.is_none();
                    st.pending = Some(p.clone());
                    let wait = st.last.map_or(Duration::ZERO, |(_, at)| {
                        OPEN_EVENT_INTERVAL.saturating_sub(at.elapsed())
                    });
                    first.then_some(wait)
                }
            };
            match flush_in {
                None => throttle.publish(p),
                Some(wait) => {
                    if let Some(h) = &handle {
                        let t = throttle.clone();
                        h.spawn(async move {
                            tokio::time::sleep(wait).await;
                            let held = {
                                let mut st = lock(&t.state);
                                let held = st.pending.take();
                                if let Some(p) = &held {
                                    st.last = Some((p.stage, std::time::Instant::now()));
                                }
                                held
                            };
                            if let Some(p) = held {
                                t.publish(&p);
                            }
                        });
                    }
                }
            }
        })
    }

    /// Announces that the session of `lease` now has a project.
    pub fn note_opened(&self, lease: &Lease) {
        self.inner
            .hub
            .publish(&lease.entry.key, event_kind::SESSION_OPENED, json!({}));
    }

    /// Opens the project of `lease` if the session has none yet. Returns notices for the
    /// caller (a stale engine cache).
    pub async fn ensure_open(&self, lease: &Lease) -> Result<Vec<String>, ProtoError> {
        let e = &lease.entry;
        if e.session.project().is_ok() {
            return Ok(Vec::new());
        }
        let _opening = e.opening.lock().await;
        if e.session.project().is_ok() {
            return Ok(Vec::new());
        }
        let opts = OpenOptions {
            sink: Some(self.open_sink(&e.key)),
            ..OpenOptions::default()
        };
        let project = e.session.open_project_opts(&e.dir, opts).await?;
        self.note_opened(lease);
        let mut warnings = Vec::new();
        if !project.epoch_mismatch().is_empty() {
            warnings.push(format!(
                "the engine cache is stale ({}); run `kraken rebuild`",
                project.epoch_mismatch().join(", ")
            ));
        }
        if let Some(r) = project.resync_report() {
            tracing::warn!(project = %e.dir.display(), "{}", r.message());
            warnings.push(r.message());
        }
        Ok(warnings)
    }

    /// Drops a session that never got a project (a failed `project_create`).
    pub fn discard_if_unopened(&self, lease: &Lease) -> bool {
        let e = &lease.entry;
        let mut map = lock(&self.inner.sessions);
        if e.session.project().is_err()
            && e.inflight.load(Ordering::SeqCst) == 1
            && map.get(&e.key).is_some_and(|m| Arc::ptr_eq(m, e))
        {
            map.remove(&e.key);
            return true;
        }
        false
    }

    /// [`discard_if_unopened`](Self::discard_if_unopened), and stops the sidecars a failed or
    /// cancelled open started, so nothing of it keeps running.
    pub async fn discard_unopened(&self, lease: &Lease) {
        if self.discard_if_unopened(lease) {
            let e = &lease.entry;
            self.inner.factory.shutdown_under(&e.dir).await;
            if e.key != e.dir {
                self.inner.factory.shutdown_under(&e.key).await;
            }
        }
    }

    /// Cancels the session's jobs, saves its engine, stops its sidecars and announces the close.
    async fn close_entry(&self, entry: &Arc<SessionEntry>, reason: &str) {
        entry.session.jobs().cancel_all();
        if let Ok(project) = entry.session.project() {
            let _ =
                tokio::time::timeout(CLOSE_SAVE_TIMEOUT, project.save(&CancellationToken::new()))
                    .await;
        }
        self.inner.factory.shutdown_under(&entry.dir).await;
        if entry.key != entry.dir {
            self.inner.factory.shutdown_under(&entry.key).await;
        }
        self.inner.hub.publish(
            &entry.key,
            event_kind::SESSION_CLOSED,
            json!({ "reason": reason }),
        );
        tracing::info!(project = %entry.dir.display(), reason, "closed session");
    }

    /// Closes the session of `key` at a client's request (`project_close`): its jobs are
    /// cancelled, the engine saved and its sidecars stopped. Returns false when no session was
    /// open for it.
    pub async fn close_project(&self, key: &Path) -> bool {
        let entry = lock(&self.inner.sessions).remove(key);
        match entry {
            Some(e) => {
                self.close_entry(&e, "closed").await;
                true
            }
            None => false,
        }
    }

    /// True when the session of `key` has a project attached.
    pub fn has_project(&self, key: &Path) -> bool {
        lock(&self.inner.sessions)
            .get(key)
            .is_some_and(|e| e.session.project().is_ok())
    }

    /// Stops accepting calls and closes every session and sidecar.
    pub async fn close_all(&self) {
        self.inner.stopping.store(true, Ordering::SeqCst);
        let all: Vec<_> = lock(&self.inner.sessions).drain().map(|(_, e)| e).collect();
        for e in &all {
            self.close_entry(e, "shutdown").await;
        }
        self.inner.factory.shutdown().await;
    }

    /// True once `close_all` ran.
    pub fn is_stopping(&self) -> bool {
        self.inner.stopping.load(Ordering::SeqCst)
    }

    fn entries(&self) -> Vec<Arc<SessionEntry>> {
        lock(&self.inner.sessions).values().cloned().collect()
    }

    /// Publishes events for new job progress and finished jobs of `entry`; returns how many of
    /// its jobs still run.
    fn watch_jobs(&self, entry: &Arc<SessionEntry>) -> usize {
        let snaps = entry.session.jobs().list();
        let mut seen = lock(&entry.jobs_seen);
        let mut running = 0;
        let mut finished_ok: Vec<String> = Vec::new();
        for s in &snaps {
            let st = seen.entry(s.id.0.clone()).or_insert(SeenJob {
                progress: None,
                done: false,
            });
            // an open reports through `open_progress` events as it goes
            if s.progress != st.progress && s.open.is_none() {
                if let Some(p) = &s.progress {
                    self.inner.hub.publish(
                        &entry.key,
                        event_kind::JOB_PROGRESS,
                        json!({
                            "job_id": s.id.0,
                            "command": s.command,
                            "phase": p.phase,
                            "done": p.done,
                            "total": p.total,
                            "message": kraken_proto::sanitize(&p.message),
                        }),
                    );
                }
                st.progress = s.progress.clone();
            }
            if s.status.is_terminal() {
                if !st.done {
                    st.done = true;
                    let mut ev = json!({
                        "job_id": s.id.0,
                        "command": s.command,
                        "status": s.status,
                    });
                    if let Some(e) = &s.error {
                        ev["error"] = json!({"code": e.code.as_str(), "message": kraken_proto::sanitize(&e.message)});
                    }
                    if let Some(r) = &s.result
                        && r.to_string().len() <= MAX_EVENT_RESULT_BYTES
                    {
                        ev["result"] = r.clone();
                    }
                    self.inner.hub.publish(&entry.key, event_kind::JOB_DONE, ev);
                    if s.status == JobStatus::Succeeded {
                        finished_ok.push(s.command.clone());
                    }
                }
            } else {
                running += 1;
            }
        }
        let live: std::collections::HashSet<&str> = snaps.iter().map(|s| s.id.0.as_str()).collect();
        seen.retain(|k, _| live.contains(k.as_str()));
        drop(seen);
        if finished_ok.iter().any(|c| c == "analyze" || c == "rebuild") {
            self.save_in_background(entry);
        }
        running
    }

    /// Publishes `ai_started`, `ai_progress` and `ai_done` events for what changed on the
    /// session's AI board since the last pass.
    fn watch_ai(&self, entry: &Arc<SessionEntry>) {
        let board = entry.session.ai();
        let version = board.version();
        let mut seen = lock(&entry.ai_seen);
        if seen.0 == version {
            return;
        }
        seen.0 = version;
        for job in board.list() {
            let before = seen.1.get(&job.id);
            if before == Some(&job) {
                continue;
            }
            let kind = match before {
                None if !job.status.is_terminal() => event_kind::AI_STARTED,
                Some(b) if b.status.is_terminal() => continue,
                _ if job.status.is_terminal() => event_kind::AI_DONE,
                _ => event_kind::AI_PROGRESS,
            };
            if let Ok(v) = serde_json::to_value(&job) {
                self.inner.hub.publish(&entry.key, kind, json!({ "ai": v }));
            }
            seen.1.insert(job.id.clone(), job);
        }
        let live: std::collections::HashSet<String> =
            board.list().into_iter().map(|j| j.id).collect();
        seen.1.retain(|k, _| live.contains(k));
    }

    /// Saves the engine behind the write queue, off the caller's path.
    fn save_in_background(&self, entry: &Arc<SessionEntry>) {
        let entry = entry.clone();
        tokio::spawn(async move {
            let _q = entry.lock_queue().await;
            if let Ok(project) = entry.session.project()
                && let Err(e) = project.save(&CancellationToken::new()).await
            {
                tracing::warn!(error = %e.message, "saving after a finished job failed");
            }
        });
    }

    /// One maintenance pass: job events, idle sweep. Returns the number of running jobs across
    /// all sessions (the idle monitor's job count).
    pub async fn maintain(&self) -> usize {
        let mut running = 0;
        let now = self.inner.clock.now();
        for e in self.entries() {
            let r = self.watch_jobs(&e);
            self.watch_ai(&e);
            running += r;
            let idle_for = now.saturating_sub(*lock(&e.last_active));
            if r == 0
                && e.inflight.load(Ordering::SeqCst) == 0
                && idle_for >= self.inner.cfg.session_idle
            {
                let removed = {
                    let mut map = lock(&self.inner.sessions);
                    // Re-check under the table lock: a call may have claimed it meanwhile.
                    if e.inflight.load(Ordering::SeqCst) == 0
                        && map.get(&e.key).is_some_and(|m| Arc::ptr_eq(m, &e))
                    {
                        map.remove(&e.key);
                        true
                    } else {
                        false
                    }
                };
                if removed {
                    self.close_entry(&e, "idle").await;
                }
            }
        }
        running
    }

    fn find_by_engine_dir(&self, engine_dir: &Path) -> Option<Arc<SessionEntry>> {
        lock(&self.inner.sessions)
            .values()
            .find(|e| engine_dir.starts_with(&e.dir) || engine_dir.starts_with(&e.key))
            .cloned()
    }

    /// Reacts to a sidecar lifecycle event: announce a death and bring the sidecar back; after
    /// a restart replay the pending log entries and announce it (decision 40).
    pub async fn on_engine_event(&self, ev: FactoryEvent) {
        if self.is_stopping() {
            return;
        }
        let Some(entry) = self.find_by_engine_dir(&ev.engine_dir) else {
            return;
        };
        let current = entry
            .session
            .project()
            .map(|p| p.dir().join(p.meta().engine_dir) == ev.engine_dir)
            .unwrap_or(false);
        match ev.event {
            EngineEvent::Started => {}
            EngineEvent::Exited { code } => {
                self.inner.hub.publish(
                    &entry.key,
                    event_kind::SIDECAR_EXITED,
                    json!({ "code": code, "engine_dir": ev.engine_dir }),
                );
                if current && let Err(e) = self.inner.factory.restart_engine(&ev.engine_dir).await {
                    tracing::warn!(error = %e.message, "sidecar restart failed");
                    self.inner.hub.publish(
                        &entry.key,
                        event_kind::SIDECAR_EXITED,
                        json!({
                            "engine_dir": ev.engine_dir,
                            "restart_failed": {"code": e.code.as_str(), "message": kraken_proto::sanitize(&e.message)},
                        }),
                    );
                }
            }
            EngineEvent::Restarted => {
                if !current {
                    return;
                }
                let _q = entry.lock_queue().await;
                let outcome = match entry.session.project() {
                    Ok(p) => p.replay_pending(&CancellationToken::new()).await,
                    Err(e) => Err(e),
                };
                let ev_fields = match outcome {
                    Ok(r) => json!({
                        "engine_dir": ev.engine_dir,
                        "replayed": r.pushed,
                        "rejected": r.rejected,
                        "deferred_until_analysis_ends": r.skipped_analysis_running,
                    }),
                    Err(e) => json!({
                        "engine_dir": ev.engine_dir,
                        "replayed": 0,
                        "error": {"code": e.code.as_str(), "message": kraken_proto::sanitize(&e.message)},
                    }),
                };
                self.inner
                    .hub
                    .publish(&entry.key, event_kind::SIDECAR_RESTARTED, ev_fields);
            }
        }
    }

    /// Per-session status for the `status` method.
    pub async fn session_status(&self) -> Vec<Value> {
        let now = self.inner.clock.now();
        let mut out = Vec::new();
        for e in self.entries() {
            let mut v = json!({
                "project_dir": e.dir,
                "opened": e.session.project().is_ok(),
                "idle_secs": now.saturating_sub(*lock(&e.last_active)).as_secs(),
                "inflight_calls": e.inflight.load(Ordering::SeqCst),
                "running_jobs": e.running_jobs(),
            });
            if e.session.project().is_ok() {
                let ctx = CallContext::user("krakend", Surface::Gui);
                let info = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.inner
                        .registry
                        .call_json("project_info", &e.session, &ctx, Value::Null),
                )
                .await;
                if let Ok(Ok(info)) = info {
                    for k in [
                        "binary_path",
                        "engine_build",
                        "analysis",
                        "pending_entries",
                        "log_entries",
                        "open_proposals",
                        "epoch_stale",
                    ] {
                        if let Some(x) = info.get(k) {
                            v[k] = x.clone();
                        }
                    }
                }
            }
            out.push(v);
        }
        out.sort_by(|a, b| {
            a["project_dir"]
                .to_string()
                .cmp(&b["project_dir"].to_string())
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_key_resolves_the_existing_prefix_and_keeps_the_rest() {
        let t = tempfile::tempdir().unwrap();
        let real = std::fs::canonicalize(t.path()).unwrap();
        let k = canonical_key(&t.path().join("new/proj")).unwrap();
        assert_eq!(k, real.join("new/proj"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, t.path().join("link")).unwrap();
            let via_link = canonical_key(&t.path().join("link/new/proj")).unwrap();
            assert_eq!(via_link, k, "a symlinked path maps to the same session");
        }
    }

    #[test]
    fn dot_elements_are_refused() {
        let e = canonical_key(Path::new("/tmp/a/../b")).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }
}

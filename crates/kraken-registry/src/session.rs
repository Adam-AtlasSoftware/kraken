//! Sessions and projects.
//!
//! A project directory holds `project.kraken.sqlite` (the `kraken-model` database, the source of
//! truth for annotations), `ghidra/` (the engine's private project directory, a rebuildable cache)
//! and `meta.json` (binary path and hash plus the cache epoch).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use async_trait::async_trait;
use kraken_engine::{CancellationToken, LoaderSpec, ProgramInfo, SharedEngine, unsupported};
use kraken_model::{EntryId, Store};
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commands::RewriteBackend;
use crate::jobs::{JobId, JobTable};

/// File name of the model database inside a project directory.
pub const DB_FILE: &str = "project.kraken.sqlite";
/// File name of the project metadata.
pub const META_FILE: &str = "meta.json";
/// Default name of the engine's directory inside a project directory.
pub const ENGINE_DIR: &str = "ghidra";
/// Identifies the loader and analysis options in the epoch hash; bump when they change.
const OPTIONS_DESCRIPTOR: &str = "loader=default;analysis=staged-v1";

/// Creates engines. The registry never depends on a concrete engine crate: the CLI passes a
/// factory building `GhidraEngine`, tests pass one building `FakeEngine`.
#[async_trait]
pub trait EngineFactory: Send + Sync {
    /// Creates an engine whose private state lives in `engine_dir` (created beforehand). An
    /// existing directory holds a warm cache from an earlier session.
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError>;

    /// Which engine kind should open `binary`. Factories with a single engine keep the default.
    /// Reads the file's headers, so call it off the async threads.
    fn detect_kind(&self, _binary: &Path) -> Result<EngineKind, ProtoError> {
        Ok(EngineKind::Ghidra)
    }

    /// Like [`create`](Self::create) for an engine of `kind`. A factory that builds one kind only
    /// ignores it.
    async fn create_kind(
        &self,
        _kind: EngineKind,
        engine_dir: &Path,
    ) -> Result<SharedEngine, ProtoError> {
        self.create(engine_dir).await
    }
}

/// The engine behind a project, recorded in `meta.json` so a project reopens with the engine
/// that created it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// The Ghidra sidecar: native code (PE, ELF, Mach-O and raw images).
    #[default]
    Ghidra,
    /// The .NET sidecar (ILSpy): managed assemblies.
    Dotnet,
}

impl EngineKind {
    /// The name used in `meta.json` and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            EngineKind::Ghidra => "ghidra",
            EngineKind::Dotnet => "dotnet",
        }
    }
}

/// Tunables of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfig {
    /// Agent edits auto-applied per run before further ones become proposals (decision 29).
    pub per_run_cap: u32,
    /// Largest page of functions returned by `list_functions`.
    pub list_page_cap: u32,
    /// Largest page returned by `history` and `proposals_list`.
    pub history_page_cap: u32,
    /// Engine pages `list_functions` may scan when `name_filter` matches nothing on a page.
    pub filter_scan_pages: u32,
    /// Longest `job_await` wait in milliseconds.
    pub max_await_ms: u64,
    /// Save the engine and move the push watermark after every successful push.
    pub save_after_push: bool,
    /// Most functions `rebuild` compares when reporting drift.
    pub drift_function_cap: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            per_run_cap: 200,
            list_page_cap: 200,
            history_page_cap: 100,
            filter_scan_pages: 10,
            max_await_ms: 600_000,
            save_after_push: true,
            drift_function_cap: 200_000,
        }
    }
}

/// What a cached engine project depends on (decision 56).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Epoch {
    /// Build identifier from the engine handshake (includes the Ghidra version).
    pub engine_build: String,
    /// Hash of the loader and analysis options.
    pub options_hash: String,
    /// SHA-256 of the binary file.
    pub binary_hash: String,
}

/// Contents of `meta.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    /// Format of this file; currently 1.
    pub format_version: u32,
    /// Absolute path of the analysed binary.
    pub binary_path: String,
    /// SHA-256 of the binary when the project was created.
    pub binary_sha256: String,
    /// Epoch of the engine cache.
    pub epoch: Epoch,
    /// Engine directory relative to the project directory.
    pub engine_dir: String,
    /// True once a full analysis finished on the current engine cache.
    pub analysis_complete: bool,
    /// Engine that opened the binary; projects written before engines were selectable are Ghidra.
    #[serde(default)]
    pub engine_kind: EngineKind,
}

/// Where analysis stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisPhase {
    /// No analysis has run on this engine cache.
    NotStarted,
    /// A job is analysing; writes are queued.
    Running,
    /// All stages finished.
    Complete,
    /// The last run failed.
    Failed,
    /// The last run was cancelled; partial results are kept.
    Cancelled,
}

#[derive(Debug, Clone)]
pub(crate) struct AnalysisState {
    pub phase: AnalysisPhase,
    pub job: Option<JobId>,
    pub function_count: Option<u64>,
    pub error: Option<String>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn internal(msg: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg.to_string())
}

/// Runs blocking work off the async threads.
pub(crate) async fn blocking<T, F>(f: F) -> Result<T, ProtoError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ProtoError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| internal(format!("blocking task failed: {e}")))?
}

fn io_err(what: &str, path: &Path, e: std::io::Error) -> ProtoError {
    let code = if e.kind() == std::io::ErrorKind::NotFound {
        ErrorCode::NotFound
    } else {
        ErrorCode::Internal
    };
    ProtoError::new(code, format!("{what} {}: {e}", path.display()))
}

fn hash_file(path: &Path) -> Result<String, ProtoError> {
    let mut f = std::fs::File::open(path).map_err(|e| io_err("cannot read", path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| io_err("cannot read", path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn options_hash() -> String {
    format!("{:x}", Sha256::digest(OPTIONS_DESCRIPTOR.as_bytes()))
}

/// Report of pushing pending log entries to the engine.
#[derive(Debug, Default)]
pub(crate) struct FlushReport {
    pub pushed: Vec<EntryId>,
    pub rejected: Vec<(EntryId, ProtoError)>,
    /// Set when the push stopped early because of cancellation; the rest stays pending.
    pub stopped: Option<ProtoError>,
}

/// Outcome of [`Project::replay_pending`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Entries pushed to the engine.
    pub pushed: u64,
    /// Entries the engine refused (now `engine_rejected`).
    pub rejected: u64,
    /// True when nothing was pushed because an analysis or rebuild is running; its end flushes.
    pub skipped_analysis_running: bool,
    /// True when the caller cancelled mid-push; the rest stays pending.
    pub stopped: bool,
}

/// An open project: engine, model database and analysis state.
pub struct Project {
    dir: PathBuf,
    config: SessionConfig,
    meta: Mutex<ProjectMeta>,
    program: Mutex<ProgramInfo>,
    engine: RwLock<SharedEngine>,
    model: Arc<Mutex<Store>>,
    pub(crate) write_lock: tokio::sync::Mutex<()>,
    analysis: Mutex<AnalysisState>,
    epoch_mismatch: Vec<String>,
    /// Auto-applied agent edits counted per quota key (see `CallContext::quota_key`).
    quota: Mutex<std::collections::HashMap<String, u64>>,
}

impl std::fmt::Debug for Project {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Project")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl Project {
    /// The project directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Edits auto-applied so far under quota `key`.
    pub(crate) fn quota_used(&self, key: &str) -> u64 {
        lock(&self.quota).get(key).copied().unwrap_or(0)
    }

    /// Counts one more auto-applied edit under quota `key`.
    pub(crate) fn quota_add(&self, key: &str) {
        *lock(&self.quota).entry(key.to_string()).or_insert(0) += 1;
    }

    /// A copy of the project metadata.
    pub fn meta(&self) -> ProjectMeta {
        lock(&self.meta).clone()
    }

    /// Facts about the loaded program.
    pub fn program(&self) -> ProgramInfo {
        lock(&self.program).clone()
    }

    /// The current engine. A rebuild swaps it, so do not cache the handle across calls.
    pub fn engine(&self) -> SharedEngine {
        self.engine
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_engine(&self, engine: SharedEngine, program: ProgramInfo) {
        *self.engine.write().unwrap_or_else(PoisonError::into_inner) = engine;
        *lock(&self.program) = program;
    }

    pub(crate) fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Names of the epoch fields that differ from the stored epoch (the engine cache is stale
    /// and a `rebuild` is advised); empty when the cache is current.
    pub fn epoch_mismatch(&self) -> &[String] {
        &self.epoch_mismatch
    }

    pub(crate) fn analysis(&self) -> AnalysisState {
        lock(&self.analysis).clone()
    }

    /// True while an analysis job runs.
    pub fn analysis_running(&self) -> bool {
        lock(&self.analysis).phase == AnalysisPhase::Running
    }

    /// Marks analysis running unless it already is; `Err` carries the running job when known.
    pub(crate) fn begin_analysis<F>(&self, spawn: F) -> Result<JobId, Option<JobId>>
    where
        F: FnOnce() -> JobId,
    {
        let mut a = lock(&self.analysis);
        if a.phase == AnalysisPhase::Running {
            return Err(a.job.clone());
        }
        a.phase = AnalysisPhase::Running;
        a.error = None;
        let id = spawn();
        a.job = Some(id.clone());
        Ok(id)
    }

    pub(crate) fn end_analysis(
        &self,
        phase: AnalysisPhase,
        count: Option<u64>,
        err: Option<String>,
    ) {
        let mut a = lock(&self.analysis);
        a.phase = phase;
        if count.is_some() {
            a.function_count = count;
        }
        a.error = err;
    }

    /// Runs `f` on the model database off the async threads.
    pub async fn with_store<T, F>(&self, f: F) -> Result<T, ProtoError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Store) -> Result<T, ProtoError> + Send + 'static,
    {
        let model = self.model.clone();
        blocking(move || {
            let mut guard = lock(&model);
            f(&mut guard)
        })
        .await
    }

    /// Writes `meta.json` atomically.
    pub(crate) async fn persist_meta(&self) -> Result<(), ProtoError> {
        let meta = self.meta();
        let dir = self.dir.clone();
        blocking(move || write_meta(&dir, &meta)).await
    }

    pub(crate) fn update_meta<F: FnOnce(&mut ProjectMeta)>(&self, f: F) {
        f(&mut lock(&self.meta));
    }

    /// Pushes every pending log entry to the engine in log order, marking each pushed or
    /// engine-rejected. Callers hold the write lock and ensure analysis is not running.
    pub(crate) async fn flush_pending(
        &self,
        cancel: &CancellationToken,
    ) -> Result<FlushReport, ProtoError> {
        let pending = self.with_store(|s| s.pending_entries()).await?;
        let mut report = FlushReport::default();
        if pending.is_empty() {
            return Ok(report);
        }
        let engine = self.engine();
        let mutator = engine.mutator().ok_or_else(|| unsupported("mutator"))?;
        for entry in pending {
            let id = entry.id;
            match mutator.apply(&entry.op, cancel).await {
                Ok(()) => {
                    self.with_store(move |s| s.mark_pushed(id)).await?;
                    report.pushed.push(id);
                }
                Err(rej) if rej.code == ErrorCode::Cancelled => {
                    report.stopped = Some(rej.into());
                    break;
                }
                Err(rej) => {
                    let reason = rej.reason.clone();
                    self.with_store(move |s| s.mark_engine_rejected(id, &reason))
                        .await?;
                    report.rejected.push((id, rej.into()));
                }
            }
        }
        if self.config.save_after_push
            && let Some(last) = report.pushed.last().copied()
        {
            self.checkpoint(last, cancel).await?;
        }
        Ok(report)
    }

    /// Pushes the log entries still pending to the (possibly just restarted) engine, in log
    /// order, under the project write lock. The daemon calls this when the sidecar came back
    /// (decision 40); pushes are idempotent. While an analysis or rebuild runs nothing is pushed:
    /// its end flushes the queue.
    pub async fn replay_pending(
        &self,
        cancel: &CancellationToken,
    ) -> Result<ReplayReport, ProtoError> {
        if self.analysis_running() {
            return Ok(ReplayReport {
                skipped_analysis_running: true,
                ..Default::default()
            });
        }
        let _guard = self.write_lock.lock().await;
        let r = self.flush_pending(cancel).await?;
        Ok(ReplayReport {
            pushed: r.pushed.len() as u64,
            rejected: r.rejected.len() as u64,
            skipped_analysis_running: false,
            stopped: r.stopped.is_some(),
        })
    }

    /// Saves the engine and records `last` as the push watermark saved with it.
    pub(crate) async fn checkpoint(
        &self,
        last: EntryId,
        cancel: &CancellationToken,
    ) -> Result<(), ProtoError> {
        let engine = self.engine();
        let mutator = engine.mutator().ok_or_else(|| unsupported("mutator"))?;
        let mark = mutator.save(cancel).await?;
        self.with_store(move |s| s.set_watermark(last, &mark.0))
            .await
    }
}

fn write_meta(dir: &Path, meta: &ProjectMeta) -> Result<(), ProtoError> {
    let mut json = serde_json::to_string_pretty(meta).map_err(internal)?;
    json.push('\n');
    let tmp = dir.join("meta.json.tmp");
    std::fs::write(&tmp, json).map_err(|e| io_err("cannot write", &tmp, e))?;
    let dest = dir.join(META_FILE);
    std::fs::rename(&tmp, &dest).map_err(|e| io_err("cannot write", &dest, e))
}

/// `engine_dir` of a project's metadata must stay inside the project directory: the metadata is
/// a file anyone with write access to the directory can craft.
fn check_engine_dir(engine_dir: &str) -> Result<(), ProtoError> {
    let p = Path::new(engine_dir);
    let escapes = engine_dir.is_empty()
        || p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)));
    if escapes {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "the project metadata names an engine directory outside the project",
        ));
    }
    Ok(())
}

/// The binary path recorded in the metadata of the project in `dir` (for the approval prompt of
/// `project_open`: the project decides which file the engine reads).
pub async fn peek_binary(dir: &Path) -> Result<String, ProtoError> {
    let dir = dir.to_path_buf();
    blocking(move || read_meta(&dir).map(|m| m.binary_path)).await
}

fn read_meta(dir: &Path) -> Result<ProjectMeta, ProtoError> {
    let path = dir.join(META_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| io_err("cannot read", &path, e))?;
    serde_json::from_str(&text).map_err(|e| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("{} is not valid project metadata: {e}", path.display()),
        )
    })
}

/// A session: the entry point of every surface. It holds the engine factory, the job table and,
/// once a project is created or opened, the current [`Project`].
///
/// Cloning gives another handle to the same session (same project slot and job table); jobs that
/// outlive the call that started them hold such a handle.
#[derive(Clone)]
pub struct Session {
    factory: Arc<dyn EngineFactory>,
    config: SessionConfig,
    jobs: JobTable,
    project: Arc<RwLock<Option<Arc<Project>>>>,
    rewrite: Option<Arc<dyn RewriteBackend>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// A session without a project; `project_create` / `project_open` attach one.
    pub fn new(factory: Arc<dyn EngineFactory>) -> Session {
        Session {
            factory,
            config: SessionConfig::default(),
            jobs: JobTable::new(),
            project: Arc::new(RwLock::new(None)),
            rewrite: None,
        }
    }

    /// Attaches the rewrite pipeline that the `rewrite_*` commands run on (kraken-rewrite).
    /// Without one those commands answer `unsupported`.
    pub fn with_rewrite(mut self, backend: Arc<dyn RewriteBackend>) -> Session {
        self.rewrite = Some(backend);
        self
    }

    /// The attached rewrite pipeline; `unsupported` when this build or surface has none.
    pub fn rewrite(&self) -> Result<&Arc<dyn RewriteBackend>, ProtoError> {
        self.rewrite.as_ref().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "the rewrite pipeline is not attached to this session; use the kraken CLI or \
                 krakend, which link it",
            )
        })
    }

    /// Replaces the configuration (before a project is attached).
    pub fn with_config(mut self, config: SessionConfig) -> Session {
        self.config = config;
        self
    }

    /// Opens the existing project in `dir`.
    pub async fn open(dir: &Path, factory: Arc<dyn EngineFactory>) -> Result<Session, ProtoError> {
        let s = Session::new(factory);
        s.open_project(dir).await?;
        Ok(s)
    }

    /// Creates a project in `dir` for `binary` and attaches it.
    pub async fn create(
        dir: &Path,
        binary: &Path,
        factory: Arc<dyn EngineFactory>,
    ) -> Result<Session, ProtoError> {
        let s = Session::new(factory);
        s.create_project(dir, binary).await?;
        Ok(s)
    }

    /// The session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// The job table.
    pub fn jobs(&self) -> &JobTable {
        &self.jobs
    }

    /// The engine factory.
    pub fn factory(&self) -> &Arc<dyn EngineFactory> {
        &self.factory
    }

    /// The current project; `not_found` when none is open.
    pub fn project(&self) -> Result<Arc<Project>, ProtoError> {
        self.project
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::NotFound,
                    "no project is open; run project_create or project_open first",
                )
            })
    }

    /// The current project's engine.
    pub fn engine(&self) -> Result<SharedEngine, ProtoError> {
        Ok(self.project()?.engine())
    }

    fn attach(&self, project: Arc<Project>) {
        self.jobs.cancel_all();
        *self.project.write().unwrap_or_else(PoisonError::into_inner) = Some(project);
    }

    /// Creates a project in `dir` for `binary`, replacing any open project.
    pub async fn create_project(
        &self,
        dir: &Path,
        binary: &Path,
    ) -> Result<Arc<Project>, ProtoError> {
        let dir = dir.to_path_buf();
        let binary_path = {
            let binary = binary.to_path_buf();
            blocking(move || {
                let p = std::fs::canonicalize(&binary)
                    .map_err(|e| io_err("cannot open binary", &binary, e))?;
                // A FIFO or device would block the hash or feed the engine endless data.
                crate::trust::ensure_regular_file(&p)?;
                Ok(p)
            })
            .await?
        };
        {
            let dir = dir.clone();
            blocking(move || {
                if dir.join(META_FILE).exists() || dir.join(DB_FILE).exists() {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidArgument,
                        format!("{} already holds a project; open it instead", dir.display()),
                    ));
                }
                let engine_dir = dir.join(ENGINE_DIR);
                std::fs::create_dir_all(&engine_dir)
                    .map_err(|e| io_err("cannot create", &engine_dir, e))
            })
            .await?;
        }
        let binary_hash = {
            let p = binary_path.clone();
            blocking(move || hash_file(&p)).await?
        };
        let kind = {
            let (factory, p) = (self.factory.clone(), binary_path.clone());
            blocking(move || factory.detect_kind(&p)).await?
        };
        let engine = self
            .factory
            .create_kind(kind, &dir.join(ENGINE_DIR))
            .await?;
        let program = open_binary(&engine, &binary_path).await?;
        let db_path = dir.join(DB_FILE);
        let store = blocking(move || Store::open(db_path)).await?;
        let meta = ProjectMeta {
            format_version: 1,
            binary_path: binary_path.to_string_lossy().into_owned(),
            binary_sha256: binary_hash.clone(),
            epoch: Epoch {
                engine_build: engine.capabilities().handshake.build,
                options_hash: options_hash(),
                binary_hash,
            },
            engine_dir: ENGINE_DIR.into(),
            analysis_complete: false,
            engine_kind: kind,
        };
        {
            let (dir, meta) = (dir.clone(), meta.clone());
            blocking(move || write_meta(&dir, &meta)).await?;
        }
        let project = Arc::new(self.build_project(dir, meta, engine, program, store, Vec::new()));
        self.attach(project.clone());
        Ok(project)
    }

    /// Opens the project in `dir`, replacing any open project. A stale engine cache (different
    /// engine build, options or binary) is reported through [`Project::epoch_mismatch`]; it is
    /// rebuilt only by the `rebuild` command.
    pub async fn open_project(&self, dir: &Path) -> Result<Arc<Project>, ProtoError> {
        let dir = dir.to_path_buf();
        let meta = {
            let dir = dir.clone();
            blocking(move || read_meta(&dir)).await?
        };
        let binary_path = PathBuf::from(&meta.binary_path);
        check_engine_dir(&meta.engine_dir)?;
        let current_hash = {
            let p = binary_path.clone();
            blocking(move || {
                crate::trust::ensure_regular_file(&p)?;
                hash_file(&p)
            })
            .await?
        };
        let engine_dir = dir.join(&meta.engine_dir);
        {
            let engine_dir = engine_dir.clone();
            blocking(move || {
                std::fs::create_dir_all(&engine_dir)
                    .map_err(|e| io_err("cannot create", &engine_dir, e))
            })
            .await?;
        }
        let engine = self
            .factory
            .create_kind(meta.engine_kind, &engine_dir)
            .await?;
        let program = open_binary(&engine, &binary_path).await?;
        let db_path = dir.join(DB_FILE);
        let store = blocking(move || Store::open(db_path)).await?;
        let now = Epoch {
            engine_build: engine.capabilities().handshake.build,
            options_hash: options_hash(),
            binary_hash: current_hash,
        };
        let mut mismatch = Vec::new();
        if now.engine_build != meta.epoch.engine_build {
            mismatch.push("engine_build".to_string());
        }
        if now.options_hash != meta.epoch.options_hash {
            mismatch.push("options_hash".to_string());
        }
        if now.binary_hash != meta.epoch.binary_hash {
            mismatch.push("binary_hash".to_string());
        }
        let project = Arc::new(self.build_project(dir, meta, engine, program, store, mismatch));
        self.attach(project.clone());
        if project.epoch_mismatch().is_empty() {
            let _guard = project.write_lock.lock().await;
            // Entries left pending by an earlier session are retried; failures stay pending.
            let _ = project.flush_pending(&CancellationToken::new()).await;
        }
        Ok(project)
    }

    fn build_project(
        &self,
        dir: PathBuf,
        meta: ProjectMeta,
        engine: SharedEngine,
        program: ProgramInfo,
        store: Store,
        epoch_mismatch: Vec<String>,
    ) -> Project {
        let phase = if meta.analysis_complete && epoch_mismatch.is_empty() {
            AnalysisPhase::Complete
        } else {
            AnalysisPhase::NotStarted
        };
        Project {
            dir,
            config: self.config.clone(),
            meta: Mutex::new(meta),
            program: Mutex::new(program),
            engine: RwLock::new(engine),
            model: Arc::new(Mutex::new(store)),
            write_lock: tokio::sync::Mutex::new(()),
            analysis: Mutex::new(AnalysisState {
                phase,
                job: None,
                function_count: None,
                error: None,
            }),
            epoch_mismatch,
            quota: Mutex::default(),
        }
    }
}

/// Opens the binary in `engine` with default loader hints.
pub(crate) async fn open_binary(
    engine: &SharedEngine,
    binary: &Path,
) -> Result<ProgramInfo, ProtoError> {
    let loader = engine.loader().ok_or_else(|| unsupported("loader"))?;
    loader
        .open_binary(binary, &LoaderSpec::default(), &CancellationToken::new())
        .await
}

/// The epoch of a freshly created engine for the project's binary.
pub(crate) fn epoch_for(engine: &SharedEngine, binary_hash: &str) -> Epoch {
    Epoch {
        engine_build: engine.capabilities().handshake.build,
        options_hash: options_hash(),
        binary_hash: binary_hash.to_string(),
    }
}

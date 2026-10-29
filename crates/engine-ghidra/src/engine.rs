//! [`GhidraEngine`]: every `kraken-engine` capability, backed by the Ghidra sidecar.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::ProgressSender;
use kraken_engine::{
    AnalysisJob, AnalysisSummary, AnalyzeRequest, Analyzer, Assembler, CancellationToken, Cap,
    Decompiler, DisasmRequest, Disassembler, Engine, EngineCaps, EngineRejected, EngineResult,
    FlowGraph, FunctionLister, Loader, LoaderSpec, MemoryReader, Mutator, OpenReporter,
    ProgramInfo, Progress, Stage, StringLister, StringsRequest, SymbolLister, TypeStore, Watermark,
    XrefProvider, XrefRequest, type_def_name, unsupported,
};
use kraken_proto::{
    Anchor, BytesRead, Cfg, DecompileResult, DisasmRow, ErrorCode, FunctionSummary, Hex64, Locator,
    LogOp, MemoryBlock, OpenStage, OpenUpdate, Page, PageRequest, ProtoError, StringEntry,
    SymbolEntry, TypeDef, VersionedLogOp, Xref,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::config::{EngineConfig, heap_mb, physical_memory_mb};
use crate::launch::{GhidraLauncher, LaunchPlan, Launcher};
use crate::rpc::WireProgress;
use crate::supervisor::{
    Diagnostics, OpenParams, Running, SidecarEvent, Supervisor, SupervisorConfig, open_request,
};

/// The Ghidra-backed engine. Cheap to share behind `Arc`; nothing is started until the first
/// [`Loader::open_binary`].
pub struct GhidraEngine {
    cfg: EngineConfig,
    sup: Supervisor,
    job_seq: AtomicU64,
    /// Sidecar stages known to be complete for the open program.
    stages_done: Arc<Mutex<BTreeSet<Stage>>>,
}

impl std::fmt::Debug for GhidraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhidraEngine")
            .field("project_dir", &self.cfg.project_dir)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct WireProgramInfo {
    #[serde(default)]
    stages_done: Vec<String>,
    language: String,
    format: String,
    image_base: Hex64,
    sha256: String,
}

#[derive(Deserialize)]
struct WireAnalyzeResult {
    #[serde(default)]
    function_count: u64,
}

#[derive(Deserialize)]
struct WireSave {
    checkpoint: String,
}

fn cancelled(what: &str) -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, format!("{what} cancelled"))
}

/// The Ghidra loader name for a neutral format name.
pub fn loader_name(format: &str) -> Option<&'static str> {
    match format {
        "elf" => Some("Executable and Linking Format (ELF)"),
        "pe" => Some("Portable Executable (PE)"),
        "macho" => Some("Mac OS X Mach-O"),
        "raw" => Some("Raw Binary"),
        "ihex" => Some("Intel Hex"),
        "srec" => Some("Motorola Hex"),
        _ => None,
    }
}

/// The neutral format name for Ghidra's `getExecutableFormat()` string.
pub fn normalize_format(ghidra: &str) -> String {
    let l = ghidra.to_ascii_lowercase();
    if l.contains("(elf)") || l.starts_with("executable and linking") {
        "elf".into()
    } else if l.contains("(pe)") || l.starts_with("portable executable") {
        "pe".into()
    } else if l.contains("mach-o") {
        "macho".into()
    } else if l.contains("raw binary") {
        "raw".into()
    } else if l == "intel hex" {
        "ihex".into()
    } else if l == "motorola hex" {
        "srec".into()
    } else {
        l
    }
}

/// `"<loader>;<language>;<compiler>;<base>;<offset>;<length>;<entry>"` for the sidecar (numbers
/// in hex, trailing empty fields dropped after the first two), or `None` for full auto-detection.
fn loader_spec(spec: &LoaderSpec) -> EngineResult<Option<String>> {
    let loader = match spec.format.as_deref() {
        None => "",
        Some(f) => loader_name(f).ok_or_else(|| unsupported(&format!("loader format `{f}`")))?,
    };
    let text = |v: &Option<String>| v.clone().unwrap_or_default();
    let num = |v: Option<Hex64>| v.map(|h| format!("{:x}", h.0)).unwrap_or_default();
    let fields = [
        loader.to_string(),
        text(&spec.arch),
        text(&spec.compiler),
        num(spec.base),
        num(spec.offset),
        num(spec.length),
        num(spec.entry),
    ];
    if fields.iter().any(|f| f.contains(';')) {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "loader options must not contain `;`",
        ));
    }
    let used = fields.iter().rposition(|f| !f.is_empty()).map(|n| n.max(1));
    Ok(used.map(|n| fields[..=n].join(";")))
}

/// Creates and canonicalises the project directory. Ghidra refuses project paths with an element
/// that starts with a dot (such as `~/.local/...` or a `.tmpXXXX` directory).
async fn prepare_project_dir(dir: &Path) -> EngineResult<std::path::PathBuf> {
    let invalid = |msg: String| ProtoError::new(ErrorCode::InvalidArgument, msg);
    tokio::fs::create_dir_all(dir).await.map_err(|e| {
        invalid(format!(
            "cannot create the project dir {}: {e}",
            dir.display()
        ))
    })?;
    let dir = tokio::fs::canonicalize(dir)
        .await
        .map_err(|e| invalid(format!("project dir {}: {e}", dir.display())))?;
    check_project_path(&dir)?;
    Ok(dir)
}

fn check_project_path(dir: &Path) -> EngineResult<()> {
    if let Some(bad) = dir.components().find_map(|c| match c {
        std::path::Component::Normal(n) if n.to_string_lossy().starts_with('.') => Some(n),
        _ => None,
    }) {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!(
                "the project path {} has an element starting with a dot ({}), which Ghidra rejects",
                dir.display(),
                bad.to_string_lossy()
            ),
        ));
    }
    Ok(())
}

fn op_anchor(op: &LogOp) -> &Anchor {
    match op {
        LogOp::Rename { anchor, .. }
        | LogOp::SetType { anchor, .. }
        | LogOp::SetComment { anchor, .. }
        | LogOp::CreateFunction { anchor, .. }
        | LogOp::DeleteFunction { anchor, .. }
        | LogOp::SetFunctionBounds { anchor, .. }
        | LogOp::SetCodeData { anchor, .. }
        | LogOp::SetCallingConvention { anchor, .. }
        | LogOp::SetPatch { anchor, .. } => anchor,
    }
}

fn page_params(page: &PageRequest) -> Value {
    let mut v = json!({"limit": page.effective_limit()});
    if let (Some(c), Some(obj)) = (&page.cursor, v.as_object_mut()) {
        obj.insert("cursor".into(), Value::String(c.clone()));
    }
    v
}

fn bad_cursor(what: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!("malformed {what} cursor"),
    )
}

fn stage_from_wire(s: &str) -> Option<Stage> {
    Stage::ALL.into_iter().find(|st| st.as_str() == s)
}

/// Which stages an analysis request runs: whether `load` counts as part of it, and the sidecar
/// stages (already-complete ones are skipped by the sidecar).
fn plan_stages(resume_from: Option<Stage>) -> (bool, Vec<Stage>) {
    match resume_from {
        None | Some(Stage::Load) => (true, vec![Stage::Core, Stage::Expensive]),
        Some(Stage::Core) => (false, vec![Stage::Core, Stage::Expensive]),
        Some(Stage::Expensive) => (false, vec![Stage::Expensive]),
    }
}

impl GhidraEngine {
    /// An engine for `config`. Nothing is spawned yet.
    pub fn new(config: EngineConfig) -> Self {
        let launcher = GhidraLauncher::new(
            config.install.clone(),
            config.confinement.clone(),
            config.temp_root.clone(),
        );
        Self::with_launcher(config, Arc::new(launcher))
    }

    /// An engine that starts sidecars with `launcher` (tests use an in-process fake).
    pub fn with_launcher(config: EngineConfig, launcher: Arc<dyn Launcher>) -> Self {
        let sup = Supervisor::new(
            launcher,
            SupervisorConfig {
                max_restarts: config.max_restarts,
                startup_timeout: config.startup_timeout,
                restart_backoff: config.restart_backoff,
                open_timeout: config.deadlines.open_binary,
                expected_ghidra_version: Some(config.install.ghidra_version.clone()),
            },
        );
        GhidraEngine {
            cfg: config,
            sup,
            job_seq: AtomicU64::new(0),
            stages_done: Arc::default(),
        }
    }

    /// The configuration this engine runs with.
    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    /// Subscribes to sidecar lifecycle events (`Started`, `Exited`, `Restarted`).
    pub fn subscribe(&self) -> broadcast::Receiver<SidecarEvent> {
        self.sup.subscribe()
    }

    /// Replaces a dead (or stuck) sidecar and reopens the last binary, making up to
    /// `max_restarts` attempts. Unsaved edits are lost with the old process: the caller replays
    /// its log afterwards (the `Restarted` event says when).
    pub async fn restart(&self) -> Result<(), ProtoError> {
        self.sup.restart().await.map(|_| ())
    }

    /// Asks the sidecar to exit and kills it. A later `open_binary` starts a new one.
    pub async fn shutdown(&self) {
        self.sup.shutdown().await;
    }

    /// State, confinement report, heap, restart count and the sidecar's log tail.
    pub fn diagnostics(&self) -> Diagnostics {
        self.sup.diagnostics()
    }

    async fn rpc(
        &self,
        method: &str,
        params: Value,
        deadline: Option<Duration>,
        cancel: &CancellationToken,
    ) -> EngineResult<Value> {
        if cancel.is_cancelled() {
            return Err(cancelled(method));
        }
        let running = self.sup.current()?;
        running
            .client
            .call(method, params, deadline, Some(cancel))
            .await
            .map_err(|e| running.enrich(e))
    }

    async fn rpc_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        deadline: Option<Duration>,
        cancel: &CancellationToken,
    ) -> EngineResult<T> {
        let v = self.rpc(method, params, deadline, cancel).await?;
        serde_json::from_value(v).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("malformed `{method}` result from the sidecar: {e}"),
            )
        })
    }

    fn deadline(&self) -> Option<Duration> {
        Some(self.cfg.deadlines.default)
    }

    #[cfg(test)]
    #[cfg_attr(not(unix), allow(dead_code))] // its callers are Unix-only tests
    pub(crate) async fn rpc_for_test(
        &self,
        method: &str,
        params: Value,
        cancel: &CancellationToken,
    ) -> EngineResult<Value> {
        self.rpc(method, params, self.deadline(), cancel).await
    }
}

#[async_trait]
impl Loader for GhidraEngine {
    async fn open_binary(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo> {
        self.open(path, spec, cancel, None).await
    }

    async fn open_binary_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: OpenReporter,
    ) -> EngineResult<ProgramInfo> {
        self.open(path, spec, cancel, Some(&report)).await
    }
}

impl GhidraEngine {
    /// Opens `path`; the sidecar reports nothing while it imports, so `report` hears the coarse
    /// stages: starting Ghidra, then importing (or reopening the Ghidra project kept from an
    /// earlier open).
    async fn open(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: Option<&OpenReporter>,
    ) -> EngineResult<ProgramInfo> {
        let say = |u: OpenUpdate| {
            if let Some(r) = report {
                r(u);
            }
        };
        if cancel.is_cancelled() {
            return Err(cancelled("open_binary"));
        }
        let loader_spec = loader_spec(spec)?;
        let binary = tokio::fs::canonicalize(path).await.map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                ErrorCode::NotFound
            } else {
                ErrorCode::InvalidArgument
            };
            ProtoError::new(code, format!("cannot open {}: {e}", path.display()))
        })?;
        let meta = tokio::fs::metadata(&binary).await.map_err(|e| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("{}: {e}", binary.display()),
            )
        })?;
        if !meta.is_file() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("{} is not a regular file", binary.display()),
            ));
        }
        let project_dir = prepare_project_dir(&self.cfg.project_dir).await?;
        let cached = project_dir.join("kraken.gpr").is_file();
        say(OpenUpdate::stage(
            OpenStage::StartEngine,
            "Starting Ghidra (a Java program; this takes a few seconds)",
        ));
        let plan = LaunchPlan {
            binary_size: meta.len(),
            heap_mb: heap_mb(meta.len(), self.cfg.max_heap_mb, physical_memory_mb()),
            binary,
            project_dir,
        };
        let running = self.sup.ensure(plan.clone()).await?;
        let request = open_request(&plan.binary, &plan.project_dir, loader_spec.as_deref());
        say(OpenUpdate {
            from_cache: cached,
            ..OpenUpdate::stage(
                OpenStage::ReadFile,
                if cached {
                    "Opening the Ghidra project saved by the last open"
                } else {
                    "Importing the file into Ghidra (a big program takes minutes)"
                },
            )
        });
        let info: WireProgramInfo = running
            .client
            .call_typed(
                "open_binary",
                request.clone(),
                Some(self.cfg.deadlines.open_binary),
                Some(cancel),
            )
            .await
            .map_err(|e| running.enrich(e))?;
        let size = plan.binary_size;
        *self
            .stages_done
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = info
            .stages_done
            .iter()
            .filter_map(|s| stage_from_wire(s))
            .collect();
        self.sup.remember_open(OpenParams { request, plan });
        Ok(ProgramInfo {
            arch: info.language,
            format: normalize_format(&info.format),
            base: info.image_base,
            sha256: info.sha256,
            size,
            ..ProgramInfo::default()
        })
    }
}

#[async_trait]
impl Analyzer for GhidraEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        if cancel.is_cancelled() {
            return Err(cancelled("analyze"));
        }
        let running = self.sup.current()?;
        let (with_load, wanted) = plan_stages(req.resume_from);
        let job_id = format!(
            "kraken-job-{}",
            self.job_seq.fetch_add(1, Ordering::Relaxed) + 1
        );
        let deadline = self.cfg.deadlines.analyze;
        let done = self.stages_done.clone();
        Ok(AnalysisJob::spawn(cancel, move |progress, cancel| {
            run_analysis(
                running, job_id, with_load, wanted, done, deadline, progress, cancel,
            )
        }))
    }
}

fn forward_progress(tx: &ProgressSender, p: WireProgress) {
    if let Some(stage) = stage_from_wire(&p.stage) {
        tx.send(Progress {
            stage,
            done: p.done.min(p.total),
            total: p.total,
            message: p.message,
            step: p.step.map(|s| kraken_engine::Step {
                name: s.name,
                done: s.done,
                total: s.total,
            }),
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_analysis(
    running: Arc<Running>,
    job_id: String,
    with_load: bool,
    wanted: Vec<Stage>,
    stages_done: Arc<Mutex<BTreeSet<Stage>>>,
    deadline: Option<Duration>,
    progress: ProgressSender,
    cancel: CancellationToken,
) -> Result<AnalysisSummary, ProtoError> {
    let cancelled_err = || {
        ProtoError::new(ErrorCode::Cancelled, "analysis cancelled")
            .with_details(json!({"job_id": job_id}))
    };
    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }
    if with_load {
        progress.send(Progress {
            stage: Stage::Load,
            done: 1,
            total: 1,
            message: "binary loaded".into(),
            step: None,
        });
    }
    // The sidecar skips stages that are already complete and says nothing about them; report
    // them as done so every requested stage shows up, in order.
    let already: BTreeSet<Stage> = {
        let done = stages_done.lock().unwrap_or_else(PoisonError::into_inner);
        wanted
            .iter()
            .copied()
            .filter(|s| done.contains(s))
            .collect()
    };
    let already_done = |stage: Stage| Progress {
        stage,
        done: 1,
        total: 1,
        message: "already complete".into(),
        step: None,
    };
    let leading = wanted.iter().take_while(|s| already.contains(s)).count();
    for stage in &wanted[..leading] {
        progress.send(already_done(*stage));
    }
    let mut sub = running.client.subscribe_progress(&job_id);
    let params = json!({
        "job_id": job_id,
        "stages": wanted.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
    });
    let call = running.client.call("analyze", params, deadline, None);
    tokio::pin!(call);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let (mut cancel_requested, mut cancel_acked) = (false, false);
    let result = loop {
        tokio::select! {
            r = &mut call => break r,
            Some(p) = sub.events.recv() => forward_progress(&progress, p),
            () = cancel.cancelled(), if !cancel_requested => cancel_requested = true,
            // The sidecar may not have registered the job yet: keep asking until it accepts.
            _ = tick.tick(), if cancel_requested && !cancel_acked => {
                let ask = running.client.call(
                    "cancel",
                    json!({"job_id": job_id}),
                    Some(Duration::from_secs(5)),
                    None,
                );
                cancel_acked = ask.await.is_ok();
            }
        }
    };
    while let Ok(p) = sub.events.try_recv() {
        forward_progress(&progress, p);
    }
    let value = result.map_err(|e| running.enrich(e))?;
    for stage in &wanted[leading..] {
        if already.contains(stage) {
            progress.send(already_done(*stage));
        }
    }
    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }
    let done: WireAnalyzeResult = serde_json::from_value(value).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("malformed `analyze` result from the sidecar: {e}"),
        )
    })?;
    stages_done
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .extend(wanted.iter().copied());
    let mut stages_completed = Vec::new();
    if with_load {
        stages_completed.push(Stage::Load);
    }
    stages_completed.extend(wanted);
    Ok(AnalysisSummary {
        stages_completed,
        function_count: done.function_count,
    })
}

#[async_trait]
impl Decompiler for GhidraEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        let limit = self.cfg.deadlines.decompile;
        let result: DecompileResult = self
            .rpc_typed(
                "decompile",
                json!({"locator": locator, "timeout_ms": limit.as_millis() as u64}),
                // The decompiler enforces `limit` itself; the request deadline is a backstop.
                Some(limit + Duration::from_secs(5)),
                cancel,
            )
            .await?;
        result.validate_tokens().map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("the sidecar produced invalid token spans: {e}"),
            )
        })?;
        Ok(result)
    }
}

#[async_trait]
impl TypeStore for GhidraEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        let page: Page<TypeDef> = self
            .rpc_typed(
                "get_types",
                json!({"name": name, "limit": kraken_proto::MAX_PAGE_LIMIT}),
                self.deadline(),
                cancel,
            )
            .await?;
        page.items
            .into_iter()
            .find(|d| type_def_name(d) == Some(name))
            .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no type named `{name}`")))
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        if type_def_name(&def).is_none() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "an anonymous type cannot be defined",
            ));
        }
        self.rpc("define_type", json!({"def": def}), self.deadline(), cancel)
            .await
            .map(drop)
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        if page
            .cursor
            .as_deref()
            .is_some_and(|c| c.parse::<u64>().is_err())
        {
            return Err(bad_cursor("type"));
        }
        self.rpc_typed("get_types", page_params(page), self.deadline(), cancel)
            .await
    }
}

#[async_trait]
impl FunctionLister for GhidraEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        if page
            .cursor
            .as_deref()
            .is_some_and(|c| c.parse::<Hex64>().is_err())
        {
            return Err(bad_cursor("function"));
        }
        self.rpc_typed("list_functions", page_params(page), self.deadline(), cancel)
            .await
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        let f: FunctionSummary = self
            .rpc_typed(
                "get_function",
                json!({"locator": locator}),
                self.deadline(),
                cancel,
            )
            .await?;
        // The sidecar also answers for addresses inside a function; the trait asks for entries.
        if &f.locator != locator {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "no function starts at {locator:?} (it lies inside {:?})",
                    f.locator
                ),
            ));
        }
        Ok(f)
    }
}

#[async_trait]
impl Mutator for GhidraEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        op.check_version()?;
        op_anchor(&op.op).native()?;
        if let LogOp::Rename {
            anchor: Anchor::Native { space, offset, .. },
            old_name,
            new_name,
        } = &op.op
        {
            // The sidecar ignores `old_name`; idempotence and stale-read detection live here.
            let at = Locator::Native {
                space: space.clone(),
                offset: *offset,
            };
            match self.get_function(&at, cancel).await {
                Ok(f) => {
                    if &f.name == new_name {
                        return Ok(());
                    }
                    if let Some(old) = old_name
                        && old != &f.name
                    {
                        return Err(EngineRejected::new(
                            ErrorCode::ConflictStaleRead,
                            format!("function at {at:?} is named `{}`, not `{old}`", f.name),
                        ));
                    }
                }
                Err(e) if e.code == ErrorCode::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.rpc("apply_op", json!({"op": op}), self.deadline(), cancel)
            .await?;
        Ok(())
    }

    async fn save(&self, cancel: &CancellationToken) -> EngineResult<Watermark> {
        let s: WireSave = self
            .rpc_typed("save", json!({}), self.deadline(), cancel)
            .await?;
        Ok(Watermark(s.checkpoint))
    }
}

/// A numeric (decimal index) cursor must parse; the sidecar reports the same error, but failing
/// here keeps the engine's contract independent of the sidecar.
fn check_index_cursor(page: &PageRequest, what: &str) -> EngineResult<()> {
    if page
        .cursor
        .as_deref()
        .is_some_and(|c| c.parse::<u32>().is_err())
    {
        return Err(bad_cursor(what));
    }
    Ok(())
}

fn with_page(mut params: Value, page: &PageRequest) -> Value {
    if let (Value::Object(m), Value::Object(p)) = (&mut params, page_params(page)) {
        m.extend(p);
    }
    params
}

#[async_trait]
impl MemoryReader for GhidraEngine {
    async fn memory_map(&self, cancel: &CancellationToken) -> EngineResult<Vec<MemoryBlock>> {
        self.rpc_typed("memory_map", json!({}), self.deadline(), cancel)
            .await
    }

    async fn read_bytes(
        &self,
        start: &Locator,
        length: u32,
        cancel: &CancellationToken,
    ) -> EngineResult<BytesRead> {
        if length == 0 {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "length must be positive",
            ));
        }
        self.rpc_typed(
            "read_bytes",
            json!({"locator": start, "length": length}),
            self.deadline(),
            cancel,
        )
        .await
    }
}

#[async_trait]
impl Disassembler for GhidraEngine {
    async fn disassemble(
        &self,
        req: &DisasmRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<DisasmRow>> {
        if page
            .cursor
            .as_deref()
            .is_some_and(|c| c.parse::<Hex64>().is_err())
        {
            return Err(bad_cursor("disassembly"));
        }
        self.rpc_typed(
            "disassemble",
            with_page(json!({"start": req.start, "scope": req.scope}), page),
            self.deadline(),
            cancel,
        )
        .await
    }
}

#[async_trait]
impl XrefProvider for GhidraEngine {
    async fn xrefs(
        &self,
        req: &XrefRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<Xref>> {
        check_index_cursor(page, "xref")?;
        let mut params = json!({
            "address": req.address,
            "direction": req.direction,
            "whole_function": req.whole_function,
        });
        if let (Some(kind), Value::Object(m)) = (req.kind, &mut params) {
            m.insert("kind".into(), json!(kind));
        }
        self.rpc_typed("xrefs", with_page(params, page), self.deadline(), cancel)
            .await
    }
}

#[async_trait]
impl FlowGraph for GhidraEngine {
    async fn cfg(&self, function: &Locator, cancel: &CancellationToken) -> EngineResult<Cfg> {
        self.rpc_typed("cfg", json!({"locator": function}), self.deadline(), cancel)
            .await
    }
}

#[async_trait]
impl StringLister for GhidraEngine {
    async fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<StringEntry>> {
        check_index_cursor(page, "string")?;
        let mut params = json!({"min_len": req.min_len});
        if let (Some(filter), Value::Object(m)) = (&req.filter, &mut params) {
            m.insert("filter".into(), json!(filter));
        }
        self.rpc_typed("strings", with_page(params, page), self.deadline(), cancel)
            .await
    }
}

#[async_trait]
impl SymbolLister for GhidraEngine {
    async fn imports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check_index_cursor(page, "import")?;
        self.rpc_typed("imports", page_params(page), self.deadline(), cancel)
            .await
    }

    async fn exports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check_index_cursor(page, "export")?;
        self.rpc_typed("exports", page_params(page), self.deadline(), cancel)
            .await
    }
}

impl Engine for GhidraEngine {
    fn process_id(&self) -> Option<u32> {
        let d = self.diagnostics();
        (d.state == "running").then_some(d.pid).flatten()
    }
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            format!(
                "engine-ghidra {} (ghidra {})",
                env!("CARGO_PKG_VERSION"),
                self.cfg.install.ghidra_version
            ),
            Cap::ALL,
        )
    }
    fn loader(&self) -> Option<&dyn Loader> {
        Some(self)
    }
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        Some(self)
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        Some(self)
    }
    fn type_store(&self) -> Option<&dyn TypeStore> {
        Some(self)
    }
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        Some(self)
    }
    fn mutator(&self) -> Option<&dyn Mutator> {
        Some(self)
    }
    fn memory_reader(&self) -> Option<&dyn MemoryReader> {
        Some(self)
    }
    fn disassembler(&self) -> Option<&dyn Disassembler> {
        Some(self)
    }
    fn xref_provider(&self) -> Option<&dyn XrefProvider> {
        Some(self)
    }
    fn flow_graph(&self) -> Option<&dyn FlowGraph> {
        Some(self)
    }
    fn string_lister(&self) -> Option<&dyn StringLister> {
        Some(self)
    }
    fn symbol_lister(&self) -> Option<&dyn SymbolLister> {
        Some(self)
    }
    fn assembler(&self) -> Option<&dyn Assembler> {
        Some(self)
    }
}

#[derive(serde::Deserialize)]
struct Assembled {
    encodings: Vec<String>,
}

#[async_trait]
impl Assembler for GhidraEngine {
    async fn assemble(
        &self,
        at: &Locator,
        text: &str,
        cancel: &CancellationToken,
    ) -> EngineResult<Vec<Vec<u8>>> {
        let out: Assembled = self
            .rpc_typed(
                "assemble",
                json!({"locator": at, "text": text}),
                self.deadline(),
                cancel,
            )
            .await?;
        out.encodings
            .iter()
            .map(|h| {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(h.get(i..i + 2).unwrap_or("zz"), 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| {
                        ProtoError::new(
                            ErrorCode::Internal,
                            "the sidecar sent bytes that are not hex",
                        )
                    })
            })
            .collect()
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn formats_map_both_ways() {
        for f in ["elf", "pe", "macho", "raw"] {
            assert_eq!(normalize_format(loader_name(f).unwrap()), f);
        }
        assert_eq!(normalize_format("Something Else"), "something else");
        assert!(loader_name("a.out").is_none());
    }

    #[test]
    fn loader_spec_is_built_from_the_neutral_spec() {
        let none = LoaderSpec::default();
        assert_eq!(loader_spec(&none).unwrap(), None);
        let elf = LoaderSpec {
            format: Some("elf".into()),
            arch: Some("x86:LE:64:default".into()),
            ..LoaderSpec::default()
        };
        assert_eq!(
            loader_spec(&elf).unwrap().as_deref(),
            Some("Executable and Linking Format (ELF);x86:LE:64:default")
        );
        let arch_only = LoaderSpec {
            arch: Some("ARM:LE:32:v8".into()),
            ..LoaderSpec::default()
        };
        assert_eq!(
            loader_spec(&arch_only).unwrap().as_deref(),
            Some(";ARM:LE:32:v8")
        );
        let bad = LoaderSpec {
            format: Some("nope".into()),
            ..LoaderSpec::default()
        };
        assert_eq!(loader_spec(&bad).unwrap_err().code, ErrorCode::Unsupported);
        let raw = LoaderSpec {
            format: Some("raw".into()),
            arch: Some("ARM:LE:32:Cortex".into()),
            base: Some(Hex64(0x0800_0000)),
            offset: Some(Hex64(0x100)),
            entry: Some(Hex64(0x0800_0101)),
            ..LoaderSpec::default()
        };
        assert_eq!(
            loader_spec(&raw).unwrap().as_deref(),
            Some("Raw Binary;ARM:LE:32:Cortex;;8000000;100;;8000101")
        );
    }

    #[test]
    fn dotted_project_paths_are_rejected_up_front() {
        assert!(check_project_path(Path::new("/var/lib/kraken/proj")).is_ok());
        let e = check_project_path(Path::new("/home/me/.local/share/kraken/proj")).unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert!(e.message.contains(".local"));
    }

    #[test]
    fn analysis_stage_plans() {
        assert_eq!(
            plan_stages(None),
            (true, vec![Stage::Core, Stage::Expensive])
        );
        assert_eq!(
            plan_stages(Some(Stage::Core)),
            (false, vec![Stage::Core, Stage::Expensive])
        );
        assert_eq!(
            plan_stages(Some(Stage::Expensive)),
            (false, vec![Stage::Expensive])
        );
    }

    #[test]
    fn page_params_clamp_the_limit() {
        let p = PageRequest {
            cursor: Some("0x10".into()),
            limit: Some(0),
        };
        assert_eq!(page_params(&p), json!({"limit": 1, "cursor": "0x10"}));
        assert_eq!(
            page_params(&PageRequest::default()),
            json!({"limit": kraken_proto::DEFAULT_PAGE_LIMIT})
        );
    }
}

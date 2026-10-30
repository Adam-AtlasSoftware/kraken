//! [`RewriteService`]: the implementation of the registry's `rewrite_*` commands.
//!
//! The commands live in `kraken-registry` (so every surface sees them); this is what a [`Session`]
//! runs them on once it is built with [`Session::with_rewrite`]. See ADR 0013.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use kraken_agent::{ChatProvider, EnvSecrets};
use kraken_assist::{AiLimits, ApiBackend, AssistBackend, ModelChoice, Pricing, RewriteModel};
use kraken_model::DailyLedger;
use kraken_proto::{AiEstimate, AiProviderKind};
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use kraken_registry::commands::{
    CounterexampleView, ExportCoverage, ExportRequest, PlanEntry, PlanScope, RewriteAcceptArgs,
    RewriteAcceptOut, RewriteBackend, RewriteBuildArgs, RewriteBuildResult, RewriteExportResult,
    RewriteFunctionArgs, RewriteFunctionResult, RewriteMode, RewritePlanArgs, RewritePlanOut,
    RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatusArgs, RewriteProgramStatusOut,
    RewriteSpecArgs, RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut, RewriteUnitArgs,
    RewriteUnitOut, StatusCounts, UnitRow, UnitSpecView, UnitStatus, UnitVersionView,
};
use kraken_registry::commands::{
    PreloadCalls, PreloadCheck, PreloadHook, PreloadSkip, RewritePreloadBuildArgs,
    RewritePreloadBuildResult,
};
use kraken_registry::{CallContext, JobProgress, JobReporter, Session};

use crate::abi::{Arg, Signature};
use crate::collect::{ProgramFacts, calls_of, collect, collect_closure};
use crate::difftest::{DiffOptions, InputSpec, Verdict};
use crate::error::RewriteError;
use crate::export::{
    ExportInfo, build_in_sandbox, check_symbols, check_target, crate_prefix, write_workspace,
};
use crate::fetch::FunctionContext;
use crate::infer::{generic_inputs, generic_notes, infer_signature, rust_name};
use crate::lift::Lift;
use crate::oracle::{FunctionOracle, OracleConfig};
use crate::pipeline::{VerifyPlan, verify_compile_only, verify_with};
use crate::plan::to_plan;
use crate::repair::{self, Attempt, DEFAULT_ATTEMPTS};
use crate::reuse::{self, Resolved};
use crate::sandbox::{self, Confinement};
use crate::store::{
    NewSpec, PlannedFunction, RewriteStore, StoredPlan, StoredSpec, UnitSummary, stale_reason,
};
use crate::task::{Budget, RewriteTask, SpecScope, SpecTask};
use crate::unit::{RewriteUnit, sha256_hex};

#[path = "service_program.rs"]
mod program_mode;

#[path = "control.rs"]
mod control;

/// Default cap on functions a new whole-program plan examines.
const DEFAULT_PLAN_FUNCTIONS: u32 = 2000;
/// Largest cap a caller may ask for.
const MAX_PLAN_FUNCTIONS: u32 = 20_000;
/// Most functions a function-scope plan walks.
const CLOSURE_CAP: usize = 200;
/// Default and largest page sizes.
const DEFAULT_PAGE: u32 = 100;
const MAX_PAGE: u32 = 200;
/// Functions a whole-program spec is written from by default.
const DEFAULT_SPEC_FUNCTIONS: u32 = 30;
/// Most bytes of one function's decompile that go into a program-level spec prompt.
const SPEC_DECOMPILE_BYTES: usize = 6000;

/// Where the assistant backend that answers the model calls comes from.
pub trait BackendSource: Send + Sync {
    /// The backend to use for the next model call: a model API or a terminal agent, the same
    /// [`AssistBackend`]s the assistant runs on.
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError>;

    /// The backend for one run: the configured model, or the assistant's (`which`), with
    /// `model` in place of the configured model name; and where it runs, when known (a local
    /// server is free). The default ignores the overrides.
    fn backend_for(
        &self,
        _which: RewriteModel,
        _model: Option<&str>,
    ) -> Result<(Arc<dyn AssistBackend>, Option<AiProviderKind>), ProtoError> {
        Ok((self.backend()?, None))
    }

    /// The model a run would use, for estimates; `None` when unknown.
    fn choice(&self, _which: RewriteModel, _model: Option<&str>) -> Option<ModelChoice> {
        None
    }

    /// Per-run caps and the daily budget (default: none).
    fn limits(&self) -> AiLimits {
        AiLimits::default()
    }

    /// Prices for cost estimates (default: the built-in table).
    fn pricing(&self) -> Pricing {
        Pricing::default()
    }

    /// The daily totals the budget is checked against and calls are added to (default: none).
    fn daily(&self) -> Option<DailyLedger> {
        None
    }
}

/// Always the same backend (tests, embedding).
pub struct FixedBackend(pub Arc<dyn AssistBackend>);

impl BackendSource for FixedBackend {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        Ok(self.0.clone())
    }
}

/// Always the same chat model API, wrapped as an [`ApiBackend`] (tests, embedding).
pub struct FixedProvider(pub Arc<dyn ChatProvider>);

impl BackendSource for FixedProvider {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        Ok(Arc::new(ApiBackend::new(self.0.clone())))
    }
}

type EnvLookup = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// The backend `config.toml` selects, as the assistant reads it: the optional `[rewrite]` table
/// when there is one, else `[provider]`. Either may be a model API or a terminal agent
/// (`kind = "terminal_agent"`). Re-read on every call, so a changed config applies without a
/// restart.
pub struct ConfigBackend {
    env: EnvLookup,
}

impl ConfigBackend {
    /// Reads the process environment.
    pub fn from_env() -> Self {
        ConfigBackend {
            env: Box::new(|k| std::env::var_os(k)),
        }
    }

    /// Reads `env` instead of the process environment.
    pub fn with_env(env: EnvLookup) -> Self {
        ConfigBackend { env }
    }
}

impl ConfigBackend {
    fn path(&self) -> Option<PathBuf> {
        kraken_assist::provider_config_path(&|k| (self.env)(k))
    }
}

fn config_error(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, e.to_string())
}

impl BackendSource for ConfigBackend {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        kraken_assist::text_backend_from_config(&|k| (self.env)(k), &EnvSecrets)
            .map_err(config_error)
    }

    fn backend_for(
        &self,
        which: RewriteModel,
        model: Option<&str>,
    ) -> Result<(Arc<dyn AssistBackend>, Option<AiProviderKind>), ProtoError> {
        let choice = kraken_assist::rewrite_choice(self.path().as_deref(), which, model)
            .map_err(config_error)?;
        let backend = kraken_assist::text_backend(&choice.config, &|k| (self.env)(k), &EnvSecrets)
            .map_err(config_error)?;
        Ok((backend, Some(choice.kind)))
    }

    fn choice(&self, which: RewriteModel, model: Option<&str>) -> Option<ModelChoice> {
        kraken_assist::rewrite_choice(self.path().as_deref(), which, model).ok()
    }

    fn limits(&self) -> AiLimits {
        AiLimits::load(self.path().as_deref())
    }

    fn pricing(&self) -> Pricing {
        Pricing::load(self.path().as_deref())
    }

    fn daily(&self) -> Option<DailyLedger> {
        DailyLedger::from_env(&|k| (self.env)(k))
    }
}

/// Settings of the service.
#[derive(Debug, Clone)]
pub struct RewriteConfig {
    /// Where the SLEIGH specs come from, and the emulator limits.
    pub oracle: OracleConfig,
    /// Sandbox settings. `allow_unconfined` is never set by the service; commands refuse to run
    /// generated code on a host that cannot confine it.
    pub confinement: Confinement,
    /// Model limits.
    pub budget: Budget,
    /// Most callees whose decompile goes into a translation prompt.
    pub max_callees: usize,
    /// Translation attempts of `rewrite_function` when the call does not say (1 = no repair).
    pub max_attempts: u32,
    /// Functions of a program rewrite translated at once (`[rewrite] parallel`).
    pub parallel: u32,
}

/// Functions translated at once when nothing says otherwise.
pub const DEFAULT_PARALLEL: u32 = 4;
/// Most functions translated at once.
pub const MAX_PARALLEL: u32 = 16;

impl Default for RewriteConfig {
    fn default() -> Self {
        RewriteConfig {
            oracle: OracleConfig::default(),
            confinement: Confinement::default(),
            budget: Budget::default(),
            max_callees: 6,
            max_attempts: DEFAULT_ATTEMPTS,
            parallel: DEFAULT_PARALLEL,
        }
    }
}

/// Runs the `rewrite_*` commands.
pub struct RewriteService {
    backends: Arc<dyn BackendSource>,
    cfg: RewriteConfig,
}

impl RewriteService {
    /// A service with the given provider source and settings.
    pub fn new(backends: Arc<dyn BackendSource>, cfg: RewriteConfig) -> Self {
        RewriteService { backends, cfg }
    }

    /// The service the CLI and `krakend` attach: provider from `config.toml`, default settings.
    pub fn standard() -> Self {
        let path = kraken_assist::provider_config_path(&|k| std::env::var_os(k));
        Self::new(
            Arc::new(ConfigBackend::from_env()),
            RewriteConfig {
                parallel: kraken_assist::rewrite_parallel(path.as_deref())
                    .unwrap_or(DEFAULT_PARALLEL),
                ..RewriteConfig::default()
            },
        )
    }

    /// Wraps the service for [`Session::with_rewrite`].
    pub fn into_backend(self) -> Arc<dyn RewriteBackend> {
        Arc::new(self)
    }
}

pub(crate) fn proto(e: RewriteError) -> ProtoError {
    match e {
        RewriteError::Provider(kraken_agent::AgentError::Limit(m)) => {
            crate::metering::limit_error(m)
        }
        RewriteError::Command(p) => p,
        RewriteError::Cancelled => ProtoError::new(ErrorCode::Cancelled, "job cancelled"),
        RewriteError::NoProcessors | RewriteError::Image(_) | RewriteError::Unsupported(_) => {
            ProtoError::new(ErrorCode::Unsupported, e.to_string())
        }
        other => ProtoError::new(ErrorCode::Internal, other.to_string()),
    }
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn unsupported(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Unsupported, msg)
}

fn internal(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg)
}

pub(crate) fn progress(job: &JobReporter, phase: &str, done: u64, total: u64, message: &str) {
    job.progress(JobProgress {
        phase: phase.to_string(),
        done,
        total,
        message: kraken_proto::sanitize(message),
        ..Default::default()
    });
}

/// Runs `f` on the project's store off the async threads.
pub(crate) async fn with_store<T, F>(dir: PathBuf, f: F) -> Result<T, ProtoError>
where
    T: Send + 'static,
    F: FnOnce(&RewriteStore) -> Result<T, RewriteError> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let store = RewriteStore::in_project(&dir)?;
        f(&store)
    })
    .await
    .map_err(|e| internal(format!("store task failed: {e}")))?
    .map_err(proto)
}

fn hex(address: &str) -> u64 {
    u64::from_str_radix(address.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn page_bounds(cursor: &Option<String>, limit: Option<u32>) -> Result<(usize, usize), ProtoError> {
    let start = match cursor {
        None => 0,
        Some(c) => c
            .parse::<usize>()
            .map_err(|_| invalid(format!("bad cursor `{c}`")))?,
    };
    let n = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize;
    Ok((start, n))
}

fn next_cursor(start: usize, n: usize, total: usize) -> Option<String> {
    (start + n < total).then(|| (start + n).to_string())
}

fn plan_entry(p: &PlannedFunction, status: UnitStatus) -> PlanEntry {
    PlanEntry {
        order: p.order,
        address: Hex64(p.address),
        name: Untrusted::sanitized(&p.name),
        group: p.group,
        group_size: p.group_size,
        callees: p.callees.iter().map(|a| Hex64(*a)).collect(),
        imports: p.imports.iter().map(|i| Untrusted::sanitized(i)).collect(),
        needs_stubs: p
            .needs_stubs
            .iter()
            .map(|i| Untrusted::sanitized(i))
            .collect(),
        flags: p.flags.clone(),
        status,
    }
}

fn verdict_name(v: &Verdict) -> (&'static str, Option<&str>) {
    match v {
        Verdict::Pass => ("pass", None),
        Verdict::Fail => ("fail", None),
        Verdict::Rejected { reason } => ("rejected", Some(reason)),
        Verdict::Inconclusive { reason } => ("inconclusive", Some(reason)),
    }
}

fn render_arg(a: &Arg) -> String {
    match a {
        Arg::Int { value } => format!("{}", *value as i64),
        Arg::Buf { data } => {
            let head: String = data.iter().take(32).map(|b| format!("{b:02x}")).collect();
            let more = if data.len() > 32 { "..." } else { "" };
            format!("buf[{}]={head}{more}", data.len())
        }
        Arg::Double { bits } => format!("{}", f64::from_bits(*bits)),
        Arg::Float { bits } => format!("{}f", f32::from_bits(*bits)),
        Arg::FnPtr { callback } => format!("callback {callback:?}"),
        Arg::Graph { objects, links } => {
            let sizes: Vec<String> = objects.iter().map(|o| o.len().to_string()).collect();
            format!("graph[{}; {} links]", sizes.join(","), links.len())
        }
    }
}

fn reused_symbols(unit: &RewriteUnit) -> Vec<String> {
    unit.callees
        .iter()
        .filter_map(|c| c.reused.as_ref().map(|r| r.symbol.clone()))
        .collect()
}

fn function_result(
    unit: &RewriteUnit,
    out: &crate::task::RewriteOutput,
    attempts: usize,
) -> RewriteFunctionResult {
    let (verdict, detail) = verdict_name(&unit.verdict);
    RewriteFunctionResult {
        unit: unit.id.clone(),
        address: Hex64(hex(&unit.anchor.address)),
        name: Untrusted::sanitized(&unit.anchor.name),
        version: unit.version,
        mode: unit.mode,
        status: unit.status,
        verdict: verdict.to_string(),
        verdict_detail: detail.map(Untrusted::sanitized),
        cases_run: u32::try_from(unit.summary.cases_run).unwrap_or(u32::MAX),
        passed: u32::try_from(unit.summary.passed).unwrap_or(u32::MAX),
        skipped: u32::try_from(unit.summary.skipped).unwrap_or(u32::MAX),
        counterexample: unit.counterexamples.first().map(|c| CounterexampleView {
            args: c.args.iter().map(render_arg).collect(),
            differences: c
                .differences
                .iter()
                .map(|d| Untrusted::sanitized(d))
                .collect(),
        }),
        rust_prototype: unit.rust_prototype.clone(),
        sandbox: unit.summary.sandbox.clone(),
        provider: unit.provenance.provider.clone().unwrap_or_default(),
        model: unit.provenance.model.clone().unwrap_or_default(),
        assumptions: out
            .assumptions
            .iter()
            .map(|a| Untrusted::sanitized(a))
            .collect(),
        unsupported: out
            .unsupported
            .iter()
            .map(|a| Untrusted::sanitized(a))
            .collect(),
        attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
        reused_callees: reused_symbols(unit),
        hints_used: false,
    }
}

fn unit_version(unit: &RewriteUnit, created: u64, stale: Option<&String>) -> UnitVersionView {
    let (verdict, detail) = verdict_name(&unit.verdict);
    let u32_of = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
    UnitVersionView {
        unit: unit.id.clone(),
        version: unit.version,
        mode: unit.mode,
        status: unit.status,
        accepted: unit.status == UnitStatus::Accepted,
        verdict: verdict.to_string(),
        verdict_detail: detail.map(Untrusted::sanitized),
        cases_run: u32_of(unit.summary.cases_run),
        passed: u32_of(unit.summary.passed),
        skipped: u32_of(unit.summary.skipped),
        counterexample: unit.counterexamples.first().map(|c| CounterexampleView {
            args: c.args.iter().map(render_arg).collect(),
            differences: c
                .differences
                .iter()
                .map(|d| Untrusted::sanitized(d))
                .collect(),
        }),
        rust_code: Untrusted::sanitized(&unit.rust_code),
        signature: unit.rust_prototype.clone(),
        oracle_kind: unit.oracle.kind.clone(),
        sandbox: unit.summary.sandbox.clone(),
        created,
        provider: unit.provenance.provider.clone().unwrap_or_default(),
        model: unit.provenance.model.clone().unwrap_or_default(),
        stale: stale.is_some(),
        stale_reason: stale.map(|r| Untrusted::sanitized(r)),
        attempt: unit.repair.as_ref().map_or(1, |r| r.attempt),
        repair_of: unit.repair.as_ref().and_then(|r| r.repair_of),
        reused_callees: reused_symbols(unit),
        coverage: unit.coverage.as_ref().map(control::coverage_view),
        user_cases: unit.user_cases,
    }
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map_or_else(
        || "program".to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

impl RewriteService {
    /// Decompiles the functions at `addresses` (`0x...`) and returns their hashes; a function
    /// that cannot be decompiled any more is left out (its old hash stays).
    async fn fresh_hashes(&self, lift: &Lift<'_>, addresses: &[String]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for a in addresses {
            if let Ok(f) = lift.function(hex(a)).await {
                out.push((a.clone(), f.decompile_hash));
            }
        }
        out
    }

    fn statuses(summaries: &[UnitSummary]) -> BTreeMap<u64, &UnitSummary> {
        summaries.iter().map(|u| (hex(&u.address), u)).collect()
    }

    /// Decompiles `address` and up to `max_callees` of the program functions it calls.
    async fn function_with_callees(
        &self,
        lift: &Lift<'_>,
        address: u64,
    ) -> Result<(FunctionContext, Vec<FunctionContext>), ProtoError> {
        let f = lift.function(address).await.map_err(proto)?;
        let facts = ProgramFacts::load(lift).await.map_err(proto)?;
        let calls = calls_of(lift, &facts, f.address).await.map_err(proto)?;
        let mut callees = Vec::new();
        for (addr, _) in calls
            .program
            .iter()
            .filter(|(a, _)| **a != f.address)
            .take(self.cfg.max_callees)
        {
            callees.push(lift.function(*addr).await.map_err(proto)?);
        }
        Ok((f, callees))
    }

    fn prepared(
        &self,
        f: FunctionContext,
        callees: Vec<FunctionContext>,
    ) -> Result<Prepared, ProtoError> {
        let signature_text = f.signature.clone().ok_or_else(|| {
            unsupported(format!(
                "`{}` has no signature; set one with set_type or rename_symbol before rewriting",
                f.name
            ))
        })?;
        let signature = infer_signature(&signature_text, &rust_name(&f.name, f.address))
            .map_err(|e| unsupported(format!("cannot check `{}` yet: {e}", f.name)))?;
        let task = RewriteTask {
            function: f.clone(),
            callees: callees.clone(),
            signature: signature.clone(),
            layout_notes: generic_notes(&signature),
            spec: None,
            reused: Vec::new(),
            repairs: Vec::new(),
            hints: None,
            hints_from_agent: false,
            budget: self.cfg.budget.clone(),
        };
        Ok(Prepared {
            function: f,
            callees,
            signature,
            task,
        })
    }

    /// Reads the function at `address` and builds what a translation request is made from:
    /// decompile, callees, the inferred ABI and the task. This is what `rewrite_function` sends,
    /// exposed so tests can build the matching cassette entry.
    pub async fn prepare(
        &self,
        s: &Session,
        ctx: &CallContext,
        address: u64,
    ) -> Result<Prepared, ProtoError> {
        let lift = Lift::new(s, ctx);
        let (f, callees) = self.function_with_callees(&lift, address).await?;
        let mut p = self.prepared(f, callees)?;
        add_layouts(s, &mut p.task, &ctx.cancel).await;
        crate::hints::add_hints(s.project()?.dir(), &mut p.task).await?;
        Ok(p)
    }

    async fn spec_for_function(
        &self,
        dir: &Path,
        f: &FunctionContext,
        callees: &[FunctionContext],
        job: &JobReporter,
        ai: &crate::metering::JobAi,
    ) -> Result<StoredSpec, ProtoError> {
        let source_hash = sha256_hex(
            &std::iter::once(f.decompile_hash.as_str())
                .chain(callees.iter().map(|c| c.decompile_hash.as_str()))
                .collect::<Vec<_>>()
                .join("|"),
        );
        let (sha, addr) = (f.program_sha256.clone(), format!("{:#x}", f.address));
        {
            let (sha, addr, source_hash) = (sha.clone(), addr.clone(), source_hash.clone());
            let existing = with_store(dir.to_path_buf(), move |st| {
                st.latest_spec(&sha, Some(&addr))
            })
            .await?;
            if let Some(sp) = existing
                && sp.source_hash == source_hash
            {
                return Ok(sp);
            }
        }
        progress(job, "spec", 0, 1, "writing the behavioural spec");
        let backend = ai.backend()?;
        let task = function_spec_task(f, callees, &self.cfg.budget);
        let (spec, reply) = task
            .run(backend.as_ref(), job.cancel_token())
            .await
            .map_err(proto)?;
        let mut stored = StoredSpec {
            id: 0,
            scope: "function".into(),
            address: Some(addr),
            markdown: spec.markdown,
            citations: spec.citations,
            facts: u32::try_from(spec.facts).unwrap_or(u32::MAX),
            functions: u32::try_from(task.functions.len()).unwrap_or(u32::MAX),
            source_hash,
            provider: reply.provider.id,
            model: reply.provider.model,
            prompt_hash: reply.prompt_hash,
        };
        let new = NewSpec {
            program_sha256: sha,
            spec: stored.clone(),
        };
        stored.id = with_store(dir.to_path_buf(), move |st| st.put_spec(new)).await?;
        Ok(stored)
    }
}

/// Why the oracle could not be built (the error is not `Clone`; every job needs a copy).
enum LoadFailure {
    NoProcessors,
    Other(String),
}

type OracleJob = Box<dyn FnOnce(&mut Result<FunctionOracle, LoadFailure>) + Send>;

/// A thread that owns the function oracle for the attempts of one run. The oracle is not `Send`
/// and is slow to build, so it is built once, on first use, inside the thread, and every attempt
/// is sent to it as a job. The thread ends when the last handle is dropped.
#[derive(Clone)]
pub(crate) struct OracleThread {
    jobs: std::sync::mpsc::Sender<OracleJob>,
}

impl OracleThread {
    pub(crate) fn spawn(binary: PathBuf, cfg: OracleConfig) -> Self {
        let (jobs, rx) = std::sync::mpsc::channel::<OracleJob>();
        let _ = std::thread::Builder::new()
            .name("kraken-rewrite-oracle".into())
            .spawn(move || {
                let mut oracle: Option<Result<FunctionOracle, LoadFailure>> = None;
                for job in rx {
                    let slot = oracle.get_or_insert_with(|| {
                        FunctionOracle::load(&binary, &cfg).map_err(|e| match e {
                            RewriteError::NoProcessors => LoadFailure::NoProcessors,
                            other => LoadFailure::Other(other.to_string()),
                        })
                    });
                    job(slot);
                }
            });
        OracleThread { jobs }
    }

    /// Runs `f` with the oracle and returns its result.
    pub(crate) async fn run<T, F>(&self, f: F) -> Result<T, RewriteError>
    where
        T: Send + 'static,
        F: FnOnce(&mut FunctionOracle) -> Result<T, RewriteError> + Send + 'static,
    {
        let (reply, answer) = tokio::sync::oneshot::channel();
        let job: OracleJob = Box::new(move |slot| {
            let r = match slot {
                Ok(o) => f(o),
                Err(LoadFailure::NoProcessors) => Err(RewriteError::NoProcessors),
                Err(LoadFailure::Other(why)) => Err(RewriteError::Emulator(why.clone())),
            };
            let _ = reply.send(r);
        });
        self.jobs
            .send(job)
            .map_err(|_| RewriteError::Emulator("the oracle thread has stopped".into()))?;
        answer
            .await
            .map_err(|_| RewriteError::Emulator("the oracle thread stopped".into()))?
    }
}

/// What the translation of one function is made from.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// The function.
    pub function: FunctionContext,
    /// Program functions it calls (decompile as context).
    pub callees: Vec<FunctionContext>,
    /// The ABI the translation is checked at.
    pub signature: Signature,
    /// The translation request (`incremental` mode).
    pub task: RewriteTask,
}

impl Prepared {
    /// The request that writes the function's spec (first step of `spec` mode).
    pub fn spec_task(&self, budget: &Budget) -> SpecTask {
        function_spec_task(&self.function, &self.callees, budget)
    }

    /// The translation request of `spec` mode: implement `spec_markdown`, without the decompile.
    pub fn reimplement_task(&self, spec_markdown: &str) -> RewriteTask {
        RewriteTask {
            callees: Vec::new(),
            spec: Some(spec_markdown.to_string()),
            ..self.task.clone()
        }
    }
}

fn function_spec_task(
    f: &FunctionContext,
    callees: &[FunctionContext],
    budget: &Budget,
) -> SpecTask {
    let mut functions = vec![f.clone()];
    functions.extend(callees.iter().cloned());
    SpecTask {
        scope: SpecScope::Function,
        functions,
        budget: budget.clone(),
    }
}

/// How a translation is checked against the original function.
#[derive(Debug, Clone)]
pub(crate) enum Check {
    /// Run the original under the emulation oracle and compare.
    Differential,
    /// Only lint and build it (no oracle); the text says why nothing is compared.
    CompileOnly(String),
}

/// One translation run of one function: what to ask the model, how to check it.
pub(crate) struct Work {
    /// The function.
    pub function: FunctionContext,
    /// The ABI it is checked at.
    pub signature: Signature,
    /// Function-level test inputs.
    pub inputs: InputSpec,
    /// The request (callees to translate inline, callees to call, notes).
    pub task: RewriteTask,
    /// The callees the code calls as Rust (`direct`) and what their code needs (`all`).
    pub reuse: Resolved,
    /// How the translation is made.
    pub mode: RewriteMode,
    /// The spec it is made from, for `spec` mode.
    pub spec_id: Option<u64>,
    /// How it is checked.
    pub check: Check,
    /// Put the runtime shim `rt` in scope of the code under test.
    pub shim: bool,
    /// Test settings.
    pub opts: DiffOptions,
    /// Most translation attempts.
    pub max_attempts: u32,
}

impl RewriteService {
    /// Asks for a translation, checks and stores it, and repairs it while that helps: the loop
    /// of `rewrite_function`, shared with `rewrite_program`. `job` gets per-step progress when
    /// given.
    pub(crate) async fn translate(
        &self,
        w: Work,
        dir: &Path,
        binary_path: &str,
        backend: &dyn AssistBackend,
        oracle: &OracleThread,
        job: Option<&JobReporter>,
    ) -> Result<repair::RepairRun, RewriteError> {
        let Work {
            function: f,
            signature: sig,
            inputs,
            task,
            reuse,
            mode,
            spec_id,
            check,
            shim,
            opts,
            max_attempts,
        } = w;
        let mut opts = opts;
        if shim {
            opts.trusted_prelude = crate::rt_module_source();
        }
        let prelude = reuse::prelude_with(&reuse.all, &reuse.direct, shim);
        let (translated_with, reused_direct) = (task.callees.clone(), reuse.direct.clone());
        let cancel = job.map(JobReporter::cancel_token).unwrap_or_default();
        let (dir, binary_path) = (dir.to_path_buf(), binary_path.to_string());
        repair::run(&task, backend, cancel.clone(), max_attempts, |attempt| {
            let (f2, sig2, opts2, inputs2) = (f.clone(), sig.clone(), opts.clone(), inputs.clone());
            let (callees2, reused2, prelude2) = (
                translated_with.clone(),
                reused_direct.clone(),
                prelude.clone(),
            );
            let (binary_path2, check2) = (binary_path.clone(), check.clone());
            let (oracle2, dir2, cancel2) = (oracle.clone(), dir.clone(), cancel.clone());
            async move {
                if cancel2.is_cancelled() {
                    return Err(RewriteError::Cancelled);
                }
                if let Some(job) = job {
                    progress(
                        job,
                        "verify",
                        2,
                        4,
                        &format!(
                            "building and testing attempt {} against the original",
                            attempt.link.attempt
                        ),
                    );
                }
                let Attempt {
                    output,
                    provenance,
                    link,
                } = attempt;
                let code = output.rust_code;
                let mut unit = match check2 {
                    Check::Differential => {
                        oracle2
                            .run(move |oracle| {
                                let entry = oracle.elf_vaddr(f2.address, f2.image_base);
                                let plan = VerifyPlan {
                                    function: &f2,
                                    callees: &callees2,
                                    signature: &sig2,
                                    inputs: &inputs2,
                                    binary: &file_name(&binary_path2),
                                    entry,
                                    mode,
                                    spec_id,
                                    reused: &reused2,
                                    prelude: &prelude2,
                                };
                                verify_with(&plan, &code, provenance, oracle, &opts2)
                            })
                            .await?
                    }
                    Check::CompileOnly(reason) => tokio::task::spawn_blocking(move || {
                        let plan = VerifyPlan {
                            function: &f2,
                            callees: &callees2,
                            signature: &sig2,
                            inputs: &inputs2,
                            binary: &file_name(&binary_path2),
                            entry: 0,
                            mode,
                            spec_id,
                            reused: &reused2,
                            prelude: &prelude2,
                        };
                        verify_compile_only(&plan, &code, provenance, &reason, &opts2)
                    })
                    .await
                    .map_err(|e| RewriteError::Store(format!("build task failed: {e}")))??,
                };
                unit.repair = Some(link);
                if let Some(job) = job {
                    progress(job, "store", 3, 4, "storing the unit");
                }
                tokio::task::spawn_blocking(move || RewriteStore::in_project(&dir2)?.put_unit(unit))
                    .await
                    .map_err(|e| RewriteError::Store(format!("store task failed: {e}")))?
            }
        })
        .await
    }
}

#[async_trait]
impl RewriteBackend for RewriteService {
    fn source_patch(&self) -> Option<Arc<dyn kraken_registry::commands::SourcePatchBackend>> {
        Some(Arc::new(RewriteService {
            backends: self.backends.clone(),
            cfg: self.cfg.clone(),
        }))
    }

    fn require_sandbox(&self) -> Result<(), ProtoError> {
        if sandbox::enforced() {
            Ok(())
        } else {
            Err(unsupported(
                "this host cannot confine generated code (it needs Linux with Landlock ABI 4+, kernel \
                 6.7, and a network or seccomp barrier); \
                 rewrite_function and the sandboxed build of rewrite_export refuse to run \
                 model-written code unconfined",
            ))
        }
    }

    async fn plan(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewritePlanArgs,
    ) -> Result<RewritePlanOut, ProtoError> {
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let lift = Lift::new(s, ctx);
        let (sha, _) = lift.program().map_err(proto)?;
        let (start, n) = page_bounds(&args.cursor, args.limit)?;
        let plan: StoredPlan = match args.scope {
            PlanScope::All => {
                if args.cursor.is_none() {
                    let cap = args
                        .max_functions
                        .unwrap_or(DEFAULT_PLAN_FUNCTIONS)
                        .clamp(1, MAX_PLAN_FUNCTIONS) as usize;
                    let collected = collect(s, ctx, cap).await.map_err(proto)?;
                    let plan = to_plan(&collected);
                    let (sha, p) = (sha.clone(), plan.clone());
                    with_store(dir.clone(), move |st| st.save_plan(&sha, &p)).await?;
                }
                let sha2 = sha.clone();
                with_store(dir.clone(), move |st| st.plan(&sha2))
                    .await?
                    .ok_or_else(|| {
                        ProtoError::new(
                            ErrorCode::NotFound,
                            "no stored plan; run rewrite_plan without a cursor first",
                        )
                    })?
            }
            PlanScope::Function => {
                let address = args
                    .address
                    .ok_or_else(|| invalid("`scope: function` needs `address`"))?;
                let (collected, _) = collect_closure(s, ctx, address.0, CLOSURE_CAP)
                    .await
                    .map_err(proto)?;
                to_plan(&collected)
            }
        };
        let sha2 = sha.clone();
        let summaries = with_store(dir, move |st| st.summaries(&sha2)).await?;
        let by_addr = Self::statuses(&summaries);
        let total = plan.entries.len();
        let entries: Vec<PlanEntry> = plan
            .entries
            .iter()
            .skip(start)
            .take(n)
            .map(|p| {
                let status = by_addr
                    .get(&p.address)
                    .map_or(UnitStatus::Planned, |u| u.status);
                plan_entry(p, status)
            })
            .collect();
        Ok(RewritePlanOut {
            scope: args.scope,
            program_sha256: sha,
            functions_total: plan.functions_total,
            functions_planned: total as u64,
            skipped_imports: plan.skipped_imports,
            skipped_runtime: plan.skipped_runtime,
            groups: plan.groups,
            truncated: plan.truncated,
            entries,
            next_cursor: next_cursor(start, n, total),
        })
    }

    async fn status(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteStatusArgs,
    ) -> Result<RewriteStatusOut, ProtoError> {
        let project = s.project()?;
        let (sha, _) = Lift::new(s, ctx).program().map_err(proto)?;
        let (start, n) = page_bounds(&args.cursor, args.limit)?;
        if args.refresh {
            let sha2 = sha.clone();
            let tracked = with_store(project.dir().to_path_buf(), move |st| {
                st.tracked_addresses(&sha2)
            })
            .await?;
            let fresh = self.fresh_hashes(&Lift::new(s, ctx), &tracked).await;
            let sha2 = sha.clone();
            with_store(project.dir().to_path_buf(), move |st| {
                st.observe(&sha2, &fresh)
            })
            .await?;
        }
        let sha2 = sha.clone();
        let (plan, summaries) = with_store(project.dir().to_path_buf(), move |st| {
            Ok((st.plan(&sha2)?, st.summaries(&sha2)?))
        })
        .await?;
        let by_addr = Self::statuses(&summaries);
        let mut rows: Vec<UnitRow> = Vec::new();
        let mut in_plan = std::collections::BTreeSet::new();
        if let Some(plan) = &plan {
            for p in &plan.entries {
                in_plan.insert(p.address);
                rows.push(row(
                    Some(p.order),
                    p.address,
                    &p.name,
                    by_addr.get(&p.address),
                    p.flags.clone(),
                ));
            }
        }
        for u in &summaries {
            let a = hex(&u.address);
            if !in_plan.contains(&a) {
                rows.push(row(None, a, &u.name, Some(&u), Vec::new()));
            }
        }
        let mut counts = StatusCounts::default();
        for r in &rows {
            match r.status {
                UnitStatus::Planned => counts.planned += 1,
                UnitStatus::Translated => counts.translated += 1,
                UnitStatus::Verified => counts.verified += 1,
                UnitStatus::Failed => counts.failed += 1,
                UnitStatus::Accepted => counts.accepted += 1,
            }
        }
        let total = rows.len();
        Ok(RewriteStatusOut {
            program_sha256: sha,
            plan_present: plan.is_some(),
            counts,
            units: rows.into_iter().skip(start).take(n).collect(),
            next_cursor: next_cursor(start, n, total),
        })
    }

    async fn unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteUnitArgs,
    ) -> Result<RewriteUnitOut, ProtoError> {
        let project = s.project()?;
        let lift = Lift::new(s, ctx);
        let (sha, _) = lift.program().map_err(proto)?;
        // The function: by address (any address inside it) or by one of its version ids.
        let (entry, by_id) = match (args.address, args.unit) {
            (Some(a), None) => (lift.listed(a.0).await.map_err(proto)?.address, None),
            (None, Some(id)) => (0, Some(id)),
            _ => return Err(invalid("give exactly one of `address` and `unit`")),
        };
        let sha2 = sha.clone();
        let (address, units, times, spec) = with_store(project.dir().to_path_buf(), move |st| {
            let address = match by_id {
                Some(id) => {
                    let Some(u) = st.get(&id)? else {
                        return Err(RewriteError::Command(ProtoError::new(
                            ErrorCode::NotFound,
                            format!("no rewrite unit `{id}`"),
                        )));
                    };
                    if u.anchor.program_sha256 != sha2 {
                        return Err(RewriteError::Command(invalid(
                            "that unit was made for a different binary",
                        )));
                    }
                    u.anchor.address
                }
                None => format!("{entry:#x}"),
            };
            let units = st.versions(&sha2, &address)?;
            let times = st.created_times(&sha2, &address)?;
            let spec = st.latest_spec(&sha2, Some(&address))?;
            Ok((address, units, times, spec))
        })
        .await?;
        let mut tracked: Vec<String> = vec![address.clone()];
        tracked.extend(
            units
                .iter()
                .flat_map(|u| u.callees.iter().map(|c| c.address.clone())),
        );
        tracked.sort();
        tracked.dedup();
        let fresh = self.fresh_hashes(&lift, &tracked).await;
        let sha3 = sha.clone();
        let observed = with_store(project.dir().to_path_buf(), move |st| {
            st.observe(&sha3, &fresh)?;
            st.observed(&sha3)
        })
        .await?;
        let versions = units
            .iter()
            .map(|u| {
                let created = times
                    .iter()
                    .find(|(id, _)| *id == u.id)
                    .map_or(0, |(_, t)| u64::try_from(*t).unwrap_or(0));
                let stale = stale_reason(
                    &u.anchor.address,
                    &u.source_decompile_hash,
                    &u.callees,
                    &observed,
                );
                unit_version(u, created, stale.as_ref())
            })
            .collect();
        Ok(RewriteUnitOut {
            address: Hex64(hex(&address)),
            versions,
            spec: spec.map(|sp| UnitSpecView {
                spec: sp.id,
                markdown: Untrusted::sanitized(&sp.markdown),
                citations: sp.citations.iter().map(|a| Hex64(*a)).collect(),
                facts: sp.facts,
                provider: sp.provider,
                model: sp.model,
            }),
        })
    }

    fn check_budget(&self) -> Result<(), ProtoError> {
        let limits = self.backends.limits();
        if let (Some(b), Some(d)) = (limits.daily_budget, self.backends.daily()) {
            let today = d.today().cost_usd;
            if today >= b {
                return Err(crate::metering::limit_error(
                    kraken_assist::daily_budget_message(b, today),
                ));
            }
        }
        Ok(())
    }

    async fn estimate(
        &self,
        s: &Session,
        ctx: &CallContext,
        command: &str,
        args: &serde_json::Value,
    ) -> Option<AiEstimate> {
        self.estimate_calls(s, ctx, command, args).await
    }

    async fn function(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteFunctionArgs,
        job: &JobReporter,
    ) -> Result<RewriteFunctionResult, ProtoError> {
        let label = format!("Rewriting the function at {}", args.address);
        let ai = crate::metering::JobAi::new(
            self.backends.clone(),
            s,
            ctx,
            job,
            label,
            args.provider.as_deref(),
            args.model.as_deref(),
        )?;
        let out = self.function_job(s, ctx, args, job, &ai).await;
        ai.finish(&out);
        out
    }

    async fn accept(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError> {
        self.accept_unit(s, ctx, args).await
    }

    async fn reject(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteRejectArgs,
    ) -> Result<kraken_registry::commands::UnitChangeOut, ProtoError> {
        self.reject_unit(s, ctx, args).await
    }

    async fn unaccept(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteUnaccept,
    ) -> Result<kraken_registry::commands::UnitChangeOut, ProtoError> {
        self.unaccept_unit(s, ctx, args).await
    }

    async fn hint_get(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteHintGetArgs,
    ) -> Result<kraken_registry::commands::RewriteHintsOut, ProtoError> {
        self.hint_get_unit(s, ctx, args).await
    }

    async fn hint_set(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteHintSetArgs,
    ) -> Result<kraken_registry::commands::RewriteHintsOut, ProtoError> {
        self.hint_set_unit(s, ctx, args).await
    }

    async fn add_case(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteAddCaseArgs,
        job: &JobReporter,
    ) -> Result<kraken_registry::commands::RewriteVerifyResult, ProtoError> {
        self.add_case_job(s, ctx, args, job).await
    }

    async fn verify(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteVerifyArgs,
        job: &JobReporter,
    ) -> Result<kraken_registry::commands::RewriteVerifyResult, ProtoError> {
        self.verify_unit_job(s, ctx, args, job).await
    }

    async fn cache(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: kraken_registry::commands::RewriteCacheArgs,
    ) -> Result<kraken_registry::commands::RewriteCacheOut, ProtoError> {
        use kraken_registry::commands::{CacheAction, RewriteCacheOut};
        let dir = s.project()?.dir().to_path_buf();
        with_store(dir, move |st| {
            let removed = match args.action {
                CacheAction::Clear => st.cache_clear()?,
                CacheAction::Stats => 0,
            };
            let c = st.cache_summary()?;
            Ok(RewriteCacheOut {
                entries: c.entries,
                bytes: c.bytes,
                hits: c.hits,
                oldest: c.oldest,
                removed,
            })
        })
        .await
    }

    async fn check(
        &self,
        s: &Session,
        ctx: &CallContext,
    ) -> Result<kraken_registry::commands::RewriteCheckOut, ProtoError> {
        self.check_prereqs(s, ctx).await
    }

    async fn spec_edit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::RewriteSpecEditArgs,
    ) -> Result<RewriteSpecResult, ProtoError> {
        self.spec_edit_unit(s, ctx, args).await
    }

    async fn spec(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecArgs,
        job: &JobReporter,
    ) -> Result<RewriteSpecResult, ProtoError> {
        let label = match args.address {
            Some(a) if args.scope == PlanScope::Function => {
                format!("Writing the spec of the function at {a}")
            }
            _ => "Writing the spec of the program".to_string(),
        };
        let ai = crate::metering::JobAi::new(
            self.backends.clone(),
            s,
            ctx,
            job,
            label,
            args.provider.as_deref(),
            args.model.as_deref(),
        )?;
        let out = self.spec_job(s, ctx, args, job, &ai).await;
        ai.finish(&out);
        out
    }

    async fn export(
        &self,
        s: &Session,
        ctx: &CallContext,
        request: ExportRequest,
        job: &JobReporter,
    ) -> Result<RewriteExportResult, ProtoError> {
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let lift = Lift::new(s, ctx);
        let (sha, image_base) = lift.program().map_err(proto)?;
        let binary_name = file_name(&project.meta().binary_path);
        progress(job, "collect", 0, 3, "reading the accepted units");
        let sha2 = sha.clone();
        let (units, plan, originals) = with_store(dir.clone(), move |st| {
            let units = st.accepted_units(&sha2)?;
            // Callees the accepted units were tested with that are not accepted themselves: the
            // export calls the original function for them.
            let accepted: std::collections::BTreeSet<String> =
                units.iter().map(|u| u.anchor.address.clone()).collect();
            let mut originals: Vec<RewriteUnit> = Vec::new();
            for c in units.iter().flat_map(|u| &u.callees) {
                let Some(r) = &c.reused else { continue };
                if accepted.contains(&c.address)
                    || originals.iter().any(|o| o.anchor.address == c.address)
                {
                    continue;
                }
                if let Some(o) = st.get(&r.unit)? {
                    originals.push(o);
                }
            }
            Ok((units, st.plan(&sha2)?, originals))
        })
        .await?;
        let functions_total = match &plan {
            Some(p) => p.functions_total,
            None => lift
                .functions(MAX_PLAN_FUNCTIONS as usize)
                .await
                .map_err(proto)?
                .0
                .len() as u64,
        };
        let coverage = ExportCoverage {
            accepted: u32::try_from(units.len()).unwrap_or(u32::MAX),
            planned: plan
                .as_ref()
                .map_or(0, |p| u32::try_from(p.entries.len()).unwrap_or(u32::MAX)),
            functions_total,
        };
        // Is what each unit was made from still what the engine decompiles today?
        let mut tracked: Vec<String> = units
            .iter()
            .flat_map(|u| {
                std::iter::once(u.anchor.address.clone())
                    .chain(u.callees.iter().map(|c| c.address.clone()))
            })
            .collect();
        tracked.sort();
        tracked.dedup();
        let fresh = self.fresh_hashes(&lift, &tracked).await;
        let sha4 = sha.clone();
        let observed = with_store(dir, move |st| {
            st.observe(&sha4, &fresh)?;
            st.observed(&sha4)
        })
        .await?;
        let mut caveats = BTreeMap::new();
        for u in &units {
            let stale = stale_reason(
                &u.anchor.address,
                &u.source_decompile_hash,
                &u.callees,
                &observed,
            );
            let why = crate::export::caveats_for(u, stale.as_deref());
            if !why.is_empty() {
                caveats.insert(u.anchor.address.clone(), why);
            }
        }
        let info = ExportInfo {
            caveats,
            prefix: crate_prefix(request.name.as_deref().unwrap_or(&binary_name)),
            binary_name,
            program_sha256: sha,
            coverage: coverage.clone(),
            originals,
            symbols: crate::image::function_symbols(
                std::path::Path::new(&project.meta().binary_path),
                image_base,
            ),
        };
        let build = request.build;
        let confinement = self.cfg.confinement.clone();
        let target = request.dir.clone();
        progress(job, "write", 1, 3, "writing the workspace");
        let job2 = job.clone();
        let built = tokio::task::spawn_blocking(move || -> Result<_, RewriteError> {
            check_target(&target)?;
            let written = write_workspace(&target, &info, &units)?;
            let mut sandbox = "none".to_string();
            if build {
                progress(
                    &job2,
                    "build",
                    2,
                    3,
                    "building the workspace in the sandbox",
                );
                let b = build_in_sandbox(&target, &written.ffi_crate, &confinement)?;
                check_symbols(&written.symbols, &b.symbols)?;
                sandbox = b.sandbox;
            }
            Ok((written, sandbox))
        })
        .await
        .map_err(|e| internal(format!("export task failed: {e}")))?
        .map_err(proto)?;
        let (written, sandbox) = built;
        progress(job, "done", 3, 3, "finished");
        Ok(RewriteExportResult {
            dir: request.dir.display().to_string(),
            crates: vec![written.lib_crate, written.ffi_crate],
            symbols: written.symbols,
            built: build,
            sandbox,
            coverage,
            readme: Untrusted::sanitized(&written.readme.display().to_string()),
        })
    }

    async fn program(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteProgramArgs,
        job: &JobReporter,
    ) -> Result<RewriteProgramResult, ProtoError> {
        let ai = crate::metering::JobAi::new(
            self.backends.clone(),
            s,
            ctx,
            job,
            "Rewriting the whole program".to_string(),
            args.provider.as_deref(),
            args.model.as_deref(),
        )?;
        let out = self.run_program(s, ctx, args, job, &ai).await;
        ai.finish(&out);
        out
    }

    async fn preload_build(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewritePreloadBuildArgs,
        job: &JobReporter,
    ) -> Result<RewritePreloadBuildResult, ProtoError> {
        self.require_sandbox()?;
        let dir = PathBuf::from(&args.dir);
        let lift = Lift::new(s, ctx);
        let (binary, image_base) = lift.binary().map_err(proto)?;
        crate::link::require_x86_64_elf(&binary).map_err(proto)?;
        let binary_len = std::fs::metadata(&binary)
            .map_err(|e| internal(format!("{}: {e}", binary.display())))?
            .len();
        progress(job, "lift", 0, 3, "reading the function sizes");
        let manifest = crate::link::read_manifest(&dir).map_err(proto)?;
        let mut sizes = BTreeMap::new();
        for e in &manifest.exports {
            if let Some(a) = u64::from_str_radix(e.address.trim_start_matches("0x"), 16).ok()
                && let Some(size) = lift.size(a).await
            {
                sizes.insert(e.address.clone(), size);
            }
        }
        let input = crate::link::PreloadInput {
            image_base,
            binary_len,
            sizes,
        };
        let confinement = self.cfg.confinement.clone();
        let check_args = args.check_args.clone();
        let check_stdin = args.check_stdin.clone();
        let job2 = job.clone();
        let done = tokio::task::spawn_blocking(move || -> Result<_, RewriteError> {
            progress(&job2, "write", 1, 3, "writing the preload crate");
            let plan = crate::link::write_preload(&dir, &input)?;
            progress(
                &job2,
                "build",
                2,
                3,
                "building the preload library in the sandbox",
            );
            let built = crate::link::build_preload(&dir, &plan, &confinement)?;
            let check = match &check_args {
                Some(a) => Some(crate::link::check_run(
                    &binary,
                    &built.library,
                    a,
                    check_stdin.as_deref(),
                    &confinement,
                )?),
                None => None,
            };
            Ok((dir, plan, built, check))
        })
        .await
        .map_err(|e| internal(format!("preload task failed: {e}")))?
        .map_err(proto)?;
        let (dir, plan, built, check) = done;
        progress(job, "done", 3, 3, "finished");
        Ok(RewritePreloadBuildResult {
            dir: dir.display().to_string(),
            library: Untrusted::sanitized(&built.library.display().to_string()),
            launcher: Untrusted::sanitized(&built.launcher.display().to_string()),
            hooked: plan
                .hooks
                .iter()
                .map(|h| PreloadHook {
                    symbol: h.symbol.clone(),
                    address: h.address.clone(),
                    size: h.size,
                })
                .collect(),
            skipped: plan
                .skipped
                .iter()
                .map(|(symbol, reason)| PreloadSkip {
                    symbol: symbol.clone(),
                    reason: reason.clone(),
                })
                .collect(),
            sandbox: built.sandbox,
            check: check.map(|c| PreloadCheck {
                original_exit: c.original.exit.clone(),
                preload_exit: c.preloaded.exit.clone(),
                identical: c.identical(),
                stdout_bytes: c.original.stdout.len() as u64,
                calls: c
                    .preloaded
                    .calls
                    .iter()
                    .map(|(symbol, calls)| PreloadCalls {
                        symbol: symbol.clone(),
                        calls: *calls,
                    })
                    .collect(),
                difference: c.difference().map(|d| Untrusted::sanitized(&d)),
            }),
            limits: crate::link::limits(),
        })
    }

    async fn build(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteBuildArgs,
        job: &JobReporter,
    ) -> Result<RewriteBuildResult, ProtoError> {
        self.require_sandbox()?;
        let dir = PathBuf::from(&args.dir);
        let test = args.test.unwrap_or(true);
        let confinement = self.cfg.confinement.clone();
        let total = 1 + u64::from(test) + u64::from(args.run_args.is_some());
        let counter = std::sync::atomic::AtomicU64::new(0);
        let job2 = job.clone();
        let report = tokio::task::spawn_blocking(move || {
            crate::build::build_and_test(
                &dir,
                test,
                args.run_args.as_deref(),
                &confinement,
                &|step| {
                    let n = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let what = match step {
                        "build" => "cargo build in the sandbox",
                        "test" => "cargo test in the sandbox",
                        _ => "running the program in the sandbox",
                    };
                    progress(&job2, step, n, total, what);
                },
            )
            .map(|r| (dir, r))
        })
        .await
        .map_err(|e| internal(format!("build task failed: {e}")))?
        .map_err(proto)?;
        let (dir, report) = report;
        progress(job, "done", total, total, "finished");
        Ok(RewriteBuildResult {
            dir: dir.display().to_string(),
            kind: report.kind.to_string(),
            passed: report.passed(),
            steps: report.steps,
            sandbox: report.sandbox,
        })
    }

    async fn program_status(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteProgramStatusArgs,
    ) -> Result<RewriteProgramStatusOut, ProtoError> {
        self.run_program_status(s, ctx, args).await
    }
}

fn row(
    order: Option<u32>,
    address: u64,
    name: &str,
    unit: Option<&&UnitSummary>,
    flags: Vec<kraken_registry::commands::PlanFlag>,
) -> UnitRow {
    match unit {
        Some(u) => UnitRow {
            unit: u.unit.clone(),
            order,
            address: Hex64(address),
            name: Untrusted::sanitized(name),
            status: u.status,
            version: u.version,
            accepted_version: u.accepted_version,
            mode: Some(u.mode),
            verdict: u.verdict.clone(),
            cases_run: u.cases_run,
            passed: u.passed,
            counterexamples: u.counterexamples,
            provider: u.provider.clone(),
            model: u.model.clone(),
            flags,
            stale: u.stale.is_some(),
        },
        None => UnitRow {
            unit: String::new(),
            order,
            address: Hex64(address),
            name: Untrusted::sanitized(name),
            status: UnitStatus::Planned,
            version: 0,
            accepted_version: None,
            mode: None,
            verdict: None,
            cases_run: 0,
            passed: 0,
            counterexamples: 0,
            provider: None,
            model: None,
            flags,
            stale: false,
        },
    }
}

fn spec_result(spec: &StoredSpec, scope: PlanScope, address: Option<u64>) -> RewriteSpecResult {
    RewriteSpecResult {
        spec: spec.id,
        scope,
        address: address.map(Hex64),
        functions: spec.functions,
        facts: spec.facts,
        citations: spec.citations.iter().map(|a| Hex64(*a)).collect(),
        markdown: Untrusted::sanitized(&spec.markdown),
        provider: spec.provider.clone(),
        model: spec.model.clone(),
    }
}

impl RewriteService {
    async fn function_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteFunctionArgs,
        job: &JobReporter,
        ai: &crate::metering::JobAi,
    ) -> Result<RewriteFunctionResult, ProtoError> {
        self.require_sandbox()?;
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let binary_path = project.meta().binary_path;
        let lift = Lift::new(s, ctx);

        progress(job, "lift", 0, 4, "reading the function");
        let (f, callees) = self.function_with_callees(&lift, args.address.0).await?;
        let mut prepared = self.prepared(f, callees)?;
        add_layouts(s, &mut prepared.task, &job.cancel_token()).await;
        if let Some(h) = args.hints.clone() {
            let (sha, addr) = (
                prepared.function.program_sha256.clone(),
                format!("{:#x}", prepared.function.address),
            );
            let (actor, by_agent) = (
                ctx.author.id.clone(),
                ctx.author.kind != kraken_model::AuthorKind::User,
            );
            with_store(dir.clone(), move |st| {
                st.put_hints(&sha, &addr, &h, &actor, by_agent)
            })
            .await?;
        }
        let hints_used = crate::hints::add_hints(&dir, &mut prepared.task).await?;

        let mut task = prepared.task.clone();
        let mut spec_id = None;
        let mut reuse = Resolved::default();
        let mut seen: Vec<(String, String)> = vec![(
            format!("{:#x}", prepared.function.address),
            prepared.function.decompile_hash.clone(),
        )];
        seen.extend(
            prepared
                .callees
                .iter()
                .map(|c| (format!("{:#x}", c.address), c.decompile_hash.clone())),
        );
        let sha = prepared.function.program_sha256.clone();
        if args.mode == RewriteMode::Spec {
            let spec = self
                .spec_for_function(&dir, &prepared.function, &prepared.callees, job, ai)
                .await?;
            spec_id = Some(spec.id);
            task = prepared.reimplement_task(&spec.markdown);
            with_store(dir.clone(), move |st| st.observe(&sha, &seen)).await?;
        } else {
            let (entry, callees) = (prepared.function.address, prepared.callees.clone());
            reuse = with_store(dir.clone(), move |st| {
                st.observe(&sha, &seen)?;
                reuse::resolve(st, &sha, entry, &callees)
            })
            .await?;
            task.callees = reuse.remaining.clone();
            task.reused = reuse.direct.clone();
        }
        let Prepared {
            function: f,
            signature: sig,
            ..
        } = prepared;

        let defaults = DiffOptions::default();
        let opts = DiffOptions {
            seed: args.seed.unwrap_or(defaults.seed),
            random_cases: args.cases.map_or(defaults.random_cases, |c| c as usize),
            confinement: self.cfg.confinement.clone(),
            ..defaults
        };
        let work = Work {
            inputs: generic_inputs(&sig),
            function: f,
            signature: sig,
            task,
            reuse,
            mode: args.mode,
            spec_id,
            check: Check::Differential,
            shim: false,
            opts,
            max_attempts: args.max_attempts.unwrap_or(self.cfg.max_attempts),
        };
        let oracle = OracleThread::spawn(PathBuf::from(&binary_path), self.cfg.oracle.clone());
        progress(job, "translate", 1, 4, "asking the model for a translation");
        let backend = crate::cache::CachingBackend::new(ai.backend()?, dir.clone(), Arc::default());
        let run = self
            .translate(work, &dir, &binary_path, &backend, &oracle, Some(job))
            .await
            .map_err(proto)?;
        crate::cache::forget_failed(
            &dir,
            &run.attempts.iter().map(|(u, _)| u).collect::<Vec<_>>(),
        );

        let (unit, out) = run.last();
        progress(job, "done", 4, 4, "finished");
        let mut result = function_result(unit, out, run.attempts.len());
        result.hints_used = hints_used;
        Ok(result)
    }

    async fn accept_unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError> {
        let project = s.project()?;
        let (sha, _) = Lift::new(s, ctx).program().map_err(proto)?;
        let (id, actor) = (args.unit, ctx.author.id.clone());
        let (unit, replaced) = with_store(project.dir().to_path_buf(), move |st| {
            let Some(u) = st.get(&id)? else {
                return Err(RewriteError::Command(ProtoError::new(
                    ErrorCode::NotFound,
                    format!("no rewrite unit `{id}`"),
                )));
            };
            if u.anchor.program_sha256 != sha {
                return Err(RewriteError::Command(invalid(
                    "that unit was made for a different binary",
                )));
            }
            if u.status != UnitStatus::Verified {
                return Err(RewriteError::Command(invalid(format!(
                    "unit `{id}` is {}; only a verified unit can be accepted",
                    u.status.as_str()
                ))));
            }
            st.accept(&id, &actor)
        })
        .await?;
        Ok(RewriteAcceptOut {
            status: "accepted".into(),
            unit: unit.id,
            address: Hex64(hex(&unit.anchor.address)),
            version: unit.version,
            replaced_version: replaced,
        })
    }

    async fn spec_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecArgs,
        job: &JobReporter,
        ai: &crate::metering::JobAi,
    ) -> Result<RewriteSpecResult, ProtoError> {
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let lift = Lift::new(s, ctx);
        match args.scope {
            PlanScope::Function => {
                let address = args
                    .address
                    .ok_or_else(|| invalid("`scope: function` needs `address`"))?;
                progress(job, "lift", 0, 2, "reading the function");
                let (f, callees) = self.function_with_callees(&lift, address.0).await?;
                // A repeated call with unchanged code returns the stored spec.
                let spec = self.spec_for_function(&dir, &f, &callees, job, ai).await?;
                Ok(spec_result(&spec, PlanScope::Function, Some(f.address)))
            }
            PlanScope::All => {
                let (sha, _) = lift.program().map_err(proto)?;
                progress(job, "plan", 0, 3, "ordering the functions");
                let max = args
                    .max_functions
                    .unwrap_or(DEFAULT_SPEC_FUNCTIONS)
                    .clamp(1, 100) as usize;
                let sha2 = sha.clone();
                let stored = with_store(dir.clone(), move |st| st.plan(&sha2)).await?;
                let plan = match stored {
                    Some(p) => p,
                    None => {
                        let collected = collect(s, ctx, MAX_PLAN_FUNCTIONS as usize)
                            .await
                            .map_err(proto)?;
                        let plan = to_plan(&collected);
                        let (sha3, p) = (sha.clone(), plan.clone());
                        with_store(dir.clone(), move |st| st.save_plan(&sha3, &p)).await?;
                        plan
                    }
                };
                let mut functions = Vec::new();
                for (i, p) in plan.entries.iter().take(max).enumerate() {
                    progress(job, "lift", i as u64, max as u64, &p.name);
                    let mut f = lift.function(p.address).await.map_err(proto)?;
                    if f.decompile.len() > SPEC_DECOMPILE_BYTES {
                        let mut cut = SPEC_DECOMPILE_BYTES;
                        while !f.decompile.is_char_boundary(cut) {
                            cut -= 1;
                        }
                        f.decompile.truncate(cut);
                        f.decompile.push_str("\n/* ... cut ... */\n");
                    }
                    functions.push(f);
                }
                if functions.is_empty() {
                    return Err(invalid("the program has no functions to describe"));
                }
                let source_hash = sha256_hex(
                    &functions
                        .iter()
                        .map(|f| f.decompile_hash.as_str())
                        .collect::<Vec<_>>()
                        .join("|"),
                );
                progress(job, "spec", 1, 3, "writing the behavioural spec");
                let backend = ai.backend()?;
                let task = SpecTask {
                    scope: SpecScope::Program,
                    functions,
                    budget: self.cfg.budget.clone(),
                };
                let (spec, reply) = task
                    .run(backend.as_ref(), job.cancel_token())
                    .await
                    .map_err(proto)?;
                let mut stored = StoredSpec {
                    id: 0,
                    scope: "program".into(),
                    address: None,
                    markdown: spec.markdown,
                    citations: spec.citations,
                    facts: u32::try_from(spec.facts).unwrap_or(u32::MAX),
                    functions: u32::try_from(task.functions.len()).unwrap_or(u32::MAX),
                    source_hash,
                    provider: reply.provider.id,
                    model: reply.provider.model,
                    prompt_hash: reply.prompt_hash,
                };
                let new = NewSpec {
                    program_sha256: sha,
                    spec: stored.clone(),
                };
                stored.id = with_store(dir, move |st| st.put_spec(new)).await?;
                progress(job, "done", 3, 3, "finished");
                Ok(spec_result(&stored, PlanScope::All, None))
            }
        }
    }
}

impl RewriteService {
    /// The most model calls `command` can make with `args`, on the model it would use.
    async fn estimate_calls(
        &self,
        s: &Session,
        ctx: &CallContext,
        command: &str,
        args: &serde_json::Value,
    ) -> Option<AiEstimate> {
        let text = |k: &str| args.get(k).and_then(serde_json::Value::as_str);
        let num = |k: &str| args.get(k).and_then(serde_json::Value::as_u64);
        let which = RewriteModel::parse(text("provider").unwrap_or("")).ok()?;
        let choice = self.backends.choice(which, text("model"))?;
        let attempts =
            u32::try_from(num("max_attempts").unwrap_or(u64::from(self.cfg.max_attempts)))
                .unwrap_or(self.cfg.max_attempts);
        let (min, max) = match command {
            "rewrite_function" => {
                let spec = text("mode") == Some("spec");
                (1, kraken_assist::rewrite_max_calls(1, attempts, spec, 0))
            }
            "rewrite_spec" => (1, 1),
            "rewrite_program" => {
                let rounds = u32::try_from(
                    num("repair_rounds")
                        .unwrap_or(u64::from(kraken_registry::commands::DEFAULT_REPAIR_ROUNDS)),
                )
                .unwrap_or(0);
                let project = s.project().ok()?;
                let (sha, _) = Lift::new(s, ctx).program().ok()?;
                let plan = with_store(project.dir().to_path_buf(), move |st| st.plan(&sha))
                    .await
                    .ok()
                    .flatten();
                let n = match plan {
                    Some(p) => p.entries.len() as u64,
                    None => return None,
                };
                (
                    n,
                    kraken_assist::rewrite_max_calls(n, attempts, false, rounds),
                )
            }
            _ => return None,
        };
        let policy = kraken_assist::AiPolicy {
            pricing: self.backends.pricing(),
            ..kraken_assist::AiPolicy::default()
        };
        Some(policy.estimate_with(kraken_proto::AiFeature::Rewrite, &choice, min, max))
    }
}

#[async_trait]
impl kraken_registry::commands::SourcePatchBackend for RewriteService {
    fn check_budget(&self) -> Result<(), ProtoError> {
        RewriteBackend::check_budget(self)
    }

    async fn patch_from_source(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::PatchFromSourceArgs,
        job: &JobReporter,
    ) -> Result<kraken_registry::commands::PatchFromSourceResult, ProtoError> {
        // The assistant's model: patching is an assistant feature, not the rewrite's.
        let ai = crate::metering::JobAi::new(
            self.backends.clone(),
            s,
            ctx,
            job,
            crate::source_patch::label(args.address),
            Some("assistant"),
            None,
        )?
        .with_feature(crate::source_patch::FEATURE);
        let out = crate::source_patch::run(s, ctx, args, job, &ai).await;
        ai.finish(&out);
        out
    }
}

/// Appends the layouts of the structs `task`'s function uses (`layouts`) to its layout notes.
pub(crate) async fn add_layouts(
    s: &Session,
    task: &mut crate::task::RewriteTask,
    cancel: &tokio_util::sync::CancellationToken,
) {
    let Ok(project) = s.project() else {
        return;
    };
    let engine = project.engine();
    let sig = task.function.signature.clone().unwrap_or_default();
    let text = crate::layouts::describe(&engine, &[&sig, &task.function.decompile], cancel).await;
    if !text.is_empty() {
        if !task.layout_notes.trim().is_empty() {
            task.layout_notes.push_str("\n\n");
        }
        task.layout_notes.push_str(&text);
    }
}

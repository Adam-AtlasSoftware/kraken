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
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use kraken_registry::commands::{
    CounterexampleView, ExportCoverage, ExportRequest, PlanEntry, PlanScope, RewriteAcceptArgs,
    RewriteAcceptOut, RewriteBackend, RewriteExportResult, RewriteFunctionArgs,
    RewriteFunctionResult, RewriteMode, RewritePlanArgs, RewritePlanOut, RewriteSpecArgs,
    RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut, StatusCounts, UnitRow, UnitStatus,
};
use kraken_registry::{CallContext, JobProgress, JobReporter, Session};

use crate::abi::{Arg, Signature};
use crate::collect::{ProgramFacts, calls_of, collect, collect_closure};
use crate::difftest::{DiffOptions, Verdict};
use crate::error::RewriteError;
use crate::export::{
    ExportInfo, build_in_sandbox, check_symbols, check_target, crate_prefix, write_workspace,
};
use crate::fetch::FunctionContext;
use crate::infer::{generic_inputs, generic_notes, infer_signature, rust_name};
use crate::lift::Lift;
use crate::oracle::{FunctionOracle, OracleConfig};
use crate::pipeline::{VerifyPlan, verify_with};
use crate::plan::to_plan;
use crate::sandbox::{self, Confinement};
use crate::store::{NewSpec, PlannedFunction, RewriteStore, StoredPlan, StoredSpec, UnitSummary};
use crate::task::{Budget, RewriteTask, SpecScope, SpecTask};
use crate::unit::{Provenance, RewriteUnit, sha256_hex};

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

/// Where the chat provider comes from.
pub trait ProviderSource: Send + Sync {
    /// The provider to use for the next model call.
    fn provider(&self) -> Result<Arc<dyn ChatProvider>, ProtoError>;
}

/// Always the same provider (tests, embedding).
pub struct FixedProvider(pub Arc<dyn ChatProvider>);

impl ProviderSource for FixedProvider {
    fn provider(&self) -> Result<Arc<dyn ChatProvider>, ProtoError> {
        Ok(self.0.clone())
    }
}

type EnvLookup = Box<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// The `[provider]` table of `config.toml`, as the assistant reads it (re-read on every call, so
/// a changed config applies without a restart).
pub struct ConfigProvider {
    env: EnvLookup,
}

impl ConfigProvider {
    /// Reads the process environment.
    pub fn from_env() -> Self {
        ConfigProvider {
            env: Box::new(|k| std::env::var_os(k)),
        }
    }

    /// Reads `env` instead of the process environment.
    pub fn with_env(env: EnvLookup) -> Self {
        ConfigProvider { env }
    }
}

impl ProviderSource for ConfigProvider {
    fn provider(&self) -> Result<Arc<dyn ChatProvider>, ProtoError> {
        let bad = |m: String| ProtoError::new(ErrorCode::InvalidArgument, m);
        let path = kraken_assist::provider_config_path(&|k| (self.env)(k));
        let cfg =
            kraken_assist::load_provider_config(path.as_deref()).map_err(|e| bad(e.to_string()))?;
        cfg.build(&EnvSecrets)
            .map_err(|e| bad(format!("provider: {e}")))
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
}

impl Default for RewriteConfig {
    fn default() -> Self {
        RewriteConfig {
            oracle: OracleConfig::default(),
            confinement: Confinement::default(),
            budget: Budget::default(),
            max_callees: 6,
        }
    }
}

/// Runs the `rewrite_*` commands.
pub struct RewriteService {
    providers: Arc<dyn ProviderSource>,
    cfg: RewriteConfig,
}

impl RewriteService {
    /// A service with the given provider source and settings.
    pub fn new(providers: Arc<dyn ProviderSource>, cfg: RewriteConfig) -> Self {
        RewriteService { providers, cfg }
    }

    /// The service the CLI and `krakend` attach: provider from `config.toml`, default settings.
    pub fn standard() -> Self {
        Self::new(
            Arc::new(ConfigProvider::from_env()),
            RewriteConfig::default(),
        )
    }

    /// Wraps the service for [`Session::with_rewrite`].
    pub fn into_backend(self) -> Arc<dyn RewriteBackend> {
        Arc::new(self)
    }
}

fn proto(e: RewriteError) -> ProtoError {
    match e {
        RewriteError::Command(p) => p,
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

fn progress(job: &JobReporter, phase: &str, done: u64, total: u64, message: &str) {
    job.progress(JobProgress {
        phase: phase.to_string(),
        done,
        total,
        message: kraken_proto::sanitize(message),
    });
}

/// Runs `f` on the project's store off the async threads.
async fn with_store<T, F>(dir: PathBuf, f: F) -> Result<T, ProtoError>
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
    }
}

fn function_result(unit: &RewriteUnit, out: &crate::task::RewriteOutput) -> RewriteFunctionResult {
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
    }
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map_or_else(
        || "program".to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

impl RewriteService {
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
        self.prepared(f, callees)
    }

    async fn spec_for_function(
        &self,
        dir: &Path,
        f: &FunctionContext,
        callees: &[FunctionContext],
        job: &JobReporter,
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
        let provider = self.providers.provider()?;
        let task = function_spec_task(f, callees, &self.cfg.budget);
        let (spec, reply) = task
            .run(provider.as_ref(), job.cancel_token())
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

#[async_trait]
impl RewriteBackend for RewriteService {
    fn require_sandbox(&self) -> Result<(), ProtoError> {
        if sandbox::enforced() {
            Ok(())
        } else {
            Err(unsupported(
                "this host cannot confine generated code (it needs Linux with Landlock); \
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

    async fn function(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteFunctionArgs,
        job: &JobReporter,
    ) -> Result<RewriteFunctionResult, ProtoError> {
        self.require_sandbox()?;
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        let binary_path = project.meta().binary_path;
        let lift = Lift::new(s, ctx);

        progress(job, "lift", 0, 4, "reading the function");
        let (f, callees) = self.function_with_callees(&lift, args.address.0).await?;
        let prepared = self.prepared(f, callees)?;
        let provider = self.providers.provider()?;

        let mut task = prepared.task.clone();
        let mut spec_id = None;
        if args.mode == RewriteMode::Spec {
            let spec = self
                .spec_for_function(&dir, &prepared.function, &prepared.callees, job)
                .await?;
            spec_id = Some(spec.id);
            task = prepared.reimplement_task(&spec.markdown);
        }
        let Prepared {
            function: f,
            callees,
            signature: sig,
            ..
        } = prepared;

        progress(job, "translate", 1, 4, "asking the model for a translation");
        let (out, reply) = task
            .run(provider.as_ref(), job.cancel_token())
            .await
            .map_err(proto)?;
        let provenance = Provenance {
            author: "model".into(),
            provider: Some(reply.provider.id.clone()),
            model: Some(reply.provider.model.clone()),
            task: "rewrite_function".into(),
            prompt_hash: reply.prompt_hash,
        };

        if job.cancel_token().is_cancelled() {
            return Err(ProtoError::new(ErrorCode::Cancelled, "job cancelled"));
        }
        progress(
            job,
            "verify",
            2,
            4,
            "building and testing against the original",
        );
        let defaults = DiffOptions::default();
        let opts = DiffOptions {
            seed: args.seed.unwrap_or(defaults.seed),
            random_cases: args.cases.map_or(defaults.random_cases, |c| c as usize),
            confinement: self.cfg.confinement.clone(),
            ..defaults
        };
        let oracle_cfg = self.cfg.oracle.clone();
        let (code, mode) = (out.rust_code.clone(), args.mode);
        let (f2, callees2, sig2) = (f.clone(), callees.clone(), sig.clone());
        let unit = tokio::task::spawn_blocking(move || -> Result<RewriteUnit, RewriteError> {
            let mut oracle = FunctionOracle::load(Path::new(&binary_path), &oracle_cfg)?;
            let entry = oracle.elf_vaddr(f2.address, f2.image_base);
            let inputs = generic_inputs(&sig2);
            let plan = VerifyPlan {
                function: &f2,
                callees: if mode == RewriteMode::Spec {
                    &[][..]
                } else {
                    &callees2[..]
                },
                signature: &sig2,
                inputs: &inputs,
                binary: &file_name(&binary_path),
                entry,
                mode,
                spec_id,
            };
            verify_with(&plan, &code, provenance, &mut oracle, &opts)
        })
        .await
        .map_err(|e| internal(format!("verification task failed: {e}")))?
        .map_err(proto)?;

        progress(job, "store", 3, 4, "storing the unit");
        let unit = with_store(dir, move |st| st.put_unit(unit)).await?;
        progress(job, "done", 4, 4, "finished");
        Ok(function_result(&unit, &out))
    }

    async fn accept(
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

    async fn spec(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecArgs,
        job: &JobReporter,
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
                let spec = self.spec_for_function(&dir, &f, &callees, job).await?;
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
                let provider = self.providers.provider()?;
                let task = SpecTask {
                    scope: SpecScope::Program,
                    functions,
                    budget: self.cfg.budget.clone(),
                };
                let (spec, reply) = task
                    .run(provider.as_ref(), job.cancel_token())
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
        let (sha, _) = lift.program().map_err(proto)?;
        let binary_name = file_name(&project.meta().binary_path);
        progress(job, "collect", 0, 3, "reading the accepted units");
        let sha2 = sha.clone();
        let (units, plan) = with_store(dir, move |st| {
            Ok((st.accepted_units(&sha2)?, st.plan(&sha2)?))
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
        let info = ExportInfo {
            prefix: crate_prefix(request.name.as_deref().unwrap_or(&binary_name)),
            binary_name,
            program_sha256: sha,
            coverage: coverage.clone(),
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
            readme: written.readme.display().to_string(),
        })
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
        },
        None => UnitRow {
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

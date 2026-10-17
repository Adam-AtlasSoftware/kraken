//! The loop for one function: lift (decompile through the registry) -> translate (a provider) ->
//! verify (differential test against the original under emulation) -> record (a versioned
//! [`RewriteUnit`]).

use kraken_agent::ChatProvider;
use kraken_host::backend::CommandBackend;
use kraken_registry::CallContext;
use kraken_registry::commands::RewriteMode;
use tokio_util::sync::CancellationToken;

use crate::abi::Signature;
use crate::difftest::{DiffOptions, DiffReport, InputSpec, compile_only, run_differential};
use crate::error::RewriteError;
use crate::fetch::{FunctionContext, fetch_function};
use crate::oracle::FunctionOracle;
use crate::reuse::ReusedCallee;
use crate::store::RewriteStore;
use crate::targets::Target;
use crate::task::{Budget, RewriteTask};
use crate::unit::{CalleeRef, OracleInfo, Provenance, RewriteUnit, UnitSource};
use crate::{EMULATOR_PIN, ORACLE_KIND};

/// Everything needed to rewrite and check one function.
#[derive(Debug, Clone)]
pub struct RewriteJob {
    /// The function.
    pub function: FunctionContext,
    /// Callees translated together with it.
    pub callees: Vec<FunctionContext>,
    /// The ABI to check at.
    pub signature: Signature,
    /// Layout facts for the prompt.
    pub layout_notes: String,
    /// Test input generation.
    pub inputs: InputSpec,
    /// File name of the binary the oracle runs.
    pub binary: String,
}

impl RewriteJob {
    /// The task for this job.
    pub fn task(&self) -> RewriteTask {
        RewriteTask {
            function: self.function.clone(),
            callees: self.callees.clone(),
            signature: self.signature.clone(),
            layout_notes: self.layout_notes.clone(),
            spec: None,
            reused: Vec::new(),
            repairs: Vec::new(),
            budget: Budget::default(),
        }
    }
}

/// Builds the job for a corpus target by reading the function and its callees through the
/// registry.
pub async fn job_for_target(
    backend: &dyn CommandBackend,
    ctx: &CallContext,
    target: &Target,
) -> Result<RewriteJob, RewriteError> {
    let function = fetch_function(backend, ctx, target.function).await?;
    let mut callees = Vec::new();
    for name in target.callees {
        callees.push(fetch_function(backend, ctx, name).await?);
    }
    Ok(RewriteJob {
        function,
        callees,
        signature: target.signature.clone(),
        layout_notes: target.layout_notes.to_string(),
        inputs: target.inputs.clone(),
        binary: target.binary.to_string(),
    })
}

/// What a verification run needs besides the code: the function, its context, the ABI, the
/// inputs and where the original runs.
#[derive(Debug, Clone)]
pub struct VerifyPlan<'a> {
    /// The function.
    pub function: &'a FunctionContext,
    /// Callees translated together with it.
    pub callees: &'a [FunctionContext],
    /// The ABI to check at.
    pub signature: &'a Signature,
    /// Test inputs.
    pub inputs: &'a InputSpec,
    /// File name of the binary the oracle runs.
    pub binary: &'a str,
    /// The function's ELF virtual address in that binary.
    pub entry: u64,
    /// How the translation was made.
    pub mode: RewriteMode,
    /// The spec it was made from, for `spec` mode.
    pub spec_id: Option<u64>,
    /// Accepted callees the code calls as Rust.
    pub reused: &'a [ReusedCallee],
    /// Source compiled in front of the code so those calls resolve ([`crate::reuse::prelude`]);
    /// empty without reuse. It is part of the test, not of the stored code.
    pub prelude: &'a str,
}

/// Differential-tests `rust_code` and returns the (unstored) record.
pub fn verify_with(
    plan: &VerifyPlan<'_>,
    rust_code: &str,
    provenance: Provenance,
    oracle: &mut FunctionOracle,
    opts: &DiffOptions,
) -> Result<RewriteUnit, RewriteError> {
    let tested = composed(plan, rust_code);
    let report = run_differential(
        oracle,
        plan.entry,
        plan.signature,
        &tested,
        plan.inputs,
        opts,
    )?;
    Ok(record(plan, rust_code, provenance, report, ORACLE_KIND))
}

/// Oracle kind of a record that was only compiled.
pub const COMPILE_ONLY_KIND: &str = "compile-only";

/// Builds `rust_code` without comparing it to the original (no oracle needed) and returns the
/// (unstored) record: `failed` when it is refused or does not compile, otherwise `translated`
/// with an `inconclusive` verdict that says `reason`.
pub fn verify_compile_only(
    plan: &VerifyPlan<'_>,
    rust_code: &str,
    provenance: Provenance,
    reason: &str,
    opts: &DiffOptions,
) -> Result<RewriteUnit, RewriteError> {
    let tested = composed(plan, rust_code);
    let report = compile_only(plan.signature, &tested, opts, reason)?;
    Ok(record(
        plan,
        rust_code,
        provenance,
        report,
        COMPILE_ONLY_KIND,
    ))
}

fn composed(plan: &VerifyPlan<'_>, rust_code: &str) -> String {
    if plan.prelude.is_empty() {
        rust_code.to_string()
    } else {
        format!("{}\n{rust_code}", plan.prelude)
    }
}

fn record(
    plan: &VerifyPlan<'_>,
    rust_code: &str,
    provenance: Provenance,
    report: DiffReport,
    oracle_kind: &str,
) -> RewriteUnit {
    let callees = plan
        .callees
        .iter()
        .map(|c| CalleeRef {
            name: c.name.clone(),
            address: format!("{:#x}", c.address),
            decompile_hash: c.decompile_hash.clone(),
            reused: None,
        })
        .chain(plan.reused.iter().map(ReusedCallee::callee_ref))
        .collect();
    RewriteUnit::from_run(
        UnitSource {
            mode: plan.mode,
            spec_id: plan.spec_id,
            anchor: plan.function.anchor(),
            source_decompile_hash: plan.function.decompile_hash.clone(),
            callees,
            signature: plan.signature.clone(),
            provenance,
            oracle: OracleInfo {
                kind: oracle_kind.to_string(),
                emulator: EMULATOR_PIN.to_string(),
                binary: plan.binary.to_string(),
                elf_vaddr: plan.entry,
            },
        },
        rust_code.to_string(),
        report,
    )
}

/// Differential-tests `rust_code` for `job` against the original and returns the (unstored)
/// record.
pub fn verify(
    job: &RewriteJob,
    rust_code: &str,
    provenance: Provenance,
    oracle: &mut FunctionOracle,
    opts: &DiffOptions,
) -> Result<RewriteUnit, RewriteError> {
    verify_with(
        &VerifyPlan {
            function: &job.function,
            callees: &job.callees,
            signature: &job.signature,
            inputs: &job.inputs,
            binary: &job.binary,
            entry: job.function.elf_vaddr(),
            mode: RewriteMode::Incremental,
            spec_id: None,
            reused: &[],
            prelude: "",
        },
        rust_code,
        provenance,
        oracle,
        opts,
    )
}

/// Asks `provider` for a translation, verifies it, and stores the record when `store` is given.
pub async fn rewrite_and_verify(
    job: &RewriteJob,
    provider: &dyn ChatProvider,
    oracle: &mut FunctionOracle,
    opts: &DiffOptions,
    store: Option<&RewriteStore>,
    cancel: CancellationToken,
) -> Result<RewriteUnit, RewriteError> {
    let task = job.task();
    let (out, reply) = task.run(provider, cancel).await?;
    let provenance = Provenance {
        author: "model".into(),
        provider: Some(reply.provider.id.clone()),
        model: Some(reply.provider.model.clone()),
        task: "rewrite_function".into(),
        prompt_hash: reply.prompt_hash,
    };
    let unit = verify(job, &out.rust_code, provenance, oracle, opts)?;
    match store {
        Some(s) => s.put_unit(unit),
        None => Ok(unit),
    }
}

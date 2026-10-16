//! The loop for one function: lift (decompile through the registry) -> translate (a provider) ->
//! verify (differential test against the original under emulation) -> record (a versioned
//! [`RewriteUnit`]).

use kraken_agent::ChatProvider;
use kraken_host::backend::CommandBackend;
use kraken_registry::CallContext;
use tokio_util::sync::CancellationToken;

use crate::abi::Signature;
use crate::difftest::{DiffOptions, InputSpec, run_differential};
use crate::error::RewriteError;
use crate::fetch::{FunctionContext, fetch_function};
use crate::oracle::FunctionOracle;
use crate::targets::Target;
use crate::task::{Budget, RewriteTask};
use crate::unit::{CalleeRef, OracleInfo, Provenance, RewriteUnit, UnitSource, UnitStore};
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

/// Differential-tests `rust_code` for `job` against the original and returns the (unstored)
/// record.
pub fn verify(
    job: &RewriteJob,
    rust_code: &str,
    provenance: Provenance,
    oracle: &mut FunctionOracle,
    opts: &DiffOptions,
) -> Result<RewriteUnit, RewriteError> {
    let entry = job.function.elf_vaddr();
    let report = run_differential(oracle, entry, &job.signature, rust_code, &job.inputs, opts)?;
    let callees = job
        .callees
        .iter()
        .map(|c| CalleeRef {
            name: c.name.clone(),
            address: format!("{:#x}", c.address),
            decompile_hash: c.decompile_hash.clone(),
        })
        .collect();
    Ok(RewriteUnit::from_run(
        UnitSource {
            anchor: job.function.anchor(),
            source_decompile_hash: job.function.decompile_hash.clone(),
            callees,
            signature: job.signature.clone(),
            provenance,
            oracle: OracleInfo {
                kind: ORACLE_KIND.to_string(),
                emulator: EMULATOR_PIN.to_string(),
                binary: job.binary.clone(),
                elf_vaddr: entry,
            },
        },
        rust_code.to_string(),
        report,
    ))
}

/// Asks `provider` for a translation, verifies it, and stores the record when `store` is given.
pub async fn rewrite_and_verify(
    job: &RewriteJob,
    provider: &dyn ChatProvider,
    oracle: &mut FunctionOracle,
    opts: &DiffOptions,
    store: Option<&UnitStore>,
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
        Some(s) => s.put(unit),
        None => Ok(unit),
    }
}

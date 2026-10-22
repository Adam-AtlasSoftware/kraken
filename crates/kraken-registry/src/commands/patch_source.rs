//! `patch_from_source` (experimental): turn an edit of a function's decompiled C into the
//! smallest byte patch that makes the machine code do the same, and check it by decompiling the
//! patched bytes again.
//!
//! The command only plans: it returns the patches and how the check went, and stages nothing.
//! Staging is `patch_set`, writing a binary `patch_export`. The work is done by a
//! [`SourcePatchBackend`] (`kraken-rewrite`, which has the model and the metering); attach it
//! with [`Session::with_source_patch`].

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::JobStarted;
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::jobs::JobReporter;
use crate::session::Session;

/// Longest edited source accepted, in bytes.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;
/// Most plan-and-check rounds.
pub const MAX_SOURCE_PATCH_ATTEMPTS: u32 = 4;
/// Rounds when the call does not say.
pub const DEFAULT_SOURCE_PATCH_ATTEMPTS: u32 = 2;

/// Arguments of `patch_from_source`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchFromSourceArgs {
    /// Entry of the function, as `0x...`.
    pub address: Hex64,
    /// The function's decompiled C with the person's edit applied.
    pub source: String,
    /// Plan-and-check rounds (default 2, at most 4): a patch whose check fails is planned again
    /// with what the check saw.
    #[serde(default)]
    pub max_attempts: Option<u32>,
}

/// One planned patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlannedPatch {
    /// Where it goes.
    pub address: Hex64,
    /// The bytes there now, as lower-case hex.
    pub original: String,
    /// The bytes to write, as lower-case hex (same length as `original`).
    pub replacement: String,
    /// What it changes, from the model (untrusted).
    pub explanation: Untrusted<String>,
}

/// How the check of a plan went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourcePatchVerdict {
    /// The patched code decompiles to what the edit asked for.
    Matches,
    /// Part of the edit shows in the patched decompile.
    Partial,
    /// The patched decompile does not show the edit.
    Mismatch,
    /// The patched bytes could not be decompiled again (no second engine on this host, for
    /// example); check the plan yourself.
    Unverified,
}

/// The check of the last plan: the patched bytes decompiled again and compared with the edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourcePatchCheck {
    /// The verdict.
    pub verdict: SourcePatchVerdict,
    /// Why, in a sentence or two (from the model when it judged; untrusted).
    pub reason: Untrusted<String>,
    /// The patched function decompiled again, when that worked (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patched_decompile: Option<Untrusted<String>>,
}

/// Result of a `patch_from_source` job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PatchFromSourceResult {
    /// Entry of the function.
    pub function: Hex64,
    /// The patches, ordered by address; empty when no in-place patch can express the edit.
    pub patches: Vec<PlannedPatch>,
    /// What the plan does, from the model (untrusted).
    pub summary: Untrusted<String>,
    /// The check of the last plan.
    pub check: SourcePatchCheck,
    /// Plan-and-check rounds used.
    pub attempts: u32,
    /// Things to know: patches dropped as invalid, a check that could not run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl PatchFromSourceResult {
    /// Total bytes the plan changes.
    pub fn changed_bytes(&self) -> usize {
        self.patches.iter().map(|p| p.replacement.len() / 2).sum()
    }
}

/// What `patch_from_source` runs on. Implemented by `kraken-rewrite`; attach with
/// [`Session::with_source_patch`].
#[async_trait]
pub trait SourcePatchBackend: Send + Sync {
    /// Refuses before the job starts when today's AI budget is used up (default: no check).
    fn check_budget(&self) -> Result<(), ProtoError> {
        Ok(())
    }

    /// The body of a `patch_from_source` job.
    async fn patch_from_source(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchFromSourceArgs,
        job: &JobReporter,
    ) -> Result<PatchFromSourceResult, ProtoError>;
}

impl std::fmt::Debug for dyn SourcePatchBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourcePatchBackend")
    }
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// Plans a byte patch from an edit of the decompiled C.
pub struct PatchFromSource;

#[async_trait]
impl Command for PatchFromSource {
    type Args = PatchFromSourceArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_from_source",
            "Plan a byte patch from an edit of a function's decompiled C (experimental, job)",
            CommandKind::Job,
            Permission::Safe,
        )
        .doc(
            "Experimental. Give a function's decompiled C with your change made (a constant, a \
             comparison, a branch taken or skipped). The assistant's model plans the smallest \
             in-place byte patch that does the same, the patched bytes are decompiled again to \
             check it, and the job result lists the patches with the check. Nothing is staged: \
             pass the patches to `patch_set`. Best for small, local changes. Sends the \
             decompile and the disassembly to the model provider.\n\
             Example: patch_from_source {\"address\": \"0x401136\", \"source\": \"int f(void)\\n{\\n  return 7;\\n}\"}",
        )
        .details(
            "Uses the assistant's model (`[provider]` in config.toml) and is metered like other \
             AI work. Patches stay inside the function and keep each instruction's length (no \
             code is moved or inserted), so an edit that needs more room comes back with no \
             patches and the reason in `summary`. The check copies the binary with the patches \
             applied into a temporary directory, opens it in a second engine of the project's \
             kind, decompiles the function and has the model compare that with the edit: \
             `matches`, `partial` or `mismatch`; `unverified` when the second engine could not \
             run. A failed check is planned again with what it saw, up to `max_attempts`.",
        )
        .needs(&[Cap::Decompiler, Cap::Disassembler, Cap::Memory])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchFromSourceArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.source_patch()?.clone();
        s.project()?;
        if args.source.trim().is_empty() {
            return Err(invalid(
                "source is empty: give the edited C of the function",
            ));
        }
        if args.source.len() > MAX_SOURCE_BYTES {
            return Err(invalid(format!(
                "source is longer than {MAX_SOURCE_BYTES} bytes; patch a smaller function"
            )));
        }
        if args
            .max_attempts
            .is_some_and(|a| !(1..=MAX_SOURCE_PATCH_ATTEMPTS).contains(&a))
        {
            return Err(invalid(format!(
                "`max_attempts` is between 1 and {MAX_SOURCE_PATCH_ATTEMPTS}"
            )));
        }
        backend.check_budget()?;
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("patch_from_source", move |reporter| async move {
                let out = backend
                    .patch_from_source(&s2, &ctx2, args, &reporter)
                    .await?;
                serde_json::to_value(&out).map_err(|e| {
                    ProtoError::new(ErrorCode::Internal, format!("cannot serialize: {e}"))
                })
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

/// Reads a [`PatchFromSourceResult`] from a finished job's `result`.
pub fn source_patch_result(v: &Value) -> Result<PatchFromSourceResult, ProtoError> {
    serde_json::from_value(v.clone()).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("unexpected patch_from_source result: {e}"),
        )
    })
}

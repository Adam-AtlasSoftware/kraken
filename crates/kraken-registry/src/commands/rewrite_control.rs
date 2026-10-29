//! Human control over rewrite units: reject, unaccept, add a test case, edit a spec, and replay
//! every case (`rewrite_reject`, `rewrite_unaccept`, `rewrite_add_case`, `rewrite_spec_edit`,
//! `rewrite_verify`).
//!
//! Deciding about a unit (reject, unaccept) is reserved for users, like `rewrite_accept`.
//! Adding a case, editing a spec and replaying cases only add evidence, so agents may run them.

use async_trait::async_trait;
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

use super::JobStarted;
use super::rewrite::{CounterexampleView, RewriteSpecResult, UnitStatus};

fn users_only(ctx: &CallContext, what: &str) -> Result<(), ProtoError> {
    if ctx.author.kind == AuthorKind::User {
        Ok(())
    } else {
        Err(ProtoError::new(
            ErrorCode::RejectedHumanPriority,
            format!("{what} is reserved for users; agents cannot do it"),
        ))
    }
}

fn to_value<T: Serialize>(v: &T) -> Result<Value, ProtoError> {
    serde_json::to_value(v)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}")))
}

// ---- rewrite_reject / rewrite_unaccept --------------------------------------------------------

/// Arguments of `rewrite_reject`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteRejectArgs {
    /// Unit id (`ru-...`).
    pub unit: String,
    /// Why, kept in the unit's history.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Arguments of `rewrite_unaccept`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteUnaccept {
    /// Unit id (`ru-...`) of the accepted version.
    pub unit: String,
}

/// What `rewrite_reject` and `rewrite_unaccept` did to a version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UnitChangeOut {
    /// The version's status now (`failed` after a reject, `verified` after an unaccept).
    pub status: UnitStatus,
    /// The unit version.
    pub unit: String,
    /// Function entry.
    pub address: Hex64,
    /// Version number.
    pub version: u32,
}

/// Rejects a version of a unit.
pub struct RewriteReject;

#[async_trait]
impl Command for RewriteReject {
    type Args = RewriteRejectArgs;
    type Output = UnitChangeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_reject",
            "Reject a rewrite unit version so it is never exported (users only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "People only. Marks a version `failed` with your reason in its history, for a \
             translation that passes the tests but is wrong or unwanted. The version stays in \
             the history. An accepted version must be unaccepted first.\n\
             Example: rewrite_reject {\"unit\": \"ru-12\", \"reason\": \"drops the error path\"}",
        )
        .details(
            "Sets the version's status to `failed` and records who rejected it and why in \
             the unit's event list. It does not delete anything: a later `rewrite_function` \
             run makes a new version. Refused for an accepted version (use `rewrite_unaccept`) \
             and for one that already failed. Agents cannot reject.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteRejectArgs,
    ) -> Result<UnitChangeOut, ProtoError> {
        users_only(ctx, "rejecting a rewrite unit")?;
        s.rewrite()?.reject(s, ctx, args).await
    }
}

/// Takes back the acceptance of a unit.
pub struct RewriteUnacceptCmd;

#[async_trait]
impl Command for RewriteUnacceptCmd {
    type Args = RewriteUnaccept;
    type Output = UnitChangeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_unaccept",
            "Take back the acceptance of a rewrite unit (users only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "People only. The accepted version goes back to `verified` and drops out of the \
             next export; the function has no accepted version until you accept one again.\n\
             Example: rewrite_unaccept {\"unit\": \"ru-12\"}",
        )
        .details(
            "Reverses `rewrite_accept`. Callers that reused the accepted unit as a callee \
             notice at their next export, which refuses a unit whose reused callee is no longer \
             accepted. Agents cannot unaccept.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteUnaccept,
    ) -> Result<UnitChangeOut, ProtoError> {
        users_only(ctx, "unaccepting a rewrite unit")?;
        s.rewrite()?.unaccept(s, ctx, args).await
    }
}

// ---- rewrite_add_case / rewrite_verify ---------------------------------------------------------

/// Arguments of `rewrite_add_case`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteAddCaseArgs {
    /// Unit id (`ru-...`).
    pub unit: String,
    /// One value per parameter: a number or "0x.." string for an integer, {"hex": "00ff"} or
    /// {"text": "abc"} for a buffer, a number for a double, "ascending" or "descending" for a
    /// function pointer.
    pub args: Vec<Value>,
    /// A note kept with the case.
    #[serde(default)]
    pub note: Option<String>,
}

/// Arguments of `rewrite_verify`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteVerifyArgs {
    /// Unit id (`ru-...`).
    pub unit: String,
}

/// What the cases of a unit reach in the original function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageView {
    /// Basic blocks of the function.
    pub blocks: u32,
    /// Blocks at least one case ran.
    pub hit: u32,
    /// Start addresses of the blocks no case reached.
    pub missed: Vec<Hex64>,
    /// Cases replayed to find out.
    pub cases: u32,
}

/// Result of a finished `rewrite_verify` or `rewrite_add_case` job (the `result` of
/// `job_status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteVerifyResult {
    /// The unit version.
    pub unit: String,
    /// Function entry.
    pub address: Hex64,
    /// Version number.
    pub version: u32,
    /// Status after the replay (a disagreement turns the version `failed`).
    pub status: UnitStatus,
    /// `pass`, `fail`, `rejected` or `inconclusive`.
    pub verdict: String,
    /// Why, for `rejected` and `inconclusive` (model- or binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_detail: Option<Untrusted<String>>,
    /// Cases replayed on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Cases the oracle could not evaluate (kept from the stored run).
    pub skipped: u32,
    /// The smallest counterexample, for a failed verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterexample: Option<CounterexampleView>,
    /// What the cases reach; absent when the emulator could not be set up for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<CoverageView>,
    /// Why there is no coverage (the oracle needs the SLEIGH spec files).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_note: Option<String>,
    /// Cases a person added to this version.
    pub user_cases: u32,
    /// How the translation was confined while it ran.
    pub sandbox: String,
}

/// Adds a test case to a unit and replays all of them.
pub struct RewriteAddCase;

#[async_trait]
impl Command for RewriteAddCase {
    type Args = RewriteAddCaseArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_add_case",
            "Add a test case to a rewrite unit and replay all its cases (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Adds an input you chose, runs the original under emulation to get its expected \
             result, and replays every case of the version on the Rust code in the sandbox. \
             A disagreement turns the version `failed` with the case as counterexample. \
             Returns a `job_id`; no model is called.\n\
             Example: rewrite_add_case {\"unit\": \"ru-12\", \"args\": [0, {\"text\": \"abc\"}]}",
        )
        .details(
            "The values are matched to the unit's parameters (see `args`). The case is stored \
             with the version and marked as yours; the replay then covers the generated cases \
             and yours. It needs the same host as `rewrite_function` (Linux with Landlock for \
             the sandbox, the SLEIGH spec files for the emulator). It adds evidence only, so \
             agents may use it; an accepted version that now disagrees is unaccepted and \
             marked `failed`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAddCaseArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        s.project()?;
        if args.args.len() > 16 {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "a case has at most 16 arguments",
            ));
        }
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_add_case", move |reporter| async move {
                let out = backend.add_case(&s2, &ctx2, args, &reporter).await?;
                to_value(&out)
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

/// Replays every case of a unit.
pub struct RewriteVerify;

#[async_trait]
impl Command for RewriteVerify {
    type Args = RewriteVerifyArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_verify",
            "Replay all stored cases of a rewrite unit and measure their coverage (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Rebuilds the stored Rust in the sandbox and replays every stored case, the \
             generated ones and those added with `rewrite_add_case`, against the oracle's \
             recorded results. Also measures which basic blocks of the original the cases run. \
             A disagreement turns the version `failed`. Returns a `job_id`; no model is \
             called.\n\
             Example: rewrite_verify {\"unit\": \"ru-12\"}",
        )
        .details(
            "Use it after the emulator or the sandbox changed, or to see how much of the \
             function the cases reach (`coverage` of the result: blocks, hit, and the start \
             addresses of the missed blocks, which a case from `rewrite_add_case` can target). \
             Coverage needs the SLEIGH spec files; without them the replay still runs and \
             `coverage_note` says why there is none. The result is stored with the version.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteVerifyArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        s.project()?;
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_verify", move |reporter| async move {
                let out = backend.verify(&s2, &ctx2, args, &reporter).await?;
                to_value(&out)
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

// ---- rewrite_spec_edit -------------------------------------------------------------------------

/// Arguments of `rewrite_spec_edit`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteSpecEditArgs {
    /// The function (any address inside it).
    pub address: Hex64,
    /// The new spec: the same sections as a written one (Purpose, Inputs, Outputs, Side effects,
    /// Invariants, Open questions), every fact citing `[@0x...]`.
    pub markdown: String,
}

/// Stores an edited spec.
pub struct RewriteSpecEdit;

#[async_trait]
impl Command for RewriteSpecEdit {
    type Args = RewriteSpecEditArgs;
    type Output = RewriteSpecResult;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_spec_edit",
            "Replace a function's behavioural spec with an edited one",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Stores your edit of a function's spec as its newest spec; `rewrite_function` with \
             `mode: spec` reimplements from it. The text is checked like a written spec: all \
             sections in order, every fact cited, every citation an address of the function \
             or its callees. The old spec stays in the history.\n\
             Example: rewrite_spec_edit {\"address\": \"0x401136\", \"markdown\": \"## Purpose\\n...\"}",
        )
        .details(
            "Get the current text from `rewrite_unit` (`spec.markdown`), change it and send it \
             back whole. The edit is stored as a new spec by `user` / `edit` and is the one \
             spec mode uses while the function's decompile and its callees' stay as they \
             were. No model is called and nothing runs. It adds a spec and replaces none, so \
             agents may use it.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecEditArgs,
    ) -> Result<RewriteSpecResult, ProtoError> {
        if args.markdown.len() > 64 * 1024 {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "a spec is at most 64 KiB",
            ));
        }
        s.rewrite()?.spec_edit(s, ctx, args).await
    }
}

// ---- rewrite_check -----------------------------------------------------------------------------

/// How a prerequisite stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrereqLevel {
    /// In place.
    Ok,
    /// Works, with a limit worth knowing.
    Warn,
    /// The rewrite cannot run until this is fixed.
    Blocked,
}

/// One prerequisite of the rewrite workflow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Prereq {
    /// `sandbox`, `toolchain`, `specs` or `program`.
    pub id: String,
    /// Short name for a list.
    pub title: String,
    /// How it stands.
    pub level: PrereqLevel,
    /// What was found.
    pub detail: String,
    /// What to do about it, for `warn` and `blocked`; a command to run when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// Result of `rewrite_check`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteCheckOut {
    /// The prerequisites, in the order to fix them.
    pub checks: Vec<Prereq>,
    /// True when no check is `blocked`.
    pub ready: bool,
}

/// Arguments of `rewrite_check` (none).
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteCheckArgs {}

/// Checks what the rewrite workflow needs on this host.
pub struct RewriteCheck;

#[async_trait]
impl Command for RewriteCheck {
    type Args = RewriteCheckArgs;
    type Output = RewriteCheckOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_check",
            "Check that this host can run the Rust rewrite workflow",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Lists what the rewrite needs and what is missing: the sandbox (Linux with Landlock), \
             the Rust toolchain, the SLEIGH spec files the emulation oracle needs, and whether \
             the program is a kind that can be rewritten. Each row has a level and, when \
             something is wrong, a fix. Run it before `rewrite_function`.\n\
             Example: rewrite_check {}",
        )
        .details(
            "Reads the host and the open program's header only; nothing is built or run. The \
             rows are `sandbox`, `toolchain` (`rustc` and `cargo` resolve and report a version), \
             `specs` (the SLEIGH files for the program's architecture can be found: \
             `KRAKEN_NATIVE_SPECS`, the tree `cargo xtask native-sla` builds, a release's \
             `share/kraken/native-sla`, or a Ghidra install; without them translations are only \
             compiled, not compared) and `program` (Linux ELF for x86-64 today).",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        _args: RewriteCheckArgs,
    ) -> Result<RewriteCheckOut, ProtoError> {
        s.rewrite()?.check(s, ctx).await
    }
}

//! The `rewrite_*` commands (ADR 0013).
//!
//! The commands, their arguments and their results live here so that the CLI, MCP server, GUI and
//! generated docs see them like every other command. The work is done by a [`RewriteBackend`]
//! attached to the [`Session`] (`kraken-rewrite` implements it); without one the commands answer
//! `unsupported`. This keeps the emulator, the sandbox and the SQLite store of generated code out
//! of this crate, the same way `EngineFactory` keeps Ghidra out of it.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext};
use crate::jobs::JobReporter;
use crate::session::Session;

use super::JobStarted;

/// How a function is rewritten (decision 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RewriteMode {
    /// Faithful translation of the decompile, checked against the original machine code
    /// (strangler pattern).
    #[default]
    Incremental,
    /// Reimplementation from a cited behavioural spec (written first when none is stored); the
    /// model does not see the function's decompile, only the spec.
    Spec,
}

impl RewriteMode {
    /// The name stored in rewrite.sqlite.
    pub fn as_str(self) -> &'static str {
        match self {
            RewriteMode::Incremental => "incremental",
            RewriteMode::Spec => "spec",
        }
    }
}

/// Where a rewrite unit stands (ADR 0013).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnitStatus {
    /// In the plan; nothing translated yet.
    Planned,
    /// Rust code exists but no passing verdict does (not run, or inconclusive).
    Translated,
    /// The differential test passed.
    Verified,
    /// The differential test found a difference, or the code was refused or did not compile.
    Failed,
    /// A user accepted this verified version for export.
    Accepted,
}

impl UnitStatus {
    /// The name stored in rewrite.sqlite.
    pub fn as_str(self) -> &'static str {
        match self {
            UnitStatus::Planned => "planned",
            UnitStatus::Translated => "translated",
            UnitStatus::Verified => "verified",
            UnitStatus::Failed => "failed",
            UnitStatus::Accepted => "accepted",
        }
    }

    /// Parses a stored name.
    pub fn parse(s: &str) -> Option<UnitStatus> {
        Some(match s {
            "planned" => UnitStatus::Planned,
            "translated" => UnitStatus::Translated,
            "verified" => UnitStatus::Verified,
            "failed" => UnitStatus::Failed,
            "accepted" => UnitStatus::Accepted,
            _ => return None,
        })
    }
}

/// What a plan or a spec covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanScope {
    /// One function (with its callees for a plan).
    Function,
    /// Every function of the program.
    #[default]
    All,
}

/// Why a function needs more than a plain translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlanFlag {
    /// Calls a library function the oracle has no stub for (for example `malloc`), directly or
    /// through its callees; the differential test can only be inconclusive until one exists.
    NeedsStubs,
    /// Reads or writes global data; the globals are not inputs of the test.
    UsesGlobals,
    /// Issues a system call directly.
    UsesSyscalls,
    /// Part of a recursive group; the group is translated together.
    Recursive,
}

// ---- rewrite_plan ----------------------------------------------------------------------------

/// Arguments of `rewrite_plan`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewritePlanArgs {
    /// `all` (default) plans the whole program and stores the plan; `function` plans one function
    /// with the callees it needs, leaves first.
    #[serde(default)]
    pub scope: PlanScope,
    /// The function (any address inside it) for `scope: function`.
    #[serde(default)]
    pub address: Option<Hex64>,
    /// Cursor from the previous page's `next_cursor` (pages of the stored plan).
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size (default 100, at most 200).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Most functions a new `all` plan examines (default 2000, at most 20000).
    #[serde(default)]
    pub max_functions: Option<u32>,
}

/// One function of a plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PlanEntry {
    /// Position in the rewrite order, from 0: callees come before their callers.
    pub order: u32,
    /// Entry address.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
    /// Functions of one recursive group share a group number and are translated together.
    pub group: u32,
    /// Number of functions in the group.
    pub group_size: u32,
    /// Entries of the functions it calls that are part of the program (not imports).
    pub callees: Vec<Hex64>,
    /// Imported library functions it calls directly.
    pub imports: Vec<Untrusted<String>>,
    /// Imports, direct or through callees, that the oracle has no stub for.
    pub needs_stubs: Vec<Untrusted<String>>,
    /// Why it needs care.
    pub flags: Vec<PlanFlag>,
    /// Where its rewrite unit stands.
    pub status: UnitStatus,
}

/// Result of `rewrite_plan`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewritePlanOut {
    /// What was planned.
    pub scope: PlanScope,
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// Functions the engine lists.
    pub functions_total: u64,
    /// Functions in the plan.
    pub functions_planned: u64,
    /// Import thunks left out (they are the program's external calls, not code to rewrite).
    pub skipped_imports: u64,
    /// Compiler and loader glue left out (`_start`, `_init`, `frame_dummy`, ...).
    pub skipped_runtime: u64,
    /// Number of groups (strongly connected components).
    pub groups: u32,
    /// True when `max_functions` cut the program short.
    pub truncated: bool,
    /// This page of the plan.
    pub entries: Vec<PlanEntry>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Plans the rewrite order.
pub struct RewritePlan;

#[async_trait]
impl Command for RewritePlan {
    type Args = RewritePlanArgs;
    type Output = RewritePlanOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_plan",
            "Plan the rewrite order: call graph bottom-up, with functions that need stubs flagged",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Orders the program's functions so that callees come before their callers; functions \
             that call each other form one group and are translated together. Import thunks and \
             compiler glue are left out. Each entry lists the imports it calls and flags what the \
             differential test cannot cover yet: `needs_stubs` (a library call the oracle does \
             not model, directly or through a callee, so the test would be inconclusive), \
             `uses_globals` (global data that is not an input of the test), `uses_syscalls` and \
             `recursive`. The plan for `scope: all` is stored in `rewrite.sqlite` in the project \
             directory (that is the only thing this command writes); pass the returned \
             `next_cursor` to read further pages of it. `scope: function` returns one function \
             and the callees it needs, leaves first, without storing anything. The global and \
             syscall flags come from references and call targets, so they are a guide, not a \
             proof.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewritePlanArgs,
    ) -> Result<RewritePlanOut, ProtoError> {
        if args.scope == PlanScope::Function && args.address.is_none() {
            return Err(invalid("`scope: function` needs `address`"));
        }
        s.rewrite()?.plan(s, ctx, args).await
    }
}

// ---- rewrite_status --------------------------------------------------------------------------

/// Arguments of `rewrite_status`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteStatusArgs {
    /// Cursor from the previous page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size (default 100, at most 200).
    #[serde(default)]
    pub limit: Option<u32>,
    /// Decompile every function that has a unit (and the callees its versions were made from)
    /// first, so `stale` is current. Without it `stale` reflects what earlier commands saw.
    #[serde(default)]
    pub refresh: bool,
}

/// Units per status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusCounts {
    /// In the plan, nothing translated yet.
    pub planned: u32,
    /// Translated, not verified.
    pub translated: u32,
    /// Verified, not accepted.
    pub verified: u32,
    /// Failed verification.
    pub failed: u32,
    /// Accepted for export.
    pub accepted: u32,
}

/// One row of `rewrite_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UnitRow {
    /// Id of the newest version (`ru-...`); empty when nothing was translated. Pass it to
    /// `rewrite_unit` or `rewrite_accept`.
    #[serde(default)]
    pub unit: String,
    /// Position in the plan, if the function is in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order: Option<u32>,
    /// Entry address.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
    /// Status.
    pub status: UnitStatus,
    /// Newest version number (0 when nothing was translated).
    pub version: u32,
    /// Accepted version, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_version: Option<u32>,
    /// Mode of the newest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<RewriteMode>,
    /// Verdict of the newest version: `pass`, `fail`, `rejected` or `inconclusive`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
    /// Test cases that ran on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Counterexamples stored with the verdict.
    pub counterexamples: u32,
    /// Provider that wrote the newest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model that wrote the newest version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Why it needs care, from the plan.
    pub flags: Vec<PlanFlag>,
    /// True when the decompile of the function, or of a callee its relevant version was made
    /// from, changed since that version was made. The relevant version is the accepted one, or
    /// the newest.
    #[serde(default)]
    pub stale: bool,
}

/// Result of `rewrite_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteStatusOut {
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// True when a plan is stored (rows then follow plan order).
    pub plan_present: bool,
    /// Units per status over the whole program.
    pub counts: StatusCounts,
    /// This page of rows.
    pub units: Vec<UnitRow>,
    /// Cursor for the next page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Progress of the rewrite.
pub struct RewriteStatus;

#[async_trait]
impl Command for RewriteStatus {
    type Args = RewriteStatusArgs;
    type Output = RewriteStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_status",
            "Show rewrite progress: counts per status and one row per function",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Reads `rewrite.sqlite`. Rows follow the stored plan (run `rewrite_plan` first); \
             functions with a unit that are not in the plan come last. `status` is one of \
             `planned`, `translated`, `verified`, `failed`, `accepted`. `stale` marks a function \
             whose decompile, or a callee's, changed since the version that counts (the \
             accepted one, else the newest) was made; it reflects what earlier commands \
             saw, and `refresh` decompiles the functions that have units first.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteStatusArgs,
    ) -> Result<RewriteStatusOut, ProtoError> {
        s.rewrite()?.status(s, ctx, args).await
    }
}

// ---- rewrite_unit ----------------------------------------------------------------------------

/// Arguments of `rewrite_unit`: the function by `address` (any address inside it) or by the id of
/// one of its unit versions; exactly one of the two.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteUnitArgs {
    /// The function (any address inside it).
    #[serde(default)]
    pub address: Option<Hex64>,
    /// A unit version id from `rewrite_function` or `rewrite_status` (`ru-...`); selects the
    /// function that version belongs to.
    #[serde(default)]
    pub unit: Option<String>,
}

/// One stored version of a function, with its code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UnitVersionView {
    /// Id of this version (`ru-...`).
    pub unit: String,
    /// Version number for the function, from 1.
    pub version: u32,
    /// How it was made.
    pub mode: RewriteMode,
    /// Status of this version.
    pub status: UnitStatus,
    /// True when this is the accepted version.
    pub accepted: bool,
    /// `pass`, `fail`, `rejected` or `inconclusive`.
    pub verdict: String,
    /// Why, for `rejected` and `inconclusive` (model- or binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_detail: Option<Untrusted<String>>,
    /// Cases that ran on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Cases the oracle could not evaluate.
    pub skipped: u32,
    /// The smallest counterexample, for a failed verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterexample: Option<CounterexampleView>,
    /// The generated Rust (model-derived; untrusted).
    pub rust_code: Untrusted<String>,
    /// The Rust declaration the code was checked at.
    pub signature: String,
    /// Kind of oracle that checked it, for example `icicle-emu/x86-64-sleigh`.
    pub oracle_kind: String,
    /// How the generated code was confined while it ran.
    pub sandbox: String,
    /// When the version was stored (seconds since the Unix epoch).
    pub created: u64,
    /// Provider id.
    pub provider: String,
    /// Model name.
    pub model: String,
    /// True when the function's decompile, or a callee's it was made from, changed since.
    #[serde(default)]
    pub stale: bool,
    /// Why it is stale (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<Untrusted<String>>,
    /// Which translation attempt of its run this is, from 1.
    #[serde(default)]
    pub attempt: u32,
    /// The version whose failure this attempt answers, for a repair attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_of: Option<u32>,
    /// Program functions this version calls as already accepted Rust instead of translating
    /// them again (their Rust names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reused_callees: Vec<String>,
}

/// The stored spec of a function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UnitSpecView {
    /// Id of the stored spec.
    pub spec: u64,
    /// The spec (model-derived Markdown; citations are `[@0xADDR]`).
    pub markdown: Untrusted<String>,
    /// Every address the spec cites.
    pub citations: Vec<Hex64>,
    /// Facts (cited bullets) in the spec.
    pub facts: u32,
    /// Provider id.
    pub provider: String,
    /// Model name.
    pub model: String,
}

/// Result of `rewrite_unit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteUnitOut {
    /// Function entry.
    pub address: Hex64,
    /// Every stored version, oldest first (empty when the function was never translated).
    pub versions: Vec<UnitVersionView>,
    /// The function's stored spec, if one was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<UnitSpecView>,
}

/// The stored versions of one function.
pub struct RewriteUnit;

#[async_trait]
impl Command for RewriteUnit {
    type Args = RewriteUnitArgs;
    type Output = RewriteUnitOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_unit",
            "Show the stored Rust versions of one function, with code, verdicts and its spec",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Reads `rewrite.sqlite`; nothing is generated or run. Give the function by `address` \
             or by the id of one of its versions (`unit`). `versions` lists every stored version, \
             oldest first, with the Rust code, the signature it was checked at, the verdict and a \
             counterexample for a failed one, and which version is accepted. `spec` is the \
             function's newest stored spec, when `rewrite_spec` wrote one. The code and the spec \
             are model-written and untrusted.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteUnitArgs,
    ) -> Result<RewriteUnitOut, ProtoError> {
        if args.address.is_some() == args.unit.is_some() {
            return Err(invalid("give exactly one of `address` and `unit`"));
        }
        s.rewrite()?.unit(s, ctx, args).await
    }
}

// ---- rewrite_function ------------------------------------------------------------------------

/// Arguments of `rewrite_function`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteFunctionArgs {
    /// The function (any address inside it).
    pub address: Hex64,
    /// `incremental` (default) translates the decompile; `spec` reimplements from the function's
    /// spec, writing it first if none is stored.
    #[serde(default)]
    pub mode: RewriteMode,
    /// Seed of the random test cases (default fixed, so runs are reproducible).
    #[serde(default)]
    pub seed: Option<u64>,
    /// Random test cases to run (default 200, at most 2000).
    #[serde(default)]
    pub cases: Option<u32>,
    /// Most translation attempts (default 3, at most 8). After an attempt that does not compile,
    /// is refused by the source lint or disagrees with the original, the compiler output or the
    /// smallest counterexample goes back to the model for another attempt. Every attempt is
    /// stored as a version. 1 turns the repair loop off.
    #[serde(default)]
    pub max_attempts: Option<u32>,
}

/// A case on which the translation and the original disagreed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CounterexampleView {
    /// The arguments, rendered (`42`, `buf[8]=00ff...`).
    pub args: Vec<String>,
    /// What differed, derived from the original's output (binary-derived).
    pub differences: Vec<Untrusted<String>>,
}

/// Result of a finished `rewrite_function` job (the `result` of `job_status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteFunctionResult {
    /// Id of the stored unit version.
    pub unit: String,
    /// Function entry.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
    /// Version number for this function.
    pub version: u32,
    /// Mode used.
    pub mode: RewriteMode,
    /// Status after verification.
    pub status: UnitStatus,
    /// `pass`, `fail`, `rejected` or `inconclusive`.
    pub verdict: String,
    /// Why, for `rejected` and `inconclusive` (model- or binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_detail: Option<Untrusted<String>>,
    /// Cases that ran on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Cases the oracle could not evaluate.
    pub skipped: u32,
    /// The smallest counterexample, for a failed verdict.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterexample: Option<CounterexampleView>,
    /// The Rust declaration the code was checked at.
    pub rust_prototype: String,
    /// How the generated code was confined.
    pub sandbox: String,
    /// Provider id.
    pub provider: String,
    /// Model name.
    pub model: String,
    /// What the model said it assumed (model-derived).
    pub assumptions: Vec<Untrusted<String>>,
    /// What the model said it could not translate (model-derived).
    pub unsupported: Vec<Untrusted<String>>,
    /// Translation attempts made (each is stored as a version; this result is the last).
    #[serde(default = "one")]
    pub attempts: u32,
    /// Rust names of accepted callees the translation calls instead of re-translating.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reused_callees: Vec<String>,
}

fn one() -> u32 {
    1
}

/// Translates and verifies one function.
pub struct RewriteFunction;

#[async_trait]
impl Command for RewriteFunction {
    type Args = RewriteFunctionArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_function",
            "Translate one function to Rust and verify it against the original (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Decompiles the function, asks the configured provider (`[provider]` in config.toml) \
             for a Rust translation behind an explicit `extern \"C\"` signature, builds it and \
             runs it against the original machine code under emulation on seeded inputs, and \
             stores the result as a new version of the function's rewrite unit in \
             `rewrite.sqlite`. The job result is a `RewriteFunctionResult`; a wrong translation \
             is a `failed` unit with a minimal counterexample, not an error. The generated code \
             is untrusted: it is built and run only inside the sandbox (read-only file system, \
             no network, resource limits), and the command refuses to run at all when the host \
             cannot enforce it (Linux with Landlock today). That is why it is `mutating` and not \
             `dangerous`. It adds artifacts only and never edits the program; accepting a unit is \
             a separate, users-only step (`rewrite_accept`). It sends decompiled code to the \
             provider. When an attempt does not compile, is refused by the source lint or \
             disagrees with the original, the compiler output or the smallest counterexample is \
             sent back for another attempt, up to `max_attempts` (default 3); every attempt is a \
             stored version. Program callees that already have an accepted, current unit are \
             called as Rust instead of being translated again.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteFunctionArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        s.project()?;
        if args.cases.is_some_and(|c| c > 2000) {
            return Err(invalid("`cases` is at most 2000"));
        }
        if args.max_attempts.is_some_and(|a| !(1..=8).contains(&a)) {
            return Err(invalid("`max_attempts` is between 1 and 8"));
        }
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_function", move |reporter| async move {
                let out = backend.function(&s2, &ctx2, args, &reporter).await?;
                to_value(&out)
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

// ---- rewrite_accept --------------------------------------------------------------------------

/// Arguments of `rewrite_accept`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteAcceptArgs {
    /// Unit id from `rewrite_function` or `rewrite_status` (`ru-...`).
    pub unit: String,
}

/// Result of `rewrite_accept`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteAcceptOut {
    /// Always `accepted`.
    pub status: String,
    /// The unit version.
    pub unit: String,
    /// Function entry.
    pub address: Hex64,
    /// Version number.
    pub version: u32,
    /// The version that was accepted before, if this replaced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaced_version: Option<u32>,
}

/// Accepts a verified unit.
pub struct RewriteAccept;

#[async_trait]
impl Command for RewriteAccept {
    type Args = RewriteAcceptArgs;
    type Output = RewriteAcceptOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_accept",
            "Accept a verified rewrite unit for export (users only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Moves a `verified` unit version to `accepted`; only accepted versions are exported. \
             A function has one accepted version: accepting another replaces it. Unverified and \
             failed versions are refused. Agents cannot accept; they can only produce units.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError> {
        if ctx.author.kind != AuthorKind::User {
            return Err(ProtoError::new(
                ErrorCode::RejectedHumanPriority,
                "accepting a rewrite unit is reserved for users; agents cannot accept",
            ));
        }
        s.rewrite()?.accept(s, ctx, args).await
    }
}

// ---- rewrite_spec ----------------------------------------------------------------------------

/// Arguments of `rewrite_spec`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteSpecArgs {
    /// `function` for one function (with `address`), `all` for the whole program.
    #[serde(default)]
    pub scope: PlanScope,
    /// The function (any address inside it) for `scope: function`.
    #[serde(default)]
    pub address: Option<Hex64>,
    /// For `scope: all`, the most functions the spec is written from, in plan order
    /// (default 30, at most 100).
    #[serde(default)]
    pub max_functions: Option<u32>,
}

/// Result of a finished `rewrite_spec` job (the `result` of `job_status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteSpecResult {
    /// Id of the stored spec.
    pub spec: u64,
    /// What it covers.
    pub scope: PlanScope,
    /// The function, for `scope: function`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// Functions the spec was written from.
    pub functions: u32,
    /// Facts (cited bullets) in the spec.
    pub facts: u32,
    /// Every address the spec cites.
    pub citations: Vec<Hex64>,
    /// The spec (model-derived Markdown; citations are `[@0xADDR]`).
    pub markdown: Untrusted<String>,
    /// Provider id.
    pub provider: String,
    /// Model name.
    pub model: String,
}

/// Writes a behavioural spec.
pub struct RewriteSpec;

#[async_trait]
impl Command for RewriteSpec {
    type Args = RewriteSpecArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_spec",
            "Write a cited behavioural spec of a function or the program (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "First half of spec-then-reimplement. The provider writes Markdown with the fixed \
             headings Purpose, Inputs, Outputs, Side effects, Invariants and Open questions; \
             every fact must cite an address `[@0x...]` that appears in the evidence, and the \
             reply is rejected otherwise. The spec is stored in `rewrite.sqlite` and used by \
             `rewrite_function` with `mode: spec`. It runs no generated code. It sends decompiled \
             code to the provider.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        s.project()?;
        if args.scope == PlanScope::Function && args.address.is_none() {
            return Err(invalid("`scope: function` needs `address`"));
        }
        if args.max_functions.is_some_and(|m| m == 0 || m > 100) {
            return Err(invalid("`max_functions` must be 1 to 100"));
        }
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s.jobs().spawn("rewrite_spec", move |reporter| async move {
            let out = backend.spec(&s2, &ctx2, args, &reporter).await?;
            to_value(&out)
        });
        Ok(JobStarted { job_id: id.0 })
    }
}

// ---- rewrite_export --------------------------------------------------------------------------

/// Arguments of `rewrite_export`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteExportArgs {
    /// Directory to write the Cargo workspace to. Relative paths are inside the project
    /// directory; `..` is not allowed. It must be empty, absent, or an earlier export. Writing
    /// outside the project directory asks for approval.
    pub dir: String,
    /// Crate name prefix (default: the binary's file name, sanitised).
    #[serde(default)]
    pub name: Option<String>,
    /// Build the generated workspace in the sandbox before reporting success (default true).
    #[serde(default)]
    pub build: Option<bool>,
}

/// Coverage of an export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportCoverage {
    /// Accepted units exported.
    pub accepted: u32,
    /// Functions in the stored plan (0 without one).
    pub planned: u32,
    /// Functions the engine lists.
    pub functions_total: u64,
}

/// Result of a finished `rewrite_export` job (the `result` of `job_status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteExportResult {
    /// The directory written.
    pub dir: String,
    /// Crates in the workspace: the library and the FFI shim.
    pub crates: Vec<String>,
    /// Exported `extern "C"` symbols, one per accepted unit.
    pub symbols: Vec<String>,
    /// True when the workspace was built in the sandbox and its symbol table matches `symbols`.
    pub built: bool,
    /// How the build was confined (`none` when `build` was off).
    pub sandbox: String,
    /// Coverage.
    pub coverage: ExportCoverage,
    /// The README written next to the workspace manifest. The path embeds the name of the
    /// analysed binary, so it is marked untrusted.
    pub readme: Untrusted<String>,
}

/// Resolved request handed to the backend.
#[derive(Debug, Clone)]
pub struct ExportRequest {
    /// Target directory, absolute.
    pub dir: PathBuf,
    /// Crate name prefix, if given.
    pub name: Option<String>,
    /// Whether to build in the sandbox.
    pub build: bool,
}

/// Writes the accepted units as a Cargo workspace.
pub struct RewriteExport;

#[async_trait]
impl Command for RewriteExport {
    type Args = RewriteExportArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_export",
            "Export accepted units as a Cargo workspace with an FFI shim (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Writes a workspace with two crates: a library holding the accepted units, one module \
             per function, and an FFI shim crate that exposes one `extern \"C\"` function per \
             unit with the original name and signature, plus a README with the coverage and how \
             to link the shim in place of the originals (strangler pattern: functions not yet \
             rewritten keep running from the original binary). With `build` (the default) the \
             workspace is built in the sandbox and its exported symbols are checked against the \
             units; the export fails if that does not hold, leaving the files for inspection. \
             Writing outside the project directory asks for approval first, as a dangerous \
             command does; inside it the command is `mutating`. Only accepted units are \
             exported.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteExportArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        let project = s.project()?;
        let build = args.build.unwrap_or(true);
        if build {
            backend.require_sandbox()?;
        }
        let dir = resolve_export_dir(project.dir(), &args.dir)?;
        if !is_inside(project.dir(), &dir) {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "rewrite_export".into(),
                    summary: format!(
                        "write the exported workspace outside the project directory, to {}",
                        dir.display()
                    ),
                    args: serde_json::json!({ "dir": dir.display().to_string() }),
                    author: ctx.author.clone(),
                    surface: ctx.surface,
                })
                .await;
            if let ApprovalDecision::Deny { reason } = decision {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!("approval denied: {reason}"),
                )
                .with_details(serde_json::json!({ "approval": "denied" })));
            }
        }
        let request = ExportRequest {
            dir,
            name: args.name,
            build,
        };
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_export", move |reporter| async move {
                let out = backend.export(&s2, &ctx2, request, &reporter).await?;
                to_value(&out)
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

// ---- the backend -----------------------------------------------------------------------------

/// What the `rewrite_*` commands run on. Implemented by `kraken-rewrite`; attach with
/// [`Session::with_rewrite`].
#[async_trait]
pub trait RewriteBackend: Send + Sync {
    /// Fails with a clear message when generated code cannot run confined on this host.
    fn require_sandbox(&self) -> Result<(), ProtoError>;

    /// `rewrite_plan`.
    async fn plan(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewritePlanArgs,
    ) -> Result<RewritePlanOut, ProtoError>;

    /// `rewrite_status`.
    async fn status(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteStatusArgs,
    ) -> Result<RewriteStatusOut, ProtoError>;

    /// `rewrite_unit` (exactly one of `address` and `unit` is set).
    async fn unit(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteUnitArgs,
    ) -> Result<RewriteUnitOut, ProtoError>;

    /// The body of a `rewrite_function` job.
    async fn function(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteFunctionArgs,
        job: &JobReporter,
    ) -> Result<RewriteFunctionResult, ProtoError>;

    /// `rewrite_accept` (the caller is already known to be a user).
    async fn accept(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError>;

    /// The body of a `rewrite_spec` job.
    async fn spec(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteSpecArgs,
        job: &JobReporter,
    ) -> Result<RewriteSpecResult, ProtoError>;

    /// The body of a `rewrite_export` job (the directory is resolved and approved).
    async fn export(
        &self,
        s: &Session,
        ctx: &CallContext,
        request: ExportRequest,
        job: &JobReporter,
    ) -> Result<RewriteExportResult, ProtoError>;
}

impl std::fmt::Debug for dyn RewriteBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RewriteBackend")
    }
}

fn invalid(msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn to_value<T: Serialize>(v: &T) -> Result<Value, ProtoError> {
    serde_json::to_value(v)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}")))
}

/// Resolves the `dir` argument of `rewrite_export`: absolute as given, relative to the project
/// directory otherwise; `..` is refused.
fn resolve_export_dir(project_dir: &Path, arg: &str) -> Result<PathBuf, ProtoError> {
    if arg.trim().is_empty() || arg.contains('\0') {
        return Err(invalid("`dir` must be a path"));
    }
    let p = Path::new(arg);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(invalid("`dir` may not contain `..`"));
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        project_dir.join(p)
    };
    if abs.parent().is_none() {
        return Err(invalid("`dir` may not be a file system root"));
    }
    Ok(abs)
}

/// True when `target` is inside `base`, following symlinks of the deepest existing ancestor.
pub fn is_inside(base: &Path, target: &Path) -> bool {
    let canon = |p: &Path| -> Option<PathBuf> {
        let mut tail: Vec<std::ffi::OsString> = Vec::new();
        let mut cur = p.to_path_buf();
        loop {
            if let Ok(c) = std::fs::canonicalize(&cur) {
                let mut out = c;
                for t in tail.iter().rev() {
                    out.push(t);
                }
                return Some(out);
            }
            tail.push(cur.file_name()?.to_os_string());
            cur = cur.parent()?.to_path_buf();
        }
    };
    match (canon(base), canon(target)) {
        (Some(b), Some(t)) => t.starts_with(&b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_dirs_resolve_inside_or_outside_the_project() {
        let tmp = std::env::temp_dir();
        let project = tmp.join("kraken-rewrite-dir-test-project");
        let inside = resolve_export_dir(&project, "out/ws").expect("relative");
        assert_eq!(inside, project.join("out/ws"));
        assert!(is_inside(&project, &inside));
        let outside = resolve_export_dir(&project, tmp.to_str().unwrap_or("/tmp")).expect("abs");
        assert!(!is_inside(&project, &outside));
        assert!(resolve_export_dir(&project, "../x").is_err());
        assert!(resolve_export_dir(&project, "").is_err());
        assert!(resolve_export_dir(&project, "/").is_err());
    }

    #[test]
    fn statuses_round_trip_through_their_stored_names() {
        for s in [
            UnitStatus::Planned,
            UnitStatus::Translated,
            UnitStatus::Verified,
            UnitStatus::Failed,
            UnitStatus::Accepted,
        ] {
            assert_eq!(UnitStatus::parse(s.as_str()), Some(s));
        }
        assert_eq!(UnitStatus::parse("nope"), None);
    }
}

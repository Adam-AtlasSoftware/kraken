//! The whole-program rewrite commands: `rewrite_program` and `rewrite_program_status` (ADR 0013).
//!
//! `rewrite_program` plans the program bottom-up, rewrites every function (reusing callees that
//! were already translated), generates a standalone Rust binary crate whose `main` is the
//! translated entry point plus a small runtime shim for the libc calls, builds it, and runs the
//! original and the rewritten program on the same inputs, both inside the sandbox. The work is
//! done by the [`RewriteBackend`](super::RewriteBackend) attached to the session.

use async_trait::async_trait;
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext, Surface};
use crate::session::Session;

use super::JobStarted;
use super::rewrite::{PlanScope, RewriteMode, UnitStatus, is_inside, resolve_export_dir};

/// Directory of the generated crate when the call names none (inside the project directory).
pub const DEFAULT_PROGRAM_DIR: &str = "rewrite-program";
/// Most explicit program cases a call may add.
pub const MAX_USER_CASES: usize = 64;
/// Most generated program cases.
pub const MAX_GENERATED_CASES: u32 = 200;
/// Program-level repair rounds when the call names none.
pub const DEFAULT_REPAIR_ROUNDS: u32 = 2;
/// Most program-level repair rounds a call may ask for.
pub const MAX_REPAIR_ROUNDS: u32 = 4;

/// What the approval question for running the original program says.
pub const RUN_ORIGINAL_SUMMARY: &str = "run the original program natively on test inputs, inside \
the sandbox (read-only file system, no network, no fork, resource limits), to compare it with \
the Rust rewrite";

// ---- rewrite_program -------------------------------------------------------------------------

/// A program-level test case given by the caller: what the program is started with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProgramCaseSpec {
    /// A short label for the report.
    pub name: String,
    /// Arguments after `argv[0]` (which is always `prog`).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Text written to the program's standard input (default: empty).
    #[serde(default)]
    pub stdin: Option<String>,
}

/// Arguments of `rewrite_program`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteProgramArgs {
    /// `all` (the only scope today): every non-library function the entry point reaches.
    #[serde(default)]
    pub scope: PlanScope,
    /// The entry point (any address inside it). Default: the function named `main`, else the
    /// first argument of `__libc_start_main` in the decompile of `entry`/`_start`.
    #[serde(default)]
    pub entry: Option<Hex64>,
    /// `incremental` (default) translates decompiles. `spec` is not available for programs yet.
    #[serde(default)]
    pub mode: RewriteMode,
    /// Seed of the random function-level and program-level cases (default fixed).
    #[serde(default)]
    pub seed: Option<u64>,
    /// Random function-level test cases per function (default 200, at most 2000).
    #[serde(default)]
    pub cases: Option<u32>,
    /// Most translation attempts per function (default 3, 1 to 8).
    #[serde(default)]
    pub max_attempts: Option<u32>,
    /// Run the function-level differential test (emulation oracle, needs the SLEIGH specs of a
    /// Ghidra install). Default true. With false, functions are only compiled; the program-level
    /// test is then the only evidence.
    #[serde(default)]
    pub verify_functions: Option<bool>,
    /// Accept every function that passed its function-level test (users only). Accepted
    /// translations are reused by later runs and by `rewrite_export`. Default false.
    #[serde(default)]
    pub accept_verified: Option<bool>,
    /// Generated program-level cases on top of the ones derived from the corpus source (default
    /// 8, at most 200).
    #[serde(default)]
    pub generated_cases: Option<u32>,
    /// Extra program-level cases (at most 64).
    #[serde(default)]
    pub inputs: Vec<ProgramCaseSpec>,
    /// Directory to write the Rust crate to. Relative paths are inside the project directory;
    /// `..` is not allowed. It must be empty, absent, or an earlier program rewrite. Default
    /// `rewrite-program` in the project directory. Writing outside the project asks for approval.
    ///
    /// The backend receives the resolved absolute path here.
    #[serde(default)]
    pub dir: Option<String>,
    /// Build the crate and run the program-level test (default true). With false the crate is
    /// only written.
    #[serde(default)]
    pub build: Option<bool>,
    /// How many times a failed program verdict is fed back for repair (default 2, at most 4; 0
    /// turns it off). Each round finds the functions most likely responsible for the first
    /// differing case (see the command description), asks the provider to fix them with that
    /// case as evidence, then rebuilds and runs every case again. A round that changes nothing
    /// ends the repair.
    #[serde(default)]
    pub repair_rounds: Option<u32>,
}

/// One function of a program rewrite.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramFunctionRow {
    /// Position in the plan.
    pub order: u32,
    /// Entry address.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
    /// Id of the unit version chosen for this function (`ru-...`); empty when none was usable.
    #[serde(default)]
    pub unit: String,
    /// Its version number (0 when none).
    #[serde(default)]
    pub version: u32,
    /// Status of the chosen version, or of the last attempt when none was usable.
    pub status: UnitStatus,
    /// Function-level verdict: `pass`, `fail`, `rejected`, `inconclusive`, or `none`.
    pub verdict: String,
    /// `differential` (checked against the original under emulation), `compile_only` (built, not
    /// compared), `stored` (an accepted unit from an earlier run, not translated again),
    /// `skipped` (not reachable from the entry point by direct calls, so not translated) or
    /// `none` (nothing could be translated; the note says why).
    pub check: String,
    /// Why the function-level test could not compare (binary-derived), if it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_note: Option<Untrusted<String>>,
    /// Translation attempts made in this run.
    pub attempts: u32,
    /// Rust names of callees this translation calls instead of translating again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reused_callees: Vec<String>,
    /// True when the function is part of the generated crate (reachable from the entry through
    /// the chosen translations).
    pub included: bool,
}

/// One function a program-level repair round asked the provider to fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramRepairView {
    /// Round, from 1.
    pub round: u32,
    /// Entry address of the function.
    pub address: Hex64,
    /// Its name (binary-derived).
    pub name: Untrusted<String>,
    /// The case whose difference was fed back.
    pub case: String,
    /// What the rewritten program was doing at the first differing output (`writing byte 12 of
    /// its standard output`), empty when it could not be traced.
    #[serde(default)]
    pub at: String,
    /// The translated functions on the rewritten program's call stack there, innermost first
    /// (Rust symbols).
    #[serde(default)]
    pub stack: Vec<String>,
    /// Why this function was suspected (binary-derived names inside).
    pub why: Untrusted<String>,
    /// `replaced` (the new translation passed its own checks and was used), `kept` (it did not,
    /// the earlier translation stays) or `no_reply` (the provider's reply could not be used).
    pub outcome: String,
    /// Version of the unit before the round.
    pub version_before: u32,
    /// Version used after the round (the same when `kept` or `no_reply`).
    pub version_after: u32,
    /// The program verdict after the round: `pass`, `fail`, `incomplete`, or empty when nothing
    /// was rebuilt because no function changed.
    #[serde(default)]
    pub verdict_after: String,
}

/// How a program ended on one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramRunView {
    /// `exit 0`, `signal 11`, `timeout`.
    pub exit: String,
    /// Standard output (lossy UTF-8, cut at 4 KiB; program-derived).
    pub stdout: Untrusted<String>,
    /// Bytes the program wrote to standard output.
    pub stdout_bytes: u64,
    /// Standard error (lossy UTF-8, cut at 4 KiB; program-derived).
    pub stderr: Untrusted<String>,
    /// Bytes the program wrote to standard error.
    pub stderr_bytes: u64,
}

/// One program-level case with what both programs did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramCaseResult {
    /// Label.
    pub name: String,
    /// `baseline`, `corpus` (derived from the program's source), `generated` or `user`.
    pub origin: String,
    /// Arguments after `argv[0]`.
    pub argv: Vec<Untrusted<String>>,
    /// Bytes of standard input.
    pub stdin_bytes: u64,
    /// True when exit status, stdout and stderr all agree.
    pub agree: bool,
    /// The original program.
    pub original: ProgramRunView,
    /// The rewritten program.
    pub rewritten: ProgramRunView,
    /// What differs (empty when `agree`).
    pub differences: Vec<Untrusted<String>>,
}

/// The program-level verdict (ADR 0013, oracle kind `process`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramVerdictView {
    /// `pass` (every case agreed), `fail` (a case differed), `incomplete` (no runnable crate: a
    /// function could not be translated or the crate does not build), `inconclusive` (no case
    /// could tell), or `not_run`.
    pub verdict: String,
    /// Why, for everything but `pass` and `fail` (model- or binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Untrusted<String>>,
    /// Cases run on both programs.
    pub cases_run: u32,
    /// Cases on which all three observations agreed.
    pub passed: u32,
    /// Cases that differed.
    pub failed: u32,
    /// Per-case results (cut to the first 200).
    pub cases: Vec<ProgramCaseResult>,
    /// How the programs were confined while they ran.
    pub sandbox: String,
}

/// Result of a finished `rewrite_program` job (the `result` of `job_status`), also what
/// `rewrite_program_status` reports for a stored run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteProgramResult {
    /// Id of this run (1, 2, ... per project).
    pub run: u64,
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// The translated entry point.
    pub entry: Hex64,
    /// Its name (binary-derived).
    pub entry_name: Untrusted<String>,
    /// Functions in the plan (translated or not).
    pub functions_planned: u32,
    /// Functions left out because the entry point cannot reach them by direct calls (loader and
    /// compiler glue in a binary without names, dead code).
    #[serde(default)]
    pub skipped: u32,
    /// Functions translated in this run.
    pub translated: u32,
    /// Functions taken from accepted units of earlier runs.
    pub reused_from_store: u32,
    /// Functions without a usable translation.
    pub failed: u32,
    /// Functions in the generated crate.
    pub included: u32,
    /// One row per planned function, in plan order.
    pub functions: Vec<ProgramFunctionRow>,
    /// Where the crate was written (empty when nothing was).
    pub crate_dir: String,
    /// True when the crate was built in the sandbox.
    pub built: bool,
    /// SHA-256 over the generated sources.
    #[serde(default)]
    pub crate_sha256: String,
    /// Provider id of the model calls.
    #[serde(default)]
    pub provider: String,
    /// Model name.
    #[serde(default)]
    pub model: String,
    /// When the run finished (seconds since the Unix epoch).
    #[serde(default)]
    pub created: u64,
    /// The program-level verdict (after the repair rounds, if there were any).
    pub verdict: ProgramVerdictView,
    /// The program-level repair rounds, oldest first (empty when the first verdict was final).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<ProgramRepairView>,
}

/// Rewrites a whole program.
pub struct RewriteProgram;

#[async_trait]
impl Command for RewriteProgram {
    type Args = RewriteProgramArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_program",
            "Rewrite a whole program to a standalone Rust crate and verify it against the original (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Plans the program bottom-up (callees first, recursive groups together), translates \
             every non-library function the entry point reaches by direct calls with the \
             configured provider (reusing callees that are already translated, repairing \
             failures as `rewrite_function` does), then writes a \
             standalone Rust binary crate: one module per function, a small runtime shim \
             (`rt`) that maps the libc calls the corpus programs use (printf, puts, strlen, \
             malloc, free, exit, ...) to Rust `std`, and a `main` that calls the translated entry \
             point. The crate is built in the sandbox and the original and the rewritten program \
             are run on the same inputs (a baseline run, cases derived from the program's source \
             when it is a corpus program, generated and given cases), both inside the sandbox \
             with no network. Exit status, stdout and stderr are compared; the result is a \
             `ProgramVerdict` with the per-case differences, stored in `rewrite.sqlite` and \
             readable with `rewrite_program_status`. A function-level verdict is evidence about \
             one function; only the program verdict says the whole program behaves the same on \
             the inputs tried. The original binary runs natively, confined, so this command \
             refuses to run on hosts that cannot confine (Linux with Landlock today), and a call \
             made for a person (an agent, MCP) asks for approval first, because it executes the \
             binary under analysis. When the program verdict is `fail`, up to `repair_rounds` rounds \
             of program-level repair follow: the rewritten program is run again on the first \
             differing case with a trace that prints its call stack where the first differing \
             output byte is written; the functions on that stack, then their callees, \
             unverified ones before those that passed their own test against the original, are \
             the suspects; the first two are re-translated with the case, both outputs and the \
             stack as evidence (the provider sees program output); a translation that fails its \
             own function-level check is not used; the crate is rebuilt and every case runs \
             again. The rounds are in `repairs`. It sends decompiled code to the provider. It adds artifacts \
             only; `accept_verified` (users only) additionally accepts the functions that passed \
             their own test.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        mut args: RewriteProgramArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        let project = s.project()?;
        if args.scope != PlanScope::All {
            return Err(invalid("`scope` must be `all`"));
        }
        if args.mode != RewriteMode::Incremental {
            return Err(invalid("`mode: spec` is not available for programs yet"));
        }
        if args.cases.is_some_and(|c| c > 2000) {
            return Err(invalid("`cases` is at most 2000"));
        }
        if args.repair_rounds.is_some_and(|r| r > MAX_REPAIR_ROUNDS) {
            return Err(invalid(&format!(
                "`repair_rounds` is at most {MAX_REPAIR_ROUNDS}"
            )));
        }
        if args.max_attempts.is_some_and(|a| !(1..=8).contains(&a)) {
            return Err(invalid("`max_attempts` is between 1 and 8"));
        }
        if args
            .generated_cases
            .is_some_and(|c| c > MAX_GENERATED_CASES)
        {
            return Err(invalid(&format!(
                "`generated_cases` is at most {MAX_GENERATED_CASES}"
            )));
        }
        if args.inputs.len() > MAX_USER_CASES {
            return Err(invalid(&format!(
                "`inputs` holds at most {MAX_USER_CASES} cases"
            )));
        }
        if args
            .inputs
            .iter()
            .any(|c| c.name.trim().is_empty() || c.argv.iter().any(|a| a.contains('\0')))
        {
            return Err(invalid(
                "every input case needs a name, and arguments cannot contain NUL",
            ));
        }
        if args.accept_verified == Some(true) && ctx.author.kind != AuthorKind::User {
            return Err(ProtoError::new(
                ErrorCode::RejectedHumanPriority,
                "accepting rewrite units is reserved for users; agents cannot pass \
                 `accept_verified`",
            ));
        }
        let dir = resolve_export_dir(
            project.dir(),
            args.dir.as_deref().unwrap_or(DEFAULT_PROGRAM_DIR),
        )?;
        if !is_inside(project.dir(), &dir) {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "rewrite_program".into(),
                    summary: format!(
                        "write the rewritten program's crate outside the project directory, to {}",
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
        // The program-level test runs the original natively (confined, no network). Whoever acts
        // on a person's behalf needs that person's approval for it, as for any dangerous step,
        // and so does the GUI's Run button (its dialog is the approval flow every dangerous
        // command uses). A person typing the command at the CLI is the approval.
        if args.build.unwrap_or(true) && (ctx.needs_user_approval() || ctx.surface == Surface::Gui)
        {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "rewrite_program".into(),
                    summary: RUN_ORIGINAL_SUMMARY.into(),
                    args: serde_json::json!({ "run_original": true }),
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
        args.dir = Some(dir.display().to_string());
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_program", move |reporter| async move {
                let out = backend.program(&s2, &ctx2, args, &reporter).await?;
                to_value(&out)
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

// ---- rewrite_program_status ------------------------------------------------------------------

/// Arguments of `rewrite_program_status`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteProgramStatusArgs {
    /// The run to show (default: the newest).
    #[serde(default)]
    pub run: Option<u64>,
    /// Include the cases that agreed (default: only the cases that differed, and the counts).
    #[serde(default)]
    pub all_cases: bool,
}

/// One stored run in a listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProgramRunSummary {
    /// Run id.
    pub run: u64,
    /// When it finished (seconds since the Unix epoch).
    pub created: u64,
    /// Entry point.
    pub entry: Hex64,
    /// Program verdict kind.
    pub verdict: String,
    /// Cases run.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Where the crate was written.
    pub crate_dir: String,
}

/// Result of `rewrite_program_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteProgramStatusOut {
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// True when at least one run is stored for this binary.
    pub present: bool,
    /// Stored runs for this binary, newest first (at most 20).
    pub runs: Vec<ProgramRunSummary>,
    /// The selected run, in full.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RewriteProgramResult>,
}

/// Reads stored program rewrites.
pub struct RewriteProgramStatus;

#[async_trait]
impl Command for RewriteProgramStatus {
    type Args = RewriteProgramStatusArgs;
    type Output = RewriteProgramStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_program_status",
            "Show a stored whole-program rewrite: functions, crate and the program-level verdict with per-case diffs",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Reads `rewrite.sqlite`; nothing is generated or run. Lists the stored program \
             rewrites of this binary (newest first) and shows one in full: the function table \
             (which version was chosen, whether it was compared against the original or only \
             compiled, which callees it reuses), where the crate is, and the program verdict. \
             By default only the cases that differed are listed; `all_cases` adds the others. \
             Program output is untrusted data.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteProgramStatusArgs,
    ) -> Result<RewriteProgramStatusOut, ProtoError> {
        s.rewrite()?.program_status(s, ctx, args).await
    }
}

fn invalid(msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn to_value<T: Serialize>(v: &T) -> Result<Value, ProtoError> {
    serde_json::to_value(v)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}")))
}

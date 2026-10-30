//! `rewrite_preload_build`: runs the accepted Rust functions inside the original Linux program.
//!
//! The export of `rewrite_export` is a library the program is linked against. This command builds
//! a second crate from that export, a shared library for `LD_PRELOAD` that replaces each accepted
//! function in the running original with its Rust version, and a launcher script. It can also run
//! the original with and without the library and compare the two.

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext, Surface};
use crate::session::Session;

use super::JobStarted;
use super::rewrite::resolve_export_dir;
use super::rewrite_build::{MAX_RUN_ARGS, crate_kind};

/// Arguments of `rewrite_preload_build`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewritePreloadBuildArgs {
    /// The export: the `dir` that `rewrite_export` wrote. Relative paths are inside the project
    /// directory.
    pub dir: String,
    /// When given, the original program is run twice in the sandbox with these arguments (at most
    /// 32), once as it is and once with the library preloaded, and the two are compared (exit
    /// status, standard output and standard error).
    #[serde(default)]
    pub check_args: Option<Vec<String>>,
    /// Text for the standard input of the checked runs.
    #[serde(default)]
    pub check_stdin: Option<String>,
}

/// One function the preload library takes over in the running program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreloadHook {
    /// The function's `extern "C"` name.
    pub symbol: String,
    /// The original function's entry as KRAKEN shows it.
    pub address: String,
    /// Bytes of the original function body.
    pub size: u64,
}

/// A function that cannot be taken over, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreloadSkip {
    /// The function's `extern "C"` name.
    pub symbol: String,
    /// Why the library leaves the original in place.
    pub reason: String,
}

/// Result of running the original with and without the library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreloadCheck {
    /// Exit of the plain run (`exit 0`, `signal 11`, `timeout`).
    pub original_exit: String,
    /// Exit of the run with the library.
    pub preload_exit: String,
    /// True when exit status, standard output and standard error are all equal.
    pub identical: bool,
    /// Bytes the original wrote to standard output.
    pub stdout_bytes: u64,
    /// How often each Rust function was called during the preloaded run.
    pub calls: Vec<PreloadCalls>,
    /// What differed, when `identical` is false (program output, untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub difference: Option<Untrusted<String>>,
}

/// Calls of one Rust function during a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PreloadCalls {
    /// The function.
    pub symbol: String,
    /// Calls counted.
    pub calls: u64,
}

/// Result of a finished `rewrite_preload_build` job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewritePreloadBuildResult {
    /// The export folder.
    pub dir: String,
    /// The shared library, inside the export folder (the path embeds the program's name).
    pub library: Untrusted<String>,
    /// The launcher script next to it: `run-with-preload.sh <program> [args]`.
    pub launcher: Untrusted<String>,
    /// Functions replaced at their entry in the running program.
    pub hooked: Vec<PreloadHook>,
    /// Accepted functions left in the original, with the reason.
    pub skipped: Vec<PreloadSkip>,
    /// How the build was confined.
    pub sandbox: String,
    /// The comparison, when `check_args` was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<PreloadCheck>,
    /// What this mode cannot do.
    pub limits: Vec<String>,
}

/// Builds the preload library of an export.
pub struct RewritePreloadBuild;

#[async_trait]
impl Command for RewritePreloadBuild {
    type Args = RewritePreloadBuildArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_preload_build",
            "Build an LD_PRELOAD library so the original program runs the accepted Rust (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Takes an export from `rewrite_export` and builds a shared library plus a launcher \
             script. With `LD_PRELOAD` the original x86-64 Linux program then calls the Rust \
             version of every accepted function, including static ones, with the rest running \
             as before. `check_args` also runs the original with and without the library and \
             compares output. Returns a `job_id`. Runs generated code, so a person is asked to \
             approve a call from an agent.\n\
             Example: rewrite_preload_build {\"dir\": \"export\", \"check_args\": []}",
        )
        .details(
            "The folder must hold the `manifest.json` of `rewrite_export`. A crate \
             `<name>-preload` is added to the workspace and built in the sandbox (offline, \
             read-only file system). The library does two things when the program loads it: every \
             accepted function is exported under its own name, so calls that go through the \
             dynamic symbol table reach the Rust version, and at start-up the entry of each \
             accepted function in the running program is overwritten with a 14-byte jump to the \
             Rust function, which also covers static functions and calls through function \
             pointers. Functions that are not accepted but that the Rust code calls are reached \
             through small trampolines to the original function's address. Limits: x86-64 ELF \
             only; the library compares the size of `/proc/self/exe` with the analysed file and \
             leaves the program alone when it differs; a function shorter than 14 bytes is \
             skipped; functions that use the C library's `stdin`, `stdout` or `stderr` objects \
             through the program's data are not supported, and functions that print buffer \
             differently from the original when output is not a terminal; programs under another \
             loader, or whose code pages cannot be made writable, are not supported. \
             `KRAKEN_PRELOAD_DISABLE=1` turns the library off; `KRAKEN_PRELOAD_LOG=1` makes it \
             report on standard error, at exit, how often each Rust function ran. With \
             `check_args` the original is run twice under the sandbox and the results are \
             compared; its output is untrusted data.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        mut args: RewritePreloadBuildArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        let project = s.project()?;
        if let Some(a) = &args.check_args {
            if a.len() > MAX_RUN_ARGS {
                return Err(invalid(&format!(
                    "`check_args` holds at most {MAX_RUN_ARGS} arguments"
                )));
            }
            if a.iter().any(|x| x.contains('\0')) {
                return Err(invalid("`check_args` cannot contain NUL"));
            }
        }
        if args.check_stdin.as_ref().is_some_and(|t| t.len() > 1 << 20) {
            return Err(invalid("`check_stdin` is at most 1 MiB"));
        }
        let dir = resolve_export_dir(project.dir(), &args.dir)?;
        if crate_kind(&dir) != Some("export") {
            return Err(invalid(&format!(
                "{} is not an export of `rewrite_export` (no manifest.json from it)",
                dir.display()
            )));
        }
        if ctx.needs_user_approval() || ctx.surface == Surface::Gui {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "rewrite_preload_build".into(),
                    summary: if args.check_args.is_some() {
                        "build the preload library in the sandbox and run the original program \
                         with and without it, confined"
                            .into()
                    } else {
                        super::rewrite_build::BUILD_SUMMARY.into()
                    },
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
        args.dir = dir.display().to_string();
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_preload_build", move |reporter| async move {
                let out = backend.preload_build(&s2, &ctx2, args, &reporter).await?;
                serde_json::to_value(&out).map_err(|e| {
                    ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}"))
                })
            });
        Ok(JobStarted { job_id: id.0 })
    }
}

fn invalid(msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

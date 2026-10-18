//! `rewrite_build`: builds and tests a crate that `rewrite_export` or `rewrite_program` wrote,
//! inside the same sandbox that builds the generated code in the first place.

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext, Surface};
use crate::session::Session;

use super::JobStarted;
use super::rewrite::resolve_export_dir;

/// Most arguments `run_args` may hold.
pub const MAX_RUN_ARGS: usize = 32;
/// Bytes of log kept per step.
pub const BUILD_LOG_CAP: usize = 16 * 1024;
/// `generator` of the `manifest.json` that `rewrite_export` writes.
pub const EXPORT_GENERATOR: &str = "kraken-rewrite";
/// `generator` of the `kraken-program.json` that `rewrite_program` writes.
pub const PROGRAM_GENERATOR: &str = "kraken-rewrite/program";

/// What the approval question for building and running generated code says.
pub const BUILD_SUMMARY: &str = "build and run the generated Rust crate inside the sandbox \
(read-only file system, no network, resource limits, scrubbed environment)";

/// Arguments of `rewrite_build`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteBuildArgs {
    /// The exported crate: the `dir` that `rewrite_export` or `rewrite_program` wrote. Relative
    /// paths are inside the project directory.
    pub dir: String,
    /// Also run `cargo test` (default true).
    #[serde(default)]
    pub test: Option<bool>,
    /// When given, `cargo run` follows with these arguments (program crates only; at most 32).
    #[serde(default)]
    pub run_args: Option<Vec<String>>,
}

/// One step of a build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BuildStepResult {
    /// `build`, `test` or `run`.
    pub step: String,
    /// True when the step exited with status 0.
    pub passed: bool,
    /// `exit 0`, `exit 101`, `signal 9` or `timeout`.
    pub exit: String,
    /// Wall-clock seconds.
    pub seconds: f64,
    /// The end of the step's output (cut at 16 KiB; generated-code-derived).
    pub log_tail: Untrusted<String>,
}

/// Result of a finished `rewrite_build` job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteBuildResult {
    /// The folder that was built.
    pub dir: String,
    /// `export` (workspace with the FFI shim) or `program` (standalone binary crate).
    pub kind: String,
    /// True when every step that ran passed.
    pub passed: bool,
    /// The steps that ran, in order. A step that fails ends the build.
    pub steps: Vec<BuildStepResult>,
    /// How the steps were confined.
    pub sandbox: String,
}

/// Tells the kind of crate a manifest marks: `export` or `program`.
pub fn manifest_kind(text: &str) -> Option<&'static str> {
    let v: Value = serde_json::from_str(text).ok()?;
    match v.get("generator")?.as_str()? {
        EXPORT_GENERATOR => Some("export"),
        PROGRAM_GENERATOR => Some("program"),
        _ => None,
    }
}

/// Reads the marker of `dir`: `export`, `program`, or `None` when KRAKEN did not write it.
pub fn crate_kind(dir: &std::path::Path) -> Option<&'static str> {
    [
        ("kraken-program.json", "program"),
        ("manifest.json", "export"),
    ]
    .into_iter()
    .find_map(|(file, kind)| {
        let text = std::fs::read_to_string(dir.join(file)).ok()?;
        (manifest_kind(&text)? == kind).then_some(kind)
    })
}

/// Builds and tests an exported crate.
pub struct RewriteBuild;

#[async_trait]
impl Command for RewriteBuild {
    type Args = RewriteBuildArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_build",
            "Build and test an exported Rust rewrite inside the sandbox (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Runs `cargo build` and `cargo test` (and `cargo run` when `run_args` is given) on a \
             crate that `rewrite_export` or `rewrite_program` wrote, confined like the generated \
             code: read-only file system, no network, limits. Returns a `job_id`; the result has \
             pass or fail per step and the end of each log. Any other folder is refused. Runs \
             generated code, so a person is asked to approve a call from an agent.\n\
             Example: rewrite_build {\"dir\": \"rewrite-program\", \"run_args\": [\"--help\"]}",
        )
        .details(
            "The folder must hold the marker file KRAKEN writes (`manifest.json` from \
             `rewrite_export` or `kraken-program.json` from `rewrite_program`), so an arbitrary \
             folder is never built. The crate is copied to a private scratch directory first, \
             so nothing is written next to the exported files. Each step runs offline with a \
             scrubbed environment and a wall-clock limit; a failing step ends the build and later \
             steps do not run. Logs are cut to their last 16 KiB and are untrusted data: they \
             come from generated code. `run_args` needs a program crate (an export is a \
             library). The command refuses to run on hosts that cannot confine generated code.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        mut args: RewriteBuildArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        backend.require_sandbox()?;
        let project = s.project()?;
        if let Some(a) = &args.run_args {
            if a.len() > MAX_RUN_ARGS {
                return Err(invalid(&format!(
                    "`run_args` holds at most {MAX_RUN_ARGS} arguments"
                )));
            }
            if a.iter().any(|x| x.contains('\0')) {
                return Err(invalid("`run_args` cannot contain NUL"));
            }
        }
        let dir = resolve_export_dir(project.dir(), &args.dir)?;
        let Some(kind) = crate_kind(&dir) else {
            return Err(invalid(&format!(
                "{} is not a crate KRAKEN exported (no manifest.json from rewrite_export or \
                 kraken-program.json from rewrite_program); only those folders are built",
                dir.display()
            )));
        };
        if args.run_args.is_some() && kind != "program" {
            return Err(invalid(
                "`run_args` needs a program crate from `rewrite_program`; an export is a library",
            ));
        }
        if ctx.needs_user_approval() || ctx.surface == Surface::Gui {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "rewrite_build".into(),
                    summary: BUILD_SUMMARY.into(),
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
        let id = s.jobs().spawn("rewrite_build", move |reporter| async move {
            let out = backend.build(&s2, &ctx2, args, &reporter).await?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_are_told_apart() {
        assert_eq!(
            manifest_kind(r#"{"generator":"kraken-rewrite","schema":1}"#),
            Some("export")
        );
        assert_eq!(
            manifest_kind(r#"{"generator":"kraken-rewrite/program"}"#),
            Some("program")
        );
        assert_eq!(manifest_kind(r#"{"generator":"cargo"}"#), None);
        assert_eq!(manifest_kind("not json"), None);
    }

    #[test]
    fn a_folder_needs_the_matching_file() {
        let d = std::env::temp_dir().join(format!("kr-kind-{}", std::process::id()));
        std::fs::create_dir_all(&d).expect("mkdir");
        assert_eq!(crate_kind(&d), None);
        std::fs::write(d.join("manifest.json"), r#"{"generator":"kraken-rewrite"}"#)
            .expect("write");
        assert_eq!(crate_kind(&d), Some("export"));
        std::fs::write(
            d.join("kraken-program.json"),
            r#"{"generator":"kraken-rewrite"}"#,
        )
        .expect("write");
        // A program marker that names the export generator is not a program crate.
        assert_eq!(crate_kind(&d), Some("export"));
        let _ = std::fs::remove_dir_all(&d);
    }
}

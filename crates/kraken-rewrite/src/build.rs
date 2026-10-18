//! `rewrite_build`: `cargo build`, `cargo test` and `cargo run` on a crate KRAKEN exported, in
//! the sandbox that builds the generated code in the first place.
//!
//! The crate is copied to a private scratch directory; each step runs offline with a scrubbed
//! environment, the file system read-only except that directory, and no network. Only folders
//! that hold the marker `rewrite_export` or `rewrite_program` writes are built.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use kraken_registry::commands::{BUILD_LOG_CAP, BuildStepResult, crate_kind};

use crate::error::RewriteError;
use crate::export::copy_tree;
use crate::sandbox::{Confinement, ReadScope, confine, run_captured, scratch_dir, toolchain};

/// Wall-clock limit of the build and test steps.
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);
/// Wall-clock limit of the run step.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);
/// Bytes read from each stream of a step.
const OUTPUT_CAP: usize = 256 * 1024;

/// The steps that ran.
#[derive(Debug, Clone)]
pub struct BuildReport {
    /// `export` or `program`.
    pub kind: &'static str,
    /// Steps in order; the last one failed when `passed` is false.
    pub steps: Vec<BuildStepResult>,
    /// How the steps were confined.
    pub sandbox: String,
}

impl BuildReport {
    /// Every step that ran passed.
    pub fn passed(&self) -> bool {
        self.steps.iter().all(|s| s.passed)
    }
}

/// The last `cap` bytes of `text`, starting at a line when one is near.
pub fn tail(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let mut start = text.len() - cap;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    let cut = &text[start..];
    let cut = cut.split_once('\n').map_or(cut, |(_, rest)| rest);
    format!("... (earlier output cut)\n{cut}")
}

/// Builds `dir`, then tests it when `test` is set, then runs it with `run_args` when they are
/// given. `on_step` is told the name of each step before it starts. A failing step ends the
/// build. Refuses a folder that KRAKEN did not write.
pub fn build_and_test(
    dir: &Path,
    test: bool,
    run_args: Option<&[String]>,
    confinement: &Confinement,
    on_step: &dyn Fn(&str),
) -> Result<BuildReport, RewriteError> {
    let Some(kind) = crate_kind(dir) else {
        return Err(RewriteError::Store(format!(
            "{} is not a crate KRAKEN exported (no manifest.json or kraken-program.json from \
             kraken-rewrite); only those folders are built",
            dir.display()
        )));
    };
    if run_args.is_some() && kind != "program" {
        return Err(RewriteError::Unsupported(
            "only a program crate can be run; an export is a library".into(),
        ));
    }
    let tc = toolchain()?;
    let run = scratch_dir("kraken-build-")?;
    let ws = run.path().join("ws");
    copy_tree(dir, &ws)?;
    let cargo_home = run.path().join("cargo-home");
    std::fs::create_dir_all(&cargo_home)
        .map_err(|e| RewriteError::Compile(format!("cargo-home: {e}")))?;
    let target = run.path().join("target");

    let mut plan: Vec<(&str, Vec<String>, Duration)> = vec![(
        "build",
        vec!["build".into(), "--release".into()],
        BUILD_TIMEOUT,
    )];
    if test {
        plan.push((
            "test",
            vec!["test".into(), "--release".into()],
            BUILD_TIMEOUT,
        ));
    }
    if let Some(a) = run_args {
        let mut v = vec!["run".to_string(), "--release".into(), "--quiet".into()];
        v.push("--".into());
        v.extend(a.iter().cloned());
        plan.push(("run", v, RUN_TIMEOUT));
    }

    let mut steps = Vec::new();
    let mut sandbox = "none".to_string();
    for (name, args, limit) in plan {
        on_step(name);
        let mut cmd = Command::new(&tc.cargo);
        cmd.arg(&args[0])
            .args(["--offline", "--target-dir"])
            .arg(&target);
        cmd.args(&args[1..]);
        let report = confine(&mut cmd, run.path(), ReadScope::Toolchain, confinement)?;
        sandbox = report.label();
        cmd.current_dir(&ws)
            .env("CARGO_HOME", &cargo_home)
            .env("RUSTC", &tc.rustc)
            .env("RUSTC_WRAPPER", "")
            .env("RUSTC_WORKSPACE_WRAPPER", "")
            .env("CARGO_ENCODED_RUSTFLAGS", "")
            .env("CARGO_TERM_COLOR", "never")
            .env("CARGO_NET_OFFLINE", "true")
            .env("TMPDIR", run.path());
        let started = Instant::now();
        let out = run_captured(&mut cmd, limit, OUTPUT_CAP, Duration::from_millis(20))
            .map_err(|e| RewriteError::Compile(format!("cannot run cargo: {e}")))?;
        let seconds = started.elapsed().as_secs_f64();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let (passed, exit) = match out.status {
            None => (false, "timeout".to_string()),
            Some(s) => (s.success(), exit_text(&s)),
        };
        steps.push(BuildStepResult {
            step: name.to_string(),
            passed,
            exit,
            seconds,
            log_tail: kraken_proto::Untrusted::sanitized(&tail(&text, BUILD_LOG_CAP)),
        });
        if !passed {
            break;
        }
    }
    Ok(BuildReport {
        kind,
        steps,
        sandbox,
    })
}

#[cfg(unix)]
fn exit_text(s: &std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (s.code(), s.signal()) {
        (Some(c), _) => format!("exit {c}"),
        (None, Some(sig)) => format!("signal {sig}"),
        _ => "unknown".into(),
    }
}

#[cfg(not(unix))]
fn exit_text(s: &std::process::ExitStatus) -> String {
    s.code().map_or("unknown".into(), |c| format!("exit {c}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_logs_are_kept_and_long_ones_cut_at_a_line() {
        assert_eq!(tail("abc\n", 100), "abc\n");
        let long = "line one\nline two\nline three\n";
        let t = tail(long, 14);
        assert!(t.starts_with("... (earlier output cut)\n"), "{t}");
        assert!(t.ends_with("line three\n"), "{t}");
        assert!(!t.contains("line one"));
    }
}

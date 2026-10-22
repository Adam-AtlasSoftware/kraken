//! Running one command line in the sandbox of `kraken-confine`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use kraken_confine::{Confinement, Limits, ReadScope, confine, run_captured, scratch_dir};
use kraken_proto::sanitize_capped;

/// The most characters of output the model gets.
pub const SHELL_OUTPUT_CHARS: usize = 4000;
/// Default and largest time a command may take, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
pub const MAX_TIMEOUT_SECS: u64 = 60;

const ADDRESS_SPACE: u64 = 2 << 30;
const CPU_SECONDS: u64 = 30;
const FILE_SIZE: u64 = 64 << 20;
/// Tasks a command may start beyond those running when it starts (the limit is counted per
/// user, and other programs keep starting threads meanwhile): room for pipelines, not for a
/// fork bomb.
const EXTRA_PROCESSES: u64 = 256;
/// Bytes read from each output stream before the rest is discarded.
const STREAM_CAP: usize = 64 * 1024;

/// What one command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellOutcome {
    /// The exit code; `None` when it was killed (timeout or signal).
    pub exit: Option<i32>,
    /// The signal that ended it, when one did and it was not the timeout.
    pub signal: Option<i32>,
    /// Standard output then standard error, sanitised and cut to [`SHELL_OUTPUT_CHARS`].
    pub output: String,
    /// The deadline killed it.
    pub timed_out: bool,
}

/// The scratch directory of one chat session: made on first use, removed when the last holder
/// lets go.
#[derive(Debug, Default)]
pub struct ShellSession {
    scratch: Mutex<Option<tempfile::TempDir>>,
}

impl ShellSession {
    /// A session with no scratch directory yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The scratch directory, made if needed.
    pub fn scratch(&self) -> Result<PathBuf, String> {
        let mut g = self.scratch.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(d) = g.as_ref() {
            return Ok(d.path().to_path_buf());
        }
        let d = scratch_dir("kraken-shell-").map_err(|e| e.to_string())?;
        let p = d.path().to_path_buf();
        *g = Some(d);
        Ok(p)
    }
}

fn shell_program() -> Option<(&'static str, bool)> {
    [
        ("/usr/bin/bash", true),
        ("/bin/bash", true),
        ("/usr/bin/sh", false),
        ("/bin/sh", false),
    ]
    .into_iter()
    .find(|(p, _)| Path::new(p).exists())
}

/// Tasks (processes and threads) running on the whole system now. The process limit counts
/// tasks of the user, threads included, so a base taken from the system is never too low. The
/// fourth field of `/proc/loadavg` is `running/total`.
fn system_tasks() -> u64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|t| {
            t.split_whitespace()
                .nth(3)?
                .split('/')
                .nth(1)?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(4096)
}

/// Runs `command` with `bash -c` (else `sh -c`) in `scratch`. Blocking: call it from a blocking
/// thread. `read_only` are the files the command may read besides the system's.
pub fn run(
    command: &str,
    scratch: &Path,
    read_only: &[PathBuf],
    timeout: Duration,
) -> Result<ShellOutcome, String> {
    let (program, is_bash) = shell_program().ok_or("no shell (bash or sh) found")?;
    let mut cmd = Command::new(program);
    if is_bash {
        cmd.args(["--norc", "--noprofile"]);
    }
    cmd.arg("-c").arg(OsStr::new(command));
    let opts = Confinement {
        extra_read_paths: read_only.iter().filter(|p| p.exists()).cloned().collect(),
        deny_exec_in_dir: true,
        limits: Some(Limits {
            address_space: ADDRESS_SPACE,
            cpu_seconds: CPU_SECONDS,
            file_size: FILE_SIZE,
            processes: system_tasks() + EXTRA_PROCESSES,
        }),
        ..Confinement::default()
    };
    confine(&mut cmd, scratch, ReadScope::Toolchain, &opts).map_err(|e| e.to_string())?;
    cmd.env("LANG", "C");
    let got = run_captured(&mut cmd, timeout, STREAM_CAP, Duration::from_millis(20))
        .map_err(|e| format!("could not start the shell: {e}"))?;
    let (exit, signal) = match got.status {
        None => (None, None),
        Some(s) => {
            #[cfg(unix)]
            let sig = std::os::unix::process::ExitStatusExt::signal(&s);
            #[cfg(not(unix))]
            let sig = None;
            (s.code(), sig)
        }
    };
    let mut text = String::from_utf8_lossy(&got.stdout).into_owned();
    if !got.stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&got.stderr));
    }
    let hit_cap = got.stdout.len() >= STREAM_CAP || got.stderr.len() >= STREAM_CAP;
    Ok(ShellOutcome {
        exit,
        signal,
        output: cut_output(&text, hit_cap),
        timed_out: got.status.is_none(),
    })
}

/// Sanitises `text` and cuts it to [`SHELL_OUTPUT_CHARS`] characters, saying so.
pub fn cut_output(text: &str, already_cut: bool) -> String {
    let clean = sanitize_capped(text, kraken_proto::MAX_UNTRUSTED_LEN);
    if clean.chars().count() <= SHELL_OUTPUT_CHARS && !already_cut {
        return clean;
    }
    let mut out: String = clean.chars().take(SHELL_OUTPUT_CHARS).collect();
    out.push_str(&format!(
        "\n[output cut at {SHELL_OUTPUT_CHARS} characters; filter it with head, tail or grep]"
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_output_is_kept_and_long_output_is_cut_with_a_note() {
        assert_eq!(cut_output("abc\n", false), "abc\n");
        let long = "x".repeat(5000);
        let cut = cut_output(&long, false);
        assert!(cut.starts_with(&"x".repeat(4000)));
        assert!(!cut.starts_with(&"x".repeat(4001)));
        assert!(cut.contains("output cut at 4000 characters"));
        assert!(cut_output("tiny", true).contains("output cut"));
    }

    #[test]
    fn control_sequences_are_removed() {
        let out = cut_output("a\u{1b}[31mred\u{1b}[0m", false);
        assert!(!out.contains('\u{1b}'), "{out:?}");
    }
}

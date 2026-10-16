//! The native side of a differential test: compile the Rust translation into a small runner
//! program with `rustc`, then run it once per test case, confined (see [`crate::sandbox`]).
//!
//! The runner is one process per case on purpose. A translation that calls `exit`, panics,
//! overflows (the runner is built with overflow checks on), loops or crashes is observed as that
//! outcome instead of taking the test process down.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::abi::{Arg, Observation, Param, Ret, Signature, Termination, from_hex, mask, to_hex};
use crate::error::RewriteError;
use crate::sandbox::{Confinement, ConfinementReport, ReadScope, confine};

/// Wall-clock limit per case.
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on captured output per stream.
const OUTPUT_CAP: usize = 1 << 20;

/// Source patterns a translation may not contain: it must be self-contained safe-to-build code
/// that only computes. This is defence in depth for the compile step; the runner itself is
/// confined by Landlock.
const FORBIDDEN: &[(&str, &str)] = &[
    ("include!", "include macros read files at build time"),
    ("include_str!", "include macros read files at build time"),
    ("include_bytes!", "include macros read files at build time"),
    ("env!", "environment access at build time"),
    ("option_env!", "environment access at build time"),
    ("asm!", "inline assembly"),
    ("global_asm!", "inline assembly"),
    ("#[link", "linking against libraries"),
    ("#![", "crate-level attributes"),
    ("extern crate", "external crates"),
    ("proc_macro", "procedural macros"),
    ("std::process::Command", "spawning processes"),
    ("std::fs", "file system access"),
    ("std::net", "network access"),
    ("std::env", "environment access"),
    ("std::os::unix", "OS-specific APIs"),
    ("std::os::fd", "OS-specific APIs"),
    ("libc::", "libc calls"),
];

/// Returns why `code` may not be built, if it may not.
pub fn lint_translation(code: &str) -> Option<String> {
    FORBIDDEN
        .iter()
        .find(|(pat, _)| code.contains(pat))
        .map(|(pat, why)| format!("`{pat}` is not allowed in a translation: {why}"))
}

/// A compiled runner.
#[derive(Debug)]
pub struct NativeRunner {
    dir: tempfile::TempDir,
    exe: PathBuf,
    sig: Signature,
    confinement: Confinement,
    /// How the build step was confined.
    pub build_confinement: ConfinementReport,
}

/// Result of building a translation.
#[derive(Debug)]
pub enum Build {
    /// Ready to run.
    Ready(NativeRunner),
    /// The translation was refused or did not compile; the text says why.
    Rejected(String),
}

fn rustc() -> PathBuf {
    std::env::var_os("RUSTC")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("rustc"), PathBuf::from)
}

/// Generates the runner's `main.rs` for `sig`.
fn runner_source(sig: &Signature) -> String {
    let call_args: Vec<String> = (0..sig.params.len())
        .map(|i| format!("vals[{i}] as _"))
        .collect();
    let call = format!(
        "unsafe {{ translation::{}({}) }}",
        sig.name,
        call_args.join(", ")
    );
    let body = match sig.ret {
        Ret::Void => format!("{call};\n    let ret: Option<u64> = None;"),
        Ret::Int { bits, .. } => format!(
            "let r = {call};\n    let ret: Option<u64> = Some((r as u64) & {:#x}u64);",
            mask(bits)
        ),
    };
    format!(
        r#"#![allow(warnings)]
mod translation;

use std::fmt::Write as _;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Chunk([u8; 16]);

const GUARD: usize = 4;

struct Buf {{
    chunks: Vec<Chunk>,
    len: usize,
}}

impl Buf {{
    fn new(data: &[u8]) -> Buf {{
        // Zeroed guard chunks on both sides: a read just outside the buffer sees zeros, as it
        // does inside the oracle's zero-filled pages.
        let mut chunks = vec![Chunk([0; 16]); GUARD + data.len() / 16 + 1 + GUARD];
        let bytes = unsafe {{
            std::slice::from_raw_parts_mut(chunks.as_mut_ptr() as *mut u8, chunks.len() * 16)
        }};
        bytes[GUARD * 16..GUARD * 16 + data.len()].copy_from_slice(data);
        Buf {{ chunks, len: data.len() }}
    }}
    fn ptr(&mut self) -> *mut u8 {{
        unsafe {{ (self.chunks.as_mut_ptr() as *mut u8).add(GUARD * 16) }}
    }}
    fn bytes(&mut self) -> &[u8] {{
        unsafe {{ std::slice::from_raw_parts(self.ptr(), self.len) }}
    }}
}}

fn unhex(s: &str) -> Vec<u8> {{
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}}

fn main() {{
    let argv: Vec<String> = std::env::args().collect();
    let case = std::fs::read_to_string(&argv[1]).unwrap();
    let mut bufs: Vec<Buf> = Vec::new();
    let mut slots: Vec<(bool, u64, usize)> = Vec::new();
    for line in case.lines() {{
        let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
        if kind == "i" {{
            slots.push((false, u64::from_str_radix(rest, 16).unwrap(), 0));
        }} else {{
            bufs.push(Buf::new(&unhex(rest)));
            slots.push((true, 0, bufs.len() - 1));
        }}
    }}
    let vals: Vec<u64> = slots
        .iter()
        .map(|&(is_buf, v, idx)| if is_buf {{ bufs[idx].ptr() as u64 }} else {{ v }})
        .collect();
    {body}
    let mut out = String::new();
    match ret {{
        Some(r) => writeln!(out, "ret {{:x}}", r).unwrap(),
        None => writeln!(out, "ret none").unwrap(),
    }}
    for (i, b) in bufs.iter_mut().enumerate() {{
        let mut hex = String::new();
        for byte in b.bytes() {{
            write!(hex, "{{:02x}}", byte).unwrap();
        }}
        writeln!(out, "buf {{}} {{}}", i, hex).unwrap();
    }}
    std::fs::write(&argv[2], out).unwrap();
}}
"#
    )
}

/// Builds the runner for `rust_code`, a translation defining `extern "C" fn <sig.name>`.
pub fn build(
    sig: &Signature,
    rust_code: &str,
    confinement: &Confinement,
) -> Result<Build, RewriteError> {
    if let Some(why) = lint_translation(rust_code) {
        return Ok(Build::Rejected(why));
    }
    if sig.params.len() > 6 {
        return Err(RewriteError::Unsupported("more than six parameters".into()));
    }
    let dir = tempfile::Builder::new()
        .prefix("kraken-rewrite-")
        .tempdir()
        .map_err(|e| RewriteError::Compile(e.to_string()))?;
    let wr = |name: &str, text: &str| {
        std::fs::write(dir.path().join(name), text)
            .map_err(|e| RewriteError::Compile(format!("{name}: {e}")))
    };
    wr("translation.rs", rust_code)?;
    wr("main.rs", &runner_source(sig))?;
    let exe = dir.path().join("runner");
    let mut cmd = Command::new(rustc());
    cmd.args([
        "--edition",
        "2024",
        "--crate-type",
        "bin",
        "--crate-name",
        "runner",
        "-C",
        "opt-level=0",
        "-C",
        "debuginfo=0",
        "-C",
        "overflow-checks=on",
        "-A",
        "warnings",
        "--error-format",
        "short",
        "-o",
    ])
    .arg(&exe)
    .arg(dir.path().join("main.rs"))
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd.env("TMPDIR", dir.path());
    let report = confine(&mut cmd, dir.path(), ReadScope::Everything, confinement)?;
    let out = cmd
        .output()
        .map_err(|e| RewriteError::Compile(format!("cannot run rustc: {e}")))?;
    if !out.status.success() {
        let text = String::from_utf8_lossy(&out.stderr);
        return Ok(Build::Rejected(format!(
            "does not compile: {}",
            text.lines().take(12).collect::<Vec<_>>().join("\n")
        )));
    }
    Ok(Build::Ready(NativeRunner {
        dir,
        exe,
        sig: sig.clone(),
        confinement: confinement.clone(),
        build_confinement: report,
    }))
}

fn read_capped(mut r: impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = r.by_ref().take(OUTPUT_CAP as u64).read_to_end(&mut out);
    // Drain the rest so the child never blocks on a full pipe.
    let _ = std::io::copy(&mut r, &mut std::io::sink());
    out
}

impl NativeRunner {
    /// The directory the runner lives in (for diagnostics).
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Runs one case.
    pub fn run(&self, args: &[Arg]) -> Result<Observation, RewriteError> {
        if args.len() != self.sig.params.len() {
            return Err(RewriteError::Unsupported("argument count".into()));
        }
        let mut case = String::new();
        for (p, a) in self.sig.params.iter().zip(args) {
            match (p, a) {
                (Param::Int { bits, .. }, Arg::Int { value }) => {
                    case.push_str(&format!("i {:x}\n", value & mask(*bits)));
                }
                (Param::Buf, Arg::Buf { data }) => {
                    case.push_str(&format!("b {}\n", to_hex(data)));
                }
                _ => return Err(RewriteError::Unsupported("argument kind".into())),
            }
        }
        let case_path = self.dir.path().join("case.txt");
        let result_path = self.dir.path().join("result.txt");
        let _ = std::fs::remove_file(&result_path);
        std::fs::write(&case_path, case).map_err(|e| RewriteError::Native(e.to_string()))?;

        let mut cmd = Command::new(&self.exe);
        cmd.arg(&case_path)
            .arg(&result_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        confine(
            &mut cmd,
            self.dir.path(),
            ReadScope::SystemLibraries,
            &self.confinement,
        )?;
        let mut child = cmd
            .spawn()
            .map_err(|e| RewriteError::Native(format!("cannot start runner: {e}")))?;
        let stdout = child
            .stdout
            .take()
            .map(|s| std::thread::spawn(move || read_capped(s)));
        let stderr = child
            .stderr
            .take()
            .map(|s| std::thread::spawn(move || read_capped(s)));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) if started.elapsed() > CASE_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(e) => return Err(RewriteError::Native(e.to_string())),
            }
        };
        let join = |h: Option<std::thread::JoinHandle<Vec<u8>>>| {
            h.and_then(|h| h.join().ok()).unwrap_or_default()
        };
        let (stdout, stderr) = (join(stdout), join(stderr));

        let termination = match status {
            None => Termination::Timeout,
            Some(s) if s.success() && result_path.is_file() => Termination::Returned,
            Some(s) => match s.code() {
                Some(101) => Termination::Fault {
                    detail: format!(
                        "panic: {}",
                        String::from_utf8_lossy(&stderr)
                            .lines()
                            .take(2)
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                },
                Some(code) => Termination::Exited { status: code },
                None => Termination::Fault {
                    detail: format!("killed by a signal ({s})"),
                },
            },
        };
        let mut obs = Observation::failed(termination.clone());
        obs.stdout = stdout;
        obs.stderr = stderr;
        if termination == Termination::Returned {
            let text = std::fs::read_to_string(&result_path)
                .map_err(|e| RewriteError::Native(format!("result file: {e}")))?;
            for line in text.lines() {
                let mut it = line.split(' ');
                match (it.next(), it.next(), it.next()) {
                    (Some("ret"), Some("none"), _) => {}
                    (Some("ret"), Some(v), _) => {
                        obs.ret = Some(
                            u64::from_str_radix(v, 16)
                                .map_err(|e| RewriteError::Native(format!("bad ret: {e}")))?,
                        );
                    }
                    (Some("buf"), Some(_), Some(h)) => {
                        obs.buffers.push(
                            from_hex(h).ok_or_else(|| RewriteError::Native("bad buffer".into()))?,
                        );
                    }
                    (Some("buf"), Some(_), None) => obs.buffers.push(Vec::new()),
                    _ => {}
                }
            }
        }
        Ok(obs)
    }
}

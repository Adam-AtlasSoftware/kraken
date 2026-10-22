//! Confinement for the processes that build and run model-written Rust (decision 71 spirit:
//! a translation is untrusted code).
//!
//! The primitives (Landlock, network isolation, limits, captured runs) live in the
//! `kraken-confine` crate and are re-exported here; this module adds the Rust toolchain, whose
//! sysroot the compile step may read.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
pub use kraken_confine::system_read_paths;
pub use kraken_confine::{
    Captured, Confinement, ConfinementReport, LANDLOCK_ABI_FLOOR, Limits, NetworkIsolation,
    ReadScope, enforced, landlock_abi_version, run_captured, run_captured_with_input, scratch_dir,
};

use crate::error::RewriteError;

impl From<kraken_confine::ConfineError> for RewriteError {
    fn from(e: kraken_confine::ConfineError) -> Self {
        match e {
            kraken_confine::ConfineError::Refused(m) => RewriteError::Native(m),
            kraken_confine::ConfineError::Scratch(m) => RewriteError::Compile(m),
        }
    }
}

/// Installs the confinement on `cmd`: environment scrubbed to the minimum, working directory
/// `dir`, the filesystem limited as `scope` says with `dir` writable, no network, its own process
/// group. With [`ReadScope::Toolchain`] the toolchain sysroot is readable too.
pub fn confine(
    cmd: &mut Command,
    dir: &Path,
    scope: ReadScope,
    opts: &Confinement,
) -> Result<ConfinementReport, RewriteError> {
    if scope == ReadScope::Toolchain {
        let mut opts = opts.clone();
        opts.exec_read_paths.push(toolchain()?.sysroot);
        return Ok(kraken_confine::confine(cmd, dir, scope, &opts)?);
    }
    Ok(kraken_confine::confine(cmd, dir, scope, opts)?)
}

// ----- toolchain -----

/// The Rust toolchain used to build generated code, resolved to real binaries.
#[derive(Debug, Clone)]
pub struct Toolchain {
    /// `rustc --print sysroot`: the only toolchain location a compile step may read.
    pub sysroot: PathBuf,
    /// The `rustc` binary (inside the sysroot when it has one, so a rustup proxy is bypassed).
    pub rustc: PathBuf,
    /// The `cargo` binary.
    pub cargo: PathBuf,
}

type ToolchainKey = (Option<std::ffi::OsString>, Option<std::ffi::OsString>);

static TOOLCHAIN: std::sync::Mutex<Option<(ToolchainKey, Toolchain)>> = std::sync::Mutex::new(None);

/// Resolves the toolchain (`RUSTC` / `CARGO` if set, else `rustc` / `cargo` on `PATH`). Runs
/// `rustc --print sysroot` once with the caller's own environment; nothing generated is involved.
pub fn toolchain() -> Result<Toolchain, RewriteError> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
    let key: ToolchainKey = (env("RUSTC"), env("CARGO"));
    if let Ok(g) = TOOLCHAIN.lock()
        && let Some((k, t)) = g.as_ref()
        && *k == key
    {
        return Ok(t.clone());
    }
    let candidate = key
        .0
        .clone()
        .map_or_else(|| PathBuf::from("rustc"), PathBuf::from);
    let out = Command::new(&candidate)
        .args(["--print", "sysroot"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| RewriteError::Compile(format!("cannot run {}: {e}", candidate.display())))?;
    if !out.status.success() {
        return Err(RewriteError::Compile(format!(
            "`{} --print sysroot` failed",
            candidate.display()
        )));
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    let sysroot = sysroot
        .canonicalize()
        .map_err(|e| RewriteError::Compile(format!("sysroot {}: {e}", sysroot.display())))?;
    let exe = |name: &str| {
        let p = sysroot.join("bin").join(name);
        if cfg!(windows) {
            p.with_extension("exe")
        } else {
            p
        }
    };
    let rustc = Some(exe("rustc"))
        .filter(|p| p.is_file())
        .unwrap_or(candidate);
    let cargo = key
        .1
        .clone()
        .map(PathBuf::from)
        .or_else(|| Some(exe("cargo")).filter(|p| p.is_file()))
        .unwrap_or_else(|| PathBuf::from("cargo"));
    let t = Toolchain {
        sysroot,
        rustc,
        cargo,
    };
    if let Ok(mut g) = TOOLCHAIN.lock() {
        *g = Some((key, t.clone()));
    }
    Ok(t)
}

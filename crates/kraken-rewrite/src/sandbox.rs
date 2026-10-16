//! Confinement for the processes that build and run model-written Rust (decision 71 spirit:
//! a translation is untrusted code).
//!
//! Linux: a scrubbed environment, `PR_SET_PDEATHSIG`, resource limits, and a Landlock ruleset
//! (filesystem: read-only system paths plus one read-write run directory; TCP denied; abstract
//! unix sockets and signals scoped). A host without Landlock refuses to run unless
//! [`Confinement::allow_unconfined`] is set. Other platforms refuse the same way.

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;

use crate::error::RewriteError;

/// What a confined child may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadScope {
    /// The compiler: the whole file system, read-only (toolchain locations vary).
    Everything,
    /// A compiled runner: system libraries and `/proc` only.
    SystemLibraries,
}

/// Confinement settings.
#[derive(Debug, Clone, Default)]
pub struct Confinement {
    /// Run unconfined when the host cannot confine. Off by default.
    pub allow_unconfined: bool,
}

/// How a child was confined, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementReport {
    /// Landlock ABI version enforced (0 when none).
    pub landlock_abi: u32,
}

impl ConfinementReport {
    /// Short label stored in unit records.
    pub fn label(&self) -> String {
        if self.landlock_abi == 0 {
            "none".to_string()
        } else {
            format!("landlock-v{}", self.landlock_abi)
        }
    }
}

/// Installs the confinement on `cmd`: environment scrubbed to `PATH`/`HOME`-less minimum, working
/// directory `dir`, the filesystem limited as `scope` says with `dir` writable.
pub fn confine(
    cmd: &mut Command,
    dir: &Path,
    scope: ReadScope,
    opts: &Confinement,
) -> Result<ConfinementReport, RewriteError> {
    imp::confine(cmd, dir, scope, opts)
}

#[cfg(target_os = "linux")]
pub(crate) fn system_read_paths() -> Vec<PathBuf> {
    [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/proc",
        "/dev/null",
        "/dev/urandom",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::os::unix::process::CommandExt;

    use landlock::{
        ABI, Access, AccessFs, AccessNet, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
    };

    use super::*;

    const ABI_TARGET: ABI = ABI::V6;
    const MEMORY_LIMIT: u64 = 2 << 30;
    const CPU_SECONDS: u64 = 30;
    const FILE_SIZE_LIMIT: u64 = 64 << 20;

    pub fn landlock_abi() -> u32 {
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
        // SAFETY: with a null attribute pointer and the VERSION flag the syscall only returns the
        // supported ABI number (or -1); it touches no memory.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0 as libc::size_t,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        u32::try_from(rc).unwrap_or(0)
    }

    fn build(dir: &Path, scope: ReadScope) -> Result<RulesetCreated, RewriteError> {
        let err = |what: &str, e: &dyn std::fmt::Display| {
            RewriteError::Native(format!("confinement: {what}: {e}"))
        };
        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI_TARGET))
            .map_err(|e| err("filesystem access", &e))?
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(|e| err("network access", &e))?;
        rs = rs
            .scope(Scope::AbstractUnixSocket)
            .map_err(|e| err("scope", &e))?
            .scope(Scope::Signal)
            .map_err(|e| err("scope", &e))?;
        let mut created = rs.create().map_err(|e| err("ruleset", &e))?;
        let read: Vec<PathBuf> = match scope {
            ReadScope::Everything => vec![PathBuf::from("/")],
            ReadScope::SystemLibraries => system_read_paths(),
        };
        for path in read {
            if let Ok(fd) = PathFd::new(&path) {
                created = created
                    .add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))
                    .map_err(|e| err("read rule", &e))?;
            }
        }
        if let Ok(fd) = PathFd::new("/dev/null") {
            created = created
                .add_rule(PathBeneath::new(
                    fd,
                    AccessFs::ReadFile | AccessFs::WriteFile,
                ))
                .map_err(|e| err("null device", &e))?;
        }
        let mut writable = vec![dir.to_path_buf()];
        if scope == ReadScope::Everything {
            // The linker (mold) ignores TMPDIR and insists on /tmp. Compile step only: no
            // model code runs yet, and the lint has refused anything that reads files.
            writable.push(PathBuf::from("/tmp"));
        }
        for w in writable {
            let fd = PathFd::new(&w).map_err(|e| err("writable directory", &e))?;
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_all(ABI_TARGET)))
                .map_err(|e| err("write rule", &e))?;
        }
        Ok(created)
    }

    pub fn confine(
        cmd: &mut Command,
        dir: &Path,
        scope: ReadScope,
        opts: &Confinement,
    ) -> Result<ConfinementReport, RewriteError> {
        let abi = landlock_abi();
        if abi == 0 && !opts.allow_unconfined {
            return Err(RewriteError::Native(
                "Landlock is not enforced on this host; refusing to run model-written code \
                 unconfined (set Confinement::allow_unconfined to accept the risk)"
                    .into(),
            ));
        }
        cmd.env_clear().current_dir(dir);
        // The compiler needs PATH to find `cc`; the runner needs nothing.
        if scope == ReadScope::Everything {
            if let Some(p) = std::env::var_os("PATH") {
                cmd.env("PATH", p);
            }
            for k in ["HOME", "RUSTUP_HOME", "CARGO_HOME", "RUSTUP_TOOLCHAIN"] {
                if let Some(v) = std::env::var_os(k) {
                    cmd.env(k, v);
                }
            }
        }
        let mut ruleset = if abi > 0 {
            Some(build(dir, scope)?)
        } else {
            None
        };
        let parent = std::process::id();
        // SAFETY: runs in the forked child before exec: plain syscalls plus the landlock
        // crate's restrict_self; the child is single threaded until exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() as u32 != parent {
                    libc::_exit(1);
                }
                let limit = |res, v: u64| {
                    let l = libc::rlimit {
                        rlim_cur: v,
                        rlim_max: v,
                    };
                    libc::setrlimit(res, &l)
                };
                if scope == ReadScope::SystemLibraries {
                    // A runner is single-purpose: bounded memory, CPU and output files; no cores.
                    limit(libc::RLIMIT_AS, MEMORY_LIMIT);
                    limit(libc::RLIMIT_CPU, CPU_SECONDS);
                    limit(libc::RLIMIT_FSIZE, FILE_SIZE_LIMIT);
                    limit(libc::RLIMIT_CORE, 0);
                }
                if let Some(rs) = ruleset.take() {
                    let status = rs.restrict_self().map_err(io::Error::other)?;
                    if status.ruleset == RulesetStatus::NotEnforced {
                        return Err(io::Error::other("landlock not enforced"));
                    }
                }
                Ok(())
            });
        }
        Ok(ConfinementReport { landlock_abi: abi })
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn confine(
        cmd: &mut Command,
        dir: &Path,
        _scope: ReadScope,
        opts: &Confinement,
    ) -> Result<ConfinementReport, RewriteError> {
        if !opts.allow_unconfined {
            return Err(RewriteError::Native(
                "confinement of model-written code is only implemented on Linux (Landlock)".into(),
            ));
        }
        cmd.env_clear().current_dir(dir);
        Ok(ConfinementReport { landlock_abi: 0 })
    }
}

//! Engine configuration and JVM sizing.

use std::path::PathBuf;
use std::time::Duration;

use crate::install::GhidraInstall;
use crate::sandbox::ConfinementOptions;

/// Smallest JVM heap, in MiB.
pub const MIN_HEAP_MB: u64 = 1024;
/// Default upper bound of the heap, in MiB (further limited to half the RAM).
pub const DEFAULT_MAX_HEAP_MB: u64 = 4096;

/// Per-request deadlines. A request that exceeds its deadline fails with `timeout`.
#[derive(Debug, Clone)]
pub struct Deadlines {
    /// Reads, edits and everything not listed below (default 120 s).
    pub default: Duration,
    /// `decompile` (default 30 s); also passed to the decompiler as its own limit.
    pub decompile: Duration,
    /// `open_binary`, which imports the file on first use (default 600 s).
    pub open_binary: Duration,
    /// `analyze`; `None` (default) means analysis runs until done or cancelled.
    pub analyze: Option<Duration>,
}

impl Default for Deadlines {
    fn default() -> Self {
        Deadlines {
            default: Duration::from_secs(120),
            decompile: Duration::from_secs(30),
            open_binary: Duration::from_secs(600),
            analyze: None,
        }
    }
}

/// Everything [`GhidraEngine`](crate::GhidraEngine) needs.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// The Ghidra + JDK + extension to run.
    pub install: GhidraInstall,
    /// Directory of the Ghidra project (created if missing, read-write for the sidecar).
    pub project_dir: PathBuf,
    /// Confinement policy.
    pub confinement: ConfinementOptions,
    /// Upper bound of the JVM heap in MiB; default `min(4096, 50% of RAM)`.
    pub max_heap_mb: Option<u64>,
    /// Request deadlines.
    pub deadlines: Deadlines,
    /// Attempts made by one [`restart`](crate::GhidraEngine::restart) call (default 3).
    pub max_restarts: u32,
    /// How long to wait for the sidecar's `ready` notification and handshake (default 60 s).
    pub startup_timeout: Duration,
    /// Base delay between restart attempts (default 250 ms, multiplied by the attempt number).
    pub restart_backoff: Duration,
    /// Parent of the per-session temporary home; default the system temp dir.
    pub temp_root: Option<PathBuf>,
}

impl EngineConfig {
    /// Defaults for everything but the install and the project directory.
    pub fn new(install: GhidraInstall, project_dir: impl Into<PathBuf>) -> Self {
        EngineConfig {
            install,
            project_dir: project_dir.into(),
            confinement: ConfinementOptions::default(),
            max_heap_mb: None,
            deadlines: Deadlines::default(),
            max_restarts: 3,
            startup_timeout: Duration::from_secs(60),
            restart_backoff: Duration::from_millis(250),
            temp_root: None,
        }
    }
}

/// Physical memory in MiB, if the platform can tell.
pub fn physical_memory_mb() -> Option<u64> {
    #[cfg(unix)]
    {
        // SAFETY: sysconf has no preconditions.
        let (pages, size) = unsafe {
            (
                libc::sysconf(libc::_SC_PHYS_PAGES),
                libc::sysconf(libc::_SC_PAGESIZE),
            )
        };
        (pages > 0 && size > 0).then(|| (pages as u64).saturating_mul(size as u64) / (1024 * 1024))
    }
    #[cfg(not(unix))]
    {
        kraken_procguard::total_memory_bytes().map(|b| b / (1024 * 1024))
    }
}

/// JVM heap for a binary of `binary_size` bytes: 1 GiB plus 64 MiB per MiB of binary, at least
/// [`MIN_HEAP_MB`], at most `max_mb` (default `min(4096, ram/2)`).
pub fn heap_mb(binary_size: u64, max_mb: Option<u64>, ram_mb: Option<u64>) -> u64 {
    let max = max_mb.unwrap_or_else(|| {
        ram_mb.map_or(DEFAULT_MAX_HEAP_MB, |r| (r / 2).min(DEFAULT_MAX_HEAP_MB))
    });
    let want = MIN_HEAP_MB + (binary_size / (1024 * 1024)).saturating_mul(64);
    want.min(max).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heap_scales_with_the_binary_and_respects_the_cap() {
        let mib = 1024 * 1024;
        assert_eq!(heap_mb(100_000, None, Some(64 * 1024)), 1024);
        assert_eq!(heap_mb(10 * mib, None, Some(64 * 1024)), 1024 + 640);
        assert_eq!(heap_mb(500 * mib, None, Some(64 * 1024)), 4096);
        assert_eq!(heap_mb(500 * mib, Some(2048), Some(64 * 1024)), 2048);
        assert_eq!(heap_mb(500 * mib, None, Some(6 * 1024)), 3072);
        assert_eq!(heap_mb(0, None, None), 1024);
    }

    #[test]
    fn deadlines_default_as_specified() {
        let d = Deadlines::default();
        assert_eq!(d.default, Duration::from_secs(120));
        assert_eq!(d.decompile, Duration::from_secs(30));
        assert!(d.analyze.is_none());
    }
}

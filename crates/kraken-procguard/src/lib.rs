//! Parent-death cleanup for supervised children (decisions 40 and 68).
//!
//! Linux uses `PR_SET_PDEATHSIG` and macOS a parent-pid watch inside the child, both set up by
//! the callers. Windows has neither, so a [`ProcessGuard`] wraps a job object created with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: every process assigned to it dies when the last handle
//! to the job closes, which the OS does for us when the supervising process exits for any
//! reason, including a crash. On other platforms the guard is an inert placeholder so callers
//! need no cfg.

#[cfg(windows)]
mod imp;

#[cfg(not(windows))]
mod imp {
    use std::io;

    /// Inert on this platform; see the crate docs.
    #[derive(Debug, Default)]
    pub struct ProcessGuard;

    impl ProcessGuard {
        /// Creates the guard.
        pub fn new() -> io::Result<Self> {
            Ok(ProcessGuard)
        }

        /// Adds the live child `pid` to the guard (no-op here).
        pub fn assign_pid(&self, _pid: u32) -> io::Result<()> {
            Ok(())
        }

        /// Kills everything in the guard (no-op here; callers signal the process group).
        pub fn terminate(&self) {}
    }
}

pub use imp::ProcessGuard;

/// Makes `child_pid` (or its whole process group when `group`) die if this process dies.
///
/// Linux uses `PR_SET_PDEATHSIG` set by the callers and Windows uses [`ProcessGuard`], so this is
/// a no-op there. On macOS and other Unixes it starts a tiny `/bin/sh` watchdog that polls both
/// pids once a second and sends SIGKILL when this process is gone first. The watchdog exits
/// quietly as soon as the child does.
pub fn watch_parent_death(child_pid: u32, group: bool) {
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::process::{Command, Stdio};
        const SCRIPT: &str = r#"
while kill -0 "$1" 2>/dev/null && kill -0 "$2" 2>/dev/null; do sleep 1; done
if ! kill -0 "$1" 2>/dev/null && kill -0 "$2" 2>/dev/null; then
  if [ "$3" = group ]; then kill -KILL -- "-$2" 2>/dev/null; else kill -KILL "$2" 2>/dev/null; fi
fi
"#;
        let spawned = Command::new("/bin/sh")
            .arg("-c")
            .arg(SCRIPT)
            .arg("kraken-watchdog")
            .arg(std::process::id().to_string())
            .arg(child_pid.to_string())
            .arg(if group { "group" } else { "single" })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if let Ok(mut watchdog) = spawned {
            // Reap it when it exits so a long-lived daemon leaves no zombies.
            let _ = std::thread::Builder::new()
                .name("kraken-watchdog-reaper".into())
                .spawn(move || {
                    let _ = watchdog.wait();
                });
        }
    }
    #[cfg(not(all(unix, not(target_os = "linux"))))]
    {
        let _ = (child_pid, group);
    }
}

/// Total physical memory in bytes on macOS and Windows; `None` elsewhere or when the probe fails
/// (Linux callers read `/proc/meminfo` or `sysconf` themselves).
pub fn total_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/sbin/sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse().ok()
    }
    #[cfg(windows)]
    {
        imp::total_memory_bytes()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessGuard;

    #[test]
    fn guard_constructs_and_terminates() {
        let g = ProcessGuard::new().expect("guard");
        g.terminate();
    }
}

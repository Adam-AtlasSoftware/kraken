//! `daemon.json`: who is running, and liveness checks for stale cleanup.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::IpcError;
use crate::token::{hex_encode, random_bytes, write_private_atomic};

/// Contents of `daemon.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonInfo {
    /// Daemon process id.
    pub pid: u32,
    /// Random per-run token guarding against pid reuse.
    pub start_token: String,
    /// IPC protocol version the daemon speaks.
    pub protocol: u32,
    /// Daemon build identifier.
    pub build: String,
}

impl DaemonInfo {
    /// Info for the current process with a fresh start token.
    pub fn for_current_process(protocol: u32, build: impl Into<String>) -> Result<Self, IpcError> {
        let mut b = [0u8; 16];
        random_bytes(&mut b)?;
        Ok(DaemonInfo {
            pid: std::process::id(),
            start_token: hex_encode(&b),
            protocol,
            build: build.into(),
        })
    }

    /// Atomically writes the file (0600).
    pub fn write(&self, path: &Path) -> Result<(), IpcError> {
        let json = serde_json::to_vec_pretty(self).map_err(|source| IpcError::Malformed {
            what: "daemon.json",
            source,
        })?;
        write_private_atomic(path, &json)
    }

    /// Reads the file; `Ok(None)` when absent.
    pub fn read(path: &Path) -> Result<Option<Self>, IpcError> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
                .map_err(|source| IpcError::Malformed {
                    what: "daemon.json",
                    source,
                }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Whether a process with this pid currently exists.
#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    use rustix::process::{Pid, test_kill_process};
    let Some(pid) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return false;
    };
    match test_kill_process(pid) {
        Ok(()) => true,
        Err(e) => e == rustix::io::Errno::PERM,
    }
}

/// Whether a process with this pid currently exists.
#[cfg(windows)]
pub fn pid_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: plain Win32 calls; the handle is closed before returning.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0;
        CloseHandle(h);
        ok && code == STILL_ACTIVE as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_liveness() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("daemon.json");
        assert_eq!(DaemonInfo::read(&p).unwrap(), None);
        let i = DaemonInfo::for_current_process(1, "b").unwrap();
        i.write(&p).unwrap();
        assert_eq!(DaemonInfo::read(&p).unwrap(), Some(i.clone()));
        assert!(pid_alive(i.pid));
    }

    #[cfg(unix)]
    #[test]
    fn reaped_child_is_dead() {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        assert!(!pid_alive(pid));
    }
}

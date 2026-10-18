//! The advisory lock that keeps a project to one process.
//!
//! Each process that opens a project in-process holds its engine's state in memory and saves it
//! on exit; a second process with its own engine would overwrite the first one's saved state.
//! A session therefore takes an exclusive lock on `kraken.lock` in the project directory when it
//! opens or creates a project and releases it when the project is dropped. The lock is per
//! process: sessions of one process (the daemon's, or tests that open a project twice) share it.
//! A client of the daemon never opens the project itself, so it never takes the lock.

use std::collections::HashMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, Weak};

use kraken_proto::{ErrorCode, ProtoError};

/// Name of the lock file in the project directory.
pub const LOCK_FILE: &str = "kraken.lock";

static HELD: LazyLock<Mutex<HashMap<PathBuf, Weak<Held>>>> = LazyLock::new(Mutex::default);

fn held() -> MutexGuard<'static, HashMap<PathBuf, Weak<Held>>> {
    HELD.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Held {
    key: PathBuf,
    file: File,
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut map = held();
        // Unlock while the table is locked, so an acquire racing this drop never finds the file
        // still locked by this process.
        let _ = self.file.unlock();
        if map.get(&self.key).is_some_and(|w| w.strong_count() == 0) {
            map.remove(&self.key);
        }
    }
}

/// This process's hold on a project directory; the lock is released when the last handle of
/// the process is dropped.
#[derive(Clone)]
pub struct ProjectLock {
    inner: Arc<Held>,
}

impl std::fmt::Debug for ProjectLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProjectLock")
            .field("dir", &self.inner.key)
            .finish()
    }
}

/// The message of a project held by another process.
pub(crate) fn in_use_message(dir: &Path, pid: Option<u32>) -> String {
    let who = match pid {
        Some(pid) => format!("another KRAKEN process (pid {pid})"),
        None => "another KRAKEN process".to_string(),
    };
    format!(
        "the project {} is open in {who}; close it, or use the daemon (krakend), which lets \
         several tools share one session",
        dir.display()
    )
}

/// Takes this process's lock on the project in `dir` (an existing directory), or shares the one
/// it already holds. Fails with `unsupported` when another process holds it.
pub fn acquire(dir: &Path) -> Result<ProjectLock, ProtoError> {
    let key = std::fs::canonicalize(dir).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot open the project {}: {e}", dir.display()),
        )
    })?;
    let mut map = held();
    if let Some(h) = map.get(&key).and_then(Weak::upgrade) {
        return Ok(ProjectLock { inner: h });
    }
    let path = key.join(LOCK_FILE);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("cannot open {}: {e}", path.display()),
            )
        })?;
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            let mut text = String::new();
            let pid = file
                .read_to_string(&mut text)
                .ok()
                .and_then(|_| text.trim().parse::<u32>().ok());
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                in_use_message(&key, pid),
            ));
        }
        Err(TryLockError::Error(e)) => {
            return Err(ProtoError::new(
                ErrorCode::Internal,
                format!("cannot lock {}: {e}", path.display()),
            ));
        }
    }
    // The pid is a courtesy for the message another process shows; failing to write it is not
    // a reason to refuse the open.
    let _ = file
        .set_len(0)
        .and_then(|()| file.seek(SeekFrom::Start(0)))
        .and_then(|_| writeln!(file, "{}", std::process::id()));
    let h = Arc::new(Held {
        key: key.clone(),
        file,
    });
    map.insert(key, Arc::downgrade(&h));
    Ok(ProjectLock { inner: h })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_process_shares_its_lock_and_releases_it_with_the_last_handle() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = acquire(tmp.path()).expect("first");
        let b = acquire(tmp.path()).expect("second handle in the same process");
        let text = std::fs::read_to_string(tmp.path().join(LOCK_FILE)).expect("lock file");
        assert_eq!(text.trim(), std::process::id().to_string());
        drop(a);
        assert!(held().contains_key(&std::fs::canonicalize(tmp.path()).expect("canon")));
        drop(b);
        assert!(!held().contains_key(&std::fs::canonicalize(tmp.path()).expect("canon")));
        // another open file description stands in for another process
        let other = File::open(tmp.path().join(LOCK_FILE)).expect("open");
        other.try_lock().expect("released");
    }

    #[test]
    fn a_lock_held_elsewhere_is_refused_with_the_pid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join(LOCK_FILE);
        std::fs::write(&path, "4242\n").expect("write");
        let other = File::open(&path).expect("open");
        other.try_lock().expect("lock");
        let e = acquire(tmp.path()).expect_err("held elsewhere");
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("pid 4242"), "{}", e.message);
        assert!(e.message.contains("daemon"), "{}", e.message);
        drop(other);
        acquire(tmp.path()).expect("free again");
    }
}

//! One-use approvals for the assistant's dangerous commands.
//!
//! A terminal agent reaches KRAKEN's tools through a `kraken mcp` process that cannot see what
//! the person decided: the window that shows the permission card, or that holds YOLO mode, is
//! somewhere else. When the assistant may run a command, the window leaves a grant here and the
//! process that would otherwise have to ask takes it. A grant names one command, works once and
//! lapses within a minute, so it answers the call it was made for and no later one.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crate::config::KrakenConfig;

/// How long a grant waits for its call.
pub const GRANT_LIFETIME: Duration = Duration::from_secs(60);

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The folder of the grants, next to the config file.
pub fn default_dir() -> Option<PathBuf> {
    KrakenConfig::default_path().and_then(|p| Some(p.parent()?.join("assistant-grants")))
}

fn valid(command: &str) -> bool {
    !command.is_empty()
        && command
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Allows one call of `command`.
pub fn grant(dir: &Path, command: &str) -> std::io::Result<()> {
    if !valid(command) {
        return Err(std::io::Error::other("not a command name"));
    }
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    std::fs::write(
        dir.join(format!("{command}.{}.{n}", std::process::id())),
        "",
    )
}

/// Takes a grant for `command`; true when there was one. Lapsed grants are removed on the way.
pub fn take(dir: &Path, command: &str) -> bool {
    if !valid(command) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    let prefix = format!("{command}.");
    let now = SystemTime::now();
    let mut found = false;
    for e in entries.filter_map(Result::ok) {
        let lapsed = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_none_or(|age| age > GRANT_LIFETIME);
        if lapsed {
            let _ = std::fs::remove_file(e.path());
        } else if !found
            && e.file_name().to_string_lossy().starts_with(&prefix)
            && std::fs::remove_file(e.path()).is_ok()
        {
            // Removing it is what claims it: two callers cannot both succeed.
            found = true;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_grant_names_one_command_and_works_once() {
        let d = tempfile::tempdir().unwrap();
        assert!(!take(d.path(), "patch_export"));
        grant(d.path(), "patch_export").unwrap();
        assert!(!take(d.path(), "rewrite_build"), "another command");
        assert!(take(d.path(), "patch_export"));
        assert!(!take(d.path(), "patch_export"), "used up");
    }

    #[test]
    fn two_grants_allow_two_calls() {
        let d = tempfile::tempdir().unwrap();
        grant(d.path(), "patch_export").unwrap();
        grant(d.path(), "patch_export").unwrap();
        assert!(take(d.path(), "patch_export"));
        assert!(take(d.path(), "patch_export"));
        assert!(!take(d.path(), "patch_export"));
    }

    #[test]
    fn an_old_grant_has_lapsed_and_is_cleared() {
        let d = tempfile::tempdir().unwrap();
        grant(d.path(), "patch_export").unwrap();
        let file = std::fs::read_dir(d.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        let old = SystemTime::now() - GRANT_LIFETIME - Duration::from_secs(5);
        std::fs::File::options()
            .write(true)
            .open(file.path())
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(!take(d.path(), "patch_export"));
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_name_cannot_leave_the_folder() {
        let d = tempfile::tempdir().unwrap();
        assert!(grant(d.path(), "../x").is_err());
        assert!(!take(d.path(), "../x"));
    }
}

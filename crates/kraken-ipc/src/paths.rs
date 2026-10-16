//! Per-user runtime directory resolution and the well-known file names inside it.

use std::path::{Path, PathBuf};

use crate::error::IpcError;

/// Environment variable overriding the runtime directory.
pub const ENV_RUNTIME_DIR: &str = "KRAKEN_RUNTIME_DIR";

/// Maximum accepted socket path length in bytes (macOS `sun_path` is 104 incl. NUL).
pub const MAX_SOCKET_PATH_LEN: usize = 100;

/// A resolved per-user runtime directory.
#[derive(Debug, Clone)]
pub struct RuntimeDir {
    dir: PathBuf,
}

impl RuntimeDir {
    /// Resolves the platform default directory, creating it with mode 0700 where applicable.
    ///
    /// `KRAKEN_RUNTIME_DIR` (an absolute path) overrides the platform default; tests and
    /// side-by-side installs use it to get a private daemon.
    pub fn resolve() -> Result<Self, IpcError> {
        Self::resolve_with(&|k| std::env::var_os(k))
    }

    /// [`resolve`](Self::resolve) with an injectable environment.
    pub fn resolve_with(
        env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
    ) -> Result<Self, IpcError> {
        if let Some(dir) = env(ENV_RUNTIME_DIR)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
        {
            if !dir.is_absolute() {
                return Err(IpcError::NoRuntimeDir(format!(
                    "{ENV_RUNTIME_DIR} must be an absolute path, got {}",
                    dir.display()
                )));
            }
            return Self::from_dir(dir);
        }
        #[cfg(target_os = "linux")]
        {
            let xdg = env("XDG_RUNTIME_DIR").map(PathBuf::from);
            Self::resolve_linux(xdg.as_deref(), rustix::process::getuid().as_raw())
        }
        #[cfg(target_os = "macos")]
        {
            let home = env("HOME")
                .map(PathBuf::from)
                .ok_or_else(|| IpcError::NoRuntimeDir("HOME is not set".into()))?;
            Self::from_dir(home.join("Library/Application Support/kraken/run"))
        }
        #[cfg(windows)]
        {
            Self::from_dir(windows_state_dir()?)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            Err(IpcError::NoRuntimeDir("unsupported platform".into()))
        }
    }

    /// Linux resolution with injected inputs: `$XDG_RUNTIME_DIR/kraken`, else `/tmp/kraken-<uid>`.
    #[cfg(unix)]
    pub fn resolve_linux(xdg_runtime_dir: Option<&Path>, uid: u32) -> Result<Self, IpcError> {
        match xdg_runtime_dir.filter(|p| p.is_absolute()) {
            Some(x) => Self::from_dir(x.join("kraken")),
            None => Self::from_dir(PathBuf::from(format!("/tmp/kraken-{uid}"))),
        }
    }

    /// Uses `dir` as the runtime directory: creates it 0700 (parents default perms) and verifies
    /// it is a real directory owned by this user with no group/other access.
    #[cfg(unix)]
    pub fn from_dir(dir: PathBuf) -> Result<Self, IpcError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let md = std::fs::symlink_metadata(&dir)?;
        let insecure = |reason: &str| IpcError::InsecureDir {
            path: dir.clone(),
            reason: reason.into(),
        };
        if !md.is_dir() {
            return Err(insecure("not a directory (or a symlink)"));
        }
        if md.uid() != rustix::process::getuid().as_raw() {
            return Err(insecure("not owned by the current user"));
        }
        if md.mode() & 0o077 != 0 {
            return Err(insecure("accessible by group or others"));
        }
        let me = RuntimeDir { dir };
        me.check_socket_len()?;
        Ok(me)
    }

    /// Windows has no filesystem socket; state files live under the user's local app data.
    #[cfg(windows)]
    pub fn from_dir(dir: PathBuf) -> Result<Self, IpcError> {
        std::fs::create_dir_all(&dir)?;
        Ok(RuntimeDir { dir })
    }

    #[cfg(unix)]
    fn check_socket_len(&self) -> Result<(), IpcError> {
        use std::os::unix::ffi::OsStrExt;
        let path = self.socket_path();
        let len = path.as_os_str().as_bytes().len();
        if len > MAX_SOCKET_PATH_LEN {
            return Err(IpcError::SocketPathTooLong {
                path,
                len,
                limit: MAX_SOCKET_PATH_LEN,
            });
        }
        Ok(())
    }

    /// The directory itself.
    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Unix domain socket path.
    pub fn socket_path(&self) -> PathBuf {
        self.dir.join("daemon.sock")
    }

    /// Spawn-serialisation lock used by `ensure_daemon`.
    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("daemon.lock")
    }

    /// Lock held by the running daemon for its whole life (single-instance proof).
    pub fn run_lock_path(&self) -> PathBuf {
        self.dir.join("daemon.run.lock")
    }

    /// Auth token file.
    pub fn token_path(&self) -> PathBuf {
        self.dir.join("daemon.token")
    }

    /// Daemon info file (`pid`, start token, protocol, build).
    pub fn info_path(&self) -> PathBuf {
        self.dir.join("daemon.json")
    }

    /// Windows named pipe name, `\\.\pipe\kraken-<user>`.
    pub fn pipe_name(&self) -> String {
        pipe_name_for(&current_user_name())
    }
}

/// Formats the pipe name for a user.
pub fn pipe_name_for(user: &str) -> String {
    let clean: String = user
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!(r"\\.\pipe\kraken-{clean}")
}

fn current_user_name() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "user".into())
}

#[cfg(windows)]
fn windows_state_dir() -> Result<PathBuf, IpcError> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| IpcError::NoRuntimeDir("LOCALAPPDATA is not set".into()))?;
    Ok(base.join("kraken").join("run"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn xdg_dir_is_created_private() {
        let t = tempfile::tempdir().unwrap();
        let d = RuntimeDir::resolve_linux(Some(t.path()), 1).unwrap();
        assert_eq!(d.path(), t.path().join("kraken"));
        let mode = std::fs::metadata(d.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        assert!(d.socket_path().ends_with("daemon.sock"));
    }

    #[test]
    fn env_override_wins_and_must_be_absolute() {
        let t = tempfile::tempdir().unwrap();
        let want = t.path().join("rt");
        let w = want.clone();
        let d = RuntimeDir::resolve_with(&move |k| {
            (k == ENV_RUNTIME_DIR).then(|| w.clone().into_os_string())
        })
        .unwrap();
        assert_eq!(d.path(), want);
        let rel = RuntimeDir::resolve_with(&|k| (k == ENV_RUNTIME_DIR).then(|| "rel/dir".into()));
        assert!(matches!(rel, Err(IpcError::NoRuntimeDir(_))));
    }

    #[test]
    fn fallback_uses_tmp_uid() {
        let uid = rustix::process::getuid().as_raw();
        let d = RuntimeDir::resolve_linux(None, uid).unwrap();
        assert_eq!(d.path(), Path::new(&format!("/tmp/kraken-{uid}")));
    }

    #[test]
    fn loose_permissions_rejected() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("loose");
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            RuntimeDir::from_dir(p),
            Err(IpcError::InsecureDir { .. })
        ));
    }

    #[test]
    fn symlink_rejected() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(matches!(
            RuntimeDir::from_dir(link),
            Err(IpcError::InsecureDir { .. })
        ));
    }

    #[test]
    fn long_socket_path_rejected() {
        let t = tempfile::tempdir().unwrap();
        let long = t.path().join("x".repeat(120));
        assert!(matches!(
            RuntimeDir::from_dir(long),
            Err(IpcError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn pipe_name_sanitised() {
        assert_eq!(pipe_name_for("a b\\c"), r"\\.\pipe\kraken-a_b_c");
    }
}

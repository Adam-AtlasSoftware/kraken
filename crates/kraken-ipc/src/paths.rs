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
    notice: Option<String>,
}

/// A directory short enough for the socket, suggested in messages.
pub const SUGGESTED_SHORT_DIR: &str = "/tmp/kr";

/// Environment variable naming the temporary directory; named in the message when the runtime
/// directory lives under it.
pub const ENV_TMPDIR: &str = "TMPDIR";

/// The advice for a socket path that is too long: names the setting the directory came from.
/// `var` is that setting's name and `value` its value; when `value` lies under `tmpdir`, the
/// temporary directory is named instead, because that is the setting the person would change.
pub fn socket_path_advice(var: &str, value: &Path, tmpdir: Option<&Path>) -> String {
    let short = SUGGESTED_SHORT_DIR;
    match tmpdir.filter(|t| !t.as_os_str().is_empty() && value.starts_with(t)) {
        Some(t) => format!(
            "Your {ENV_TMPDIR} ({}) is too long: set {ENV_TMPDIR} or {ENV_RUNTIME_DIR} to a \
             shorter directory such as {short}.",
            t.display()
        ),
        None if var == ENV_RUNTIME_DIR => format!(
            "Your {var} ({}) is too long: set {var} to a shorter directory such as {short}.",
            value.display()
        ),
        None => format!(
            "Your {var} ({}) is too long: set {ENV_RUNTIME_DIR} to a shorter directory such as \
             {short}.",
            value.display()
        ),
    }
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
            let tmpdir = env(ENV_TMPDIR).map(PathBuf::from);
            return Self::from_dir(dir.clone())
                .map_err(|e| with_advice(e, ENV_RUNTIME_DIR, &dir, tmpdir.as_deref()));
        }
        #[cfg(target_os = "linux")]
        {
            let xdg = env("XDG_RUNTIME_DIR").map(PathBuf::from);
            let tmpdir = env(ENV_TMPDIR).map(PathBuf::from);
            match Self::resolve_linux(xdg.as_deref()) {
                Err(IpcError::SocketPathTooLong { .. }) => {
                    let x = xdg.unwrap_or_default();
                    Self::resolve_fallback(&x, tmpdir.as_deref())
                        .map_err(|e| with_advice(e, "XDG_RUNTIME_DIR", &x, tmpdir.as_deref()))
                }
                other => other,
            }
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

    /// Linux resolution with injected inputs: `$XDG_RUNTIME_DIR/kraken`.
    ///
    /// Fails closed when `XDG_RUNTIME_DIR` is missing or relative: there is deliberately no
    /// fallback into the world-writable `/tmp`, where another user could pre-create the
    /// directory. Set `KRAKEN_RUNTIME_DIR` to an absolute private path instead. (A set but
    /// too long `XDG_RUNTIME_DIR` is different: `resolve_with` falls back to `/tmp/kraken-<uid>`,
    /// which must pass the same ownership and mode checks.)
    #[cfg(unix)]
    pub fn resolve_linux(xdg_runtime_dir: Option<&Path>) -> Result<Self, IpcError> {
        match xdg_runtime_dir.filter(|p| p.is_absolute()) {
            Some(x) => Self::from_dir(x.join("kraken")),
            None => Err(IpcError::NoRuntimeDir(format!(
                "XDG_RUNTIME_DIR is not set to an absolute path; set it, or set {ENV_RUNTIME_DIR} \
                 to a private absolute directory"
            ))),
        }
    }

    /// `XDG_RUNTIME_DIR` is too long for a socket: use the private `/tmp/kraken-<uid>` instead.
    /// The directory must be a real directory owned by this user with mode 0700 (checked like
    /// any runtime directory), so another user pre-creating the name only makes this fail. An
    /// explicit `KRAKEN_RUNTIME_DIR` is never replaced: that choice is honoured or reported.
    #[cfg(target_os = "linux")]
    fn resolve_fallback(xdg: &Path, tmpdir: Option<&Path>) -> Result<Self, IpcError> {
        let uid = rustix::process::getuid().as_raw();
        let mut me = Self::from_dir(PathBuf::from(format!("/tmp/kraken-{uid}")))?;
        let culprit = match tmpdir.filter(|t| xdg.starts_with(t)) {
            Some(t) => format!("your {ENV_TMPDIR} ({})", t.display()),
            None => format!("your XDG_RUNTIME_DIR ({})", xdg.display()),
        };
        me.notice = Some(format!(
            "warning: {culprit} is too long for the daemon socket (the limit is {MAX_SOCKET_PATH_LEN} \
             bytes); using {} instead. Set {ENV_RUNTIME_DIR} to a short directory such as \
             {SUGGESTED_SHORT_DIR} to choose it yourself.",
            me.dir.display()
        ));
        Ok(me)
    }

    /// A warning about how the directory was chosen (a fallback was used), if any. Callers show
    /// it to the person: `krakend` and the CLI on stderr, the GUI on its welcome screen.
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
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
        let me = RuntimeDir { dir, notice: None };
        me.check_socket_len()?;
        Ok(me)
    }

    /// Windows has no filesystem socket; state files live under the user's local app data.
    #[cfg(windows)]
    pub fn from_dir(dir: PathBuf) -> Result<Self, IpcError> {
        std::fs::create_dir_all(&dir)?;
        Ok(RuntimeDir { dir, notice: None })
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
                advice: socket_path_advice(ENV_RUNTIME_DIR, &self.dir, None),
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

    /// Token file of the agent credential class (MCP servers and other agent-side clients). It
    /// opens connections whose author is always an agent and whose approvals are never trusted;
    /// the user token in [`token_path`](Self::token_path) is the only one that can approve.
    pub fn agent_token_path(&self) -> PathBuf {
        self.dir.join("agent.token")
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

/// Replaces the advice of a too-long-socket error with one naming where the directory came from.
fn with_advice(e: IpcError, var: &str, value: &Path, tmpdir: Option<&Path>) -> IpcError {
    match e {
        IpcError::SocketPathTooLong {
            path, len, limit, ..
        } => IpcError::SocketPathTooLong {
            path,
            len,
            limit,
            advice: socket_path_advice(var, value, tmpdir),
        },
        other => other,
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
        let d = RuntimeDir::resolve_linux(Some(t.path())).unwrap();
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
    fn missing_or_relative_xdg_fails_closed() {
        assert!(matches!(
            RuntimeDir::resolve_linux(None),
            Err(IpcError::NoRuntimeDir(_))
        ));
        assert!(matches!(
            RuntimeDir::resolve_linux(Some(Path::new("relative/run"))),
            Err(IpcError::NoRuntimeDir(_))
        ));
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

    fn long_env(
        var: &'static str,
        extra: Option<(&'static str, String)>,
        v: String,
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        move |k| {
            if k == var {
                return Some(v.clone().into());
            }
            extra
                .as_ref()
                .filter(|(n, _)| *n == k)
                .map(|(_, x)| x.clone().into())
        }
    }

    #[test]
    fn advice_names_tmpdir_when_dir_lives_under_it() {
        let a = socket_path_advice(
            ENV_RUNTIME_DIR,
            Path::new("/tmp/very/long/rt"),
            Some(Path::new("/tmp/very/long")),
        );
        assert_eq!(
            a,
            "Your TMPDIR (/tmp/very/long) is too long: set TMPDIR or KRAKEN_RUNTIME_DIR to a \
             shorter directory such as /tmp/kr."
        );
        let b = socket_path_advice(ENV_RUNTIME_DIR, Path::new("/a/b"), Some(Path::new("/tmp")));
        assert!(
            b.starts_with("Your KRAKEN_RUNTIME_DIR (/a/b) is too long"),
            "{b}"
        );
        let c = socket_path_advice("XDG_RUNTIME_DIR", Path::new("/a/b"), None);
        assert!(c.contains("XDG_RUNTIME_DIR (/a/b)") && c.contains("set KRAKEN_RUNTIME_DIR"));
    }

    #[test]
    fn explicit_runtime_dir_too_long_reports_and_does_not_fall_back() {
        let t = tempfile::tempdir().unwrap();
        let long = t.path().join("x".repeat(120));
        let env = long_env(
            ENV_RUNTIME_DIR,
            Some((ENV_TMPDIR, t.path().to_string_lossy().into_owned())),
            long.to_string_lossy().into_owned(),
        );
        let err = RuntimeDir::resolve_with(&env).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, IpcError::SocketPathTooLong { .. }));
        assert!(msg.contains("bytes; the limit is 100."), "{msg}");
        assert!(msg.contains("Your TMPDIR ("), "{msg}");
        assert!(msg.contains("such as /tmp/kr."), "{msg}");
    }

    #[test]
    fn explicit_runtime_dir_without_tmpdir_names_itself() {
        let t = tempfile::tempdir().unwrap();
        let long = t.path().join("y".repeat(120));
        let env = long_env(ENV_RUNTIME_DIR, None, long.to_string_lossy().into_owned());
        let msg = RuntimeDir::resolve_with(&env).unwrap_err().to_string();
        assert!(msg.contains("Your KRAKEN_RUNTIME_DIR ("), "{msg}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn long_xdg_falls_back_to_private_tmp_dir_with_notice() {
        let t = tempfile::tempdir().unwrap();
        let long = t.path().join("z".repeat(120));
        let env = long_env("XDG_RUNTIME_DIR", None, long.to_string_lossy().into_owned());
        match RuntimeDir::resolve_with(&env) {
            Ok(d) => {
                let uid = rustix::process::getuid().as_raw();
                assert_eq!(d.path(), Path::new(&format!("/tmp/kraken-{uid}")));
                let n = d.notice().unwrap();
                assert!(n.contains("XDG_RUNTIME_DIR") && n.contains(&format!("/tmp/kraken-{uid}")));
                let mode = std::fs::metadata(d.path()).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o700);
            }
            // Someone else owns the fixed name: failing closed is the contract.
            Err(IpcError::InsecureDir { .. } | IpcError::SocketPathTooLong { .. }) => {}
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn pipe_name_sanitised() {
        assert_eq!(pipe_name_for("a b\\c"), r"\\.\pipe\kraken-a_b_c");
    }
}

//! Path policy for what an agent may point KRAKEN at.
//!
//! An agent (or the MCP surface) that asks for `project_create` or `project_open` names files the
//! engine then reads and the model sees through `read_bytes`. Approval by a person is the main
//! gate; this module is the part that does not depend on the person reading the prompt closely:
//! it refuses secrets-by-location outright (dot-directories under the home directory such as
//! `~/.ssh`, `~/.config` and `~/.gnupg`, and the kernel's `/proc`, `/sys` and `/dev`) and anything
//! that is not an ordinary file.

use std::path::{Component, Path, PathBuf};

use kraken_proto::{ErrorCode, ProtoError};

fn refuse(what: &str, path: &Path, why: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!(
            "{what} {} is refused for agents: {why}; a person can do this from the GUI or the CLI",
            kraken_proto::sanitize_capped(&path.display().to_string(), 512)
        ),
    )
}

/// The current user's home directory from the environment.
pub fn home_dir() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// `path` made absolute, with every symlink of its existing part resolved, so a link cannot hide
/// a forbidden location. A missing tail is appended unresolved; `..` is refused.
fn resolve(path: &Path) -> std::io::Result<PathBuf> {
    let abs = std::path::absolute(path)?;
    if abs.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "`..` in the path",
        ));
    }
    let mut existing = abs.as_path();
    let mut tail = Vec::new();
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut resolved) => {
                resolved.extend(tail.iter().rev());
                return Ok(resolved);
            }
            Err(_) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    tail.push(name.to_owned());
                    existing = parent;
                }
                _ => return Ok(abs),
            },
        }
    }
}

/// Checks `path` against the policy with an explicit `home` (tests inject one).
///
/// `what` names the argument in the message. Returns the resolved path.
pub fn check_agent_path_in(
    what: &str,
    path: &Path,
    home: Option<&Path>,
) -> Result<PathBuf, ProtoError> {
    let resolved = resolve(path).map_err(|e| refuse(what, path, &e.to_string()))?;
    if cfg!(unix) {
        for sys in ["/proc", "/sys", "/dev"] {
            if resolved.starts_with(sys) {
                return Err(refuse(what, path, "it is a kernel or device file system"));
            }
        }
    }
    if let Some(home) = home {
        let home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
        if let Ok(rest) = resolved.strip_prefix(&home)
            && rest
                .components()
                .any(|c| matches!(c, Component::Normal(n) if n.to_string_lossy().starts_with('.')))
        {
            return Err(refuse(
                what,
                path,
                "it is inside a hidden directory of the home directory (credentials and \
                 configuration live there)",
            ));
        }
    }
    Ok(resolved)
}

/// [`check_agent_path_in`] with the home directory of the current user.
pub fn check_agent_path(what: &str, path: &Path) -> Result<PathBuf, ProtoError> {
    check_agent_path_in(what, path, home_dir().as_deref())
}

/// Requires `path` to be an ordinary file (not a FIFO, device or directory); symlinks are
/// followed first.
pub fn ensure_regular_file(path: &Path) -> Result<(), ProtoError> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("{} is not an ordinary file", path.display()),
        )),
        Err(e) => Err(ProtoError::new(
            if e.kind() == std::io::ErrorKind::NotFound {
                ErrorCode::NotFound
            } else {
                ErrorCode::Internal
            },
            format!("cannot open binary {}: {e}", path.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_directories_under_home_are_refused() {
        let t = tempfile::tempdir().expect("tempdir");
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).expect("mkdir");
        std::fs::create_dir_all(home.join("work/.cache")).expect("mkdir");
        std::fs::write(home.join(".ssh/id_ed25519"), b"key").expect("write");
        std::fs::write(home.join("work/prog.bin"), b"elf").expect("write");

        assert!(check_agent_path_in("binary", &home.join("work/prog.bin"), Some(&home)).is_ok());
        for bad in [
            home.join(".ssh/id_ed25519"),
            home.join(".config/kraken/secrets.toml"),
            home.join("work/.cache/x"),
        ] {
            let e = check_agent_path_in("binary", &bad, Some(&home)).unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidArgument, "{bad:?}");
            assert!(e.message.contains("hidden directory"), "{}", e.message);
        }
        // Outside the home directory, dots are fine (temporary directories are often hidden).
        assert!(check_agent_path_in("binary", Path::new("/tmp/.x/prog"), Some(&home)).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_dotdot_cannot_hide_a_forbidden_path() {
        let t = tempfile::tempdir().expect("tempdir");
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join(".gnupg")).expect("mkdir");
        std::fs::write(home.join(".gnupg/key"), b"k").expect("write");
        let link = t.path().join("innocent");
        std::os::unix::fs::symlink(home.join(".gnupg/key"), &link).expect("symlink");
        assert!(check_agent_path_in("binary", &link, Some(&home)).is_err());
        let dotdot = home.join("a/../.gnupg/key");
        assert!(check_agent_path_in("binary", &dotdot, Some(&home)).is_err());
        for p in ["/proc/self/environ", "/dev/zero", "/sys/kernel/notes"] {
            assert!(
                check_agent_path_in("binary", Path::new(p), None).is_err(),
                "{p}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn only_ordinary_files_pass() {
        let t = tempfile::tempdir().expect("tempdir");
        let f = t.path().join("f");
        std::fs::write(&f, b"x").expect("write");
        assert!(ensure_regular_file(&f).is_ok());
        assert!(ensure_regular_file(t.path()).is_err());
        assert!(ensure_regular_file(Path::new("/dev/zero")).is_err());
        assert_eq!(
            ensure_regular_file(&t.path().join("missing"))
                .unwrap_err()
                .code,
            ErrorCode::NotFound
        );
    }
}

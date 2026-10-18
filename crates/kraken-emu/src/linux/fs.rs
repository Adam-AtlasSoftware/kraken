//! The guest's view of the file system. Exactly two host trees are reachable:
//!
//! * `/work`, the guest's working directory: the private run directory, read-write. Relative
//!   paths resolve here. The program itself appears read-only as `/work/prog` (served from the
//!   host file, never copied, and not counted as a file the run wrote).
//! * every other absolute path: inside the optional sysroot, read-only, with symbolic links
//!   resolved as if the sysroot were `/` (an absolute link target is re-rooted, `..` stops at the
//!   sysroot), so no link can lead outside it.
//!
//! Plus `/dev/null`, `/dev/zero` and `/dev/urandom` (deterministic bytes). Nothing else on the
//! host is visible; `..` never climbs out of `/work` or the sysroot.

use std::path::{Path, PathBuf};

/// The guest working directory.
pub const GUEST_CWD: &str = "/work";
/// The name the program has in the working directory.
pub const PROG_NAME: &str = "prog";

/// What a guest path refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// A path in the private working directory (it may not exist yet).
    Work(PathBuf),
    /// An existing file or directory of the sysroot (read-only).
    Sys(PathBuf),
    /// The program file (read-only).
    Prog,
    /// `/dev/null`.
    Null,
    /// `/dev/zero`.
    Zero,
    /// `/dev/urandom` or `/dev/random`.
    Random,
    /// Nothing there.
    Missing,
    /// The working directory itself or another directory the guest may list but not open.
    Dir(PathBuf),
}

/// Path resolution for one run.
#[derive(Debug, Clone)]
pub struct Vfs {
    workdir: PathBuf,
    sysroot: Option<PathBuf>,
    program: PathBuf,
}

/// Lexically normalised components of an absolute guest path (`.` dropped, `..` popped, never
/// above `/`).
pub fn normalize(path: &[u8], cwd: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let full: Vec<u8> = if path.first() == Some(&b'/') {
        path.to_vec()
    } else {
        let mut v = cwd.as_bytes().to_vec();
        v.push(b'/');
        v.extend_from_slice(path);
        v
    };
    for c in full.split(|b| *b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            other => parts.push(String::from_utf8_lossy(other).into_owned()),
        }
    }
    parts
}

impl Vfs {
    /// A view with `workdir` as `/work`, `program` as `/work/prog` and an optional sysroot.
    pub fn new(workdir: PathBuf, sysroot: Option<PathBuf>, program: PathBuf) -> Self {
        Vfs {
            workdir,
            sysroot,
            program,
        }
    }

    /// The private directory.
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// The host program file.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The sysroot, if any.
    pub fn sysroot(&self) -> Option<&Path> {
        self.sysroot.as_deref()
    }

    /// Resolves a guest path.
    pub fn resolve(&self, path: &[u8]) -> Node {
        if path.is_empty() {
            return Node::Missing;
        }
        let parts = normalize(path, GUEST_CWD);
        let strs: Vec<&str> = parts.iter().map(String::as_str).collect();
        match strs.as_slice() {
            ["work"] => Node::Dir(self.workdir.clone()),
            ["work", name] if *name == PROG_NAME => Node::Prog,
            ["work", rest @ ..] => {
                let mut p = self.workdir.clone();
                for r in rest {
                    p.push(r);
                }
                Node::Work(p)
            }
            ["dev", "null"] => Node::Null,
            ["dev", "zero"] => Node::Zero,
            ["dev", "urandom"] | ["dev", "random"] => Node::Random,
            _ => match &self.sysroot {
                Some(root) => match resolve_in_root(root, &parts) {
                    Some(p) if p.is_dir() => Node::Dir(p),
                    Some(p) => Node::Sys(p),
                    None => Node::Missing,
                },
                None => Node::Missing,
            },
        }
    }
}

/// Resolves `parts` under `root` as if `root` were `/`: symbolic links are followed with their
/// absolute targets re-rooted and `..` clamped at the root. `None` when the path does not exist
/// or links loop.
pub fn resolve_in_root(root: &Path, parts: &[String]) -> Option<PathBuf> {
    let mut todo: Vec<String> = parts.iter().rev().cloned().collect();
    let mut cur: Vec<String> = Vec::new();
    let mut hops = 0;
    while let Some(c) = todo.pop() {
        match c.as_str() {
            "" | "." => continue,
            ".." => {
                cur.pop();
                continue;
            }
            _ => {}
        }
        let mut host = root.to_path_buf();
        for p in &cur {
            host.push(p);
        }
        host.push(&c);
        let meta = std::fs::symlink_metadata(&host).ok()?;
        if meta.file_type().is_symlink() {
            hops += 1;
            if hops > 40 {
                return None;
            }
            let target = std::fs::read_link(&host).ok()?;
            let t = target.to_string_lossy().into_owned();
            if t.starts_with('/') {
                cur.clear();
            }
            for piece in t.split('/').rev() {
                todo.push(piece.to_string());
            }
        } else {
            cur.push(c);
        }
    }
    let mut host = root.to_path_buf();
    for p in &cur {
        host.push(p);
    }
    host.exists().then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_dot_never_climbs_out() {
        assert_eq!(
            normalize(b"../../etc/passwd", "/work"),
            vec!["etc", "passwd"]
        );
        assert_eq!(normalize(b"/work/../../x", "/work"), vec!["x"]);
        assert_eq!(normalize(b"a/./b/../c", "/work"), vec!["work", "a", "c"]);
    }

    #[test]
    fn without_a_sysroot_only_work_and_devices_exist() {
        let dir = tempfile::tempdir().expect("tmp");
        let v = Vfs::new(dir.path().into(), None, "/nonexistent/prog".into());
        assert_eq!(v.resolve(b"/etc/passwd"), Node::Missing);
        assert_eq!(v.resolve(b"../../../etc/passwd"), Node::Missing);
        assert_eq!(
            v.resolve(b"out.txt"),
            Node::Work(dir.path().join("out.txt"))
        );
        assert_eq!(v.resolve(b"/work/prog"), Node::Prog);
        assert_eq!(v.resolve(b"prog"), Node::Prog);
        assert_eq!(v.resolve(b"/dev/null"), Node::Null);
    }

    #[cfg(unix)]
    #[test]
    fn sysroot_links_stay_inside_the_sysroot() {
        let root = tempfile::tempdir().expect("tmp");
        let r = root.path();
        std::fs::create_dir_all(r.join("usr/lib")).expect("mkdir");
        std::fs::write(r.join("usr/lib/libc.so.6"), b"x").expect("write");
        std::os::unix::fs::symlink("usr/lib", r.join("lib")).expect("link");
        std::os::unix::fs::symlink("/usr/lib/libc.so.6", r.join("usr/lib/abs")).expect("link");
        std::os::unix::fs::symlink("../../../../../etc/passwd", r.join("usr/lib/esc"))
            .expect("link");
        std::os::unix::fs::symlink("loop", r.join("loop")).expect("link");
        let v = Vfs::new(
            "/nonexistent".into(),
            Some(r.into()),
            "/nonexistent/p".into(),
        );
        assert_eq!(
            v.resolve(b"/lib/libc.so.6"),
            Node::Sys(r.join("usr/lib/libc.so.6"))
        );
        assert_eq!(
            v.resolve(b"/usr/lib/abs"),
            Node::Sys(r.join("usr/lib/libc.so.6"))
        );
        // Climbing out through a link lands on the sysroot's own /etc/passwd, which is absent.
        assert_eq!(v.resolve(b"/usr/lib/esc"), Node::Missing);
        assert_eq!(v.resolve(b"/loop"), Node::Missing);
    }
}

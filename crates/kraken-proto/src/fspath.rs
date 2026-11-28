//! Canonical paths that read like the ones people type.
//!
//! On Windows `std::fs::canonicalize` returns the verbatim form (`\\?\C:\Users\...`). It names
//! the right file, but it ends up in messages, results and stored paths, where it differs from
//! the same path written the usual way. [`canonicalize`] drops the prefix whenever the plain form
//! names the same file; elsewhere it is `std::fs::canonicalize`.

use std::io;
use std::path::{Path, PathBuf};

/// `std::fs::canonicalize`, without the verbatim prefix where it is not needed.
pub fn canonicalize(path: impl AsRef<Path>) -> io::Result<PathBuf> {
    std::fs::canonicalize(path).map(without_verbatim)
}

/// `path` without the `\\?\` prefix when the plain form names the same file: `\\?\C:\x` is
/// `C:\x` and `\\?\UNC\server\share\x` is `\\server\share\x`. Other verbatim paths (a volume
/// GUID) and every other path are returned unchanged.
pub fn without_verbatim(path: PathBuf) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest)
            if rest.len() >= 3
                && rest.as_bytes()[0].is_ascii_alphabetic()
                && rest.as_bytes()[1..3] == *br":\" =>
        {
            PathBuf::from(rest)
        }
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbatim_prefixes_are_dropped_only_when_the_plain_path_is_the_same() {
        let p = |s: &str| without_verbatim(PathBuf::from(s));
        assert_eq!(
            p(r"\\?\C:\Users\a b\KRAKEN"),
            PathBuf::from(r"C:\Users\a b\KRAKEN")
        );
        assert_eq!(p(r"\\?\UNC\srv\share\k"), PathBuf::from(r"\\srv\share\k"));
        assert_eq!(p(r"\\?\Volume{x}\k"), PathBuf::from(r"\\?\Volume{x}\k"));
        assert_eq!(p(r"\\?\é:\k"), PathBuf::from(r"\\?\é:\k"));
        assert_eq!(p("/usr/bin/kraken"), PathBuf::from("/usr/bin/kraken"));
    }

    #[test]
    fn a_canonical_path_names_the_same_file() {
        let here = std::env::current_dir().expect("cwd");
        let c = canonicalize(&here).expect("canonical");
        assert!(c.is_absolute());
        assert!(!c.to_string_lossy().starts_with(r"\\?\"));
        assert_eq!(
            std::fs::canonicalize(&c).expect("again"),
            std::fs::canonicalize(&here).expect("std")
        );
    }
}

//! License and notice files of the C/C++ code `engine-native-sys` compiles into the shipped
//! binaries: Ghidra's decompiler and Sleigh (Apache-2.0, with Ghidra's `NOTICE`) and the zlib
//! subset Ghidra bundles (zlib License).
//!
//! The texts are committed under `crates/engine-native-sys/licenses` so `cargo xtask notices`
//! and its staleness test work without the source cache. When the pinned source archive is in
//! the cache (`cargo xtask native-src`), `cargo xtask notices` refreshes the committed copies from
//! it, and a test checks that they still match the archive (skipped without it).

use std::fs;
use std::path::{Path, PathBuf};

use crate::native_src::{PREFIX, SHA256, TAG, URL, archive_path, extract, sha256_file};
use crate::{Result, workspace_root};

/// The committed copies, relative to the workspace root (also what the release archive ships
/// as `licenses/`).
pub const DIR: &str = "crates/engine-native-sys/licenses";

const DECOMPILE: &str = "Ghidra/Features/Decompiler/src/decompile";

/// (archive member below the top-level directory, committed path below [`DIR`]).
const MEMBERS: &[(&str, &str)] = &[
    ("LICENSE", "ghidra/LICENSE"),
    ("NOTICE", "ghidra/NOTICE"),
    ("licenses/zlib_License.txt", "zlib/LICENSE"),
    (
        "Ghidra/Features/Decompiler/src/decompile/zlib/README.txt",
        "zlib/README.txt",
    ),
];

/// File below [`DIR`] that records where the texts come from.
pub const PROVENANCE: &str = "PROVENANCE.txt";

/// The Ghidra version of [`TAG`] (`12.2` for `Ghidra_12.2_build`).
pub fn ghidra_version() -> &'static str {
    TAG.trim_start_matches("Ghidra_").trim_end_matches("_build")
}

/// `ZLIB_VERSION` from a `zlib.h`.
pub fn zlib_version(zlib_h: &str) -> Option<String> {
    zlib_h.lines().find_map(|l| {
        let rest = l.trim().strip_prefix("#define ZLIB_VERSION ")?;
        Some(rest.trim().trim_matches('"').to_string())
    })
}

/// The zlib version the committed provenance records.
pub fn recorded_zlib_version(provenance: &str) -> Option<String> {
    provenance.lines().find_map(|l| {
        l.strip_prefix("zlib ")
            .and_then(|r| r.split_whitespace().next())
            .map(|v| v.trim_end_matches(',').to_string())
    })
}

fn provenance(zlib: &str) -> String {
    format!(
        "Compiled into KRAKEN by engine-native-sys (the native engine's decompiler library).\n\
         \n\
         Ghidra {ver} decompiler and Sleigh (C++), Apache License 2.0\n\
         \x20 source: {URL}\n\
         \x20 sha256: {SHA256}\n\
         \x20 members: {DECOMPILE}/cpp\n\
         \x20   (the Makefile's CORE, DECCORE and SLEIGH sets, sleigh_arch, inject_sleigh)\n\
         \x20 license: ghidra/LICENSE; notice: ghidra/NOTICE\n\
         \n\
         zlib {zlib}, zlib License\n\
         \x20 the subset bundled with Ghidra in {DECOMPILE}/zlib,\n\
         \x20 unmodified apart from a header comment per file\n\
         \x20 license: zlib/LICENSE; Ghidra's note on the subset: zlib/README.txt\n",
        ver = ghidra_version(),
    )
}

/// The files [`DIR`] should hold, read from the pinned archive at `archive`.
pub fn from_archive(archive: &Path) -> Result<Vec<(String, String)>> {
    let tmp = std::env::temp_dir().join(format!("kraken-native-licenses-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
    let result = (|| {
        let mut out = Vec::new();
        let mut wanted: Vec<&str> = MEMBERS.iter().map(|(m, _)| *m).collect();
        let zlib_h = format!("{DECOMPILE}/zlib/zlib.h");
        wanted.push(&zlib_h);
        for m in &wanted {
            extract(archive, &tmp, &format!("{PREFIX}/{m}"), 1)?;
        }
        let read =
            |m: &str| fs::read_to_string(tmp.join(m)).map_err(|e| format!("cannot read {m}: {e}"));
        for (member, dest) in MEMBERS {
            out.push((dest.to_string(), read(member)?));
        }
        let zlib = zlib_version(&read(&zlib_h)?).ok_or("no ZLIB_VERSION in zlib.h")?;
        out.push((PROVENANCE.to_string(), provenance(&zlib)));
        Ok(out)
    })();
    let _ = fs::remove_dir_all(&tmp);
    result
}

/// The pinned archive in the cache, if it is there and intact (never downloads).
pub fn cached_archive() -> Option<PathBuf> {
    let a = archive_path().ok()?;
    (a.is_file() && sha256_file(&a).ok()? == SHA256).then_some(a)
}

/// Rewrites [`DIR`] from the cached archive; `false` (and nothing written) without one.
pub fn sync() -> Result<bool> {
    let Some(archive) = cached_archive() else {
        return Ok(false);
    };
    let dir = workspace_root().join(DIR);
    for (name, text) in from_archive(&archive)? {
        let path = dir.join(&name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    Ok(true)
}

/// A committed file below [`DIR`].
pub fn committed(name: &str) -> std::result::Result<String, String> {
    let path = workspace_root().join(DIR).join(name);
    fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_read() {
        assert_eq!(ghidra_version(), "12.2");
        assert_eq!(
            zlib_version("x\n#define ZLIB_VERSION \"1.3.1\"\n").as_deref(),
            Some("1.3.1")
        );
        assert_eq!(
            recorded_zlib_version(&provenance("1.3.1")).as_deref(),
            Some("1.3.1")
        );
    }

    #[test]
    fn committed_copies_are_complete() {
        for (_, dest) in MEMBERS {
            let text = committed(dest).expect("committed license file");
            assert!(!text.trim().is_empty(), "{dest} is empty");
        }
        let prov = committed(PROVENANCE).expect("provenance");
        assert!(prov.contains(SHA256) && prov.contains(ghidra_version()));
        assert!(
            committed("ghidra/LICENSE")
                .expect("license")
                .contains("Apache License")
        );
        assert!(
            committed("zlib/LICENSE")
                .expect("zlib")
                .contains("Jean-loup Gailly")
        );
    }

    /// Skipped unless `cargo xtask native-src` has put the pinned archive in the cache.
    #[test]
    fn committed_copies_match_the_pinned_archive() {
        let Some(archive) = cached_archive() else {
            eprintln!("skipping: the pinned Ghidra source archive is not in the cache");
            return;
        };
        for (name, text) in from_archive(&archive).expect("read archive") {
            let have = committed(&name).unwrap_or_default();
            assert!(
                have == text,
                "{DIR}/{name} is stale: run `cargo xtask notices` and commit the result"
            );
        }
    }
}

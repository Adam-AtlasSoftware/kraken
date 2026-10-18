//! The jump tables of a discovery on disk, so that opening the same binary again does not run
//! the decompiler's switch analysis a second time (see [`JumpCache`]).
//!
//! The file lives in the state directory next to `native-state.json`. It is keyed by the SHA-256
//! of the binary, whether symbols were used and the library version; a file for anything else
//! is ignored and replaced. Both reading and writing are best effort: a missing, unreadable or
//! stale file only costs the time the analysis would have taken.

use std::collections::BTreeMap;
use std::path::Path;

use engine_native_sys::JumpEdge;
use serde::{Deserialize, Serialize};

use crate::discover::JumpCache;
use crate::engine::SOURCE_TAG;

/// File name inside the state directory.
pub const CACHE_FILE: &str = "discovery-cache.json";

/// Bumped whenever a change to discovery alters which jump tables it asks for, or in which order.
const FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
struct File {
    format: u32,
    source: String,
    sha256: String,
    use_symbols: bool,
    runs: BTreeMap<u64, Vec<Vec<[u64; 2]>>>,
}

/// The cache saved for `sha256` and `use_symbols` in `dir`, empty when there is none.
pub fn load(dir: &Path, sha256: &str, use_symbols: bool) -> JumpCache {
    let Ok(text) = std::fs::read_to_string(dir.join(CACHE_FILE)) else {
        return JumpCache::default();
    };
    let Ok(f) = serde_json::from_str::<File>(&text) else {
        return JumpCache::default();
    };
    if f.format != FORMAT
        || f.source != SOURCE_TAG
        || f.sha256 != sha256
        || f.use_symbols != use_symbols
    {
        return JumpCache::default();
    }
    JumpCache {
        runs: f
            .runs
            .into_iter()
            .map(|(entry, runs)| {
                let runs = runs
                    .into_iter()
                    .map(|r| {
                        r.into_iter()
                            .map(|[op, target]| JumpEdge { op, target })
                            .collect()
                    })
                    .collect();
                (entry, runs)
            })
            .collect(),
    }
}

/// Writes `cache` to `dir` (created if needed); errors are ignored.
pub fn save(dir: &Path, sha256: &str, use_symbols: bool, cache: &JumpCache) {
    let file = File {
        format: FORMAT,
        source: SOURCE_TAG.to_string(),
        sha256: sha256.to_string(),
        use_symbols,
        runs: cache
            .runs
            .iter()
            .map(|(entry, runs)| {
                let runs = runs
                    .iter()
                    .map(|r| r.iter().map(|e| [e.op, e.target]).collect())
                    .collect();
                (*entry, runs)
            })
            .collect(),
    };
    let Ok(text) = serde_json::to_string(&file) else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let tmp = dir.join(format!("{CACHE_FILE}.tmp"));
    if std::fs::write(&tmp, text).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(CACHE_FILE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_cache_comes_back_only_for_the_same_binary() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut c = JumpCache::default();
        c.runs.insert(
            0x1000,
            vec![
                vec![JumpEdge {
                    op: 0x1010,
                    target: 0x1020,
                }],
                vec![],
            ],
        );
        save(dir.path(), "abc", true, &c);
        assert_eq!(load(dir.path(), "abc", true), c);
        assert!(load(dir.path(), "abd", true).is_empty());
        assert!(load(dir.path(), "abc", false).is_empty());
        assert!(load(&dir.path().join("none"), "abc", true).is_empty());
    }
}

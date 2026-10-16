//! Shared helpers for the integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use kraken_rewrite::oracle::{FunctionOracle, OracleConfig};

pub fn corpus_bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/bin")
        .join(name)
}

/// A Ghidra install for the SLEIGH specs: the environment, else the dev cache.
pub fn ghidra_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("KRAKEN_GHIDRA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    let home = std::env::var_os("HOME")?;
    let dir = Path::new(&home).join(".cache/kraken-dev/ghidra");
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.join("Ghidra/Processors/x86/data/languages/x86.ldefs")
                .is_file()
        })
}

pub fn config() -> OracleConfig {
    OracleConfig {
        ghidra_home: ghidra_home(),
        ..OracleConfig::default()
    }
}

pub fn oracle(path: &Path) -> FunctionOracle {
    FunctionOracle::load(path, &config()).expect("oracle (needs a Ghidra install for SLEIGH specs)")
}

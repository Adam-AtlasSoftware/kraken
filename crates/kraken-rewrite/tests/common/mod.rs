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

/// Whether the SLEIGH spec files the oracle compiles its CPU from can be found (a Ghidra
/// install, `KRAKEN_NATIVE_SPECS`, or the tree `cargo xtask native-sla` builds). Without them a
/// test that needs the oracle is skipped, unless `KRAKEN_REQUIRE_SPECS=1` is set (CI sets it), which
/// makes missing specs a failure so a job cannot pass by skipping.
pub fn need_specs() -> bool {
    if kraken_rewrite::oracle::find_processors(&config()).is_ok() {
        return true;
    }
    assert!(
        !std::env::var("KRAKEN_REQUIRE_SPECS").is_ok_and(|v| !v.is_empty() && v != "0"),
        "KRAKEN_REQUIRE_SPECS is set but no SLEIGH spec files were found \
         (KRAKEN_NATIVE_SPECS, KRAKEN_GHIDRA_HOME or `cargo xtask native-sla`)"
    );
    eprintln!(
        "skipped: no SLEIGH spec files (set KRAKEN_NATIVE_SPECS or run `cargo xtask native-sla`)"
    );
    false
}

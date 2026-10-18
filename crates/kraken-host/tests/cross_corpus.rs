//! The cross-architecture corpus sets (`corpus/{arm32,aarch64,riscv64,riscv32}`): every binary is
//! there, matches its set's `MANIFEST.sha256`, has ground truth, and `binary_probe` sees an ELF
//! executable of the right processor and width. Whether an engine opens it is not checked (the
//! native engine is x86 only for now); the test prints what the probe says.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kraken_host::KrakenConfig;
use kraken_registry::commands::BinaryFormat;
use sha2::{Digest, Sha256};

struct Set {
    name: &'static str,
    arch: &'static str,
    bits: u8,
    binaries: usize,
}

const SETS: &[Set] = &[
    Set {
        name: "arm32",
        arch: "ARM",
        bits: 32,
        binaries: 20,
    },
    Set {
        name: "aarch64",
        arch: "AArch64",
        bits: 64,
        binaries: 16,
    },
    Set {
        name: "riscv64",
        arch: "RISC-V 64",
        bits: 64,
        binaries: 16,
    },
    Set {
        name: "riscv32",
        arch: "RISC-V 32",
        bits: 32,
        binaries: 16,
    },
];

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `bin/<file>` -> hash, from a set's manifest.
fn manifest(set: &Path) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(set.join("MANIFEST.sha256")).expect("manifest");
    text.lines()
        .filter_map(|l| l.split_once("  "))
        .filter(|(_, f)| f.starts_with("bin/"))
        .map(|(h, f)| (f.to_string(), h.to_string()))
        .collect()
}

#[test]
fn cross_sets_match_their_manifests_and_probe_as_their_architecture() {
    // The probe asks the engine factory about this machine; keep it off the user's config.
    let cfg = KrakenConfig::default();
    for set in SETS {
        let dir = corpus().join(set.name);
        let listed = manifest(&dir);
        let mut files: Vec<String> = std::fs::read_dir(dir.join("bin"))
            .expect("bin dir")
            .map(|e| format!("bin/{}", e.expect("entry").file_name().to_string_lossy()))
            .collect();
        files.sort();
        assert_eq!(files.len(), set.binaries, "{}: binary count", set.name);
        assert_eq!(
            files,
            listed.keys().cloned().collect::<Vec<_>>(),
            "{}: bin/ and MANIFEST.sha256 list different files",
            set.name
        );
        let mut said = BTreeMap::new();
        for file in &files {
            let path = dir.join(file);
            let data = std::fs::read(&path).expect("binary");
            assert_eq!(hex(&data), listed[file], "{}/{file}: hash", set.name);
            let name = file.trim_start_matches("bin/");
            assert!(
                dir.join(format!("truth/{name}.json")).is_file(),
                "{}/{file}: no truth",
                set.name
            );
            let program = name.split('-').next().expect("program");
            assert!(
                corpus().join(format!("expected/{program}.json")).is_file(),
                "{program}: no expected outputs"
            );

            let p = kraken_host::native::probe_binary(&cfg, &path).expect("probe");
            assert_eq!(p.format, BinaryFormat::Elf, "{}/{file}", set.name);
            assert_eq!(p.kind, "executable", "{}/{file}", set.name);
            assert_eq!(p.arch.as_deref(), Some(set.arch), "{}/{file}", set.name);
            assert_eq!(p.bits, Some(set.bits), "{}/{file}", set.name);
            assert_eq!(p.endian.as_deref(), Some("little"), "{}/{file}", set.name);
            assert_eq!(p.sha256, listed[file], "{}/{file}", set.name);
            assert_eq!(
                p.stripped,
                Some(name.ends_with("-stripped")),
                "{}/{file}",
                set.name
            );
            let verdict = format!(
                "supported={} engine={:?} problem={:?} reason={:?}",
                p.supported, p.recommended_engine, p.problem, p.recommended_reason
            );
            said.entry(verdict)
                .or_insert_with(Vec::new)
                .push(name.to_string());
        }
        for (verdict, names) in said {
            println!("{} ({} binaries): {verdict}", set.name, names.len());
        }
    }
}

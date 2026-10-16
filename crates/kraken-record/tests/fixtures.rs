//! Tests over the committed corpus fixtures (`corpus/fixtures/*.json`).

use std::path::{Path, PathBuf};

use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::testing::run_contract_suite;
use kraken_proto::{Hex64, Locator};
use kraken_record::{DEFAULT_FUNCTION_CAP, render_fixture};
use serde::Deserialize;

fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

fn names() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(corpus().join("bin"))
        .expect("corpus/bin")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn fixture_path(name: &str) -> PathBuf {
    corpus().join("fixtures").join(format!("{name}.json"))
}

fn load(name: &str) -> FixtureFile {
    FixtureFile::from_path(&fixture_path(name))
        .unwrap_or_else(|e| panic!("fixture for {name}: {e}"))
}

#[test]
fn a_fixture_exists_for_every_corpus_binary() {
    let names = names();
    assert_eq!(names.len(), 20);
    for n in &names {
        assert!(fixture_path(n).is_file(), "missing fixture for {n}");
    }
}

#[test]
fn fixtures_are_well_formed_and_canonically_formatted() {
    for name in names() {
        let path = fixture_path(&name);
        let text = std::fs::read_to_string(&path).expect("read fixture");
        let fx = load(&name);
        assert_eq!(
            render_fixture(&fx).expect("render"),
            text,
            "{name}: not in the recorder's canonical format"
        );
        assert!(fx.ghidra_version.starts_with("12."), "{name}");
        assert!(!fx.functions.is_empty(), "{name}");
        let rec = fx.recording.as_ref().expect("recording header");
        assert_eq!(rec.function_cap, DEFAULT_FUNCTION_CAP, "{name}");
        assert_eq!(rec.functions_recorded, fx.functions.len(), "{name}");
        assert!(rec.functions_recorded <= rec.function_cap, "{name}");
        assert!(rec.functions_listed >= rec.functions_recorded, "{name}");
        assert_eq!(rec.types_recorded, fx.types.len(), "{name}");
        let mut last = 0u64;
        for f in &fx.functions {
            let Locator::Native { offset, .. } = &f.summary.locator else {
                panic!("{name}: non-native locator");
            };
            assert!(
                offset.0 > last,
                "{name}: functions must be sorted and unique"
            );
            last = offset.0;
            assert_eq!(f.summary.locator, f.decompile.function, "{name}");
            f.decompile
                .validate_tokens()
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fake_engine_passes_the_contract_suite_on_every_fixture() {
    for name in names() {
        let fx = load(&name);
        let exp = fx.expectations(corpus().join("bin").join(&name));
        let engine = FakeEngine::new(fx);
        run_contract_suite(&engine, &exp)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[derive(Deserialize)]
struct Truth {
    functions: Vec<TruthFunction>,
}

#[derive(Deserialize)]
struct TruthFunction {
    name: String,
    entry: Hex64,
}

/// Compares each unstripped binary's fixture with its DWARF ground truth and prints the recall.
/// Only -O0 non-C++ programs must reach 0.9; the rest are reported.
#[test]
fn ground_truth_recall() {
    println!(
        "{:<24} {:>5} {:>8} {:>8}",
        "binary", "truth", "at entry", "by name"
    );
    for name in names() {
        if name.ends_with("-stripped") {
            continue;
        }
        let truth: Truth = serde_json::from_slice(
            &std::fs::read(corpus().join("truth").join(format!("{name}.json"))).expect("truth"),
        )
        .expect("truth json");
        let fx = load(&name);
        let base = fx.program.base.0;
        let (mut at_entry, mut by_name) = (0usize, 0usize);
        for t in &truth.functions {
            // PIE truth is link-time (base 0); static truth is already absolute
            let at = if t.entry.0 < base {
                base + t.entry.0
            } else {
                t.entry.0
            };
            let hit = fx.functions.iter().find(
                |f| matches!(&f.summary.locator, Locator::Native { offset, .. } if offset.0 == at),
            );
            if let Some(f) = hit {
                at_entry += 1;
                if f.summary.name == t.name {
                    by_name += 1;
                }
            }
        }
        let total = truth.functions.len();
        let recall = at_entry as f64 / total as f64;
        println!("{name:<24} {total:>5} {at_entry:>8} {by_name:>8}   recall {recall:.2}");
        let must_pass = name.ends_with("-O0") && !name.starts_with("cpp_");
        if must_pass {
            assert!(
                recall >= 0.9,
                "{name}: recall {recall:.2} ({at_entry}/{total}) below 0.9"
            );
        }
    }
}

//! `patch_lint` and `patch_verify` on a real corpus program: the fixture's rows carry the file's
//! real bytes, so patches line up with `stripped_calc-O0` and the emulator can run the result.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use engine_fake::FixtureFile;
use kraken_proto::{DisasmRow, ErrorCode, FlowKind, Hex64, Locator};
use serde_json::json;

fn row(address: u64, bytes: &str, mnemonic: &str) -> DisasmRow {
    DisasmRow {
        address: Hex64(address),
        bytes: bytes.into(),
        mnemonic: mnemonic.into(),
        operands: Vec::new(),
        comment: None,
        labels: Vec::new(),
        flow: FlowKind::Fallthrough,
    }
}

/// `tiny` with the rows of `stripped_calc-O0` the tests patch: the file's virtual address plus
/// the fixture's load base 0x400000 is the engine address.
fn calc_fixture() -> FixtureFile {
    let mut fx = tiny();
    let at = |f: &engine_fake::FixtureFunction, a: u64| matches!(&f.summary.locator, Locator::Native { offset, .. } if offset.0 == a);
    let main = fx
        .functions
        .iter_mut()
        .find(|f| at(f, 0x401000))
        .expect("function at 0x401000");
    main.disassembly = Some(vec![row(0x40103e, "ffffff25", "data")]);
    let mut eval = fx
        .functions
        .iter()
        .find(|f| at(f, 0x401040))
        .expect("function at 0x401040")
        .clone();
    eval.summary.locator = Locator::ram(0x401440);
    eval.summary.name = "evaluate".into();
    eval.summary.size = Some(0x40);
    eval.disassembly = Some(vec![row(0x401446, "4801d0", "add")]);
    fx.functions.push(eval);
    fx
}

fn corpus_binary(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/bin")
        .join(name)
}

fn runner() -> PathBuf {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("exe");
    let dir = exe.parent().and_then(Path::parent).expect("target dir");
    dir.join("kraken-emu-run")
}

#[tokio::test]
async fn lint_flags_a_patch_across_a_function_end_and_is_quiet_for_a_clean_one() {
    let env = Setup::new(calc_fixture()).start().await;
    std::fs::copy(corpus_binary("stripped_calc-O0"), &env.binary).expect("copy corpus binary");
    let u = user();

    let none = env.ok(&u, "patch_lint", json!({})).await;
    assert_eq!(none["patches_checked"], 0, "{none}");
    assert_eq!(none["findings"], json!([]), "{none}");

    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401446", "bytes": "4829d0"}),
    )
    .await;
    let clean = env.ok(&u, "patch_lint", json!({})).await;
    assert_eq!(clean["patches_checked"], 1, "{clean}");
    assert_eq!(clean["findings"], json!([]), "{clean}");

    // main ends at 0x401040: four bytes from 0x40103e run into helper.
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x40103e", "bytes": "90909090"}),
    )
    .await;
    let out = env.ok(&u, "patch_lint", json!({})).await;
    let findings = out["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1, "{out}");
    assert_eq!(findings[0]["kind"], "function_boundary");
    assert_eq!(findings[0]["severity"], "warning");
    assert_eq!(findings[0]["address"], "0x40103e");
    assert!(
        findings[0]["message"]
            .as_str()
            .expect("message")
            .contains("main"),
        "{out}"
    );

    let e = env.err(&u, "patch_lint", json!({"group": "nope"})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
#[ignore = "needs the SLEIGH tree (KRAKEN_NATIVE_SPECS), the x86_64 emulator sysroot, Landlock and \
            `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn verifying_a_patch_records_a_verdict_that_patch_list_shows() {
    let env = Setup::new(calc_fixture()).start().await;
    std::fs::copy(corpus_binary("stripped_calc-O0"), &env.binary).expect("copy corpus binary");
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let u = user();

    let e = env.err(&u, "patch_verify", json!({})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument, "nothing to verify: {e}");

    // `add rax, rdx` becomes `sub rax, rdx` in the expression evaluator: "1 + 2 * 3" changes.
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401446", "bytes": "4829d0"}),
    )
    .await;
    let before = env.ok(&u, "patch_list", json!({})).await;
    assert!(before["items"][0].get("verdict").is_none(), "{before}");

    let out = env
        .ok(&u, "patch_verify", json!({"timeout_seconds": 120}))
        .await;
    assert_eq!(out["same"], false, "{out}");
    let first = out["first_divergence"]["value"].as_str().expect("first");
    assert!(first.starts_with("stdout: line 1"), "{out}");
    assert!(first.contains("= 7") && first.contains("= 5"), "{out}");
    assert_eq!(out["verdict"]["same"], false);
    let hash = out["verdict"]["set_hash"]
        .as_str()
        .expect("hash")
        .to_string();
    assert_eq!(hash.len(), 16);

    let after = env.ok(&u, "patch_list", json!({})).await;
    let v = &after["items"][0]["verdict"];
    assert_eq!(v["same"], false, "{after}");
    assert_eq!(v["set_hash"], hash.as_str());
    assert_eq!(v["summary"]["value"].as_str(), Some(first), "{after}");

    // A second patch is a different set: the verdict no longer applies until verified again.
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x40103e", "bytes": "ffffff25"}),
    )
    .await;
    let changed = env.ok(&u, "patch_list", json!({})).await;
    assert!(
        changed["items"]
            .as_array()
            .expect("items")
            .iter()
            .all(|p| p.get("verdict").is_none()),
        "{changed}"
    );
    // Taking it away again restores the first set and so its verdict.
    env.ok(&u, "patch_remove", json!({"address": "0x40103e"}))
        .await;
    let restored = env.ok(&u, "patch_list", json!({})).await;
    assert_eq!(restored["items"][0]["verdict"]["set_hash"], hash.as_str());
}

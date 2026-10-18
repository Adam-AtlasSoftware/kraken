//! Callee reuse through the sandboxed build and the export. Needs only a Rust toolchain; where
//! the host cannot confine generated code the build test skips.

use kraken_registry::commands::{ExportCoverage, RewriteMode};
use kraken_rewrite::abi::{Arg, Termination};
use kraken_rewrite::difftest::{DiffReport, Verdict};
use kraken_rewrite::export::{ExportInfo, write_workspace};
use kraken_rewrite::fetch::FunctionContext;
use kraken_rewrite::infer::infer_signature;
use kraken_rewrite::native::{Build, build};
use kraken_rewrite::reuse::{self, Resolved};
use kraken_rewrite::sandbox::{self, Confinement};
use kraken_rewrite::store::RewriteStore;
use kraken_rewrite::unit::{OracleInfo, Provenance, RewriteUnit, UnitSource, sha256_hex};

const SHA: &str = "feedface";

fn function(name: &str, address: u64, decompile: &str) -> FunctionContext {
    FunctionContext {
        name: name.into(),
        address,
        signature: Some("int f(int a)".into()),
        decompile: decompile.into(),
        decompile_hash: sha256_hex(decompile),
        program_sha256: SHA.into(),
        image_base: 0,
    }
}

fn code(name: &str, body: &str) -> String {
    format!("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn {name}(a: i32) -> i32 {{ {body} }}")
}

fn unit_of(
    f: &FunctionContext,
    rust: String,
    callees: Vec<kraken_rewrite::unit::CalleeRef>,
) -> RewriteUnit {
    RewriteUnit::from_run(
        UnitSource {
            mode: RewriteMode::Incremental,
            spec_id: None,
            anchor: f.anchor(),
            source_decompile_hash: f.decompile_hash.clone(),
            callees,
            signature: infer_signature("int f(int a)", &f.name).expect("signature"),
            provenance: Provenance {
                author: "model".into(),
                provider: None,
                model: None,
                task: "t".into(),
                prompt_hash: "p".into(),
            },
            oracle: OracleInfo {
                kind: "test".into(),
                emulator: "test".into(),
                binary: "t".into(),
                elf_vaddr: f.address,
            },
        },
        rust,
        DiffReport {
            verdict: Verdict::Pass,
            seed: 1,
            cases_run: 10,
            passed: 10,
            skipped: 0,
            counterexamples: Vec::new(),
            cases: Vec::new(),
            sandbox: "test".into(),
        },
    )
}

/// Accepts `inner`, translates `top` against it and accepts that too.
fn inner_and_top(store: &RewriteStore) -> (RewriteUnit, RewriteUnit, Resolved) {
    let inner = function("inner", 0x401100, "int inner(int a) { return a + 1; }");
    let top = function("top", 0x401300, "int top(int a) { return inner(a) * 2; }");
    let inner_unit = store
        .put_unit(unit_of(&inner, code("inner", "a.wrapping_add(1)"), vec![]))
        .expect("put");
    store.accept(&inner_unit.id, "tester").expect("accept");
    let resolved =
        reuse::resolve(store, SHA, top.address, std::slice::from_ref(&inner)).expect("resolve");
    assert_eq!(resolved.direct.len(), 1);
    let top_unit = store
        .put_unit(unit_of(
            &top,
            code("top", "unsafe { inner(a) }.wrapping_mul(2)"),
            resolved.direct.iter().map(|r| r.callee_ref()).collect(),
        ))
        .expect("put");
    store.accept(&top_unit.id, "tester").expect("accept");
    (
        store.get(&inner_unit.id).expect("get").expect("inner"),
        store.get(&top_unit.id).expect("get").expect("top"),
        resolved,
    )
}

#[test]
fn a_translation_that_calls_a_reused_callee_builds_and_runs_confined() {
    if !sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code");
        return;
    }
    let store = RewriteStore::open_in_memory().expect("store");
    let (_, top, resolved) = inner_and_top(&store);
    let composed = format!(
        "{}\n{}",
        reuse::prelude(&resolved.all, &resolved.direct),
        top.rust_code
    );
    let Build::Ready(runner) =
        build(&top.signature, &composed, &Confinement::default()).expect("build")
    else {
        panic!("composed source was rejected");
    };
    let obs = runner.run(&[Arg::Int { value: 20 }]).expect("run");
    assert_eq!(obs.termination, Termination::Returned);
    assert_eq!(obs.ret, Some(42), "(20 + 1) * 2 through the reused callee");
}

#[test]
fn the_export_links_a_reusing_unit_to_its_callees_module() {
    let store = RewriteStore::open_in_memory().expect("store");
    let (inner, top, _) = inner_and_top(&store);
    let dir = tempfile::tempdir().expect("dir");
    let info = ExportInfo {
        binary_name: "t".into(),
        program_sha256: SHA.into(),
        prefix: "t".into(),
        coverage: ExportCoverage {
            accepted: 2,
            planned: 0,
            functions_total: 2,
        },
        originals: Vec::new(),
        symbols: Default::default(),
    };

    let target = dir.path().join("out");
    let written = write_workspace(&target, &info, &[inner, top.clone()]).expect("write");
    let module = std::fs::read_to_string(target.join(&written.lib_crate).join("src/u_top.rs"))
        .expect("module");
    assert!(module.contains("use super::u_inner::inner;"), "{module}");
    assert!(!module.contains("no_mangle"));

    // Leaving the callee out of the export is refused, not silently exported broken.
    let err = write_workspace(&dir.path().join("out2"), &info, &[top]).expect_err("missing callee");
    assert!(err.to_string().contains("not among the accepted"), "{err}");
}

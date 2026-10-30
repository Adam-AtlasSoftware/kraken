//! `debuginfo_probe`, `debuginfo_attach` and `debuginfo_detach` on a real program whose debug
//! information was split into another file with `objcopy`, run on the native engine.
//!
//! Needs `objcopy` and `strip`, the native build and the Sleigh specs; without them the test
//! says "skipped" and passes.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{
    CallContext, EngineChoice, EngineFactory, EngineKind, EngineSelection, Registry, Session,
    Surface,
};
use serde_json::{Value, json};

struct NativeFactory {
    config: NativeConfig,
}

#[async_trait]
impl EngineFactory for NativeFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let mut config = self.config.clone();
        config.state_dir = Some(engine_dir.to_path_buf());
        Ok(Arc::new(NativeEngine::new(config)))
    }

    fn detect_kind(&self, _binary: &Path) -> Result<EngineKind, ProtoError> {
        Ok(EngineKind::Native)
    }

    fn select_kind(
        &self,
        _binary: &Path,
        _choice: Option<EngineChoice>,
    ) -> Result<EngineSelection, ProtoError> {
        Ok(EngineSelection {
            kind: EngineKind::Native,
            choice: EngineChoice::Native,
            reason: "the test factory has the native engine only".into(),
        })
    }
}

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn tool(name: &str, args: &[&Path]) -> bool {
    std::process::Command::new(name)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

/// `prog` (stripped, with a debug link) in `bin/` and its `prog.debug` in `dbg/`, plus
/// `dbg/other.debug` split from a different build of the same source.
fn split_program(root: &Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (bin, dbg) = (root.join("bin"), root.join("dbg"));
    std::fs::create_dir_all(&bin).ok()?;
    std::fs::create_dir_all(&dbg).ok()?;
    let (src, o2) = (corpus("bin/pie_list-O0"), corpus("bin/pie_list-O2"));
    let (prog, debug, other) = (
        bin.join("prog"),
        dbg.join("prog.debug"),
        dbg.join("other.debug"),
    );
    let ok = tool("objcopy", &["--only-keep-debug".as_ref(), &src, &debug])
        && tool("objcopy", &["--only-keep-debug".as_ref(), &o2, &other])
        && tool(
            "strip",
            &["--strip-all".as_ref(), "-o".as_ref(), &prog, &src],
        )
        && std::process::Command::new("objcopy")
            .arg(format!("--add-gnu-debuglink={}", debug.display()))
            .arg(&prog)
            .status()
            .is_ok_and(|s| s.success());
    ok.then_some((prog, debug, other))
}

async fn call(r: &Registry, s: &Session, command: &str, args: Value) -> Result<Value, ProtoError> {
    r.call_json(command, s, &CallContext::user("adam", Surface::Cli), args)
        .await
}

async fn job(r: &Registry, s: &Session, command: &str, args: Value) -> Value {
    let started = call(r, s, command, args)
        .await
        .unwrap_or_else(|e| panic!("{command}: {e}"));
    let done = call(
        r,
        s,
        "job_await",
        json!({"job_id": started["job_id"], "timeout_ms": 480_000}),
    )
    .await
    .expect("job_await");
    assert_eq!(done["status"], "succeeded", "{command}: {done}");
    done
}

async fn named_functions(r: &Registry, s: &Session) -> usize {
    let page = call(r, s, "list_functions", json!({"limit": 500}))
        .await
        .expect("list_functions");
    page["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter(|f| {
            let n = f["name"]["value"].as_str().unwrap_or("");
            !(n.starts_with("FUN_") || n.starts_with("sub_"))
        })
        .count()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_separate_debug_file_is_found_checked_attached_and_detached() {
    let Some(mut config) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs");
        return;
    };
    if !NativeEngine::is_usable(&config) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    config.isolation = match WorkerOptions::default().locate() {
        Ok(w) => Isolation::Worker(WorkerOptions::with_program(w)),
        Err(_) => Isolation::InProcess,
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let Some((prog, debug, other)) = split_program(tmp.path()) else {
        eprintln!("skipped: objcopy or strip is not available");
        return;
    };
    let r = Registry::standard();
    let s = Session::new(Arc::new(NativeFactory { config }));

    // the debug file is not beside the program, so nothing is found by itself
    let p = call(&r, &s, "debuginfo_probe", json!({"path": prog}))
        .await
        .expect("probe");
    assert_eq!(p["status"], "missing", "{p}");
    assert!(
        p["refs"]["debuglink"]["name"]["value"].as_str().is_some(),
        "{p}"
    );
    assert!(p["candidates"].as_array().expect("candidates").is_empty());
    assert!(
        p["summary"].as_str().unwrap_or("").contains("not found"),
        "{p}"
    );

    // a folder that holds it: found and checked
    let dbg_dir = debug.parent().expect("parent");
    let p = call(
        &r,
        &s,
        "debuginfo_probe",
        json!({"path": prog, "debug_file": dbg_dir}),
    )
    .await
    .expect("probe with a folder");
    assert_eq!(p["status"], "found", "{p}");
    assert_eq!(p["candidates"][0]["verdict"], "match", "{p}");
    assert_eq!(p["candidates"][0]["source"], "chosen");
    assert_eq!(
        p["best"]["value"].as_str().map(Path::new),
        Some(debug.canonicalize().expect("canon").as_path())
    );

    // a file of another build is refused, with the reason
    let p = call(
        &r,
        &s,
        "debuginfo_probe",
        json!({"path": prog, "debug_file": other}),
    )
    .await
    .expect("probe with another build");
    assert_eq!(p["candidates"][0]["verdict"], "mismatch", "{p}");
    assert!(
        p["candidates"][0]["detail"]["value"]
            .as_str()
            .unwrap_or("")
            .contains("another build"),
        "{p}"
    );
    assert!(p["best"].is_null());

    // a project without the debug file has no names; creating one with it has them
    let plain_dir = tmp.path().join("plain.kraken");
    call(
        &r,
        &s,
        "project_create",
        json!({"binary": prog, "project_dir": plain_dir, "engine": "native"}),
    )
    .await
    .expect("create");
    job(&r, &s, "analyze", json!({})).await;
    let without = named_functions(&r, &s).await;

    let err = call(&r, &s, "debuginfo_attach", json!({"debug_file": other}))
        .await
        .expect_err("another build's file is refused");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("another build"), "{}", err.message);
    assert_eq!(
        call(&r, &s, "debuginfo_detach", json!({}))
            .await
            .expect_err("nothing attached")
            .code,
        ErrorCode::InvalidArgument
    );

    job(&r, &s, "debuginfo_attach", json!({"debug_file": debug})).await;
    let meta: Value =
        serde_json::from_slice(&std::fs::read(plain_dir.join("meta.json")).expect("meta"))
            .expect("json");
    assert_eq!(
        meta["loader"]["debug_file"].as_str().map(PathBuf::from),
        Some(debug.canonicalize().expect("canon"))
    );
    let with = named_functions(&r, &s).await;
    assert!(
        with > without,
        "the debug file names functions: {without} before, {with} after"
    );

    job(&r, &s, "debuginfo_detach", json!({})).await;
    let meta: Value =
        serde_json::from_slice(&std::fs::read(plain_dir.join("meta.json")).expect("meta"))
            .expect("json");
    assert!(meta["loader"]["debug_file"].is_null(), "{meta}");
    assert_eq!(named_functions(&r, &s).await, without);

    // project_create takes the file straight away and checks it first
    let bad = call(
        &r,
        &s,
        "project_create",
        json!({"binary": prog, "project_dir": tmp.path().join("bad.kraken"), "debug_file": other}),
    )
    .await
    .expect_err("mismatch refused at creation");
    assert!(bad.message.contains("another build"), "{}", bad.message);
    call(
        &r,
        &s,
        "project_create",
        json!({"binary": prog, "project_dir": tmp.path().join("good.kraken"),
               "engine": "native", "debug_file": debug}),
    )
    .await
    .expect("create with the debug file");
    job(&r, &s, "analyze", json!({})).await;
    assert_eq!(named_functions(&r, &s).await, with);
}

/// A PDB kept apart from its image is probed, attached to a native project (a job) and names
/// the functions; detaching takes the names away again.
#[tokio::test(flavor = "multi_thread")]
async fn a_pdb_is_attached_to_a_native_project() {
    let Some(mut config) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs");
        return;
    };
    if !NativeEngine::is_usable(&config) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    config.isolation = match WorkerOptions::default().locate() {
        Ok(w) => Isolation::Worker(WorkerOptions::with_program(w)),
        Err(_) => Isolation::InProcess,
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let exe = tmp.path().join("bin").join("sample.exe");
    let pdb = tmp.path().join("symbols").join("pdb_sample-x64.pdb");
    std::fs::create_dir_all(exe.parent().expect("parent")).expect("bin");
    std::fs::create_dir_all(pdb.parent().expect("parent")).expect("symbols");
    std::fs::copy(corpus("pe/bin/pdb_sample-x64.exe"), &exe).expect("exe");
    std::fs::copy(corpus("pe/bin/pdb_sample-x64.pdb"), &pdb).expect("pdb");
    let r = Registry::standard();
    let s = Session::new(Arc::new(NativeFactory { config }));

    let p = call(
        &r,
        &s,
        "debuginfo_probe",
        json!({"path": exe, "debug_file": pdb}),
    )
    .await
    .expect("probe");
    assert_eq!(p["candidates"][0]["verdict"], "match", "{p}");

    let dir = tmp.path().join("pdb.kraken");
    call(
        &r,
        &s,
        "project_create",
        json!({"binary": exe, "project_dir": dir, "engine": "native"}),
    )
    .await
    .expect("create");
    job(&r, &s, "analyze", json!({})).await;
    let without = named_functions(&r, &s).await;
    job(&r, &s, "debuginfo_attach", json!({"debug_file": pdb})).await;
    let with = named_functions(&r, &s).await;
    assert!(with >= without + 6, "{without} before, {with} after");
    let page = call(&r, &s, "list_functions", json!({"limit": 500}))
        .await
        .expect("list");
    let names: Vec<&str> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|f| f["name"]["value"].as_str())
        .collect();
    assert!(
        names.contains(&"shape_area") && names.contains(&"list_sum"),
        "{names:?}"
    );
    let types = call(&r, &s, "types_list", json!({"name_filter": "shape"}))
        .await
        .expect("types_list");
    assert!(types.to_string().contains("shape"), "{types}");

    job(&r, &s, "debuginfo_detach", json!({})).await;
    assert_eq!(named_functions(&r, &s).await, without);
}

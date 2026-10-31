//! `debuginfo_export` round trip on the native engine: name and type functions of a stripped
//! program, write the DWARF debug file, attach it to a fresh project and read the names, a
//! prototype and a type back. `readelf` and `gdb` check the file when they are installed.
//!
//! Needs the native build and the Sleigh specs; without them the test says "skipped" and
//! passes.

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

async fn functions(r: &Registry, s: &Session) -> Vec<Value> {
    call(r, s, "list_functions", json!({"limit": 500}))
        .await
        .expect("list_functions")["items"]
        .as_array()
        .expect("items")
        .clone()
}

fn text_of(f: &Value, key: &str) -> String {
    f[key]["value"]
        .as_str()
        .or_else(|| f[key].as_str())
        .unwrap_or("")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn names_prototypes_and_types_survive_a_dwarf_export() {
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
    let prog = tmp.path().join("calc");
    std::fs::copy(corpus("bin/stripped_calc-O0-stripped"), &prog).expect("copy");
    let r = Registry::standard();
    let s = Session::new(Arc::new(NativeFactory { config }));

    call(
        &r,
        &s,
        "project_create",
        json!({"binary": prog, "project_dir": tmp.path().join("a.kraken"), "engine": "native"}),
    )
    .await
    .expect("create");
    job(&r, &s, "analyze", json!({})).await;
    let fns = functions(&r, &s).await;
    assert!(fns.len() >= 3, "{} functions", fns.len());
    let unnamed: Vec<String> = fns
        .iter()
        .filter(|f| text_of(f, "name").starts_with("FUN_"))
        .map(|f| f["address"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(unnamed.len() >= 2, "{unnamed:?}");
    let (a, b) = (unnamed[0].clone(), unnamed[1].clone());

    call(
        &r,
        &s,
        "rename_symbol",
        json!({"address": a, "new_name": "calc_eval"}),
    )
    .await
    .expect("rename");
    call(
        &r,
        &s,
        "rename_symbol",
        json!({"address": b, "new_name": "pair_sum"}),
    )
    .await
    .expect("rename");
    call(
        &r,
        &s,
        "type_define",
        json!({"c_declaration": "struct pair { int left; long right; };"}),
    )
    .await
    .expect("type_define");
    let int = json!({"kind": "primitive", "class": "int", "size": 4, "signed": true});
    let long = json!({"kind": "primitive", "class": "int", "size": 8, "signed": true});
    let chr = json!({"kind": "primitive", "class": "char", "size": 1, "signed": true});
    let ptr = |t: &Value| json!({"kind": "pointer", "target": t, "size": 8});
    call(
        &r,
        &s,
        "set_type",
        json!({"address": a, "prototype": {
            "return_type": int, "calling_convention": "", "varargs": false, "noreturn": false,
            "params": [{"name": "text", "type": ptr(&chr)}, {"name": "out", "type": ptr(&long)}]}}),
    )
    .await
    .expect("set_type calc_eval");
    call(
        &r,
        &s,
        "set_type",
        json!({"address": b, "prototype": {
            "return_type": long, "calling_convention": "", "varargs": false, "noreturn": false,
            "params": [{"name": "p", "type": ptr(&json!({"kind": "named", "name": "pair"}))}]}}),
    )
    .await
    .expect("set_type pair_sum");

    // an agent reads the bytes; only a person writes a file
    let agent = CallContext::agent("a1", "run-1", Surface::Mcp);
    let err = r
        .call_json("debuginfo_export", &s, &agent, json!({"path": "x.debug"}))
        .await
        .expect_err("agents do not write files");
    assert_eq!(err.code, ErrorCode::RejectedHumanPriority);
    let inline = r
        .call_json("debuginfo_export", &s, &agent, json!({}))
        .await
        .expect("inline export");
    assert!(
        inline["data_base64"]
            .as_str()
            .is_some_and(|d| d.len() > 100)
    );

    let debug = tmp.path().join("calc.debug");
    let out = call(&r, &s, "debuginfo_export", json!({"path": debug}))
        .await
        .expect("export");
    assert!(out["functions"].as_u64().unwrap_or(0) >= 2, "{out}");
    assert!(out["prototypes"].as_u64().unwrap_or(0) >= 2, "{out}");
    assert!(out["types"].as_u64().unwrap_or(0) >= 1, "{out}");
    assert!(
        call(&r, &s, "debuginfo_export", json!({"path": debug}))
            .await
            .is_err(),
        "an existing file is not replaced without overwrite"
    );

    if let Ok(o) = std::process::Command::new("readelf")
        .arg("--debug-dump=info")
        .arg(&debug)
        .output()
    {
        let dump = String::from_utf8_lossy(&o.stdout);
        for want in ["calc_eval", "pair_sum", "DW_TAG_subprogram", "left", "pair"] {
            assert!(dump.contains(want), "readelf shows {want}:\n{dump}");
        }
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    if let Ok(o) = std::process::Command::new("gdb")
        .args(["-batch", "-ex", "info functions calc_eval|pair_sum"])
        .arg(&debug)
        .output()
    {
        let text = String::from_utf8_lossy(&o.stdout);
        assert!(
            text.contains("calc_eval") && text.contains("pair_sum"),
            "gdb lists them:\n{text}{}",
            String::from_utf8_lossy(&o.stderr)
        );
    }

    // a fresh project of the same program gets everything back from the file
    let dir_b = tmp.path().join("b.kraken");
    call(
        &r,
        &s,
        "project_create",
        json!({"binary": prog, "project_dir": dir_b, "engine": "native"}),
    )
    .await
    .expect("create b");
    job(&r, &s, "analyze", json!({})).await;
    assert!(
        !functions(&r, &s)
            .await
            .iter()
            .any(|f| text_of(f, "name") == "calc_eval")
    );
    job(&r, &s, "debuginfo_attach", json!({"debug_file": debug})).await;
    let back = functions(&r, &s).await;
    let find = |n: &str| back.iter().find(|f| text_of(f, "name") == n).cloned();
    let calc = find("calc_eval").expect("calc_eval came back");
    let sig = text_of(&calc, "signature");
    assert!(
        sig.contains("char") && sig.contains("text"),
        "signature {sig}"
    );
    let pair = find("pair_sum").expect("pair_sum came back");
    let sig = text_of(&pair, "signature");
    assert!(sig.contains("pair"), "signature {sig}");
    let ty = call(&r, &s, "type_get", json!({"name": "pair"}))
        .await
        .expect("type pair");
    let c = ty.to_string();
    assert!(c.contains("left") && c.contains("right"), "{c}");
}

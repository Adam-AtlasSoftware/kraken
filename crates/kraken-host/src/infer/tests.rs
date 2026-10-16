//! Manager behaviour against the fake inference server (a real child process on 127.0.0.1).

use std::sync::Arc;
use std::time::Duration;

use kraken_engine::SharedEngine;
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{GenericOpenAiServerBackend, MemoryBudget};
use kraken_registry::EngineFactory;

use super::*;
use crate::factory::EngineDiagnostics;

const FAKE_ID: &str = "fake";

fn registry() -> BackendRegistry {
    let mut r = BackendRegistry::new();
    let m = fake_manifest(FAKE_ID, &fake_server_path());
    r.register(Arc::new(
        GenericOpenAiServerBackend::from_manifest_str(&m).expect("manifest"),
    ));
    r
}

fn manager() -> InferManager {
    InferManager::with_registry(registry())
        .with_total_memory(8 * GIB, None)
        .with_manifest_ids(vec![FAKE_ID.into()])
}

fn model_file(dir: &Path) -> PathBuf {
    let p = dir.join("tiny.gguf");
    std::fs::write(&p, vec![0u8; 4096]).expect("model");
    p
}

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-host-infer")
        .tempdir()
        .expect("tempdir")
}

async fn wait_ready(m: &InferManager) -> StatusReply {
    for _ in 0..400 {
        let s = m.status().await.expect("status");
        if s.is_ready() {
            return s;
        }
        assert!(!s.is_failed(), "failed: {}", s.message);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("model never became ready");
}

#[tokio::test]
async fn start_status_logs_stop() {
    let t = tmp();
    let m = manager();
    assert_eq!(m.status().await.unwrap().phase, "none");
    assert_eq!(m.loaded_models(), 0);

    let model = model_file(t.path());
    let r = m
        .start(FAKE_ID, json!({"model": model}))
        .await
        .expect("start");
    assert!(
        r.base_url.starts_with("http://127.0.0.1:"),
        "{}",
        r.base_url
    );
    assert!(r.base_url.ends_with("/v1"));
    assert_eq!(r.model.as_deref(), Some("tiny.gguf"));
    assert!(r.pid.is_some());
    assert_eq!(m.loaded_models(), 1);

    let s = wait_ready(&m).await;
    assert!(s.running);
    assert_eq!(s.backend.as_deref(), Some(FAKE_ID));
    assert_eq!(s.base_url.as_deref(), Some(r.base_url.as_str()));

    let logs = m.logs(LogsParams::default()).await.unwrap();
    assert!(
        logs.lines.iter().any(|l| l.text.contains("listening on")),
        "{:?}",
        logs.lines
    );
    let again = m
        .logs(LogsParams {
            after_seq: Some(logs.last_seq),
            limit: None,
        })
        .await
        .unwrap();
    assert!(again.lines.is_empty() || again.lines[0].seq > logs.last_seq);
    let one = m
        .logs(LogsParams {
            after_seq: None,
            limit: Some(1),
        })
        .await
        .unwrap();
    assert_eq!(one.lines.len(), 1);

    assert!(m.stop().await.unwrap().stopped);
    assert_eq!(m.loaded_models(), 0);
    let s = m.status().await.unwrap();
    assert!(!s.running);
    assert_eq!(s.phase, "stopped");
    // The logs stay readable after a stop; a second stop does nothing.
    assert!(
        !m.logs(LogsParams::default())
            .await
            .unwrap()
            .lines
            .is_empty()
    );
    assert!(!m.stop().await.unwrap().stopped);
}

#[tokio::test]
async fn loading_progress_is_visible_and_one_model_at_a_time() {
    let t = tmp();
    let m = manager();
    let model = model_file(t.path());
    m.start(FAKE_ID, json!({"model": model, "ready_after": 1.0}))
        .await
        .unwrap();
    let s = m.status().await.unwrap();
    assert!(s.running && !s.is_ready(), "{s:?}");
    assert!(matches!(s.phase.as_str(), "starting" | "loading"));

    let e = m.start(FAKE_ID, json!({"model": model})).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("already running"), "{}", e.message);

    wait_ready(&m).await;
    m.stop().await.unwrap();
    // After a stop a new start works.
    m.start(FAKE_ID, json!({"model": model})).await.unwrap();
    wait_ready(&m).await;
    m.shutdown().await;
    assert_eq!(m.loaded_models(), 0);
}

#[tokio::test]
async fn bad_requests_are_explained() {
    let t = tmp();
    let m = manager();
    let model = model_file(t.path());

    let e = m.start("nope", Value::Null).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    assert!(e.message.contains(FAKE_ID), "{}", e.message);

    let e = m.start(FAKE_ID, json!([1])).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    let e = m.start(FAKE_ID, json!({})).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("model"), "{}", e.message);

    let e = m
        .start(FAKE_ID, json!({"model": "relative/model.gguf"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("absolute"), "{}", e.message);

    let e = m
        .start(FAKE_ID, json!({"model": model, "bogus": 1}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(m.loaded_models(), 0);
}

#[tokio::test]
async fn the_memory_budget_denies_and_warns_in_plain_words() {
    let t = tmp();
    let model = model_file(t.path());
    // The fake engine asks for at least 256 MiB.
    let small = InferManager::with_registry(registry()).with_total_memory(100 * MIB, None);
    let e = small
        .start(FAKE_ID, json!({"model": model}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("not enough memory"), "{}", e.message);
    assert_eq!(e.details, Some(json!({"reason": "memory_budget"})));
    assert_eq!(small.loaded_models(), 0);

    // Plenty of RAM, but open Ghidra sessions hold most of it.
    let busy = InferManager::with_registry(registry()).with_total_memory(2 * GIB, None);
    busy.set_reservations(|| vec![Reservation::new("Ghidra heap of p", 2 * GIB - 100 * MIB, 0)]);
    let e = busy
        .start(FAKE_ID, json!({"model": model}))
        .await
        .unwrap_err();
    assert!(e.message.contains("not enough memory"), "{}", e.message);
    let l = busy.list().await.unwrap();
    assert_eq!(l.memory.total_ram, 2 * GIB);
    assert_eq!(l.memory.ghidra_reserved, 2 * GIB - 100 * MIB);
    assert_eq!(l.memory.available_ram, 100 * MIB);

    // A tight fit starts, with a warning.
    let tight = InferManager::with_registry(registry()).with_total_memory(290 * MIB, None);
    let r = tight.start(FAKE_ID, json!({"model": model})).await.unwrap();
    assert_eq!(r.warnings.len(), 1, "{:?}", r.warnings);
    assert!(r.warnings[0].contains("committed"), "{}", r.warnings[0]);
    let logs = tight.logs(LogsParams::default()).await.unwrap();
    assert!(
        logs.lines
            .iter()
            .any(|l| l.text.starts_with("budget warning"))
    );
    tight.shutdown().await;
}

struct StubFactory(Vec<EngineDiagnostics>);

#[async_trait]
impl EngineFactory for StubFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Err(ProtoError::new(ErrorCode::Unsupported, "stub"))
    }
}

#[async_trait]
impl ManagedFactory for StubFactory {
    async fn shutdown(&self) {}

    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        self.0.clone()
    }
}

#[test]
fn ghidra_heaps_become_reservations() {
    let f = StubFactory(vec![
        EngineDiagnostics {
            engine_dir: "/p/sample/ghidra".into(),
            value: json!({"state": "running", "heap_mb": 3072}),
        },
        EngineDiagnostics {
            engine_dir: "/p/idle/ghidra".into(),
            value: json!({"state": "stopped", "heap_mb": null}),
        },
    ]);
    let r = ghidra_reservations(&f);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ram, 3072 * MIB);
    assert!(r[0].name.contains("sample"), "{}", r[0].name);
    let mut b = MemoryBudget::new(4 * GIB, None);
    for x in r {
        b.reserve(x);
    }
    assert_eq!(b.committed_ram(), 3 * GIB);
}

#[tokio::test]
async fn list_describes_the_engines_for_this_platform() {
    let m = manager();
    let l = m.list().await.unwrap();
    assert_eq!(l.platform.os, std::env::consts::OS);
    assert_eq!(l.backends.len(), 1);
    let b = &l.backends[0];
    assert_eq!(b.id, FAKE_ID);
    assert!(!b.builtin);
    assert!(b.capabilities.supports_moe_offload);
    assert_eq!(b.settings_schema["required"][0], "model");
    assert_eq!(l.llama.pinned_tag, llama_setup::LLAMA_TAG);
}

#[tokio::test]
async fn the_default_registry_has_llama_server_and_its_install_state() {
    let t = tmp();
    let data = t.path().to_path_buf();
    let env = move |k: &str| match k {
        "XDG_DATA_HOME" => Some(data.clone().into_os_string()),
        "PATH" => Some(OsString::from("/nonexistent-kraken-path")),
        _ => None,
    };
    let m = InferManager::from_env_with(&env).with_total_memory(8 * GIB, None);
    let l = m.list().await.unwrap();
    let llama = l.backends.iter().find(|b| b.id == LLAMA_ID).expect("llama");
    assert!(llama.builtin);
    assert_eq!(llama.installed, Some(false));
    assert!(
        llama
            .setup_hint
            .as_deref()
            .unwrap_or("")
            .contains("kraken infer setup llama"),
        "{:?}",
        llama.setup_hint
    );
    assert!(llama.settings_schema["properties"]["n_cpu_moe"].is_object());
    assert!(l.llama.installed.is_none());

    // Starting without the program says what to do.
    let model = model_file(t.path());
    let e = m
        .start(LLAMA_ID, json!({"model_path": model}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    assert!(
        e.message.contains("kraken infer setup llama"),
        "{}",
        e.message
    );
}

#[tokio::test]
async fn manifests_come_from_the_environment_directory() {
    let t = tmp();
    let dir = t.path().join("manifests");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("fake.toml"),
        fake_manifest("my-moe-engine", &fake_server_path()),
    )
    .unwrap();
    let dirs = dir.clone().into_os_string();
    let env = move |k: &str| (k == ENV_INFER_MANIFESTS).then(|| dirs.clone());
    let m = InferManager::from_env_with(&env).with_total_memory(8 * GIB, None);
    let l = m.list().await.unwrap();
    let ids: Vec<&str> = l.backends.iter().map(|b| b.id.as_str()).collect();
    assert!(
        ids.contains(&"my-moe-engine") && ids.contains(&LLAMA_ID),
        "{ids:?}"
    );
    assert!(
        !l.backends
            .iter()
            .find(|b| b.id == "my-moe-engine")
            .unwrap()
            .builtin
    );
    assert_eq!(l.manifests_dir.as_deref(), Some(dir.as_path()));
    assert!(l.warnings.is_empty());

    std::fs::write(dir.join("broken.toml"), "id = 1").unwrap();
    let dirs = dir.into_os_string();
    let env = move |k: &str| (k == ENV_INFER_MANIFESTS).then(|| dirs.clone());
    let l = InferManager::from_env_with(&env).list().await.unwrap();
    assert!(l.warnings[0].contains("manifests"), "{:?}", l.warnings);
}

#[tokio::test]
async fn rpc_dispatch_round_trips() {
    let t = tmp();
    let m = manager();
    let model = model_file(t.path());
    assert!(serve_rpc(&m, "call", Value::Null).await.is_none());

    let list = serve_rpc(&m, METHOD_INFER_LIST, Value::Null)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(list["backends"][0]["id"], FAKE_ID);

    let started = serve_rpc(
        &m,
        METHOD_INFER_START,
        json!({"backend": FAKE_ID, "settings": {"model": model}}),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(started["base_url"].as_str().unwrap().contains("127.0.0.1"));
    wait_ready(&m).await;

    let bad = serve_rpc(&m, METHOD_INFER_START, json!({"nope": 1}))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidArgument);

    let st = serve_rpc(&m, METHOD_INFER_STATUS, Value::Null)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(st["phase"], "ready");
    let logs = serve_rpc(&m, METHOD_INFER_LOGS, json!({"limit": 2}))
        .await
        .unwrap()
        .unwrap();
    assert!(logs["lines"].as_array().unwrap().len() <= 2);
    let stop = serve_rpc(&m, METHOD_INFER_STOP, Value::Null)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stop["stopped"], true);
}

#[test]
fn settings_pairs_follow_the_schema() {
    let schema = json!({
        "type": "object",
        "properties": {
            "model_path": {"type": "string", "x-kraken-widget": "file-path"},
            "context_size": {"type": "integer"},
            "temp": {"type": "number"},
            "jinja": {"type": "boolean"},
            "extra": {"type": "array"},
            "name": {"type": "string"}
        }
    });
    let cwd = Path::new("/work");
    let pairs: Vec<String> = [
        "model_path=models/a b.gguf",
        "context_size=32768",
        "temp=0.5",
        "jinja=off",
        "extra=[1,2]",
        "name=x=y",
    ]
    .map(String::from)
    .to_vec();
    let v = settings_from_pairs(&schema, &pairs, Some(cwd)).unwrap();
    assert_eq!(
        v,
        json!({
            "model_path": "/work/models/a b.gguf",
            "context_size": 32768,
            "temp": 0.5,
            "jinja": false,
            "extra": [1, 2],
            "name": "x=y"
        })
    );
    // Absolute paths and a missing cwd are left alone.
    let v = settings_from_pairs(&schema, &["model_path=/m/x.gguf".into()], Some(cwd)).unwrap();
    assert_eq!(v["model_path"], "/m/x.gguf");
    let v = settings_from_pairs(&schema, &["model_path=x.gguf".into()], None).unwrap();
    assert_eq!(v["model_path"], "x.gguf");

    for (bad, needle) in [
        ("context_size=lots", "whole number"),
        ("temp=hot", "number"),
        ("jinja=maybe", "true or false"),
        ("extra=[", "JSON"),
        ("nope=1", "model_path"),
        ("novalue", "key=value"),
    ] {
        let e = settings_from_pairs(&schema, &[bad.into()], None).unwrap_err();
        assert!(e.contains(needle), "{bad}: {e}");
    }
    assert_eq!(model_setting(&schema), Some("model_path"));
    assert_eq!(
        model_setting(&json!({"properties": {"model": {}}})),
        Some("model")
    );
    assert_eq!(model_setting(&json!({})), None);
}

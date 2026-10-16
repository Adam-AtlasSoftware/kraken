//! The `infer_*` daemon methods over a real socket with the fake inference server as the model:
//! start, status, logs, stop, the memory budget, and the idle monitor counting the loaded model.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use engine_fake::FixtureFile;
use kraken_host::DaemonSettings;
use kraken_host::daemon::DaemonClient;
use kraken_host::infer::{
    InferApi, InferManager, LogsParams, METHOD_INFER_LIST, METHOD_INFER_START, METHOD_INFER_STATUS,
    METHOD_INFER_STOP,
};
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{BackendRegistry, GenericOpenAiServerBackend};
use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, RuntimeDir};
use kraken_proto::ErrorCode;
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory;
use krakend::{Daemon, DaemonOptions};
use serde_json::{Value, json};

const TINY: &str = "../engine-fake/fixtures/tiny.json";
const ID: &str = "fake";
const GIB: u64 = 1024 * 1024 * 1024;

struct Rig {
    tmp: tempfile::TempDir,
    dir: RuntimeDir,
    daemon: Option<Daemon>,
    clock: ManualClock,
}

fn manager(total_ram: u64) -> Arc<InferManager> {
    let mut r = BackendRegistry::new();
    r.register(Arc::new(
        GenericOpenAiServerBackend::from_manifest_str(&fake_manifest(ID, &fake_server_path()))
            .expect("manifest"),
    ));
    Arc::new(InferManager::with_registry(r).with_total_memory(total_ram, None))
}

fn rig(idle_secs: u64, infer: Arc<InferManager>) -> Rig {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-infer-d")
        .tempdir()
        .expect("tempdir");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let fixture =
        FixtureFile::from_path(&Path::new(env!("CARGO_MANIFEST_DIR")).join(TINY)).expect("tiny");
    let clock = ManualClock::new();
    let daemon = krakend::start_with_infer(
        DaemonOptions {
            runtime_dir: dir.clone(),
            factory: Arc::new(FakeFactory::new(fixture, Duration::ZERO)),
            registry: Arc::new(Registry::standard()),
            settings: DaemonSettings {
                idle_secs: Some(idle_secs),
                session_idle_secs: Some(1800),
                max_sessions: Some(4),
            },
            session_config: SessionConfig::default(),
            clock: Arc::new(clock.clone()),
            poll: Duration::from_millis(10),
            build: "test-build".into(),
        },
        infer,
    )
    .expect("daemon starts");
    Rig {
        tmp,
        dir,
        daemon: Some(daemon),
        clock,
    }
}

impl Rig {
    async fn client(&self) -> DaemonClient {
        let c = Client::connect(&self.dir, &ClientHello::new(ClientKind::Cli, "test-build"))
            .await
            .expect("connect");
        DaemonClient::from_client(c, "test-build")
    }

    fn model(&self) -> PathBuf {
        let p = self.tmp.path().join("m.gguf");
        std::fs::write(&p, vec![0u8; 1024]).expect("model file");
        p
    }

    async fn finish(mut self) {
        let d = self.daemon.take().expect("daemon");
        d.shutdown();
        tokio::time::timeout(Duration::from_secs(10), d.wait())
            .await
            .expect("daemon stops");
    }
}

async fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn wait_ready(c: &DaemonClient) -> Value {
    for _ in 0..400 {
        let s = c
            .rpc(METHOD_INFER_STATUS, Value::Null)
            .await
            .expect("status");
        if s["phase"] == "ready" {
            return s;
        }
        assert_ne!(s["phase"], "failed", "{s}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("model never became ready");
}

#[tokio::test(flavor = "multi_thread")]
async fn start_status_logs_stop_over_the_socket() {
    let r = rig(600, manager(8 * GIB));
    let c = r.client().await;

    let list = c.rpc(METHOD_INFER_LIST, Value::Null).await.unwrap();
    assert_eq!(list["backends"][0]["id"], ID);
    assert!(list["memory"]["total_ram"].as_u64().unwrap() > 0);

    let none = c.rpc(METHOD_INFER_STATUS, Value::Null).await.unwrap();
    assert_eq!(none["phase"], "none");

    let started = c
        .rpc(
            METHOD_INFER_START,
            json!({"backend": ID, "settings": {"model": r.model()}}),
        )
        .await
        .unwrap();
    let url = started["base_url"].as_str().unwrap().to_string();
    assert!(
        url.starts_with("http://127.0.0.1:") && url.ends_with("/v1"),
        "{url}"
    );
    assert_eq!(started["model"], "m.gguf");

    let st = wait_ready(&c).await;
    assert_eq!(st["base_url"], started["base_url"]);
    assert_eq!(st["running"], true);

    // The typed client API goes through the same methods.
    let logs = InferApi::logs(&c, LogsParams::default()).await.unwrap();
    assert!(logs.lines.iter().any(|l| l.text.contains("listening on")));
    assert!(logs.last_seq >= logs.lines.last().unwrap().seq);

    // The daemon status shows the model too.
    let daemon_status = c.status().await.unwrap();
    assert_eq!(daemon_status["daemon"]["loaded_models"], 1);
    assert_eq!(daemon_status["model"]["phase"], "ready");

    // A second model is refused while one runs.
    let e = c
        .rpc(
            METHOD_INFER_START,
            json!({"backend": ID, "settings": {"model": r.model()}}),
        )
        .await;
    assert!(e.is_err());

    let stop = c.rpc(METHOD_INFER_STOP, Value::Null).await.unwrap();
    assert_eq!(stop["stopped"], true);
    let st = c.rpc(METHOD_INFER_STATUS, Value::Null).await.unwrap();
    assert_eq!(st["phase"], "stopped");
    r.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_budget_check_and_errors_reach_the_client() {
    let r = rig(600, manager(100 * 1024 * 1024));
    let c = r.client().await;
    let e = c
        .rpc(
            METHOD_INFER_START,
            json!({"backend": ID, "settings": {"model": r.model()}}),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("not enough memory"), "{}", e.message);

    let e = c
        .rpc(METHOD_INFER_START, json!({"backend": "nope"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = c.rpc("infer_bogus", Value::Null).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = c
        .rpc(METHOD_INFER_START, json!({"settings": {}}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    r.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_loaded_model_keeps_an_otherwise_idle_daemon_alive() {
    let infer = manager(8 * GIB);
    let r = rig(60, infer.clone());
    let c = r.client().await;
    c.rpc(
        METHOD_INFER_START,
        json!({"backend": ID, "settings": {"model": r.model()}}),
    )
    .await
    .unwrap();
    wait_ready(&c).await;
    drop(c);
    wait_until("the client to be gone", || {
        r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    wait_until("the model to be counted", || {
        r.daemon.as_ref().unwrap().loaded_models() == 1
    })
    .await;

    for _ in 0..3 {
        r.clock.advance(Duration::from_secs(1000));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !r.daemon.as_ref().unwrap().is_stopping(),
            "must not exit while a model is loaded"
        );
    }

    // Stop the model through a new connection; then the idle time runs out.
    let c = r.client().await;
    c.rpc(METHOD_INFER_STOP, Value::Null).await.unwrap();
    drop(c);
    wait_until("the model to be gone from the count", || {
        r.daemon.as_ref().unwrap().loaded_models() == 0 && r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    r.clock.advance(Duration::from_secs(61));
    let mut r = r;
    let d = r.daemon.take().unwrap();
    tokio::time::timeout(Duration::from_secs(10), d.wait())
        .await
        .expect("exits once the model is gone and the idle time passed");
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_the_daemon_stops_the_model() {
    let infer = manager(8 * GIB);
    let r = rig(600, infer.clone());
    let c = r.client().await;
    let started = c
        .rpc(
            METHOD_INFER_START,
            json!({"backend": ID, "settings": {"model": r.model()}}),
        )
        .await
        .unwrap();
    wait_ready(&c).await;
    let pid = started["pid"].as_u64().expect("pid");
    drop(c);
    r.finish().await;
    assert_eq!(infer.loaded_models(), 0);
    #[cfg(target_os = "linux")]
    wait_until("the model process to be gone", || !process_alive(pid)).await;
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
}

/// True while `pid` exists and is not a zombie (Linux `/proc`).
#[cfg(target_os = "linux")]
fn process_alive(pid: u64) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s.contains(") Z "),
        Err(_) => false,
    }
}

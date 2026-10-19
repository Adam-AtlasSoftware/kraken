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

/// A manager with one model set up (processor only), served by the fake server as llama-server.
fn serving_manager(dir: &Path) -> Arc<InferManager> {
    use kraken_host::infer::ServingConfig;
    use kraken_proto::infer::{LocalEngine, LocalModel, MultiGpuMode};
    let path = dir.join("served.gguf");
    std::fs::write(&path, vec![0u8; 1024]).expect("model file");
    let cfg = ServingConfig {
        models: vec![LocalModel {
            id: "m".into(),
            name: "Model".into(),
            engine: LocalEngine::Llama,
            model_path: path,
            devices: Vec::new(),
            cpu_only: true,
            multi_gpu: MultiGpuMode::Split,
            shares: None,
            main_device: None,
            context_size: Some(2048),
            autostart: true,
            extra: None,
        }],
        roles: vec!["m".into()],
        serving: kraken_host::LocalServingSettings::default(),
    };
    Arc::new(
        InferManager::with_registry(BackendRegistry::new())
            .with_total_memory(8 * GIB, None)
            .with_serving_config(cfg)
            .with_llama_binary(fake_server_path()),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn holds_end_with_their_connection_and_the_model_stops_after_the_grace() {
    use kraken_host::infer::{ServingApi, StartOptions};
    use kraken_proto::infer::ModelState;
    let t = tempfile::tempdir().expect("tempdir");
    let infer = serving_manager(t.path());
    let r = rig(600, infer.clone());
    let gui1 = r.client().await;
    let gui2 = r.client().await;

    let s = gui1.hold("m", StartOptions::default()).await.expect("hold");
    assert_eq!(s.holders, 1);
    assert!(s.api_key.is_some());
    let auto = gui2.autostart().await.expect("autostart");
    assert_eq!(auto.started, ["m"]);
    assert_eq!(infer.model_status("m").holders, 2);
    let models = gui2.models().await.expect("models");
    assert_eq!(models.models[0].id, "m");

    // The first GUI dies: its hold goes, the second keeps the model.
    drop(gui1);
    wait_until("the first hold to go", || {
        infer.model_status("m").holders == 1
    })
    .await;
    r.clock.advance(Duration::from_secs(500));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(infer.model_status("m").is_running());

    drop(gui2);
    wait_until("the grace period to start", || {
        let s = infer.model_status("m");
        s.holders == 0 && s.stops_in_secs.is_some()
    })
    .await;
    assert!(infer.model_status("m").is_running());
    r.clock.advance(Duration::from_secs(121));
    wait_until("the model to stop", || {
        infer.model_status("m").state == ModelState::Stopped
    })
    .await;
    assert_eq!(infer.loaded_models(), 0);
    r.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_manual_start_outlives_its_connection_until_stopped() {
    use kraken_host::infer::{ServingApi, StartOptions};
    use kraken_proto::infer::ModelState;
    let t = tempfile::tempdir().expect("tempdir");
    let infer = serving_manager(t.path());
    let r = rig(600, infer.clone());
    let c = r.client().await;
    let s = c
        .start_model("m", StartOptions::default())
        .await
        .expect("start");
    assert!(s.pinned);
    drop(c);
    wait_until("the client to be gone", || {
        r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    r.clock.advance(Duration::from_secs(1000));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = infer.model_status("m");
    assert!(
        s.is_running() && s.pinned && s.stops_in_secs.is_none(),
        "{s:?}"
    );

    let c = r.client().await;
    let e = c.hold("nope", StartOptions::default()).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    assert!(c.stop_model("m").await.expect("stop").stopped);
    assert_eq!(infer.model_status("m").state, ModelState::Stopped);
    drop(c);
    r.finish().await;
}

//! Machine-global commands over a real daemon socket with no project open: `setup_status`, the
//! `integrations_*` and `local_model_*` commands, and the `setup_*` installs as cancellable
//! global jobs (`job-gN`) whose progress and cancel go through `job_status` and `job_cancel`.
//! The download comes from a canned fetcher that never finishes, so cancel is what ends it.

#![cfg(all(unix, target_os = "linux", target_arch = "x86_64"))]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use kraken_host::KrakenConfig;
use kraken_host::daemon::{CallParams, DaemonClient};
use kraken_host::infer::InferManager;
use kraken_host::provision::{Body, Fetched, Fetcher, Layout, ProvisionError};
use kraken_host::setup::HostSetup;
use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, RuntimeDir};
use kraken_model::AuthorKind;
use kraken_proto::ProtoError;
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory;
use krakend::{DaemonOptions, start_with_setup};
use serde_json::{Value, json};

/// A download of a huge file that arrives slowly: 64 KiB every 15 ms.
struct Endless(Arc<AtomicU64>);

#[async_trait]
impl Body for Endless {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        tokio::time::sleep(Duration::from_millis(15)).await;
        self.0.fetch_add(65536, Ordering::SeqCst);
        Ok(Some(vec![7u8; 65536]))
    }
}

struct EndlessFetcher(Arc<AtomicU64>);

#[async_trait]
impl Fetcher for EndlessFetcher {
    async fn fetch(&self, _url: &str, _from: u64) -> Result<Fetched, ProvisionError> {
        Ok(Fetched {
            resumed: false,
            total: Some(1 << 40),
            body: Box::new(Endless(self.0.clone())),
        })
    }
}

fn params(command: &str, args: Value) -> CallParams {
    CallParams {
        // no project: the commands here are about the machine
        project_dir: String::new(),
        command: command.into(),
        args,
        author_kind: AuthorKind::User,
        author_id: Some("tester".into()),
        run_id: None,
        surface: None,
        approved: true,
    }
}

async fn call(c: &DaemonClient, command: &str, args: Value) -> Result<Value, ProtoError> {
    c.call(&params(command, args)).await.map(|r| r.result)
}

struct Rig {
    _tmp: tempfile::TempDir,
    daemon: krakend::Daemon,
    dir: RuntimeDir,
    layout_root: std::path::PathBuf,
    received: Arc<AtomicU64>,
}

fn rig() -> Rig {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-gj")
        .tempdir()
        .expect("tempdir");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let fixture = engine_fake::FixtureFile::from_path(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json"),
    )
    .expect("tiny");
    let received = Arc::new(AtomicU64::new(0));
    let layout = Layout::at(tmp.path().join("runtime"));
    let layout_root = layout.root().to_path_buf();
    let setup = HostSetup::with(
        layout,
        Arc::new(EndlessFetcher(received.clone())),
        KrakenConfig::default(),
    );
    let clock = ManualClock::new();
    let daemon = start_with_setup(
        DaemonOptions {
            runtime_dir: dir.clone(),
            factory: Arc::new(FakeFactory::new(fixture, Duration::ZERO)),
            registry: Arc::new(Registry::standard()),
            settings: Default::default(),
            session_config: SessionConfig::default(),
            clock: Arc::new(clock),
            poll: Duration::from_millis(10),
            build: "test-build".into(),
        },
        None,
        Arc::new(InferManager::with_registry(Default::default())),
        Some(Arc::new(setup)),
    )
    .expect("daemon starts");
    Rig {
        _tmp: tmp,
        daemon,
        dir,
        layout_root,
        received,
    }
}

impl Rig {
    async fn client(&self) -> DaemonClient {
        let c = Client::connect(&self.dir, &ClientHello::new(ClientKind::Cli, "test-build"))
            .await
            .expect("connect");
        DaemonClient::from_client(c, "test-build")
    }

    async fn stop(self) {
        self.daemon.shutdown();
        tokio::time::timeout(Duration::from_secs(10), self.daemon.wait())
            .await
            .expect("daemon stops");
    }
}

async fn status_of(c: &DaemonClient, job: &str) -> Value {
    call(c, "job_status", json!({ "job_id": job }))
        .await
        .expect("job_status")
}

#[tokio::test]
async fn setup_status_and_catalogue_commands_need_no_project() {
    let r = rig();
    let c = r.client().await;
    let out = call(&c, "setup_status", json!({})).await.expect("status");
    let items = out["items"].as_array().expect("items");
    let ids: Vec<&str> = items.iter().map(|i| i["id"].as_str().unwrap()).collect();
    for want in [
        "ghidra",
        "native",
        "dotnet",
        "rust",
        "emulators",
        "llama",
        "strata",
    ] {
        assert!(ids.contains(&want), "{want} missing from {ids:?}");
    }
    // the layout is empty, so Ghidra is not installed and the report says how to fix it
    let ghidra = items.iter().find(|i| i["id"] == "ghidra").unwrap();
    assert_eq!(ghidra["state"], "missing");
    assert_eq!(ghidra["fix_command"], "setup_ghidra");
    let ready = out["ready"].as_u64().unwrap();
    assert_eq!(
        ready + out["not_ready"].as_u64().unwrap(),
        items.len() as u64
    );

    let list = call(&c, "integrations_list", json!({}))
        .await
        .expect("integrations_list");
    assert!(
        list["integrations"]
            .as_array()
            .is_some_and(|l| !l.is_empty())
    );
    let devices = call(&c, "local_model_list", json!({})).await;
    assert!(devices.is_ok(), "{devices:?}");
    r.stop().await;
}

#[tokio::test]
async fn an_install_runs_as_a_global_job_with_progress_and_cancel() {
    let r = rig();
    let c = r.client().await;
    let started = call(&c, "setup_ghidra", json!({})).await.expect("start");
    let job = started["job_id"].as_str().expect("job id").to_string();
    assert_eq!(job, "job-g1");

    // another connection sees the same job and its progress while the download runs
    let other = r.client().await;
    let mut seen = Value::Null;
    for _ in 0..200 {
        let v = status_of(&other, &job).await;
        if v["progress"]["phase"] == "download" && v["progress"]["done"].as_u64() > Some(0) {
            seen = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(seen["status"], "running", "{seen}");
    assert_eq!(seen["command"], "setup_ghidra");
    assert_eq!(seen["progress"]["total"], 1u64 << 40);
    assert!(
        seen["progress"]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("downloading ghidra")),
        "{seen}"
    );

    let cancelled = call(&c, "job_cancel", json!({ "job_id": job }))
        .await
        .expect("cancel");
    assert!(
        matches!(cancelled["status"].as_str(), Some("cancelled" | "running")),
        "{cancelled}"
    );
    let mut end = Value::Null;
    for _ in 0..200 {
        let v = status_of(&c, &job).await;
        if v["status"] != "running" {
            end = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(end["status"], "cancelled", "{end}");
    assert_eq!(end["error"]["code"], "cancelled");

    // the download stopped, and what arrived stays for the next run to resume
    let after = r.received.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(
        r.received.load(Ordering::SeqCst),
        after,
        "download kept going"
    );
    let part = std::fs::read_dir(r.layout_root.join("downloads"))
        .expect("downloads dir")
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().ends_with(".part"))
        .expect("partial download kept");
    assert!(part.metadata().expect("meta").len() > 0);

    // a second job gets the next global number and unknown ones are refused
    let again = call(&c, "setup_dotnet", json!({})).await.expect("start");
    assert_eq!(again["job_id"], "job-g2");
    let gone = call(&c, "job_status", json!({ "job_id": "job-g99" })).await;
    assert!(gone.is_err());
    let stop = call(&c, "job_cancel", json!({ "job_id": "job-g2" })).await;
    assert!(stop.is_ok(), "{stop:?}");
    r.stop().await;
}

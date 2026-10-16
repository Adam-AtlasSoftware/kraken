//! The panel against an in-process `krakend` that hosts the fake inference server, reached
//! through the GUI's daemon backend (so a reconnect is covered by the adapter's design).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine_fake::FixtureFile;
use kraken_host::DaemonSettings;
use kraken_host::infer::InferManager;
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{BackendRegistry, GenericOpenAiServerBackend};
use kraken_ipc::{ManualClock, RuntimeDir};
use kraken_registry::{Registry, SessionConfig};
use krakend::DaemonOptions;
use krakend::fake::FakeFactory;

use super::*;
use crate::daemon::{BackendOptions, Backoff, DaemonClientBackend, attach_connector};

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn the_panel_drives_a_model_hosted_by_the_daemon() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let tmp = tempfile::Builder::new()
        .prefix("kraken-vm-infer")
        .tempdir()
        .expect("tempdir");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(
        GenericOpenAiServerBackend::from_manifest_str(&fake_manifest("fake", &fake_server_path()))
            .expect("manifest"),
    ));
    let infer = Arc::new(InferManager::with_registry(reg).with_total_memory(8 * GIB, None));
    let fixture = FixtureFile::from_path(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json"),
    )
    .expect("tiny fixture");
    let daemon = {
        let _guard = rt.enter();
        krakend::start_with_infer(
            DaemonOptions {
                runtime_dir: dir.clone(),
                factory: Arc::new(FakeFactory::new(fixture, Duration::ZERO)),
                registry: Arc::new(Registry::standard()),
                settings: DaemonSettings {
                    idle_secs: Some(600),
                    session_idle_secs: Some(1800),
                    max_sessions: Some(4),
                },
                session_config: SessionConfig::default(),
                clock: Arc::new(ManualClock::new()),
                poll: Duration::from_millis(10),
                build: crate::daemon::BUILD.into(),
            },
            infer.clone(),
        )
        .expect("daemon starts")
    };
    let backend = Arc::new(
        rt.block_on(DaemonClientBackend::connect(
            attach_connector(dir.clone()),
            BackendOptions {
                author: "tester".into(),
                backoff: Backoff {
                    initial: Duration::from_millis(20),
                    max: Duration::from_millis(100),
                },
            },
        ))
        .expect("backend connects"),
    );

    let mut panel = InferPanel::new(Arc::new(DaemonInfer(backend)), rt.handle().clone());
    panel.refresh();
    let deadline = Instant::now() + Duration::from_secs(20);
    let step = |panel: &mut InferPanel, what: &str, f: &dyn Fn(&InferPanel) -> bool| {
        loop {
            panel.poll();
            panel.tick(Instant::now() + Duration::from_secs(10));
            if f(panel) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    step(&mut panel, "the listing", &|p| p.loaded());
    assert_eq!(panel.selected.as_deref(), Some("fake"));

    let model = tmp.path().join("m.gguf");
    std::fs::write(&model, vec![0u8; 2048]).expect("model");
    panel.set_model_path(&model);
    panel.form.set_text("ready_after", "0.3");
    panel.start();
    step(&mut panel, "ready", &|p| p.is_ready());
    assert_eq!(infer.loaded_models(), 1);
    step(&mut panel, "logs", &|p| {
        p.logs.iter().any(|l| l.text.contains("listening on"))
    });
    assert!(panel.provider_config().is_some());

    panel.stop();
    step(&mut panel, "stopped", &|p| {
        !p.is_busy() && p.status.phase == "stopped"
    });
    assert_eq!(infer.loaded_models(), 0);

    daemon.shutdown();
    rt.block_on(async { tokio::time::timeout(Duration::from_secs(10), daemon.wait()).await })
        .expect("daemon stops");
}

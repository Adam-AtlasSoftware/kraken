//! Holds, grace, fit and autostart against the fake inference server standing in for
//! `llama-server` (a real child process on 127.0.0.1).

use std::sync::Arc;
use std::time::Duration;

use kraken_infer::testing::fake_server_path;
use kraken_ipc::ManualClock;
use kraken_proto::infer::{DeviceInfo, DeviceRef, DeviceState, GpuVendor, ModelState};

use super::*;
use kraken_infer::port::pick_free_port;
use kraken_infer::{ManagedProcess, ProcessSpec, RunningBackend};
use serving::install_respawned;

const MIB_: u64 = 1024 * 1024;

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-host-serving")
        .tempdir()
        .expect("tempdir")
}

/// A model file that claims `bytes` without using the disk.
fn sparse(dir: &Path, name: &str, bytes: u64) -> PathBuf {
    let p = dir.join(name);
    let f = std::fs::File::create(&p).expect("model file");
    f.set_len(bytes).expect("size");
    p
}

fn model(id: &str, path: PathBuf, cpu_only: bool) -> LocalModel {
    LocalModel {
        id: id.into(),
        name: format!("Model {id}"),
        engine: LocalEngine::Llama,
        model_path: path,
        devices: Vec::new(),
        cpu_only,
        multi_gpu: MultiGpuMode::Split,
        shares: None,
        main_device: None,
        context_size: Some(4096),
        autostart: true,
        extra: None,
    }
}

fn card(free: u64) -> DeviceInfo {
    DeviceInfo {
        index: 0,
        uuid: "GPU-test".into(),
        vendor: GpuVendor::Nvidia,
        name: "Test card".into(),
        vram_total: free,
        vram_used: 0,
        state: DeviceState::Ok,
    }
}

fn manager(models: Vec<LocalModel>, roles: Vec<&str>, clock: &ManualClock) -> Arc<InferManager> {
    manager_with(models, roles, clock, fake_server_path(), Vec::new())
}

fn manager_with(
    models: Vec<LocalModel>,
    roles: Vec<&str>,
    clock: &ManualClock,
    binary: PathBuf,
    devices: Vec<DeviceInfo>,
) -> Arc<InferManager> {
    let cfg = ServingConfig {
        models,
        roles: roles.into_iter().map(str::to_string).collect(),
        serving: crate::config::LocalServingSettings::default(),
    };
    let m = InferManager::with_registry(BackendRegistry::new())
        .with_total_memory(8 * GIB, None)
        .with_serving_config(cfg)
        .with_llama_binary(binary)
        .with_devices(move || devices.clone());
    m.set_clock(Arc::new(clock.clone()));
    Arc::new(m)
}

async fn wait_state(m: &InferManager, id: &str, want: fn(&ModelState) -> bool) -> ModelStatus {
    for _ in 0..400 {
        let s = m.model_status(id);
        if want(&s.state) {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!(
        "{id} never reached the state; last {:?}",
        m.model_status(id)
    );
}

async fn ready(m: &InferManager, id: &str) -> ModelStatus {
    wait_state(m, id, |s| *s == ModelState::Ready).await
}

#[tokio::test]
async fn the_last_hold_starts_the_grace_period_and_a_new_hold_cancels_it() {
    let t = tmp();
    let clock = ManualClock::new();
    let m = manager(
        vec![model("a", sparse(t.path(), "a.gguf", MIB_), true)],
        vec![],
        &clock,
    );
    let s = m
        .hold_model(Holder::Connection(1), "a", StartOptions::default())
        .await
        .expect("hold");
    assert_eq!(s.holders, 1);
    assert!(s.base_url.as_deref().is_some_and(|u| u.ends_with("/v1")));
    assert!(s.api_key.is_some(), "llama models get a per-run key");
    let s = ready(&m, "a").await;
    assert_eq!(m.loaded_models(), 1);
    assert!(s.stops_in_secs.is_none());

    assert!(m.release_model(Holder::Connection(1), "a").await.released);
    let s = m.model_status("a");
    assert_eq!(s.holders, 0);
    assert_eq!(s.stops_in_secs, Some(120));
    clock.advance(Duration::from_secs(119));
    m.tick().await;
    assert!(m.model_status("a").is_ready(), "still in its grace period");

    // A new hold cancels the stop.
    m.hold_model(Holder::Connection(2), "a", StartOptions::default())
        .await
        .expect("hold again");
    clock.advance(Duration::from_secs(10));
    m.tick().await;
    let s = m.model_status("a");
    assert!(s.is_ready() && s.stops_in_secs.is_none(), "{s:?}");

    m.release_model(Holder::Connection(2), "a").await;
    clock.advance(Duration::from_secs(120));
    m.tick().await;
    assert_eq!(m.model_status("a").state, ModelState::Stopped);
    assert_eq!(m.loaded_models(), 0);
}

#[tokio::test]
async fn two_holders_keep_it_until_both_are_gone_and_pinned_survives_disconnects() {
    let t = tmp();
    let clock = ManualClock::new();
    let m = manager(
        vec![model("a", sparse(t.path(), "a.gguf", MIB_), true)],
        vec![],
        &clock,
    );
    let port = m
        .hold_model(Holder::Connection(1), "a", StartOptions::default())
        .await
        .expect("first")
        .port;
    let second = m
        .hold_model(Holder::Connection(2), "a", StartOptions::default())
        .await
        .expect("second");
    assert_eq!(
        second.port, port,
        "the second hold shares the running model"
    );
    assert_eq!(second.holders, 2);

    m.release_connection(1);
    assert_eq!(m.model_status("a").holders, 1);
    assert!(m.model_status("a").stops_in_secs.is_none());

    // A manual start: a hold no disconnect removes.
    let s = m
        .pin_model("a", StartOptions::default())
        .await
        .expect("pin");
    assert!(s.pinned);
    m.release_connection(2);
    let s = m.model_status("a");
    assert!(
        s.pinned && s.holders == 0 && s.stops_in_secs.is_none(),
        "{s:?}"
    );
    clock.advance(Duration::from_secs(3600));
    m.tick().await;
    assert!(m.model_status("a").is_running());

    assert!(m.stop_model("a").await);
    let s = m.model_status("a");
    assert_eq!(s.state, ModelState::Stopped);
    assert!(!s.pinned);
}

#[tokio::test]
async fn several_models_run_at_once_on_their_own_ports_and_keys() {
    let t = tmp();
    let clock = ManualClock::new();
    let m = manager(
        vec![
            model("a", sparse(t.path(), "a.gguf", MIB_), true),
            model("b", sparse(t.path(), "b.gguf", MIB_), true),
        ],
        vec!["b"],
        &clock,
    );
    let a = m
        .hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect("a");
    let b = m
        .hold_model(Holder::Owner, "b", StartOptions::default())
        .await
        .expect("b");
    assert_ne!(a.port, b.port);
    assert_ne!(a.api_key, b.api_key);
    ready(&m, "a").await;
    ready(&m, "b").await;
    assert_eq!(m.loaded_models(), 2);
    // The old single-model status reports the role's model.
    let legacy = m.status().await.expect("status");
    assert_eq!(legacy.base_url, b.base_url);
    let all = m.model_statuses();
    assert_eq!(
        all.models.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    assert!(all.models[1].role_assigned);
    m.shutdown().await;
    assert_eq!(m.loaded_models(), 0);
}

#[tokio::test]
async fn autostart_puts_role_models_first_and_skips_what_does_not_fit() {
    let t = tmp();
    let clock = ManualClock::new();
    let devices = vec![card(12 * GIB)];
    let m = manager_with(
        vec![
            model("small", sparse(t.path(), "s.gguf", 2 * GIB), false),
            model("huge", sparse(t.path(), "h.gguf", 20 * GIB), false),
            model("tiny", sparse(t.path(), "t.gguf", GIB), false),
        ],
        vec!["tiny", "huge"],
        &clock,
        fake_server_path(),
        devices,
    );
    let r = m.autostart_for(Holder::Connection(7)).await;
    assert_eq!(r.started, ["tiny", "small"]);
    assert_eq!(r.skipped.len(), 1);
    assert_eq!(r.skipped[0].model, "huge");
    assert_eq!(r.skipped[0].kind, "no_fit");
    let huge = m.model_status("huge");
    assert_eq!(huge.state, ModelState::Stopped);
    assert!(
        huge.notice
            .as_deref()
            .is_some_and(|n| n.contains("Not started")),
        "{huge:?}"
    );
    let tiny = m.model_status("tiny");
    assert_eq!(tiny.holders, 1);
    assert_eq!(tiny.devices.len(), 1, "runs on the card");
    m.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn a_loading_model_reserves_its_memory_and_no_fit_offers_the_choices() {
    use std::os::unix::fs::PermissionsExt;
    let t = tmp();
    // The fake server, slow to load.
    let script = t.path().join("slow-llama");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nexec '{}' --ready-after 30 \"$@\"\n",
            fake_server_path().display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let clock = ManualClock::new();
    let m = manager_with(
        vec![
            model("a", sparse(t.path(), "a.gguf", 6 * GIB), false),
            model("b", sparse(t.path(), "b.gguf", 6 * GIB), false),
        ],
        vec![],
        &clock,
        script,
        vec![card(12 * GIB)],
    );
    m.hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect("a fits alone");
    assert_eq!(m.model_status("a").state, ModelState::Loading);

    let e = m
        .hold_model(Holder::Owner, "b", StartOptions::default())
        .await
        .expect_err("a's memory is spoken for while it loads");
    assert_eq!(e.code, ErrorCode::Unsupported);
    let d = e.details.expect("details");
    assert_eq!(d["reason"], "no_fit");
    let kinds: Vec<&str> = d["choices"]
        .as_array()
        .expect("choices")
        .iter()
        .filter_map(|c| c["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["stop_model", "cpu", "start_anyway"]);
    assert_eq!(d["choices"][0]["model"], "a");
    assert!(e.message.contains("stop another model"), "{}", e.message);
    assert_eq!(m.model_status("b").state, ModelState::Stopped);

    let forced = m
        .hold_model(
            Holder::Owner,
            "b",
            StartOptions {
                force: true,
                cpu: false,
            },
        )
        .await
        .expect("start anyway");
    assert!(forced.warnings.iter().any(|w| w.contains("anyway")));
    m.shutdown().await;
}

#[tokio::test]
async fn a_card_that_is_gone_fails_the_model_with_a_message() {
    let t = tmp();
    let clock = ManualClock::new();
    let mut a = model("a", sparse(t.path(), "a.gguf", MIB_), false);
    a.devices = vec![DeviceRef {
        uuid: "GPU-gone".into(),
        index: 1,
        vendor: GpuVendor::Nvidia,
    }];
    let m = manager_with(vec![a], vec![], &clock, fake_server_path(), vec![card(GIB)]);
    let e = m
        .hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect_err("no card");
    assert!(
        e.message.contains("no longer in this computer"),
        "{}",
        e.message
    );
    match m.model_status("a").state {
        ModelState::Failed { message } => assert!(message.contains("no longer"), "{message}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(m.model_status("a").holders, 0);
    // Unknown ids are named.
    let e = m
        .hold_model(Holder::Owner, "zz", StartOptions::default())
        .await
        .expect_err("unknown");
    assert_eq!(e.code, ErrorCode::NotFound);
    assert!(e.message.contains("`zz`") && e.message.contains("a"));
}

#[tokio::test]
async fn the_serving_rpc_round_trips() {
    let t = tmp();
    let clock = ManualClock::new();
    let m = manager(
        vec![model("a", sparse(t.path(), "a.gguf", MIB_), true)],
        vec![],
        &clock,
    );
    let held = m.holder(Holder::Connection(3));
    let r = serve_serving_rpc(&held, METHOD_INFER_HOLD, json!({"model": "a"}))
        .await
        .expect("served")
        .expect("ok");
    assert_eq!(r["id"], "a");
    assert_eq!(r["holders"], 1);
    let r = serve_serving_rpc(&held, METHOD_INFER_MODELS, Value::Null)
        .await
        .expect("served")
        .expect("ok");
    assert_eq!(r["models"][0]["id"], "a");
    assert_eq!(r["grace_secs"], 120);
    let r = serve_serving_rpc(&held, METHOD_INFER_RELEASE, json!({"model": "a"}))
        .await
        .expect("served")
        .expect("ok");
    assert_eq!(r["released"], true);
    let e = serve_serving_rpc(&held, METHOD_INFER_HOLD, json!({}))
        .await
        .expect("served")
        .expect_err("no model");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(
        serve_serving_rpc(&held, "infer_nothing", Value::Null)
            .await
            .is_none()
    );
    m.shutdown().await;
}

#[test]
fn roles_come_from_local_provider_tables() {
    let cfg = crate::KrakenConfig {
        provider: Some(json!({"kind": "local", "model": "q"})),
        rewrite: Some(json!({"kind": "local", "model": "r"})),
        local_models: vec![
            model("r", PathBuf::new(), false),
            model("x", PathBuf::new(), false),
            model("q", PathBuf::new(), false),
        ],
        ..Default::default()
    };
    let s = ServingConfig::from_config(&cfg);
    assert_eq!(s.roles, ["q", "r"]);
    let cloud = crate::KrakenConfig {
        provider: Some(json!({"kind": "anthropic", "model": "q"})),
        ..Default::default()
    };
    assert!(ServingConfig::from_config(&cloud).roles.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn a_model_that_keeps_crashing_fails_for_good() {
    use std::os::unix::fs::PermissionsExt;
    let t = tmp();
    let script = t.path().join("crashing-llama");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nexec '{}' --crash-after 0.05 \"$@\"\n",
            fake_server_path().display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let clock = ManualClock::new();
    let m = manager_with(
        vec![model("a", sparse(t.path(), "a.gguf", MIB_), true)],
        vec![],
        &clock,
        script,
        Vec::new(),
    );
    m.hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect("spawned");
    let s = wait_state(&m, "a", |s| matches!(s, ModelState::Failed { .. })).await;
    let ModelState::Failed { message } = &s.state else {
        unreachable!()
    };
    assert!(message.contains("not restarted again"), "{message}");
    assert_eq!(m.loaded_models(), 0);
    let restarts = s.restarts;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(m.model_status("a").restarts, restarts, "no endless restart");
    // The old status reports the failure too.
    assert!(m.status().await.expect("status").is_failed());
}

#[tokio::test]
async fn strata_runs_from_its_manifest_on_the_picked_port_with_the_card_overrides() {
    let t = tmp();
    let install = t.path().join("strata");
    std::fs::create_dir_all(install.join("serve")).expect("install dir");
    let manifest = t.path().join("backend.toml");
    std::fs::write(
        &manifest,
        kraken_infer::strata::backend_manifest_text(
            &fake_server_path().display().to_string(),
            &install.display().to_string(),
            "/nowhere/strata-x.json",
        ),
    )
    .expect("manifest");
    let weights = t.path().join("weights");
    std::fs::create_dir_all(&weights).expect("weights");
    sparse(&weights, "part1.gguf", GIB);
    let mut a = model("s", weights, false);
    a.engine = LocalEngine::Strata;
    let clock = ManualClock::new();
    let m = InferManager::with_registry(BackendRegistry::new())
        .with_total_memory(8 * GIB, None)
        .with_serving_config(ServingConfig {
            models: vec![a],
            ..Default::default()
        })
        .with_strata_manifest(manifest)
        .with_devices(|| vec![card(24 * GIB)]);
    m.set_clock(Arc::new(clock));
    let s = m
        .hold_model(Holder::Owner, "s", StartOptions::default())
        .await
        .expect("start");
    let port = s.port.expect("port");
    let ready = wait_state(&m, "s", |s| *s == ModelState::Ready).await;
    assert_eq!(ready.port, Some(port));
    let logs = m.model_logs(&ModelLogsParams {
        model: "s".into(),
        ..Default::default()
    });
    let spawn = &logs.lines[0].text;
    assert!(
        spawn.contains(&format!("--port {port}")) && spawn.ends_with("--gpu 0 --replicas 1"),
        "{spawn}"
    );
    // On the processor Strata cannot run.
    m.stop_model("s").await;
    let e = m
        .hold_model(
            Holder::Owner,
            "s",
            StartOptions {
                force: false,
                cpu: true,
            },
        )
        .await
        .expect_err("cpu");
    assert_eq!(e.code, ErrorCode::Unsupported);
}

fn fake_process() -> RunningBackend {
    let port = pick_free_port().expect("port");
    let mut spec = ProcessSpec::new(fake_server_path(), port, "/health");
    spec.args = vec!["--port".into(), port.to_string()];
    spec.health.interval = Duration::from_millis(50);
    spec.grace = Duration::from_millis(300);
    RunningBackend::new(
        LLAMA_ID,
        None,
        ManagedProcess::start(spec).expect("fake server"),
    )
}

#[tokio::test]
async fn a_stop_during_the_port_retry_stops_the_new_process_too() {
    let old = fake_process();
    let slot = Slot::new_manual(LLAMA_ID, old, Vec::new());
    // The watcher stopped the old process for the retry; the stop arrives before the swap.
    slot.run().stop().await;
    slot.stopping
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let new = fake_process();
    assert!(
        !install_respawned(&slot, new),
        "a stopping slot keeps nothing running"
    );
    for _ in 0..400 {
        if slot.state() == ModelState::Stopped {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(slot.state(), ModelState::Stopped);
    assert!(!slot.live());

    // Not stopping: the new process is kept.
    let slot = Slot::new_manual(LLAMA_ID, fake_process(), Vec::new());
    slot.run().stop().await;
    let new = fake_process();
    let port = new.port();
    assert!(install_respawned(&slot, new));
    assert_eq!(slot.run().port(), port);
    assert!(slot.live());
    slot.stop().await;
}

#[tokio::test]
async fn a_vulkan_build_is_told_its_card_by_name_not_by_cuda_variables() {
    let t = tmp();
    // The installed llama.cpp is the Vulkan build.
    let data = t.path().join("data");
    std::fs::create_dir_all(data.join("llama")).expect("llama dir");
    std::fs::write(
        data.join("llama/current.json"),
        serde_json::to_string(&json!({
            "tag": crate::llama_setup::LLAMA_TAG,
            "variant": "vulkan",
            "binary": fake_server_path(),
        }))
        .expect("json"),
    )
    .expect("current.json");
    let cfg = ServingConfig {
        models: vec![model("a", sparse(t.path(), "a.gguf", MIB_), false)],
        roles: Vec::new(),
        serving: crate::config::LocalServingSettings::default(),
    };
    let make = |listed: Vec<kraken_infer::hardware::LlamaDevice>| {
        let cfg = cfg.clone();
        Arc::new(
            InferManager::with_registry(BackendRegistry::new())
                .with_total_memory(8 * GIB, None)
                .with_serving_config(cfg)
                .with_llama_layout(crate::llama_setup::LlamaLayout::in_data_dir(&data))
                .with_llama_binary(fake_server_path())
                .with_devices(|| vec![card(8 * GIB)])
                .with_llama_devices(move |_| listed.clone()),
        )
    };
    let vk = |id: &str, name: &str| kraken_infer::hardware::LlamaDevice {
        id: id.into(),
        name: name.into(),
        total: GIB,
        free: GIB,
    };
    let m = make(vec![
        vk("Vulkan0", "AMD Radeon Graphics"),
        vk("Vulkan1", "Test card"),
    ]);
    m.hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect("starts");
    let logs = m.model_logs(&ModelLogsParams {
        model: "a".into(),
        after_seq: None,
        limit: None,
    });
    let spawn = logs
        .lines
        .iter()
        .find(|l| l.text.starts_with("spawning"))
        .expect("spawn line");
    assert!(spawn.text.contains("--device Vulkan1"), "{}", spawn.text);
    m.shutdown().await;

    // A card llama.cpp does not list by that name is refused, not guessed.
    let m = make(vec![vk("Vulkan0", "AMD Radeon Graphics")]);
    let e = m
        .hold_model(Holder::Owner, "a", StartOptions::default())
        .await
        .expect_err("cannot tell the card");
    assert!(e.message.contains("Vulkan"), "{}", e.message);
    assert_eq!(m.loaded_models(), 0);
}

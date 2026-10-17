//! The settings form generated from schemas, and the panel against a scripted service and
//! against a real manager running the fake inference server.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_host::infer::{
    InferApi, InferListReply, InferManager, LlamaInfo, LogEntry, LogsParams, LogsReply, MemoryInfo,
    PlatformInfo, StartReply, StatusReply, StopReply,
};
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{
    BackendCapabilities, BackendRegistry, GenericOpenAiServerBackend, GpuApi, InferenceBackend,
    LlamaServerBackend,
};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};

use super::*;

const GIB: u64 = 1024 * 1024 * 1024;

// ---- the form --------------------------------------------------------------------------

#[test]
fn the_llama_schema_becomes_a_form() {
    let schema = LlamaServerBackend::new().settings_schema();
    let form = SettingsForm::from_schema(&schema);
    assert_eq!(form.title.as_deref(), Some("llama.cpp server"));
    // Required first, then paths, then the rest by title.
    let keys: Vec<&str> = form.fields.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys[0], "model_path");
    assert_eq!(keys[1], "binary_path");
    assert!(form.field("model_path").unwrap().required);
    assert_eq!(form.field("model_path").unwrap().kind, FieldKind::Path);
    assert_eq!(form.model_key(), Some("model_path"));

    let ctx = form.field("context_size").unwrap();
    assert_eq!(
        ctx.kind,
        FieldKind::Integer {
            min: Some(1),
            max: None
        }
    );
    assert_eq!(ctx.text, "8192", "the default is pre-filled");
    let port = form.field("port").unwrap();
    assert_eq!(
        port.kind,
        FieldKind::Integer {
            min: Some(1),
            max: Some(65535)
        }
    );
    assert!(port.text.is_empty());
    let jinja = form.field("jinja").unwrap();
    assert_eq!(jinja.kind, FieldKind::Bool);
    assert!(jinja.flag, "default true");
    assert!(
        form.field("n_cpu_moe")
            .unwrap()
            .description
            .as_deref()
            .unwrap()
            .contains("MoE")
    );
    assert_eq!(form.field("gpu_layers").unwrap().title, "GPU layers (-ngl)");
}

#[test]
fn every_field_kind_is_generated_and_validated() {
    let schema = json!({
        "type": "object",
        "required": ["weights"],
        "properties": {
            "weights": {"type": "string", "x-kraken-widget": "file-path"},
            "threads": {"type": "integer", "minimum": 1, "maximum": 64},
            "temperature": {"type": "number", "minimum": 0, "maximum": 2},
            "flash_attn": {"type": "boolean", "default": false},
            "mode": {"type": "string", "enum": ["fast", "small"], "default": "fast"},
            "label": {"type": "string"},
            "extra": {"type": "array"}
        }
    });
    let mut form = SettingsForm::from_schema(&schema);
    assert_eq!(
        form.field("weights").unwrap().title,
        "Weights",
        "title from the key"
    );
    assert_eq!(
        form.field("mode").unwrap().kind,
        FieldKind::Enum(vec!["fast".into(), "small".into()])
    );
    assert_eq!(form.field("extra").unwrap().kind, FieldKind::Json);
    assert_eq!(form.field("label").unwrap().kind, FieldKind::Text);

    // Required and empty.
    let problems = form.to_settings().unwrap_err();
    assert_eq!(problems, ["Weights is required"]);
    assert!(form.errors().contains_key("weights"));

    form.set_text("weights", "/m/a.gguf");
    // Defaults the person did not change are still sent when they are text (pre-filled), but an
    // untouched checkbox is left to the engine.
    let v = form.to_settings().unwrap();
    assert_eq!(v, json!({"weights": "/m/a.gguf", "mode": "fast"}));

    form.set_text("threads", "8");
    form.set_text("temperature", "0.7");
    form.set_flag("flash_attn", true);
    form.set_text("mode", "small");
    form.set_text("label", "  hello ");
    form.set_text("extra", "[1, 2]");
    assert_eq!(
        form.to_settings().unwrap(),
        json!({
            "weights": "/m/a.gguf", "threads": 8, "temperature": 0.7, "flash_attn": true,
            "mode": "small", "label": "hello", "extra": [1, 2]
        })
    );

    for (key, text, needle) in [
        ("threads", "many", "whole number"),
        ("threads", "0", "at least 1"),
        ("threads", "65", "at most 64"),
        ("temperature", "hot", "number"),
        ("temperature", "-1", "at least 0"),
        ("mode", "huge", "one of: fast, small"),
        ("extra", "[", "JSON"),
    ] {
        let mut f = form.clone();
        f.set_text(key, text);
        let e = f.to_settings().unwrap_err().join("; ");
        assert!(e.contains(needle), "{key}={text}: {e}");
        assert!(f.errors().contains_key(key));
    }

    // Emptying an optional field leaves it out.
    let mut f = form.clone();
    f.set_text("threads", "");
    assert!(f.to_settings().unwrap().get("threads").is_none());
    // A checkbox switched back to the default is still an explicit choice.
    f.set_flag("flash_attn", false);
    assert_eq!(f.to_settings().unwrap()["flash_attn"], false);
}

#[test]
fn a_manifest_schema_needs_no_gui_code() {
    let b = GenericOpenAiServerBackend::from_manifest_str(&fake_manifest(
        "my-engine",
        &PathBuf::from("/bin/true"),
    ))
    .unwrap();
    let mut form = SettingsForm::from_schema(&b.settings_schema());
    let keys: Vec<&str> = form.fields.iter().map(|f| f.key.as_str()).collect();
    assert_eq!(keys[0], "model");
    for k in ["ready_after", "ctx", "flash", "mode"] {
        assert!(keys.contains(&k), "{keys:?}");
    }
    form.set_text("model", "/m/x.gguf");
    let v = form.to_settings().unwrap();
    assert_eq!(v["model"], "/m/x.gguf");
    assert_eq!(v["ctx"], 4096);
    assert_eq!(v["mode"], "fast");
    assert_eq!(form.number("ctx"), Some(4096.0));
}

#[test]
fn an_empty_or_missing_schema_gives_an_empty_form() {
    assert!(SettingsForm::from_schema(&json!({})).fields.is_empty());
    assert!(
        SettingsForm::from_schema(&json!({"type": "object", "properties": {}}))
            .to_settings()
            .unwrap()
            == json!({})
    );
}

// ---- the panel -------------------------------------------------------------------------

fn caps(tools: bool) -> BackendCapabilities {
    BackendCapabilities {
        os: vec![std::env::consts::OS.into()],
        arch: vec![std::env::consts::ARCH.into()],
        gpu_apis: vec![GpuApi::Cpu],
        min_ram: 0,
        supports_moe_offload: true,
        supports_tool_calls: tools,
        license: "MIT".into(),
        detected_version: None,
    }
}

fn info(id: &str, installed: Option<bool>) -> kraken_host::infer::BackendInfo {
    kraken_host::infer::BackendInfo {
        id: id.into(),
        display_name: format!("{id} engine"),
        capabilities: caps(id == "llama-server"),
        settings_schema: LlamaServerBackend::new().settings_schema(),
        builtin: true,
        installed,
        setup_hint: (installed == Some(false)).then(|| "Run `kraken infer setup llama`".into()),
    }
}

fn listing(total: u64, ghidra: u64) -> InferListReply {
    InferListReply {
        platform: PlatformInfo {
            os: "linux".into(),
            arch: "x86_64".into(),
        },
        backends: vec![info("llama-server", Some(true)), info("other", None)],
        memory: MemoryInfo {
            total_ram: total,
            ghidra_reserved: ghidra,
            available_ram: total.saturating_sub(ghidra),
        },
        llama: LlamaInfo {
            pinned_tag: "b1".into(),
            variants: vec!["cpu".into()],
            installed: None,
        },
        manifests_dir: None,
        warnings: Vec::new(),
    }
}

struct Script {
    list: InferListReply,
    started: Vec<(String, Value)>,
    status: StatusReply,
    start_error: Option<ProtoError>,
    stops: u32,
    log_lines: Vec<LogEntry>,
}

struct FakeApi(Mutex<Script>);

fn status(phase: &str, fraction: Option<f32>) -> StatusReply {
    StatusReply {
        running: !matches!(phase, "none" | "stopped" | "failed"),
        phase: phase.into(),
        backend: Some("llama-server".into()),
        model: Some("tiny.gguf".into()),
        base_url: Some("http://127.0.0.1:9/v1".into()),
        fraction,
        message: format!("{phase} now"),
        restarts: 0,
        pid: Some(7),
        uptime_secs: Some(1),
        api_key: Some("run-key".into()),
    }
}

#[async_trait]
impl InferApi for FakeApi {
    async fn list(&self) -> Result<InferListReply, ProtoError> {
        Ok(self.0.lock().unwrap().list.clone())
    }

    async fn start(&self, backend: &str, settings: Value) -> Result<StartReply, ProtoError> {
        let mut s = self.0.lock().unwrap();
        if let Some(e) = s.start_error.clone() {
            return Err(e);
        }
        s.started.push((backend.into(), settings));
        s.status = status("loading", Some(0.25));
        Ok(StartReply {
            backend: backend.into(),
            base_url: "http://127.0.0.1:9/v1".into(),
            model: Some("tiny.gguf".into()),
            port: 9,
            pid: Some(7),
            api_key: Some("run-key".into()),
            warnings: vec!["RAM is tight".into()],
        })
    }

    async fn status(&self) -> Result<StatusReply, ProtoError> {
        Ok(self.0.lock().unwrap().status.clone())
    }

    async fn stop(&self) -> Result<StopReply, ProtoError> {
        let mut s = self.0.lock().unwrap();
        s.stops += 1;
        s.status = status("stopped", None);
        Ok(StopReply { stopped: true })
    }

    async fn logs(&self, p: LogsParams) -> Result<LogsReply, ProtoError> {
        let s = self.0.lock().unwrap();
        let after = p.after_seq.unwrap_or(0);
        let lines: Vec<LogEntry> = s
            .log_lines
            .iter()
            .filter(|l| p.after_seq.is_none() || l.seq > after)
            .cloned()
            .collect();
        Ok(LogsReply {
            last_seq: s.log_lines.last().map_or(0, |l| l.seq),
            lines,
        })
    }
}

fn script(total: u64, ghidra: u64) -> Arc<FakeApi> {
    Arc::new(FakeApi(Mutex::new(Script {
        list: listing(total, ghidra),
        started: Vec::new(),
        status: status("none", None),
        start_error: None,
        stops: 0,
        log_lines: vec![
            LogEntry {
                seq: 1,
                stream: "stdout".into(),
                text: "loading tensors".into(),
            },
            LogEntry {
                seq: 2,
                stream: "stderr".into(),
                text: "offloaded 3/33 layers".into(),
            },
        ],
    })))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn wait(panel: &mut InferPanel, what: &str, mut f: impl FnMut(&mut InferPanel) -> bool) {
    let start = Instant::now();
    loop {
        panel.poll();
        if f(panel) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out: {what}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn model_file(dir: &std::path::Path, bytes: usize) -> PathBuf {
    let p = dir.join("tiny.gguf");
    std::fs::write(&p, vec![0u8; bytes]).unwrap();
    p
}

#[test]
fn the_panel_lists_selects_starts_follows_and_stops() {
    let rt = runtime();
    let api = script(32 * GIB, 0);
    let mut p = InferPanel::new(api.clone(), rt.handle().clone());
    assert!(!p.loaded() && !p.can_start());
    p.refresh();
    wait(&mut p, "the listing", |p| p.loaded());
    assert_eq!(
        p.selected.as_deref(),
        Some("llama-server"),
        "first engine chosen"
    );
    assert!(p.form.field("model_path").is_some());
    assert!(p.can_start());

    // Missing model: nothing is sent, the problem is explained.
    p.start();
    assert!(
        p.error.as_deref().unwrap().contains("Model file"),
        "{:?}",
        p.error
    );
    assert!(api.0.lock().unwrap().started.is_empty());

    let t = tempfile::tempdir().unwrap();
    p.set_model_path(&model_file(t.path(), 1024));
    p.form.set_text("gpu_layers", "99");
    p.start();
    assert!(p.is_busy() && p.phase_text() == "Starting...");
    wait(&mut p, "start answered", |p| !p.is_busy());
    assert!(p.error.is_none(), "{:?}", p.error);
    assert_eq!(p.warnings, ["RAM is tight"]);
    {
        let s = api.0.lock().unwrap();
        assert_eq!(s.started.len(), 1);
        assert_eq!(s.started[0].0, "llama-server");
        assert_eq!(s.started[0].1["gpu_layers"], 99);
        assert_eq!(s.started[0].1["context_size"], 8192);
        assert!(
            s.started[0].1["model_path"]
                .as_str()
                .unwrap()
                .ends_with("tiny.gguf")
        );
    }
    assert!(p.is_running() && !p.can_start());

    // Progress and logs arrive through ticks.
    p.tick(Instant::now());
    wait(&mut p, "status and logs", |p| {
        p.status.phase == "loading" && p.logs.len() == 2
    });
    assert_eq!(p.progress(), Some(0.25));
    assert_eq!(p.phase_text(), "Loading tiny.gguf: 25%");
    assert!(p.provider_config().is_none(), "not ready yet");
    // Polling is rate limited.
    let calls_before = p.logs.len();
    p.tick(Instant::now());
    assert_eq!(p.logs.len(), calls_before);

    api.0.lock().unwrap().status = status("ready", None);
    p.tick(Instant::now() + Duration::from_secs(5));
    wait(&mut p, "ready", |p| p.is_ready());
    assert_eq!(p.phase_text(), "tiny.gguf is running and ready.");
    assert!(p.progress().is_none());
    match p.provider_config().expect("provider") {
        kraken_agent::ProviderConfig::OpenaiCompatible {
            base_url,
            model,
            supports_tools,
            context_window,
            api_key,
        } => {
            assert_eq!(p.api_key(), Some("run-key"));
            assert_eq!(
                api_key,
                Some(kraken_agent::SecretRef::Keyring {
                    service: crate::assist::SECRETS_SERVICE.into(),
                    account: LOCAL_INFER_ACCOUNT.into(),
                }),
                "the key is referenced, never embedded in the config"
            );
            assert_eq!(base_url, "http://127.0.0.1:9/v1");
            assert_eq!(model, "tiny.gguf");
            assert!(supports_tools, "llama-server calls tools");
            assert_eq!(context_window, Some(8192));
        }
        other => panic!("unexpected provider {other:?}"),
    }

    p.stop();
    wait(&mut p, "stop answered", |p| !p.is_busy());
    p.tick(Instant::now() + Duration::from_secs(60));
    wait(&mut p, "stopped", |p| p.status.phase == "stopped");
    assert!(!p.is_running() && p.can_start());
    assert_eq!(api.0.lock().unwrap().stops, 1);
    assert_eq!(p.phase_text(), "Stopped.");
}

#[test]
fn errors_from_the_service_are_shown_as_they_are() {
    let rt = runtime();
    let api = script(32 * GIB, 0);
    api.0.lock().unwrap().start_error = Some(ProtoError::new(
        ErrorCode::Unsupported,
        "there is not enough memory to load this model",
    ));
    let mut p = InferPanel::new(api.clone(), rt.handle().clone());
    p.refresh();
    wait(&mut p, "the listing", |p| p.loaded());
    let t = tempfile::tempdir().unwrap();
    p.set_model_path(&model_file(t.path(), 16));
    p.start();
    wait(&mut p, "error", |p| p.error.is_some());
    assert!(p.error.as_deref().unwrap().contains("not enough memory"));
    assert!(!p.is_running() && p.can_start());

    // A model that dies while running is reported once, with the log opened.
    api.0.lock().unwrap().start_error = None;
    p.start();
    wait(&mut p, "running", |p| p.is_running());
    assert!(p.error.is_none());
    api.0.lock().unwrap().status = status("failed", None);
    p.tick(Instant::now() + Duration::from_secs(5));
    wait(&mut p, "failure noticed", |p| p.status.phase == "failed");
    assert!(
        p.error.as_deref().unwrap().contains("stopped working"),
        "{:?}",
        p.error
    );
    assert!(p.show_logs);
    assert!(p.can_start());
}

#[test]
fn switching_engines_keeps_what_was_typed_and_a_relist_keeps_the_choice() {
    let rt = runtime();
    let api = script(32 * GIB, 0);
    let mut p = InferPanel::new(api, rt.handle().clone());
    p.refresh();
    wait(&mut p, "the listing", |p| p.loaded());
    p.form.set_text("threads", "12");
    p.select("other");
    assert_eq!(p.selected.as_deref(), Some("other"));
    assert_eq!(p.form.field("threads").unwrap().text, "");
    p.form.set_text("threads", "3");
    p.select("llama-server");
    assert_eq!(p.form.field("threads").unwrap().text, "12");
    p.select("does-not-exist");
    assert_eq!(p.selected.as_deref(), Some("llama-server"));

    p.refresh();
    wait(&mut p, "relist", |p| !p.is_refreshing());
    assert_eq!(p.selected.as_deref(), Some("llama-server"));
    assert_eq!(p.form.field("threads").unwrap().text, "12");
}

#[test]
fn the_install_hint_shows_only_when_the_engine_is_missing() {
    let rt = runtime();
    let api = script(32 * GIB, 0);
    api.0.lock().unwrap().list.backends[0] = info("llama-server", Some(false));
    let mut p = InferPanel::new(api, rt.handle().clone());
    p.refresh();
    wait(&mut p, "the listing", |p| p.loaded());
    assert!(
        p.install_hint()
            .unwrap()
            .contains("kraken infer setup llama")
    );
    p.select("other");
    assert!(p.install_hint().is_none());
}

#[test]
fn the_memory_hint_follows_the_budget() {
    let rt = runtime();
    let t = tempfile::tempdir().unwrap();
    // Sparse file: the size counts, the disk does not.
    let big = t.path().join("big.gguf");
    let f = std::fs::File::create(&big).unwrap();
    f.set_len(10 * GIB).unwrap();

    let hint = |total: u64, ghidra: u64, extra: &[(&str, &str)]| {
        let api = script(total, ghidra);
        let mut p = InferPanel::new(api, rt.handle().clone());
        p.refresh();
        wait(&mut p, "the listing", |p| p.loaded());
        assert!(p.memory_hint().is_none(), "no file yet");
        p.set_model_path(&big);
        for (k, v) in extra {
            p.form.set_text(k, *v);
        }
        p.memory_hint().expect("hint")
    };

    let h = hint(64 * GIB, 0, &[]);
    assert_eq!(h.level, HintLevel::Info);
    assert!(h.text.contains("fits"), "{}", h.text);

    let h = hint(12 * GIB, 0, &[]);
    assert_eq!(h.level, HintLevel::Warn, "{}", h.text);
    assert!(h.text.contains("little is left"), "{}", h.text);

    let h = hint(12 * GIB, 4 * GIB, &[]);
    assert_eq!(h.level, HintLevel::Bad, "{}", h.text);
    assert!(h.text.contains("will not start it"), "{}", h.text);
    assert!(h.text.contains("held by open projects"), "{}", h.text);

    // Offloading to the GPU takes the weights out of the RAM estimate.
    let h = hint(12 * GIB, 4 * GIB, &[("gpu_layers", "99")]);
    assert_eq!(h.level, HintLevel::Info, "{}", h.text);
    assert!(h.text.contains("video memory"), "{}", h.text);
    // Unless the experts stay in RAM.
    let h = hint(
        12 * GIB,
        4 * GIB,
        &[("gpu_layers", "99"), ("n_cpu_moe", "30")],
    );
    assert_eq!(h.level, HintLevel::Bad, "{}", h.text);

    let h = hint(0, 0, &[]);
    assert!(h.text.contains("could not read"), "{}", h.text);
}

// ---- against a real manager ---------------------------------------------------------------

#[test]
fn the_panel_runs_the_fake_engine_through_a_real_manager() {
    let rt = runtime();
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(
        GenericOpenAiServerBackend::from_manifest_str(&fake_manifest("fake", &fake_server_path()))
            .unwrap(),
    ));
    let mgr = Arc::new(
        InferManager::with_registry(reg)
            .with_total_memory(8 * GIB, None)
            .with_manifest_ids(vec!["fake".into()]),
    );
    let mut p = InferPanel::new(mgr.clone(), rt.handle().clone());
    p.refresh();
    wait(&mut p, "the listing", |p| p.loaded());
    assert_eq!(p.selected.as_deref(), Some("fake"));
    assert!(!p.selected_backend().unwrap().builtin);

    let t = tempfile::tempdir().unwrap();
    p.set_model_path(&model_file(t.path(), 4096));
    p.form.set_text("ready_after", "0.5");
    p.form.set_flag("flash", false);
    p.start();
    wait(&mut p, "running", |p| p.is_running());
    let mut now = Instant::now();
    wait(&mut p, "ready", |p| {
        now += Duration::from_secs(2);
        p.tick(now);
        p.is_ready()
    });
    assert!(
        p.logs.iter().any(|l| l.text.contains("listening on")),
        "{:?}",
        p.logs
    );
    assert!(p.provider_config().is_some());
    p.stop();
    wait(&mut p, "stopped", |p| !p.is_busy() && !mgr_running(&mgr));
    assert_eq!(mgr.loaded_models(), 0);
}

fn mgr_running(m: &InferManager) -> bool {
    m.loaded_models() > 0
}

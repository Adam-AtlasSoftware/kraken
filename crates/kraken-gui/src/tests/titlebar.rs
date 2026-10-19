//! The title bar and the model chips, driven through the whole app with a fake serving service:
//! the chips for each state of a model, the narrow layout, the memory question raised from a
//! chip with Settings closed, the setting, and the system-bar layout. Dragging and resizing
//! need a real window and are checked by hand.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui_kittest::kittest::Queryable;
use kraken_host::{KrakenConfig, TitlebarMode};
use kraken_proto::infer::{
    DeviceInfo, DeviceRef, DeviceState, DeviceVram, GpuVendor, LocalEngine, LocalModel, ModelState,
    ModelStats, MultiGpuMode, TokSource,
};
use kraken_viewmodel::infer::fake::{FakeCall, FakeServing, stopped_status};
use kraken_viewmodel::{AnalysisPhase, Connection};

use super::options;
use super::shell::{Kit, kit_from, kit_sized};
use crate::services::Services;

fn card() -> DeviceInfo {
    DeviceInfo {
        index: 0,
        uuid: "GPU-0".into(),
        vendor: GpuVendor::Nvidia,
        name: "RTX 3070 Ti".into(),
        vram_total: 8 << 30,
        vram_used: 1 << 30,
        state: DeviceState::Ok,
    }
}

fn on_card() -> DeviceRef {
    DeviceRef {
        uuid: "GPU-0".into(),
        index: 0,
        vendor: GpuVendor::Nvidia,
    }
}

fn local(id: &str, name: &str) -> LocalModel {
    LocalModel {
        id: id.into(),
        name: name.into(),
        engine: LocalEngine::Llama,
        model_path: PathBuf::from(format!("/models/{id}.gguf")),
        devices: Vec::new(),
        cpu_only: false,
        multi_gpu: MultiGpuMode::Split,
        shares: None,
        main_device: None,
        context_size: None,
        autostart: false,
        extra: None,
    }
}

fn stats(id: &str, phase: ModelState, fraction: Option<f32>) -> ModelStats {
    ModelStats {
        model: id.into(),
        phase,
        load_fraction: fraction,
        vram_per_device: vec![DeviceVram {
            device: on_card(),
            bytes: 7_400_000_000,
        }],
        ram_bytes: 5_000_000_000,
        tok_s: Some(38.0),
        tok_s_source: Some(TokSource::Engine),
        devices: vec![on_card()],
    }
}

struct Rig {
    k: Kit,
    fake: Arc<FakeServing>,
    config: PathBuf,
    _dir: tempfile::TempDir,
}

/// `models` are `(id, name)`; all are role-assigned and not started by themselves.
fn rig(mode: TitlebarMode, models: &[(&str, &str)], size: [f32; 2], extra: &str) -> Rig {
    rig_gpu(mode, models, size, extra, false)
}

fn rig_gpu(
    mode: TitlebarMode,
    models: &[(&str, &str)],
    size: [f32; 2],
    extra: &str,
    gpu: bool,
) -> Rig {
    let dir = crate::testutil::tempdir();
    let config = dir.path().join("kraken/config.toml");
    let mut cfg = KrakenConfig {
        local_models: models.iter().map(|(i, n)| local(i, n)).collect(),
        ..KrakenConfig::default()
    };
    cfg.local_serving.titlebar = mode;
    cfg.save(&config).unwrap();
    if !extra.is_empty() {
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str(extra);
        std::fs::write(&config, text).unwrap();
    }
    let statuses = models
        .iter()
        .map(|(i, n)| {
            let mut s = stopped_status(i, n);
            s.autostart = false;
            s.role_assigned = true;
            s
        })
        .collect();
    let fake = Arc::new(FakeServing::new(statuses, vec![card()]));
    let mut services = Services::offline();
    services.cfg = KrakenConfig::from_file(&config).unwrap();
    services.config_path = Some(config.clone());
    services.serving = Some(fake.clone());
    let k = kit_sized(services, &options(false), gpu, size);
    Rig {
        k,
        fake,
        config,
        _dir: dir,
    }
}

impl Rig {
    fn until(&mut self, what: &str, mut cond: impl FnMut(&mut Kit) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.k.h.run_steps(2);
            if cond(&mut self.k) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(15));
        }
    }

    fn has(&mut self, text: &str) -> bool {
        self.k.h.query_all_by_label_contains(text).next().is_some()
    }

    fn ready(&self, id: &str) {
        self.fake.edit(id, |m| {
            m.state = ModelState::Ready;
            m.devices = vec![on_card()];
            m.port = Some(40123);
            m.stats = Some(stats(id, ModelState::Ready, None));
        });
    }
}

#[test]
fn the_custom_bar_has_the_logo_menus_and_window_buttons() {
    let mut r = rig(TitlebarMode::Custom, &[], [1280.0, 700.0], "");
    r.k.h.run_steps(4);
    for t in [
        "KRAKEN",
        "File",
        "Help",
        "Minimize window",
        "Maximize window",
        "Close window",
    ] {
        assert!(r.has(t), "the bar should have {t}");
    }
}

#[test]
fn the_system_bar_has_no_window_buttons() {
    let mut r = rig(TitlebarMode::System, &[], [1280.0, 700.0], "");
    r.k.h.run_steps(4);
    assert!(r.has("File"));
    assert!(!r.has("Close window"));
}

#[test]
fn a_ready_model_shows_its_figures_and_stop_stops_it() {
    let mut r = rig(
        TitlebarMode::Custom,
        &[("qwen", "Qwen Coder")],
        [1500.0, 700.0],
        "",
    );
    r.until("loaded", |k| k.h.query_by_label("Qwen Coder").is_some());
    r.ready("qwen");
    r.until("the figures", |k| k.h.query_by_label("38 tok/s").is_some());
    assert!(r.has("VRAM 6.9/8.0 GB"));
    assert!(r.has("RAM 4.7 GB"));
    r.k.h.get_by_label("Stop").click();
    r.until("stopped", |k| k.h.query_by_label("stopped").is_some());
    assert!(r.fake.calls().contains(&FakeCall::Stop("qwen".into())));
    assert!(r.has("Start"));
}

#[test]
fn a_measured_speed_says_about() {
    let mut r = rig(
        TitlebarMode::Custom,
        &[("qwen", "Qwen Coder")],
        [1500.0, 700.0],
        "",
    );
    r.until("loaded", |k| k.h.query_by_label("Qwen Coder").is_some());
    r.ready("qwen");
    r.fake.edit("qwen", |m| {
        m.stats.as_mut().unwrap().tok_s_source = Some(TokSource::Approx);
    });
    r.until("about", |k| k.h.query_by_label("about 38 tok/s").is_some());
}

#[test]
fn a_loading_model_shows_percent_card_and_memory() {
    let mut r = rig(
        TitlebarMode::Custom,
        &[("qwen", "Qwen Coder")],
        [1500.0, 700.0],
        "",
    );
    r.until("loaded", |k| k.h.query_by_label("Qwen Coder").is_some());
    r.fake.edit("qwen", |m| {
        m.state = ModelState::Loading;
        m.devices = vec![on_card()];
        m.load_fraction = Some(0.62);
        m.stats = Some(stats("qwen", ModelState::Loading, Some(0.62)));
    });
    r.until("loading", |k| k.h.query_by_label("loading 62%").is_some());
    assert!(r.has("on RTX 3070 Ti"));
    assert!(r.has("VRAM 6.9 GB"));
    assert!(r.has("Stop"));
    assert!(!r.has("tok/s"), "no speed before it is ready");
}

#[test]
fn a_stopped_model_offers_start_and_a_failed_one_says_why_on_hover() {
    let mut r = rig(
        TitlebarMode::Custom,
        &[("qwen", "Qwen Coder"), ("big", "Big Model")],
        [1500.0, 700.0],
        "",
    );
    r.fake.edit("big", |m| {
        m.state = ModelState::Failed {
            message: "The card is gone.".into(),
        };
    });
    r.until("both", |k| {
        k.h.query_all_by_label("stopped").count() == 1 && k.h.query_by_label("failed").is_some()
    });
    r.k.h.get_by_label("Start").click();
    r.until("started", |k| k.h.query_by_label("Stop").is_some());
    assert!(
        r.fake
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Start(id, _) if id == "qwen"))
    );
}

#[test]
fn the_memory_question_from_a_chip_shows_with_settings_closed() {
    let mut r = rig(
        TitlebarMode::Custom,
        &[("qwen", "Qwen Coder")],
        [1500.0, 800.0],
        "",
    );
    r.fake.refuse_start("qwen");
    r.until("a stopped chip", |k| k.h.query_by_label("Start").is_some());
    assert!(!r.k.h.state().settings().open);
    r.k.h.get_by_label("Start").click();
    r.until("the question", |k| {
        k.h.query_by_label_contains("Not enough memory").is_some()
    });
    assert!(!r.k.h.state().settings().open);
    r.k.h.get_by_label("Cancel").click();
    r.k.h.run_steps(3);
    assert!(!r.has("Not enough memory"));
}

#[test]
fn narrow_windows_keep_only_names_and_dots() {
    let models = [("a", "Alpha"), ("b", "Bravo"), ("c", "Charlie")];
    let mut r = rig(TitlebarMode::Custom, &models, [1500.0, 700.0], "");
    r.until("loaded", |k| k.h.query_by_label("Alpha").is_some());
    for (id, _) in models {
        r.ready(id);
    }
    r.until("wide", |k| k.h.query_all_by_label("38 tok/s").count() == 3);
    assert_eq!(r.k.h.query_all_by_label("Stop").count(), 3);

    let mut narrow = rig(TitlebarMode::Custom, &models, [940.0, 700.0], "");
    narrow.until("loaded", |k| k.h.query_by_label("Alpha").is_some());
    for (id, _) in models {
        narrow.ready(id);
    }
    narrow.until("running", |k| {
        k.h.query_all_by_label("stopped").count() == 0
    });
    assert!(narrow.k.h.query_all_by_label("38 tok/s").count() < 3);
    assert!(narrow.k.h.query_all_by_label("Stop").count() < 3);
    for name in ["Alpha", "Bravo", "Charlie"] {
        assert!(narrow.has(name), "{name} keeps its name");
    }
}

#[test]
fn the_title_bar_setting_is_saved_for_the_next_start() {
    let mut r = rig(TitlebarMode::Auto, &[], [1280.0, 1400.0], "");
    r.k.h.state_mut().settings_mut().show_window();
    r.k.h.run_steps(4);
    assert!(r.has("Title bar:"));
    assert!(r.has("next time KRAKEN starts"));
    r.k.h.get_by_label("KRAKEN's own").click();
    r.k.h.run_steps(4);
    let saved = KrakenConfig::from_file(&r.config).unwrap();
    assert_eq!(saved.local_serving.titlebar, TitlebarMode::Custom);
    r.k.h.get_by_label("The system's").click();
    r.k.h.run_steps(4);
    let saved = KrakenConfig::from_file(&r.config).unwrap();
    assert_eq!(saved.local_serving.titlebar, TitlebarMode::System);
}

#[test]
fn with_the_system_bar_the_chips_sit_in_the_top_bar_of_an_open_project() {
    let dir = crate::testutil::tempdir();
    let mut services = Services::offline();
    let config = dir.path().join("config.toml");
    let mut cfg = KrakenConfig {
        local_models: vec![local("qwen", "Qwen Coder")],
        ..KrakenConfig::default()
    };
    cfg.local_serving.titlebar = TitlebarMode::System;
    cfg.save(&config).unwrap();
    let mut s = stopped_status("qwen", "Qwen Coder");
    s.autostart = false;
    s.role_assigned = true;
    let fake = Arc::new(FakeServing::new(vec![s], vec![card()]));
    services.cfg = cfg;
    services.config_path = Some(config);
    services.serving = Some(fake.clone());
    let mut k = kit_from(services, &options(true), false);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h
            .state()
            .view_model()
            .is_some_and(|vm| vm.connection == Connection::Open)
            && k.h.query_by_label("Qwen Coder").is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        k.h.query_by_label("Qwen Coder").is_some(),
        "chip in the top bar"
    );
    assert!(k.h.query_by_label("Start").is_some());
    assert!(k.h.query_by_label("Close window").is_none());
}

#[test]
fn a_server_you_run_gets_a_chip_with_its_reachability() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        while let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let body = r#"{"data":[{"id":"llama3"}]}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    let provider = format!(
        "\n[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\nmodel = \"llama3\"\n"
    );
    let mut r = rig(TitlebarMode::Custom, &[], [1280.0, 700.0], &provider);
    r.until("the chip", |k| k.h.query_by_label("reachable").is_some());
    assert!(
        r.has("127.0.0.1"),
        "an address with no known name is named by its host"
    );
    assert!(
        r.k.h.query_by_label("Stop").is_none() && r.k.h.query_by_label("Start").is_none(),
        "it cannot be started or stopped here"
    );
}

fn serve_models_list() -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let body = r#"{"data":[{"id":"llama3"}]}"#;
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!(
        "\n[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:{port}/v1\"\nmodel = \"llama3\"\n"
    )
}

/// Pictures of the bar for review:
/// `KRAKEN_SHOT_DIR=<dir> cargo test -p kraken-gui screenshot_titlebar -- --ignored`.
#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_titlebar() {
    let dir = std::env::var_os("KRAKEN_SHOT_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    std::fs::create_dir_all(&dir).unwrap();
    let save = |k: &mut Kit, name: &str| {
        k.h.run_steps(6);
        let img = k.h.render().expect("render");
        let path = dir.join(name);
        img.save(&path).expect("save png");
        println!("saved {}", path.display());
    };

    // Ready, with a server the person runs.
    let provider = serve_models_list();
    let mut r = rig_gpu(
        TitlebarMode::Custom,
        &[("strata", "strata-iq1-m")],
        [1360.0, 300.0],
        &provider,
        true,
    );
    r.until("loaded", |k| k.h.query_by_label("strata-iq1-m").is_some());
    r.ready("strata");
    r.until("the figures", |k| {
        k.h.query_by_label("38 tok/s").is_some() && k.h.query_by_label("reachable").is_some()
    });
    save(&mut r.k, "titlebar-custom-ready.png");

    // Loading, with a second model stopped.
    let mut r = rig_gpu(
        TitlebarMode::Custom,
        &[("strata", "strata-iq1-m"), ("qwen", "qwen2.5-coder-7b")],
        [1360.0, 300.0],
        "",
        true,
    );
    r.until("loaded", |k| k.h.query_by_label("strata-iq1-m").is_some());
    r.fake.edit("strata", |m| {
        m.state = ModelState::Loading;
        m.devices = vec![on_card()];
        m.load_fraction = Some(0.62);
        let mut s = stats("strata", ModelState::Loading, Some(0.62));
        s.vram_per_device[0].bytes = 5_200_000_000;
        s.ram_bytes = 3_100_000_000;
        m.stats = Some(s);
    });
    r.until("loading", |k| k.h.query_by_label("loading 62%").is_some());
    save(&mut r.k, "titlebar-custom-loading.png");

    // Narrow: names and dots.
    let models = [
        ("a", "strata-iq1-m"),
        ("b", "qwen2.5-coder-7b"),
        ("c", "llama-3.1-8b"),
    ];
    let mut r = rig_gpu(TitlebarMode::Custom, &models, [940.0, 300.0], "", true);
    r.until("loaded", |k| k.h.query_by_label("strata-iq1-m").is_some());
    for (id, _) in models {
        r.ready(id);
    }
    r.fake.edit("c", |m| {
        m.state = ModelState::Failed {
            message: "The card is gone.".into(),
        };
    });
    r.until("running", |k| {
        k.h.query_all_by_label("stopped").count() == 0 && k.h.query_by_label("failed").is_none()
    });
    save(&mut r.k, "titlebar-custom-narrow.png");

    // The system's bar: the chips sit in the top bar.
    let dir2 = crate::testutil::tempdir();
    let config = dir2.path().join("config.toml");
    let mut cfg = KrakenConfig {
        local_models: vec![local("strata", "strata-iq1-m")],
        ..KrakenConfig::default()
    };
    cfg.local_serving.titlebar = TitlebarMode::System;
    cfg.save(&config).unwrap();
    let mut st = stopped_status("strata", "strata-iq1-m");
    st.autostart = false;
    st.role_assigned = true;
    st.state = ModelState::Ready;
    st.devices = vec![on_card()];
    st.stats = Some(stats("strata", ModelState::Ready, None));
    let fake = Arc::new(FakeServing::new(vec![st], vec![card()]));
    let mut services = Services::offline();
    services.cfg = cfg;
    services.config_path = Some(config);
    services.serving = Some(fake);
    let mut k = kit_sized(services, &options(true), true, [1700.0, 760.0]);
    for _ in 0..2000 {
        k.h.run_steps(1);
        if k.h.state().view_model().is_some_and(|vm| {
            vm.connection == Connection::Open && vm.analysis.phase == AnalysisPhase::Complete
        }) && k.h.query_by_label("38 tok/s").is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    k.h.run_steps(10);
    for label in ["Not now", "\u{00d7}"] {
        if let Some(n) = k.h.query_all_by_label(label).next() {
            n.click();
        }
        k.h.run_steps(3);
    }
    save(&mut k, "titlebar-system.png");
}

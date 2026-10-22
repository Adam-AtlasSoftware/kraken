//! The model list and model card of Settings > AI, driven through the whole app with a fake
//! serving service and a scratch configuration file.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui_kittest::kittest::Queryable;
use kraken_host::KrakenConfig;
use kraken_proto::infer::{
    DeviceInfo, DeviceState, GpuVendor, LocalEngine, LocalModel, MultiGpuMode,
};
use kraken_viewmodel::infer::fake::{
    FakeCall, FakeServing, FakeSetupProbe, sample_survey, stopped_status,
};

use super::options;
use super::shell::{Kit, kit_sized};
use crate::services::Services;

fn gpu(index: u32, vendor: GpuVendor, name: &str, state: DeviceState) -> DeviceInfo {
    DeviceInfo {
        index,
        uuid: format!("GPU-{index}"),
        vendor,
        name: name.into(),
        vram_total: 8 << 30,
        vram_used: 1 << 30,
        state,
    }
}

fn cards() -> Vec<DeviceInfo> {
    vec![
        gpu(0, GpuVendor::Nvidia, "RTX 3070 Ti", DeviceState::Ok),
        gpu(1, GpuVendor::Nvidia, "RTX 3060", DeviceState::Ok),
        gpu(
            2,
            GpuVendor::Intel,
            "Intel UHD 750",
            DeviceState::Unsupported {
                reason: "not supported yet".into(),
            },
        ),
    ]
}

fn model(id: &str, name: &str, engine: LocalEngine) -> LocalModel {
    LocalModel {
        id: id.into(),
        name: name.into(),
        engine,
        model_path: PathBuf::from(format!("/models/{id}.gguf")),
        devices: Vec::new(),
        cpu_only: false,
        multi_gpu: MultiGpuMode::Split,
        shares: None,
        main_device: None,
        context_size: None,
        autostart: true,
        extra: None,
    }
}

struct Rig {
    k: Kit,
    fake: Arc<FakeServing>,
    probe: Option<Arc<FakeSetupProbe>>,
    config: PathBuf,
    _dir: tempfile::TempDir,
}

/// Settings open over a scratch configuration with two models and `provider` as the assistant.
fn rig(provider: Option<serde_json::Value>) -> Rig {
    rig_with(provider, false, [1280.0, 2400.0])
}

fn rig_with(provider: Option<serde_json::Value>, gpu: bool, size: [f32; 2]) -> Rig {
    build(provider, gpu, size, None)
}

/// The same, with the guided setup looking at a computer that has `cards`.
fn rig_setup(cards: Vec<DeviceInfo>, size: [f32; 2], slow: Duration) -> Rig {
    let survey = sample_survey(cards, 31.2, 412.0);
    build(None, false, size, Some((survey, slow)))
}

fn build(
    provider: Option<serde_json::Value>,
    gpu: bool,
    size: [f32; 2],
    setup: Option<(kraken_viewmodel::infer::RawSurvey, Duration)>,
) -> Rig {
    let dir = crate::testutil::tempdir();
    let config = dir.path().join("kraken/config.toml");
    let cfg = KrakenConfig {
        local_models: vec![
            model("qwen", "Qwen Coder", LocalEngine::Llama),
            model("strata-iq1-m", "Strata IQ1", LocalEngine::Strata),
        ],
        provider,
        ..KrakenConfig::default()
    };
    cfg.save(&config).unwrap();
    let fake = Arc::new(FakeServing::new(
        vec![
            stopped_status("qwen", "Qwen Coder"),
            stopped_status("strata-iq1-m", "Strata IQ1"),
        ],
        cards(),
    ));
    let mut services = Services::offline();
    services.config_path = Some(config.clone());
    services.serving = Some(fake.clone());
    let probe = setup.map(|(survey, slow)| {
        let p = Arc::new(FakeSetupProbe::new(survey, fake.clone(), &config).slow(slow));
        services.setup_probe = Some(p.clone());
        p
    });
    let mut k = kit_sized(services, &options(false), gpu, size);
    k.h.run_steps(3);
    k.h.state_mut().settings_mut().show_window();
    k.h.run_steps(3);
    Rig {
        k,
        fake,
        probe,
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

    /// Clicks the widget with exactly this label.
    fn press(&mut self, text: &str) {
        self.k.h.get_by_label(text).click();
        self.k.h.run_steps(3);
    }

    /// The same for a widget whose label starts with the text (a checkbox with its figures).
    fn click(&mut self, text: &str) {
        self.k.h.get_by_label_contains(text).click();
        self.k.h.run_steps(3);
    }

    fn open_picker(&mut self, shown: &str) {
        self.k.h.get_by_value(shown).click();
        self.k.h.run_steps(3);
    }

    fn saved(&self) -> KrakenConfig {
        KrakenConfig::from_file(&self.config).unwrap()
    }
}

fn local_provider(id: &str) -> Option<serde_json::Value> {
    Some(serde_json::json!({"kind": "local", "model": id}))
}

#[test]
fn the_picker_lists_models_here_servers_cloud_and_agents_and_picking_shows_the_card() {
    let mut r = rig(None);
    r.open_picker("Ollama");
    for t in [
        "On this computer",
        "Qwen Coder",
        "Strata IQ1",
        "+ Set up a model on this computer...",
        "Server you run",
        "Other OpenAI-compatible server",
        "Cloud",
        "Anthropic (Claude)",
        "Terminal agent",
    ] {
        assert!(r.has(t), "the picker should list {t}");
    }
    r.press("Strata IQ1");
    r.until("the card", |k| {
        k.h.query_by_label_contains("Serve automatically").is_some()
    });
    assert!(
        r.k.h
            .query_by_value("Strata IQ1 \u{b7} on this computer")
            .is_some()
    );
    assert!(r.has("Run on"));
    assert!(!r.has("Server address"), "the server form is gone");
    assert!(
        !r.has("Run a model on this computer"),
        "the old section is gone"
    );
}

#[test]
fn the_card_shows_state_and_starts_and_stops_the_model() {
    let mut r = rig(local_provider("qwen"));
    // The window held the model that is marked to start with it.
    r.until("the model running", |k| {
        k.h.query_by_label("Stop serving").is_some()
    });
    assert!(r.has("Running on"));
    assert!(r.fake.calls().contains(&FakeCall::Autostart));
    r.press("Stop serving");
    r.until("stopped", |k| k.h.query_by_label("Start serving").is_some());
    assert!(r.fake.calls().contains(&FakeCall::Stop("qwen".into())));
    assert!(r.has("Stopped"));
    r.press("Start serving");
    r.until("running again", |k| {
        k.h.query_by_label("Stop serving").is_some()
    });
}

#[test]
fn the_autostart_checkbox_is_written_to_the_model() {
    let mut r = rig(local_provider("qwen"));
    assert!(r.saved().local_models[0].autostart);
    r.click("Serve automatically");
    assert!(!r.saved().local_models[0].autostart);
    assert!(
        r.saved().local_models[1].autostart,
        "the other is untouched"
    );
    r.click("Serve automatically");
    assert!(r.saved().local_models[0].autostart);
}

#[test]
fn unusable_cards_are_greyed_with_the_reason_and_several_cards_open_the_options() {
    let mut r = rig(local_provider("qwen"));
    r.until("the cards", |k| {
        k.h.query_by_label_contains("RTX 3070 Ti").is_some()
    });
    assert!(r.has("Intel UHD 750"));
    assert!(r.has("not supported yet"));
    assert!(r.has("CPU only (much slower)"));
    assert!(!r.has("How to use several cards"), "one card by default");

    r.click("RTX 3060");
    assert!(r.has("How to use several cards"));
    assert!(r.has("Split the model across the cards"));
    assert!(r.has("Split every layer between the cards"));
    assert!(
        !r.has("Each card runs its own full copy"),
        "that is Strata's"
    );
    assert!(r.has("Advanced: share per card, main card"));
    let m = &r.saved().local_models[0];
    assert_eq!(m.devices.len(), 2);

    r.press("Split every layer between the cards");

    assert_eq!(
        r.saved().local_models[0].multi_gpu,
        MultiGpuMode::SplitEveryLayer
    );
    r.click("RTX 3060");
    assert!(!r.has("How to use several cards"));
}

#[test]
fn strata_offers_a_full_copy_per_card_and_greys_out_cards_it_cannot_use() {
    let mut r = rig(local_provider("strata-iq1-m"));
    r.until("the cards", |k| {
        k.h.query_by_label_contains("RTX 3070 Ti").is_some()
    });
    assert!(r.has("NVIDIA cards only") || r.has("not supported yet"));
    assert!(!r.has("CPU only"), "Strata cannot run on the processor");
    r.click("RTX 3060");
    assert!(r.has("Each card runs its own full copy"));
    assert!(!r.has("Split every layer between the cards"));
}

#[test]
fn strata_tuning_is_saved_in_extra_and_reset_to_automatic_removes_it() {
    let mut r = rig(local_provider("strata-iq1-m"));
    r.until("the cards", |k| {
        k.h.query_by_label_contains("RTX 3070 Ti").is_some()
    });
    assert!(r.has("Automatic (recommended)"), "offered with one card");
    assert!(!r.has("Second card helps (peer tier)"));
    assert!(!r.has("Reset to automatic"), "nothing set yet");
    assert!(!r.has("Second card keeps free"));
    r.click("Read pictures");
    let t = kraken_proto::infer::StrataTuning::from_extra(r.saved().local_models[1].extra.as_ref());
    assert_eq!(t.vision, Some(false));
    r.click("RTX 3060");
    r.press("Second card helps (peer tier)");
    assert!(r.has("Second card keeps free (MiB)"));
    r.click("Reset to automatic");
    assert!(r.saved().local_models[1].extra.is_none());
}

#[test]
fn answer_speed_presets_are_saved_in_extra_and_reset_clears_them() {
    let mut r = rig(local_provider("strata-iq1-m"));
    r.until("the cards", |k| {
        k.h.query_by_label_contains("RTX 3070 Ti").is_some()
    });
    assert!(r.has("Answer speed"));
    assert!(r.has("Strata's own settings."));
    r.press("Faster");
    assert!(r.has("About 20 percent faster answers"));
    let t = kraken_proto::infer::StrataTuning::from_extra(r.saved().local_models[1].extra.as_ref());
    assert_eq!(
        (t.tail_skip, t.spec, t.spec_min_p_percent),
        (Some(5), Some(3), Some(65))
    );
    r.press("Exact");
    let t = kraken_proto::infer::StrataTuning::from_extra(r.saved().local_models[1].extra.as_ref());
    assert_eq!((t.tail_skip, t.spec), (Some(0), None));
    r.click("Reset to automatic");
    assert!(r.saved().local_models[1].extra.is_none());
}

#[test]
fn running_out_of_memory_asks_what_to_do() {
    let mut r = rig(local_provider("qwen"));
    r.until("running", |k| k.h.query_by_label("Stop serving").is_some());
    r.press("Stop serving");
    r.until("stopped", |k| k.h.query_by_label("Start serving").is_some());
    r.fake.refuse_start("qwen");
    r.press("Start serving");
    r.until("the question", |k| {
        k.h.query_by_label_contains("Not enough memory").is_some()
    });
    assert!(r.has("only 2.1 GB"));
    assert!(r.has("Run on the processor"));
    assert!(r.has("Start anyway"));
    assert!(r.has("Cancel"));
    r.click("Cancel");
    assert!(!r.has("Not enough memory"));
    assert!(
        r.k.h.query_by_label("Start serving").is_some(),
        "nothing was started"
    );

    r.press("Start serving");
    r.until("the question again", |k| {
        k.h.query_by_label_contains("Not enough memory").is_some()
    });
    r.k.h.get_by_label("Run on the processor").click();
    r.until("running on the processor", |k| {
        k.h.query_by_label("Stop serving").is_some()
    });
    assert!(matches!(
        r.fake.calls().last(),
        Some(FakeCall::Start(id, o)) if id == "qwen" && o.cpu
    ));
}

#[test]
fn removing_a_model_takes_it_off_the_list_and_off_the_assistant() {
    let mut r = rig(local_provider("qwen"));
    r.press("Remove this model");
    assert!(r.has("The downloaded files stay on your disk"));
    r.press("Keep it");
    assert_eq!(r.saved().local_models.len(), 2);
    r.press("Remove this model");
    r.k.h
        .query_all_by_label("Remove")
        .next()
        .expect("the confirm button")
        .click();
    r.k.h.run_steps(4);
    let saved = r.saved();
    assert_eq!(saved.local_models.len(), 1);
    assert_eq!(saved.local_models[0].id, "strata-iq1-m");
    assert!(saved.provider.is_none(), "the assistant used that model");
    assert!(r.has("The assistant is off until you pick one."));
}

fn one_card() -> Vec<DeviceInfo> {
    vec![gpu(0, GpuVendor::Nvidia, "RTX 3070 Ti", DeviceState::Ok)]
}

impl Rig {
    fn open_setup(&mut self) {
        self.open_picker("Ollama");
        self.press("+ Set up a model on this computer...");
        self.until("the setup window", |k| {
            k.h.query_by_label_contains("Check this computer").is_some()
        });
    }
}

#[test]
fn the_setup_walks_four_steps_and_the_assistant_ends_up_using_the_new_model() {
    let mut r = rig_setup(one_card(), [1280.0, 2400.0], Duration::from_millis(300));
    r.open_setup();

    // 1 Check this computer
    r.until("the computer", |k| {
        k.h.query_by_label_contains("Your graphics card: RTX 3070 Ti with 8.0 GB of video memory")
            .is_some()
    });
    assert!(r.has("Step 1 of 4"));
    assert!(r.has("Computer memory (RAM): 31.2 GB"));
    assert!(r.has("Free disk space: 412 GB"));
    r.press("Next");

    // 2 Pick a model
    assert!(r.has("Step 2 of 4"));
    assert!(r.has("Recommended"));
    assert!(r.has("Won't fit"), "the 32B models do not fit 8 GB");
    assert!(r.has("Fits in RTX 3070 Ti (video memory) with room to spare."));
    assert!(
        r.k.h.query_by_label("Next").is_some(),
        "Next waits for a pick"
    );
    r.k.h
        .get_by_label_contains("Qwen3 8B \u{b7} Q4_K_M")
        .click();
    r.k.h.run_steps(3);
    r.press("Next");

    // 3 Pick cards
    assert!(r.has("Step 3 of 4"));
    assert!(r.has("Run on"));
    assert!(r.has("Qwen3 8B fits on these cards."));
    r.press("Download and test");

    // 4 Download and test
    assert!(r.has("Step 4 of 4"));
    r.until("done", |k| {
        k.h.query_by_label_contains("It works.").is_some()
    });
    assert!(r.has("answered \"ready\""));
    assert_eq!(r.probe.as_ref().unwrap().installs().len(), 1);
    r.press("Done");
    r.until("the window to close", |k| {
        k.h.query_by_label_contains("Step 4 of 4").is_none()
    });

    let saved = r.saved();
    assert_eq!(saved.local_models.len(), 3);
    let m = saved
        .local_models
        .iter()
        .find(|m| m.id == "qwen3-8b-q4_k_m")
        .unwrap();
    assert!(m.autostart);
    assert_eq!(m.name, "Qwen3 8B");
    assert_eq!(m.devices[0].uuid, "GPU-0");
    assert_eq!(saved.provider, local_provider("qwen3-8b-q4_k_m"));
    assert!(
        r.k.h
            .query_by_value("Qwen3 8B \u{b7} on this computer")
            .is_some()
    );
    assert!(
        r.fake
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Start(id, _) if id == "qwen3-8b-q4_k_m"))
    );
    assert!(!r.has("Save and use"), "a local model has no save row");
    assert!(!r.has("Test connection"));
}

#[test]
fn cancel_back_and_errors_in_the_setup() {
    let mut r = rig_setup(one_card(), [1280.0, 2400.0], Duration::ZERO);
    r.open_setup();
    r.until("the computer", |k| {
        k.h.query_by_label_contains("Your graphics card").is_some()
    });
    r.press("Next");
    r.k.h
        .get_by_label_contains("Qwen3 4B \u{b7} Q4_K_M")
        .click();
    r.k.h.run_steps(3);
    r.press("Next");
    r.press("Back");
    assert!(r.has("Step 2 of 4"));
    r.press("Cancel");
    r.until("cancel to close the window", |k| {
        k.h.query_by_label_contains("Step 2 of 4").is_none()
    });
    assert_eq!(r.saved().local_models.len(), 2, "nothing was added");

    // A refused download says what happened and offers another try.
    let probe = r.probe.clone().unwrap();
    probe.fail_install(
        kraken_proto::ProtoError::new(kraken_proto::ErrorCode::Unsupported, "approval denied: x")
            .with_details(serde_json::json!({"approval": "denied"})),
    );
    r.open_setup();
    r.until("the computer", |k| {
        k.h.query_by_label_contains("Your graphics card").is_some()
    });
    r.press("Next");
    r.k.h
        .get_by_label_contains("Qwen3 4B \u{b7} Q4_K_M")
        .click();
    r.k.h.run_steps(3);
    r.press("Next");
    r.press("Download and test");
    r.until("the failure", |k| {
        k.h.query_by_label_contains("Nothing was downloaded")
            .is_some()
    });
    r.press("Try again");
    r.until("done", |k| {
        k.h.query_by_label_contains("It works.").is_some()
    });
}

#[test]
fn an_agent_can_open_and_drive_the_setup_and_the_step_is_described() {
    let mut r = rig_setup(one_card(), [1280.0, 2400.0], Duration::ZERO);
    let app = r.k.h.state_mut();
    app.drive_setup(kraken_viewmodel::AppAction::SetUpLocalModel);
    r.k.h.run_steps(4);
    r.until("the setup window", |k| {
        k.h.query_by_label_contains("Check this computer").is_some()
    });
    let said = r.k.h.state_mut().setup_description().unwrap();
    assert!(
        said.contains("step 1 of 4") && said.contains("`check_computer`"),
        "{said}"
    );
    r.k.h
        .state_mut()
        .drive_setup(kraken_viewmodel::AppAction::LocalSetupNext);
    r.k.h.run_steps(3);
    let said = r.k.h.state_mut().setup_description().unwrap();
    assert!(
        said.contains("step 2 of 4") && said.contains("Pick a model"),
        "{said}"
    );
    assert!(said.contains("None chosen yet"), "{said}");
    r.k.h
        .state_mut()
        .drive_setup(kraken_viewmodel::AppAction::LocalSetupCancel);
    r.k.h.run_steps(3);
    assert!(r.k.h.state_mut().setup_description().is_none());
}

#[test]
fn rewriting_has_the_same_list_and_a_card() {
    let mut r = rig(None);
    r.click("Use its own model");
    r.open_picker("Anthropic API (cloud)");
    for t in [
        "Qwen Coder",
        "Strata IQ1",
        "Server you run (Ollama, vLLM, other)",
    ] {
        assert!(r.has(t), "the rewriting picker should list {t}");
    }
    r.k.h.get_by_label("Qwen Coder").click();
    r.until("the card", |k| {
        k.h.query_all_by_label_contains("Serve automatically")
            .count()
            >= 1
    });
    r.click("Save rewriting model");
    let saved = r.saved();
    assert_eq!(
        saved.rewrite,
        Some(serde_json::json!({"kind": "local", "model": "qwen"}))
    );
}

/// Pictures of the card for the documentation and review:
/// `KRAKEN_SHOT_DIR=<dir> cargo test -p kraken-gui settings_ai_with_a_local_model -- --ignored`.
#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_settings_ai_with_a_local_model() {
    use kraken_proto::infer::{DeviceRef, DeviceVram, ModelState, ModelStats, TokSource};

    let dir = std::env::var_os("KRAKEN_SHOT_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    std::fs::create_dir_all(&dir).unwrap();
    let mut r = rig_with(local_provider("qwen"), true, [1100.0, 1500.0]);
    r.until("running", |k| k.h.query_by_label("Stop serving").is_some());
    let on = DeviceRef {
        uuid: "GPU-0".into(),
        index: 0,
        vendor: GpuVendor::Nvidia,
    };
    r.fake.edit("qwen", |m| {
        m.devices = vec![on.clone()];
        m.stats = Some(ModelStats {
            model: "qwen".into(),
            phase: ModelState::Ready,
            load_fraction: None,
            vram_per_device: vec![DeviceVram {
                device: on.clone(),
                bytes: 7_400_000_000,
            }],
            ram_bytes: 1_800_000_000,
            tok_s: Some(38.0),
            tok_s_source: Some(TokSource::Engine),
            devices: vec![on.clone()],
        });
    });
    r.until("the figures", |k| {
        k.h.query_by_label_contains("38 words/s").is_some()
    });
    let save = |r: &mut Rig, name: &str| {
        r.k.h.run_steps(6);
        let img = r.k.h.render().expect("render");
        let path = dir.join(name);
        img.save(&path).expect("save png");
        println!("saved {}", path.display());
    };
    save(&mut r, "settings-ai-local-model.png");
    r.click("RTX 3060");
    save(&mut r, "settings-ai-local-model-two-cards.png");
    r.open_picker("Qwen Coder \u{b7} on this computer");
    save(&mut r, "settings-ai-picker.png");
}

/// Pictures of the guided setup:
/// `KRAKEN_SHOT_DIR=<dir> cargo test -p kraken-gui screenshot_local_setup -- --ignored`.
#[test]
#[ignore = "writes PNG files and needs a GPU; run by hand"]
fn screenshot_local_setup() {
    let dir = std::env::var_os("KRAKEN_SHOT_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cards = one_card();
    cards.push(gpu(
        1,
        GpuVendor::Intel,
        "Intel UHD 750",
        DeviceState::Unsupported {
            reason: "not supported yet".into(),
        },
    ));
    let mut r = build(
        None,
        true,
        [900.0, 900.0],
        Some((sample_survey(cards, 31.2, 412.0), Duration::from_secs(4))),
    );
    let save = |r: &mut Rig, name: &str| {
        r.k.h.run_steps(6);
        let img = r.k.h.render().expect("render");
        let path = dir.join(name);
        img.save(&path).expect("save png");
        println!("saved {}", path.display());
    };
    r.open_setup();
    r.until("the computer", |k| {
        k.h.query_by_label_contains("Your graphics card").is_some()
    });
    save(&mut r, "setup-1-check-computer.png");
    r.press("Next");
    save(&mut r, "setup-2-pick-model.png");
    r.k.h
        .get_by_label_contains("Qwen3 8B \u{b7} Q4_K_M")
        .click();
    r.k.h.run_steps(3);
    r.press("Next");
    save(&mut r, "setup-3-pick-cards.png");
    r.press("Download and test");
    r.until("the progress", |k| {
        k.h.query_by_label_contains("Downloading Qwen3 8B: about 1")
            .is_some()
    });
    save(&mut r, "setup-4-download.png");
    r.until("done", |k| {
        k.h.query_by_label_contains("It works.").is_some()
    });
    save(&mut r, "setup-4-done.png");
}

#[test]
fn the_pick_step_offers_strata_engine_choices_and_a_model_file_you_have() {
    // A GPU is needed only for the screenshot; CI runners have none.
    let shot = std::env::var_os("KRAKEN_SHOT_DIR").is_some();
    let mut r = build(
        None,
        shot,
        [900.0, 1100.0],
        Some((sample_survey(one_card(), 64.0, 412.0), Duration::ZERO)),
    );
    r.open_setup();
    r.until("the computer", |k| {
        k.h.query_by_label_contains("Your graphics card").is_some()
    });
    r.press("Next");
    assert!(r.has("Use a model file I already have\u{2026}"));
    assert!(r.has("Ready-made") && r.has("Build from source"));
    assert!(r.has("Latest release") && r.has("Tested") && r.has("Latest commit"));
    assert!(!r.has("Use the list instead"), "no file picked yet");

    // The newest commit has no ready-made engine, so choosing it switches to a build.
    r.k.h.get_by_label("Latest commit").click();
    r.k.h.run_steps(3);
    r.k.h.get_by_label("Ready-made").click();
    r.k.h.run_steps(3);

    if let Ok(dir) = std::env::var("KRAKEN_SHOT_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        r.k.h
            .render()
            .expect("render")
            .save(dir.join("setup-2-strata.png"))
            .unwrap();
    }
}

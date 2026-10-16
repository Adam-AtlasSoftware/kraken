//! Headless frames of the local-model section against a real manager running the fake inference
//! server (no real model, nothing on the network).

use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Context, RawInput, Rect, pos2};
use kraken_host::infer::InferManager;
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{BackendRegistry, GenericOpenAiServerBackend};
use kraken_viewmodel::assist::ProviderStore;

use super::InferSettings;
use crate::assist::{AiSettings, Change};
use crate::services::Mode;
use crate::settings::{Settings, SettingsEnv};

const GIB: u64 = 1024 * 1024 * 1024;
const WAIT: Duration = Duration::from_secs(30);

struct Harness {
    ctx: Context,
    rt: Arc<tokio::runtime::Runtime>,
    manager: Arc<InferManager>,
}

impl Harness {
    fn new() -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        crate::fonts::install(&ctx);
        let mut reg = BackendRegistry::new();
        reg.register(Arc::new(
            GenericOpenAiServerBackend::from_manifest_str(&fake_manifest(
                "fake",
                &fake_server_path(),
            ))
            .expect("manifest"),
        ));
        let manager = Arc::new(
            InferManager::with_registry(reg)
                .with_total_memory(8 * GIB, None)
                .with_manifest_ids(vec!["fake".into()]),
        );
        Harness { ctx, rt, manager }
    }

    fn section(&self) -> InferSettings {
        InferSettings::with_service(self.manager.clone(), self.rt.handle().clone())
    }

    fn frame(&self, f: impl FnMut(&mut egui::Ui)) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(900.0, 900.0))),
            ..Default::default()
        };
        let mut out = self.ctx.run_ui(input, f);
        out.textures_delta.clear();
    }
}

fn draw(
    h: &Harness,
    s: &mut InferSettings,
    ai: &mut AiSettings,
    config: Option<&std::path::PathBuf>,
) {
    let rt = h.rt.handle().clone();
    h.frame(|ui| s.show(ui, &rt, Mode::NoDaemon, None, config, ai));
}

fn until(
    h: &Harness,
    s: &mut InferSettings,
    ai: &mut AiSettings,
    config: Option<&std::path::PathBuf>,
    what: &str,
    mut cond: impl FnMut(&mut InferSettings) -> bool,
) {
    let deadline = Instant::now() + WAIT;
    loop {
        draw(h, s, ai, config);
        if cond(s) {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_section_runs_a_model_and_hands_it_to_the_assistant() {
    let h = Harness::new();
    let mut s = h.section();
    let mut ai = AiSettings::default();
    let dir = crate::testutil::tempdir();
    let config = dir.path().join("kraken/config.toml");
    let model = dir.path().join("tiny.gguf");
    std::fs::write(&model, vec![0u8; 4096]).unwrap();

    until(&h, &mut s, &mut ai, Some(&config), "the engines", |s| {
        s.panel_mut().is_some_and(|p| p.loaded())
    });
    {
        let p = s.panel_mut().unwrap();
        assert_eq!(p.selected.as_deref(), Some("fake"));
        p.set_model_path(&model);
        p.form.set_text("ready_after", "0.3");
        assert!(p.memory_hint().is_some());
        p.start();
    }
    until(&h, &mut s, &mut ai, Some(&config), "ready", |s| {
        s.panel_mut().is_some_and(|p| p.is_ready())
    });
    assert_eq!(h.manager.loaded_models(), 1);
    // Frames with logs open draw the lines.
    s.panel_mut().unwrap().show_logs = true;
    until(&h, &mut s, &mut ai, Some(&config), "log lines", |s| {
        s.panel_mut()
            .is_some_and(|p| p.logs.iter().any(|l| l.text.contains("listening on")))
    });

    s.use_for_assistant(Some(&config), &mut ai);
    assert!(matches!(s.notice(), Some(Ok(_))), "{:?}", s.notice());
    let saved = ProviderStore::new(Some(config.clone()))
        .load()
        .expect("readable")
        .expect("a provider was saved");
    match saved {
        kraken_agent::ProviderConfig::OpenaiCompatible {
            base_url, model, ..
        } => {
            assert!(base_url.starts_with("http://127.0.0.1:"), "{base_url}");
            assert_eq!(model, "tiny.gguf");
        }
        other => panic!("unexpected provider {other:?}"),
    }
    match ai.take_change() {
        Some(Change::Use(_, badge)) => {
            assert!(badge.local, "a model on this computer is local");
            assert_eq!(badge.model, "tiny.gguf");
        }
        _ => panic!("the assistant should have been told to use the model"),
    }

    s.panel_mut().unwrap().stop();
    until(&h, &mut s, &mut ai, Some(&config), "stopped", |s| {
        s.panel_mut()
            .is_some_and(|p| !p.is_running() && !p.is_busy())
    });
    assert_eq!(h.manager.loaded_models(), 0);
    // Using a model that is not running is refused with a plain message.
    s.use_for_assistant(Some(&config), &mut ai);
    assert!(matches!(s.notice(), Some(Err(e)) if e.contains("finished loading")));
}

#[test]
fn bad_settings_and_a_refused_start_are_shown_not_sent() {
    let h = Harness::new();
    let mut s = h.section();
    let mut ai = AiSettings::default();
    until(&h, &mut s, &mut ai, None, "the engines", |s| {
        s.panel_mut().is_some_and(|p| p.loaded())
    });
    // No model chosen.
    s.panel_mut().unwrap().start();
    draw(&h, &mut s, &mut ai, None);
    assert!(s.panel_mut().unwrap().error.is_some());
    assert!(!s.panel_mut().unwrap().is_running());

    // Using without a settings folder says why.
    s.use_for_assistant(None, &mut ai);
    assert!(matches!(s.notice(), Some(Err(_))));
}

#[test]
fn the_settings_window_has_the_section() {
    let h = Harness::new();
    let mut settings = Settings::default();
    settings.infer = h.section();
    settings.show_window();
    let rt = h.rt.handle().clone();
    let deadline = Instant::now() + WAIT;
    loop {
        let env = SettingsEnv {
            rt: &rt,
            mode: Mode::NoDaemon,
            dark: true,
            config_path: None,
            backend: None,
            connecting: false,
            connect_error: None,
        };
        h.frame(|ui| {
            settings.show(ui.ctx(), &env);
        });
        if settings.infer.panel_mut().is_some_and(|p| p.loaded()) {
            break;
        }
        assert!(Instant::now() < deadline, "the section never loaded");
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(settings.infer.panel_mut().unwrap().backends()[0].id, "fake");
}

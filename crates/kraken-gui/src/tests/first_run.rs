//! The first-run wizard on a fresh config directory, walked through the whole app with a
//! scripted backend: engine set up, assistant, keys, look, and what ends up in the files.

use std::sync::Arc;
use std::time::{Duration, Instant};

use egui_kittest::kittest::Queryable;
use kraken_host::KrakenConfig;
use kraken_viewmodel::testing::FakeBackend;
use serde_json::json;

use super::options;
use super::shell::{Kit, kit_sized};
use crate::services::Services;

struct Rig {
    k: Kit,
    backend: Arc<FakeBackend>,
    dir: tempfile::TempDir,
}

fn rig() -> Rig {
    let backend = FakeBackend::new()
        .on("setup_status", |_| {
            Ok(json!({
                "items": [{
                    "id": "native", "name": "Native engine", "purpose": "reads programs",
                    "state": "missing", "detail": "no compiled processor files",
                    "fix": "run kraken setup --native", "fix_command": "setup_native",
                }],
                "ready": 0, "not_ready": 1,
            }))
        })
        .on("setup_native", |_| Ok(json!({"job_id": "job-g1"})))
        .on("job_status", |_| {
            Ok(json!({
                "job_id": "job-g1", "command": "setup_native", "status": "running",
                "progress": {"phase": "build", "done": 1, "total": 4,
                             "message": "compiling processor files"},
            }))
        })
        .shared();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut services = Services::offline();
    services.integrations_backend = Some(backend.clone());
    services.config_path = Some(dir.path().join("config").join("config.toml"));
    services.prefs_file = Some(dir.path().join("config").join("gui.json"));
    services.first_run_tour = true;
    let k = kit_sized(services, &options(false), false, [1280.0, 800.0]);
    Rig { k, backend, dir }
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

    fn click(&mut self, label: &str) {
        // A new step resizes the window over a few frames; wait for it to settle.
        self.k.h.run_steps(8);
        self.k.h.get_by_label_contains(label).click();
        self.k.h.run_steps(3);
    }

    fn config(&self) -> KrakenConfig {
        KrakenConfig::from_file(&self.dir.path().join("config").join("config.toml"))
            .expect("config")
    }
}

#[test]
fn a_fresh_install_walks_the_wizard_and_saves_the_choices() {
    let mut r = rig();
    r.until("the wizard", |k| {
        k.h.query_all_by_label_contains("Step 1 of 5")
            .next()
            .is_some()
    });
    r.until("the engine report", |k| {
        k.h.query_all_by_label_contains("not set up yet")
            .next()
            .is_some()
    });
    r.click("Set up the native engine");
    r.until("the job", |k| {
        k.h.query_all_by_label_contains("Setting up the native engine")
            .next()
            .is_some()
    });
    assert_eq!(r.backend.calls_to("setup_native").len(), 1);

    r.click("Next");
    assert!(r.has("Step 2 of 5"));
    // The assistant step cannot be left before a choice is made.
    assert!(r.has("Choose one of the options above"));
    r.click("None for now");
    r.click("Next");
    assert!(r.has("Step 3 of 5"));
    r.click("Classic desktop");
    assert!(r.has("A few keys in Classic desktop"));
    r.click("Next");
    assert!(r.has("Step 4 of 5"));
    r.click("Light");
    r.click("115%");
    r.click("Next");
    assert!(r.has("Step 5 of 5"));
    r.click("Finish");
    r.k.h.run_steps(3);
    assert!(!r.has("Step 5 of 5"), "the wizard closed");

    let cfg = r.config();
    assert_eq!(cfg.ui.keymap.as_deref(), Some("classic"));
    assert_eq!(cfg.ui.zoom_percent, Some(115));
    assert!(cfg.ui.first_run_done);
    let prefs =
        std::fs::read_to_string(r.dir.path().join("config").join("gui.json")).expect("gui.json");
    assert!(prefs.contains("\"dark\": false") && prefs.contains("\"tour_done\": true"));
}

#[test]
fn skipping_the_wizard_is_remembered_and_help_opens_it_again() {
    let mut r = rig();
    r.until("the wizard", |k| {
        k.h.query_all_by_label_contains("Step 1 of 5")
            .next()
            .is_some()
    });
    r.click("Cancel");
    assert!(!r.has("Step 1 of 5"));
    let cfg = r.config();
    assert!(cfg.ui.first_run_done);
    assert_eq!(cfg.ui.keymap, None);

    r.k.h.get_by_label("Help").click();
    r.k.h.run_steps(3);
    r.click("First-run setup");
    assert!(r.has("Step 1 of 5"));
}

#[test]
fn a_user_who_finished_it_before_does_not_see_it_again() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[ui]\nfirst_run_done = true\nkeymap = \"binja-like\"\n",
    )
    .expect("seed");
    let mut services = Services::offline();
    services.cfg = KrakenConfig::from_file(&path).expect("config");
    services.config_path = Some(path);
    services.prefs_file = Some(dir.path().join("gui.json"));
    services.first_run_tour = true;
    let mut k = kit_sized(services, &options(false), false, [1280.0, 800.0]);
    k.h.run_steps(5);
    assert!(
        k.h.query_all_by_label_contains("Step 1 of 5")
            .next()
            .is_none()
    );
    assert_eq!(k.h.state().active_keymap(), "binja-like");
}

#[test]
fn the_settings_window_changes_the_keymap_at_once_and_saves_it() {
    let mut r = rig();
    r.click("Cancel");
    r.k.h
        .key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::Comma);
    r.k.h.run_steps(5);
    r.click("Classic RE tool");
    assert_eq!(r.k.h.state().active_keymap(), "ida-like");
    assert_eq!(r.config().ui.keymap.as_deref(), Some("ida-like"));
    r.click("90%");
    assert_eq!(r.config().ui.zoom_percent, Some(90));
}

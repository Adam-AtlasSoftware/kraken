//! The Integrations window driven through the whole app with a scripted backend: the cards, the
//! licence gate in front of Install, a finished install and the Tools menu entry.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egui_kittest::kittest::{NodeT, Queryable};
use kraken_registry::commands::{IntegrationSource, IntegrationStatus, IntegrationView};
use kraken_viewmodel::AppAction;
use kraken_viewmodel::testing::FakeBackend;
use serde_json::json;

use super::options;
use super::shell::{Kit, kit_sized};
use crate::services::Services;

fn row(id: &str, name: &str, status: IntegrationStatus) -> IntegrationView {
    IntegrationView {
        id: id.into(),
        name: name.into(),
        kind: "emulator".into(),
        summary: format!("{name} runs test programs"),
        homepage: String::new(),
        platforms: vec!["Test Console".into()],
        formats: vec!["rom".into()],
        status,
        source: (status == IntegrationStatus::Ready).then_some(IntegrationSource::Downloaded),
        version: None,
        pinned_version: Some("1.0".into()),
        path: None,
        download_bytes: 3 << 20,
        disk_bytes: 0,
        license: "MIT".into(),
        notice: "Bring your own firmware.".into(),
        contains_key_material: false,
        user_supplied: false,
        debuggable: false,
        argv: vec!["{exe}".into(), "{binary}".into()],
        progress: None,
    }
}

struct Rig {
    k: Kit,
    backend: Arc<FakeBackend>,
}

fn rig() -> Rig {
    let installed = Arc::new(Mutex::new(false));
    let (a, b) = (installed.clone(), installed.clone());
    let backend = FakeBackend::new()
        .on("integrations_list", move |_| {
            let status = if *a.lock().unwrap() {
                IntegrationStatus::Ready
            } else {
                IntegrationStatus::NotInstalled
            };
            Ok(json!({"integrations": [
                row("toy", "Toy Emulator", status),
                row("other", "Other Machine", IntegrationStatus::ManualOnly),
            ]}))
        })
        .on("integration_install", move |args| {
            assert_eq!(args["id"], "toy");
            assert_eq!(args["accept_licence"], true);
            *b.lock().unwrap() = true;
            Ok(json!({}))
        })
        .shared();
    let mut services = Services::offline();
    services.integrations_backend = Some(backend.clone());
    let k = kit_sized(services, &options(false), false, [1280.0, 800.0]);
    Rig { k, backend }
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
}

#[test]
fn install_waits_for_the_licence_then_downloads_and_shows_the_result() {
    let mut r = rig();
    r.k.h.state_mut().drive_setup(AppAction::ShowIntegrations);
    r.until("the cards", |k| {
        k.h.query_all_by_label_contains("Toy Emulator")
            .next()
            .is_some()
    });
    assert!(r.has("Other Machine"));
    assert!(r.has("Not installed"));
    assert!(r.has("Use your own copy"));
    assert!(
        r.has("Bring your own firmware."),
        "the notice is shown first"
    );

    // Install is not available until the licence is accepted.
    assert!(
        r.k.h
            .query_all_by_label_contains("Install 1.0")
            .all(|n| n.accesskit_node().is_disabled()),
        "install must be disabled before the licence is accepted"
    );
    assert!(r.backend.calls_to("integration_install").is_empty());
    let licence = r.k.h.get_by_label_contains("I have read the MIT licence");
    licence.scroll_to_me();
    r.k.h.run_steps(2);
    r.k.h
        .get_by_label_contains("I have read the MIT licence")
        .click();
    r.k.h.run_steps(3);
    r.k.h.get_by_label_contains("Install 1.0").click();
    r.until("the installed chip", |k| {
        k.h.query_all_by_label_contains("Installed by KRAKEN")
            .next()
            .is_some()
    });
    assert_eq!(r.backend.calls_to("integration_install").len(), 1);
    assert!(r.has("Toy Emulator is installed"));
    assert!(r.has("Remove"));
}

#[test]
fn the_tools_menu_opens_the_window() {
    let mut r = rig();
    r.k.h.get_by_label("Tools").click();
    r.k.h.run_steps(3);
    r.k.h.get_by_label_contains("Emulators and tools").click();
    r.until("the cards", |k| {
        k.h.query_all_by_label_contains("Toy Emulator")
            .next()
            .is_some()
    });
    assert!(r.has("Other Machine"));
}

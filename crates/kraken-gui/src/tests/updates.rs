//! The update strip, the Updates window and About, driven through the whole app with a canned
//! update backend: Update now with progress and Restart now, Copy command for a package-managed
//! install, Skip this version and Later.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use egui_kittest::kittest::Queryable;
use kraken_proto::ProtoError;
use kraken_registry::commands::{
    InstallView, SystemView, UpdateApplied, UpdateBackend, UpdateStatusOut,
};
use kraken_registry::jobs::JobProgress;

use super::options;
use super::shell::{Kit, kit_sized};
use crate::services::Services;

#[derive(Debug)]
struct Canned {
    status: UpdateStatusOut,
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl UpdateBackend for Canned {
    fn status(&self) -> Result<UpdateStatusOut, ProtoError> {
        Ok(self.status.clone())
    }
    async fn check(&self, force: bool) -> Result<UpdateStatusOut, ProtoError> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("check {force}"));
        Ok(self.status.clone())
    }
    async fn apply(
        &self,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<UpdateApplied, ProtoError> {
        self.calls.lock().expect("lock").push("apply".into());
        progress(JobProgress {
            phase: "download".into(),
            message: "downloading kraken-0.4.0".into(),
            done: 5,
            total: 10,
            ..Default::default()
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(UpdateApplied {
            from: "0.3.0".into(),
            to: "0.4.0".into(),
            replaced: vec!["/home/a/.local/bin/kraken".into()],
            message: "Updated to 0.4.0. Restart KRAKEN to use it.".into(),
        })
    }
    fn rollback(&self) -> Result<UpdateApplied, ProtoError> {
        Err(ProtoError::new(kraken_proto::ErrorCode::NotFound, "none"))
    }
    fn skip(&self, version: Option<String>) -> Result<(), ProtoError> {
        self.calls
            .lock()
            .expect("lock")
            .push(format!("skip {}", version.unwrap_or_default()));
        Ok(())
    }
}

fn status(command: Option<&str>) -> UpdateStatusOut {
    UpdateStatusOut {
        version: "0.3.0".into(),
        target: "x86_64-unknown-linux-gnu".into(),
        build_channel: "release".into(),
        channel: "stable".into(),
        install: InstallView {
            kind: if command.is_some() { "aur" } else { "script" }.into(),
            label: if command.is_some() {
                "AUR package kraken-workbench-bin"
            } else {
                "install script into ~/.local"
            }
            .into(),
            can_self_update: command.is_none(),
            self_update_blocked: None,
            command: command.map(str::to_string),
            program: "/home/a/.local/bin/kraken-gui".into(),
        },
        system: SystemView {
            os: "Arch Linux (Linux)".into(),
            arch: "x86_64".into(),
            libc: "glibc".into(),
            session: "KDE desktop (Wayland)".into(),
        },
        checks_enabled: true,
        checks_disabled_by: None,
        last_check: Some(1),
        latest: Some("0.4.0".into()),
        notes_url: Some("https://github.com/Adam-AtlasSoftware/kraken/releases/tag/v0.4.0".into()),
        latest_signed: true,
        update_available: true,
        skipped: None,
        last_error: None,
        rollback_to: None,
        summary: "KRAKEN 0.4.0 is available (you have 0.3.0); run `kraken update`.".into(),
    }
}

struct Rig {
    k: Kit,
    backend: Arc<Canned>,
}

fn rig(command: Option<&str>) -> Rig {
    let backend = Arc::new(Canned {
        status: status(command),
        calls: Mutex::new(Vec::new()),
    });
    let mut services = Services::offline();
    services.updater = Some(backend.clone());
    let k = kit_sized(services, &options(false), false, [1280.0, 800.0]);
    Rig { k, backend }
}

impl Rig {
    fn until(&mut self, what: &str, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            self.k.h.run_steps(2);
            if self.has(text) {
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
        self.k.h.run_steps(3);
        self.k.h.get_by_label(label).click();
        self.k.h.run_steps(3);
    }

    fn calls(&self) -> Vec<String> {
        self.backend.calls.lock().expect("lock").clone()
    }
}

#[test]
fn update_now_shows_progress_then_restart_now() {
    let mut r = rig(None);
    r.until("the strip", "KRAKEN 0.4.0 is available (you have 0.3.0).");
    assert!(
        r.calls().contains(&"check false".to_string()),
        "{:?}",
        r.calls()
    );
    assert!(r.has("What's new"));
    r.click("Update now");
    r.until("the result", "Restart now");
    assert!(r.has("Updated to 0.4.0. Restart KRAKEN to use it."));
    assert!(r.calls().contains(&"apply".to_string()));
}

#[test]
fn a_package_managed_install_gets_its_command_and_skip_hides_the_strip() {
    let mut r = rig(Some("yay -Syu kraken-workbench-bin"));
    r.until("the strip", "Your package manager installed KRAKEN");
    assert!(r.has("Copy command"));
    assert!(!r.has("Update now"));
    r.click("Skip this version");
    assert!(!r.has("Your package manager installed KRAKEN"));
    r.k.h.run_steps(5);
    assert!(
        r.calls().contains(&"skip 0.4.0".to_string()),
        "{:?}",
        r.calls()
    );
}

#[test]
fn later_hides_the_strip_and_help_opens_updates_and_about() {
    let mut r = rig(None);
    r.until("the strip", "KRAKEN 0.4.0 is available");
    r.click("Later");
    assert!(!r.has("KRAKEN 0.4.0 is available (you have 0.3.0)."));
    r.k.h.get_by_label("Help").click();
    r.k.h.run_steps(3);
    r.click("About KRAKEN");
    r.until("about", "KDE desktop (Wayland)");
    assert!(r.has("install script into ~/.local"));
    // About's own button opens the Updates window.
    r.click("Check for updates...");
    r.until("the window", "Last check");
    r.click("Check now");
    r.k.h.run_steps(10);
    assert!(
        r.calls().contains(&"check true".to_string()),
        "{:?}",
        r.calls()
    );
}

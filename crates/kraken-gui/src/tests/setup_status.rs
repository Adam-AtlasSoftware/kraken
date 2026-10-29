//! The Setup status window driven through the whole app with a scripted backend: the report, an
//! install started as a global job whose progress is polled, and the Help menu entry.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egui_kittest::kittest::{NodeT, Queryable};
use kraken_viewmodel::testing::FakeBackend;
use serde_json::json;

use super::options;
use super::shell::{Kit, kit_sized};
use crate::services::Services;

fn item(id: &str, name: &str, state: &str, fix_command: Option<&str>) -> serde_json::Value {
    let mut v = json!({
        "id": id, "name": name, "purpose": format!("{name} test purpose"),
        "state": state, "detail": format!("{name} detail"),
    });
    if state != "ready" {
        v["fix"] = json!(format!("fix {name} by hand"));
    }
    if let Some(c) = fix_command {
        v["fix_command"] = json!(c);
    }
    v
}

struct Rig {
    k: Kit,
    backend: Arc<FakeBackend>,
}

fn rig() -> Rig {
    let polls = Arc::new(AtomicUsize::new(0));
    let installed = Arc::new(Mutex::new(false));
    let (p, i1, i2) = (polls.clone(), installed.clone(), installed.clone());
    let backend = FakeBackend::new()
        .on("setup_status", move |_| {
            let engine = if *i1.lock().unwrap() {
                "ready"
            } else {
                "missing"
            };
            let ready = if engine == "ready" { 2 } else { 1 };
            Ok(json!({
                "items": [
                    item("engine", "Test engine", engine, Some("setup_ghidra")),
                    item("rust", "Rust toolchain", "ready", None),
                ],
                "ready": ready, "not_ready": 2 - ready,
            }))
        })
        .on("setup_ghidra", |_| Ok(json!({"job_id": "job-g1"})))
        .on("job_status", move |args| {
            assert_eq!(args["job_id"], "job-g1");
            if p.fetch_add(1, Ordering::SeqCst) < 4 {
                Ok(json!({
                    "job_id": "job-g1", "command": "setup_ghidra", "status": "running",
                    "progress": {"phase": "download", "done": 50, "total": 100,
                                 "message": "downloading engine: 50.0 / 100.0 MiB"},
                }))
            } else {
                *i2.lock().unwrap() = true;
                Ok(json!({
                    "job_id": "job-g1", "command": "setup_ghidra", "status": "succeeded",
                    "result": {},
                }))
            }
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
fn the_help_menu_opens_the_report_and_install_runs_as_a_job() {
    let mut r = rig();
    r.k.h.get_by_label("Help").click();
    r.k.h.run_steps(3);
    r.k.h.get_by_label_contains("Setup status").click();
    r.until("the report", |k| {
        k.h.query_all_by_label_contains("Test engine")
            .next()
            .is_some()
    });
    assert!(r.has("Rust toolchain"));
    assert!(r.has("Not installed"));
    assert!(r.has("fix Test engine by hand"));
    assert!(r.has("1 ready, 1 not ready"));
    // only the part with an install command offers the button
    assert_eq!(r.k.h.query_all_by_label("Install").count(), 1);

    r.k.h.get_by_label("Install").click();
    r.until("the progress line", |k| {
        k.h.query_all_by_label_contains("downloading engine: 50.0")
            .next()
            .is_some()
    });
    assert!(
        r.k.h
            .query_all_by_label("Cancel")
            .all(|n| !n.accesskit_node().is_disabled())
    );
    r.until("the finished install", |k| {
        k.h.query_all_by_label_contains("Test engine: done")
            .next()
            .is_some()
    });
    assert_eq!(r.backend.calls_to("setup_ghidra").len(), 1);
    assert!(r.backend.calls_to("job_status").len() >= 5);
    r.until("the refreshed report", |k| {
        k.h.query_all_by_label_contains("2 ready, 0 not ready")
            .next()
            .is_some()
    });
}

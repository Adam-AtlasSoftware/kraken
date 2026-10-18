//! The loading screen of a slow open (a scripted engine): stages, bar, counts, Cancel.

use std::sync::Arc;
use std::time::Duration;

use egui_kittest::kittest::Queryable;
use kraken_proto::OpenStage;

use super::options;
use crate::app::KrakenApp;
use crate::services::Services;

struct Kit {
    h: egui_kittest::Harness<'static, KrakenApp>,
    _rt: Arc<tokio::runtime::Runtime>,
}

/// The app opening the demo slowly: `open_time` for the whole open.
fn opening(open_time: Duration) -> Kit {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let ctx = egui::Context::default();
    let mut app = KrakenApp::new(&ctx, rt.clone(), Services::offline(), &options(false));
    {
        let _g = rt.enter();
        app.start_loading_demo(&ctx, open_time);
    }
    let mut fonts_done = false;
    let h = egui_kittest::Harness::builder()
        .with_size([1280.0, 800.0])
        .build_ui_state(
            move |ui, app: &mut KrakenApp| {
                if !fonts_done {
                    crate::fonts::install(ui.ctx());
                    fonts_done = true;
                    return;
                }
                app.frame(ui);
            },
            app,
        );
    Kit { h, _rt: rt }
}

impl Kit {
    fn run_until(&mut self, what: &str, cond: impl Fn(&KrakenApp) -> bool) {
        for _ in 0..4000 {
            self.h.run_steps(1);
            if cond(self.h.state()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out waiting for {what}");
    }

    /// Waits until the screen shows the function search with a known share done.
    fn mid_open(&mut self) {
        self.run_until("the function search", |a| {
            a.view_model()
                .and_then(|v| v.loading.as_ref())
                .is_some_and(|l| {
                    l.stage() == OpenStage::Functions
                        && l.fraction().is_some()
                        && l.started.elapsed() >= crate::loading::SHOW_AFTER
                })
        });
        self.h.run_steps(2);
    }
}

#[test]
fn the_loading_screen_shows_stages_progress_and_counts() {
    let mut k = opening(Duration::from_secs(30));
    k.mid_open();
    assert!(k.h.query_by_label("Opening libpython3.14.so").is_some());
    for stage in [
        "Checking the file",
        "Starting the engine",
        "Finding functions",
        "Restoring your changes",
        "Ready",
    ] {
        assert!(k.h.query_by_label(stage).is_some(), "stage {stage}");
    }
    assert!(k.h.query_by_label_contains("functions found").is_some());
    assert!(k.h.query_by_label_contains("to look at").is_some());
    assert!(k.h.query_by_label_contains("Elapsed 0:").is_some());
    assert!(
        k.h.query_by_label_contains("first open of a big program")
            .is_some()
    );
    assert!(k.h.query_by_label("Cancel").is_some());
    // the workspace and the welcome screen are not drawn meanwhile
    assert!(k.h.query_by_label("New project from a program").is_none());
}

#[test]
fn cancel_on_the_loading_screen_goes_back_to_the_welcome_screen() {
    let mut k = opening(Duration::from_secs(60));
    k.mid_open();
    k.h.get_by_label("Cancel").click();
    k.h.run_steps(2);
    assert!(
        k.h.state()
            .view_model()
            .and_then(|v| v.loading.as_ref())
            .is_none_or(|l| l.cancelling),
        "the click asked to stop"
    );
    k.run_until("the welcome screen", |a| a.view_model().is_none());
    k.h.run_steps(3);
    assert!(k.h.query_by_label("New project from a program").is_some());
    assert!(
        k.h.state().welcome_error().is_none(),
        "a cancel is no error"
    );
}

#[test]
fn a_quick_open_never_shows_the_loading_screen() {
    let mut k = opening(Duration::ZERO);
    let mut saw = false;
    for _ in 0..2000 {
        k.h.run_steps(1);
        saw |= k.h.query_by_label("Finding functions").is_some();
        if k.h
            .state()
            .view_model()
            .is_some_and(|v| v.connection == kraken_viewmodel::Connection::Open)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!saw, "no flash of the loading screen");
}

/// Renders the loading screen mid-open to `KRAKEN_GUI_SHOT` (a PNG path). Needs a GPU adapter;
/// run by hand: `KRAKEN_GUI_SHOT=/tmp/loading.png cargo test -p kraken-gui loading_png -- --ignored`.
#[test]
#[ignore = "renders with wgpu; run by hand"]
fn loading_png() {
    let path = std::env::var("KRAKEN_GUI_SHOT").expect("set KRAKEN_GUI_SHOT to a .png path");
    let mut k = opening(Duration::from_secs(20));
    k.run_until("40% done", |a| {
        a.view_model()
            .and_then(|v| v.loading.as_ref())
            .is_some_and(|l| l.fraction().is_some_and(|f| f >= 0.4))
    });
    k.h.run_steps(4);
    let image = k.h.render().expect("render");
    image.save(&path).expect("save the png");
}

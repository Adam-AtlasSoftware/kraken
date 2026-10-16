//! Headless tests: the whole app is driven frame by frame through `egui::Context::run_ui`, with
//! keyboard events injected, so no window or GPU is needed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Context, Event, Key, Modifiers, RawInput, Rect, pos2};
use kraken_gui_widgets::KrakenTheme;
use kraken_viewmodel::{AnalysisPhase, Connection, Load, UiRequest};

use crate::app::KrakenApp;
use crate::args::{Options, RendererChoice, Scene};
use crate::fonts;
use crate::welcome::Choice;
use crate::workspace::{self, DOUBLE_CLICK_WINDOW, Tab};

const WAIT: Duration = Duration::from_secs(20);

struct Harness {
    ctx: Context,
    app: KrakenApp,
    _rt: Arc<tokio::runtime::Runtime>,
}

fn options(demo: bool) -> Options {
    Options {
        scene: Scene::Main,
        renderer: RendererChoice::Wgpu,
        demo,
        screenshot: None,
        light: false,
    }
}

impl Harness {
    fn new(demo: bool) -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        fonts::install(&ctx);
        let app = KrakenApp::new(&ctx, rt.clone(), None, &options(demo));
        Harness { ctx, app, _rt: rt }
    }

    fn step_with(&mut self, events: Vec<Event>) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1280.0, 800.0))),
            events,
            ..Default::default()
        };
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(input, |ui| app.frame(ui));
        out.textures_delta.clear();
    }

    fn step(&mut self) {
        self.step_with(Vec::new());
    }

    fn run_until(&mut self, what: &str, cond: impl Fn(&KrakenApp) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !cond(&self.app) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            self.step();
            std::thread::sleep(Duration::from_millis(4));
        }
    }

    fn key(&mut self, key: Key, modifiers: Modifiers) {
        self.step_with(vec![Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat: false,
            modifiers,
        }]);
        self.step_with(vec![Event::Key {
            key,
            physical_key: Some(key),
            pressed: false,
            repeat: false,
            modifiers,
        }]);
    }

    fn ready_demo() -> Self {
        let mut h = Harness::new(true);
        h.run_until("the demo to finish analysis", |a| {
            a.view_model().is_some_and(|vm| {
                vm.connection == Connection::Open
                    && vm.analysis.phase == AnalysisPhase::Complete
                    && !vm.functions.items.is_empty()
                    && !vm.busy()
            })
        });
        h
    }

    fn select_main(&mut self) -> u64 {
        let vm = self.app.view_model_mut().unwrap();
        let main = vm
            .functions
            .items
            .iter()
            .find(|f| f.name == "main")
            .unwrap()
            .address;
        vm.select_function(main);
        self.run_until("main to decompile", |a| {
            a.view_model()
                .and_then(|vm| vm.current.as_ref())
                .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)))
        });
        main
    }
}

const CTRL: Modifiers = Modifiers {
    alt: false,
    ctrl: true,
    shift: false,
    mac_cmd: false,
    command: true,
};

#[test]
fn welcome_screen_renders_without_a_project() {
    let mut h = Harness::new(false);
    for _ in 0..3 {
        h.step();
    }
    assert!(h.app.view_model().is_none());
}

#[test]
fn real_projects_explain_that_the_engine_is_not_connected_yet() {
    let mut h = Harness::new(false);
    let ctx = h.ctx.clone();
    h.app
        .start_real(Choice::OpenProject("/some/project".into()), &ctx);
    h.app.start_real(Choice::NewProject("/bin/ls".into()), &ctx);
    h.step();
    assert!(h.app.view_model().is_none());
    assert!(h.app.welcome_error().unwrap().contains("not connected"));
}

#[test]
fn demo_opens_analyzes_and_fills_the_function_list() {
    let h = Harness::ready_demo();
    let vm = h.app.view_model().unwrap();
    assert!(vm.functions.items.len() >= 10);
    assert_eq!(vm.project.as_ref().unwrap().name, "demo-server");
    assert!(vm.status_text().starts_with("Ready"));
}

#[test]
fn the_workspace_draws_a_decompiled_function_across_frames() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    for _ in 0..5 {
        h.step();
    }
    let vm = h.app.view_model().unwrap();
    assert_eq!(vm.current.as_ref().unwrap().address, main);
    assert_eq!(vm.selected, Some(main));
}

#[test]
fn ctrl_k_and_ctrl_shift_p_toggle_the_palette_and_escape_closes_it() {
    let mut h = Harness::ready_demo();
    h.key(Key::K, CTRL);
    assert!(h.app.view_model().unwrap().palette.open);
    h.key(Key::K, CTRL);
    assert!(!h.app.view_model().unwrap().palette.open);
    h.key(
        Key::P,
        Modifiers {
            shift: true,
            ..CTRL
        },
    );
    assert!(h.app.view_model().unwrap().palette.open);
    h.step();
    h.key(Key::Escape, Modifiers::NONE);
    assert!(!h.app.view_model().unwrap().palette.open);
}

#[test]
fn palette_typing_and_enter_run_an_action() {
    let mut h = Harness::ready_demo();
    h.select_main();
    h.key(Key::K, CTRL);
    h.step_with(vec![Event::Text("rename this".into())]);
    h.step();
    assert_eq!(
        h.app.view_model().unwrap().palette.query,
        "rename this",
        "typing reaches the palette"
    );
    h.key(Key::Enter, Modifiers::NONE);
    let vm = h.app.view_model().unwrap();
    assert!(!vm.palette.open);
    assert_eq!(
        vm.rename.as_ref().map(|r| r.old_name.as_str()),
        Some("main")
    );
}

#[test]
fn pressing_n_opens_rename_and_escape_cancels() {
    let mut h = Harness::ready_demo();
    h.select_main();
    for _ in 0..3 {
        h.step();
    }
    h.key(Key::N, Modifiers::NONE);
    assert!(
        h.app.view_model().unwrap().rename.is_some(),
        "N opens the dialog"
    );
    h.step();
    h.key(Key::Escape, Modifiers::NONE);
    assert!(h.app.view_model().unwrap().rename.is_none());
}

#[test]
fn rename_dialog_submits_through_the_view_model() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    let vm = h.app.view_model_mut().unwrap();
    vm.begin_rename_current();
    vm.set_rename_input("program_entry");
    h.step();
    h.key(Key::Enter, Modifiers::NONE);
    h.run_until("the rename to land", |a| {
        a.view_model().is_some_and(|vm| {
            vm.rename.is_none()
                && vm
                    .functions
                    .find(main)
                    .is_some_and(|f| f.name == "program_entry")
        })
    });
}

#[test]
fn alt_arrows_walk_the_navigation_history() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    let vm = h.app.view_model_mut().unwrap();
    let other = vm
        .functions
        .items
        .iter()
        .find(|f| f.address != main)
        .unwrap()
        .address;
    vm.navigate_to(other);
    h.run_until("the second function", |a| {
        a.view_model()
            .unwrap()
            .current
            .as_ref()
            .is_some_and(|c| c.address == other)
    });
    h.key(Key::ArrowLeft, Modifiers::ALT);
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .address,
        main
    );
    h.key(Key::ArrowRight, Modifiers::ALT);
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .address,
        other
    );
}

#[test]
fn ui_requests_change_the_window_state() {
    let mut h = Harness::ready_demo();
    let ctx = h.ctx.clone();
    assert_eq!(h.app.theme(), KrakenTheme::DARK);
    h.app.handle(UiRequest::ToggleTheme, &ctx);
    h.step();
    assert_eq!(h.app.theme(), KrakenTheme::LIGHT);
    assert!(
        !ctx.global_style().visuals.dark_mode,
        "the theme was applied to egui"
    );
    h.app.handle(UiRequest::ShowHistory, &ctx);
    h.step();
    h.app.handle(UiRequest::ShowProposals, &ctx);
    h.step();
    h.app.handle(UiRequest::FocusFunctionFilter, &ctx);
    h.step();
    h.app.handle(UiRequest::OpenProject, &ctx);
    h.step();
    assert!(h.app.view_model().is_none(), "back to the welcome screen");
    h.app.handle(UiRequest::OpenDemo, &ctx);
    h.run_until("the demo to reopen", |a| {
        a.view_model()
            .is_some_and(|vm| vm.connection == Connection::Open)
    });
}

#[test]
fn a_call_click_waits_out_the_double_click_window_before_navigating() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    let target = h
        .app
        .view_model()
        .unwrap()
        .functions
        .items
        .iter()
        .find(|f| f.address != main)
        .unwrap()
        .address;
    h.app.pending_nav().pending_nav = Some((target, Instant::now()));
    h.step();
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .address,
        main,
        "not yet: it could still be a double-click"
    );
    std::thread::sleep(DOUBLE_CLICK_WINDOW + Duration::from_millis(40));
    h.step();
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .current
            .as_ref()
            .unwrap()
            .address,
        target
    );
    assert!(h.app.pending_nav().pending_nav.is_none());
}

#[test]
fn analysis_can_be_cancelled_and_restarted_from_actions() {
    let mut h = Harness::ready_demo();
    let vm = h.app.view_model_mut().unwrap();
    vm.perform(kraken_viewmodel::AppAction::Analyze);
    h.run_until("analysis to run or finish", |a| {
        a.view_model()
            .is_some_and(|vm| vm.analysis.running() || vm.analysis.phase == AnalysisPhase::Complete)
    });
    h.run_until("analysis to end", |a| {
        a.view_model()
            .is_some_and(|vm| !vm.analysis.running() && !vm.busy())
    });
}

#[test]
fn every_tab_has_a_title_and_a_plain_tooltip() {
    for t in [
        Tab::Functions,
        Tab::Decompiler,
        Tab::Hex,
        Tab::Listing,
        Tab::History,
        Tab::Proposals,
    ] {
        assert!(!t.title().is_empty());
        let tip = t.tooltip();
        assert!(tip.ends_with('.'), "{tip}");
        assert!(tip.len() < 100, "one plain sentence: {tip}");
    }
    assert_eq!(workspace::initial_dock().iter_all_tabs().count(), 6);
}

#[test]
fn placeholder_bytes_are_stable_and_shaped_like_a_function() {
    let a = workspace::placeholder_bytes(0x401000, 64);
    assert_eq!(a, workspace::placeholder_bytes(0x401000, 64));
    assert_ne!(a, workspace::placeholder_bytes(0x401040, 64));
    assert_eq!(a.len(), 64);
    assert_eq!(&a[..4], &[0x55, 0x48, 0x89, 0xe5]);
    assert_eq!(a[63], 0xc3);
}

#[test]
fn no_default_fonts_are_needed() {
    // A context that only has the bundled fonts can lay out proportional, monospace and medium text.
    let ctx = Context::default();
    fonts::install(&ctx);
    let mut out = ctx.run_ui(RawInput::default(), |ui| {
        ui.label("Proportional");
        ui.label(egui::RichText::new("mono").monospace());
        ui.label(crate::style::medium("medium", 14.0));
    });
    out.textures_delta.clear();
}

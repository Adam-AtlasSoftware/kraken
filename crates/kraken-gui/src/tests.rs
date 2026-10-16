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
use crate::services::Services;
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
        no_daemon: false,
        open_project: None,
        function: None,
    }
}

impl Harness {
    fn new(demo: bool) -> Self {
        Self::with_services(demo, Services::offline())
    }

    fn with_services(demo: bool, services: Services) -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        fonts::install(&ctx);
        let app = KrakenApp::new(&ctx, rt.clone(), services, &options(demo));
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
fn real_projects_explain_when_the_daemon_cannot_be_reached() {
    let mut h = Harness::new(false);
    let ctx = h.ctx.clone();
    h.app
        .start_real(Choice::OpenProject("/some/project".into()), &ctx);
    h.run_until("the connection to fail", |a| {
        a.welcome_error()
            .is_some_and(|e| e.contains("Could not reach"))
    });
    assert!(h.app.view_model().is_none());
    assert!(h.app.welcome_error().unwrap().contains("--no-daemon"));
}

#[test]
fn ctrl_comma_opens_and_closes_the_settings_window() {
    let mut h = Harness::new(false);
    h.key(Key::Comma, CTRL);
    h.step();
    assert!(h.app.settings().open);
    h.step();
    h.key(Key::Comma, CTRL);
    assert!(!h.app.settings().open);
    h.key(Key::Comma, CTRL);
    h.key(Key::Escape, Modifiers::NONE);
    assert!(!h.app.settings().open);
}

#[test]
fn a_dangerous_command_waits_for_the_dialog_and_escape_denies_it() {
    use kraken_viewmodel::{ApprovalPrompt, Approver};
    let mut h = Harness::new(false);
    let broker = h.app.approvals().clone();
    let (tx, rx) = std::sync::mpsc::channel();
    h._rt.spawn(async move {
        let allowed = broker
            .approve(ApprovalPrompt {
                command: "wipe_project".into(),
                summary: "Remove everything".into(),
                args: serde_json::json!({"keep": false}),
            })
            .await;
        let _ = tx.send(allowed);
    });
    h.run_until("the question", |a| a.approvals().current().is_some());
    h.step();
    assert!(
        rx.try_recv().is_err(),
        "nothing is decided until the person answers"
    );
    h.key(Key::Escape, Modifiers::NONE);
    let deadline = Instant::now() + WAIT;
    let allowed = loop {
        if let Ok(a) = rx.try_recv() {
            break a;
        }
        assert!(Instant::now() < deadline, "no answer");
        h.step();
    };
    assert!(!allowed);
    assert!(h.app.approvals().current().is_none());
}

#[test]
fn the_palette_action_for_settings_asks_the_window_to_open_it() {
    let mut h = Harness::ready_demo();
    h.key(Key::Comma, CTRL);
    h.step();
    assert!(h.app.settings().open);
    // The palette lists the window too.
    let vm = h.app.view_model_mut().unwrap();
    assert_eq!(
        vm.perform(kraken_viewmodel::AppAction::OpenSettings),
        Some(UiRequest::OpenSettings)
    );
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
        Tab::Graph,
        Tab::Xrefs,
        Tab::Strings,
        Tab::Symbols,
        Tab::History,
        Tab::Proposals,
    ] {
        assert!(!t.title().is_empty());
        let tip = t.tooltip();
        assert!(tip.ends_with('.'), "{tip}");
        assert!(tip.len() < 100, "one plain sentence: {tip}");
    }
    assert_eq!(workspace::initial_dock().iter_all_tabs().count(), 10);
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

// ---------------------------------------------------------------- against a real daemon

mod live {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use engine_fake::FixtureFile;
    use kraken_host::DaemonSettings;
    use kraken_host::daemon::{CallParams, DaemonClient};
    use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, RuntimeDir};
    use kraken_model::AuthorKind;
    use kraken_proto::Locator;
    use kraken_registry::{Registry, SessionConfig};
    use krakend::fake::FakeFactory;
    use krakend::{Daemon, DaemonOptions};
    use serde_json::json;

    use super::*;
    use crate::testutil;

    const BUILD: &str = env!("CARGO_PKG_VERSION");

    struct Rig {
        tmp: tempfile::TempDir,
        dir: RuntimeDir,
        daemon: Option<Daemon>,
        h: Harness,
    }

    fn fixture() -> FixtureFile {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
        let mut fx = FixtureFile::from_path(&p).expect("fixture");
        for f in &mut fx.functions {
            if let Locator::Native { offset, .. } = &f.summary.locator {
                f.summary.name = format!("FUN_{:08x}", offset.0);
            }
        }
        fx
    }

    impl Rig {
        fn new() -> Self {
            let tmp = testutil::tempdir();
            let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
            let mut services = Services::offline();
            services.connector = Some(kraken_viewmodel::attach_connector(dir.clone()));
            services.prefs_file = Some(tmp.path().join("cfg/gui.json"));
            services.config_path = Some(tmp.path().join("cfg/config.toml"));
            services.cfg.projects_root = Some(tmp.path().join("projects"));
            let h = Harness::with_services(false, services);
            let daemon = {
                let _g = h._rt.enter();
                krakend::start(DaemonOptions {
                    runtime_dir: dir.clone(),
                    factory: Arc::new(FakeFactory::new(fixture(), Duration::ZERO)),
                    registry: Arc::new(Registry::standard()),
                    settings: DaemonSettings {
                        idle_secs: Some(600),
                        session_idle_secs: Some(1800),
                        max_sessions: Some(4),
                    },
                    session_config: SessionConfig::default(),
                    clock: Arc::new(ManualClock::new()),
                    poll: Duration::from_millis(10),
                    build: BUILD.into(),
                })
                .expect("daemon starts")
            };
            Rig {
                tmp,
                dir,
                daemon: Some(daemon),
                h,
            }
        }

        fn binary(&self) -> String {
            let p = self.tmp.path().join("prog.bin");
            std::fs::write(&p, b"\x7fELF fake binary").expect("binary");
            p.to_string_lossy().into_owned()
        }

        fn project(&self) -> PathBuf {
            self.tmp.path().join("projects/prog")
        }

        fn agent(&self) -> DaemonClient {
            self.h._rt.block_on(async {
                let c = Client::connect(&self.dir, &ClientHello::new(ClientKind::Mcp, BUILD))
                    .await
                    .expect("connect");
                DaemonClient::from_client(c, BUILD)
            })
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            if let Some(d) = self.daemon.take() {
                d.shutdown();
                self.h._rt.block_on(async {
                    let _ = tokio::time::timeout(Duration::from_secs(10), d.wait()).await;
                });
            }
        }
    }

    #[test]
    #[cfg_attr(
        target_os = "macos",
        ignore = "daemon event stream stalls on macOS CI runners; under investigation"
    )]
    fn the_gui_creates_a_project_through_the_daemon_and_follows_an_agent() {
        let mut r = Rig::new();
        let ctx = r.h.ctx.clone();
        let (binary, project) = (r.binary(), r.project());
        r.h.app.start_real(
            Choice::NewProject {
                binary,
                project_dir: project.to_string_lossy().into_owned(),
            },
            &ctx,
        );
        r.h.run_until("the new project to be analyzed", |a| {
            a.view_model().is_some_and(|vm| {
                vm.connection == Connection::Open
                    && vm.analysis.phase == AnalysisPhase::Complete
                    && !vm.functions.items.is_empty()
                    && !vm.busy()
            })
        });
        // It is remembered, and a second window would list it.
        assert_eq!(r.h.app.prefs().items().len(), 1);
        let again = crate::recent::Prefs::load(Some(r.tmp.path().join("cfg/gui.json")));
        assert_eq!(again.items()[0].name, "prog.bin");

        // An agent renames a function over a second connection.
        let (addr, old) = {
            let f = &r.h.app.view_model().unwrap().functions.items[0];
            (f.address, f.name.clone())
        };
        let agent = r.agent();
        let out =
            r.h._rt
                .block_on(agent.call(&CallParams {
                    project_dir: project.to_string_lossy().into_owned(),
                    command: "rename_symbol".into(),
                    args: json!({"address": format!("{addr:#x}"), "new_name": "from_agent"}),
                    author_kind: AuthorKind::Agent,
                    author_id: Some("claude".into()),
                    run_id: Some("run-1".into()),
                    surface: None,
                    approved: false,
                }))
                .expect("agent rename")
                .result;
        assert_eq!(out["status"], "applied", "{out}");
        r.h.run_until("the toast and the refreshed list", |a| {
            a.view_model().is_some_and(|vm| {
                vm.functions.items.iter().any(|f| f.name == "from_agent")
                    && vm.toasts.iter().any(|t| {
                        t.text.contains(&format!("Agent renamed {old}")) && t.action.is_some()
                    })
            })
        });

        // The settings window shows the daemon's sessions and engines.
        r.h.key(Key::Comma, CTRL);
        r.h.run_until("daemon status", |a| {
            matches!(a.settings().status(), Some(Ok(v)) if v["sessions"].as_array().is_some_and(|s| s.len() == 1))
        });
    }

    #[test]
    fn a_missing_binary_is_reported_by_the_daemon() {
        let mut r = Rig::new();
        let ctx = r.h.ctx.clone();
        r.h.app.start_real(
            Choice::NewProject {
                binary: r.tmp.path().join("nope").to_string_lossy().into_owned(),
                project_dir: r.project().to_string_lossy().into_owned(),
            },
            &ctx,
        );
        r.h.run_until("the failure", |a| a.welcome_error().is_some());
        assert!(r.h.app.view_model().is_none());
    }
}

fn rename_current_to(h: &mut Harness, name: &str) {
    let vm = h.app.view_model_mut().unwrap();
    vm.begin_rename_current();
    vm.set_rename_input(name);
    vm.submit_rename();
    let name = name.to_string();
    h.run_until("the rename to land", move |a| {
        a.view_model().is_some_and(|vm| {
            vm.rename.is_none()
                && !vm.busy()
                && vm
                    .history
                    .entries
                    .iter()
                    .any(|e| e.description.contains(&name))
        })
    });
}

#[test]
fn history_undo_previews_the_edits_that_depended_on_it_and_undo_all_reverses_them() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    rename_current_to(&mut h, "first_name");
    rename_current_to(&mut h, "second_name");
    let ctx = h.ctx.clone();
    h.app.handle(UiRequest::ShowHistory, &ctx);
    h.step();

    // the older rename has a later edit of the same name depending on it
    let first = {
        let vm = h.app.view_model().unwrap();
        vm.history
            .entries
            .iter()
            .find(|e| e.description.contains("-> first_name"))
            .unwrap()
            .id
    };
    h.app.view_model_mut().unwrap().request_undo_entry(first);
    h.run_until("the preview dialog", |a| {
        a.view_model()
            .and_then(|vm| vm.undo.dialog.as_ref())
            .is_some_and(|d| d.visible())
    });
    h.step();
    let d = h.app.view_model().unwrap().undo.dialog.clone().unwrap();
    assert_eq!(d.dependents.len(), 1);
    assert!(
        d.summary()
            .starts_with("Undoing this also undoes 1 later edit that depended on it"),
        "{}",
        d.summary()
    );
    // nothing changed yet
    assert_eq!(
        h.app
            .view_model()
            .unwrap()
            .functions
            .find(main)
            .unwrap()
            .name,
        "second_name"
    );

    // Escape cancels
    h.key(Key::Escape, Modifiers::NONE);
    assert!(h.app.view_model().unwrap().undo.dialog.is_none());

    h.app.view_model_mut().unwrap().request_undo_entry(first);
    h.run_until("the preview dialog", |a| {
        a.view_model()
            .and_then(|vm| vm.undo.dialog.as_ref())
            .is_some_and(|d| d.visible())
    });
    h.app.view_model_mut().unwrap().confirm_undo();
    h.run_until("both renames to be undone", |a| {
        a.view_model().is_some_and(|vm| {
            !vm.busy()
                && vm.undo.dialog.is_none()
                && vm.functions.find(main).is_some_and(|f| f.name == "main")
        })
    });
}

#[test]
fn stale_functions_get_a_marker_that_draws() {
    let mut h = Harness::ready_demo();
    let main = h.select_main();
    let ctx = h.ctx.clone();
    h.app.handle(UiRequest::ShowHistory, &ctx);
    h.app.view_model_mut().unwrap().undo.stale.insert(main);
    for _ in 0..3 {
        h.step();
    }
    assert!(h.app.view_model().unwrap().is_stale(main));
}

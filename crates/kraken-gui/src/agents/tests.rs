//! Headless tests of the Agents tab: whole frames are driven against the fake ACP agent, so
//! egui's own checks (clashing ids and the like) cover every kind of item.

use std::ffi::OsString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Context, RawInput, Rect, pos2};
use kraken_acp::{AgentPaths, AgentProfile, Platform, Resolver};
use kraken_viewmodel::agents::{
    AgentItem, AgentsConfig, PermissionState, SessionPhase, SetupState,
};
use kraken_viewmodel::testing::fake_agent;
use kraken_viewmodel::{AnalysisPhase, Connection};

use super::with_agents_tab;
use crate::app::KrakenApp;
use crate::args::{Options, RendererChoice, Scene};
use crate::assist::with_assistant_tab;
use crate::services::Services;
use crate::workspace::{self, Tab};

const WAIT: Duration = Duration::from_secs(25);

struct Harness {
    ctx: Context,
    app: KrakenApp,
    dir: tempfile::TempDir,
    _rt: Arc<tokio::runtime::Runtime>,
}

fn options() -> Options {
    Options {
        scene: Scene::Main,
        renderer: RendererChoice::Wgpu,
        demo: true,
        screenshot: None,
        light: false,
        no_daemon: false,
        open_project: None,
        function: None,
    }
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
        let app = KrakenApp::new(&ctx, rt.clone(), Services::offline(), &options());
        let mut h = Harness {
            ctx,
            app,
            dir: crate::testutil::tempdir(),
            _rt: rt,
        };
        h.run_until("the demo to finish analysis", |a| {
            a.view_model().is_some_and(|vm| {
                vm.connection == Connection::Open
                    && vm.analysis.phase == AnalysisPhase::Complete
                    && !vm.functions.items.is_empty()
                    && !vm.busy()
            })
        });
        let fake = fake_agent();
        let mut cfg = AgentsConfig::new(
            Resolver {
                paths: AgentPaths::in_data_dir(h.dir.path().join("data")),
                platform: Platform::new("linux", "x86_64"),
                path_env: Some(h.dir.path().as_os_str().to_owned()),
            },
            Some(h.dir.path().join("config")),
        );
        cfg.kraken_exe = Some("/opt/kraken/kraken".into());
        cfg.parent_env = Some(vec![(
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin"),
        )]);
        cfg.extra_profiles = vec![
            AgentProfile::custom("fake", "Fake agent", fake.to_string_lossy(), vec![])
                .allow_env("FAKE_ACP_*"),
        ];
        h.app.view_model_mut().expect("vm").agents_configure(cfg);
        h.app.pending_nav().bring_to_front = Some(Tab::Agents);
        h
    }

    fn step(&mut self) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1280.0, 800.0))),
            ..Default::default()
        };
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(input, |ui| app.frame(ui));
        out.textures_delta.clear();
    }

    fn run_until(&mut self, what: &str, cond: impl Fn(&KrakenApp) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !cond(&self.app) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            self.step();
            std::thread::sleep(Duration::from_millis(4));
        }
        for _ in 0..3 {
            self.step();
        }
    }

    fn vm(&mut self) -> &mut kraken_viewmodel::ViewModel {
        self.app.view_model_mut().expect("vm")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(vm) = self.app.view_model_mut() {
            vm.agents_close_session();
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn the_agents_tab_joins_the_assistant_pane() {
    let dock = with_agents_tab(with_assistant_tab(workspace::initial_dock()));
    let tree = dock.main_surface();
    let (assistant, _) = tree.find_tab(&Tab::Assistant).expect("assistant tab");
    let (agents, _) = tree.find_tab(&Tab::Agents).expect("agents tab");
    assert_eq!(assistant, agents);
    assert_eq!(Tab::Agents.title(), "Agents");
    let tip = Tab::Agents.tooltip();
    assert!(tip.ends_with('.') && tip.len() < 100, "{tip}");
}

#[test]
fn the_scene_parses() {
    let args: Vec<String> = ["--demo", "--screenshot", "x.png", "--scene", "agents"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match crate::args::parse(args).expect("parses") {
        crate::args::Parsed::Run(o) => assert_eq!(o.scene, Scene::Agents),
        crate::args::Parsed::Help => panic!("help"),
    }
}

#[test]
fn the_tab_lists_agents_and_shows_the_setup_consent() {
    let mut h = Harness::new();
    h.run_until("the agent list", |a| {
        a.view_model().is_some_and(|vm| vm.agents.loaded)
    });
    assert_eq!(h.vm().agents.rows.len(), 4);

    h.vm().agents_request_setup("claude");
    h.run_until("the consent card", |a| {
        a.view_model()
            .is_some_and(|vm| matches!(vm.agents.setup, SetupState::Confirm(_)))
    });
    h.vm().agents_dismiss_setup();
    for _ in 0..3 {
        h.step();
    }
    assert_eq!(h.vm().agents.setup, SetupState::Idle);
}

#[test]
fn the_warning_then_a_whole_session_draws_cleanly() {
    let mut h = Harness::new();
    h.run_until("the agent list", |a| {
        a.view_model().is_some_and(|vm| vm.agents.loaded)
    });

    h.vm().agents_start("fake");
    h.run_until("the warning", |a| {
        a.view_model()
            .is_some_and(|vm| vm.agents.pending_notice.is_some())
    });
    assert!(h.vm().agents.session.is_none());

    h.vm().agents_acknowledge();
    h.run_until("the agent to be ready", |a| {
        a.view_model().is_some_and(|vm| {
            vm.agents
                .session
                .as_ref()
                .is_some_and(|s| s.phase == SessionPhase::Ready)
        })
    });

    h.vm().agents_send("go");
    h.run_until("a permission request", |a| {
        a.view_model().is_some_and(|vm| {
            vm.agents
                .session
                .as_ref()
                .is_some_and(|s| s.waiting_permissions() == 1)
        })
    });
    let id = {
        let s = h.vm().agents.session.as_ref().expect("session");
        s.items
            .iter()
            .find_map(|i| match i {
                AgentItem::Permission(c) => Some(c.request.request_id),
                _ => None,
            })
            .expect("card")
    };
    h.vm().agents_answer_permission(id, true);
    h.run_until("the turn to end", |a| {
        a.view_model()
            .is_some_and(|vm| vm.agents.session.as_ref().is_some_and(|s| !s.busy))
    });
    assert!(
        h.vm()
            .agents
            .session
            .as_ref()
            .expect("session")
            .items
            .iter()
            .any(|i| matches!(i, AgentItem::Permission(c) if c.state == PermissionState::Allowed))
    );

    // The agent dies: the ended state draws, and Back returns to the list.
    h.vm().agents_send("die");
    h.run_until("the session to end", |a| {
        a.view_model().is_some_and(|vm| {
            vm.agents
                .session
                .as_ref()
                .is_some_and(|s| matches!(s.phase, SessionPhase::Ended(_)))
        })
    });
    h.vm().agents_close_session();
    h.run_until("the list again", |a| {
        a.view_model().is_some_and(|vm| vm.agents.session.is_none())
    });
}

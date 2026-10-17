//! Headless tests of the assistant's windows: whole frames are driven with a scripted model, so
//! egui's own checks (clashing ids and the like) cover every kind of conversation item.

use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Context, Event, Key, Modifiers, RawInput, Rect, pos2};
use kraken_viewmodel::assist::script::{answer, say, tool_call};
use kraken_viewmodel::assist::{
    AutoNameState, ChatItem, OverviewOffer, ProposalState, ProviderKind, scripted_provider,
};
use kraken_viewmodel::{AnalysisPhase, Connection};
use serde_json::json;

use super::menu::MenuState;
use super::{AssistRequest, AssistSetup, with_assistant_tab};
use crate::app::KrakenApp;
use crate::args::{Options, RendererChoice, Scene};
use crate::services::Services;
use crate::workspace::{self, Tab};

const WAIT: Duration = Duration::from_secs(20);

pub(super) struct Harness {
    pub(super) ctx: Context,
    pub(super) app: KrakenApp,
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
    pub(super) fn new(services: Services) -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let ctx = Context::default();
        crate::fonts::install(&ctx);
        let app = KrakenApp::new(&ctx, rt.clone(), services, &options());
        let mut h = Harness { ctx, app, _rt: rt };
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

    pub(super) fn step_with(&mut self, events: Vec<Event>) {
        let input = RawInput {
            screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1280.0, 800.0))),
            events,
            ..Default::default()
        };
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(input, |ui| app.frame(ui));
        out.textures_delta.clear();
    }

    pub(super) fn step(&mut self) {
        self.step_with(Vec::new());
    }

    pub(super) fn run_until(&mut self, what: &str, cond: impl Fn(&KrakenApp) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !cond(&self.app) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            self.step();
            std::thread::sleep(Duration::from_millis(4));
        }
    }

    pub(super) fn settle(&mut self) {
        self.run_until("the assistant to finish", |a| {
            a.view_model()
                .is_some_and(|vm| !vm.assist.busy() && !vm.busy())
        });
        for _ in 0..3 {
            self.step();
        }
    }

    fn provide(&mut self, script: Vec<Vec<kraken_agent::StreamEvent>>) {
        let (p, b) = scripted_provider(script, "test-model");
        self.app
            .view_model_mut()
            .expect("vm")
            .assist
            .set_provider(p, b);
    }
}

fn temp_config() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = crate::testutil::tempdir();
    let path = dir.path().join("kraken/config.toml");
    (dir, path)
}

#[test]
fn the_assistant_tab_joins_the_hex_pane_with_room_to_read() {
    let dock = with_assistant_tab(workspace::initial_dock());
    let tree = dock.main_surface();
    let (hex, _) = tree.find_tab(&Tab::Hex).expect("hex tab");
    let (assistant, _) = tree.find_tab(&Tab::Assistant).expect("assistant tab");
    assert_eq!(hex, assistant);
    assert!(Tab::Assistant.tooltip().contains("assistant"));
    assert_eq!(Tab::Assistant.title(), "Assistant");
}

#[test]
fn the_new_scenes_parse() {
    for (name, scene) in [
        ("assistant", Scene::Assistant),
        ("explain", Scene::Explain),
        ("autoname", Scene::AutoName),
        ("assistant-agent", Scene::AssistantAgent),
    ] {
        let args: Vec<String> = ["--demo", "--screenshot", "x.png", "--scene", name]
            .iter()
            .map(|s| s.to_string())
            .collect();
        match crate::args::parse(args).expect("parses") {
            crate::args::Parsed::Run(o) => assert_eq!(o.scene, scene),
            crate::args::Parsed::Help => panic!("help"),
        }
    }
}

#[test]
fn every_kind_of_conversation_item_draws_and_the_tab_comes_to_the_front() {
    let mut h = Harness::new(Services::offline());
    // The banner is offered after the first analysis and draws without a model.
    assert_eq!(
        h.app.view_model().expect("vm").assist.overview_offer,
        OverviewOffer::Offered
    );
    for _ in 0..3 {
        h.step();
    }

    // Empty state first: no model.
    h.app.view_model_mut().expect("vm").assist_send("hello");
    h.step();
    h.step();
    assert!(
        !h.app.view_model().expect("vm").assist.show_requested,
        "the window consumed the request"
    );

    // A person-named function makes the assistant's rename a proposal.
    {
        let vm = h.app.view_model_mut().expect("vm");
        vm.begin_rename(0x401340, None);
        assert!(vm.block_until_idle(WAIT));
        vm.set_rename_input("my_name");
        vm.submit_rename();
        assert!(vm.block_until_idle(WAIT));
    }
    h.provide(vec![
        tool_call("c1", "decompile", json!({"address": "0x401340"})),
        tool_call(
            "c2",
            "rename_symbol",
            json!({"address": "0x401340", "new_name": "assistant_guess"}),
        ),
        say("I looked at `0x401340`, see 0x401340 and 0x4011a0."),
    ]);
    h.app
        .view_model_mut()
        .expect("vm")
        .assist_send("What is 0x401340?");
    h.settle();
    {
        let vm = h.app.view_model().expect("vm");
        assert!(
            vm.assist
                .items
                .iter()
                .any(|i| matches!(i, ChatItem::Proposal(c) if c.state == ProposalState::Waiting))
        );
    }
    h.step();

    // Explanation card, overview card, notice and error.
    h.provide(vec![answer(
        "ok",
        &json!({"summary": "It stops the program.", "key_behaviours": ["exits"],
                    "suggested_names": [{"name": "stop_now", "reason": "it exits"}],
                    "caveats": ["`unsure`"]}),
    )]);
    h.app
        .view_model_mut()
        .expect("vm")
        .assist_explain_function(0x401340);
    h.settle();
    h.provide(vec![answer(
        "ok",
        &json!({"what_it_is": "A tool.", "components": [{"name": "a", "description": "b"}],
                "interesting_functions": [{"address": "0x401000", "name": "main", "reason": "start"}],
                "next_steps": ["read main"]}),
    )]);
    h.app.view_model_mut().expect("vm").assist_overview();
    h.settle();
    let vm = h.app.view_model().expect("vm");
    assert!(
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Explanation(_)))
    );
    assert!(
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Overview(_)))
    );
    assert_eq!(vm.assist.overview_offer, OverviewOffer::Hidden);

    // Learn mode adds the "?" tab hints and still draws.
    h.app.view_model_mut().expect("vm").assist.learn_mode = true;
    for _ in 0..3 {
        h.step();
    }
}

#[test]
fn a_clicked_address_in_the_conversation_opens_that_function() {
    let mut h = Harness::new(Services::offline());
    h.app.pending_nav().assist.goto = Some(0x4011a0);
    // The panel only follows links while it is drawn; give it a conversation to draw.
    h.provide(vec![say("Look at 0x4011a0.")]);
    h.app.view_model_mut().expect("vm").assist_send("where?");
    h.settle();
    h.app.pending_nav().assist.goto = Some(0x4011a0);
    for _ in 0..3 {
        h.step();
    }
    h.run_until("the function to open", |a| {
        a.view_model()
            .and_then(|vm| vm.current.as_ref())
            .is_some_and(|c| c.address == 0x4011a0)
    });
}

#[test]
fn auto_name_review_window_draws_while_running_and_when_ready() {
    let mut h = Harness::new(Services::offline());
    h.provide(vec![
        tool_call("c1", "list_functions", json!({"name_filter": "FUN_"})),
        answer(
            "ok",
            &json!({"suggestions": [{
                "address": "0x401340", "current_name": "FUN_00401340", "new_name": "stop_now",
                "evidence": [{"kind": "string", "detail": "out of memory"}, {"kind": "import", "detail": "exit"}]
            }]}),
        ),
    ]);
    h.app.view_model_mut().expect("vm").assist_auto_name(5);
    h.step();
    assert!(matches!(
        h.app.view_model().expect("vm").assist.autoname,
        AutoNameState::Running
    ));
    h.settle();
    assert!(matches!(
        h.app.view_model().expect("vm").assist.autoname,
        AutoNameState::Review(_)
    ));
    // Closing the window with Escape is not wired (it has a Close button); closing through the
    // view-model leaves the review gone.
    h.app.view_model_mut().expect("vm").autoname_close();
    h.step();
    assert_eq!(
        h.app.view_model().expect("vm").assist.autoname,
        AutoNameState::Idle
    );
}

#[test]
fn the_explain_menu_closes_on_escape() {
    let mut h = Harness::new(Services::offline());
    h.app.pending_nav().assist.menu = Some(MenuState {
        pos: pos2(200.0, 200.0),
        token: Some("helper".into()),
        line: Some("helper(argc);".into()),
        line_kind: kraken_viewmodel::assist::SelectionKind::Decompile,
        function: Some(0x401000),
    });
    h.step();
    h.step();
    assert!(h.app.pending_nav().assist.menu.is_some());
    h.step_with(vec![Event::Key {
        key: Key::Escape,
        physical_key: Some(Key::Escape),
        pressed: true,
        repeat: false,
        modifiers: Modifiers::NONE,
    }]);
    assert!(h.app.pending_nav().assist.menu.is_none());
}

#[test]
fn one_click_presets_save_to_config_toml_and_activate() {
    let (_dir, path) = temp_config();
    let mut services = Services::offline();
    services.config_path = Some(path.clone());
    let mut h = Harness::new(services);
    assert!(!h.app.assist_setup().is_ready(), "nothing saved yet");

    h.app
        .pending_nav()
        .assist
        .requests
        .push(AssistRequest::UsePreset(ProviderKind::Ollama));
    h.step();
    assert!(h.app.assist_setup().is_ready());
    let vm = h.app.view_model().expect("vm");
    let badge = vm.assist.badge().expect("a backend on the open project");
    assert!(badge.local && !badge.terminal_agent);
    assert_eq!(badge.service, "Ollama");
    let text = std::fs::read_to_string(&path).expect("config written");
    assert!(
        text.contains("[provider]") && text.contains("11434"),
        "{text}"
    );

    // A new app over the same file picks it up on its own.
    let again = AssistSetup::load(Some(path));
    assert!(again.is_ready());

    // The settings request opens the window on the AI section.
    h.app
        .pending_nav()
        .assist
        .requests
        .push(AssistRequest::OpenSettings(Some(ProviderKind::Anthropic)));
    h.step();
    h.step();
    assert!(h.app.settings().open);
    assert_eq!(h.app.settings().ai.draft().kind, ProviderKind::Anthropic);
}

#[cfg(unix)]
#[test]
fn saving_a_pasted_key_from_the_settings_form_keeps_it_out_of_config_toml() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, path) = temp_config();
    let mut ai = super::AiSettings::default();
    ai.preset(ProviderKind::Anthropic);
    let secret = "sk-ant-form-secret-value";
    ai.draft_mut().key_paste = secret.into();
    ai.save(Some(&path));
    assert!(matches!(ai.take_change(), Some(super::Change::Use(..))));
    assert!(
        ai.draft().key_paste.is_empty(),
        "the pasted text is not kept in the form"
    );
    let config = std::fs::read_to_string(&path).expect("config");
    assert!(!config.contains(secret));
    let secrets = path.parent().expect("dir").join("secrets.toml");
    let mode = std::fs::metadata(&secrets)
        .expect("secrets")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    assert!(
        std::fs::read_to_string(&secrets)
            .expect("read")
            .contains(secret)
    );

    // Problems come back as text, not panics.
    let mut bad = super::AiSettings::default();
    bad.preset(ProviderKind::OpenAiCompatible);
    bad.save(Some(&path));
    assert!(bad.take_change().is_none());
}

#[test]
fn the_settings_window_has_an_ai_section_that_loads_the_saved_provider() {
    let (_dir, path) = temp_config();
    let store = kraken_viewmodel::assist::ProviderStore::new(Some(path.clone()));
    store
        .save(&kraken_viewmodel::assist::ProviderDraft::preset(
            ProviderKind::LmStudio,
        ))
        .expect_err("LM Studio needs a model name first");
    let mut d = kraken_viewmodel::assist::ProviderDraft::preset(ProviderKind::LmStudio);
    d.model = "my-model".into();
    store.save(&d).expect("save");

    let mut services = Services::offline();
    services.config_path = Some(path);
    let mut h = Harness::new(services);
    h.step_with(vec![Event::Key {
        key: Key::Comma,
        physical_key: Some(Key::Comma),
        pressed: true,
        repeat: false,
        modifiers: Modifiers {
            ctrl: true,
            command: true,
            ..Modifiers::NONE
        },
    }]);
    h.step();
    h.step();
    assert!(h.app.settings().open);
    assert_eq!(h.app.settings().ai.draft().kind, ProviderKind::LmStudio);
    assert_eq!(h.app.settings().ai.draft().model, "my-model");
}

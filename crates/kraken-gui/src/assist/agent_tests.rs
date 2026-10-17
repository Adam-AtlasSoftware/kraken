//! Headless tests of the assistant on a terminal agent: whole frames are driven against the fake
//! ACP agent, from picking the agent in Settings to a whole conversation, so egui's own checks
//! (clashing ids and the like) cover every kind of item.

use std::ffi::OsString;
use std::path::PathBuf;

use kraken_acp::{AgentPaths, AgentProfile, Platform, Resolver};
use kraken_viewmodel::agents::{AgentsConfig, SetupState};
use kraken_viewmodel::assist::{ChatItem, PermissionState, ProviderKind};
use kraken_viewmodel::testing::fake_agent;

use super::tests::Harness;
use super::{AssistRequest, Change};
use crate::services::Services;

/// A harness whose agents are the fake one (plus the built-in ones, not installed), with a
/// config file to save into.
fn harness() -> (Harness, tempfile::TempDir, PathBuf) {
    let dir = crate::testutil::tempdir();
    let config_path = dir.path().join("kraken/config.toml");
    let mut services = Services::offline();
    services.config_path = Some(config_path.clone());
    let mut h = Harness::new(services);
    let mut cfg = AgentsConfig::new(
        Resolver {
            paths: AgentPaths::in_data_dir(dir.path().join("data")),
            platform: Platform::new("linux", "x86_64"),
            path_env: Some(dir.path().as_os_str().to_owned()),
        },
        Some(dir.path().join("kraken")),
    );
    cfg.kraken_exe = Some("/opt/kraken/kraken".into());
    cfg.parent_env = Some(vec![(
        OsString::from("PATH"),
        OsString::from("/usr/bin:/bin"),
    )]);
    cfg.extra_profiles = vec![
        AgentProfile::custom("fake", "Fake agent", fake_agent().to_string_lossy(), vec![])
            .allow_env("FAKE_ACP_*"),
    ];
    h.app
        .settings_mut()
        .ai
        .hub_mut()
        .expect("hub")
        .configure(cfg);
    (h, dir, config_path)
}

fn open_settings(h: &mut Harness) {
    h.app
        .pending_nav()
        .assist
        .requests
        .push(AssistRequest::OpenSettings(Some(
            ProviderKind::TerminalAgent,
        )));
    h.step();
    h.step();
    assert!(h.app.settings().open);
}

fn permission_waiting(h: &Harness) -> Option<String> {
    h.app
        .view_model()?
        .assist
        .items
        .iter()
        .find_map(|i| match i {
            ChatItem::Permission(c) if c.state == PermissionState::Waiting => Some(c.id.clone()),
            _ => None,
        })
}

#[test]
fn the_settings_list_models_and_agents_in_one_picker_and_run_the_setup_consent() {
    let (mut h, _dir, _config) = harness();
    open_settings(&mut h);
    h.run_until("the agent list", |a| {
        a.settings().ai.hub().is_some_and(|hub| hub.loaded)
    });
    {
        let hub = h.app.settings().ai.hub().expect("hub");
        let ids: Vec<_> = hub.rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["claude", "codex", "gemini", "fake"]);
    }
    // The agent form draws: availability, the notice, the model fields.
    assert_eq!(
        h.app.settings().ai.draft().kind,
        ProviderKind::TerminalAgent
    );
    for _ in 0..3 {
        h.step();
    }

    // Set up asks first, and says what it would download.
    {
        let hub = h.app.settings_mut().ai.hub_mut().expect("hub");
        hub.request_setup("claude");
        assert!(matches!(hub.setup, SetupState::Confirm(_)));
    }
    for _ in 0..3 {
        h.step();
    }
    {
        let hub = h.app.settings_mut().ai.hub_mut().expect("hub");
        hub.dismiss_setup();
        assert_eq!(hub.setup, SetupState::Idle);
    }
    h.step();
}

#[test]
fn picking_an_agent_in_settings_makes_it_the_assistant_and_a_conversation_draws_cleanly() {
    let (mut h, _dir, config) = harness();
    open_settings(&mut h);
    h.run_until("the agent list", |a| {
        a.settings().ai.hub().is_some_and(|hub| hub.loaded)
    });
    assert!(!h.app.assist_setup().is_ready());

    // Pick the fake agent and save: the same table the CLI reads.
    {
        let ai = &mut h.app.settings_mut().ai;
        ai.preset(ProviderKind::TerminalAgent);
        ai.draft_mut().agent = "fake".into();
        ai.save(Some(&config));
    }
    h.step();
    h.step();
    assert!(h.app.assist_setup().is_agent());
    let text = std::fs::read_to_string(&config).expect("config written");
    assert!(
        text.contains("kind = \"terminal_agent\"") && text.contains("agent = \"fake\""),
        "{text}"
    );
    {
        let vm = h.app.view_model().expect("vm");
        let badge = vm.assist.badge().expect("badge");
        assert!(badge.terminal_agent);
        assert_eq!(badge.service, "Fake agent");
        assert!(vm.assist.agent_notice_pending(), "the note comes first");
    }
    // The note is shown above the chat; reading it is a request from the panel.
    h.app.view_model_mut().expect("vm").assist_send("too early");
    h.step();
    assert!(!h.app.view_model().expect("vm").assist.busy());
    h.app
        .pending_nav()
        .assist
        .requests
        .push(AssistRequest::AcknowledgeAgents);
    h.step();
    h.step();
    assert!(
        !h.app
            .view_model()
            .expect("vm")
            .assist
            .agent_notice_pending()
    );

    // The assistant works exactly as with a model: send, tool chips, an approval card.
    h.app.view_model_mut().expect("vm").assist_send("go");
    h.run_until("a permission card", |a| permission_waiting_app(a).is_some());
    for _ in 0..3 {
        h.step();
    }
    let id = permission_waiting(&h).expect("card");
    h.app
        .view_model_mut()
        .expect("vm")
        .assist_answer_permission(&id, true);
    h.settle();
    {
        let vm = h.app.view_model().expect("vm");
        assert!(
            vm.assist.items.iter().any(
                |i| matches!(i, ChatItem::Permission(c) if c.state == PermissionState::Allowed)
            )
        );
        assert_eq!(vm.assist.badge().expect("badge").model, "Fake model 1");
    }

    // An explanation card from the same agent.
    h.app
        .view_model_mut()
        .expect("vm")
        .assist_explain_function(0x401340);
    h.settle();
    assert!(
        h.app
            .view_model()
            .expect("vm")
            .assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Explanation(_) | ChatItem::Error(_)))
    );
    for _ in 0..3 {
        h.step();
    }
}

fn permission_waiting_app(a: &crate::app::KrakenApp) -> Option<String> {
    a.view_model()?.assist.items.iter().find_map(|i| match i {
        ChatItem::Permission(c) if c.state == PermissionState::Waiting => Some(c.id.clone()),
        _ => None,
    })
}

#[test]
fn switching_back_to_a_model_replaces_the_agent() {
    let (mut h, _dir, config) = harness();
    open_settings(&mut h);
    {
        let ai = &mut h.app.settings_mut().ai;
        ai.preset(ProviderKind::TerminalAgent);
        ai.draft_mut().agent = "fake".into();
        ai.save(Some(&config));
    }
    h.step();
    assert!(h.app.assist_setup().is_agent());
    {
        let ai = &mut h.app.settings_mut().ai;
        ai.preset(ProviderKind::Ollama);
        ai.save(Some(&config));
    }
    h.step();
    h.step();
    assert!(!h.app.assist_setup().is_agent());
    assert!(h.app.assist_setup().is_ready());
    let badge = h
        .app
        .view_model()
        .expect("vm")
        .assist
        .badge()
        .expect("badge");
    assert!(!badge.terminal_agent);
    assert_eq!(badge.service, "Ollama");
    assert!(!matches!(
        h.app.settings_mut().ai.take_change(),
        Some(Change::Clear)
    ));
}

#[test]
fn a_saved_agent_is_picked_up_at_startup() {
    let (_h, _dir, config) = harness();
    std::fs::create_dir_all(config.parent().expect("dir")).expect("mkdir");
    std::fs::write(
        &config,
        "[provider]\nkind = \"terminal_agent\"\nagent = \"codex\"\nmodel = \"gpt-5\"\n",
    )
    .expect("config");
    let again = super::AssistSetup::load(Some(config));
    assert!(again.is_ready() && again.is_agent());
}

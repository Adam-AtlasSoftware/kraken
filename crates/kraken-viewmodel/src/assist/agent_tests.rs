//! The assistant on a terminal agent: the real ACP host against `kraken-fake-acp-agent` (a
//! separate process speaking raw ACP). The same view-model methods, items and cards as with a
//! model API; no network, no real agents, no real daemon.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use kraken_acp::{AgentPaths, AgentProfile, Platform, Resolver};
use serde_json::json;
use tokio::runtime::Runtime;

use super::script::{say, scripted_provider, tool_call};
use super::*;
use crate::agents::{AgentEnv, AgentsConfig};
use crate::demo::{demo_fixture, demo_project_with};
use crate::state::{AnalysisPhase, Connection};
use crate::testing::fake_agent;
use crate::vm::ViewModel;

const WAIT: Duration = Duration::from_secs(30);

struct Rig {
    _rt: Runtime,
    _dir: tempfile::TempDir,
    vm: ViewModel,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.vm.assist.close_engine();
        // Let the agent process end before the runtime goes away.
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn base_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/home/test")),
    ]
}

fn env_with(dir: &std::path::Path, acknowledged: bool, extra: &[(&str, &str)]) -> AgentEnv {
    let mut profile =
        AgentProfile::custom("fake", "Fake agent", fake_agent().to_string_lossy(), vec![]);
    for (k, v) in extra {
        profile = profile.with_env(*k, *v);
    }
    let resolver = Resolver {
        paths: AgentPaths::in_data_dir(dir.join("data")),
        platform: Platform::new("linux", "x86_64"),
        path_env: Some(dir.join("bin").into_os_string()),
    };
    let mut config = AgentsConfig::new(resolver, Some(dir.join("config")));
    config.kraken_exe = Some(PathBuf::from("/opt/kraken/kraken"));
    config.parent_env = Some(base_env());
    config.extra_profiles = vec![profile];
    config.start_timeout = WAIT;
    AgentEnv {
        config,
        acknowledged,
    }
}

fn agent_badge() -> ProviderBadge {
    ProviderBadge {
        service: "Fake agent".into(),
        model: String::new(),
        local: false,
        terminal_agent: true,
    }
}

fn choose_fake(vm: &mut ViewModel) {
    vm.assist.set_backend(
        BackendChoice::Agent(AgentChoice {
            agent: "fake".into(),
            model: None,
            args: Vec::new(),
        }),
        agent_badge(),
    );
}

fn rig_with(extra: &[(&str, &str)], acknowledged: bool) -> Rig {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::from_millis(1)).expect("demo");
    let mut vm = ViewModel::new(d.backend.clone(), rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    vm.start_analysis();
    assert!(vm.block_until(WAIT, |vm| {
        vm.analysis.phase == AnalysisPhase::Complete && !vm.busy()
    }));
    let dir = tempfile::tempdir().expect("tempdir");
    vm.assist.agent_env = Some(env_with(dir.path(), acknowledged, extra));
    choose_fake(&mut vm);
    Rig {
        _rt: rt,
        _dir: dir,
        vm,
    }
}

fn rig() -> Rig {
    rig_with(&[], true)
}

impl Rig {
    fn until(&mut self, what: &str, cond: impl Fn(&ViewModel) -> bool) {
        assert!(
            self.vm.block_until(WAIT, cond),
            "timed out waiting for {what}; items: {:#?}",
            self.vm.assist.items
        );
    }

    fn settle(&mut self) {
        self.until("the assistant to finish", |vm| {
            !vm.assist.busy() && !vm.busy()
        });
    }

    fn permission(&self) -> Option<PermissionCard> {
        self.vm.assist.items.iter().find_map(|i| match i {
            ChatItem::Permission(c) => Some(c.clone()),
            _ => None,
        })
    }

    fn text(&self) -> String {
        self.vm
            .assist
            .items
            .iter()
            .filter_map(|i| match i {
                ChatItem::Assistant { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }

    fn tools(&self) -> Vec<ToolChip> {
        self.vm
            .assist
            .items
            .iter()
            .filter_map(|i| match i {
                ChatItem::Tool(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }
}

// ------------------------------------------------------------------ chat

#[test]
fn chat_runs_on_the_agent_and_its_own_tools_ask_first() {
    let mut r = rig();
    r.vm.assist_send("Hello");
    assert!(r.vm.assist.busy());
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });

    // The agent's own shell tool is a chip marked as outside KRAKEN, with a card asking.
    let chip = r.tools().into_iter().next().expect("a tool chip");
    assert_eq!(chip.name, "Run rm -rf build");
    assert!(chip.own_tool);
    let card = r.permission().expect("card");
    assert_eq!(card.state, PermissionState::Waiting);
    assert_eq!(card.title, "Run rm -rf build");
    assert_eq!(card.kind.as_deref(), Some("execute"));
    assert!(
        card.input.as_deref().is_some_and(|i| i.contains("rm -rf")),
        "{card:?}"
    );
    assert!(r.vm.assist.busy(), "the run waits for the person");

    r.vm.assist_answer_permission(&card.id, true);
    assert_eq!(
        r.permission().expect("card").state,
        PermissionState::Allowed
    );
    r.settle();
    assert!(r.text().contains("permission granted."), "{}", r.text());
    // The conversation is remembered for the next question, as with a model API.
    assert_eq!(r.vm.assist.history.len(), 2);
}

#[test]
fn denying_a_permission_tells_the_agent_no() {
    let mut r = rig();
    r.vm.assist_send("Hello");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    let id = r.permission().expect("card").id;
    r.vm.assist_answer_permission(&id, false);
    r.settle();
    assert_eq!(r.permission().expect("card").state, PermissionState::Denied);
    assert!(r.text().contains("permission denied."), "{}", r.text());
}

#[test]
fn stop_withdraws_a_waiting_request_and_the_chat_stays_usable() {
    let mut r = rig();
    r.vm.assist_send("Hello");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    r.vm.assist_stop();
    r.settle();
    assert_eq!(
        r.permission().expect("card").state,
        PermissionState::Withdrawn
    );
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Notice(n) if n == "Stopped.")),
        "{:?}",
        r.vm.assist.items
    );
    // The same session answers the next question.
    r.vm.assist_send("Again");
    r.until("the second permission request", |vm| {
        vm.assist
            .items
            .iter()
            .filter(|i| matches!(i, ChatItem::Permission(_)))
            .count()
            == 2
    });
    let id = match r.vm.assist.items.iter().rev().find_map(|i| match i {
        ChatItem::Permission(c) => Some(c.id.clone()),
        _ => None,
    }) {
        Some(id) => id,
        None => panic!("no card"),
    };
    r.vm.assist_answer_permission(&id, true);
    r.settle();
}

#[test]
fn kraken_tool_calls_look_like_the_api_paths_and_edits_refresh_the_window() {
    let mut r = rig_with(&[("FAKE_ACP_SCRIPT", "kraken")], true);
    r.vm.assist_send("Name the error handler");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    let tools = r.tools();
    let names: Vec<_> = tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        ["decompile", "rename_symbol", "Run strings -n 8 ./sample"]
    );
    assert!(!tools[0].own_tool && !tools[1].own_tool);
    assert!(tools[2].own_tool);
    assert!(tools[0].args_short.contains("0x401340"), "{:?}", tools[0]);
    assert!(tools[1].summary.is_some() && !tools[1].is_error);
    let id = r.permission().expect("card").id;
    r.vm.assist_answer_permission(&id, false);
    r.settle();
    assert!(r.text().contains("did not run the command"), "{}", r.text());
}

#[test]
fn the_badge_names_the_agent_and_the_model_it_reports() {
    let mut r = rig();
    let b = r.vm.assist.badge().expect("badge");
    assert!(b.terminal_agent);
    assert_eq!(b.service, "Fake agent");
    assert_eq!(b.model, "", "unknown until the agent has started");
    r.vm.assist_send("Hello");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    assert_eq!(r.vm.assist.badge().expect("badge").model, "Fake model 1");
    assert!(b.privacy().contains("outside KRAKEN's safety net"));
    r.vm.assist_stop();
    r.settle();
}

// ------------------------------------------------------------------ tasks

#[test]
fn explain_function_becomes_the_same_card_on_the_agent() {
    let mut r = rig();
    r.vm.assist_explain_function(0x4011a0);
    r.settle();
    let card = r.vm.assist.items.iter().find_map(|i| match i {
        ChatItem::Explanation(c) => Some(c.clone()),
        _ => None,
    });
    let card = card.unwrap_or_else(|| panic!("no card: {:#?}", r.vm.assist.items));
    assert_eq!(card.address, Some(0x4011a0));
    assert_eq!(card.summary, "It calls a helper and returns its answer.");
    assert_eq!(card.suggested_names[0].0, "program_main");
    let names: Vec<_> = r.tools().iter().map(|t| t.name.clone()).collect();
    assert_eq!(names, ["get_function", "decompile"]);
}

#[test]
fn explain_selection_and_overview_run_on_the_agent_too() {
    let mut r = rig();
    r.vm.assist_explain_selection(SelectionKind::Decompile, "x = helper(1);", Some(0x4011a0));
    r.settle();
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Explanation(c) if c.summary.contains("helper"))),
        "{:#?}",
        r.vm.assist.items
    );
    r.vm.assist_overview();
    r.settle();
    let card = r.vm.assist.items.iter().find_map(|i| match i {
        ChatItem::Overview(c) => Some(c.clone()),
        _ => None,
    });
    let card = card.unwrap_or_else(|| panic!("no overview: {:#?}", r.vm.assist.items));
    assert_eq!(card.what_it_is, "A small command-line program.");
    assert_eq!(card.interesting.len(), 1);
}

#[test]
fn auto_name_reviews_first_on_the_agent_too() {
    let mut r = rig();
    r.vm.assist_auto_name(2);
    assert!(matches!(r.vm.assist.autoname, AutoNameState::Running));
    r.settle();
    let AutoNameState::Review(rev) = &r.vm.assist.autoname else {
        panic!("expected a review: {:?}", r.vm.assist.autoname);
    };
    assert_eq!(rev.rows.len(), 2);
    assert_eq!(rev.rows[0].new_name.as_deref(), Some("program_main"));
    assert!(rev.rows.iter().all(|row| row.status == RowStatus::Pending));
}

#[test]
fn a_task_asks_for_the_agents_own_tools_through_the_same_cards() {
    let mut r = rig_with(&[("FAKE_ACP_TASK_PERMISSION", "1")], true);
    r.vm.assist_overview();
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    let card = r.permission().expect("card");
    assert_eq!(card.title, "Run strings ./sample");
    r.vm.assist_answer_permission(&card.id, false);
    r.settle();
    assert_eq!(r.permission().expect("card").state, PermissionState::Denied);
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Overview(_)))
    );
}

// ------------------------------------------------------------------ switching and gating

#[test]
fn switching_between_a_model_and_an_agent_keeps_the_conversation_and_ends_the_session() {
    let mut r = rig();
    // Start on the agent.
    r.vm.assist_send("Hello");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    let id = r.permission().expect("card").id;
    r.vm.assist_answer_permission(&id, true);
    r.settle();
    assert!(r.vm.assist.backend.as_ref().is_some_and(|b| b.is_agent()));
    let before = r.vm.assist.items.len();

    // Switch to a scripted model API: the agent's session ends, the screen stays.
    let (p, badge) = scripted_provider(
        vec![
            tool_call("m1", "get_function", json!({"address": "0x4011a0"})),
            say("From the model."),
        ],
        "scripted-model",
    );
    r.vm.assist.set_provider(p, badge);
    assert!(r.vm.assist.backend.as_ref().is_some_and(|b| !b.is_agent()));
    assert_eq!(r.vm.assist.items.len(), before);
    assert_eq!(r.vm.assist.badge().expect("badge").model, "scripted-model");
    r.vm.assist_send("And now?");
    r.settle();
    assert!(r.text().contains("From the model."), "{}", r.text());
    // The model's tool chip is never marked as one of an agent's own tools.
    let last = r.tools().pop().expect("a tool chip");
    assert_eq!(last.name, "get_function");
    assert!(!last.own_tool);

    // Back to the agent: a new session, caught up from the conversation.
    choose_fake(&mut r.vm);
    assert!(r.vm.assist.backend.as_ref().is_some_and(|b| b.is_agent()));
    assert_eq!(r.vm.assist.badge().expect("badge").model, "");
    r.vm.assist_send("Back again");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .filter(|i| matches!(i, ChatItem::Permission(_)))
            .count()
            == 2
    });
    r.vm.assist_stop();
    r.settle();
}

#[test]
fn an_agent_waits_for_the_one_time_notice_and_says_why() {
    let mut r = rig_with(&[], false);
    assert!(r.vm.assist.agent_notice_pending());
    r.vm.assist_send("Hello");
    assert!(!r.vm.assist.busy(), "nothing starts before the notice");
    assert!(
        matches!(
            r.vm.assist.items.last(),
            Some(ChatItem::Error(e)) if e.contains("note about terminal agents")
        ),
        "{:?}",
        r.vm.assist.items
    );
    // Once it is read, the same question runs.
    r.vm.assist.agent_env.as_mut().expect("env").acknowledged = true;
    assert!(!r.vm.assist.agent_notice_pending());
    r.vm.assist_send("Hello");
    assert!(r.vm.assist.busy());
    r.vm.assist_stop();
    r.settle();
}

#[test]
fn an_agent_that_is_not_set_up_is_explained_in_the_chat() {
    let mut r = rig();
    r.vm.assist.set_backend(
        BackendChoice::Agent(AgentChoice {
            agent: "claude".into(),
            model: None,
            args: Vec::new(),
        }),
        ProviderBadge {
            service: "Claude Code".into(),
            ..agent_badge()
        },
    );
    r.vm.assist_send("Hello");
    assert!(!r.vm.assist.busy());
    assert!(
        matches!(
            r.vm.assist.items.last(),
            Some(ChatItem::Error(e)) if e.contains("Claude Code") && e.contains("Set up")
        ),
        "{:?}",
        r.vm.assist.items
    );
}

#[test]
fn an_agent_that_needs_a_login_ends_with_a_plain_reason() {
    let mut r = rig_with(&[("FAKE_ACP_REQUIRE_AUTH", "1")], true);
    r.vm.assist_send("Hello");
    r.settle();
    assert!(
        matches!(
            r.vm.assist.items.last(),
            Some(ChatItem::Error(e)) if e.contains("sign in")
        ),
        "{:?}",
        r.vm.assist.items
    );
}

#[test]
fn changing_project_ends_the_agents_session() {
    let mut r = rig();
    r.vm.assist_send("Hello");
    r.until("the permission request", |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    });
    r.vm.assist.reset_for_project();
    assert!(!r.vm.assist.busy());
    assert!(
        r.vm.assist
            .backend
            .as_ref()
            .is_some_and(|b| b.engine.is_none()),
        "the next question starts a new session on the new project"
    );
    assert!(r.vm.assist.backend.is_some(), "the choice itself is kept");
}

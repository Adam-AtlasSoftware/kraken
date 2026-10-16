//! Agents tab tests: the real ACP host against `kraken-fake-acp-agent` (a separate process
//! speaking raw ACP). No network, no real agents, no real daemon.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use kraken_acp::{AgentPaths, AgentProfile, NoticeStore, Platform, Resolver};
use kraken_host::provision::{Fetched, Fetcher, ProvisionError};
use tokio::runtime::Runtime;

use super::*;
use crate::demo::{demo_fixture, demo_project_with};
use crate::state::Connection;
use crate::vm::ViewModel;

const WAIT: Duration = Duration::from_secs(20);

use crate::testing::fake_agent;

fn base_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/home/test")),
    ]
}

fn fake_profile() -> AgentProfile {
    AgentProfile::custom("fake", "Fake agent", fake_agent().to_string_lossy(), vec![])
        .allow_env("FAKE_ACP_*")
}

fn config(dir: &Path, platform: Platform, node_dir: &Path) -> AgentsConfig {
    let resolver = Resolver {
        paths: AgentPaths::in_data_dir(dir.join("data")),
        platform,
        path_env: Some(node_dir.as_os_str().to_owned()),
    };
    let mut c = AgentsConfig::new(resolver, Some(dir.join("config")));
    c.kraken_exe = Some(PathBuf::from("/opt/kraken/kraken"));
    c.parent_env = Some(base_env());
    c.extra_profiles = vec![fake_profile()];
    c.start_timeout = WAIT;
    c
}

struct Rig {
    dir: tempfile::TempDir,
    node_dir: PathBuf,
    rt: Runtime,
    vm: ViewModel,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.vm.agents_close_session();
        // Let the shutdown task end the agent before the runtime goes away.
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn rig() -> Rig {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::from_millis(1)).expect("demo");
    let mut vm = ViewModel::new(d.backend.clone(), rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    let dir = tempfile::tempdir().expect("tempdir");
    let node_dir = dir.path().join("bin");
    std::fs::create_dir_all(&node_dir).expect("bin dir");
    let cfg = config(dir.path(), Platform::new("linux", "x86_64"), &node_dir);
    vm.agents_configure(cfg);
    Rig {
        dir,
        node_dir,
        rt,
        vm,
    }
}

impl Rig {
    fn load(&mut self) {
        self.vm.agents.loaded = false;
        self.vm.agents_refresh();
        assert!(self.vm.block_until(WAIT, |vm| vm.agents.loaded));
    }

    fn session(&self) -> &AgentSession {
        self.vm.agents.session.as_ref().expect("a session")
    }

    fn until(&mut self, what: &str, cond: impl Fn(&ViewModel) -> bool) {
        assert!(
            self.vm.block_until(WAIT, cond),
            "timed out waiting for {what}; items: {:#?}",
            self.vm
                .agents
                .session
                .as_ref()
                .map(|s| (&s.phase, &s.items))
        );
    }

    /// Acknowledges the warning and starts the fake agent; waits until it is ready.
    fn start_fake(&mut self) {
        self.load();
        self.vm.agents_start("fake");
        assert_eq!(self.vm.agents.pending_notice.as_deref(), Some("fake"));
        self.vm.agents_acknowledge();
        self.until("the agent to be ready", |vm| {
            vm.agents
                .session
                .as_ref()
                .is_some_and(|s| s.phase != SessionPhase::Starting)
        });
        assert_eq!(self.session().phase, SessionPhase::Ready);
    }

    fn texts(&self) -> String {
        self.session()
            .items
            .iter()
            .filter_map(|i| match i {
                AgentItem::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }
}

fn permission(s: &AgentSession) -> Option<&PermissionCard> {
    s.items.iter().find_map(|i| match i {
        AgentItem::Permission(c) => Some(c),
        _ => None,
    })
}

fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).expect("write script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

// ------------------------------------------------------------------ availability

#[test]
fn availability_states_for_each_kind_of_agent() {
    let mut r = rig();
    r.vm.agents
        .config
        .as_mut()
        .expect("config")
        .extra_profiles
        .push(AgentProfile::custom(
            "ghost",
            "Ghost",
            "/nonexistent/ghost-agent",
            vec![],
        ));
    r.load();
    let rows = &r.vm.agents.rows;
    assert_eq!(
        rows.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        ["claude", "codex", "gemini", "fake", "ghost"]
    );

    // No Node.js anywhere: the built-in agents need setup, and setup would download Node.js.
    for id in ["claude", "codex", "gemini"] {
        let row = r.vm.agents.row(id).expect("row");
        match &row.availability {
            Availability::NeedsSetup {
                reason,
                downloads_node,
            } => {
                assert!(*downloads_node, "{id}: {reason}");
                assert!(reason.contains("Node.js"), "{id}: {reason}");
            }
            other => panic!("{id}: {other:?}"),
        }
        assert_eq!(row.availability.label(), "Needs setup");
        assert!(row.builtin);
    }
    let fake = r.vm.agents.row("fake").expect("fake");
    assert!(fake.is_ready(), "{:?}", fake.availability);
    assert_eq!(fake.availability.label(), "Ready");
    assert!(!fake.builtin);
    match &r.vm.agents.row("ghost").expect("ghost").availability {
        Availability::NotFound { reason } => assert!(reason.contains("ghost-agent"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(r.vm.agents.platform_note, None);

    // A Node.js on PATH: only the adapter is missing, nothing to download for Node.js.
    write_script(&r.node_dir.join("node"), "#!/bin/sh\necho v24.1.0\n");
    r.load();
    match &r.vm.agents.row("claude").expect("claude").availability {
        Availability::NeedsSetup { downloads_node, .. } => assert!(!downloads_node),
        other => panic!("{other:?}"),
    }

    // A platform the adapters do not ship for.
    let cfg = {
        let mut c = config(r.dir.path(), Platform::new("linux", "riscv64"), &r.node_dir);
        c.extra_profiles = vec![fake_profile()];
        c
    };
    r.vm.agents_configure(cfg);
    r.load();
    for id in ["claude", "codex", "gemini"] {
        let row = r.vm.agents.row(id).expect("row");
        match &row.availability {
            Availability::Unsupported { reason } => assert!(reason.contains("riscv64"), "{reason}"),
            other => panic!("{id}: {other:?}"),
        }
        assert_eq!(row.availability.label(), "Not supported here");
    }
    assert!(
        r.vm.agents
            .platform_note
            .as_deref()
            .is_some_and(|n| n.contains("riscv64"))
    );
    assert!(r.vm.agents.row("fake").expect("fake").is_ready());
    let _ = &r.rt;
}

#[test]
fn an_unreadable_agents_file_keeps_the_builtin_agents() {
    let mut r = rig();
    let cfg_dir = r.dir.path().join("config");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(cfg_dir.join("agents.toml"), "this is = not [valid").expect("write");
    r.load();
    assert!(r.vm.agents.catalogue_error.is_some());
    assert!(r.vm.agents.row("claude").is_some());
}

// ------------------------------------------------------------------ setup consent

struct CountingFetcher(Arc<AtomicUsize>);

#[async_trait]
impl Fetcher for CountingFetcher {
    async fn fetch(&self, url: &str, _from: u64) -> Result<Fetched, ProvisionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ProvisionError::Http {
            url: url.to_string(),
            message: "no network in this test".into(),
        })
    }
}

#[test]
fn setup_asks_before_it_downloads_anything() {
    let mut r = rig();
    let fetches = Arc::new(AtomicUsize::new(0));
    r.vm.agents.config.as_mut().expect("config").fetcher =
        Some(Arc::new(CountingFetcher(fetches.clone())));
    r.load();

    r.vm.agents_request_setup("claude");
    let SetupState::Confirm(plan) = r.vm.agents.setup.clone() else {
        panic!("expected the consent step, got {:?}", r.vm.agents.setup);
    };
    assert_eq!(plan.agent_id, "claude");
    assert!(plan.downloads.len() == 2, "{:?}", plan.downloads);
    assert!(plan.downloads[0].contains("Node.js") && plan.downloads[0].contains("nodejs.org"));
    assert!(plan.downloads[1].contains("claude-agent-acp"));
    assert!(plan.into_dir.ends_with("agents"), "{}", plan.into_dir);
    std::thread::sleep(Duration::from_millis(300));
    r.vm.poll();
    assert_eq!(fetches.load(Ordering::SeqCst), 0, "nothing before the yes");

    // Saying no leaves no trace.
    r.vm.agents_dismiss_setup();
    assert_eq!(r.vm.agents.setup, SetupState::Idle);
    r.vm.agents_confirm_setup();
    assert_eq!(r.vm.agents.setup, SetupState::Idle, "no plan, no download");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(fetches.load(Ordering::SeqCst), 0);

    // Yes: it starts, reports progress, and a failed download is explained.
    r.vm.agents_request_setup("claude");
    r.vm.agents_confirm_setup();
    assert!(r.vm.agents.setup.running());
    r.until("setup to fail", |vm| {
        matches!(vm.agents.setup, SetupState::Failed { .. })
    });
    let SetupState::Failed { agent_id, message } = r.vm.agents.setup.clone() else {
        unreachable!()
    };
    assert_eq!(agent_id, "claude");
    assert!(message.contains("no network"), "{message}");
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    r.vm.agents_dismiss_setup();
    assert_eq!(r.vm.agents.setup, SetupState::Idle);
}

#[test]
fn only_agents_that_need_setup_can_be_set_up() {
    let mut r = rig();
    r.load();
    r.vm.agents_request_setup("fake");
    assert_eq!(r.vm.agents.setup, SetupState::Idle);
    r.vm.agents_request_setup("nobody");
    assert_eq!(r.vm.agents.setup, SetupState::Idle);
}

// ------------------------------------------------------------------ the warning

#[test]
fn the_warning_gates_the_first_run_and_is_remembered() {
    let mut r = rig();
    r.load();
    let store = NoticeStore::in_config_dir(&r.dir.path().join("config"));
    assert!(!store.is_acknowledged());
    assert!(!r.vm.agents.notice.acknowledged);

    r.vm.agents_start("fake");
    assert_eq!(r.vm.agents.pending_notice.as_deref(), Some("fake"));
    assert!(
        r.vm.agents.session.is_none(),
        "nothing starts before the warning"
    );
    assert!(!store.is_acknowledged());

    // Closing the warning starts nothing.
    r.vm.agents_cancel_notice();
    assert_eq!(r.vm.agents.pending_notice, None);
    assert!(r.vm.agents.session.is_none());

    // The text the tab shows is the one from kraken-acp.
    assert!(WARNING_TEXT.contains("outside") || WARNING_TEXT.contains("do not cover"));
    assert!(!WARNING_TITLE.is_empty());

    r.vm.agents_start("fake");
    r.vm.agents_acknowledge();
    assert!(r.vm.agents.notice.acknowledged);
    assert_eq!(r.vm.agents.notice.save_error, None);
    assert!(store.is_acknowledged(), "saved in the config dir");
    assert!(r.vm.agents.session.is_some(), "the waiting agent starts");
    r.until("the agent to be ready", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.phase == SessionPhase::Ready)
    });
    r.vm.agents_close_session();

    // A new window (new configuration) reads the saved acknowledgement and does not ask again.
    let cfg = r.vm.agents.config.clone().expect("config");
    r.vm.agents_configure(cfg);
    assert!(r.vm.agents.notice.acknowledged);
    r.load();
    r.vm.agents_start("fake");
    assert_eq!(r.vm.agents.pending_notice, None);
    r.until("the second session", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.phase == SessionPhase::Ready)
    });
}

#[test]
fn a_warning_that_cannot_be_saved_still_lets_the_agent_run() {
    let mut r = rig();
    // The config dir is a file, so nothing can be written under it.
    let blocked = r.dir.path().join("blocked");
    std::fs::write(&blocked, "x").expect("file");
    let mut cfg = r.vm.agents.config.clone().expect("config");
    cfg.config_dir = Some(blocked);
    r.vm.agents_configure(cfg);
    r.load();
    r.vm.agents_start("fake");
    r.vm.agents_acknowledge();
    assert!(r.vm.agents.notice.acknowledged);
    assert!(r.vm.agents.notice.save_error.is_some());
    assert!(r.vm.agents.session.is_some());
}

// ------------------------------------------------------------------ starting

#[test]
fn an_agent_that_is_not_ready_does_not_start() {
    let mut r = rig();
    r.load();
    r.vm.agents.notice.acknowledged = true;
    r.vm.agents_start("claude");
    assert!(r.vm.agents.session.is_none());
    assert!(
        r.vm.agents
            .error
            .as_deref()
            .is_some_and(|e| e.contains("Claude Code")),
        "{:?}",
        r.vm.agents.error
    );
}

#[test]
fn starting_needs_an_open_project() {
    let mut r = rig();
    r.load();
    r.vm.agents.notice.acknowledged = true;
    r.vm.project = None;
    r.vm.agents_start("fake");
    assert!(r.vm.agents.session.is_none());
    assert!(
        r.vm.agents
            .error
            .as_deref()
            .is_some_and(|e| e.contains("project"))
    );
}

#[test]
fn the_session_header_names_the_agent_and_model() {
    let mut r = rig();
    r.start_fake();
    let s = r.session();
    assert_eq!(s.agent_name, "Fake agent");
    assert_eq!(
        s.agent_label.as_deref(),
        Some("kraken-fake-acp-agent 0.0.0")
    );
    assert_eq!(s.model.as_deref(), Some("Fake model 1"));
    assert!(!s.project_dir.is_empty());
}

#[test]
fn an_agent_that_needs_a_login_ends_with_a_plain_reason() {
    let mut r = rig();
    let mut cfg = r.vm.agents.config.clone().expect("config");
    cfg.extra_profiles = vec![fake_profile().with_env("FAKE_ACP_REQUIRE_AUTH", "1")];
    r.vm.agents_configure(cfg);
    r.load();
    r.vm.agents.notice.acknowledged = true;
    r.vm.agents_start("fake");
    r.until("the start to fail", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| matches!(s.phase, SessionPhase::Ended(_)))
    });
    let SessionPhase::Ended(why) = &r.session().phase else {
        unreachable!()
    };
    assert!(why.contains("sign in"), "{why}");
    assert!(!r.vm.agents.in_session());
    // The ended session can be dismissed and another started.
    r.vm.agents_close_session();
    assert!(r.vm.agents.session.is_none());
}

// ------------------------------------------------------------------ streaming and tools

#[test]
fn a_turn_streams_text_tool_calls_and_a_plan() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("hello");
    assert!(r.session().busy);
    r.until("the permission request", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.waiting_permissions() == 1)
    });

    let s = r.session();
    assert!(matches!(&s.items[0], AgentItem::User(t) if t == "hello"));
    assert_eq!(
        r.texts(),
        "Hello from the fake agent. ",
        "chunks are joined"
    );
    assert!(
        s.items
            .iter()
            .any(|i| matches!(i, AgentItem::Thought(t) if t.contains("thinking")))
    );
    let tool = s
        .items
        .iter()
        .find_map(|i| match i {
            AgentItem::Tool(t) => Some(t),
            _ => None,
        })
        .expect("a tool chip");
    assert_eq!(tool.title, "Run rm -rf build");
    assert!(!tool.is_kraken, "a shell command is the agent's own tool");
    assert_eq!(tool.kind, "execute");
    assert!(tool.working());
    assert_eq!(tool.paths, ["/tmp/project/build"]);
    let plan = s.items.iter().find_map(|i| match i {
        AgentItem::Plan(p) => Some(p),
        _ => None,
    });
    assert_eq!(plan.map(Vec::len), Some(2));
    assert!(s.busy, "the turn waits for the person");

    r.vm.agents_answer_permission(
        permission(r.session()).expect("card").request.request_id,
        true,
    );
    r.until("the turn to end", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    let s = r.session();
    let tool = s
        .items
        .iter()
        .find_map(|i| match i {
            AgentItem::Tool(t) => Some(t),
            _ => None,
        })
        .expect("tool");
    assert_eq!(tool.status, "completed");
    assert_eq!(tool.output.as_deref(), Some("permission granted"));
    assert!(r.texts().ends_with("permission granted."));
    assert!(
        !s.items.iter().any(|i| matches!(
            i,
            AgentItem::Text {
                streaming: true,
                ..
            }
        )),
        "no text is still streaming"
    );
}

#[test]
fn kraken_tool_calls_are_told_apart_from_the_agents_own() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("kraken");
    r.until("the permission request", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.waiting_permissions() == 1)
    });
    let tools: Vec<&AgentTool> = r
        .session()
        .items
        .iter()
        .filter_map(|i| match i {
            AgentItem::Tool(t) => Some(t),
            _ => None,
        })
        .collect();
    assert_eq!(
        tools
            .iter()
            .map(|t| (t.name.as_str(), t.is_kraken, t.status.as_str()))
            .collect::<Vec<_>>(),
        [
            ("decompile", true, "completed"),
            ("rename_symbol", true, "completed"),
            ("Run strings -n 8 ./sample", false, "pending"),
        ]
    );
    assert_eq!(tools[0].input.as_deref(), Some(r#"{"address":"0x401340"}"#));
    r.vm.agents_answer_permission(
        permission(r.session()).expect("card").request.request_id,
        false,
    );
    r.until("the turn to end", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
}

#[test]
fn tool_titles_are_classified() {
    assert_eq!(
        classify_tool("mcp__kraken__decompile"),
        ("decompile".into(), true)
    );
    assert_eq!(
        classify_tool("kraken.rename_symbol"),
        ("rename_symbol".into(), true)
    );
    assert_eq!(
        classify_tool("kraken: xrefs_to 0x401000"),
        ("xrefs_to".into(), true)
    );
    assert_eq!(classify_tool("Read main.c"), ("Read main.c".into(), false));
    assert_eq!(
        classify_tool("mcp__other__thing"),
        ("mcp__other__thing".into(), false)
    );
}

// ------------------------------------------------------------------ permissions

#[test]
fn allow_once_lets_the_agent_continue() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("go");
    r.until("the permission request", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.waiting_permissions() == 1)
    });
    let card = permission(r.session()).expect("card").clone();
    assert_eq!(card.request.title, "Run rm -rf build");
    assert_eq!(card.request.tool_kind.as_deref(), Some("execute"));
    assert_eq!(
        card.request
            .options
            .iter()
            .map(|o| o.name.as_str())
            .collect::<Vec<_>>(),
        ["Allow once", "Reject"]
    );
    assert_eq!(card.state, PermissionState::Waiting);

    // An unknown request id changes nothing.
    r.vm.agents_answer_permission(card.request.request_id + 99, true);
    r.vm.agents_answer_permission(card.request.request_id, true);
    r.until("the answer", |vm| {
        vm.agents
            .session
            .as_ref()
            .and_then(permission)
            .is_some_and(|c| c.state == PermissionState::Allowed)
    });
    r.until("the turn to end", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    assert!(r.texts().contains("permission granted"));
    assert_eq!(r.session().waiting_permissions(), 0);
}

#[test]
fn deny_tells_the_agent_no() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("go");
    r.until("the permission request", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.waiting_permissions() == 1)
    });
    let id = permission(r.session()).expect("card").request.request_id;
    r.vm.agents_answer_permission(id, false);
    r.until("the turn to end", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    let s = r.session();
    assert_eq!(permission(s).expect("card").state, PermissionState::Denied);
    assert!(r.texts().contains("permission denied"));
    let failed = s
        .items
        .iter()
        .any(|i| matches!(i, AgentItem::Tool(t) if t.failed()));
    assert!(failed, "the denied tool call shows as failed");
}

// ------------------------------------------------------------------ stop

#[test]
fn stop_ends_the_turn_and_the_session_stays_usable() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("wait");
    r.until("the first words", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| {
            s.items.iter().any(|i| matches!(i, AgentItem::Text { text, .. } if text.contains("waiting for cancel")))
        })
    });
    assert!(r.session().busy);
    r.vm.agents_stop();
    assert!(r.session().stopping);
    r.until("the turn to stop", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    let s = r.session();
    assert!(!s.stopping);
    assert!(
        s.items
            .iter()
            .any(|i| matches!(i, AgentItem::Notice(n) if n == "Stopped.")),
        "{:?}",
        s.items
    );
    assert_eq!(s.phase, SessionPhase::Ready);

    // The same agent takes the next prompt.
    r.vm.agents_send("report");
    r.until("the next answer", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    assert!(r.texts().contains("mcpServers"));
}

#[test]
fn stop_withdraws_a_waiting_permission_request() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("go");
    r.until("the permission request", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| s.waiting_permissions() == 1)
    });
    r.vm.agents_stop();
    r.until("the turn to stop", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    let s = r.session();
    assert_eq!(
        permission(s).expect("card").state,
        PermissionState::Withdrawn
    );
    assert_eq!(s.waiting_permissions(), 0);
    assert!(
        s.items
            .iter()
            .any(|i| matches!(i, AgentItem::Notice(n) if n == "Stopped."))
    );
}

#[test]
fn stop_does_nothing_when_idle() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_stop();
    assert!(!r.session().stopping);
}

// ------------------------------------------------------------------ the agent going away

#[test]
fn an_agent_that_exits_ends_the_session_with_a_reason() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_send("die");
    r.until("the session to end", |vm| {
        vm.agents
            .session
            .as_ref()
            .is_some_and(|s| matches!(s.phase, SessionPhase::Ended(_)))
    });
    let s = r.session();
    assert!(!s.busy);
    let SessionPhase::Ended(why) = &s.phase else {
        unreachable!()
    };
    assert!(
        (why.contains("exit code 7") || why.contains("stopped")),
        "{why}"
    );
    assert!(s.items.iter().any(
        |i| matches!(i, AgentItem::Error(e) if (e.contains("exit code 7") || e.contains("stopped")))
    ));
    // Prompts after the end are ignored.
    let before = s.items.len();
    r.vm.agents_send("again");
    assert_eq!(r.session().items.len(), before);
}

#[test]
fn only_one_session_at_a_time() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_start("fake");
    assert!(
        r.vm.agents
            .error
            .as_deref()
            .is_some_and(|e| e.contains("already running"))
    );
}

#[test]
fn changing_project_ends_the_session() {
    let mut r = rig();
    r.start_fake();
    r.vm.agents_project_changed();
    assert!(r.vm.agents.session.is_none());
}

#[test]
fn prompts_need_a_ready_session() {
    let mut r = rig();
    r.vm.agents_send("hello");
    assert!(r.vm.agents.session.is_none());
    r.start_fake();
    r.vm.agents_send("   ");
    assert!(r.session().items.is_empty(), "blank prompts are ignored");
}

// ------------------------------------------------------------------ the MCP wiring

fn mcp_server_seen_by_the_agent(r: &mut Rig) -> serde_json::Value {
    r.start_fake();
    r.vm.agents_send("report");
    r.until("the report", |vm| {
        vm.agents.session.as_ref().is_some_and(|s| !s.busy)
    });
    let report: serde_json::Value = serde_json::from_str(&r.texts()).expect("json report");
    report["mcpServers"][0].clone()
}

#[test]
fn the_agent_is_given_kraken_mcp_for_the_open_project() {
    let mut r = rig();
    let project = r.vm.project.as_ref().expect("project").project_dir.clone();
    let server = mcp_server_seen_by_the_agent(&mut r);
    assert_eq!(server["name"], "kraken");
    assert_eq!(server["command"], "/opt/kraken/kraken");
    assert_eq!(
        server["args"],
        serde_json::json!(["mcp", "--project", project])
    );
}

#[test]
fn with_the_daemon_the_agent_joins_it_so_edits_flow_back_live() {
    let mut r = rig();
    let project = r.vm.project.as_ref().expect("project").project_dir.clone();
    let mut cfg = r.vm.agents.config.clone().expect("config");
    cfg.use_daemon = true;
    cfg.mcp_env = vec![("KRAKEN_RUNTIME_DIR".into(), "/run/private-kraken".into())];
    r.vm.agents_configure(cfg);
    let server = mcp_server_seen_by_the_agent(&mut r);
    assert_eq!(
        server["args"],
        serde_json::json!(["mcp", "--daemon", "--project", project])
    );
    let env = server["env"].to_string();
    assert!(
        env.contains("KRAKEN_RUNTIME_DIR") && env.contains("/run/private-kraken"),
        "{env}"
    );
}

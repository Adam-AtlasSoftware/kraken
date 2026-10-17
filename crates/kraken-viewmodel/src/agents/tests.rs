//! The agents hub: availability, the setup flow with its consent step, the one-time notice and
//! the connection test, against shell-script fakes for node and npm and the fake ACP agent. No
//! network, no real agents.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_acp::{AgentPaths, AgentProfile, NoticeStore, Platform, Resolver};
use kraken_host::provision::{Fetched, Fetcher, ProvisionError};
use tokio::runtime::Runtime;

use super::*;
use crate::testing::fake_agent;

const WAIT: Duration = Duration::from_secs(30);

fn base_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/home/test")),
    ]
}

fn fake_profile(extra: &[(&str, &str)]) -> AgentProfile {
    let mut p = AgentProfile::custom("fake", "Fake agent", fake_agent().to_string_lossy(), vec![]);
    for (k, v) in extra {
        p = p.with_env(*k, *v);
    }
    p
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
    c.extra_profiles = vec![fake_profile(&[("FAKE_ACP_ALLOW_NO_MCP", "1")])];
    c.start_timeout = WAIT;
    c
}

struct Rig {
    dir: tempfile::TempDir,
    node_dir: PathBuf,
    rt: Runtime,
    hub: AgentsHub,
}

fn rig() -> Rig {
    let rt = Runtime::new().expect("runtime");
    let dir = tempfile::tempdir().expect("tempdir");
    let node_dir = dir.path().join("bin");
    std::fs::create_dir_all(&node_dir).expect("bin dir");
    let cfg = config(dir.path(), Platform::new("linux", "x86_64"), &node_dir);
    let hub = AgentsHub::new(rt.handle().clone(), Some(cfg));
    Rig {
        dir,
        node_dir,
        rt,
        hub,
    }
}

impl Rig {
    /// Polls the hub until `cond` holds.
    fn until(&mut self, what: &str, cond: impl Fn(&AgentsHub) -> bool) {
        let end = Instant::now() + WAIT;
        loop {
            self.hub.poll();
            if cond(&self.hub) {
                return;
            }
            assert!(
                Instant::now() < end,
                "timed out waiting for {what}; setup {:?}, test {:?}",
                self.hub.setup,
                self.hub.test
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn load(&mut self) {
        self.hub.loaded = false;
        self.hub.refresh();
        self.until("the list", |h| h.loaded);
    }
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
    r.hub
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
    assert_eq!(
        r.hub.rows.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        ["claude", "codex", "gemini", "fake", "ghost"]
    );

    // No Node.js anywhere: the built-in agents need setup, and setup would download Node.js.
    for id in ["claude", "codex", "gemini"] {
        let row = r.hub.row(id).expect("row");
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
    let fake = r.hub.row("fake").expect("fake");
    assert!(fake.is_ready(), "{:?}", fake.availability);
    assert_eq!(fake.availability.label(), "Ready");
    assert!(!fake.builtin);
    match &r.hub.row("ghost").expect("ghost").availability {
        Availability::NotFound { reason } => assert!(reason.contains("ghost-agent"), "{reason}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(r.hub.platform_note, None);

    // A Node.js on PATH: only the adapter is missing, nothing to download for Node.js.
    write_script(&r.node_dir.join("node"), "#!/bin/sh\necho v24.1.0\n");
    r.load();
    match &r.hub.row("claude").expect("claude").availability {
        Availability::NeedsSetup { downloads_node, .. } => assert!(!downloads_node),
        other => panic!("{other:?}"),
    }

    // A platform the adapters do not ship for.
    let cfg = config(r.dir.path(), Platform::new("linux", "riscv64"), &r.node_dir);
    r.hub.configure(cfg);
    r.load();
    for id in ["claude", "codex", "gemini"] {
        let row = r.hub.row(id).expect("row");
        match &row.availability {
            Availability::Unsupported { reason } => assert!(reason.contains("riscv64"), "{reason}"),
            other => panic!("{id}: {other:?}"),
        }
        assert_eq!(row.availability.label(), "Not supported here");
    }
    assert!(
        r.hub
            .platform_note
            .as_deref()
            .is_some_and(|n| n.contains("riscv64"))
    );
    assert!(r.hub.row("fake").expect("fake").is_ready());
    let _ = &r.rt;
}

#[test]
fn an_unreadable_agents_file_keeps_the_builtin_agents() {
    let mut r = rig();
    let cfg_dir = r.dir.path().join("config");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    std::fs::write(cfg_dir.join("agents.toml"), "this is = not [valid").expect("write");
    r.load();
    assert!(r.hub.catalogue_error.is_some());
    assert!(r.hub.row("claude").is_some());
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
    r.hub.config.as_mut().expect("config").fetcher =
        Some(Arc::new(CountingFetcher(fetches.clone())));
    r.load();

    r.hub.request_setup("claude");
    let SetupState::Confirm(plan) = r.hub.setup.clone() else {
        panic!("expected the consent step, got {:?}", r.hub.setup);
    };
    assert_eq!(plan.agent_id, "claude");
    assert!(plan.downloads.len() == 2, "{:?}", plan.downloads);
    assert!(plan.downloads[0].contains("Node.js") && plan.downloads[0].contains("nodejs.org"));
    assert!(plan.downloads[1].contains("claude-agent-acp"));
    assert!(plan.into_dir.ends_with("agents"), "{}", plan.into_dir);
    std::thread::sleep(Duration::from_millis(300));
    r.hub.poll();
    assert_eq!(fetches.load(Ordering::SeqCst), 0, "nothing before the yes");

    // Saying no leaves no trace.
    r.hub.dismiss_setup();
    assert_eq!(r.hub.setup, SetupState::Idle);
    r.hub.confirm_setup();
    assert_eq!(r.hub.setup, SetupState::Idle, "no plan, no download");
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(fetches.load(Ordering::SeqCst), 0);

    // Yes: it starts, reports progress, and a failed download is explained.
    r.hub.request_setup("claude");
    r.hub.confirm_setup();
    assert!(r.hub.setup.running());
    r.until("setup to fail", |h| {
        matches!(h.setup, SetupState::Failed { .. })
    });
    let SetupState::Failed { agent_id, message } = r.hub.setup.clone() else {
        unreachable!()
    };
    assert_eq!(agent_id, "claude");
    assert!(message.contains("no network"), "{message}");
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
    r.hub.dismiss_setup();
    assert_eq!(r.hub.setup, SetupState::Idle);
}

#[test]
fn only_agents_that_need_setup_can_be_set_up() {
    let mut r = rig();
    r.load();
    r.hub.request_setup("fake");
    assert_eq!(r.hub.setup, SetupState::Idle);
    r.hub.request_setup("nobody");
    assert_eq!(r.hub.setup, SetupState::Idle);
}

// ------------------------------------------------------------------ the notice

#[test]
fn the_notice_is_remembered_across_windows() {
    let mut r = rig();
    let store = NoticeStore::in_config_dir(&r.dir.path().join("config"));
    assert!(!store.is_acknowledged());
    assert!(!r.hub.notice.acknowledged);
    assert!(!r.hub.env().expect("env").acknowledged);

    // The text the settings show is the one from kraken-acp.
    assert!(WARNING_TEXT.contains("outside") || WARNING_TEXT.contains("do not cover"));
    assert!(!WARNING_TITLE.is_empty());

    r.hub.acknowledge();
    assert!(r.hub.notice.acknowledged);
    assert_eq!(r.hub.notice.save_error, None);
    assert!(store.is_acknowledged(), "saved in the config dir");
    assert!(r.hub.env().expect("env").acknowledged);

    // A new window (new configuration) reads the saved acknowledgement and does not ask again.
    let cfg = r.hub.config().expect("config");
    r.hub.configure(cfg);
    assert!(r.hub.notice.acknowledged);
}

#[test]
fn a_notice_that_cannot_be_saved_still_counts_for_this_run() {
    let mut r = rig();
    // The config dir is a file, so nothing can be written under it.
    let blocked = r.dir.path().join("blocked");
    std::fs::write(&blocked, "x").expect("file");
    let mut cfg = r.hub.config().expect("config");
    cfg.config_dir = Some(blocked);
    r.hub.configure(cfg);
    r.hub.acknowledge();
    assert!(r.hub.notice.acknowledged);
    assert!(r.hub.notice.save_error.is_some());
}

#[test]
fn the_daemon_choice_reaches_the_agents_environment() {
    let mut r = rig();
    assert!(!r.hub.env().expect("env").config.use_daemon);
    r.hub.set_daemon(true);
    assert!(r.hub.env().expect("env").config.use_daemon);
    r.hub.set_daemon(false);
    assert!(!r.hub.env().expect("env").config.use_daemon);
}

// ------------------------------------------------------------------ the test button

#[test]
fn testing_an_agent_starts_it_and_reports_what_it_said() {
    let mut r = rig();
    r.load();
    r.hub.acknowledge();
    r.hub.test_agent("fake", None, &[]);
    assert!(r.hub.test.running());
    r.until("the test", |h| !h.test.running());
    let AgentTestState::Passed { agent_id, message } = r.hub.test.clone() else {
        panic!("{:?}", r.hub.test);
    };
    assert_eq!(agent_id, "fake");
    assert!(message.starts_with("Connected."), "{message}");
    assert!(message.contains("Fake model 1"), "{message}");
    assert!(message.contains("kraken-fake-acp-agent"), "{message}");
}

#[test]
fn a_test_needs_the_notice_a_ready_agent_and_reports_a_login_problem() {
    let mut r = rig();
    r.load();
    r.hub.test_agent("fake", None, &[]);
    assert!(
        matches!(&r.hub.test, AgentTestState::Failed { message, .. } if message.contains("Read the note")),
        "{:?}",
        r.hub.test
    );

    r.hub.acknowledge();
    r.hub.test_agent("claude", None, &[]);
    assert!(
        matches!(&r.hub.test, AgentTestState::Failed { message, .. } if message.contains("Set up")),
        "{:?}",
        r.hub.test
    );
    r.hub.test_agent("nobody", None, &[]);
    assert!(
        matches!(&r.hub.test, AgentTestState::Failed { message, .. } if message.contains("nobody")),
        "{:?}",
        r.hub.test
    );

    // An agent that wants a sign-in says so in plain words.
    let mut cfg = r.hub.config().expect("config");
    cfg.extra_profiles = vec![fake_profile(&[
        ("FAKE_ACP_ALLOW_NO_MCP", "1"),
        ("FAKE_ACP_REQUIRE_AUTH", "1"),
    ])];
    r.hub.configure(cfg);
    r.load();
    r.hub.test_agent("fake", None, &[]);
    r.until("the test", |h| !h.test.running());
    assert!(
        matches!(&r.hub.test, AgentTestState::Failed { message, .. } if message.contains("sign in")),
        "{:?}",
        r.hub.test
    );
}

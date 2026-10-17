//! The daemon's trust model: credentials decide author and approval, agents reach only what a
//! person opened or approved, and approvals wait on the board.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use engine_fake::FixtureFile;
use kraken_host::daemon::{CallParams, DaemonClient};
use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, RuntimeDir};
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, Locator, ProtoError};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory;
use krakend::{Daemon, DaemonOptions};
use serde_json::{Value, json};

const TINY: &str = "../engine-fake/fixtures/tiny.json";

fn fixture() -> FixtureFile {
    let mut fx =
        FixtureFile::from_path(&Path::new(env!("CARGO_MANIFEST_DIR")).join(TINY)).expect("tiny");
    // Engine default names, so an agent's first rename is additive and auto-applies.
    for f in &mut fx.functions {
        if let Locator::Native { offset, .. } = &f.summary.locator {
            f.summary.name = format!("FUN_{:08x}", offset.0);
        }
    }
    fx
}

struct Rig {
    tmp: tempfile::TempDir,
    dir: RuntimeDir,
    daemon: Option<Daemon>,
    cap: u32,
    binary: PathBuf,
}

fn start(dir: &RuntimeDir, cap: u32) -> Daemon {
    krakend::start(DaemonOptions {
        runtime_dir: dir.clone(),
        factory: Arc::new(FakeFactory::new(fixture(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: kraken_host::DaemonSettings {
            idle_secs: Some(600),
            session_idle_secs: Some(1800),
            max_sessions: Some(4),
        },
        session_config: SessionConfig {
            per_run_cap: cap,
            ..SessionConfig::default()
        },
        clock: Arc::new(ManualClock::new()),
        poll: Duration::from_millis(10),
        build: "test-build".into(),
    })
    .expect("daemon starts")
}

impl Rig {
    fn new(cap: u32) -> Rig {
        let tmp = tempfile::Builder::new()
            .prefix("kraken-t")
            .tempdir()
            .expect("tempdir");
        let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
        let binary = tmp.path().join("prog.bin");
        std::fs::write(&binary, b"\x7fELF fake binary").expect("binary");
        let daemon = Some(start(&dir, cap));
        Rig {
            tmp,
            dir,
            daemon,
            cap,
            binary,
        }
    }

    async fn client(&self, kind: ClientKind) -> DaemonClient {
        let c = Client::connect(&self.dir, &ClientHello::new(kind, "test-build"))
            .await
            .expect("connect");
        DaemonClient::from_client(c, "test-build")
    }

    fn project(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    /// Stops the daemon and starts a fresh one in the same directory: nothing is granted yet.
    async fn restart(&mut self) {
        let d = self.daemon.take().expect("daemon");
        d.shutdown();
        d.wait().await;
        self.daemon = Some(start(&self.dir, self.cap));
    }

    fn daemon(&self) -> &Daemon {
        self.daemon.as_ref().expect("daemon")
    }

    async fn stop(mut self) {
        let d = self.daemon.take().expect("daemon");
        d.shutdown();
        tokio::time::timeout(Duration::from_secs(10), d.wait())
            .await
            .expect("daemon stops");
    }
}

fn params(dir: &Path, command: &str, args: Value) -> CallParams {
    CallParams {
        project_dir: dir.to_string_lossy().into_owned(),
        command: command.into(),
        args,
        author_kind: AuthorKind::User,
        author_id: Some("tester".into()),
        run_id: None,
        surface: None,
        approved: false,
    }
}

async fn call(
    c: &DaemonClient,
    dir: &Path,
    command: &str,
    args: Value,
) -> Result<Value, ProtoError> {
    c.call(&params(dir, command, args)).await.map(|r| r.result)
}

/// An agent's call that claims everything it could: user author, user surface, approved.
async fn lying_agent_call(
    c: &DaemonClient,
    dir: &Path,
    command: &str,
    args: Value,
    run: &str,
) -> Result<Value, ProtoError> {
    let mut p = params(dir, command, args);
    p.author_kind = AuthorKind::User;
    p.author_id = Some("definitely-the-user".into());
    p.run_id = Some(run.into());
    p.surface = Some(kraken_registry::Surface::Gui);
    p.approved = true;
    c.call(&p).await.map(|r| r.result)
}

async fn pending(c: &DaemonClient) -> Vec<Value> {
    for _ in 0..300 {
        let v = c.rpc("approvals", Value::Null).await.expect("approvals");
        let list = v["pending"].as_array().cloned().unwrap_or_default();
        if !list.is_empty() {
            return list;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Vec::new()
}

async fn decide(c: &DaemonClient, id: u64, allow: bool) {
    let v = c
        .rpc("approval_decide", json!({"id": id, "allow": allow}))
        .await
        .expect("decide");
    assert_eq!(v["decided"], true);
}

fn address_of(list: &Value, i: usize) -> String {
    list["items"][i]["address"]
        .as_str()
        .expect("address")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_credential_cannot_claim_the_user_or_an_approval() {
    let r = Rig::new(200);
    let user = r.client(ClientKind::Cli).await;
    let agent = r.client(ClientKind::Mcp).await;
    let p = r.project("p");
    call(
        &user,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
    )
    .await
    .expect("create");
    let list = call(&user, &p, "list_functions", json!({})).await.unwrap();
    let addr = address_of(&list, 0);
    call(
        &user,
        &p,
        "rename_symbol",
        json!({"address": addr, "new_name": "mine"}),
    )
    .await
    .expect("the person names it");

    // The agent says it is the user and approved. A user edit would simply apply; an agent's
    // overwrite of the person's work becomes a proposal.
    let out = lying_agent_call(
        &agent,
        &p,
        "rename_symbol",
        json!({"address": addr, "new_name": "theirs"}),
        "run-x",
    )
    .await
    .expect("rename");
    assert_eq!(out["status"], "proposed", "{out}");
    let history = call(&user, &p, "history", json!({})).await.unwrap();
    let text = history.to_string();
    assert!(!text.contains("definitely-the-user"), "{text}");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_credential_cannot_use_the_user_only_methods() {
    let r = Rig::new(200);
    let agent = r.client(ClientKind::Mcp).await;
    for (method, params) in [
        ("shutdown", Value::Null),
        ("status", Value::Null),
        ("approvals", Value::Null),
        ("approval_decide", json!({"id": 1, "allow": true})),
        ("infer_list", Value::Null),
    ] {
        let e = agent.rpc(method, params).await.expect_err(method);
        assert_eq!(e.code, ErrorCode::Unsupported, "{method}: {e}");
        assert_eq!(e.details.as_ref().unwrap()["reason"], "agent_credential");
    }
    assert!(!r.daemon().is_stopping());
    // What an agent may use still works.
    agent.commands().await.expect("commands");
    agent.events_since(0, None).await.expect("events");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_creating_a_project_waits_for_a_person() {
    let r = Rig::new(200);
    let user = r.client(ClientKind::Gui).await;
    let agent = r.client(ClientKind::Mcp).await;
    let p = r.project("agent-made");
    let args = json!({"binary": r.binary, "project_dir": p});

    // `approved: true` from an agent connection means nothing; the question lands on the board.
    let asker = {
        let (agent, p, args) = (agent.clone(), p.clone(), args.clone());
        tokio::spawn(
            async move { lying_agent_call(&agent, &p, "project_create", args, "run-1").await },
        )
    };
    let waiting = pending(&user).await;
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert_eq!(waiting[0]["command"], "project_create");
    assert!(waiting[0]["summary"].as_str().unwrap().contains("prog.bin"));
    assert!(!p.exists(), "nothing happens before the answer");
    decide(&user, waiting[0]["id"].as_u64().unwrap(), true).await;
    let out = asker.await.unwrap().expect("created after approval");
    assert_eq!(out["program"]["format"], "elf");

    // The project is now available to the agent without another question.
    lying_agent_call(&agent, &p, "list_functions", json!({}), "run-1")
        .await
        .expect("list");
    assert!(
        user.rpc("approvals", Value::Null).await.unwrap()["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // A refusal.
    let p2 = r.project("refused");
    let asker = {
        let (agent, p2, binary) = (agent.clone(), p2.clone(), r.binary.clone());
        tokio::spawn(async move {
            lying_agent_call(
                &agent,
                &p2,
                "project_create",
                json!({"binary": binary, "project_dir": p2}),
                "run-1",
            )
            .await
        })
    };
    let waiting = pending(&user).await;
    decide(&user, waiting[0]["id"].as_u64().unwrap(), false).await;
    let e = asker.await.unwrap().expect_err("refused");
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    assert!(!p2.exists());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nobody_answering_is_a_denial() {
    let r = Rig::new(200);
    r.daemon()
        .approvals()
        .set_timeout(Duration::from_millis(100));
    let agent = r.client(ClientKind::Mcp).await;
    let p = r.project("nobody");
    let e = lying_agent_call(
        &agent,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
        "run-1",
    )
    .await
    .expect_err("timed out");
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    assert!(e.message.contains("nobody approved"), "{e}");
    assert!(!p.exists());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn kernel_files_are_refused_without_asking_anyone() {
    let r = Rig::new(200);
    let user = r.client(ClientKind::Gui).await;
    let agent = r.client(ClientKind::Mcp).await;
    let p = r.project("environ");
    let e = lying_agent_call(
        &agent,
        &p,
        "project_create",
        json!({"binary": "/proc/self/environ", "project_dir": p}),
        "run-1",
    )
    .await
    .expect_err("refused");
    assert_eq!(e.code, ErrorCode::InvalidArgument, "{e}");
    assert!(
        user.rpc("approvals", Value::Null).await.unwrap()["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_needs_approval_for_a_project_no_person_opened() {
    let mut r = Rig::new(200);
    let user = r.client(ClientKind::Gui).await;
    let p = r.project("existing");
    call(
        &user,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
    )
    .await
    .expect("create");
    drop(user);
    // A new daemon: the person has not touched the project in this daemon's life.
    r.restart().await;
    let user = r.client(ClientKind::Gui).await;
    let agent = r.client(ClientKind::Mcp).await;

    let asker = {
        let (agent, p) = (agent.clone(), p.clone());
        tokio::spawn(async move {
            lying_agent_call(&agent, &p, "list_functions", json!({}), "run-1").await
        })
    };
    let waiting = pending(&user).await;
    assert_eq!(waiting.len(), 1);
    assert!(
        waiting[0]["summary"]
            .as_str()
            .unwrap()
            .contains("work on the project")
    );
    decide(&user, waiting[0]["id"].as_u64().unwrap(), true).await;
    asker.await.unwrap().expect("allowed");
    // Granted for the rest of the daemon's life.
    lying_agent_call(&agent, &p, "list_functions", json!({}), "run-1")
        .await
        .expect("no second question");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_working_on_a_project_makes_it_available_to_agents() {
    let mut r = Rig::new(200);
    let user = r.client(ClientKind::Cli).await;
    let p = r.project("existing");
    call(
        &user,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
    )
    .await
    .expect("create");
    drop(user);
    r.restart().await;
    let user = r.client(ClientKind::Cli).await;
    let agent = r.client(ClientKind::Mcp).await;
    // The person opens it (as `kraken project_open` or the GUI would) ...
    call(&user, &p, "project_open", json!({"project_dir": p}))
        .await
        .expect("open");
    // ... and the agent can use it at once.
    lying_agent_call(&agent, &p, "list_functions", json!({}), "run-1")
        .await
        .expect("no question");
    assert!(
        user.rpc("approvals", Value::Null).await.unwrap()["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnecting_does_not_reset_the_auto_apply_budget() {
    let r = Rig::new(2);
    let user = r.client(ClientKind::Cli).await;
    let p = r.project("p");
    call(
        &user,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
    )
    .await
    .expect("create");
    let list = call(&user, &p, "list_functions", json!({})).await.unwrap();
    let mut statuses = Vec::new();
    // Three connections, each with a fresh run id of its own.
    for i in 0..3 {
        let agent = r.client(ClientKind::Mcp).await;
        let out = lying_agent_call(
            &agent,
            &p,
            "rename_symbol",
            json!({"address": address_of(&list, i), "new_name": format!("agent_{i}")}),
            &format!("fresh-run-{i}"),
        )
        .await
        .expect("rename");
        statuses.push(out["status"].as_str().unwrap().to_string());
        drop(agent);
    }
    assert_eq!(statuses, ["applied", "applied", "proposed"]);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gui_selection_is_published_by_a_person_and_readable_by_an_agent() {
    use kraken_host::daemon::GuiSelection;

    let r = Rig::new(200);
    let user = r.client(ClientKind::Gui).await;
    let agent = r.client(ClientKind::Mcp).await;
    let p = r.project("watched");
    call(
        &user,
        &p,
        "project_create",
        json!({"binary": r.binary, "project_dir": p}),
    )
    .await
    .expect("create");

    // Nothing selected yet.
    let none = agent.gui_selection(&p).await.expect("reply");
    assert!(!none.attached && none.selection.is_none());

    // Only a person's connection can publish.
    let sel = GuiSelection {
        kind: "function".into(),
        function: Some("0x401000".into()),
        function_name: Some("main\u{7}\u{1b}[31m".into()),
        address: Some("0x401004".into()),
        text: Some("x".repeat(20_000)),
    };
    let e = agent
        .set_gui_selection(&p, Some(sel.clone()))
        .await
        .expect_err("an agent cannot publish a selection");
    assert_eq!(e.code, ErrorCode::Unsupported);
    user.set_gui_selection(&p, Some(sel))
        .await
        .expect("publish");

    let got = agent.gui_selection(&p).await.expect("reply");
    assert!(got.attached && !got.stale);
    let s = got.selection.expect("selection");
    assert_eq!(s.function.as_deref(), Some("0x401000"));
    assert!(
        !s.function_name.as_deref().unwrap().contains('\u{1b}'),
        "control characters are stripped"
    );
    assert!(
        s.text.as_deref().unwrap().len() <= 8 * 1024,
        "text is capped"
    );

    // An agent sees it only for a project it may use.
    let other = r.project("never-opened");
    assert!(!agent.gui_selection(&other).await.expect("reply").attached);

    user.set_gui_selection(&p, None).await.expect("clear");
    assert!(!agent.gui_selection(&p).await.expect("reply").attached);
    r.stop().await;
}

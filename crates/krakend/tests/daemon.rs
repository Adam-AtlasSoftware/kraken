//! The daemon over a real socket in a temporary runtime directory, with a scripted FakeEngine.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use engine_fake::FixtureFile;
use kraken_host::daemon::{CallParams, DaemonClient, METHOD_EVENT};
use kraken_host::{DaemonSettings, EngineEvent};
use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, Notification, RuntimeDir};
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::{FakeControl, FakeFactory};
use krakend::{Daemon, DaemonOptions};
use serde_json::{Value, json};
use tokio::sync::mpsc::UnboundedReceiver;

const TINY: &str = "../engine-fake/fixtures/tiny.json";

fn fixture() -> FixtureFile {
    FixtureFile::from_path(&Path::new(env!("CARGO_MANIFEST_DIR")).join(TINY)).expect("tiny")
}

struct Rig {
    tmp: tempfile::TempDir,
    dir: RuntimeDir,
    daemon: Option<Daemon>,
    ctl: Arc<FakeControl>,
    clock: ManualClock,
    binary: PathBuf,
}

fn settings(idle: u64, session_idle: u64, max_sessions: u32) -> DaemonSettings {
    DaemonSettings {
        idle_secs: Some(idle),
        session_idle_secs: Some(session_idle),
        max_sessions: Some(max_sessions),
    }
}

fn rig_with(settings: DaemonSettings, stage_delay: Duration) -> Rig {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-d")
        .tempdir()
        .expect("tempdir");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let factory = Arc::new(FakeFactory::new(fixture(), stage_delay));
    let ctl = factory.control();
    let clock = ManualClock::new();
    let daemon = krakend::start(DaemonOptions {
        runtime_dir: dir.clone(),
        factory,
        registry: Arc::new(Registry::standard()),
        settings,
        session_config: SessionConfig::default(),
        clock: Arc::new(clock.clone()),
        poll: Duration::from_millis(10),
        build: "test-build".into(),
    })
    .expect("daemon starts");
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake binary").expect("binary");
    Rig {
        tmp,
        dir,
        daemon: Some(daemon),
        ctl,
        clock,
        binary,
    }
}

fn rig() -> Rig {
    rig_with(settings(600, 1800, 4), Duration::ZERO)
}

impl Rig {
    async fn client(&self, kind: ClientKind) -> DaemonClient {
        let c = Client::connect(&self.dir, &ClientHello::new(kind, "test-build"))
            .await
            .expect("connect");
        DaemonClient::from_client(c, "test-build")
    }

    fn project(&self, name: &str) -> PathBuf {
        self.tmp.path().join(name)
    }

    async fn create(&self, c: &DaemonClient, name: &str) -> PathBuf {
        let dir = self.project(name);
        let out = call(
            c,
            &dir,
            "project_create",
            json!({"binary": self.binary, "project_dir": dir}),
        )
        .await
        .expect("project_create");
        assert_eq!(out["program"]["format"], "elf");
        dir
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

async fn next_event(rx: &mut UnboundedReceiver<Notification>, kind: &str) -> Value {
    let found = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = rx.recv().await.expect("event stream open");
            assert_eq!(n.method, METHOD_EVENT);
            if n.params["kind"] == kind {
                return n.params;
            }
        }
    })
    .await;
    found.unwrap_or_else(|_| panic!("no `{kind}` event arrived"))
}

async fn wait_until<F: FnMut() -> bool>(what: &str, mut f: F) {
    for _ in 0..500 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn address_of(list: &Value, i: usize) -> String {
    list["items"][i]["address"]
        .as_str()
        .expect("address")
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_status_and_a_full_project_session() {
    let r = rig();
    let c = r.client(ClientKind::Cli).await;
    assert_eq!(c.daemon_build(), "test-build");

    let commands = c.commands().await.unwrap();
    assert_eq!(
        commands.as_array().unwrap().len(),
        Registry::standard().len()
    );
    let first = &commands[0];
    assert!(first["spec"]["name"].is_string() && first["args_schema"].is_object());

    let dir = r.create(&c, "p1").await;
    let started = call(&c, &dir, "analyze", json!({})).await.unwrap();
    let done = call(
        &c,
        &dir,
        "job_await",
        json!({"job_id": started["job_id"], "timeout_ms": 20000}),
    )
    .await
    .unwrap();
    assert_eq!(done["status"], "succeeded", "{done}");
    let list = call(&c, &dir, "list_functions", json!({})).await.unwrap();
    assert!(list["items"].as_array().unwrap().len() >= 3);

    let st = c.status().await.unwrap();
    assert_eq!(st["daemon"]["build"], "test-build");
    assert_eq!(st["daemon"]["clients"], 1);
    assert_eq!(st["daemon"]["max_sessions"], 4);
    assert_eq!(st["sessions"].as_array().unwrap().len(), 1);
    let s = &st["sessions"][0];
    assert_eq!(s["opened"], true);
    assert_eq!(s["analysis"]["phase"], "complete");
    let engines = st["engines"].as_array().unwrap();
    assert_eq!(engines.len(), 1);
    assert_eq!(engines[0]["diagnostics"]["state"], "running");
    assert!(engines[0]["diagnostics"]["confinement"].is_object());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_requests_get_structured_errors() {
    let r = rig();
    let c = r.client(ClientKind::Cli).await;
    let relative = c
        .call(&params(
            Path::new("relative/dir"),
            "project_info",
            json!({}),
        ))
        .await
        .unwrap_err();
    assert_eq!(relative.code, ErrorCode::InvalidArgument);
    let unknown = call(&c, &r.project("x"), "no_such_command", json!({}))
        .await
        .unwrap_err();
    assert_eq!(unknown.code, ErrorCode::NotFound);
    // A project that does not exist: an error, and no session is left behind.
    let missing = call(&c, &r.project("missing"), "project_info", json!({}))
        .await
        .unwrap_err();
    assert_eq!(missing.code, ErrorCode::NotFound);
    let st = c.status().await.unwrap();
    assert_eq!(st["sessions"].as_array().unwrap().len(), 0);
    // A failed create leaves nothing either.
    let bad_create = call(
        &c,
        &r.project("nobin"),
        "project_create",
        json!({"binary": r.tmp.path().join("nonexistent"), "project_dir": r.project("nobin")}),
    )
    .await
    .unwrap_err();
    assert_eq!(bad_create.code, ErrorCode::NotFound);
    assert_eq!(
        c.status().await.unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let e = c.events_since(0, None).await.expect("events");
    assert!(e["events"].is_array());
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_clients_on_shared_and_separate_projects() {
    let r = rig();
    let setup = r.client(ClientKind::Cli).await;
    let p1 = r.create(&setup, "p1").await;
    let p2 = r.create(&setup, "p2").await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        let c = r
            .client(if i % 2 == 0 {
                ClientKind::Cli
            } else {
                ClientKind::Mcp
            })
            .await;
        let dir = if i % 3 == 0 { p2.clone() } else { p1.clone() };
        tasks.push(tokio::spawn(async move {
            for _ in 0..5 {
                let list = call(&c, &dir, "list_functions", json!({"limit": 2}))
                    .await
                    .unwrap();
                assert_eq!(list["items"].as_array().unwrap().len(), 2);
                let info = call(&c, &dir, "project_info", json!({})).await.unwrap();
                assert_eq!(Path::new(info["project_dir"].as_str().unwrap()), dir);
            }
            c
        }));
    }
    let mut clients = Vec::new();
    for t in tasks {
        clients.push(t.await.unwrap());
    }
    let st = setup.status().await.unwrap();
    assert_eq!(st["sessions"].as_array().unwrap().len(), 2);
    assert_eq!(st["daemon"]["clients"], 9);
    // One engine per project, not one per client.
    assert_eq!(r.ctl.created.load(Ordering::SeqCst), 2);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mutations_are_serialized_and_all_apply() {
    let r = rig();
    let setup = r.client(ClientKind::Cli).await;
    let dir = r.create(&setup, "p").await;
    let list = call(&setup, &dir, "list_functions", json!({}))
        .await
        .unwrap();
    let addrs: Vec<String> = (0..3).map(|i| address_of(&list, i)).collect();
    r.ctl.push_delay_ms.store(25, Ordering::SeqCst);

    let started = std::time::Instant::now();
    let mut tasks = Vec::new();
    for (i, addr) in addrs.iter().enumerate() {
        let c = r.client(ClientKind::Cli).await;
        let (dir, addr) = (dir.clone(), addr.clone());
        tasks.push(tokio::spawn(async move {
            for round in 0..3 {
                let out = call(
                    &c,
                    &dir,
                    "rename_symbol",
                    json!({"address": addr, "new_name": format!("renamed_{i}_{round}")}),
                )
                .await
                .unwrap();
                assert_eq!(out["status"], "applied", "{out}");
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(r.ctl.pushes.load(Ordering::SeqCst), 9);
    assert_eq!(
        r.ctl.max_pushes_in_flight.load(Ordering::SeqCst),
        1,
        "pushes never overlap"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(9 * 25),
        "pushes ran one after another"
    );
    let hist = call(&setup, &dir, "history", json!({"limit": 50}))
        .await
        .unwrap();
    assert_eq!(hist["items"].as_array().unwrap().len(), 9);

    // Queries keep flowing while a slow mutation runs.
    r.ctl.push_delay_ms.store(300, Ordering::SeqCst);
    let c = r.client(ClientKind::Cli).await;
    let (d2, a2) = (dir.clone(), addrs[0].clone());
    let slow = tokio::spawn(async move {
        call(
            &c,
            &d2,
            "rename_symbol",
            json!({"address": a2, "new_name": "slow_one"}),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let t0 = std::time::Instant::now();
    call(&setup, &dir, "list_functions", json!({}))
        .await
        .unwrap();
    assert!(
        t0.elapsed() < Duration::from_millis(200),
        "queries are not queued behind writes"
    );
    assert_eq!(slow.await.unwrap().unwrap()["status"], "applied");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_vanished_client_does_not_break_the_write_queue() {
    let r = rig();
    let setup = r.client(ClientKind::Cli).await;
    let dir = r.create(&setup, "p").await;
    let list = call(&setup, &dir, "list_functions", json!({}))
        .await
        .unwrap();
    let (a0, a1) = (address_of(&list, 0), address_of(&list, 1));
    r.ctl.push_delay_ms.store(150, Ordering::SeqCst);

    let gone = r.client(ClientKind::Cli).await;
    let (d, a) = (dir.clone(), a0.clone());
    let doomed = tokio::spawn(async move {
        call(
            &gone,
            &d,
            "rename_symbol",
            json!({"address": a, "new_name": "from_gone"}),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    doomed.abort(); // drops the only handle of that connection mid-call
    let _ = doomed.await;

    let out = call(
        &setup,
        &dir,
        "rename_symbol",
        json!({"address": a1, "new_name": "after_gone"}),
    )
    .await
    .unwrap();
    assert_eq!(out["status"], "applied");
    assert_eq!(r.ctl.max_pushes_in_flight.load(Ordering::SeqCst), 1);
    // The abandoned mutation still completed: it is in the log exactly once.
    let hist = call(&setup, &dir, "history", json!({"limit": 10}))
        .await
        .unwrap();
    assert_eq!(hist["items"].as_array().unwrap().len(), 2, "{hist}");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn gui_navigate_and_job_starts_reach_the_other_clients() {
    let r = rig();
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("event stream");
    let worker = r.client(ClientKind::Cli).await;
    let dir = r.create(&worker, "p").await;

    let started = call(&worker, &dir, "analyze", json!({})).await.unwrap();
    let ev = next_event(&mut rx, "job_started").await;
    assert_eq!(ev["job_id"], started["job_id"]);
    assert_eq!(ev["command"], "analyze");
    assert_eq!(ev["author_kind"], "user");
    next_event(&mut rx, "job_done").await;

    let out = call(
        &worker,
        &dir,
        "gui_navigate",
        json!({"address": "0x401136", "tab": "listing"}),
    )
    .await
    .unwrap();
    assert_eq!(out["requested"], true);
    let ev = next_event(&mut rx, "gui_navigate").await;
    assert_eq!(ev["address"], "0x401136");
    assert_eq!(ev["tab"], "listing");
    assert_eq!(ev["author_id"], "tester");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_action_highlight_and_state_round_trip_through_the_daemon() {
    let r = rig();
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("event stream");
    let worker = r.client(ClientKind::Cli).await;
    let dir = r.create(&worker, "p").await;

    // No GUI has published its state yet.
    let st = call(&worker, &dir, "ui_state", json!({})).await.unwrap();
    assert_eq!(st["attached"], false, "{st}");

    // The GUI publishes tabs and a selection; an agent reads them back.
    watcher
        .set_gui_selection(
            &dir,
            Some(kraken_host::daemon::GuiSelection {
                kind: "function".into(),
                function: Some("0x401136".into()),
                function_name: Some("main".into()),
                tabs: vec!["decompiler".into(), "history".into()],
                active_tab: Some("decompiler".into()),
                actions: vec!["show_history".into()],
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    let st = call(&worker, &dir, "ui_state", json!({})).await.unwrap();
    assert_eq!(st["attached"], true, "{st}");
    assert_eq!(st["tabs"], json!(["decompiler", "history"]));
    assert_eq!(st["active_tab"], "decompiler");
    assert_eq!(st["function_name"], "main");
    assert_eq!(st["actions"], json!(["show_history"]));

    // An action reaches the GUI as an event.
    call(
        &worker,
        &dir,
        "ui_action",
        json!({"action": "show_history", "tab": "graph", "address": "0x401136"}),
    )
    .await
    .unwrap();
    let ev = next_event(&mut rx, "gui_ui").await;
    assert_eq!(ev["action"], "show_history");
    assert_eq!(ev["tab"], "graph");
    assert_eq!(ev["address"], "0x401136");

    call(
        &worker,
        &dir,
        "ui_highlight",
        json!({"target": "proposals", "note": "Review my renames"}),
    )
    .await
    .unwrap();
    let ev = next_event(&mut rx, "gui_ui").await;
    assert_eq!(ev["target"], "proposals");
    assert_eq!(ev["note"], "Review my renames");

    // Closing the program or quitting is refused, and nothing is sent.
    let err = call(&worker, &dir, "ui_action", json!({"action": "quit"}))
        .await
        .unwrap_err();
    assert!(err.message.contains("not available to agents"), "{err:?}");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_client_sees_the_change_event_stream() {
    let r = rig();
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("event stream");
    let worker = r.client(ClientKind::Cli).await;

    let dir = r.create(&worker, "p").await;
    let opened = next_event(&mut rx, "session_opened").await;
    // Events carry the canonical project path (macOS temp dirs sit behind a symlink).
    assert_eq!(
        Path::new(opened["project_dir"].as_str().unwrap()),
        canon(&dir)
    );

    let started = call(&worker, &dir, "analyze", json!({})).await.unwrap();
    let progress = next_event(&mut rx, "job_progress").await;
    assert_eq!(progress["job_id"], started["job_id"]);
    assert!(progress["phase"].is_string() && progress["total"].is_number());
    let done = next_event(&mut rx, "job_done").await;
    assert_eq!(done["job_id"], started["job_id"]);
    assert_eq!(done["status"], "succeeded");
    assert!(done["result"]["function_count"].as_u64().unwrap() >= 3);

    let list = call(&worker, &dir, "list_functions", json!({}))
        .await
        .unwrap();
    let addr = address_of(&list, 0);
    let out = call(
        &worker,
        &dir,
        "rename_symbol",
        json!({"address": addr, "new_name": "from_worker"}),
    )
    .await
    .unwrap();
    let ev = next_event(&mut rx, "entry_applied").await;
    assert_eq!(ev["command"], "rename_symbol");
    assert_eq!(ev["status"], "applied");
    assert_eq!(ev["entry_id"], out["entry_id"]);
    assert_eq!(ev["author_id"], "tester");
    assert_eq!(ev["author_kind"], "user");

    // An agent overwriting a user-named function ends up as a proposal.
    let mut agent = params(
        &dir,
        "rename_symbol",
        json!({"address": addr, "new_name": "agent_idea"}),
    );
    agent.author_kind = AuthorKind::Agent;
    agent.author_id = Some("bot".into());
    agent.run_id = Some("run-1".into());
    let prop = worker.call(&agent).await.unwrap().result;
    assert_eq!(prop["status"], "proposed", "{prop}");
    let pev = next_event(&mut rx, "proposal_created").await;
    assert_eq!(pev["proposal_id"], prop["proposal_id"]);
    assert_eq!(pev["run_id"], "run-1");

    // Sequence numbers are strictly increasing, and a late client can catch up.
    let late = r.client(ClientKind::Gui).await;
    let all = late.events_since(0, Some(1000)).await.unwrap();
    let seqs: Vec<u64> = all["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    assert!(seqs.len() >= 5, "{seqs:?}");
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(all["last_seq"], *seqs.last().unwrap());
    let tail = late.events_since(seqs[seqs.len() - 2], None).await.unwrap();
    assert_eq!(tail["events"].as_array().unwrap().len(), 1);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_exit_follows_the_clock_and_cleans_up() {
    let r = rig_with(settings(600, 1800, 4), Duration::ZERO);
    let c = r.client(ClientKind::Cli).await;
    r.create(&c, "p").await;

    // A connected client keeps the daemon alive however long the clock runs.
    r.clock.advance(Duration::from_secs(6000));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!r.daemon.as_ref().unwrap().is_stopping());

    drop(c);
    wait_until("the client to be gone", || {
        r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    // The idle period starts when the monitor first sees no activity.
    tokio::time::sleep(Duration::from_millis(100)).await;
    r.clock.advance(Duration::from_secs(599));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !r.daemon.as_ref().unwrap().is_stopping(),
        "not yet idle long enough"
    );

    // A new client resets the idle period.
    let c2 = r.client(ClientKind::Cli).await;
    call(&c2, &r.project("p"), "project_info", json!({}))
        .await
        .unwrap();
    // Long enough for the monitor to see it.
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(c2);
    wait_until("the client to be gone", || {
        r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    r.clock.advance(Duration::from_secs(599));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!r.daemon.as_ref().unwrap().is_stopping());
    r.clock.advance(Duration::from_secs(2));

    let mut r = r;
    let d = r.daemon.take().unwrap();
    tokio::time::timeout(Duration::from_secs(10), d.wait())
        .await
        .expect("the idle daemon exits");
    assert!(!r.dir.socket_path().exists(), "socket removed");
    assert!(!r.dir.info_path().exists(), "daemon.json removed");
    assert!(!r.dir.token_path().exists(), "token removed");
    assert!(
        r.ctl
            .closed
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.ends_with("p")),
        "the session's sidecar was stopped"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_running_job_keeps_an_otherwise_idle_daemon_alive() {
    // 9 analysis steps of 120 ms.
    let r = rig_with(settings(60, 1800, 4), Duration::from_millis(120));
    let c = r.client(ClientKind::Cli).await;
    let dir = r.create(&c, "p").await;
    call(&c, &dir, "analyze", json!({})).await.unwrap();
    drop(c);
    wait_until("the client to be gone", || {
        r.daemon.as_ref().unwrap().clients() == 0
    })
    .await;
    wait_until("the job to be counted", || {
        r.daemon.as_ref().unwrap().running_jobs() == 1
    })
    .await;
    for _ in 0..3 {
        r.clock.advance(Duration::from_secs(1000));
        tokio::time::sleep(Duration::from_millis(60)).await;
        let d = r.daemon.as_ref().unwrap();
        if d.running_jobs() == 0 {
            break;
        }
        assert!(!d.is_stopping(), "must not exit while analysis runs");
    }
    wait_until("the job to finish", || {
        r.daemon.as_ref().unwrap().running_jobs() == 0
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    r.clock.advance(Duration::from_secs(61));
    let mut r = r;
    let d = r.daemon.take().unwrap();
    tokio::time::timeout(Duration::from_secs(10), d.wait())
        .await
        .expect("exits once the job is done and the idle time passed");
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_restart_replays_pending_entries() {
    let r = rig();
    let c = r.client(ClientKind::Cli).await;
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("events");
    let dir = r.create(&c, "p").await;
    let list = call(&c, &dir, "list_functions", json!({})).await.unwrap();
    let addr = address_of(&list, 0);

    // The sidecar "dies" while a push is under way: the entry stays pending in the log.
    r.ctl.fail_pushes_as_cancelled.store(true, Ordering::SeqCst);
    let err = call(
        &c,
        &dir,
        "rename_symbol",
        json!({"address": addr, "new_name": "survivor"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled, "{err:?}");
    let info = call(&c, &dir, "project_info", json!({})).await.unwrap();
    assert_eq!(info["pending_entries"], 1);

    // The sidecar comes back: the daemon restarts it, replays the log and tells everyone.
    r.ctl
        .fail_pushes_as_cancelled
        .store(false, Ordering::SeqCst);
    r.ctl
        .emit(&dir.join("ghidra"), EngineEvent::Exited { code: Some(137) });
    let exited = next_event(&mut rx, "sidecar_exited").await;
    assert_eq!(exited["code"], 137);
    let restarted = next_event(&mut rx, "sidecar_restarted").await;
    assert_eq!(restarted["replayed"], 1, "{restarted}");
    assert_eq!(restarted["rejected"], 0);
    assert_eq!(r.ctl.restarts.load(Ordering::SeqCst), 1);

    let info = call(&c, &dir, "project_info", json!({})).await.unwrap();
    assert_eq!(info["pending_entries"], 0);
    let found = call(
        &c,
        &dir,
        "list_functions",
        json!({"name_filter": "survivor"}),
    )
    .await
    .unwrap();
    assert_eq!(found["items"].as_array().unwrap().len(), 1, "{found}");

    // Events of engines the daemon does not know about are ignored.
    r.ctl
        .emit(Path::new("/nowhere/ghidra"), EngineEvent::Restarted);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(r.ctl.restarts.load(Ordering::SeqCst), 1);
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_are_limited_evicted_and_closed_when_idle() {
    let r = rig_with(settings(100_000, 300, 2), Duration::ZERO);
    let c = r.client(ClientKind::Cli).await;
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("events");
    let p1 = r.create(&c, "p1").await;
    r.clock.advance(Duration::from_secs(1));
    let p2 = r.create(&c, "p2").await;
    r.clock.advance(Duration::from_secs(1));
    // Both are in use recently; a third evicts the least recently used one (p1).
    call(&c, &p2, "project_info", json!({})).await.unwrap();
    let p3 = r.create(&c, "p3").await;
    let closed = next_event(&mut rx, "session_closed").await;
    assert_eq!(closed["reason"], "evicted");
    assert_eq!(
        Path::new(closed["project_dir"].as_str().unwrap()),
        canon(&p1)
    );
    let st = c.status().await.unwrap();
    let open: Vec<&str> = st["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["project_dir"].as_str().unwrap())
        .collect();
    assert_eq!(open.len(), 2);
    assert!(open.contains(&p2.to_str().unwrap()) && open.contains(&p3.to_str().unwrap()));
    assert!(r.ctl.closed.lock().unwrap().iter().any(|p| p == &p1));

    // The evicted project reopens on demand (evicting another).
    let info = call(&c, &p1, "project_info", json!({})).await.unwrap();
    assert_eq!(Path::new(info["project_dir"].as_str().unwrap()), p1);

    // Idle sessions are closed after their own idle time.
    r.clock.advance(Duration::from_secs(301));
    for _ in 0..2 {
        let ev = next_event(&mut rx, "session_closed").await;
        assert!(["evicted", "idle"].contains(&ev["reason"].as_str().unwrap()));
    }
    wait_until("all sessions to close", || {
        r.daemon.as_ref().unwrap().host().session_count() == 0
    })
    .await;
    // ... and any call opens its project again.
    let again = call(&c, &p3, "project_info", json!({})).await.unwrap();
    assert_eq!(again["program"]["format"], "elf");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn too_many_busy_sessions_are_refused_not_evicted() {
    let r = rig_with(settings(100_000, 100_000, 1), Duration::from_millis(200));
    let c = r.client(ClientKind::Cli).await;
    let p1 = r.create(&c, "p1").await;
    call(&c, &p1, "analyze", json!({})).await.unwrap();
    let err = call(
        &c,
        &r.project("p2"),
        "project_create",
        json!({"binary": r.binary, "project_dir": r.project("p2")}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported, "{err:?}");
    assert!(err.message.contains("too many open projects"));
    // The busy session is untouched.
    let info = call(&c, &p1, "project_info", json!({})).await.unwrap();
    assert_eq!(info["analysis"]["phase"], "running");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn project_open_on_an_open_project_reports_instead_of_reopening() {
    let r = rig();
    let c = r.client(ClientKind::Cli).await;
    let dir = r.create(&c, "p").await;
    let created = r.ctl.created.load(Ordering::SeqCst);
    let again = call(&c, &dir, "project_open", json!({"project_dir": dir}))
        .await
        .unwrap();
    assert_eq!(again["program"]["format"], "elf");
    assert_eq!(
        r.ctl.created.load(Ordering::SeqCst),
        created,
        "no second engine"
    );
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shutdown_method_stops_the_daemon_and_removes_its_files() {
    let mut r = rig();
    let c = r.client(ClientKind::Cli).await;
    c.shutdown().await.unwrap();
    let d = r.daemon.take().unwrap();
    tokio::time::timeout(Duration::from_secs(10), d.wait())
        .await
        .expect("stops");
    assert!(!r.dir.socket_path().exists());
    assert!(!r.dir.info_path().exists());
    // A new daemon can start in the same directory afterwards.
    let again = krakend::start(DaemonOptions {
        runtime_dir: r.dir.clone(),
        factory: Arc::new(FakeFactory::new(fixture(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: settings(600, 600, 2),
        session_config: SessionConfig::default(),
        clock: Arc::new(ManualClock::new()),
        poll: Duration::from_millis(10),
        build: "test-build".into(),
    })
    .expect("restart in the same directory");
    again.shutdown();
    again.wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_daemon_in_the_same_directory_is_refused() {
    let r = rig();
    let second = krakend::start(DaemonOptions {
        runtime_dir: r.dir.clone(),
        factory: Arc::new(FakeFactory::new(fixture(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: settings(600, 600, 2),
        session_config: SessionConfig::default(),
        clock: Arc::new(ManualClock::new()),
        poll: Duration::from_millis(10),
        build: "test-build".into(),
    });
    assert!(matches!(second, Err(krakend::DaemonError::AlreadyRunning)));
    r.stop().await;
}

/// The canonical form the daemon publishes events under.
fn canon(p: &Path) -> std::path::PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

#[tokio::test(flavor = "multi_thread")]
async fn binary_probe_makes_no_session_and_project_close_ends_one() {
    let r = rig();
    let c = r.client(ClientKind::Gui).await;
    let probe = call(
        &c,
        &r.project("unused"),
        "binary_probe",
        json!({"path": r.binary}),
    )
    .await
    .expect("binary_probe");
    assert_eq!(probe["size"], 16);
    assert_eq!(c.status().await.unwrap()["sessions"], json!([]));

    let dir = r.create(&c, "p1").await;
    assert_eq!(
        c.status().await.unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let closed = call(&c, &dir, "project_close", json!({})).await.unwrap();
    assert_eq!(closed["closed"], true);
    assert_eq!(c.status().await.unwrap()["sessions"], json!([]));
    let again = call(&c, &dir, "project_close", json!({})).await.unwrap();
    assert_eq!(again["closed"], false);
    // The next command opens it again.
    let info = call(&c, &dir, "project_info", json!({})).await.unwrap();
    assert_eq!(info["program"]["format"], "elf");
    r.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_reports_progress_and_job_cancel_stops_it_cleanly() {
    let r = rig();
    let watcher = r.client(ClientKind::Gui).await;
    let mut rx = watcher.take_events().expect("event stream");
    let opener = Arc::new(r.client(ClientKind::Cli).await);
    let dir = r.project("slow");

    // a quick open first: stages in order, the fraction never goes back and ends at 1
    let quick = r.project("quick");
    r.create(&opener, "quick").await;
    let mut stages = Vec::new();
    let mut fractions = Vec::new();
    loop {
        let ev = next_event(&mut rx, "open_progress").await;
        assert_eq!(
            Path::new(ev["project_dir"].as_str().unwrap()),
            canon(&quick)
        );
        assert_eq!(ev["command"], "project_create");
        assert_eq!(ev["program"], "prog.bin");
        if let Some(f) = ev["fraction"].as_f64() {
            fractions.push(f);
        }
        let stage = ev["stage"].as_str().unwrap().to_string();
        stages.push(stage.clone());
        if stage == "ready" {
            break;
        }
    }
    assert_eq!(stages.first().map(String::as_str), Some("prepare"));
    assert!(fractions.windows(2).all(|w| w[0] <= w[1]), "{fractions:?}");
    assert_eq!(fractions.last(), Some(&1.0));

    // a slow one, cancelled through its job from another connection
    r.ctl.open_delay_ms.store(60_000, Ordering::SeqCst);
    let create = {
        let (c, dir, binary) = (opener.clone(), dir.clone(), r.binary.clone());
        tokio::spawn(async move {
            call(
                &c,
                &dir,
                "project_create",
                json!({"binary": binary, "project_dir": dir}),
            )
            .await
        })
    };
    let job = loop {
        let ev = next_event(&mut rx, "open_progress").await;
        if ev["stage"] == "functions" {
            assert!(ev["elapsed_ms"].is_u64());
            assert!(ev["found"].is_u64() && ev["queued"].is_u64());
            break ev["job_id"].as_str().unwrap().to_string();
        }
    };
    let canceller = r.client(ClientKind::Gui).await;
    let status = call(&canceller, &dir, "job_status", json!({ "job_id": job }))
        .await
        .expect("job_status during the open");
    assert_eq!(status["status"], "running");
    assert_eq!(status["open_progress"]["stage"], "functions");
    let started = std::time::Instant::now();
    call(&canceller, &dir, "job_cancel", json!({ "job_id": job }))
        .await
        .expect("job_cancel");
    let e = tokio::time::timeout(Duration::from_secs(10), create)
        .await
        .expect("the open stops")
        .unwrap()
        .expect_err("cancelled");
    assert_eq!(e.code, ErrorCode::Cancelled, "{e:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    let sessions = canceller.status().await.unwrap()["sessions"].clone();
    assert!(
        sessions
            .as_array()
            .unwrap()
            .iter()
            .all(|s| canon(Path::new(s["project_dir"].as_str().unwrap())) != canon(&dir)),
        "no half-open session: {sessions}"
    );
    assert!(
        r.ctl
            .closed
            .lock()
            .unwrap()
            .iter()
            .any(|d| canon(d) == canon(&dir)),
        "the engine of the cancelled open was stopped"
    );
    // the same folder can be used right away
    r.ctl.open_delay_ms.store(0, Ordering::SeqCst);
    r.create(&opener, "slow").await;
    r.stop().await;
}

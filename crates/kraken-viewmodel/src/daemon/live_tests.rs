//! [`DaemonClientBackend`] against an in-process `krakend` over a real socket in a private
//! runtime directory, with the scripted fake engine.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use engine_fake::FixtureFile;
use kraken_host::daemon::{CallParams, DaemonClient};
use kraken_ipc::{Client, ClientHello, ClientKind, ManualClock, RuntimeDir};
use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, Locator};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory;
use krakend::{Daemon, DaemonOptions};
use serde_json::{Value, json};
use tokio::runtime::Runtime;

use super::*;
use crate::{AnalysisPhase, ApprovalBroker, Connection, LinkState, ToastLevel, ViewModel};

const WAIT: Duration = Duration::from_secs(20);
const TINY: &str = "../engine-fake/fixtures/tiny.json";

fn fixture() -> FixtureFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(TINY);
    let mut fx = FixtureFile::from_path(&path).expect("tiny fixture");
    for f in &mut fx.functions {
        if let Locator::Native { offset, .. } = &f.summary.locator {
            f.summary.name = format!("FUN_{:08x}", offset.0);
        }
    }
    fx
}

fn start_daemon(dir: &RuntimeDir) -> Daemon {
    krakend::start(DaemonOptions {
        runtime_dir: dir.clone(),
        factory: Arc::new(FakeFactory::new(fixture(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: kraken_host::DaemonSettings {
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
}

struct Rig {
    rt: Arc<Runtime>,
    tmp: tempfile::TempDir,
    dir: RuntimeDir,
    daemon: Option<Daemon>,
}

impl Rig {
    fn new() -> Self {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime"),
        );
        let tmp = tempfile::Builder::new()
            .prefix("kraken-vm")
            .tempdir()
            .expect("tempdir");
        let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
        // The daemon's tasks live on this runtime.
        let daemon = {
            let _guard = rt.enter();
            start_daemon(&dir)
        };
        Rig {
            rt,
            tmp,
            dir,
            daemon: Some(daemon),
        }
    }

    fn backend(&self) -> Arc<DaemonClientBackend> {
        let opts = BackendOptions {
            author: "tester".into(),
            backoff: Backoff {
                initial: Duration::from_millis(20),
                max: Duration::from_millis(100),
            },
        };
        Arc::new(
            self.rt
                .block_on(DaemonClientBackend::connect(
                    attach_connector(self.dir.clone()),
                    opts,
                ))
                .expect("backend connects"),
        )
    }

    fn vm(&self, backend: &Arc<DaemonClientBackend>) -> ViewModel {
        ViewModel::new(backend.clone(), self.rt.handle().clone())
    }

    fn binary(&self) -> PathBuf {
        let p = self.tmp.path().join("prog.bin");
        std::fs::write(&p, b"\x7fELF fake binary").expect("binary");
        p
    }

    fn project_dir(&self) -> PathBuf {
        self.tmp.path().join("proj")
    }

    /// A VM with the project created and analysis complete.
    fn analyzed_vm(&self, backend: &Arc<DaemonClientBackend>) -> ViewModel {
        let mut vm = self.vm(backend);
        vm.create_project(
            self.binary().to_string_lossy().into_owned(),
            self.project_dir().to_string_lossy().into_owned(),
        );
        assert!(
            vm.block_until(WAIT, |v| v.connection == Connection::Open),
            "project opens: {:?}",
            vm.connection
        );
        vm.start_analysis();
        assert!(
            vm.block_until(WAIT, |v| {
                v.analysis.phase == AnalysisPhase::Complete
                    && !v.functions.items.is_empty()
                    && !v.busy()
            }),
            "analysis completes: {:?}",
            vm.analysis
        );
        vm
    }

    /// A second client, as an MCP agent or the CLI would connect.
    fn other_client(&self, kind: ClientKind) -> DaemonClient {
        self.rt.block_on(async {
            let c = Client::connect(&self.dir, &ClientHello::new(kind, BUILD))
                .await
                .expect("connect");
            DaemonClient::from_client(c, BUILD)
        })
    }

    fn call(
        &self,
        c: &DaemonClient,
        author: AuthorKind,
        id: &str,
        run: Option<&str>,
        command: &str,
        args: Value,
    ) -> Value {
        let params = CallParams {
            project_dir: self.project_dir().to_string_lossy().into_owned(),
            command: command.into(),
            args,
            author_kind: author,
            author_id: Some(id.into()),
            run_id: run.map(str::to_string),
            surface: None,
            approved: false,
        };
        self.rt
            .block_on(c.call(&params))
            .expect("call succeeds")
            .result
    }

    fn stop_daemon(&mut self) {
        let d = self.daemon.take().expect("daemon");
        d.shutdown();
        self.rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), d.wait())
                .await
                .expect("daemon stops");
        });
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        if self.daemon.is_some() {
            self.stop_daemon();
        }
    }
}

fn first_function(vm: &ViewModel) -> (u64, String) {
    let f = &vm.functions.items[0];
    (f.address, f.name.clone())
}

#[test]
fn calls_and_commands_go_through_the_daemon() {
    let rig = Rig::new();
    let backend = rig.backend();
    assert!(backend.is_connected());
    let cmds = backend.commands();
    let analyze = cmds.iter().find(|c| c.name == "analyze").expect("analyze");
    assert_eq!(analyze.kind, crate::CommandKind::Job);

    let no_project = rig
        .rt
        .block_on(backend.call("list_functions", json!({})))
        .unwrap_err();
    assert_eq!(no_project.code, ErrorCode::NotFound);

    let vm = rig.analyzed_vm(&backend);
    assert_eq!(
        backend.current_project().as_deref(),
        Some(rig.project_dir().as_path())
    );
    assert!(vm.functions.items.len() >= 3);
    let status = rig.rt.block_on(backend.status()).expect("status");
    assert_eq!(status["sessions"].as_array().map(Vec::len), Some(1));
}

#[test]
fn an_agent_edit_from_a_second_client_refreshes_the_gui_with_an_undo() {
    let rig = Rig::new();
    let backend = rig.backend();
    let mut vm = rig.analyzed_vm(&backend);
    let (addr, old) = first_function(&vm);
    let agent = rig.other_client(ClientKind::Mcp);

    let out = rig.call(
        &agent,
        AuthorKind::Agent,
        "claude",
        Some("run-7"),
        "rename_symbol",
        json!({"address": format!("{addr:#x}"), "new_name": "agent_picked"}),
    );
    assert_eq!(out["status"], "applied", "{out}");

    assert!(
        vm.block_until(WAIT, |v| {
            v.functions.items.iter().any(|f| f.name == "agent_picked")
                && v.toasts.iter().any(|t| t.action.is_some())
        }),
        "function list refreshed and toast shown: {:?} {:?}",
        vm.functions.items.first(),
        vm.toasts
    );
    let toast = vm
        .toasts
        .iter()
        .find(|t| t.action.is_some())
        .cloned()
        .expect("toast");
    assert!(
        toast.text.contains(&format!("Agent renamed {old}")) && toast.text.contains("agent_picked"),
        "{}",
        toast.text
    );
    assert_eq!(toast.level, ToastLevel::Info);
    assert!(
        vm.block_until(WAIT, |v| v.history.entries.iter().any(|h| h.by_agent)),
        "history shows the agent edit"
    );

    vm.run_toast_action(toast.id);
    assert!(
        vm.block_until(WAIT, |v| {
            v.functions.items.iter().any(|f| f.name == old)
                && !v.functions.items.iter().any(|f| f.name == "agent_picked")
        }),
        "undo restored the name: {:?}",
        vm.toasts
    );
}

#[test]
fn an_agent_proposal_shows_up_in_the_proposals_tab() {
    let rig = Rig::new();
    let backend = rig.backend();
    let mut vm = rig.analyzed_vm(&backend);
    let (addr, _) = first_function(&vm);
    let cli = rig.other_client(ClientKind::Cli);
    let agent = rig.other_client(ClientKind::Mcp);
    let hex = format!("{addr:#x}");

    rig.call(
        &cli,
        AuthorKind::User,
        "tester",
        None,
        "rename_symbol",
        json!({"address": hex, "new_name": "mine"}),
    );
    assert!(vm.block_until(WAIT, |v| v.functions.items.iter().any(|f| f.name == "mine")));

    let out = rig.call(
        &agent,
        AuthorKind::Agent,
        "claude",
        Some("run-8"),
        "rename_symbol",
        json!({"address": hex, "new_name": "theirs"}),
    );
    assert_eq!(out["status"], "proposed", "{out}");
    assert!(
        vm.block_until(WAIT, |v| {
            !v.proposals.items.is_empty()
                && v.project.as_ref().is_some_and(|p| p.open_proposals == 1)
                && v.toasts.iter().any(|t| t.text.contains("proposed"))
        }),
        "proposal visible: {:?} {:?}",
        vm.proposals.items,
        vm.toasts
    );
    assert_eq!(vm.proposals.items[0].who, "claude");
    assert!(
        vm.functions.items.iter().any(|f| f.name == "mine"),
        "the proposal did not change the name"
    );
}

#[test]
fn events_of_other_projects_are_ignored() {
    let rig = Rig::new();
    let backend = rig.backend();
    let vm = rig.analyzed_vm(&backend);
    let mut events = backend.events();
    // A second project in the same daemon.
    let other = rig.tmp.path().join("other");
    let cli = rig.other_client(ClientKind::Cli);
    let params = CallParams {
        project_dir: other.to_string_lossy().into_owned(),
        command: "project_create".into(),
        args: json!({"binary": rig.binary(), "project_dir": other}),
        author_kind: AuthorKind::User,
        author_id: Some("tester".into()),
        run_id: None,
        surface: None,
        approved: false,
    };
    rig.rt.block_on(cli.call(&params)).expect("create");
    let addr = vm.functions.items[0].address;
    let mut p = params;
    p.command = "rename_symbol".into();
    p.args = json!({"address": format!("{addr:#x}"), "new_name": "elsewhere"});
    rig.rt.block_on(cli.call(&p)).expect("rename elsewhere");
    std::thread::sleep(Duration::from_millis(300));
    while let Ok(ev) = events.try_recv() {
        assert!(
            !matches!(ev, BackendEvent::EntryApplied(_)),
            "an edit of another project leaked: {ev:?}"
        );
    }
}

#[test]
fn the_backend_reconnects_after_the_daemon_restarts_and_the_gui_refreshes() {
    let mut rig = Rig::new();
    let backend = rig.backend();
    let mut vm = rig.analyzed_vm(&backend);

    rig.stop_daemon();
    assert!(
        vm.block_until(WAIT, |v| matches!(v.link, LinkState::Disconnected(_))),
        "disconnect noticed"
    );
    assert!(!backend.is_connected());
    let err = rig
        .rt
        .block_on(backend.call("list_functions", json!({})))
        .unwrap_err();
    assert!(err.message.contains("not connected"), "{}", err.message);

    {
        let _guard = rig.rt.enter();
        rig.daemon = Some(start_daemon(&rig.dir));
    }
    assert!(
        vm.block_until(WAIT, |v| v.link == LinkState::Connected),
        "reconnected"
    );
    assert!(backend.is_connected());
    assert!(
        vm.block_until(WAIT, |v| {
            !v.busy() && v.toasts.iter().any(|t| t.text.contains("Reconnected"))
        }),
        "refresh settles"
    );
    assert!(vm.functions.error.is_none(), "{:?}", vm.functions.error);
    let info = rig
        .rt
        .block_on(backend.call("project_info", json!({})))
        .expect("the project reopens on the new daemon");
    assert_eq!(info["program"]["format"], "elf");
}

#[test]
fn dangerous_commands_need_the_approver() {
    let rig = Rig::new();
    let backend = rig.backend();
    let _vm = rig.analyzed_vm(&backend);
    lock(&backend.inner.commands).push(CommandInfo {
        name: "wipe_everything".into(),
        summary: "Wipe".into(),
        kind: crate::CommandKind::Mutation,
        permission: Permission::Dangerous,
    });

    let denied = rig
        .rt
        .block_on(backend.call("wipe_everything", json!({})))
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::Unsupported);
    assert_eq!(denied.details, Some(json!({"approval": "denied"})));

    let broker = ApprovalBroker::new();
    backend.set_approver(Arc::new(broker.clone()));
    let b = backend.clone();
    let task = rig
        .rt
        .spawn(async move { b.call("wipe_everything", json!({})).await });
    let deadline = std::time::Instant::now() + WAIT;
    let (id, prompt) = loop {
        if let Some(q) = broker.current() {
            break q;
        }
        assert!(std::time::Instant::now() < deadline, "no approval asked");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(prompt.command, "wipe_everything");
    broker.respond(id, true);
    // Approved, so the call reached the daemon, which does not know the command.
    let reached = rig.rt.block_on(task).expect("join").unwrap_err();
    assert_eq!(reached.code, ErrorCode::NotFound, "{reached:?}");
}

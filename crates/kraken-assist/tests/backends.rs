//! Every task on both backends: a model API (scripted `ReplayProvider`) and a terminal agent
//! (the fake ACP agent, a separate process speaking raw ACP). The same task prompts go in, and
//! the same result types and event kinds come out. No network, no real agents.
// The fake agent is a Unix-style process in these tests.
#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_acp::{AgentProfile, LaunchSpec, McpServerConfig};
use kraken_agent::{
    AgentEvent, ApprovalDecision, ApprovalHandle, FinishReason, Message, ReplayProvider,
    StopReason, StreamEvent, ToolHost,
};
use kraken_assist::{
    AcpBackend, AcpSettings, ApiBackend, AssistBackend, Assistant, AutoNameOptions, BackendKind,
    Outcome, Purpose, RegistryToolHost, ResultTagFilter, RunSpec, SelectionKind, Task, TaskOutput,
    TaskResult,
};
use kraken_engine::SharedEngine;
use kraken_host::backend::{CommandBackend, LocalBackend};
use kraken_proto::ProtoError;
use kraken_registry::{EngineFactory, Registry, Session, Surface};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

/// The `kraken-fake-acp-agent` binary. Cargo builds a package's binaries only for that
/// package's own tests, so this builds it (a no-op when up to date) and finds it next to the
/// running test binary.
fn fake_agent() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().expect("test exe");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target profile dir")
            .to_path_buf();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "-q",
            "-p",
            "kraken-acp",
            "--bin",
            "kraken-fake-acp-agent",
        ]);
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
        let status = cmd.status().expect("run cargo build");
        assert!(status.success(), "building the fake ACP agent failed");
        let bin = profile_dir.join(format!(
            "kraken-fake-acp-agent{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(bin.is_file(), "missing {}", bin.display());
        bin
    })
    .clone()
}

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

struct Rig {
    tmp: tempfile::TempDir,
    registry: Arc<Registry>,
    backend: Arc<LocalBackend>,
}

async fn rig() -> Rig {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-assist-backends-")
        .tempdir()
        .expect("tempdir");
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake").expect("binary");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
    let fixture = FixtureFile::from_path(&path).expect("tiny fixture");
    let session = Arc::new(Session::new(Arc::new(FakeFactory { fixture })));
    session
        .create_project(&tmp.path().join("p"), &binary)
        .await
        .expect("project");
    let registry = Arc::new(Registry::standard());
    let backend = Arc::new(LocalBackend::new(registry.clone(), session, None));
    Rig {
        tmp,
        registry,
        backend,
    }
}

fn say(text: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta { text: text.into() },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

fn answer(prose: &str, result: &Value) -> Vec<StreamEvent> {
    say(&format!("{prose}\n<kraken-result>{result}</kraken-result>"))
}

/// A backend over a scripted model: one final answer carrying `result`.
fn api(result: &Value) -> Arc<dyn AssistBackend> {
    Arc::new(ApiBackend::new(Arc::new(ReplayProvider::scripted(vec![
        answer("Here is what I found.", result),
    ]))))
}

fn base_env() -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/home/test")),
    ]
}

fn acp_settings(rig: &Rig, env: &[(&str, &str)]) -> AcpSettings {
    let exe = fake_agent();
    let mut profile = AgentProfile::custom("fake", "Fake agent", exe.to_string_lossy(), vec![]);
    for (k, v) in env {
        profile = profile.with_env(*k, *v);
    }
    let dir = rig.tmp.path().to_path_buf();
    AcpSettings {
        profile,
        launch: LaunchSpec {
            program: exe,
            args: vec![],
            path_prepend: None,
            via: "test".into(),
        },
        mcp: McpServerConfig::project("/opt/kraken/kraken", &dir),
        project_dir: dir,
        parent_env: Some(base_env()),
        start_timeout: Duration::from_secs(20),
        model: None,
    }
}

fn acp(rig: &Rig, env: &[(&str, &str)]) -> Arc<AcpBackend> {
    Arc::new(AcpBackend::new(
        acp_settings(rig, env),
        rig.registry.clone(),
    ))
}

async fn run_on(
    rig: &Rig,
    engine: Arc<dyn AssistBackend>,
    task: Task,
) -> (TaskResult, Vec<AgentEvent>) {
    let a = Assistant::with_engine(rig.registry.clone(), rig.backend.clone(), engine)
        .with_surface(Surface::Test);
    let mut events = Vec::new();
    let r = a
        .run(task, &CancellationToken::new(), &mut |e| {
            events.push(e.clone());
        })
        .await;
    (r, events)
}

fn kind_of(o: &Option<TaskOutput>) -> &'static str {
    match o {
        Some(TaskOutput::Explanation(_)) => "explanation",
        Some(TaskOutput::Overview(_)) => "overview",
        Some(TaskOutput::AutoName(_)) => "auto_name",
        None => "none",
    }
}

fn all_text(events: &[AgentEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            AgentEvent::TextDelta { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

/// Events by variant name, in order, with the text deltas folded into one.
fn shape(events: &[AgentEvent]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for e in events {
        let name = match e {
            AgentEvent::TextDelta { .. } => "text",
            AgentEvent::ToolCallStarted { .. } => "tool_started",
            AgentEvent::ToolCallFinished { .. } => "tool_finished",
            AgentEvent::ApprovalRequired { .. } => "approval",
            AgentEvent::ProposalCreated { .. } => "proposal",
            AgentEvent::Error { .. } => "error",
            AgentEvent::Done { .. } => "done",
        };
        if name == "text" && out.last() == Some(&"text") {
            continue;
        }
        out.push(name);
    }
    out
}

const EXPLAIN: &str = r#"{"summary": "It calls a helper and returns its answer.",
    "key_behaviours": ["calls helper with its first argument", "returns the result"],
    "suggested_names": [{"name": "program_main", "reason": "takes argc"}], "caveats": []}"#;

fn explain_json() -> Value {
    serde_json::from_str(EXPLAIN).expect("json")
}

fn overview_json() -> Value {
    json!({
        "what_it_is": "A small command-line program.",
        "components": [{"name": "entry", "description": "starts the program"}],
        "interesting_functions": [
            {"address": "0x401000", "name": "FUN_00401000", "reason": "takes argc and argv"}
        ],
        "next_steps": ["Ask for an explanation of the first function"]
    })
}

fn autoname_json() -> Value {
    json!({"suggestions": [
        {"address": "0x401000", "current_name": "FUN_00401000", "new_name": "program_main",
         "comment": "Program entry.",
         "evidence": [{"kind": "string", "detail": "usage"}, {"kind": "import", "detail": "puts"},
                      {"kind": "caller", "detail": "entry stub"}]},
        {"address": "0x401040", "new_name": "assistant_guess",
         "evidence": [{"kind": "decompile", "detail": "short body"}]}
    ]})
}

#[tokio::test]
async fn explain_function_gives_the_same_result_type_on_both_backends() {
    let rig = rig().await;
    let task = || Task::explain_function(&rig.registry, "0x401000").expect("task");
    let (a, a_events) = run_on(&rig, api(&explain_json()), task()).await;
    let (t, t_events) = run_on(&rig, acp(&rig, &[]), task()).await;

    for r in [&a, &t] {
        assert_eq!(r.stop, StopReason::Completed, "{:?}", r.error);
        assert_eq!(kind_of(&r.output), "explanation");
        let Some(TaskOutput::Explanation(e)) = &r.output else {
            panic!("{:?}", r.output);
        };
        assert_eq!(e.summary, "It calls a helper and returns its answer.");
        assert_eq!(e.suggested_names[0].name, "program_main");
        assert!(!r.text.contains("kraken-result"), "{}", r.text);
    }
    assert_eq!(a.backend, BackendKind::Api);
    assert_eq!(t.backend, BackendKind::TerminalAgent);
    assert_eq!(t.provider.id, "fake");

    // KRAKEN tool calls show as chips named after the command, like the API path's.
    let names: Vec<_> = t.tool_calls.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["get_function", "decompile"]);
    assert_eq!(t.tool_calls[1].arguments["address"], "0x401000");
    assert!(t.tool_calls.iter().all(|c| !c.is_error));
    for events in [&a_events, &t_events] {
        let s = shape(events);
        assert_eq!(s.last(), Some(&"done"), "{s:?}");
        assert!(s.contains(&"text"), "{s:?}");
    }
    assert!(shape(&t_events).contains(&"tool_started"));
    assert!(shape(&t_events).contains(&"tool_finished"));
}

#[tokio::test]
async fn explain_selection_gives_the_same_result_type_on_both_backends() {
    let rig = rig().await;
    let task = || {
        Task::explain_selection(
            &rig.registry,
            SelectionKind::Decompile,
            "x = helper(1);",
            Some("0x401000"),
        )
        .expect("task")
    };
    let sel = json!({"summary": "It calls helper and stores the result in x.",
        "key_behaviours": ["calls helper"], "suggested_names": [], "caveats": []});
    let (a, _) = run_on(&rig, api(&sel), task()).await;
    let (t, _) = run_on(&rig, acp(&rig, &[]), task()).await;
    for r in [&a, &t] {
        assert_eq!(r.stop, StopReason::Completed, "{:?}", r.error);
        assert_eq!(kind_of(&r.output), "explanation");
        let Some(TaskOutput::Explanation(e)) = &r.output else {
            panic!("{:?}", r.output);
        };
        assert!(e.summary.contains("helper"));
    }
}

#[tokio::test]
async fn overview_gives_the_same_result_type_on_both_backends() {
    let rig = rig().await;
    let task = || Task::overview(&rig.registry);
    let (a, _) = run_on(&rig, api(&overview_json()), task()).await;
    let (t, _) = run_on(&rig, acp(&rig, &[]), task()).await;
    for r in [&a, &t] {
        assert_eq!(r.stop, StopReason::Completed, "{:?}", r.error);
        let Some(TaskOutput::Overview(o)) = &r.output else {
            panic!("{:?}", r.output);
        };
        assert_eq!(o.what_it_is, "A small command-line program.");
        assert_eq!(o.interesting_functions.len(), 1);
        assert_eq!(o.next_steps.len(), 1);
    }
    let names: Vec<_> = t.tool_calls.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["project_info", "list_functions"]);
}

#[tokio::test]
async fn auto_name_dry_run_gives_the_same_result_type_on_both_backends() {
    let rig = rig().await;
    let task = || {
        Task::auto_name(
            &rig.registry,
            AutoNameOptions {
                limit: 2,
                dry_run: true,
            },
        )
    };
    let (a, _) = run_on(&rig, api(&autoname_json()), task()).await;
    let (t, _) = run_on(&rig, acp(&rig, &[]), task()).await;
    for r in [&a, &t] {
        assert_eq!(r.stop, StopReason::Completed, "{:?}", r.error);
        let Some(TaskOutput::AutoName(rep)) = &r.output else {
            panic!("{:?}", r.output);
        };
        assert!(rep.dry_run);
        assert_eq!(rep.suggestions.len(), 2);
        assert!(
            rep.suggestions
                .iter()
                .all(|s| s.rename_outcome == Some(Outcome::NotAttempted))
        );
        assert_eq!(rep.applied + rep.proposed + rep.failed, 0);
    }
    assert!(t.tool_calls.iter().all(|c| c.name != "rename_symbol"));
}

#[tokio::test]
async fn auto_name_on_a_terminal_agent_reports_what_the_registry_did() {
    let rig = rig().await;
    let task = Task::auto_name(
        &rig.registry,
        AutoNameOptions {
            limit: 2,
            dry_run: false,
        },
    );
    let (t, events) = run_on(&rig, acp(&rig, &[]), task).await;
    assert_eq!(t.stop, StopReason::Completed, "{:?}", t.error);
    let Some(TaskOutput::AutoName(rep)) = &t.output else {
        panic!("{:?}", t.output);
    };
    // The agent's rename of 0x401000 and its comment applied, the other rename was held back.
    assert_eq!(rep.applied, 2, "{rep:?}");
    assert_eq!(rep.proposed, 1);
    let by = |addr: &str| {
        rep.suggestions
            .iter()
            .find(|s| s.address == addr)
            .expect(addr)
    };
    assert_eq!(by("0x401000").rename_outcome, Some(Outcome::Applied));
    assert_eq!(by("0x401000").comment_outcome, Some(Outcome::Applied));
    assert_eq!(by("0x401040").rename_outcome, Some(Outcome::Proposed));
    // The proposal reached the event stream and the result, like the API path's.
    assert_eq!(t.proposals.len(), 1);
    assert_eq!(t.proposals[0]["proposal_id"], 7);
    assert!(shape(&events).contains(&"proposal"));
    assert!(t.run_id.starts_with("run-"));
}

#[tokio::test]
async fn read_only_tasks_that_change_things_are_called_out() {
    let rig = rig().await;
    // The fake agent's auto-name turn renames; running it as a read-only explain task is
    // not possible, so mimic a misbehaving agent with an auto-name task marked read-only.
    let mut task = Task::auto_name(
        &rig.registry,
        AutoNameOptions {
            limit: 2,
            dry_run: false,
        },
    );
    task.read_only = true;
    let (t, _) = run_on(&rig, acp(&rig, &[]), task).await;
    assert!(
        t.warnings.iter().any(|w| w.contains("changed the project")),
        "{:?}",
        t.warnings
    );
}

#[tokio::test]
async fn the_agents_own_tools_wait_for_the_approval_flow() {
    let rig = rig().await;
    let task = || Task::overview(&rig.registry);

    // With no approver the request is denied, so a run never hangs.
    let (denied, events) = run_on(
        &rig,
        acp(&rig, &[("FAKE_ACP_TASK_PERMISSION", "1")]),
        task(),
    )
    .await;
    assert!(all_text(&events).contains("(shell denied)"));
    assert!(shape(&events).contains(&"approval"));
    assert_eq!(kind_of(&denied.output), "overview");

    // With one, the answer given through the handle is the agent's answer.
    let handle: Arc<Mutex<Option<ApprovalHandle>>> = Arc::default();
    let slot = handle.clone();
    let a = Assistant::with_engine(
        rig.registry.clone(),
        rig.backend.clone(),
        acp(&rig, &[("FAKE_ACP_TASK_PERMISSION", "1")]),
    )
    .with_approver(move |h| *slot.lock().expect("lock") = Some(h));
    let mut asked = Vec::new();
    let mut said = String::new();
    let r = a
        .run(task(), &CancellationToken::new(), &mut |e| {
            if let AgentEvent::TextDelta { text } = e {
                said.push_str(text);
            }
            if let AgentEvent::ApprovalRequired {
                id,
                name,
                arguments,
            } = e
            {
                asked.push((name.clone(), arguments.clone()));
                if let Some(h) = handle.lock().expect("lock").as_ref() {
                    h.decide(id.clone(), ApprovalDecision::Approve);
                }
            }
        })
        .await;
    assert!(said.contains("(shell allowed)"), "{said}");
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, "Run strings ./sample");
    assert_eq!(asked[0].1["kind"], "execute");
    assert_eq!(kind_of(&r.output), "overview");
}

#[tokio::test]
async fn chat_keeps_one_agent_session_between_turns() {
    let rig = rig().await;
    let record = rig.tmp.path().join("record.jsonl");
    let backend = acp(&rig, &[("FAKE_ACP_RECORD", record.to_str().expect("utf8"))]);
    let tools: Arc<dyn ToolHost> = Arc::new(RegistryToolHost::new(
        rig.registry.clone(),
        rig.backend.clone() as Arc<dyn CommandBackend>,
        kraken_assist::HostOptions::default(),
    ));

    let mut history: Vec<Message> = Vec::new();
    let mut done = Vec::new();
    for (n, text) in ["What is this?", "And the entry point?"].iter().enumerate() {
        history.push(Message::user(*text));
        let mut run = backend.start(RunSpec {
            messages: history.clone(),
            config: kraken_agent::AgentConfig {
                run_id: format!("run-chat-{n}"),
                system_extra: Some("CHAT-INSTRUCTIONS".into()),
                ..Default::default()
            },
            tools: tools.clone(),
            purpose: Purpose::Chat,
        });
        let mut filter = ResultTagFilter::new();
        let mut shown = String::new();
        let mut saw_card = false;
        while let Some(ev) = run.next_event().await {
            match ev {
                AgentEvent::TextDelta { text } => shown.push_str(&filter.push(&text)),
                AgentEvent::ApprovalRequired { id, .. } => {
                    saw_card = true;
                    run.approvals().decide(id, ApprovalDecision::Deny);
                }
                AgentEvent::Done { stop, .. } => {
                    done.push((stop, saw_card, shown.clone()));
                    break;
                }
                _ => {}
            }
        }
    }
    assert_eq!(done.len(), 2);
    for (stop, saw_card, shown) in &done {
        assert_eq!(*stop, StopReason::Completed);
        assert!(saw_card, "the agent asked for permission each turn");
        assert!(shown.contains("permission denied"), "{shown}");
    }

    // One session: the instructions went with the first prompt only.
    let log = std::fs::read_to_string(&record).expect("record");
    let prompts: Vec<String> = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["method"] == "session/prompt")
        .filter_map(|v| {
            v.pointer("/params/prompt/0/text")?
                .as_str()
                .map(str::to_string)
        })
        .collect();
    assert_eq!(prompts.len(), 2, "{prompts:?}");
    assert!(prompts[0].contains("CHAT-INSTRUCTIONS") && prompts[0].contains("What is this?"));
    assert_eq!(prompts[1], "And the entry point?");
    let news = log
        .lines()
        .filter(|l| l.contains("\"session/new\""))
        .count();
    assert_eq!(news, 1);
    assert_eq!(
        backend.info().name,
        "Fake agent",
        "the backend names the agent"
    );
    assert_eq!(backend.info().model.as_deref(), Some("Fake model 1"));
    backend.close();
}

#[tokio::test]
async fn a_task_prompt_carries_the_same_instructions_on_both_backends() {
    let rig = rig().await;
    let record = rig.tmp.path().join("task.jsonl");
    let task = Task::explain_function(&rig.registry, "0x401000").expect("task");
    let goal = task.goal.clone();
    let system = task.system_extra.clone();
    let (_, _) = run_on(
        &rig,
        acp(&rig, &[("FAKE_ACP_RECORD", record.to_str().expect("utf8"))]),
        task,
    )
    .await;
    let log = std::fs::read_to_string(&record).expect("record");
    let prompt = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["method"] == "session/prompt")
        .and_then(|v| {
            v.pointer("/params/prompt/0/text")?
                .as_str()
                .map(str::to_string)
        })
        .expect("a prompt");
    assert!(prompt.contains(&system), "the task's instructions are sent");
    assert!(prompt.ends_with(&goal));
    // The MCP server the agent is given logs its edits under the task's run id.
    let new = log
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["method"] == "session/new")
        .expect("session/new");
    let args = new.pointer("/params/mcpServers/0/args").expect("args");
    assert!(
        args.to_string().contains("--run-id"),
        "the MCP server gets the run id: {args}"
    );
}

#[tokio::test]
async fn an_agent_that_cannot_start_is_a_failed_result_not_a_panic() {
    let rig = rig().await;
    let mut settings = acp_settings(&rig, &[("FAKE_ACP_REQUIRE_AUTH", "1")]);
    settings.start_timeout = Duration::from_secs(10);
    let backend = Arc::new(AcpBackend::new(settings, rig.registry.clone()));
    let task = Task::overview(&rig.registry);
    let (r, events) = run_on(&rig, backend, task).await;
    assert_eq!(r.stop, StopReason::Error);
    let why = r.error.expect("an error");
    assert!(why.contains("sign in"), "{why}");
    assert_eq!(shape(&events), ["error", "done"]);
    assert!(r.output.is_none());
}

#[tokio::test]
async fn cancelling_stops_a_terminal_agent_task() {
    let rig = rig().await;
    let a = Assistant::with_engine(
        rig.registry.clone(),
        rig.backend.clone(),
        acp(&rig, &[("FAKE_ACP_TASK_PERMISSION", "1")]),
    )
    .with_approver(|_| {});
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    let r = a
        .run(Task::overview(&rig.registry), &cancel, &mut |e| {
            // The agent is waiting for an answer nobody gives; stop instead.
            if matches!(e, AgentEvent::ApprovalRequired { .. }) {
                c2.cancel();
            }
        })
        .await;
    assert_eq!(r.stop, StopReason::Cancelled);
}

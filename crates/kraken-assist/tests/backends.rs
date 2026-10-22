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
            // Only the built-in loop reports these; the shape compares backends.
            AgentEvent::StepUsage { .. } | AgentEvent::Compacted { .. } => continue,
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

// ----- text-only requests (the rewrite pipeline's model calls) -----

fn text_request(user: &str) -> kraken_agent::ChatRequest {
    kraken_agent::ChatRequest {
        system: "SYSTEM-RULES".into(),
        messages: vec![Message::user(user)],
        tools: Vec::new(),
        max_tokens: Some(100),
        temperature: Some(0.0),
    }
}

fn answers_file(rig: &Rig, entries: &Value) -> String {
    let path = rig.tmp.path().join("answers.json");
    std::fs::write(&path, entries.to_string()).expect("answers");
    path.to_string_lossy().into_owned()
}

#[tokio::test]
async fn a_text_request_on_a_model_api_returns_the_reply_text() {
    let backend = ApiBackend::new(Arc::new(ReplayProvider::scripted(vec![say("the reply")])));
    let r = backend
        .complete_text(text_request("hello"), CancellationToken::new())
        .await
        .expect("reply");
    assert_eq!(r.text, "the reply");
    assert_eq!(r.provider.id, "replay");
}

#[tokio::test]
async fn a_text_request_on_a_terminal_agent_is_tool_free_and_its_permission_requests_are_denied() {
    let rig = rig().await;
    let record = rig.tmp.path().join("text.jsonl");
    let marker = rig.tmp.path().join("agent-wrote-something");
    let answers = answers_file(
        &rig,
        &json!([{"match": "translate this", "reply": "<kraken-rust>fn x() {}</kraken-rust>"}]),
    );
    let backend = acp(
        &rig,
        &[
            ("FAKE_ACP_RECORD", record.to_str().expect("utf8")),
            ("FAKE_ACP_ALLOW_NO_MCP", "1"),
            ("FAKE_ACP_COMPLETION_ANSWERS", answers.as_str()),
            (
                "FAKE_ACP_COMPLETION_MISBEHAVE",
                marker.to_str().expect("utf8"),
            ),
        ],
    );
    let r = backend
        .complete_text(
            text_request("please translate this"),
            CancellationToken::new(),
        )
        .await
        .expect("reply");
    assert_eq!(r.text, "<kraken-rust>fn x() {}</kraken-rust>");
    assert_eq!(r.provider.id, "fake");

    // The agent asked to write a file and to run a command; both were denied.
    assert!(!marker.exists(), "a permission request was granted");
    let notes = backend.take_notes();
    assert!(
        notes.iter().any(|n| n.contains("2 permission requests")),
        "{notes:?}"
    );

    let log = std::fs::read_to_string(&record).expect("record");
    let events: Vec<Value> = log
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let new = events
        .iter()
        .find(|v| v["method"] == "session/new")
        .expect("session/new");
    // No KRAKEN tools, and not in the project directory.
    assert_eq!(new.pointer("/params/mcpServers"), Some(&json!([])));
    let cwd = new["params"]["cwd"].as_str().expect("cwd");
    assert!(
        !cwd.starts_with(rig.tmp.path().to_str().expect("utf8")),
        "{cwd}"
    );
    let prompt = events
        .iter()
        .find(|v| v["method"] == "session/prompt")
        .and_then(|v| v.pointer("/params/prompt/0/text"))
        .and_then(Value::as_str)
        .expect("prompt");
    assert!(prompt.starts_with(kraken_assist::acp::COMPLETION_PREAMBLE));
    assert!(prompt.contains("SYSTEM-RULES") && prompt.ends_with("please translate this"));
    backend.close();
}

#[tokio::test]
async fn a_text_request_that_cannot_start_or_is_cancelled_is_an_error() {
    let rig = rig().await;
    let backend = acp(
        &rig,
        &[
            ("FAKE_ACP_REQUIRE_AUTH", "1"),
            ("FAKE_ACP_ALLOW_NO_MCP", "1"),
        ],
    );
    let err = backend
        .complete_text(text_request("x"), CancellationToken::new())
        .await
        .expect_err("cannot start");
    assert!(err.to_string().contains("sign in"), "{err}");

    let backend = acp(&rig, &[("FAKE_ACP_ALLOW_NO_MCP", "1")]);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = backend
        .complete_text(text_request("x"), cancel)
        .await
        .expect_err("cancelled");
    assert!(matches!(err, kraken_agent::AgentError::Cancelled), "{err}");
}

// ----- the `[rewrite]` override and terminal agents chosen by config -----

fn config_env(root: &Path) -> impl Fn(&str) -> Option<OsString> + use<> {
    let root = root.to_path_buf();
    move |k| match k {
        "KRAKEN_CONFIG" => Some(root.join("config.toml").into_os_string()),
        "HOME" | "XDG_DATA_HOME" => Some(root.join("home").into_os_string()),
        "PATH" => Some(OsString::from("/usr/bin:/bin")),
        _ => None,
    }
}

const API_TABLE: &str =
    "kind = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:9/v1\"\nmodel = \"m\"\n";
const AGENT_TABLE: &str = "kind = \"terminal_agent\"\nagent = \"wrapped\"\n";

fn backend_kind(root: &Path, config: &str) -> Result<BackendKind, String> {
    std::fs::write(root.join("config.toml"), config).expect("config");
    kraken_assist::text_backend_from_config(&config_env(root), &kraken_agent::EnvSecrets)
        .map(|b| b.info().kind)
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn the_rewrite_table_overrides_the_provider_and_either_may_be_a_terminal_agent() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::Builder::new()
        .prefix("kraken-assist-textcfg-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("home")).expect("home");
    // A custom agent in agents.toml: a wrapper that gives the fake agent its answers.
    let answers = root.join("answers.json");
    std::fs::write(
        &answers,
        json!([{"match": "from config", "reply": "answered by the configured agent"}]).to_string(),
    )
    .expect("answers");
    let wrapper = root.join("wrapped-agent.sh");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nFAKE_ACP_ALLOW_NO_MCP=1 FAKE_ACP_COMPLETION_ANSWERS={} exec {}\n",
            answers.display(),
            fake_agent().display()
        ),
    )
    .expect("wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::write(
        root.join("agents.toml"),
        format!(
            "[[agent]]\nid = \"wrapped\"\nname = \"Wrapped fake\"\ncommand = \"{}\"\n",
            wrapper.display()
        ),
    )
    .expect("agents.toml");

    // `[provider]` alone decides when there is no `[rewrite]`.
    assert_eq!(
        backend_kind(root, &format!("[provider]\n{API_TABLE}")),
        Ok(BackendKind::Api)
    );
    assert_eq!(
        backend_kind(root, &format!("[provider]\n{AGENT_TABLE}")),
        Ok(BackendKind::TerminalAgent)
    );
    // `[rewrite]` wins in both directions.
    assert_eq!(
        backend_kind(
            root,
            &format!("[provider]\n{API_TABLE}\n[rewrite]\n{AGENT_TABLE}")
        ),
        Ok(BackendKind::TerminalAgent)
    );
    assert_eq!(
        backend_kind(
            root,
            &format!("[provider]\n{AGENT_TABLE}\n[rewrite]\n{API_TABLE}")
        ),
        Ok(BackendKind::Api)
    );
    // `[rewrite]` alone is enough for the rewrite pipeline.
    assert_eq!(
        backend_kind(root, &format!("[rewrite]\n{AGENT_TABLE}")),
        Ok(BackendKind::TerminalAgent)
    );
    // Nothing configured, a broken table, or an agent nobody set up say so.
    let none = backend_kind(root, "").expect_err("no provider");
    assert!(none.contains("no AI provider"), "{none}");
    let bad = backend_kind(
        root,
        &format!("[provider]\n{API_TABLE}\n[rewrite]\nkind = \"nope\"\n"),
    )
    .expect_err("bad table");
    assert!(bad.contains("[rewrite]"), "{bad}");
    let unknown = backend_kind(
        root,
        "[rewrite]\nkind = \"terminal_agent\"\nagent = \"no-such-agent\"\n",
    )
    .expect_err("unknown agent");
    assert!(unknown.contains("no-such-agent"), "{unknown}");

    // The configured agent really answers a text request.
    std::fs::write(
        root.join("config.toml"),
        format!("[provider]\n{API_TABLE}\n[rewrite]\n{AGENT_TABLE}"),
    )
    .expect("config");
    let backend =
        kraken_assist::text_backend_from_config(&config_env(root), &kraken_agent::EnvSecrets)
            .expect("backend");
    let r = backend
        .complete_text(
            text_request("a request from config"),
            CancellationToken::new(),
        )
        .await
        .expect("reply");
    assert_eq!(r.text, "answered by the configured agent");
    assert_eq!(r.provider.id, "wrapped");
    backend.close();
}

#[tokio::test]
async fn automate_on_a_terminal_agent_may_use_only_the_tools_of_its_goal() {
    use kraken_assist::AutomateGoal;
    let rig = rig().await;
    let ask = |goal| {
        let rig = &rig;
        async move {
            let task = Task::automate(&rig.registry, goal);
            let (t, _) = run_on(rig, acp(rig, &[]), task).await;
            assert_eq!(t.stop, StopReason::Completed, "{:?}", t.error);
            t.text
        }
    };
    let understand = ask(AutomateGoal::Understand).await;
    assert!(
        understand.contains("(rewrite_program denied)"),
        "{understand}"
    );
    assert!(
        understand.contains("(rewrite_accept denied)"),
        "{understand}"
    );
    let both = ask(AutomateGoal::Both).await;
    assert!(both.contains("(rewrite_program allowed)"), "{both}");
    assert!(
        both.contains("(rewrite_accept denied)"),
        "accepting stays the person's: {both}"
    );
}

#[tokio::test]
async fn automate_on_a_model_api_exposes_the_same_tools() {
    use kraken_assist::AutomateGoal;
    let rig = rig().await;
    let a = Assistant::with_engine(
        rig.registry.clone(),
        rig.backend.clone(),
        Arc::new(ApiBackend::new(Arc::new(ReplayProvider::scripted(vec![
            say("Nothing to do."),
        ])))),
    );
    let names = |goal| -> Vec<String> {
        use kraken_agent::ToolHost;
        a.host_for(&Task::automate(&rig.registry, goal))
            .tools()
            .into_iter()
            .map(|t| t.name)
            .collect()
    };
    let understand = names(AutomateGoal::Understand);
    assert!(understand.contains(&"apply_edits".to_string()));
    assert!(!understand.contains(&"rewrite_program".to_string()));
    let rewrite = names(AutomateGoal::Rewrite);
    for t in ["rewrite_plan", "rewrite_program", "rewrite_export"] {
        assert!(rewrite.contains(&t.to_string()), "{t}");
    }
    for t in [
        "rewrite_accept",
        "proposal_accept",
        "undo_run",
        "project_create",
    ] {
        assert!(!rewrite.contains(&t.to_string()), "{t}");
    }
}

#[tokio::test]
async fn starting_or_stopping_local_models_is_not_offered_by_default() {
    use kraken_agent::ToolHost;
    let rig = rig().await;
    let names = |read_only: bool| -> Vec<String> {
        kraken_assist::RegistryToolHost::new(
            rig.registry.clone(),
            rig.backend.clone(),
            kraken_assist::HostOptions {
                read_only,
                ..Default::default()
            },
        )
        .tools()
        .into_iter()
        .map(|t| t.name)
        .collect()
    };
    for read_only in [false, true] {
        let tools = names(read_only);
        for t in [
            "local_model_start",
            "local_model_hold",
            "local_model_release",
            "local_model_stop",
        ] {
            assert!(
                !tools.contains(&t.to_string()),
                "{t} (read_only {read_only})"
            );
        }
        assert!(tools.contains(&"local_model_status".to_string()));
    }
}

// ---- metering ----------------------------------------------------------------------------

fn said_with_usage(text: &str, input: u64, output: u64) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta { text: text.into() },
        StreamEvent::Usage(kraken_agent::Usage {
            input_tokens: input,
            output_tokens: output,
        }),
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

fn priced() -> kraken_assist::Pricing {
    let mut p = kraken_assist::Pricing::empty();
    p.set(
        "cassette",
        kraken_assist::Price {
            input: 2.0,
            output: 10.0,
        },
    );
    p
}

#[tokio::test]
async fn metering_records_tokens_and_cost_of_a_model_api_in_the_ledger() {
    use kraken_proto::{AiBilling, AiFeature, AiOrigin};
    let rig = rig().await;
    let db = rig.tmp.path().join("p").join("project.kraken.sqlite");
    let daily = kraken_model::DailyLedger::at(rig.tmp.path().join("daily.json"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let meter = kraken_assist::Meter::builder(
        kraken_assist::MeterSpec::new(AiFeature::Rewrite, AiOrigin::Cli).job("job-7"),
    )
    .pricing(priced())
    .sink(Arc::new(kraken_model::ProjectLedger::new(&db)))
    .daily(Some(daily.clone()))
    .observer(Arc::new(move |r, t| {
        seen2.lock().unwrap().push((r.clone(), *t));
    }))
    .build();
    let backend = meter.wrap(Arc::new(ApiBackend::new(Arc::new(
        ReplayProvider::scripted(vec![
            said_with_usage("one", 1_000_000, 100_000),
            said_with_usage("two", 500_000, 0),
        ]),
    ))));
    for _ in 0..2 {
        backend
            .complete_text(text_request("x"), CancellationToken::new())
            .await
            .expect("reply");
    }
    let t = meter.totals();
    assert_eq!(t.calls, 2);
    assert_eq!(t.input_tokens, 1_500_000);
    assert_eq!(t.output_tokens, 100_000);
    // 1.5M input at $2 plus 0.1M output at $10.
    assert!((t.cost_usd - 4.0).abs() < 1e-9, "{t:?}");
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0.billing, AiBilling::Metered);
        assert_eq!(seen[0].0.job_id.as_deref(), Some("job-7"));
        assert_eq!(seen[1].1.calls, 2);
    }

    let store = kraken_model::Store::open(&db).expect("db");
    let (all, _) = store
        .ai_usage_summary(&kraken_model::UsageFilter::default())
        .expect("summary");
    assert_eq!(all.calls, 2);
    assert_eq!(all.input_tokens, 1_500_000);
    assert_eq!(daily.today().calls, 2);
    assert!((daily.today().cost_usd - 4.0).abs() < 1e-9);
}

#[tokio::test]
async fn metering_counts_the_model_calls_of_an_assistant_task() {
    use kraken_proto::{AiFeature, AiOrigin};
    let rig = rig().await;
    let meter = kraken_assist::Meter::builder(kraken_assist::MeterSpec::new(
        AiFeature::Assistant,
        AiOrigin::Gui,
    ))
    .pricing(priced())
    .build();
    let mut events = answer("Here is what I found.", &explain_json());
    events.insert(
        1,
        StreamEvent::Usage(kraken_agent::Usage {
            input_tokens: 10,
            output_tokens: 5,
        }),
    );
    let engine = meter.wrap(Arc::new(ApiBackend::new(Arc::new(
        ReplayProvider::scripted(vec![events]),
    ))));
    let task = Task::explain_function(&rig.registry, "0x401000").expect("task");
    let (r, _) = run_on(&rig, engine, task).await;
    assert_eq!(kind_of(&r.output), "explanation");
    assert_eq!(meter.totals().calls, 1);
    assert_eq!(meter.totals().input_tokens, 10);
}

#[tokio::test]
async fn metering_a_terminal_agent_counts_calls_and_time_but_no_tokens() {
    use kraken_proto::{AiBilling, AiFeature, AiOrigin, AiProviderKind};
    let rig = rig().await;
    let answers = answers_file(&rig, &json!([{"match": "hello", "reply": "hi there"}]));
    let agent = acp(
        &rig,
        &[
            ("FAKE_ACP_ALLOW_NO_MCP", "1"),
            ("FAKE_ACP_COMPLETION_ANSWERS", answers.as_str()),
        ],
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let meter = kraken_assist::Meter::builder(kraken_assist::MeterSpec::new(
        AiFeature::Rewrite,
        AiOrigin::Gui,
    ))
    .observer(Arc::new(move |r, _| seen2.lock().unwrap().push(r.clone())))
    .build();
    let backend = meter.wrap(agent);
    let r = backend
        .complete_text(text_request("hello"), CancellationToken::new())
        .await
        .expect("reply");
    assert_eq!(r.text, "hi there");
    let t = meter.totals();
    assert_eq!(t.calls, 1);
    assert_eq!(t.subscription_calls, 1);
    assert_eq!(t.input_tokens + t.output_tokens, 0);
    assert_eq!(t.cost_text(), "billed by the agent's subscription");
    let rec = seen.lock().unwrap()[0].clone();
    assert_eq!(rec.provider_kind, AiProviderKind::TerminalAgent);
    assert_eq!(rec.billing, AiBilling::Subscription);
    assert!(rec.input_tokens.is_none() && rec.cost_usd.is_none());
    backend.close();
}

#[tokio::test]
async fn a_call_cap_stops_the_run_and_the_daily_budget_refuses_new_work() {
    use kraken_proto::{AiFeature, AiOrigin};
    let rig = rig().await;
    let scripted = || {
        Arc::new(ApiBackend::new(Arc::new(ReplayProvider::scripted(vec![
            said_with_usage("a", 1_000_000, 0),
            said_with_usage("b", 1_000_000, 0),
        ])))) as Arc<dyn AssistBackend>
    };
    let meter = kraken_assist::Meter::builder(kraken_assist::MeterSpec::new(
        AiFeature::Rewrite,
        AiOrigin::Cli,
    ))
    .pricing(priced())
    .limits(kraken_assist::AiLimits {
        max_calls_per_run: Some(1),
        ..kraken_assist::AiLimits::default()
    })
    .build();
    let b = meter.wrap(scripted());
    b.complete_text(text_request("x"), CancellationToken::new())
        .await
        .expect("first call");
    let e = b
        .complete_text(text_request("x"), CancellationToken::new())
        .await
        .expect_err("over the cap");
    assert!(matches!(e, kraken_agent::AgentError::Limit(_)), "{e}");
    assert!(e.to_string().contains("limit of 1 model calls"), "{e}");
    assert!(meter.limit_message().is_some());
    assert_eq!(meter.totals().calls, 1);

    let daily = kraken_model::DailyLedger::at(rig.tmp.path().join("budget.json"));
    let limits = kraken_assist::AiLimits {
        daily_budget: Some(1.5),
        ..kraken_assist::AiLimits::default()
    };
    let first = kraken_assist::Meter::builder(kraken_assist::MeterSpec::new(
        AiFeature::Assistant,
        AiOrigin::Gui,
    ))
    .pricing(priced())
    .daily(Some(daily.clone()))
    .limits(limits.clone())
    .build();
    first
        .wrap(scripted())
        .complete_text(text_request("x"), CancellationToken::new())
        .await
        .expect("under the budget");
    assert!((daily.today().cost_usd - 2.0).abs() < 1e-9);
    let later = kraken_assist::Meter::builder(kraken_assist::MeterSpec::new(
        AiFeature::Rewrite,
        AiOrigin::Gui,
    ))
    .pricing(priced())
    .daily(Some(daily.clone()))
    .limits(limits)
    .build();
    let e = later
        .wrap(scripted())
        .complete_text(text_request("x"), CancellationToken::new())
        .await
        .expect_err("budget used up");
    assert!(e.to_string().contains("Today's AI budget of $1.50"), "{e}");
    assert_eq!(later.totals().calls, 0);
}

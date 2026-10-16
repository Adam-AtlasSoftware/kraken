//! `AcpHost` against the fake ACP agent (a separate process speaking raw ACP JSON-RPC).
//! No network, no real agents.
// These tests drive /bin/sh helpers and inspect processes the Unix way.
#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kraken_acp::{
    AcpError, AcpEvent, AcpHost, AgentProfile, AllowAll, DenyAll, HostConfig, LaunchSpec,
    McpServerConfig, PermissionDecision, PermissionPolicy, TurnEnd,
};
use serde_json::Value;
use tokio::sync::mpsc::UnboundedReceiver;

const FAKE: &str = env!("CARGO_BIN_EXE_kraken-fake-acp-agent");

fn base_env(extra: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    let mut v = vec![
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("HOME"), OsString::from("/home/test")),
    ];
    for (k, val) in extra {
        v.push((OsString::from(k), OsString::from(val)));
    }
    v
}

fn profile() -> AgentProfile {
    AgentProfile::custom("fake", "Fake agent", FAKE, vec![]).allow_env("FAKE_ACP_*")
}

fn config(dir: &Path, policy: PermissionPolicy) -> HostConfig {
    let launch = LaunchSpec {
        program: PathBuf::from(FAKE),
        args: vec![],
        path_prepend: None,
        via: "test".into(),
    };
    let mut c = HostConfig::new(
        profile(),
        launch,
        dir.to_path_buf(),
        Some(McpServerConfig::project("/opt/kraken/kraken", dir)),
    );
    c.permission = policy;
    c.parent_env = Some(base_env(&[]));
    c.start_timeout = Duration::from_secs(20);
    c
}

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-acp-host")
        .tempdir()
        .expect("tempdir")
}

async fn until_turn_end(rx: &mut UnboundedReceiver<AcpEvent>) -> Vec<AcpEvent> {
    let mut out = Vec::new();
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("event within 20s")
            .expect("channel open");
        let end = matches!(ev, AcpEvent::TurnEnded { .. });
        out.push(ev);
        if end {
            return out;
        }
    }
}

async fn next_matching(
    rx: &mut UnboundedReceiver<AcpEvent>,
    pred: impl Fn(&AcpEvent) -> bool,
) -> AcpEvent {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("event within 20s")
            .expect("channel open");
        if pred(&ev) {
            return ev;
        }
    }
}

fn text_of(events: &[AcpEvent]) -> String {
    events
        .iter()
        .filter_map(|e| match e {
            AcpEvent::AgentText { text } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn alive(pid: u32) -> bool {
    // A reaped or killed process disappears from /proc; a zombie shows state Z.
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => !s.contains(") Z "),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn alive(pid: u32) -> bool {
    // No /proc here: ask ps for the state; no output means the process is gone.
    std::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .map(|o| {
            let stat = String::from_utf8_lossy(&o.stdout);
            let stat = stat.trim();
            !stat.is_empty() && !stat.starts_with('Z')
        })
        .unwrap_or(false)
}

async fn gone(pid: u32) -> bool {
    for _ in 0..200 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

#[tokio::test]
async fn session_carries_the_kraken_mcp_server_and_no_fs_or_terminal() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(
        d.path(),
        PermissionPolicy::Handler(Arc::new(DenyAll)),
    ))
    .await
    .expect("started");
    let started = next_matching(&mut rx, |e| matches!(e, AcpEvent::Started { .. })).await;
    let AcpEvent::Started { agent, session_id } = started else {
        unreachable!()
    };
    assert_eq!(agent.name.as_deref(), Some("kraken-fake-acp-agent"));
    assert_eq!(agent.protocol_version, 1);
    assert_eq!(agent.auth_methods, ["Fake login"]);
    assert_eq!(session_id, host.session_id());

    assert_eq!(host.prompt("report").await.expect("turn"), TurnEnd::EndTurn);
    let events = until_turn_end(&mut rx).await;
    let report: Value = serde_json::from_str(&text_of(&events)).expect("json report");
    let servers = report["mcpServers"].as_array().expect("servers");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0]["name"], "kraken");
    assert_eq!(servers[0]["command"], "/opt/kraken/kraken");
    assert_eq!(
        servers[0]["args"],
        serde_json::json!(["mcp", "--project", d.path().to_string_lossy()])
    );
    assert_eq!(report["cwd"], d.path().to_string_lossy().as_ref());
    // The agent would have refused to start had KRAKEN advertised fs or terminal support.
    let caps = &report["clientCapabilities"];
    assert_ne!(caps["terminal"], Value::Bool(true));
    assert_ne!(caps["fs"]["writeTextFile"], Value::Bool(true));
    host.shutdown().await;
}

#[tokio::test]
async fn daemon_flavoured_mcp_config() {
    let m = McpServerConfig::daemon("/k/kraken", Some(Path::new("/p")));
    assert_eq!(m.args, ["mcp", "--daemon", "--project", "/p"]);
    let m = McpServerConfig::daemon("/k/kraken", None).with_env("KRAKEN_RUNTIME_DIR", "/r");
    assert_eq!(m.args, ["mcp", "--daemon"]);
    assert_eq!(
        m.env,
        [("KRAKEN_RUNTIME_DIR".to_string(), "/r".to_string())]
    );
}

#[tokio::test]
async fn a_scripted_turn_streams_text_tool_calls_plan_and_permission() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(
        d.path(),
        PermissionPolicy::Handler(Arc::new(AllowAll)),
    ))
    .await
    .expect("started");
    assert_eq!(host.prompt("do it").await.expect("turn"), TurnEnd::EndTurn);
    let events = until_turn_end(&mut rx).await;

    assert!(matches!(events[0], AcpEvent::Started { .. }));
    assert_eq!(
        text_of(&events),
        "Hello from the fake agent. permission granted."
    );
    assert!(
        events.iter().any(
            |e| matches!(e, AcpEvent::AgentThought { text } if text == "thinking about main.c")
        )
    );
    let call = events
        .iter()
        .find_map(|e| match e {
            AcpEvent::ToolCall(c) => Some(c),
            _ => None,
        })
        .expect("tool call");
    assert_eq!(call.id, "call-1");
    assert_eq!(call.title, "Run rm -rf build");
    assert_eq!(call.kind, "execute");
    assert_eq!(call.status, "pending");
    assert_eq!(call.paths, ["/tmp/project/build"]);
    assert!(
        call.input
            .as_deref()
            .is_some_and(|i| i.contains("rm -rf build"))
    );

    let plan = events
        .iter()
        .find_map(|e| match e {
            AcpEvent::Plan { steps } => Some(steps),
            _ => None,
        })
        .expect("plan");
    assert_eq!(plan.len(), 2);
    assert_eq!(plan[0].content, "Clean the build");
    assert_eq!(plan[0].status, "in_progress");
    assert_eq!(plan[0].priority, "high");

    let req = events
        .iter()
        .find_map(|e| match e {
            AcpEvent::PermissionRequested(r) => Some(r),
            _ => None,
        })
        .expect("permission request");
    assert_eq!(req.title, "Run rm -rf build");
    assert_eq!(req.tool_kind.as_deref(), Some("execute"));
    assert_eq!(req.options.len(), 2);
    assert_eq!(req.options[0].kind, "allow_once");
    assert!(events.iter().any(|e| matches!(
        e,
        AcpEvent::PermissionResolved { selected: Some(s), .. } if s == "allow"
    )));
    let update = events
        .iter()
        .find_map(|e| match e {
            AcpEvent::ToolCallUpdate(u) => Some(u),
            _ => None,
        })
        .expect("tool update");
    assert_eq!(update.id, "call-1");
    assert_eq!(update.status.as_deref(), Some("completed"));
    assert_eq!(update.output.as_deref(), Some("permission granted"));
    assert!(matches!(
        events.last(),
        Some(AcpEvent::TurnEnded {
            reason: TurnEnd::EndTurn
        })
    ));
    host.shutdown().await;
}

#[tokio::test]
async fn a_handler_can_deny() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(
        d.path(),
        PermissionPolicy::Handler(Arc::new(DenyAll)),
    ))
    .await
    .expect("started");
    host.prompt("do it").await.expect("turn");
    let events = until_turn_end(&mut rx).await;
    assert!(text_of(&events).ends_with("permission denied."));
    assert!(events.iter().any(|e| matches!(
        e,
        AcpEvent::ToolCallUpdate(u) if u.status.as_deref() == Some("failed")
    )));
    host.shutdown().await;
}

#[tokio::test]
async fn ask_the_user_waits_for_answer_permission() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let host = Arc::new(host);
    let h = host.clone();
    let turn = tokio::spawn(async move { h.prompt("do it").await });

    let ev = next_matching(&mut rx, |e| matches!(e, AcpEvent::PermissionRequested(_))).await;
    let AcpEvent::PermissionRequested(req) = ev else {
        unreachable!()
    };
    // The turn is blocked until a person answers.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!turn.is_finished());
    assert!(!host.answer_permission(req.request_id + 99, PermissionDecision::Cancel));
    assert!(host.answer_permission(req.request_id, req.allow()));
    assert_eq!(turn.await.expect("join").expect("turn"), TurnEnd::EndTurn);
    let events = until_turn_end(&mut rx).await;
    assert!(text_of(&events).ends_with("permission granted."));
    // Answering twice does nothing.
    assert!(!host.answer_permission(req.request_id, PermissionDecision::Cancel));
    Arc::into_inner(host).expect("sole owner").shutdown().await;
}

#[tokio::test]
async fn cancel_answers_waiting_permission_requests_as_cancelled() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let host = Arc::new(host);
    let h = host.clone();
    let turn = tokio::spawn(async move { h.prompt("do it").await });
    next_matching(&mut rx, |e| matches!(e, AcpEvent::PermissionRequested(_))).await;
    host.cancel().expect("cancel sent");
    assert_eq!(turn.await.expect("join").expect("turn"), TurnEnd::Cancelled);
    let events = until_turn_end(&mut rx).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, AcpEvent::PermissionResolved { selected: None, .. }))
    );
    assert!(text_of(&events).ends_with("permission cancelled."));
    Arc::into_inner(host).expect("sole owner").shutdown().await;
}

#[tokio::test]
async fn cancel_ends_a_running_turn() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let host = Arc::new(host);
    let h = host.clone();
    let turn = tokio::spawn(async move { h.prompt("wait").await });
    next_matching(&mut rx, |e| matches!(e, AcpEvent::AgentText { .. })).await;
    assert!(matches!(host.prompt("again").await, Err(AcpError::Busy)));
    host.cancel().expect("cancel sent");
    assert_eq!(turn.await.expect("join").expect("turn"), TurnEnd::Cancelled);
    // The session is still usable afterwards.
    assert_eq!(host.prompt("report").await.expect("turn"), TurnEnd::EndTurn);
    Arc::into_inner(host).expect("sole owner").shutdown().await;
}

#[tokio::test]
async fn fs_requests_are_declined() {
    let d = tmp();
    let (host, mut rx) = AcpHost::start(config(
        d.path(),
        PermissionPolicy::Handler(Arc::new(DenyAll)),
    ))
    .await
    .expect("started");
    host.prompt("fs").await.expect("turn");
    let events = until_turn_end(&mut rx).await;
    assert_eq!(text_of(&events), "fs write: declined");
    host.shutdown().await;
}

#[tokio::test]
async fn kraken_secrets_and_api_keys_are_not_passed_to_the_agent() {
    let d = tmp();
    let mut c = config(d.path(), PermissionPolicy::Handler(Arc::new(DenyAll)));
    c.parent_env = Some(base_env(&[
        ("KRAKEN_PROVIDER_KEY", "secret"),
        ("KRAKEN_RUNTIME_DIR", "/r"),
        ("SECRET_TEST", "x"),
        ("ANTHROPIC_API_KEY", "sk-ant"),
        ("FAKE_ACP_EXTRA", "1"),
    ]));
    let (host, mut rx) = AcpHost::start(c).await.expect("started");
    host.prompt("env").await.expect("turn");
    let events = until_turn_end(&mut rx).await;
    // HOME and the explicitly allowed FAKE_ACP_EXTRA only.
    assert_eq!(text_of(&events), "env: FAKE_ACP_EXTRA,HOME");
    host.shutdown().await;
}

#[tokio::test]
async fn a_session_without_the_kraken_server_is_refused_by_the_agent() {
    let d = tmp();
    let mut c = config(d.path(), PermissionPolicy::AskUser);
    c.mcp = None;
    let err = AcpHost::start(c)
        .await
        .expect_err("fake agent insists on kraken");
    match err {
        AcpError::Agent { message, .. } => assert!(message.contains("kraken"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn authentication_errors_say_to_sign_in_with_the_agent() {
    let d = tmp();
    let mut c = config(d.path(), PermissionPolicy::AskUser);
    c.parent_env = Some(base_env(&[("FAKE_ACP_REQUIRE_AUTH", "1")]));
    let err = AcpHost::start(c).await.expect_err("needs auth");
    assert!(matches!(err, AcpError::AuthRequired { .. }), "{err:?}");
    assert!(err.to_string().contains("sign in"));
}

#[tokio::test]
async fn a_dying_agent_is_reported_with_its_stderr() {
    let d = tmp();
    let (host, _rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let err = host.prompt("die").await.expect_err("agent exited");
    assert!(matches!(err, AcpError::Disconnected { .. }), "{err:?}");
    host.shutdown().await;
}

#[tokio::test]
async fn startup_times_out_when_the_agent_says_nothing() {
    let d = tmp();
    let mut c = config(d.path(), PermissionPolicy::AskUser);
    c.launch.program = PathBuf::from("/bin/sh");
    c.launch.args = vec![
        OsString::from("-c"),
        OsString::from("echo not-acp >&2; sleep 60"),
    ];
    c.start_timeout = Duration::from_millis(500);
    let err = AcpHost::start(c).await.expect_err("times out");
    match err {
        AcpError::StartTimeout { stderr, .. } => assert!(stderr.contains("not-acp"), "{stderr}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn shutdown_and_drop_leave_no_agent_process() {
    let d = tmp();
    let (host, _rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let pid = host.pid();
    assert!(alive(pid));
    let exit = host.shutdown().await.expect("exit info");
    assert!(exit.code.is_some() || exit.signal.is_some());
    assert!(gone(pid).await);

    let (host, _rx) = AcpHost::start(config(d.path(), PermissionPolicy::AskUser))
        .await
        .expect("started");
    let pid = host.pid();
    drop(host);
    assert!(gone(pid).await, "dropping the host kills the agent");
}

#[tokio::test]
async fn a_missing_agent_program_is_a_spawn_error() {
    let d = tmp();
    let mut c = config(d.path(), PermissionPolicy::AskUser);
    c.launch.program = PathBuf::from("/nonexistent/agent");
    let err = AcpHost::start(c).await.expect_err("cannot spawn");
    assert!(matches!(err, AcpError::Spawn(_)), "{err:?}");
}

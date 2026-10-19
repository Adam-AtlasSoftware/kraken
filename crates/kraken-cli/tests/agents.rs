//! `kraken agents list | setup | run` with a fake PATH, a fake npm and a fake ACP agent.
//! No network, no real agents, no daemon.

#![cfg(unix)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use common::*;
use kraken_cli::CliAuthor;

fn script(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("write script");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct World {
    tmp: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        World {
            tmp: tempfile::Builder::new()
                .prefix("kraken-cli-agents-")
                .tempdir()
                .expect("tempdir"),
        }
    }

    fn dir(&self, name: &str) -> std::path::PathBuf {
        let p = self.tmp.path().join(name);
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn vars(&self, path: &Path) -> Vec<(&'static str, String)> {
        let s = |p: std::path::PathBuf| p.to_string_lossy().into_owned();
        vec![
            ("PATH", s(path.to_path_buf())),
            ("XDG_DATA_HOME", s(self.dir("data"))),
            ("XDG_CONFIG_HOME", s(self.dir("config"))),
            ("HOME", s(self.dir("home"))),
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_RUNTIME_DIR", s(self.dir("runtime"))),
            ("KRAKEN_EXE", env!("CARGO_BIN_EXE_kraken").into()),
        ]
    }
}

fn env_with(vars: Vec<(&'static str, String)>) -> kraken_cli::CliEnv {
    rig(CliAuthor::User("tester".into()), vars).env
}

#[tokio::test]
async fn list_reports_detected_available_and_missing_with_reasons() {
    let w = World::new();
    let bin = w.dir("bin");
    script(&bin, "node", "echo v24.21.0");
    script(&bin, "gemini", "exit 0");
    let env = env_with(w.vars(&bin));
    let cfg = w.dir("config").join("kraken");
    std::fs::create_dir_all(&cfg).expect("mkdir");
    std::fs::write(
        cfg.join("agents.toml"),
        "[[agent]]\nid = \"ghost\"\nname = \"Ghost\"\ncommand = \"no-such-agent-kraken\"\n",
    )
    .expect("agents.toml");

    let r = kraken(&env, &["agents", "list", "--json"]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = r.json();
    let status = |id: &str| -> (String, String) {
        let a = v["agents"]
            .as_array()
            .expect("agents")
            .iter()
            .find(|a| a["id"] == id)
            .unwrap_or_else(|| panic!("no {id}: {v}"));
        (
            a["status"].as_str().unwrap_or_default().to_string(),
            a["detail"].as_str().unwrap_or_default().to_string(),
        )
    };
    let (s, d) = status("gemini");
    assert_eq!(s, "detected", "{d}");
    assert!(d.contains("gemini"), "{d}");
    let (s, d) = status("claude");
    assert_eq!(s, "available");
    assert!(d.contains("not installed yet"), "{d}");
    assert!(d.contains("24.21.0"), "{d}");
    assert_eq!(status("codex").0, "available");
    let (s, d) = status("ghost");
    assert_eq!(s, "missing");
    assert!(d.contains("no-such-agent-kraken"), "{d}");
    assert_eq!(
        v["platform"]["platform"],
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
    );

    let human = kraken(&env, &["agents", "list"]).await;
    assert_eq!(human.code, 0);
    for needle in [
        "claude",
        "Claude Code",
        "available",
        "detected",
        "missing",
        "Ghost",
    ] {
        assert!(
            human.stdout.contains(needle),
            "{needle} in {}",
            human.stdout
        );
    }
}

#[tokio::test]
async fn list_on_a_machine_without_node() {
    let w = World::new();
    let empty = w.dir("empty");
    let env = env_with(w.vars(&empty));
    let r = kraken(&env, &["agents", "list", "--json"]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    let v = r.json();
    let claude = v["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|a| a["id"] == "claude")
        .expect("claude");
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert_eq!(claude["status"], "available");
        assert!(
            claude["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("download")
        );
    } else {
        assert!(
            ["available", "missing", "unsupported"]
                .contains(&claude["status"].as_str().unwrap_or_default())
        );
    }
}

#[tokio::test]
async fn setup_installs_the_adapter_with_a_fake_npm() {
    let w = World::new();
    let bin = w.dir("bin");
    script(&bin, "node", "echo v24.21.0");
    script(
        &bin,
        "npm",
        "mkdir -p node_modules/@agentclientprotocol/claude-agent-acp/dist\n\
         echo '//' > node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js",
    );
    let env = env_with(w.vars(&bin));
    let r = kraken(&env, &["agents", "setup", "claude", "--yes"]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(r.stdout.contains("Claude Code is ready"), "{}", r.stdout);
    assert!(r.stderr.contains("will download"), "{}", r.stderr);
    assert!(
        r.stderr.contains("install scripts disabled"),
        "{}",
        r.stderr
    );

    let l = kraken(&env, &["agents", "list", "--json"]).await.json();
    let claude = l["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|a| a["id"] == "claude")
        .expect("claude");
    assert_eq!(claude["status"], "detected");
    // A second setup is a no-op.
    let again = kraken(&env, &["agents", "setup", "claude", "--yes"]).await;
    assert_eq!(again.code, 0);
    assert!(!again.stderr.contains("will download"));
}

#[tokio::test]
async fn setup_and_run_reject_unknown_and_custom_agents() {
    let w = World::new();
    let env = env_with(w.vars(&w.dir("empty")));
    let r = kraken(&env, &["agents", "setup", "nope", "--yes"]).await;
    assert_eq!(r.code, 3, "{}", r.stderr);
    assert!(r.stderr.contains("claude"));
    let r = kraken(&env, &["agents", "run", "nope", "hi", "--project", "."]).await;
    assert_eq!(r.code, 3);
    let r = kraken(&env, &["agents", "run", "claude", "hi", "--project", "."]).await;
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(
        r.stderr.contains("kraken agents setup claude"),
        "{}",
        r.stderr
    );
}

fn custom_fake_agent(w: &World) {
    let dir = w.dir("config").join("kraken");
    std::fs::create_dir_all(&dir).expect("mkdir");
    std::fs::write(
        dir.join("agents.toml"),
        format!(
            "[[agent]]\nid = \"fake\"\nname = \"Fake agent\"\ncommand = \"{}\"\nargs = [\"agents\", \"__fake-agent\"]\n",
            env!("CARGO_BIN_EXE_kraken")
        ),
    )
    .expect("agents.toml");
}

#[tokio::test]
async fn run_streams_the_agent_and_warns_only_the_first_time() {
    let w = World::new();
    custom_fake_agent(&w);
    let project = w.dir("project");
    let env = env_with(w.vars(&w.dir("empty")));
    let p = project.to_string_lossy().into_owned();
    let args = [
        "--project",
        &p,
        "agents",
        "run",
        "fake",
        "hello",
        "--auto-approve",
    ];

    let first = kraken(&env, &args).await;
    assert_eq!(first.code, 0, "{}", first.stderr);
    assert_eq!(
        first.stdout.trim(),
        "Hello from the fake agent. permission granted."
    );
    assert!(
        first.stderr.contains(kraken_acp::WARNING_TITLE),
        "{}",
        first.stderr
    );
    assert!(
        first.stderr.contains("[tool] Run rm -rf build"),
        "{}",
        first.stderr
    );
    assert!(first.stderr.contains("[plan]"), "{}", first.stderr);
    assert!(
        w.dir("config").join("kraken/acp-warning.json").is_file(),
        "acknowledgement persisted in the config dir"
    );

    let second = kraken(&env, &args).await;
    assert_eq!(second.code, 0, "{}", second.stderr);
    assert!(!second.stderr.contains(kraken_acp::WARNING_TITLE));
}

#[tokio::test]
async fn run_without_a_terminal_declines_permissions_and_json_streams_events() {
    let w = World::new();
    custom_fake_agent(&w);
    let project = w.dir("project");
    let env = env_with(w.vars(&w.dir("empty")));
    let p = project.to_string_lossy().into_owned();
    // `cargo test` has no terminal on stdin, so the default handler declines.
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return;
    }
    let r = kraken(
        &env,
        &["--project", &p, "--json", "agents", "run", "fake", "hello"],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    let events: Vec<serde_json::Value> = r
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("json line"))
        // Where unprivileged namespaces are unavailable (e.g. GitHub's Ubuntu runners) the host
        // first reports that the agent runs unconfined; that notice is not part of the turn.
        // Lines the agent process writes to stderr are forwarded by a task of their own, so
        // they can land anywhere in the stream (before `started`, after `turn_ended`); they are
        // not part of the turn either.
        .filter(|e: &serde_json::Value| e["event"] != "info" && e["event"] != "agent_stderr")
        .collect();
    assert_eq!(events[0]["event"], "started");
    assert!(events.iter().any(|e| e["event"] == "tool_call"));
    let text: String = events
        .iter()
        .filter(|e| e["event"] == "agent_text")
        .filter_map(|e| e["text"].as_str())
        .collect();
    assert!(text.ends_with("permission denied."), "{text}");
    assert_eq!(events.last().expect("last")["event"], "turn_ended");
}

#[tokio::test]
async fn run_needs_an_existing_project_directory() {
    let w = World::new();
    custom_fake_agent(&w);
    let env = env_with(w.vars(&w.dir("empty")));
    let r = kraken(&env, &["agents", "run", "fake", "hello"]).await;
    assert_eq!(r.code, 2, "{}", r.stderr);
    let r = kraken(
        &env,
        &[
            "--project",
            "/nonexistent/kraken-project",
            "agents",
            "run",
            "fake",
            "hi",
        ],
    )
    .await;
    assert_eq!(r.code, 3, "{}", r.stderr);
}

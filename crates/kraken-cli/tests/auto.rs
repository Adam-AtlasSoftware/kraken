//! `kraken auto`: open, analyse, name and rewrite in one command, on FakeEngine fixtures with
//! scripted providers, the fake ACP agent and the rewrite cassettes. No network, no daemon.

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::*;
use engine_fake::FixtureFile;
use kraken_agent::{ChatProvider, FinishReason, ReplayProvider, StreamEvent};
use kraken_cli::{CliAuthor, CliEnv, DaemonMode, run_with_provider};
use kraken_host::KrakenConfig;
use kraken_registry::Registry;
use kraken_rewrite::oracle::OracleConfig;
use kraken_rewrite::service::{FixedProvider, RewriteConfig, RewriteService};
use serde_json::{Value, json};

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn tool(id: &str, name: &str, args: Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::ToolCallDelta {
            index: 0,
            id: Some(id.into()),
            name: Some(name.into()),
            arguments: args.to_string(),
        },
        StreamEvent::Finish {
            reason: FinishReason::ToolCalls,
        },
    ]
}

fn say(text: &str) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta { text: text.into() },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

async fn kraken_with(env: &CliEnv, provider: Arc<dyn ChatProvider>, args: &[&str]) -> Run {
    let argv: Vec<OsString> = std::iter::once("kraken")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_with_provider(argv, env, Some(provider), &mut out, &mut err).await;
    Run {
        code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }
}

#[tokio::test]
async fn auto_creates_a_project_analyses_it_and_summarises() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    let run = kraken(
        &r.env,
        &["auto", &path_str(&work.binary), "--project-dir", &dir],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stderr.contains("[1/2] checked"), "{}", run.stderr);
    assert!(run.stderr.contains("ELF"), "{}", run.stderr);
    assert!(
        run.stderr.contains("[2/2] creating the project"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.contains("Summary"), "{}", run.stdout);
    assert!(run.stdout.contains("functions:"), "{}", run.stdout);
    assert!(!run.stdout.contains("renamed:"), "{}", run.stdout);
    assert!(Path::new(&dir).join("meta.json").exists());

    // The project is analysed: its functions are listed.
    let list = kraken(&r.env, &["--json", "--project", &dir, "list-functions"]).await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(
        list.json()["items"]
            .as_array()
            .is_some_and(|a| a.len() >= 3)
    );
}

#[tokio::test]
async fn auto_json_prints_one_object() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    let run = kraken(
        &r.env,
        &[
            "--json",
            "auto",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["project_dir"], dir.as_str());
    assert!(v["functions"].as_u64().is_some_and(|n| n >= 3), "{v}");
    assert!(v["format"].as_str().is_some());
}

#[tokio::test]
async fn auto_names_functions_through_the_assistant_and_counts_them() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));
    let provider: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![
        tool(
            "c1",
            "apply_edits",
            json!({"edits": [
                {"op": "rename", "address": "0x401000", "name": "program_main"},
                {"op": "comment", "address": "0x401000", "text": "Program entry."}
            ]}),
        ),
        say("I named the entry point."),
    ]));
    let run = kraken_with(
        &r.env,
        provider,
        &[
            "--json",
            "auto",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
            "--names",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stderr.contains("[3/3] the assistant"), "{}", run.stderr);
    assert!(run.stderr.contains("> apply_edits"), "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["renamed"], 1, "{v}");
    assert!(
        v["names_run"]
            .as_str()
            .is_some_and(|s| s.starts_with("run-"))
    );

    let f = kraken(
        &r.env,
        &[
            "--json",
            "--project",
            &dir,
            "get-function",
            "--address",
            "0x401000",
        ],
    )
    .await;
    assert_eq!(f.code, 0, "{}", f.stderr);
    assert_eq!(f.json()["name"]["value"], "program_main", "{}", f.stdout);
}

#[tokio::test]
async fn auto_checks_its_inputs_before_it_does_any_work() {
    let work = workdir();
    let r = rig(CliAuthor::User("tester".into()), vec![]);
    let dir = path_str(&work.tmp.path().join("p"));

    let missing = kraken(
        &r.env,
        &["auto", "/definitely/not/here", "--project-dir", &dir],
    )
    .await;
    assert_eq!(missing.code, 3, "{}", missing.stderr);

    let bad_cases = kraken(
        &r.env,
        &[
            "auto",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
            "--rewrite",
            "--cases",
            "not json",
        ],
    )
    .await;
    assert_eq!(bad_cases.code, 2, "{}", bad_cases.stderr);
    assert!(bad_cases.stderr.contains("--cases"));

    // --names without any assistant configured explains how to set one up, and creates nothing.
    let no_provider = kraken(
        &r.env,
        &[
            "auto",
            &path_str(&work.binary),
            "--project-dir",
            &dir,
            "--names",
        ],
    )
    .await;
    assert_eq!(no_provider.code, 2, "{}", no_provider.stderr);
    assert!(
        no_provider.stderr.contains("[provider]"),
        "{}",
        no_provider.stderr
    );
    assert!(!Path::new(&dir).join("meta.json").exists());

    // --accept-verified only makes sense with --rewrite.
    let alone = kraken(
        &r.env,
        &["auto", &path_str(&work.binary), "--accept-verified"],
    )
    .await;
    assert_ne!(alone.code, 0);
}

#[cfg(unix)]
mod terminal_agent {
    use super::*;

    const FAKE: &str = "[provider]\nkind = \"terminal_agent\"\nagent = \"fake\"\n";

    fn select(tmp: &Path) -> Vec<(&'static str, String)> {
        let dir = |n: &str| {
            let p = tmp.join(n);
            std::fs::create_dir_all(&p).expect("mkdir");
            path_str(&p)
        };
        let cfg_dir = tmp.join("config").join("kraken");
        std::fs::create_dir_all(&cfg_dir).expect("mkdir");
        std::fs::write(
            cfg_dir.join("agents.toml"),
            format!(
                "[[agent]]\nid = \"fake\"\nname = \"Fake agent\"\ncommand = \"{}\"\nargs = [\"agents\", \"__fake-agent\"]\n",
                env!("CARGO_BIN_EXE_kraken")
            ),
        )
        .expect("agents.toml");
        let config = cfg_dir.join("config.toml");
        std::fs::write(&config, FAKE).expect("config.toml");
        vec![
            ("PATH", dir("empty")),
            ("XDG_DATA_HOME", dir("data")),
            ("XDG_CONFIG_HOME", dir("config")),
            ("HOME", dir("home")),
            ("KRAKEN_CONFIG", path_str(&config)),
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_RUNTIME_DIR", dir("runtime")),
            ("KRAKEN_EXE", env!("CARGO_BIN_EXE_kraken").into()),
        ]
    }

    #[tokio::test]
    async fn names_run_on_a_terminal_agent_that_may_not_accept_or_rewrite() {
        let work = workdir();
        let world = tempfile::tempdir().expect("tempdir");
        let r = rig(CliAuthor::User("tester".into()), select(world.path()));
        let dir = path_str(&work.tmp.path().join("p"));
        let run = kraken(
            &r.env,
            &[
                "auto",
                &path_str(&work.binary),
                "--project-dir",
                &dir,
                "--names",
            ],
        )
        .await;
        assert_eq!(run.code, 0, "{}", run.stderr);
        assert!(
            run.stderr.contains("terminal agent: Fake agent"),
            "{}",
            run.stderr
        );
        // The naming goal switches the rewrite commands off, and accepting is never offered.
        assert!(
            run.stdout.contains("(rewrite_program denied)"),
            "{}",
            run.stdout
        );
        assert!(
            run.stdout.contains("(rewrite_accept denied)"),
            "{}",
            run.stdout
        );
        assert!(run.stdout.contains("Summary"), "{}", run.stdout);
    }

    /// Without a daemon, the agent's own `kraken mcp` and this run share one session: the run
    /// starts a private daemon and the agent's MCP server goes through it. Before, the agent's
    /// server opened the project in a second session and the run, saving last, dropped the
    /// agent's renames from the engine while the log marked them pushed.
    #[tokio::test(flavor = "multi_thread")]
    async fn without_a_daemon_the_agent_edits_in_the_runs_session_through_a_private_daemon() {
        use kraken_engine::CancellationToken;
        use kraken_proto::Locator;
        use kraken_registry::Session;
        use std::os::unix::fs::PermissionsExt;

        let work = workdir();
        let world = tempfile::tempdir().expect("tempdir");
        let vars = select(world.path());
        // the agent: the fake, which starts the MCP server it is given and renames through it
        let record = world.path().join("acp.jsonl");
        let calls = json!([{"name": "rename_symbol",
                            "arguments": {"address": "0x401040", "new_name": "parse_args"}}]);
        let script = world.path().join("agent.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nFAKE_ACP_RECORD='{}' FAKE_ACP_MCP_CALLS='{calls}' exec '{}' agents __fake-agent\n",
                path_str(&record),
                env!("CARGO_BIN_EXE_kraken")
            ),
        )
        .expect("script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(
            world.path().join("config/kraken/agents.toml"),
            format!(
                "[[agent]]\nid = \"fake\"\nname = \"Fake agent\"\ncommand = \"{}\"\n",
                path_str(&script)
            ),
        )
        .expect("agents.toml");
        let runtime = vars
            .iter()
            .find(|(k, _)| *k == "KRAKEN_RUNTIME_DIR")
            .map(|(_, v)| v.clone())
            .expect("runtime dir");
        let factory = Arc::new(StatefulFactory);
        let env = CliEnv {
            factory: factory.clone(),
            ..fresh_env(KrakenConfig::default(), vars)
        };
        let dir = work.tmp.path().join("p");
        let run = kraken(
            &env,
            &[
                "auto",
                &path_str(&work.binary),
                "--project-dir",
                &path_str(&dir),
                "--names",
            ],
        )
        .await;
        assert_eq!(run.code, 0, "{}\n{}", run.stdout, run.stderr);
        assert!(run.stderr.contains("private one"), "{}", run.stderr);
        assert!(
            run.stdout.contains("mcp rename_symbol: ok"),
            "{}\n{}",
            run.stdout,
            run.stderr
        );

        // session/new pointed the agent's MCP server at the run's private daemon
        let text = std::fs::read_to_string(&record).expect("record");
        let new = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .find(|m| m["method"] == "session/new")
            .expect("session/new");
        let server = &new["params"]["mcpServers"][0];
        assert!(
            server["args"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x == "--daemon")),
            "{server}"
        );
        let env_of = |k: &str| {
            server["env"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["name"] == k))
                .and_then(|e| e["value"].as_str())
                .map(str::to_string)
        };
        let private = env_of("KRAKEN_RUNTIME_DIR").expect("runtime dir for the MCP server");
        assert_ne!(private, runtime);
        assert!(env_of("KRAKEN_NO_DAEMON").is_none(), "{server}");
        // the private daemon is gone with the run
        assert!(!Path::new(&private).exists());

        // reopened from disk: the engine has the agent's rename, and the state needed no repair
        let s = Session::open(&dir, factory).await.expect("reopen");
        let f = s
            .engine()
            .expect("engine")
            .function_lister()
            .expect("lister")
            .get_function(&Locator::ram(0x401040), &CancellationToken::new())
            .await
            .expect("function");
        assert_eq!(f.name, "parse_args");
        assert!(s.project().expect("project").resync_report().is_none());
    }
}

// ---- the rewrite path, on a corpus program with a cassette -------------------------------------

fn corpus(sub: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(sub)
        .join(file)
}

fn ghidra_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("KRAKEN_GHIDRA_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    let home = std::env::var_os("HOME")?;
    std::fs::read_dir(Path::new(&home).join(".cache/kraken-dev/ghidra"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.join("Ghidra/Processors/x86/data/languages/x86.ldefs")
                .is_file()
        })
}

fn rewrite_env(binary: &str, cassette: &str) -> CliEnv {
    let fixture =
        FixtureFile::from_path(&corpus("fixtures", &format!("{binary}.json"))).expect("fixture");
    let cassette = ReplayProvider::from_path(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kraken-rewrite/cassettes")
            .join(cassette),
    )
    .expect("cassette");
    let service = RewriteService::new(
        Arc::new(FixedProvider(Arc::new(cassette))),
        RewriteConfig {
            oracle: OracleConfig {
                ghidra_home: ghidra_home(),
                ..OracleConfig::default()
            },
            ..RewriteConfig::default()
        },
    );
    CliEnv {
        registry: Arc::new(Registry::standard()),
        factory: Arc::new(FakeFactory { fixture }),
        config: KrakenConfig::default(),
        author: CliAuthor::User("tester".into()),
        vars: Box::new(|_| None),
        interactive: false,
        session: None,
        daemon: DaemonMode::Direct,
        rewrite: Some(service.into_backend()),
    }
}

#[tokio::test]
async fn auto_rewrite_reports_the_program_verdict_and_where_the_crate_is() {
    if !kraken_rewrite::sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code (Landlock ABI 4+ needed)");
        return;
    }
    let env = rewrite_env("switch_vm-O0", "program-switch-vm.json");
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&tmp.path().join("p"));
    let binary = corpus("bin", "switch_vm-O0");
    let run = kraken(
        &env,
        &[
            "--json",
            "auto",
            &path_str(&binary),
            "--project-dir",
            &dir,
            "--rewrite",
            "--no-function-tests",
            "--cases",
            r#"[{"name": "no arguments", "argv": []}]"#,
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["rewrite"]["verdict"], "pass", "{v:#}");
    let crate_dir = v["rewrite"]["crate_dir"].as_str().expect("crate dir");
    assert!(
        Path::new(crate_dir).join("Cargo.toml").exists(),
        "{crate_dir}"
    );
    assert!(
        run.stderr.contains("functions planned"),
        "progress is reported: {}",
        run.stderr
    );
}

#[tokio::test]
async fn accept_verified_accepts_what_passed_and_reports_the_export() {
    if !kraken_rewrite::sandbox::enforced() || ghidra_home().is_none() {
        eprintln!("skipped: needs Landlock and a Ghidra install for the SLEIGH specs");
        return;
    }
    let env = rewrite_env("pie_list-O0", "program-pie-list.json");
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&tmp.path().join("p"));
    let binary = corpus("bin", "pie_list-O0");
    let run = kraken(
        &env,
        &[
            "--json",
            "auto",
            &path_str(&binary),
            "--project-dir",
            &dir,
            "--rewrite",
            "--accept-verified",
        ],
    )
    .await;
    let v: Value = serde_json::from_str(run.stdout.trim()).expect("summary on stdout");
    assert_eq!(v["rewrite"]["verdict"], "pass", "{v:#}");
    assert!(
        v["rewrite"]["accepted"].as_u64().is_some_and(|n| n > 0),
        "{v:#}"
    );
    // The export carries the runtime shim, so it builds.
    let export = v["rewrite"]["export_dir"]
        .as_str()
        .unwrap_or_else(|| panic!("{v:#}"));
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(Path::new(export).join("Cargo.toml").exists(), "{export}");
}

#[tokio::test]
async fn an_export_calls_an_unaccepted_callee_in_the_original() {
    if !kraken_rewrite::sandbox::enforced() || ghidra_home().is_none() {
        eprintln!("skipped: needs Landlock and a Ghidra install for the SLEIGH specs");
        return;
    }
    // `op_name` returns a pointer, so it is never accepted, and `main` calls it: the export
    // declares the original `op_name` and calls it, and the README says so.
    let env = rewrite_env("switch_vm-O0", "program-switch-vm.json");
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&tmp.path().join("p"));
    let binary = corpus("bin", "switch_vm-O0");
    let run = kraken(
        &env,
        &[
            "--json",
            "auto",
            &path_str(&binary),
            "--project-dir",
            &dir,
            "--rewrite",
            "--accept-verified",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v: Value = serde_json::from_str(run.stdout.trim()).expect("summary on stdout");
    assert_eq!(v["rewrite"]["verdict"], "pass", "{v:#}");
    let export = v["rewrite"]["export_dir"].as_str().expect("export dir");
    let readme = std::fs::read_to_string(Path::new(export).join("README.md")).expect("readme");
    assert!(
        readme.contains("Calls into the original program"),
        "{readme}"
    );
    assert!(readme.contains("op_name"), "{readme}");
}

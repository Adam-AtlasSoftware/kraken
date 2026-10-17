//! The real `kraken` and `krakend` binaries: auto-start from the directory of `kraken`, commands
//! through the daemon, `daemon status|stop|start`, `kraken mcp --daemon`. The daemon runs the
//! scripted fake engine (`KRAKEN_FAKE_ENGINE`), so no Ghidra is needed.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use common::default_named;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use serde_json::{Value, json};

/// `krakend` next to the `kraken` binary; built on demand when only this package was tested.
fn ensure_krakend() -> PathBuf {
    let kraken = Path::new(env!("CARGO_BIN_EXE_kraken"));
    let sibling = kraken.with_file_name("krakend");
    if !sibling.is_file() {
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let status = Command::new(cargo)
            .args(["build", "-p", "krakend"])
            .status()
            .expect("cargo build -p krakend");
        assert!(status.success());
    }
    assert!(sibling.is_file(), "{} exists", sibling.display());
    sibling
}

struct Env {
    tmp: tempfile::TempDir,
    rt: PathBuf,
    fixture: PathBuf,
    binary: PathBuf,
    idle_secs: &'static str,
}

fn env() -> Env {
    ensure_krakend();
    let tmp = tempfile::Builder::new()
        .prefix("kraken-bin")
        .tempdir()
        .expect("tempdir");
    let fixture = tmp.path().join("fixture.json");
    std::fs::write(&fixture, default_named().to_json().expect("fixture json")).unwrap();
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake binary").unwrap();
    Env {
        rt: tmp.path().join("rt"),
        tmp,
        fixture,
        binary,
        idle_secs: "600",
    }
}

impl Env {
    fn command(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kraken"));
        self.configure(&mut c);
        c
    }

    fn configure(&self, c: &mut Command) {
        c.env("KRAKEN_RUNTIME_DIR", &self.rt)
            .env("KRAKEN_FAKE_ENGINE", &self.fixture)
            .env("KRAKEN_CONFIG", self.tmp.path().join("no-config.toml"))
            .env("KRAKEN_DAEMON_IDLE_SECS", self.idle_secs)
            .env_remove("KRAKEN_PROJECT")
            .env_remove("KRAKEN_KRAKEND")
            .env_remove("KRAKEN_NO_DAEMON");
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("run kraken")
    }

    fn ok(&self, args: &[&str]) -> Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "kraken {args:?}: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "kraken {args:?}: not JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
    }

    fn files_left(&self) -> bool {
        self.rt.join("daemon.json").exists() || self.rt.join("daemon.sock").exists()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        // Never leave a daemon behind.
        let mut c = self.command();
        let _ = c.args(["daemon", "stop"]).output();
    }
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
fn the_first_command_starts_the_daemon_and_later_ones_reuse_it() {
    let e = env();
    assert!(!e.files_left());
    let proj = path(&e.tmp.path().join("proj"));

    let created = e.ok(&[
        "--json",
        "project-create",
        "--binary",
        &path(&e.binary),
        "--project-dir",
        &proj,
    ]);
    assert_eq!(created["program"]["format"], "elf");
    assert!(e.files_left(), "kraken started a daemon");

    let st = e.ok(&["--json", "daemon", "status"]);
    assert_eq!(st["running"], true);
    let pid = st["daemon"]["pid"].as_u64().expect("pid");
    assert_eq!(st["sessions"].as_array().map(Vec::len), Some(1));

    // State lives in the daemon between invocations (the fake engine itself is not persistent).
    let renamed = e.ok(&[
        "--json",
        "--project",
        &proj,
        "rename-symbol",
        "--address",
        "0x401000",
        "--new-name",
        "survives_invocations",
    ]);
    assert_eq!(renamed["status"], "applied");
    let found = e.ok(&[
        "--json",
        "--project",
        &proj,
        "list-functions",
        "--name-filter",
        "survives",
    ]);
    assert_eq!(found["items"].as_array().map(Vec::len), Some(1));

    // A job through the daemon prints progress on stderr and the final job view on stdout.
    let out = e.run(&["--json", "--project", &proj, "analyze"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let job: Value = serde_json::from_slice(&out.stdout).expect("job JSON");
    assert_eq!(job["status"], "succeeded", "{job}");
    assert!(String::from_utf8_lossy(&out.stderr).contains('['));

    // Still the same daemon.
    assert_eq!(e.ok(&["--json", "daemon", "status"])["daemon"]["pid"], pid);
    let start = e.ok(&["--json", "daemon", "start"]);
    assert_eq!(start["started"], false);
    assert_eq!(start["pid"], pid);

    let stop = e.ok(&["--json", "daemon", "stop"]);
    assert_eq!(stop["stopped"], true);
    assert!(!e.files_left(), "the daemon cleaned up");
    assert_eq!(e.ok(&["--json", "daemon", "status"])["running"], false);

    // The next command starts a fresh daemon with a new pid.
    let again = e.ok(&["--json", "daemon", "start"]);
    assert_eq!(again["started"], true);
    assert_ne!(again["pid"], pid);
}

#[test]
fn racing_clients_start_exactly_one_daemon() {
    let e = env();
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let mut c = e.command();
            c.args(["--json", "daemon", "start"]);
            std::thread::spawn(move || c.output().expect("run kraken"))
        })
        .collect();
    let mut pids = Vec::new();
    let mut started = 0;
    for h in handles {
        let out = h.join().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        pids.push(v["pid"].as_u64().unwrap());
        started += usize::from(v["started"] == true);
    }
    pids.dedup();
    assert_eq!(pids.len(), 1, "{pids:?}");
    assert!(started >= 1);
}

#[test]
fn the_daemon_leaves_by_itself_after_the_idle_timeout() {
    let mut e = env();
    e.idle_secs = "1";
    e.ok(&["--json", "daemon", "start"]);
    assert!(e.files_left());
    for _ in 0..200 {
        if !e.files_left() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the idle daemon did not exit");
}

#[tokio::test(flavor = "multi_thread")]
async fn kraken_mcp_daemon_routes_the_tools_through_krakend() {
    let e = env();
    let proj = path(&e.tmp.path().join("proj"));
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_kraken")).configure(|c| {
            c.args(["mcp", "--daemon"])
                .env("KRAKEN_RUNTIME_DIR", &e.rt)
                .env("KRAKEN_FAKE_ENGINE", &e.fixture)
                .env("KRAKEN_CONFIG", e.tmp.path().join("no-config.toml"))
                .env_remove("KRAKEN_PROJECT");
        }),
    )
    .expect("spawn kraken mcp --daemon");
    let client = ().serve(transport).await.expect("initialise");
    assert_eq!(client.list_all_tools().await.expect("tools").len(), 47);

    let call = |tool: &str, args: Value| {
        let client = &client;
        let tool = tool.to_string();
        async move {
            let r = client
                .call_tool(
                    CallToolRequestParams::new(tool.clone())
                        .with_arguments(args.as_object().cloned().unwrap_or_default()),
                )
                .await
                .unwrap_or_else(|err| panic!("{tool}: {err}"));
            let text = r
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.clone())
                .unwrap();
            (
                r.is_error != Some(true),
                serde_json::from_str::<Value>(&text).unwrap(),
            )
        }
    };
    let (ok, v) = call("list_functions", json!({})).await;
    assert!(!ok && v["code"] == "not_found", "no project yet: {v}");
    // An agent cannot open a project by itself: the request waits for the person, who answers
    // it with the CLI.
    let approver = async {
        for _ in 0..400 {
            let v = e.ok(&["--json", "daemon", "approvals"]);
            if let Some(p) = v["pending"].as_array().and_then(|a| a.first()) {
                assert_eq!(p["command"], "project_create", "{p}");
                let id = p["id"].to_string();
                e.ok(&["--json", "daemon", "approvals", "--approve", &id]);
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the agent's request never reached the approval list");
    };
    let ((ok, v), ()) = tokio::join!(
        call(
            "project_create",
            json!({"binary": path(&e.binary), "project_dir": proj}),
        ),
        approver
    );
    assert!(ok, "{v}");
    let (ok, v) = call("list_functions", json!({})).await;
    assert!(ok && v["items"].as_array().map(Vec::len) == Some(3), "{v}");
    let (ok, v) = call(
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "from_mcp"}),
    )
    .await;
    assert!(ok, "{v}");

    // The CLI sees the agent's edit and its author in the same daemon.
    let hist = e.ok(&["--json", "--project", &proj, "history"]);
    let first = &hist["items"][0];
    assert_eq!(first["author"]["kind"], "agent", "{hist}");
    let st = e.ok(&["--json", "daemon", "status"]);
    assert_eq!(st["sessions"].as_array().map(Vec::len), Some(1));
    client.cancel().await.expect("shutdown");
}

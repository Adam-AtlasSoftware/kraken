//! Dependency-aware undo against real Ghidra (decisions 28, 49, 58, 74). `#[ignore]`d:
//!
//! ```text
//! cargo xtask ghidra-ext && \
//!   env $(sed 's/^export //' plans/dev-env.sh) \
//!   cargo test -p kraken-e2e --test undo_dependents -- --ignored
//! ```
//!
//! A user renames a function and gives it a prototype; an agent then renames another function
//! having read that prototype. Undoing the prototype is refused until the agent's rename is
//! listed, then undone with `cascade`. The engine must show the old signature and the old name,
//! and a rebuild from the log must report no drift.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::{Value, json};

const BINARY: &str = "pie_list-O0-stripped";
const AGENT: &str = "undo-agent";

#[derive(Clone)]
struct Agent;

impl ClientHandler for Agent {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            ClientCapabilities::default(),
            Implementation::new(AGENT, "1.0"),
        )
    }
}

fn first_child(parent: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

/// Environment for every `kraken` child: Ghidra and JDK homes, no user config, no ambient project.
struct KrakenEnv {
    ghidra_home: Option<PathBuf>,
    java_home: Option<PathBuf>,
    config: PathBuf,
    runtime: PathBuf,
}

impl KrakenEnv {
    fn new(scratch: &Path) -> KrakenEnv {
        let cache = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kraken-dev"));
        KrakenEnv {
            ghidra_home: std::env::var_os("KRAKEN_GHIDRA_HOME")
                .map(PathBuf::from)
                .or_else(|| cache.as_ref().and_then(|c| first_child(&c.join("ghidra")))),
            java_home: std::env::var_os("KRAKEN_JAVA_HOME")
                .or_else(|| std::env::var_os("JAVA_HOME"))
                .map(PathBuf::from)
                .or_else(|| cache.as_ref().and_then(|c| first_child(&c.join("jdk")))),
            config: scratch.join("no-config.toml"),
            runtime: private_runtime_dir(scratch),
        }
    }

    fn apply(&self, cmd: &mut Command) {
        // Never touch the developer's real daemon: a private runtime dir, and in-process sessions.
        cmd.env("KRAKEN_CONFIG", &self.config)
            .env("KRAKEN_RUNTIME_DIR", &self.runtime)
            .env("KRAKEN_NO_DAEMON", "1")
            .env_remove("KRAKEN_PROJECT");
        if let Some(g) = &self.ghidra_home {
            cmd.env("KRAKEN_GHIDRA_HOME", g);
        }
        if let Some(j) = &self.java_home {
            cmd.env("KRAKEN_JAVA_HOME", j);
        }
    }
}

fn private_runtime_dir(scratch: &Path) -> PathBuf {
    let dir = scratch.join("run");
    std::fs::create_dir_all(&dir).expect("create runtime dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("chmod runtime dir");
    }
    dir
}

/// `target/<profile>/kraken`, built on demand (this crate cannot name another package's binary).
fn kraken_bin() -> PathBuf {
    let exe = std::env::current_exe().expect("test exe path");
    let profile_dir = exe
        .parent()
        .and_then(Path::parent)
        .expect("target profile directory")
        .to_path_buf();
    let bin = profile_dir.join("kraken");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut build = Command::new(cargo);
    build.args(["build", "-p", "kraken-cli", "--bin", "kraken"]);
    if profile_dir.file_name().is_some_and(|n| n == "release") {
        build.arg("--release");
    }
    let status = build.status().expect("run cargo build");
    assert!(status.success(), "cargo build -p kraken-cli failed");
    assert!(bin.is_file(), "missing {}", bin.display());
    bin
}

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

/// One MCP session against `kraken mcp [--project dir]`.
struct Session {
    client: RunningService<RoleClient, Agent>,
}

impl Session {
    async fn start(bin: &Path, env: &KrakenEnv, project: Option<&Path>) -> Session {
        let mut std_cmd = Command::new(bin);
        env.apply(&mut std_cmd);
        let mut cmd = tokio::process::Command::from(std_cmd);
        cmd.kill_on_drop(true);
        let transport = TokioChildProcess::new(cmd.configure(|c| {
            c.arg("mcp");
            if let Some(p) = project {
                c.arg("--project").arg(p);
            }
        }))
        .expect("spawn kraken mcp");
        let client = Agent.serve(transport).await.expect("initialise");
        Session { client }
    }

    async fn call(&self, tool: &str, args: Value) -> Value {
        let obj = args.as_object().cloned().unwrap_or_default();
        let r = self
            .client
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(obj))
            .await
            .unwrap_or_else(|e| panic!("{tool}: protocol error: {e}"));
        if r.is_error == Some(true) {
            let text = r
                .content
                .first()
                .and_then(|c| c.as_text())
                .map(|t| t.text.clone())
                .unwrap_or_default();
            panic!("{tool} failed: {text}");
        }
        r.structured_content.expect("structured content")
    }

    /// Runs a job tool and waits for it to finish.
    async fn job(&self, tool: &str) -> Value {
        let started = self.call(tool, json!({})).await;
        let done = self
            .call(
                "job_await",
                json!({"job_id": started["job_id"], "timeout_ms": 480_000}),
            )
            .await;
        assert_eq!(done["status"], "succeeded", "{tool}: {done}");
        done
    }

    /// Every function, as (address, name, size), following the pagination cursor.
    async fn functions(&self) -> Vec<(String, String, u64)> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut args = json!({"limit": 200});
            if let Some(c) = &cursor {
                args["cursor"] = json!(c);
            }
            let page = self.call("list_functions", args).await;
            for f in page["items"].as_array().expect("items") {
                out.push((
                    f["address"].as_str().expect("address").to_string(),
                    f["name"]["value"].as_str().expect("name").to_string(),
                    f["size"].as_u64().unwrap_or(0),
                ));
            }
            match page["next_cursor"].as_str() {
                Some(c) => cursor = Some(c.to_string()),
                None => return out,
            }
        }
    }

    async fn close(self) {
        self.client.cancel().await.expect("shut the session down");
    }
}

/// Runs the CLI as the user with JSON arguments; returns (success, stdout JSON or stderr text).
fn cli(bin: &Path, env: &KrakenEnv, project: &Path, command: &str, args: &Value) -> (bool, Value) {
    let mut cmd = Command::new(bin);
    env.apply(&mut cmd);
    let out = cmd
        .arg("--json")
        .arg("--project")
        .arg(project)
        .arg(command)
        .arg("--args-json")
        .arg(args.to_string())
        .output()
        .expect("run kraken");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let text = if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        stdout.trim().to_string()
    };
    let json = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "text": text }));
    (out.status.success(), json)
}

fn is_default_name(n: &str) -> bool {
    n.strip_prefix("FUN_")
        .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex address")
}

async fn signature(s: &Session, addr: &str) -> String {
    s.call("get_function", json!({"address": addr})).await["signature"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn name(s: &Session, addr: &str) -> String {
    s.call("get_function", json!({"address": addr})).await["name"]["value"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Ghidra: cargo xtask ghidra-ext and KRAKEN_GHIDRA_HOME / KRAKEN_JAVA_HOME"]
async fn undoing_a_type_with_cascade_leaves_the_engine_matching_the_log() {
    let bin = kraken_bin();
    // Ghidra rejects project paths with a dot-prefixed element, so no default `.tmpXXXX` dirs.
    let tmp = tempfile::Builder::new()
        .prefix("kraken-undo-")
        .tempdir()
        .expect("tempdir");
    let env = KrakenEnv::new(tmp.path());
    let project = tmp.path().join("proj");
    let binary = corpus(&format!("bin/{BINARY}"));
    assert!(binary.is_file(), "missing {}", binary.display());

    // ---- The agent loads and analyses.
    let s = Session::start(&bin, &env, None).await;
    s.call(
        "project_create",
        json!({"binary": binary, "project_dir": project}),
    )
    .await;
    let analysed = s.job("analyze").await;
    assert!(
        analysed["result"]["function_count"].as_u64().unwrap_or(0) > 8,
        "{analysed}"
    );
    let funcs = s.functions().await;
    let mut named = funcs
        .iter()
        .filter(|(_, n, size)| is_default_name(n) && *size >= 16);
    let a = named
        .next()
        .expect("a function to rename and retype")
        .clone();
    let b = named.next().expect("a function the agent renames").clone();
    s.close().await;

    // ---- The user renames A and gives it a prototype.
    let (ok, r) = cli(
        &bin,
        &env,
        &project,
        "rename-symbol",
        &json!({"address": a.0, "new_name": "user_fn"}),
    );
    assert!(ok && r["status"] == "applied", "{r}");
    let prototype = json!({
        "return_type": {"kind": "primitive", "class": "int", "size": 4, "signed": true},
        "params": [
            {"name": "count", "type": {"kind": "primitive", "class": "int", "size": 4, "signed": true}}
        ],
        "calling_convention": "",
        "varargs": false,
        "noreturn": false
    });
    let (ok, typed) = cli(
        &bin,
        &env,
        &project,
        "set-type",
        &json!({"address": a.0, "prototype": prototype}),
    );
    assert!(ok && typed["status"] == "applied", "{typed}");
    let type_entry = typed["entry_id"].as_u64().expect("type entry id");
    let type_key = format!("native:ram:{:#x}:type", hex(&a.0));
    let type_version = typed["versions"][&type_key].as_u64().expect("type version");

    // ---- The agent renames B, having read A's prototype.
    let s = Session::start(&bin, &env, Some(&project)).await;
    let sig_typed = signature(&s, &a.0).await;
    assert!(
        sig_typed.contains("user_fn") && sig_typed.contains("count"),
        "{sig_typed}"
    );
    let name_key = format!("native:ram:{:#x}:name", hex(&b.0));
    let renamed = s
        .call(
            "rename_symbol",
            json!({"address": b.0, "new_name": "agent_fn",
                   "expect_versions": {type_key.clone(): type_version, name_key: 0}}),
        )
        .await;
    assert_eq!(renamed["status"], "applied", "{renamed}");
    let agent_entry = renamed["entry_id"].as_u64().expect("agent entry id");
    assert_eq!(name(&s, &b.0).await, "agent_fn");
    s.close().await;

    // ---- Preview, refusal, then the cascade.
    let (ok, preview) = cli(
        &bin,
        &env,
        &project,
        "undo-preview",
        &json!({"entry_id": type_entry}),
    );
    assert!(ok, "{preview}");
    assert_eq!(preview["dependents"].as_array().map(Vec::len), Some(1));
    assert_eq!(preview["dependents"][0]["entry"]["id"], agent_entry);
    assert_eq!(preview["undo_order"], json!([agent_entry, type_entry]));

    let (ok, refused) = cli(
        &bin,
        &env,
        &project,
        "undo-entry",
        &json!({"entry_id": type_entry}),
    );
    assert!(!ok, "{refused}");
    assert!(refused.to_string().contains("has_dependents"), "{refused}");

    let (ok, undone) = cli(
        &bin,
        &env,
        &project,
        "undo-entry",
        &json!({"entry_id": type_entry, "cascade": true}),
    );
    assert!(ok, "{undone}");
    assert_eq!(undone["status"], "applied", "{undone}");
    assert_eq!(
        undone["failed"],
        json!([]),
        "the engine accepted both: {undone}"
    );
    assert_eq!(undone["undone_entry_ids"], json!([agent_entry, type_entry]));
    let stale = |v: &Value, addr: &str| {
        v.as_array().is_some_and(|t| {
            t.iter()
                .any(|x| hex(x.as_str().unwrap_or("0")) == hex(addr))
        })
    };
    assert!(
        stale(&undone["tainted"], &a.0),
        "the retyped function is marked stale: {undone}"
    );
    assert_eq!(
        undone["drift"].as_array().map_or(0, Vec::len),
        0,
        "{undone}"
    );

    // ---- The engine shows the old state; a rebuild from the log finds no drift.
    let s = Session::start(&bin, &env, Some(&project)).await;
    let sig_after = signature(&s, &a.0).await;
    assert!(
        sig_after.contains("user_fn") && !sig_after.contains("count"),
        "the prototype went back but the user's rename stays: {sig_after}"
    );
    assert_eq!(name(&s, &b.0).await, b.1, "the agent's rename is gone");
    let listed = s.call("tainted_list", json!({})).await;
    assert!(
        listed["items"].as_array().is_some_and(|i| i
            .iter()
            .any(|x| hex(x["address"].as_str().unwrap_or("0")) == hex(&a.0))),
        "{listed}"
    );

    let rebuilt = s.job("rebuild").await;
    let report = &rebuilt["result"];
    assert_eq!(report["failed"], json!([]), "replay failures: {report}");
    assert_eq!(
        report["drifted"],
        json!([]),
        "drift after rebuild: {report}"
    );
    assert_eq!(signature(&s, &a.0).await, sig_after);
    assert_eq!(name(&s, &b.0).await, b.1);
    s.close().await;
}

//! 0.1a exit criterion (decision 81), against real Ghidra. `#[ignore]`d:
//!
//! ```text
//! cargo xtask ghidra-ext && \
//!   env $(sed 's/^export //' plans/dev-env.sh) cargo test -p kraken-e2e -- --ignored
//! ```
//!
//! An agent drives the built `kraken mcp` binary (a child process speaking MCP over stdio): it
//! loads a corpus ELF, renames two functions, retypes one, and proposes deleting and recreating
//! a small one (proposing the recreate once the delete is in). Structural edits are never auto-applied for agents, so the user accepts those
//! proposals with the CLI between MCP sessions. A third agent session undoes its last edit,
//! rebuilds the Ghidra project from the log and checks that the rebuild matches the log.
//!
//! The binary is the stripped `pie_list-O0` build: every function carries a Ghidra default
//! name, so the agent's renames are additive and auto-apply. Its unstripped twin has real
//! symbols, which would turn the same renames into proposals.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::{Value, json};

const BINARY: &str = "pie_list-O0-stripped";
/// A tiny leaf comparator in the corpus source (`cmp_id`, 30 bytes), known from the truth file.
const RECREATE: &str = "cmp_id";
const AGENT: &str = "exit-agent";

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

/// Runs the CLI as the user and returns its JSON output.
fn cli(bin: &Path, env: &KrakenEnv, project: &Path, args: &[&str]) -> Value {
    let mut cmd = Command::new(bin);
    env.apply(&mut cmd);
    let out = cmd
        .arg("--json")
        .arg("--project")
        .arg(project)
        .args(args)
        .output()
        .expect("run kraken");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "kraken {args:?} failed\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("kraken {args:?}: {e}: {stdout}"))
}

fn is_default_name(n: &str) -> bool {
    n.strip_prefix("FUN_")
        .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()))
}

fn hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex address")
}

/// Entry offset of `name` from the corpus truth file (link-time address, base 0).
fn truth_entry(name: &str) -> u64 {
    let path = corpus(&format!("truth/{BINARY}.json"));
    let truth: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("truth file")).expect("json");
    let f = truth["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("{name} not in {}", path.display()));
    hex(f["entry"].as_str().expect("entry"))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Ghidra: cargo xtask ghidra-ext and KRAKEN_GHIDRA_HOME / KRAKEN_JAVA_HOME"]
async fn agent_edits_undo_and_rebuild_match_the_log() {
    let bin = kraken_bin();
    // Ghidra rejects project paths with a dot-prefixed element, so no default `.tmpXXXX` dirs.
    let tmp = tempfile::Builder::new()
        .prefix("kraken-exit-")
        .tempdir()
        .expect("tempdir");
    let env = KrakenEnv::new(tmp.path());
    let project = tmp.path().join("proj");
    let binary = corpus(&format!("bin/{BINARY}"));
    assert!(binary.is_file(), "missing {}", binary.display());

    // ---- Session 1: the agent loads, analyses, renames, retypes and proposes structure edits.
    let s = Session::start(&bin, &env, None).await;
    let created = s
        .call(
            "project_create",
            json!({"binary": binary, "project_dir": project}),
        )
        .await;
    let base = hex(created["program"]["base"].as_str().expect("image base"));
    let analysed = s.job("analyze").await;
    assert!(
        analysed["result"]["function_count"].as_u64().unwrap_or(0) > 8,
        "{analysed}"
    );

    let funcs = s.functions().await;
    assert!(funcs.len() > 8, "{funcs:?}");

    // The function to delete and recreate: the corpus truth gives its link-time entry.
    let target_addr = base + truth_entry(RECREATE);
    let target_hex = format!("{target_addr:#x}");
    let target = funcs
        .iter()
        .find(|(a, _, _)| hex(a) == target_addr)
        .unwrap_or_else(|| panic!("no function at {target_hex} in {funcs:?}"))
        .clone();
    assert!(is_default_name(&target.1), "{target:?}");
    assert!(
        target.2 > 0 && target.2 < 64,
        "a small function: {target:?}"
    );

    // Two other default-named functions to rename; the first also gets a prototype.
    let mut others = funcs
        .iter()
        .filter(|(a, n, _)| hex(a) != target_addr && is_default_name(n))
        // Skip thunks and stubs: real corpus functions have a body worth naming.
        .filter(|(_, _, size)| *size >= 16);
    let first = others.next().expect("a first function to rename").clone();
    let second = others.next().expect("a second function to rename").clone();

    let sig_before =
        s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
            .as_str()
            .map(str::to_string);

    for (f, new_name) in [(&first, "exit_first"), (&second, "exit_second")] {
        let r = s
            .call(
                "rename_symbol",
                json!({"address": f.0, "new_name": new_name}),
            )
            .await;
        assert_eq!(r["status"], "applied", "{r}");
    }

    let prototype = json!({
        "return_type": {"kind": "primitive", "class": "int", "size": 4, "signed": true},
        "params": [
            {"name": "count", "type": {"kind": "primitive", "class": "int", "size": 4, "signed": true}}
        ],
        "calling_convention": "",
        "varargs": false,
        "noreturn": false
    });
    let typed = s
        .call(
            "set_type",
            json!({"address": first.0, "prototype": prototype}),
        )
        .await;
    assert_eq!(typed["status"], "applied", "{typed}");
    let sig_typed = s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
        .as_str()
        .map(str::to_string);
    assert!(
        sig_typed
            .as_deref()
            .is_some_and(|sig| sig.contains("exit_first") && sig.contains("count")),
        "the retyped signature shows in the engine: {sig_typed:?}"
    );

    // Structural edits by an agent are proposals. A function can only be proposed for creation
    // once it is gone, so the delete is proposed and accepted first.
    let del = s
        .call("delete_function", json!({"address": target_hex}))
        .await;
    assert_eq!(del["status"], "proposed", "{del}");
    let still_there = s.functions().await;
    assert!(
        still_there.iter().any(|(a, _, _)| hex(a) == target_addr),
        "proposals do not touch the engine"
    );
    s.close().await;

    // ---- The user accepts the delete with the CLI.
    let out = cli(
        &bin,
        &env,
        &project,
        &["proposal-accept", "--id", &del["proposal_id"].to_string()],
    );
    assert_eq!(out["status"], "applied", "{out}");

    // ---- Session 2: the agent proposes recreating the function; the user accepts it.
    let s = Session::start(&bin, &env, Some(&project)).await;
    assert!(
        !s.functions()
            .await
            .iter()
            .any(|(a, _, _)| hex(a) == target_addr),
        "the function is gone after the accepted delete"
    );
    let create = s
        .call("create_function", json!({"address": target_hex}))
        .await;
    assert_eq!(create["status"], "proposed", "{create}");
    s.close().await;
    let out = cli(
        &bin,
        &env,
        &project,
        &[
            "proposal-accept",
            "--id",
            &create["proposal_id"].to_string(),
        ],
    );
    assert_eq!(out["status"], "applied", "{out}");

    // ---- Session 3: the agent undoes its last edit, then rebuilds from the log.
    let s = Session::start(&bin, &env, Some(&project)).await;
    let after_structure = s.functions().await;
    assert!(
        after_structure
            .iter()
            .any(|(a, _, _)| hex(a) == target_addr),
        "the function exists again after delete + create: {after_structure:?}"
    );

    let undone = s.call("undo", json!({})).await;
    assert_eq!(undone["status"], "applied", "{undone}");
    assert_eq!(
        undone["failed"],
        json!([]),
        "the engine accepted the undo: {undone}"
    );
    let sig_undone =
        s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
            .as_str()
            .map(str::to_string);
    assert_ne!(sig_undone, sig_typed, "undo reverted the prototype");
    if let Some(before) = &sig_before {
        // The rename stays; only the type went back.
        assert!(
            sig_undone
                .as_deref()
                .is_some_and(|s| s.contains("exit_first") && !s.contains("count")),
            "before={before} undone={sig_undone:?}"
        );
    }

    let live: BTreeMap<u64, String> = s
        .functions()
        .await
        .into_iter()
        .map(|(a, n, _)| (hex(&a), n))
        .collect();
    assert_eq!(
        live.get(&hex(&first.0)).map(String::as_str),
        Some("exit_first")
    );
    assert_eq!(
        live.get(&hex(&second.0)).map(String::as_str),
        Some("exit_second")
    );

    let rebuilt = s.job("rebuild").await;
    let report = &rebuilt["result"];
    assert_eq!(report["failed"], json!([]), "replay failures: {report}");
    assert_eq!(
        report["drifted"],
        json!([]),
        "drift after rebuild: {report}"
    );
    assert!(report["replayed"].as_u64().unwrap_or(0) >= 6, "{report}");

    // The names materialised in the rebuilt project match the log and the pre-rebuild project.
    let fresh: BTreeMap<u64, String> = s
        .functions()
        .await
        .into_iter()
        .map(|(a, n, _)| (hex(&a), n))
        .collect();
    assert_eq!(fresh, live, "rebuilt function list differs");

    let history = s.call("history", json!({"limit": 100})).await;
    let mut logged_names: BTreeMap<u64, String> = BTreeMap::new();
    let mut applied = 0;
    for e in history["items"].as_array().expect("items").iter().rev() {
        if e["status"]["kind"] != "applied" {
            continue;
        }
        applied += 1;
        let desc = e["description"]["value"].as_str().unwrap_or_default();
        if e["op"] == "rename" {
            // `description` reads "rename 0x... old -> new"; the state check below is exact.
            if let Some((_, new)) = desc.rsplit_once("-> ") {
                let addr = desc
                    .split_whitespace()
                    .find(|w| w.starts_with("0x"))
                    .map(hex);
                if let Some(a) = addr {
                    logged_names.insert(a, new.trim().to_string());
                }
            }
        }
    }
    assert!(applied >= 6, "log has the edits: {history}");
    assert_eq!(
        logged_names.get(&hex(&first.0)).map(String::as_str),
        Some("exit_first"),
        "{history}"
    );
    assert_eq!(
        logged_names.get(&hex(&second.0)).map(String::as_str),
        Some("exit_second"),
        "{history}"
    );
    for (addr, name) in &logged_names {
        assert_eq!(fresh.get(addr), Some(name), "{addr:#x} after rebuild");
    }
    s.close().await;
}

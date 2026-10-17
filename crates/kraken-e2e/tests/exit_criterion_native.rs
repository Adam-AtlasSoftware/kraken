//! The 0.1a exit-criterion flow (decision 81) against a native-engine project, with no JVM.
//!
//! The same script as `exit_criterion.rs`, run in this process (`kraken-host`'s
//! `NativeEngineFactory` builds the same engines, but would pull in the Ghidra and .NET
//! factories): the registry gets an engine factory that builds `NativeEngine`s whose state lives
//! in the project's engine directory, in the confined worker (`kraken-native-worker`, as the
//! host runs it; built by `cargo build -p engine-native`, else the test runs the engine
//! in-process and says so). Every step that is a separate `kraken` process in the Ghidra version
//! opens the project afresh here, so the engine's saved state is replayed on each open:
//!
//! - an agent (an MCP client on an in-process `kraken-mcp` server) analyses the stripped
//!   `pie_list-O0`, renames two functions, retypes one and proposes deleting a small one,
//! - the user accepts the delete; a second agent session proposes recreating it and the user
//!   accepts that too,
//! - a third agent session undoes its last edit (the prototype), rebuilds the engine project
//!   from the log and checks that the rebuild matches the log and the previous engine.
//!
//! Needs the native build (`cargo xtask native-src`) and Sleigh specs (`cargo xtask native-sla`
//! or `KRAKEN_GHIDRA_HOME`); without them it prints "skipped" and passes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::SharedEngine;
use kraken_mcp::{KrakenMcp, McpOptions, serve_transport};
use kraken_proto::ProtoError;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation};
use rmcp::service::RunningService;
use rmcp::{ClientHandler, RoleClient, ServiceExt};
use serde_json::{Value, json};

const BINARY: &str = "pie_list-O0-stripped";
/// A tiny leaf comparator in the corpus source (`cmp_id`, 30 bytes), known from the truth file.
const RECREATE: &str = "cmp_id";
const AGENT: &str = "exit-agent";

/// Builds native engines that keep their state in the engine directory the registry gives.
struct NativeFactory {
    config: NativeConfig,
}

#[async_trait]
impl EngineFactory for NativeFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let mut config = self.config.clone();
        config.state_dir = Some(engine_dir.to_path_buf());
        Ok(Arc::new(NativeEngine::new(config)))
    }
}

fn native_config() -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs (cargo xtask native-sla or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = match WorkerOptions::default().locate() {
        Ok(worker) => Isolation::Worker(WorkerOptions::with_program(worker)),
        Err(e) => {
            eprintln!("note: running the engine in-process: {}", e.message);
            Isolation::InProcess
        }
    };
    Some(c)
}

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

fn corpus(rel: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel);
    std::fs::canonicalize(&p).unwrap_or(p)
}

/// One agent session: the project opened afresh (as `kraken mcp --project` does) and an MCP
/// client on an in-process server bound to it.
struct AgentSession {
    client: RunningService<RoleClient, Agent>,
}

impl AgentSession {
    async fn start(registry: &Arc<Registry>, factory: &Arc<NativeFactory>, project: &Path) -> Self {
        let session = Arc::new(
            Session::open(project, factory.clone())
                .await
                .expect("open the project"),
        );
        let server = KrakenMcp::new(
            registry.clone(),
            session,
            McpOptions {
                bound_project: true,
                ..McpOptions::default()
            },
        );
        let (c, s) = tokio::io::duplex(1 << 22);
        tokio::spawn(async move {
            let _ = serve_transport(server, s).await;
        });
        let client = Agent.serve(c).await.expect("initialise");
        AgentSession { client }
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

/// The user runs one command in a fresh process (here: a fresh session over the project).
async fn user(
    registry: &Registry,
    factory: &Arc<NativeFactory>,
    project: &Path,
    command: &str,
    args: Value,
) -> Value {
    let session = Session::open(project, factory.clone())
        .await
        .expect("open the project");
    let ctx = CallContext::user("adam", Surface::Cli);
    registry
        .call_json(command, &session, &ctx, args)
        .await
        .unwrap_or_else(|e| panic!("{command}: {e}"))
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
async fn native_agent_edits_undo_and_rebuild_match_the_log() {
    let Some(config) = native_config() else {
        return;
    };
    let factory = Arc::new(NativeFactory { config });
    let registry = Arc::new(Registry::standard());
    let tmp = tempfile::Builder::new()
        .prefix("kraken-exit-native-")
        .tempdir()
        .expect("tempdir");
    let project = tmp.path().join("proj");
    let binary = corpus(&format!("bin/{BINARY}"));
    assert!(binary.is_file(), "missing {}", binary.display());

    // ---- The user creates the project.
    let base = {
        let session = Session::new(factory.clone());
        let p = session
            .create_project(&project, &binary)
            .await
            .expect("project-create");
        p.program().base.0
    };

    // ---- Session 1: the agent analyses, renames, retypes and proposes a delete.
    let s = AgentSession::start(&registry, &factory, &project).await;
    let analysed = s.job("analyze").await;
    assert!(
        analysed["result"]["function_count"].as_u64().unwrap_or(0) > 8,
        "{analysed}"
    );
    let funcs = s.functions().await;
    assert!(funcs.len() > 8, "{funcs:?}");

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

    let mut others = funcs
        .iter()
        .filter(|(a, n, _)| hex(a) != target_addr && is_default_name(n))
        .filter(|(_, _, size)| *size >= 16);
    let first = others.next().expect("a first function to rename").clone();
    let second = others.next().expect("a second function to rename").clone();

    let sig_before =
        s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
            .as_str()
            .map(str::to_string);
    assert!(sig_before.is_some(), "the analysis filled in a signature");

    for (f, new_name) in [(&first, "exit_first"), (&second, "exit_second")] {
        let r = s
            .call(
                "rename_symbol",
                json!({"address": f.0, "new_name": new_name}),
            )
            .await;
        assert_eq!(r["status"], "applied", "{r}");
    }
    let d = s.call("decompile", json!({"address": first.0})).await;
    let text = d["text"]["value"].as_str().unwrap_or_default();
    assert!(
        text.contains("exit_first("),
        "the decompiler shows the name: {text}"
    );

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
    let d = s.call("decompile", json!({"address": first.0})).await;
    let text = d["text"]["value"].as_str().unwrap_or_default();
    assert!(
        text.contains("exit_first(int count)"),
        "the decompiler uses the prototype: {text}"
    );

    let del = s
        .call("delete_function", json!({"address": target_hex}))
        .await;
    assert_eq!(del["status"], "proposed", "{del}");
    assert!(
        s.functions()
            .await
            .iter()
            .any(|(a, _, _)| hex(a) == target_addr),
        "proposals do not touch the engine"
    );
    s.close().await;

    // ---- The user accepts the delete.
    let out = user(
        &registry,
        &factory,
        &project,
        "proposal_accept",
        json!({"id": del["proposal_id"]}),
    )
    .await;
    assert_eq!(out["status"], "applied", "{out}");

    // ---- Session 2: the reopened project has every edit; the agent proposes the recreate.
    let s = AgentSession::start(&registry, &factory, &project).await;
    let now = s.functions().await;
    assert!(
        !now.iter().any(|(a, _, _)| hex(a) == target_addr),
        "the function is gone after the accepted delete"
    );
    let names: BTreeMap<u64, String> = now.iter().map(|(a, n, _)| (hex(a), n.clone())).collect();
    assert_eq!(
        names.get(&hex(&first.0)).map(String::as_str),
        Some("exit_first")
    );
    assert_eq!(
        s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
            .as_str()
            .map(str::to_string),
        sig_typed,
        "the prototype survived the reopen"
    );
    let create = s
        .call("create_function", json!({"address": target_hex}))
        .await;
    assert_eq!(create["status"], "proposed", "{create}");
    s.close().await;
    let out = user(
        &registry,
        &factory,
        &project,
        "proposal_accept",
        json!({"id": create["proposal_id"]}),
    )
    .await;
    assert_eq!(out["status"], "applied", "{out}");

    // ---- Session 3: the agent undoes its last edit, then rebuilds from the log.
    let s = AgentSession::start(&registry, &factory, &project).await;
    let after_structure = s.functions().await;
    let back = after_structure
        .iter()
        .find(|(a, _, _)| hex(a) == target_addr)
        .unwrap_or_else(|| panic!("the function exists again: {after_structure:?}"));
    assert_eq!(back.2, target.2, "with the body discovery found");

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
    assert!(
        sig_undone
            .as_deref()
            .is_some_and(|s| s.contains("exit_first") && !s.contains("count")),
        "before={sig_before:?} undone={sig_undone:?}"
    );

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
        if e["op"] == "rename"
            && let Some((_, new)) = desc.rsplit_once("-> ")
            && let Some(a) = desc
                .split_whitespace()
                .find(|w| w.starts_with("0x"))
                .map(hex)
        {
            logged_names.insert(a, new.trim().to_string());
        }
    }
    assert!(applied >= 6, "log has the edits: {history}");
    assert_eq!(
        logged_names.get(&hex(&first.0)).map(String::as_str),
        Some("exit_first"),
        "{history}"
    );
    for (addr, name) in &logged_names {
        assert_eq!(fresh.get(addr), Some(name), "{addr:#x} after rebuild");
    }
    s.close().await;

    // ---- And once more from disk: the rebuilt engine directory replays to the same state.
    let s = AgentSession::start(&registry, &factory, &project).await;
    let reopened: BTreeMap<u64, String> = s
        .functions()
        .await
        .into_iter()
        .map(|(a, n, _)| (hex(&a), n))
        .collect();
    assert_eq!(
        reopened, live,
        "the rebuilt project reopens with the same names"
    );
    assert_eq!(
        s.call("get_function", json!({"address": first.0})).await["signature"]["value"]
            .as_str()
            .map(str::to_string),
        sig_undone
    );
    s.close().await;

    // the engine (in the worker, when it runs there) wrote its state into the engine directory
    let states: Vec<PathBuf> = std::fs::read_dir(&project)
        .expect("project dir")
        .filter_map(Result::ok)
        .map(|d| d.path().join("native-state.json"))
        .filter(|p| p.is_file())
        .collect();
    // (the rebuild keeps the previous engine directory next to the new one)
    assert!(
        !states.is_empty(),
        "no engine directory holds native-state.json"
    );
}

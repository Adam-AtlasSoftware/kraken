//! Contract test: every registry command gives identical output JSON through the CLI code path
//! (`--json`, in process) and through an rmcp client talking to an in-process kraken-mcp server.
//! Both surfaces act as the same agent; author, run ids, timestamps and temp paths are normalised.

mod common;

use std::sync::Arc;

use common::*;
use kraken_cli::CliAuthor;
use kraken_mcp::{KrakenMcp, McpOptions, serve_transport};
use kraken_registry::Registry;
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};

const CLI_RUN: &str = "run-cli-1";
const MCP_RUN: &str = "run-mcp-1";

struct Surfaces {
    cli: Rig,
    cli_dir: String,
    mcp_session: Arc<kraken_registry::Session>,
    mcp_dir: String,
    client: rmcp::service::RunningService<rmcp::RoleClient, ApprovingClient>,
    _work: Workdir,
    binary: String,
}

async fn surfaces() -> Surfaces {
    let work = workdir();
    let cli = rig(
        CliAuthor::Agent {
            id: "bot".into(),
            run_id: CLI_RUN.into(),
        },
        vec![],
    );
    let mcp_factory = Arc::new(FakeFactory {
        fixture: default_named(),
    });
    let mcp_session = Arc::new(kraken_registry::Session::new(mcp_factory));
    let server = KrakenMcp::new(
        Arc::new(Registry::standard()),
        mcp_session.clone(),
        McpOptions {
            agent_id: Some("bot".into()),
            run_id: Some(MCP_RUN.into()),
            ..McpOptions::default()
        },
    );
    let (c, s) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_transport(server, s).await;
    });
    let client = ApprovingClient.serve(c).await.expect("client connects");
    Surfaces {
        cli,
        cli_dir: work
            .tmp
            .path()
            .join("proj-cli")
            .to_string_lossy()
            .into_owned(),
        mcp_session,
        mcp_dir: work
            .tmp
            .path()
            .join("proj-mcp")
            .to_string_lossy()
            .into_owned(),
        binary: work.binary.to_string_lossy().into_owned(),
        _work: work,
        client,
    }
}

fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

/// Calls `tool` over MCP; returns the output JSON, or the ProtoError JSON for `isError`.
async fn mcp_call(s: &Surfaces, tool: &str, args: &Value) -> (bool, Value) {
    let obj = args.as_object().cloned().unwrap_or_default();
    let r: CallToolResult = s
        .client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(obj))
        .await
        .unwrap_or_else(|e| panic!("{tool}: protocol error {e}"));
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    let from_text: Value = serde_json::from_str(&text).expect("content text is JSON");
    if r.is_error == Some(true) {
        assert!(
            r.structured_content.is_none(),
            "{tool}: errors carry text only"
        );
        (false, from_text)
    } else {
        let structured = r.structured_content.expect("structured content");
        assert_eq!(
            structured, from_text,
            "{tool}: text and structured content agree"
        );
        (true, structured)
    }
}

async fn cli_call(s: &Surfaces, tool: &str, args: &Value, extra: &[&str]) -> (bool, Value) {
    let text = args.to_string();
    // The rig runs the CLI as an agent author; a person approves its project_create with --yes.
    let mut argv = vec!["--json", "--yes", "--project", "/nonexistent-never-used"];
    let sub = kebab(tool);
    argv.push(&sub);
    argv.extend_from_slice(extra);
    argv.push("--args-json");
    argv.push(&text);
    let r = kraken(&s.cli.env, &argv).await;
    (r.code == 0, r.json())
}

fn normalise(v: &Value, s: &Surfaces) -> Value {
    // The text is JSON, so a Windows path appears with its backslashes escaped.
    let escaped = |p: &str| {
        let q = Value::String(p.to_string()).to_string();
        q[1..q.len() - 1].to_string()
    };
    let text = v
        .to_string()
        .replace(&escaped(&s.cli_dir), "<dir>")
        .replace(&escaped(&s.mcp_dir), "<dir>")
        .replace(CLI_RUN, "<run>")
        .replace(MCP_RUN, "<run>");
    let mut out: Value = serde_json::from_str(&text).expect("still JSON");
    zero_timestamps(&mut out);
    out
}

fn zero_timestamps(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "ts_ms" || k == "elapsed_ms" {
                    *x = json!(0);
                } else if k == "engine_dir"
                    && x.as_str().is_some_and(|d| d.starts_with("ghidra-rebuild-"))
                {
                    *x = json!("ghidra-rebuild-<ms>");
                } else {
                    zero_timestamps(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(zero_timestamps),
        _ => {}
    }
}

/// Runs one step on both surfaces and asserts the results are identical.
async fn both(s: &Surfaces, tool: &str, args: Value) -> Value {
    let (cli_ok, cli) = cli_call(s, tool, &args, &[]).await;
    let (mcp_ok, mcp) = mcp_call(s, tool, &args).await;
    assert_eq!(
        cli_ok, mcp_ok,
        "{tool}: success differs\ncli: {cli}\nmcp: {mcp}"
    );
    let (cli, mcp) = (normalise(&cli, s), normalise(&mcp, s));
    assert_eq!(cli, mcp, "{tool} {args}: outputs differ");
    cli
}

/// A job command: the CLI waits for the job and prints the final job view, MCP starts the job
/// and awaits it.
async fn both_job(s: &Surfaces, tool: &str) -> Value {
    let (cli_ok, cli) = cli_call(s, tool, &json!({}), &[]).await;
    let (started_ok, started) = mcp_call(s, tool, &json!({})).await;
    assert!(started_ok, "{tool}: {started}");
    let (mcp_ok, mcp) = mcp_call(
        s,
        "job_await",
        &json!({"job_id": started["job_id"], "timeout_ms": 20000}),
    )
    .await;
    assert!(cli_ok && mcp_ok, "{tool}: cli {cli} mcp {mcp}");
    let (cli, mcp) = (normalise(&cli, s), normalise(&mcp, s));
    assert_eq!(cli, mcp, "{tool}: waited job views differ");
    assert_eq!(cli["status"], "succeeded", "{tool}: {cli}");
    cli
}

#[tokio::test(flavor = "multi_thread")]
async fn every_registry_command_is_identical_over_cli_and_mcp() {
    let s = surfaces().await;
    let mut covered = std::collections::BTreeSet::new();
    macro_rules! step {
        ($tool:expr, $args:expr) => {{
            covered.insert($tool.to_string());
            // Boxed: every step inlined in this one future overflows the test thread's stack.
            Box::pin(both(&s, $tool, $args)).await
        }};
    }

    // Project lifecycle: each surface creates its own project directory.
    covered.insert("project_create".to_string());
    let cli_create = cli_call(
        &s,
        "project_create",
        &json!({"binary": s.binary, "project_dir": s.cli_dir}),
        &[],
    )
    .await;
    let mcp_create = mcp_call(
        &s,
        "project_create",
        &json!({"binary": s.binary, "project_dir": s.mcp_dir}),
    )
    .await;
    assert!(
        cli_create.0 && mcp_create.0,
        "{cli_create:?} {mcp_create:?}"
    );
    assert_eq!(normalise(&cli_create.1, &s), normalise(&mcp_create.1, &s));
    assert!(s.mcp_session.project().is_ok());

    step!("project_info", json!({}));
    step!("binary_probe", json!({"path": s.binary}));

    covered.extend(["analyze".to_string(), "job_await".to_string()]);
    let analysis = both_job(&s, "analyze").await;
    assert_eq!(analysis["result"]["function_count"], 3);
    let job_id = analysis["job_id"].clone();
    step!("job_status", json!({"job_id": job_id}));
    step!("job_await", json!({"job_id": job_id, "timeout_ms": 500}));
    step!("job_cancel", json!({"job_id": job_id}));
    step!("job_status", json!({"job_id": "job-99"}));

    // Queries.
    let list = step!("list_functions", json!({}));
    assert_eq!(list["items"].as_array().map(Vec::len), Some(3));
    step!("list_functions", json!({"limit": 1, "name_filter": "fun_"}));
    step!("get_function", json!({"address": "0x401000"}));
    step!("decompile", json!({"address": "0x401040"}));
    step!("decompile", json!({"address": "0x999999"}));

    // Program data.
    let map = step!("memory_map", json!({}));
    assert!(map["blocks"].as_array().is_some_and(|b| !b.is_empty()));
    step!("read_bytes", json!({"address": "0x401000", "length": 16}));
    step!("read_bytes", json!({"address": "0x401000", "length": 0}));
    let listing = step!("disassemble", json!({"function": "0x401000"}));
    assert_eq!(listing["items"].as_array().map(Vec::len), Some(16));
    step!(
        "disassemble",
        json!({"address": "0x401000", "max_instructions": 3})
    );
    step!("disassemble", json!({}));
    let xr = step!("xrefs", json!({"address": "0x401040", "direction": "to"}));
    assert_eq!(xr["items"].as_array().map(Vec::len), Some(1));
    step!("callers", json!({"address": "0x401040"}));
    step!("callees", json!({"address": "0x401000"}));
    step!("cfg", json!({"function": "0x401000"}));
    step!("strings", json!({}));
    step!("imports", json!({}));
    step!("exports", json!({}));

    // Edits as an agent: additive edits apply, overwrites and structural edits become proposals.
    let renamed = step!(
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "entry_main"})
    );
    assert_eq!(renamed["status"], "applied");
    let overwrite = step!(
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "entry_again"})
    );
    assert_eq!(overwrite["status"], "proposed");
    assert!(
        overwrite["proposal"].is_object(),
        "proposal convention: {overwrite}"
    );
    let commented = step!(
        "set_comment",
        json!({"address": "0x401040", "kind": "plate", "text": "helper of main"})
    );
    assert_eq!(commented["status"], "applied", "{commented}");
    let typed = step!(
        "set_type",
        json!({"address": "0x401040", "prototype": {
            "return_type": {"kind": "primitive", "class": "void", "size": 0, "signed": false},
            "params": [], "calling_convention": "__cdecl", "varargs": false, "noreturn": false}})
    );
    assert_eq!(typed["status"], "applied", "{typed}");
    let cc = step!(
        "set_calling_convention",
        json!({"address": "0x401040", "convention": "__cdecl"})
    );
    assert_eq!(cc["status"], "applied", "{cc}");
    let created = step!(
        "create_function",
        json!({"address": "0x401100", "name": "fresh"})
    );
    assert_eq!(created["status"], "proposed");
    step!("delete_function", json!({"address": "0x401080"}));
    step!(
        "set_function_bounds",
        json!({"address": "0x401040", "start": "0x401040", "end": "0x401070"})
    );
    step!("rename_symbol", json!({"address": "0x401040"}));
    step!(
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "x", "bogus": 1})
    );
    // An item without its name is refused on its own; nothing is logged.
    let bulk = step!(
        "apply_edits",
        json!({"edits": [{"op": "rename", "address": "0x401040"}]})
    );
    assert_eq!(bulk["rejected"], 1, "{bulk}");
    let nav = step!(
        "gui_navigate",
        json!({"address": "0x401040", "tab": "listing"})
    );
    assert_eq!(nav["requested"], true, "{nav}");
    let ui = step!("ui_action", json!({"tab": "listing"}));
    assert_eq!(ui["requested"], true, "{ui}");
    let refused = step!("ui_action", json!({"action": "quit"}));
    assert_eq!(refused["code"], "unsupported", "{refused}");
    step!(
        "ui_highlight",
        json!({"target": "history", "note": "look here"})
    );
    let state = step!("ui_state", json!({}));
    assert_eq!(state["attached"], false, "{state}");
    let help = step!("kraken_help", json!({"query": "local models", "limit": 2}));
    assert!(
        help["sections"].as_array().is_some_and(|a| !a.is_empty()),
        "{help}"
    );
    step!("local_model_recommend", json!({}));

    // Search and bookmarks.
    step!("search", json!({"query": "main", "kind": "names"}));
    step!(
        "bookmark_add",
        json!({"address": "0x401040", "note": "look here"})
    );
    step!("bookmark_list", json!({}));
    step!("bookmark_remove", json!({"address": "0x401040"}));

    // AI usage: nothing called a model here, so the ledger is empty on every surface.
    let usage = step!("ai_usage", json!({}));
    assert_eq!(usage["totals"]["calls"], 0, "{usage}");
    step!("ai_usage", json!({"scope": "run", "run_id": "job-1"}));
    let bad = step!("ai_usage", json!({"scope": "run"}));
    assert_eq!(bad["code"], "invalid_argument", "{bad}");
    let jobs = step!("ai_jobs", json!({}));
    assert_eq!(jobs["running"], 0, "{jobs}");

    // Proposals and history.
    step!("proposals_list", json!({"status": "all"}));
    let denied = step!("proposal_accept", json!({"id": 1}));
    assert_eq!(denied["code"], "rejected_human_priority", "{denied}");
    step!("proposal_reject", json!({"id": 1}));
    step!("history", json!({}));
    step!("history", json!({"limit": 2}));
    step!("undo", json!({}));
    let run_cli = json!({"run_id": CLI_RUN});
    let run_mcp = json!({"run_id": MCP_RUN});
    {
        covered.insert("undo_run".to_string());
        let (a_ok, a) = cli_call(&s, "undo_run", &run_cli, &[]).await;
        let (b_ok, b) = mcp_call(&s, "undo_run", &run_mcp).await;
        assert_eq!(a_ok, b_ok);
        assert_eq!(normalise(&a, &s), normalise(&b, &s));
    }
    step!("history", json!({}));
    step!("undo_preview", json!({"entry_id": 2}));
    step!("undo_preview", json!({"entry_id": 999}));
    step!("undo_entry", json!({"entry_id": 2}));
    step!("undo_entry", json!({"entry_id": 999, "cascade": true}));
    step!("tainted_list", json!({}));
    step!("tainted_clear", json!({"address": "0x401040"}));
    step!("history", json!({}));

    covered.insert("rebuild".to_string());
    let rebuilt = both_job(&s, "rebuild").await;
    assert!(rebuilt["result"]["replayed"].is_number(), "{rebuilt}");
    step!("list_functions", json!({}));

    // Byte patches: the overlay alike over both surfaces. Exporting is dangerous and is refused
    // alike without an approver; running is refused alike (no emulator for the fixture).
    step!(
        "patch_set",
        json!({"address": "0x401040", "bytes": "90", "note": "nop"})
    );
    step!("patch_list", json!({}));
    step!(
        "assemble",
        json!({"address": "0x401040", "text": "xor eax, eax"})
    );
    step!(
        "assemble",
        json!({"address": "0x401040", "text": "frobnicate"})
    );
    step!("patch_export", json!({"output_path": "patched.bin"}));
    step!("emulate_run", json!({"patched": true}));
    step!("patch_remove", json!({"address": "0x401040"}));
    step!("patch_remove", json!({"address": "0x401040"}));

    let closed = step!("project_close", json!({}));
    assert_eq!(closed["closed"], true, "{closed}");

    // Reopening the project through both surfaces.
    {
        covered.insert("project_open".to_string());
        let (a_ok, a) = cli_call(&s, "project_open", &json!({"project_dir": s.cli_dir}), &[]).await;
        let (b_ok, b) = mcp_call(&s, "project_open", &json!({"project_dir": s.mcp_dir})).await;
        assert!(a_ok && b_ok, "{a} {b}");
        assert_eq!(normalise(&a, &s), normalise(&b, &s));
    }
    // A directory that does not exist, under the (normalised) work dir so the path is valid
    // and absolute on every platform.
    let missing = std::path::Path::new(&s.cli_dir)
        .join("no-such-project")
        .to_string_lossy()
        .into_owned();
    step!("project_open", json!({"project_dir": missing}));

    // The rewrite pipeline is not attached to these sessions; every surface says so alike. Its
    // behaviour is tested in kraken-rewrite (commands) and tests/rewrite.rs (CLI).
    for (name, args) in [
        ("rewrite_plan", json!({})),
        ("rewrite_status", json!({})),
        ("rewrite_unit", json!({"address": "0x401040"})),
        ("rewrite_function", json!({"address": "0x401040"})),
        ("rewrite_spec", json!({"scope": "all"})),
        ("rewrite_export", json!({"dir": "out"})),
        ("rewrite_build", json!({"dir": "out"})),
        ("rewrite_program", json!({"scope": "all"})),
        ("rewrite_program_status", json!({})),
        (
            "patch_from_source",
            json!({"address": "0x401040", "source": "int f(void) { return 7; }"}),
        ),
        ("local_model_setup", json!({})),
        ("local_model_list", json!({})),
        ("local_model_devices", json!({})),
        ("local_model_status", json!({"model": "m"})),
        ("local_model_start", json!({"model": "m"})),
        ("local_model_hold", json!({"model": "m"})),
        ("local_model_release", json!({"model": "m"})),
        ("local_model_stop", json!({"model": "m"})),
    ] {
        let r = step!(name, args);
        assert_eq!(r["code"], "unsupported", "{name}: {r}");
    }
    let denied = step!("rewrite_accept", json!({"unit": "ru-1"}));
    assert_eq!(denied["code"], "rejected_human_priority", "{denied}");

    let all: Vec<String> = Registry::standard()
        .iter()
        .map(|e| e.spec().name.clone())
        .collect();
    let missing: Vec<&String> = all.iter().filter(|n| !covered.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "commands without a contract step: {missing:?}"
    );

    s.client.cancel().await.expect("client closes");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_wait_prints_the_started_job_like_mcp() {
    let s = surfaces().await;
    let create = json!({"binary": s.binary, "project_dir": s.cli_dir});
    let (ok, _) = cli_call(&s, "project_create", &create, &[]).await;
    assert!(ok);
    let create = json!({"binary": s.binary, "project_dir": s.mcp_dir});
    let (ok, _) = mcp_call(&s, "project_create", &create).await;
    assert!(ok);
    let (cli_ok, cli) = cli_call(&s, "analyze", &json!({}), &["--no-wait"]).await;
    let (mcp_ok, mcp) = mcp_call(&s, "analyze", &json!({})).await;
    assert!(cli_ok && mcp_ok);
    assert_eq!(cli, mcp);
    assert_eq!(cli, json!({"job_id": "job-1", "already_running": false}));
    s.client.cancel().await.expect("client closes");
}

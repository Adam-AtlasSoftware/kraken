//! Contract test for the daemon: every registry command gives identical output JSON through
//!
//! - the CLI in direct mode (an in-process session, the 0.1a path),
//! - the CLI talking to an in-process `krakend` over a real socket in a temporary runtime dir, and
//! - an MCP server routed through that daemon (`kraken mcp --daemon`).
//!
//! The three act as the same agent; run ids, timestamps and temp paths are normalised.

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kraken_cli::{CliAuthor, CliEnv, DaemonMode};
use kraken_host::backend::DaemonBackend;
use kraken_host::daemon::DaemonClient;
use kraken_ipc::{Client, ClientHello, ClientKind, RuntimeDir, SystemClock};
use kraken_mcp::{KrakenMcp, McpOptions, serve_transport};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory as DaemonFakeFactory;
use krakend::{Daemon, DaemonOptions};
use rmcp::ServiceExt;
use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{Value, json};

const RUN_DIRECT: &str = "run-direct";
const RUN_CLI: &str = "run-daemon-cli";
const RUN_MCP: &str = "run-daemon-mcp";

struct Surfaces {
    direct: Rig,
    direct_dir: String,
    daemon_cli: CliEnv,
    cli_dir: String,
    mcp_dir: String,
    mcp: rmcp::service::RunningService<rmcp::RoleClient, ()>,
    daemon: Option<Daemon>,
    binary: String,
    _work: Workdir,
    _rt: tempfile::TempDir,
}

async fn surfaces() -> Surfaces {
    let work = workdir();
    let rt = tempfile::Builder::new()
        .prefix("kraken-cli-d")
        .tempdir()
        .expect("runtime tempdir");
    let dir = RuntimeDir::from_dir(rt.path().join("rt")).expect("runtime dir");
    let daemon = krakend::start(DaemonOptions {
        runtime_dir: dir.clone(),
        factory: Arc::new(DaemonFakeFactory::new(default_named(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: Default::default(),
        session_config: SessionConfig::default(),
        clock: Arc::new(SystemClock::new()),
        poll: Duration::from_millis(20),
        build: "test".into(),
    })
    .expect("daemon starts");
    let connect = || async {
        let c = Client::connect(&dir, &ClientHello::new(ClientKind::Cli, "test"))
            .await
            .expect("connect");
        Arc::new(DaemonClient::from_client(c, "test"))
    };

    let direct = rig(
        CliAuthor::Agent {
            id: "bot".into(),
            run_id: RUN_DIRECT.into(),
        },
        vec![],
    );
    let mut daemon_cli = fresh_env(kraken_host::KrakenConfig::default(), vec![]);
    daemon_cli.author = CliAuthor::Agent {
        id: "bot".into(),
        run_id: RUN_CLI.into(),
    };
    daemon_cli.daemon = DaemonMode::Connected(connect().await);

    // The MCP server connects like the real one: with the agent credential. What it asks to
    // open waits on the daemon's approval list; a stand-in for the person answers yes.
    let agent = {
        let c = Client::connect(&dir, &ClientHello::new(ClientKind::Mcp, "test"))
            .await
            .expect("connect as an agent");
        Arc::new(DaemonClient::from_client(c, "test"))
    };
    let board = daemon.approvals().clone();
    tokio::spawn(async move {
        loop {
            for p in board.pending() {
                board.decide(p.id, true);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
    let mcp_server = KrakenMcp::with_backend(
        Arc::new(Registry::standard()),
        Arc::new(DaemonBackend::new(
            agent,
            Arc::new(Registry::standard()),
            None,
        )),
        McpOptions {
            agent_id: Some("bot".into()),
            run_id: Some(RUN_MCP.into()),
            ..McpOptions::default()
        },
    );
    let (c, s) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = serve_transport(mcp_server, s).await;
    });
    let mcp = ().serve(c).await.expect("mcp client connects");
    let p = |n: &str| work.tmp.path().join(n).to_string_lossy().into_owned();
    Surfaces {
        direct,
        direct_dir: p("proj-direct"),
        daemon_cli,
        cli_dir: p("proj-cli"),
        mcp_dir: p("proj-mcp"),
        mcp,
        daemon: Some(daemon),
        binary: work.binary.to_string_lossy().into_owned(),
        _work: work,
        _rt: rt,
    }
}

fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

async fn cli_call(env: &CliEnv, project: &str, tool: &str, args: &Value) -> (bool, Value) {
    let text = args.to_string();
    let sub = kebab(tool);
    let argv = [
        "--json",
        "--yes",
        "--project",
        project,
        &sub,
        "--args-json",
        &text,
    ];
    let r = kraken(env, &argv).await;
    (r.code == 0, r.json())
}

async fn mcp_call(s: &Surfaces, tool: &str, args: &Value) -> (bool, Value) {
    let obj = args.as_object().cloned().unwrap_or_default();
    let r: CallToolResult = s
        .mcp
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(obj))
        .await
        .unwrap_or_else(|e| panic!("{tool}: protocol error {e}"));
    let text = r
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.clone())
        .expect("text content");
    let v: Value = serde_json::from_str(&text).expect("content text is JSON");
    (r.is_error != Some(true), v)
}

fn normalise(v: &Value, s: &Surfaces) -> Value {
    let text = v
        .to_string()
        .replace(&s.direct_dir, "<dir>")
        .replace(&s.cli_dir, "<dir>")
        .replace(&s.mcp_dir, "<dir>")
        .replace(RUN_DIRECT, "<run>")
        .replace(RUN_CLI, "<run>")
        .replace(RUN_MCP, "<run>");
    let mut out: Value = serde_json::from_str(&text).expect("still JSON");
    zero(&mut out);
    out
}

fn zero(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "ts_ms" {
                    *x = json!(0);
                } else if k == "engine_dir"
                    && x.as_str().is_some_and(|d| d.starts_with("ghidra-rebuild-"))
                {
                    *x = json!("ghidra-rebuild-<ms>");
                } else {
                    zero(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(zero),
        _ => {}
    }
}

/// One step on all three surfaces; asserts the results are identical.
async fn all(s: &Surfaces, tool: &str, args: Value) -> Value {
    let direct = cli_call(&s.direct.env, "/unused", tool, &args).await;
    let via_cli = cli_call(&s.daemon_cli, &s.cli_dir, tool, &args).await;
    let via_mcp = mcp_call(s, tool, &args).await;
    assert_eq!(
        (direct.0, via_cli.0, via_mcp.0),
        (via_cli.0, via_cli.0, via_cli.0),
        "{tool} {args}: success differs\ndirect: {}\ndaemon cli: {}\ndaemon mcp: {}",
        direct.1,
        via_cli.1,
        via_mcp.1
    );
    let (d, c, m) = (
        normalise(&direct.1, s),
        normalise(&via_cli.1, s),
        normalise(&via_mcp.1, s),
    );
    assert_eq!(d, c, "{tool} {args}: direct vs daemon CLI differ");
    assert_eq!(d, m, "{tool} {args}: direct vs daemon MCP differ");
    d
}

/// A job command: both CLIs wait and print the final job view; MCP starts it and awaits it.
async fn all_job(s: &Surfaces, tool: &str) -> Value {
    let direct = cli_call(&s.direct.env, "/unused", tool, &json!({})).await;
    let via_cli = cli_call(&s.daemon_cli, &s.cli_dir, tool, &json!({})).await;
    let (ok, started) = mcp_call(s, tool, &json!({})).await;
    assert!(ok, "{tool}: {started}");
    let via_mcp = mcp_call(
        s,
        "job_await",
        &json!({"job_id": started["job_id"], "timeout_ms": 20000}),
    )
    .await;
    assert!(
        direct.0 && via_cli.0 && via_mcp.0,
        "{tool}: {direct:?} {via_cli:?} {via_mcp:?}"
    );
    let (d, c, m) = (
        normalise(&direct.1, s),
        normalise(&via_cli.1, s),
        normalise(&via_mcp.1, s),
    );
    assert_eq!(d, c, "{tool}: waited job views differ (CLI)");
    assert_eq!(d, m, "{tool}: waited job views differ (MCP)");
    assert_eq!(d["status"], "succeeded", "{tool}: {d}");
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn every_registry_command_is_identical_direct_and_through_the_daemon() {
    let mut s = surfaces().await;
    let mut covered = std::collections::BTreeSet::new();
    macro_rules! step {
        ($tool:expr, $args:expr) => {{
            covered.insert($tool.to_string());
            all(&s, $tool, $args).await
        }};
    }

    // Each surface creates its own project directory.
    covered.insert("project_create".to_string());
    let direct = cli_call(
        &s.direct.env,
        "/unused",
        "project_create",
        &json!({"binary": s.binary, "project_dir": s.direct_dir}),
    )
    .await;
    let via_cli = cli_call(
        &s.daemon_cli,
        &s.cli_dir,
        "project_create",
        &json!({"binary": s.binary, "project_dir": s.cli_dir}),
    )
    .await;
    let via_mcp = mcp_call(
        &s,
        "project_create",
        &json!({"binary": s.binary, "project_dir": s.mcp_dir}),
    )
    .await;
    assert!(
        direct.0 && via_cli.0 && via_mcp.0,
        "{direct:?} {via_cli:?} {via_mcp:?}"
    );
    assert_eq!(normalise(&direct.1, &s), normalise(&via_cli.1, &s));
    assert_eq!(normalise(&direct.1, &s), normalise(&via_mcp.1, &s));

    step!("project_info", json!({}));
    step!("binary_probe", json!({"path": s.binary}));

    covered.extend(["analyze".to_string(), "job_await".to_string()]);
    let analysis = all_job(&s, "analyze").await;
    assert_eq!(analysis["result"]["function_count"], 3);
    let job_id = analysis["job_id"].clone();
    step!("job_status", json!({"job_id": job_id}));
    step!("job_await", json!({"job_id": job_id, "timeout_ms": 500}));
    step!("job_cancel", json!({"job_id": job_id}));
    step!("job_status", json!({"job_id": "job-99"}));

    let list = step!("list_functions", json!({}));
    assert_eq!(list["items"].as_array().map(Vec::len), Some(3));
    step!("list_functions", json!({"limit": 1, "name_filter": "fun_"}));
    step!("get_function", json!({"address": "0x401000"}));
    step!("decompile", json!({"address": "0x401040"}));
    step!("decompile", json!({"address": "0x999999"}));
    step!("memory_map", json!({}));
    step!("read_bytes", json!({"address": "0x401000", "length": 16}));
    step!("read_bytes", json!({"address": "0x401000", "length": 0}));
    step!("disassemble", json!({"function": "0x401000"}));
    step!(
        "disassemble",
        json!({"address": "0x401000", "max_instructions": 3})
    );
    step!("disassemble", json!({}));
    step!("xrefs", json!({"address": "0x401040", "direction": "to"}));
    step!("callers", json!({"address": "0x401040"}));
    step!("callees", json!({"address": "0x401000"}));
    step!("cfg", json!({"function": "0x401000"}));
    step!("strings", json!({}));
    step!("imports", json!({}));
    step!("exports", json!({}));

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
    assert!(overwrite["proposal"].is_object(), "{overwrite}");
    step!(
        "set_comment",
        json!({"address": "0x401040", "kind": "plate", "text": "helper of main"})
    );
    step!(
        "set_type",
        json!({"address": "0x401040", "prototype": {
            "return_type": {"kind": "primitive", "class": "void", "size": 0, "signed": false},
            "params": [], "calling_convention": "__cdecl", "varargs": false, "noreturn": false}})
    );
    step!(
        "set_calling_convention",
        json!({"address": "0x401040", "convention": "__cdecl"})
    );
    step!(
        "create_function",
        json!({"address": "0x401100", "name": "fresh"})
    );
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
    step!(
        "apply_edits",
        json!({"edits": [{"op": "rename", "address": "0x401040"}]})
    );
    step!(
        "gui_navigate",
        json!({"address": "0x401040", "tab": "listing"})
    );
    step!("search", json!({"query": "main", "kind": "names"}));
    step!(
        "bookmark_add",
        json!({"address": "0x401040", "note": "look here"})
    );
    step!("bookmark_list", json!({}));
    step!("bookmark_remove", json!({"address": "0x401040"}));

    step!("proposals_list", json!({"status": "all"}));
    let denied = step!("proposal_accept", json!({"id": 1}));
    assert_eq!(denied["code"], "rejected_human_priority", "{denied}");
    step!("proposal_reject", json!({"id": 1}));
    step!("history", json!({}));
    step!("history", json!({"limit": 2}));
    step!("undo", json!({}));
    {
        covered.insert("undo_run".to_string());
        let a = cli_call(
            &s.direct.env,
            "/unused",
            "undo_run",
            &json!({"run_id": RUN_DIRECT}),
        )
        .await;
        let b = cli_call(
            &s.daemon_cli,
            &s.cli_dir,
            "undo_run",
            &json!({"run_id": RUN_CLI}),
        )
        .await;
        let c = mcp_call(&s, "undo_run", &json!({"run_id": RUN_MCP})).await;
        assert!(a.0 && b.0 && c.0, "{a:?} {b:?} {c:?}");
        assert_eq!(normalise(&a.1, &s), normalise(&b.1, &s));
        assert_eq!(normalise(&a.1, &s), normalise(&c.1, &s));
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
    let rebuilt = all_job(&s, "rebuild").await;
    assert!(rebuilt["result"]["replayed"].is_number(), "{rebuilt}");
    step!("list_functions", json!({}));
    let closed = step!("project_close", json!({}));
    assert_eq!(closed["closed"], true, "{closed}");

    // Reopening: each surface opens its own directory. The one documented difference: in direct
    // mode this really reopens (the session forgets the transient analysis counters), while the
    // daemon, which other clients share, reports an already open project instead of reopening it
    // (a reopen would cancel their jobs and restart the sidecar).
    {
        covered.insert("project_open".to_string());
        let a = cli_call(
            &s.direct.env,
            "/unused",
            "project_open",
            &json!({"project_dir": s.direct_dir}),
        )
        .await;
        let b = cli_call(
            &s.daemon_cli,
            &s.cli_dir,
            "project_open",
            &json!({"project_dir": s.cli_dir}),
        )
        .await;
        let c = mcp_call(&s, "project_open", &json!({"project_dir": s.mcp_dir})).await;
        assert!(a.0 && b.0 && c.0, "{a:?} {b:?} {c:?}");
        let strip = |v: &Value| {
            let mut v = normalise(v, &s);
            if let Some(a) = v["analysis"].as_object_mut() {
                a.remove("function_count");
                a.remove("job_id");
            }
            v
        };
        assert_eq!(strip(&a.1), strip(&b.1));
        assert_eq!(strip(&a.1), strip(&c.1));
    }
    step!(
        "project_open",
        json!({"project_dir": "/nonexistent/kraken-project"})
    );

    // No rewrite pipeline is attached to these daemons or sessions; every surface says so alike.
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
    ] {
        let r = step!(name, args);
        assert_eq!(r["code"], "unsupported", "{name}: {r}");
    }
    let denied = step!("rewrite_accept", json!({"unit": "ru-1"}));
    assert_eq!(denied["code"], "rejected_human_priority", "{denied}");

    let missing: Vec<String> = Registry::standard()
        .iter()
        .map(|e| e.spec().name.clone())
        .filter(|n| !covered.contains(n))
        .collect();
    assert!(
        missing.is_empty(),
        "commands without a contract step: {missing:?}"
    );

    // The daemon really served the CLI and MCP surfaces: two projects, one engine each.
    let status = Client::connect(
        &RuntimeDir::from_dir(s._rt.path().join("rt")).unwrap(),
        &ClientHello::new(ClientKind::Gui, "test"),
    )
    .await
    .map(|c| DaemonClient::from_client(c, "test"))
    .unwrap()
    .status()
    .await
    .unwrap();
    assert_eq!(
        status["sessions"].as_array().map(Vec::len),
        Some(2),
        "{status}"
    );

    s.mcp.cancel().await.expect("client closes");
    let d = s.daemon.take().expect("daemon");
    d.shutdown();
    d.wait().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_wait_prints_the_started_job_in_every_mode() {
    let s = surfaces().await;
    for (env, dir) in [
        (&s.direct.env, "/unused"),
        (&s.daemon_cli, s.cli_dir.as_str()),
    ] {
        let project_dir = if dir == "/unused" {
            &s.direct_dir
        } else {
            &s.cli_dir
        };
        let (ok, _) = cli_call(
            env,
            dir,
            "project_create",
            &json!({"binary": s.binary, "project_dir": project_dir}),
        )
        .await;
        assert!(ok);
        let r = kraken(env, &["--json", "--project", dir, "analyze", "--no-wait"]).await;
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(
            r.json(),
            json!({"job_id": "job-1", "already_running": false})
        );
    }
    s.mcp.cancel().await.expect("client closes");
}

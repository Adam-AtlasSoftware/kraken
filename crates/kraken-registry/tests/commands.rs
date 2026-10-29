mod common;

use common::*;
use kraken_proto::ErrorCode;
use kraken_registry::{CommandKind, Permission, Registry, Session};
use serde_json::json;

const EXPECTED: &[&str] = &[
    "ai_jobs",
    "ai_usage",
    "analyze",
    "apply_edits",
    "assemble",
    "binary_probe",
    "bookmark_add",
    "bookmark_list",
    "bookmark_remove",
    "callees",
    "callers",
    "cfg",
    "create_function",
    "decompile",
    "delete_function",
    "disassemble",
    "emulate_run",
    "emulator_run",
    "exports",
    "get_function",
    "gui_navigate",
    "history",
    "imports",
    "integration_install",
    "integration_remove",
    "integration_use_path",
    "integrations_list",
    "job_await",
    "job_cancel",
    "job_status",
    "kraken_help",
    "list_functions",
    "local_model_devices",
    "local_model_hold",
    "local_model_list",
    "local_model_recommend",
    "local_model_release",
    "local_model_setup",
    "local_model_start",
    "local_model_status",
    "local_model_stop",
    "memory_map",
    "patch_branch",
    "patch_constant",
    "patch_export",
    "patch_fill",
    "patch_from_source",
    "patch_list",
    "patch_nop",
    "patch_remove",
    "patch_return",
    "patch_set",
    "project_close",
    "project_create",
    "project_info",
    "project_open",
    "proposal_accept",
    "proposal_reject",
    "proposals_list",
    "read_bytes",
    "rebuild",
    "rename_symbol",
    "rewrite_accept",
    "rewrite_build",
    "rewrite_export",
    "rewrite_function",
    "rewrite_plan",
    "rewrite_program",
    "rewrite_program_status",
    "rewrite_spec",
    "rewrite_status",
    "rewrite_unit",
    "search",
    "set_calling_convention",
    "set_comment",
    "set_function_bounds",
    "set_type",
    "strings",
    "tainted_clear",
    "tainted_list",
    "type_get",
    "types_list",
    "ui_action",
    "ui_highlight",
    "ui_state",
    "undo",
    "undo_entry",
    "undo_preview",
    "undo_run",
    "xrefs",
];

#[tokio::test]
async fn kraken_help_finds_sections_and_ui_commands_validate() {
    let env = Setup::new(tiny()).start().await;
    let out = env
        .ok(
            &user(),
            "kraken_help",
            json!({"query": "local models", "limit": 3}),
        )
        .await;
    let sections = out["sections"].as_array().unwrap();
    assert!(!sections.is_empty() && sections.len() <= 3, "{out}");
    assert!(
        sections[0]["uri"]
            .as_str()
            .unwrap()
            .starts_with("kraken://")
    );
    assert!(
        out["pages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "assistant")
    );
    let none = env
        .ok(&user(), "kraken_help", json!({"query": "zzqxjv"}))
        .await;
    assert!(none["sections"].as_array().unwrap().is_empty());

    for bad in [
        json!({}),
        json!({"action": "Show History"}),
        json!({"action": "close_project"}),
    ] {
        assert!(env.call(&user(), "ui_action", bad).await.is_err());
    }
    let ok = env
        .ok(&user(), "ui_action", json!({"tab": "listing"}))
        .await;
    assert_eq!(ok["requested"], true);
    let state = env.ok(&user(), "ui_state", json!({})).await;
    assert_eq!(state["attached"], false);
    assert!(
        env.call(
            &user(),
            "ui_highlight",
            json!({"target": "history", "note": " "})
        )
        .await
        .is_err()
    );
}

#[test]
fn standard_registry_is_complete_and_self_describing() {
    let r = Registry::standard();
    let names: Vec<_> = r.iter().map(|e| e.spec().name.as_str()).collect();
    assert_eq!(names, EXPECTED);
    for e in r.iter() {
        let spec = e.spec();
        assert!(
            spec.name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_'),
            "{} is not snake_case",
            spec.name
        );
        assert!(!spec.summary.is_empty(), "{}", spec.name);
        assert_eq!(e.args_schema()["type"], "object", "{}", spec.name);
        assert_eq!(
            e.args_schema()["additionalProperties"],
            false,
            "{} must reject unknown arguments",
            spec.name
        );
        assert!(e.output_schema().is_object(), "{}", spec.name);
        if spec.kind == CommandKind::Mutation {
            assert_ne!(spec.permission, Permission::Safe, "{}", spec.name);
        }
    }
    let rename = r.get("rename_symbol").expect("rename_symbol");
    let props = &rename.args_schema()["properties"];
    for p in ["address", "new_name", "expect_versions"] {
        assert!(props[p].is_object(), "{p}");
        assert!(
            !props[p]["description"].is_null()
                || !props[p]["$ref"].is_null()
                || !props[p]["anyOf"].is_null()
        );
    }
    assert_eq!(props["new_name"]["type"], "string");
    assert_eq!(
        r.get("analyze").expect("analyze").spec().kind,
        CommandKind::Job
    );
}

#[tokio::test]
async fn project_lifecycle_and_epoch() {
    let env = Setup::new(tiny()).start().await;
    for f in ["project.kraken.sqlite", "meta.json", "ghidra"] {
        assert!(env.project_dir.join(f).exists(), "{f}");
    }
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["analysis"]["phase"], "not_started");
    assert_eq!(info["epoch_stale"], false);
    assert_eq!(info["program"]["format"], "elf");
    assert_eq!(info["epoch"]["binary_hash"], info["binary_sha256"]);
    assert!(
        info["capabilities"]
            .as_array()
            .expect("caps")
            .iter()
            .any(|c| c == "mutator")
    );

    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.project_dir.join("meta.json")).expect("meta"),
    )
    .expect("meta json");
    assert_eq!(meta["analysis_complete"], false);
    assert_eq!(
        meta["epoch"]["options_hash"].as_str().map(str::len),
        Some(64)
    );

    // creating again in the same directory is refused
    let e = env
        .err(
            &user(),
            "project_create",
            json!({"binary": env.binary.to_str().unwrap(), "project_dir": env.project_dir.to_str().unwrap()}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(
            &user(),
            "project_create",
            json!({"binary": "/nonexistent/prog", "project_dir": env.tmp.path().join("other").to_str().unwrap()}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    env.ok(
        &user(),
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "mine"}),
    )
    .await;
    env.analyze().await;

    // a new session opens the same project
    let s2 = Session::open(&env.project_dir, env.factory.clone())
        .await
        .expect("open");
    let info = env
        .registry
        .call_json("project_info", &s2, &user(), json!({}))
        .await
        .expect("info");
    assert_eq!(info["log_entries"], 1);
    assert_eq!(info["epoch_stale"], false);
    assert_eq!(info["analysis"]["phase"], "complete");
    let h = env
        .registry
        .call_json("history", &s2, &user(), json!({}))
        .await
        .expect("history");
    assert_eq!(h["items"][0]["op"], "rename");

    // a changed binary makes the engine cache stale
    std::fs::write(&env.binary, b"changed").expect("rewrite");
    let info = env
        .ok(
            &user(),
            "project_open",
            json!({"project_dir": env.project_dir.to_str().unwrap()}),
        )
        .await;
    assert_eq!(info["epoch_stale"], true);
    assert_eq!(info["stale_fields"], json!(["binary_hash"]));
}

#[tokio::test]
async fn commands_need_a_project() {
    let env = Setup::new(tiny()).start().await;
    let bare = Session::new(env.factory.clone());
    let e = env
        .registry
        .call_json("list_functions", &bare, &user(), json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = env
        .registry
        .call_json("no_such_command", &bare, &user(), json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn unknown_and_bad_arguments_are_invalid_argument() {
    let env = Setup::new(tiny()).start().await;
    let e = env
        .err(
            &user(),
            "get_function",
            json!({"address": "0x401000", "extra": 1}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(&user(), "get_function", json!({"address": 4198400}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env.err(&user(), "get_function", json!({})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn queries_page_filter_and_cap_output() {
    let mut fx = tiny();
    // pad the first function's text so it exceeds the 64 KiB cap
    fx.functions[0]
        .decompile
        .text
        .push_str(&"x".repeat(100_000));
    let env = Setup::new(fx).start().await;

    let p1 = env.ok(&user(), "list_functions", json!({"limit": 2})).await;
    assert_eq!(p1["items"].as_array().expect("items").len(), 2);
    assert_eq!(p1["total"], 3);
    assert_eq!(p1["items"][0]["address"], "0x401000");
    assert_eq!(
        p1["items"][0]["name"],
        json!({"untrusted": true, "value": "main"})
    );
    let p2 = env
        .ok(
            &user(),
            "list_functions",
            json!({"limit": 2, "cursor": p1["next_cursor"]}),
        )
        .await;
    assert_eq!(p2["items"].as_array().expect("items").len(), 1);
    assert!(p2["next_cursor"].is_null());

    let f = env
        .ok(&user(), "list_functions", json!({"name_filter": "HELP"}))
        .await;
    assert_eq!(f["items"].as_array().expect("items").len(), 1);
    assert_eq!(f["items"][0]["address"], "0x401040");
    let f = env
        .ok(
            &user(),
            "list_functions",
            json!({"name_filter": "cleanup", "limit": 1}),
        )
        .await;
    assert_eq!(f["items"][0]["address"], "0x401080");

    let e = env
        .err(&user(), "list_functions", json!({"cursor": "garbage"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    let g = env
        .ok(&user(), "get_function", json!({"address": "0x401000"}))
        .await;
    assert_eq!(g["name"]["value"], "main");
    assert_eq!(g["versions"], json!({}));
    let e = env
        .err(&user(), "get_function", json!({"address": "0x999999"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    let d = env
        .ok(&user(), "decompile", json!({"address": "0x401000"}))
        .await;
    assert_eq!(d["truncated"], true);
    assert!(d["text"]["value"].as_str().expect("text").len() <= 64 * 1024);
    assert!(
        d["text"]["value"]
            .as_str()
            .expect("text")
            .starts_with("int main")
    );
    let refs = d["references"].as_array().expect("refs");
    assert!(
        refs.iter()
            .any(|r| r["address"] == "0x401040" && r["name"]["value"] == "helper")
    );
    let d = env
        .ok(&user(), "decompile", json!({"address": "0x401040"}))
        .await;
    assert_eq!(d["truncated"], false);
    assert_eq!(d["language"], "c");
    assert_eq!(d["completeness"]["kind"], "complete");
    let e = env
        .err(&user(), "decompile", json!({"address": "0x999999"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn missing_capability_makes_commands_unsupported() {
    let env = Setup::new(tiny())
        .without(kraken_engine::Cap::Decompiler)
        .start()
        .await;
    let e = env
        .err(&user(), "decompile", json!({"address": "0x401000"}))
        .await;
    assert_eq!(e.code, ErrorCode::Unsupported);
    let entry = env.registry.get("decompile").expect("decompile");
    assert!(!entry.available(&env.session));
    assert!(
        env.registry
            .get("list_functions")
            .expect("list")
            .available(&env.session)
    );
}

#[tokio::test]
async fn every_edit_command_works_for_a_user() {
    let env = Setup::new(tiny()).start().await;
    let u = user();

    let r = env
        .ok(
            &u,
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "do_helper"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    assert_eq!(r["key"], "native:ram:0x401040:name");
    assert_eq!(r["versions"]["native:ram:0x401040:name"], 1);
    assert_eq!(env.engine_name(0x401040).await, "do_helper");

    let r = env
        .ok(
            &u,
            "set_comment",
            json!({"address": "0x401000", "kind": "plate", "text": "entry point"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let g = env
        .ok(&u, "get_function", json!({"address": "0x401000"}))
        .await;
    assert_eq!(
        g["comments"],
        json!([{"kind": "plate", "text": {"untrusted": true, "value": "entry point"}}])
    );
    assert_eq!(g["versions"]["native:ram:0x401000:comment:plate"], 1);
    // an empty text clears it
    env.ok(
        &u,
        "set_comment",
        json!({"address": "0x401000", "kind": "plate", "text": ""}),
    )
    .await;
    let g = env
        .ok(&u, "get_function", json!({"address": "0x401000"}))
        .await;
    assert_eq!(g["comments"], json!([]));

    let proto = json!({
        "return_type": {"kind": "primitive", "class": "int", "size": 4, "signed": true},
        "params": [{"name": "n", "type": {"kind": "primitive", "class": "int", "size": 4, "signed": true}}],
        "calling_convention": "__cdecl", "varargs": false, "noreturn": false
    });
    let r = env
        .ok(
            &u,
            "set_type",
            json!({"address": "0x401040", "prototype": proto}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let r = env
        .ok(
            &u,
            "set_type",
            json!({"address": "0x401040", "type_name": "my_struct"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let e = env
        .err(&u, "set_type", json!({"address": "0x401040"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(
            &u,
            "set_type",
            json!({"address": "0x401040", "type_name": "a", "prototype": proto}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    let r = env
        .ok(
            &u,
            "set_calling_convention",
            json!({"address": "0x401040", "convention": "__fastcall"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let g = env
        .ok(&u, "get_function", json!({"address": "0x401040"}))
        .await;
    assert_eq!(g["calling_convention"], "__fastcall");
    let e = env
        .err(
            &u,
            "set_calling_convention",
            json!({"address": "0x500000", "convention": "__fastcall"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    let r = env
        .ok(
            &u,
            "create_function",
            json!({"address": "0x402000", "name": "fresh"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    assert_eq!(env.engine_name(0x402000).await, "fresh");
    let e = env
        .err(&u, "create_function", json!({"address": "0x402000"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    let r = env
        .ok(
            &u,
            "set_function_bounds",
            json!({"address": "0x402000", "start": "0x402000", "end": "0x402040"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    let e = env
        .err(
            &u,
            "set_function_bounds",
            json!({"address": "0x402000", "start": "0x402040", "end": "0x402000"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let g = env
        .ok(&u, "get_function", json!({"address": "0x402000"}))
        .await;
    assert_eq!(g["size"], 64);

    let r = env
        .ok(&u, "delete_function", json!({"address": "0x402000"}))
        .await;
    assert_eq!(r["status"], "applied");
    let e = env
        .err(&u, "delete_function", json!({"address": "0x402000"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    // the history shows everything, newest first, with paging and a run filter
    let h = env.ok(&u, "history", json!({"limit": 5})).await;
    assert_eq!(h["items"].as_array().expect("items").len(), 5);
    assert_eq!(h["items"][0]["op"], "delete_function");
    assert_eq!(
        h["items"][0]["author"],
        json!({"kind": "user", "id": "adam"})
    );
    assert_eq!(h["items"][0]["sync"], json!({"kind": "pushed"}));
    assert!(h["next_cursor"].is_string());
    let h2 = env
        .ok(
            &u,
            "history",
            json!({"cursor": h["next_cursor"], "limit": 100}),
        )
        .await;
    assert_eq!(
        h["total"].as_u64().expect("total") as usize,
        5 + h2["items"].as_array().expect("items").len()
    );
    let h3 = env.ok(&u, "history", json!({"run_id": "nope"})).await;
    assert_eq!(h3["items"], json!([]));

    let info = env.ok(&u, "project_info", json!({})).await;
    assert_eq!(info["pending_entries"], 0);
    assert_eq!(info["log_entries"], h["total"]);
}

#[tokio::test]
async fn engine_refusal_is_a_structured_error_and_marked_in_the_log() {
    let env = Setup::new(tiny()).start().await;
    // the fake only accepts bounds that start at the entry
    let e = env
        .err(
            &user(),
            "set_function_bounds",
            json!({"address": "0x401000", "start": "0x401008", "end": "0x401040"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::EngineRejected);
    let details = e.details.expect("details");
    assert_eq!(details["engine_code"], "invalid_argument");
    let entry_id = details["entry_id"].as_u64().expect("entry id");
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["items"][0]["id"], entry_id);
    assert_eq!(h["items"][0]["sync"]["kind"], "engine_rejected");
    // nothing is pending afterwards
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["pending_entries"], 0);
}

#[tokio::test]
async fn project_close_releases_the_project_and_is_harmless_twice() {
    let env = Setup::new(tiny()).start().await;
    let out = env.ok(&user(), "project_close", json!({})).await;
    assert_eq!(out["closed"], true);
    assert!(
        out["project_dir"]
            .as_str()
            .is_some_and(|d| d.ends_with("proj"))
    );
    let e = env.err(&user(), "project_info", json!({})).await;
    assert_eq!(e.code, ErrorCode::NotFound);
    let again = env.ok(&user(), "project_close", json!({})).await;
    assert_eq!(again, json!({"closed": false}));
    // The project reopens with what it had.
    let dir = env.project_dir.to_str().unwrap();
    env.ok(&user(), "project_open", json!({"project_dir": dir}))
        .await;
}

#[tokio::test]
async fn binary_probe_needs_no_project_and_keeps_agents_out_of_hidden_folders() {
    let env = Setup::new(tiny()).start().await;
    let fresh = Session::new(env.factory.clone());
    let r = Registry::standard();
    let txt = env.tmp.path().join("notes.txt");
    std::fs::write(&txt, b"hello").unwrap();
    let out = r
        .call_json(
            "binary_probe",
            &fresh,
            &user(),
            json!({"path": txt.to_str().unwrap()}),
        )
        .await
        .expect("probe");
    assert_eq!(out["format"], "unknown");
    assert_eq!(out["supported"], false);
    assert_eq!(out["size"], 5);

    let Some(home) = kraken_registry::trust::home_dir() else {
        return;
    };
    let hidden = home.join(".ssh").join("id_ed25519");
    let e = r
        .call_json(
            "binary_probe",
            &fresh,
            &agent("r1"),
            json!({"path": hidden.to_str().unwrap()}),
        )
        .await
        .expect_err("refused");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(e.message.contains("refused for agents"), "{}", e.message);
}

#[derive(Debug, Default)]
struct MockServing {
    calls: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
}

#[async_trait::async_trait]
impl kraken_registry::commands::ServingBackend for MockServing {
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, kraken_proto::ProtoError> {
        self.calls
            .lock()
            .expect("lock")
            .push((method.to_string(), params));
        let model = json!({
            "id": "qwen", "name": "Qwen", "state": {"kind": "ready"},
            "base_url": "http://127.0.0.1:9/v1", "served_model": "q.gguf",
            "api_key": "run-key-never-shown", "holders": 1, "role_assigned": true,
        });
        Ok(match method {
            "infer_models" => json!({"models": [model], "grace_secs": 120}),
            "infer_model_logs" => {
                json!({"lines": [{"seq": 1, "stream": "stderr", "text": "loaded"}], "last_seq": 1})
            }
            "infer_devices" => json!({"devices": []}),
            "infer_release" => json!({"released": true}),
            "infer_model_stop" => json!({"stopped": true}),
            _ => model,
        })
    }
}

#[tokio::test]
async fn local_model_commands_use_the_serving_service_and_hide_the_key() {
    let mock = std::sync::Arc::new(MockServing::default());
    let env = Setup::new(tiny()).start().await;
    let session = Session::new(env.factory.clone()).with_serving(mock.clone());
    let registry = Registry::standard();
    let ctx = user();
    let call = |name: &'static str, args: serde_json::Value| {
        let (registry, session, ctx) = (&registry, &session, &ctx);
        async move {
            registry
                .call_json(name, session, ctx, args)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e}"))
        }
    };
    let list = call("local_model_list", json!({})).await;
    assert_eq!(list["models"][0]["id"], "qwen");
    assert!(!list.to_string().contains("run-key-never-shown"), "{list}");
    call("local_model_devices", json!({})).await;
    let status = call("local_model_status", json!({"model": "qwen"})).await;
    assert_eq!(status["log_tail"], json!(["loaded"]));
    assert!(!status.to_string().contains("run-key-never-shown"));
    let started = call("local_model_start", json!({"model": "qwen", "cpu": true})).await;
    assert_eq!(started["id"], "qwen");
    assert!(started.get("api_key").is_none(), "{started}");
    call("local_model_hold", json!({"model": "qwen"})).await;
    assert_eq!(
        call("local_model_release", json!({"model": "qwen"})).await["released"],
        true
    );
    assert_eq!(
        call("local_model_stop", json!({"model": "qwen"})).await["stopped"],
        true
    );
    assert!(
        mock.calls
            .lock()
            .expect("lock")
            .iter()
            .any(|(m, p)| m == "infer_model_start" && p["cpu"] == true && p["model"] == "qwen")
    );
    let unknown = registry
        .call_json(
            "local_model_status",
            &session,
            &ctx,
            json!({"model": "nope"}),
        )
        .await
        .expect_err("unknown model");
    assert_eq!(unknown.code, ErrorCode::NotFound);
    let none = Session::new(env.factory.clone());
    let e = registry
        .call_json("local_model_list", &none, &ctx, json!({}))
        .await
        .expect_err("not attached");
    assert_eq!(e.code, ErrorCode::Unsupported);
}

#[test]
fn serving_commands_that_run_or_end_a_program_are_not_read_only() {
    let r = Registry::standard();
    let perm = |name: &str| r.get(name).expect(name).spec().permission;
    for name in [
        "local_model_start",
        "local_model_hold",
        "local_model_release",
        "local_model_stop",
    ] {
        assert_eq!(perm(name), Permission::Mutating, "{name}");
    }
    for name in [
        "local_model_list",
        "local_model_devices",
        "local_model_status",
    ] {
        assert_eq!(perm(name), Permission::Safe, "{name}");
    }
}

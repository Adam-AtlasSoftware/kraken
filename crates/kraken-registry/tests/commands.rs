mod common;

use common::*;
use kraken_proto::ErrorCode;
use kraken_registry::{CommandKind, Permission, Registry, Session};
use serde_json::json;

const EXPECTED: &[&str] = &[
    "analyze",
    "callees",
    "callers",
    "cfg",
    "create_function",
    "decompile",
    "delete_function",
    "disassemble",
    "exports",
    "get_function",
    "history",
    "imports",
    "job_await",
    "job_cancel",
    "job_status",
    "list_functions",
    "memory_map",
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
    "rewrite_export",
    "rewrite_function",
    "rewrite_plan",
    "rewrite_spec",
    "rewrite_status",
    "set_calling_convention",
    "set_comment",
    "set_function_bounds",
    "set_type",
    "strings",
    "tainted_clear",
    "tainted_list",
    "undo",
    "undo_entry",
    "undo_preview",
    "undo_run",
    "xrefs",
];

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

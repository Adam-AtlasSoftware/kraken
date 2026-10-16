mod common;

use common::*;
use engine_fake::Perturb;
use kraken_proto::{ErrorCode, Hex64};
use serde_json::{Value, json};

const TYPE_1000: &str = "native:ram:0x401000:type";
const NAME_1040: &str = "native:ram:0x401040:name";

/// user set_type on 0x401000, then an agent rename of 0x401040 that read that type.
/// Returns (type entry id, agent entry id).
async fn type_and_dependent_rename(env: &Env) -> (u64, u64) {
    let t = env
        .ok(
            &user(),
            "set_type",
            json!({"address": "0x401000", "type_name": "int"}),
        )
        .await;
    assert_eq!(t["status"], "applied", "{t}");
    let v = t["versions"][TYPE_1000].as_u64().expect("type version");
    let a = env
        .ok(
            &agent("run-7"),
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "uses_int",
                   "expect_versions": {TYPE_1000: v, NAME_1040: 0}}),
        )
        .await;
    assert_eq!(a["status"], "applied", "{a}");
    (
        t["entry_id"].as_u64().expect("id"),
        a["entry_id"].as_u64().expect("id"),
    )
}

#[tokio::test]
async fn preview_lists_the_dependents_with_author_command_and_keys() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let (t, a) = type_and_dependent_rename(&env).await;

    let p = env
        .ok(&user(), "undo_preview", json!({"entry_id": t}))
        .await;
    assert_eq!(p["entry"]["id"], t);
    assert_eq!(p["entry"]["op"], "set_type");
    assert_eq!(p["dependents"].as_array().map(Vec::len), Some(1));
    let d = &p["dependents"][0];
    assert_eq!(d["entry"]["id"], a);
    assert_eq!(d["entry"]["op"], "rename");
    assert_eq!(d["entry"]["author"], json!({"kind": "agent", "id": "bot"}));
    assert_eq!(d["entry"]["run_id"], "run-7");
    assert_eq!(d["keys"], json!([TYPE_1000]));
    assert_eq!(p["undo_order"], json!([a, t]));
    assert_eq!(p["stale_functions"], json!(["0x401000", "0x401040"]));

    // the dependent itself has nothing depending on it
    let p = env
        .ok(&user(), "undo_preview", json!({"entry_id": a}))
        .await;
    assert_eq!(p["dependents"], json!([]));
    assert_eq!(p["undo_order"], json!([a]));
    assert_eq!(p["stale_functions"], json!([]));

    // previewing changes nothing
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["total"], 2);
    let e = env
        .err(&user(), "undo_preview", json!({"entry_id": 999}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn undo_without_cascade_is_refused_with_the_dependents_listed() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let (t, a) = type_and_dependent_rename(&env).await;

    let e = env.err(&user(), "undo_entry", json!({"entry_id": t})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let details = e.details.expect("details");
    assert_eq!(details["reason"], "has_dependents");
    assert_eq!(details["entry_id"], t);
    let dep = &details["dependents"][0];
    assert_eq!(dep["entry"]["id"], a);
    assert_eq!(dep["entry"]["author"]["id"], "bot");
    assert_eq!(dep["entry"]["op"], "rename");
    assert_eq!(dep["keys"], json!([TYPE_1000]));
    // nothing changed
    assert_eq!(env.engine_name(0x401040).await, "uses_int");
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["total"], 2);
}

#[tokio::test]
async fn cascade_undoes_dependents_first_and_reports_stale_functions() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let (t, a) = type_and_dependent_rename(&env).await;

    let out = env
        .ok(
            &user(),
            "undo_entry",
            json!({"entry_id": t, "cascade": true}),
        )
        .await;
    assert_eq!(out["status"], "applied", "{out}");
    assert_eq!(out["undone_entry_ids"], json!([a, t]));
    assert_eq!(out["failed"], json!([]));
    assert_eq!(out["tainted"], json!(["0x401000", "0x401040"]));
    assert!(out["drift"].is_null() || out["drift"] == json!([]), "{out}");
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");

    let h = env.ok(&user(), "history", json!({})).await;
    let items = h["items"].as_array().expect("items");
    let by_id = |id: u64| -> &Value { items.iter().find(|i| i["id"] == id).expect("entry") };
    assert!(by_id(t)["undone_by"].is_number());
    assert!(by_id(a)["undone_by"].is_number());
    // the compensating entries are authored by the caller
    let comp = by_id(out["entry_ids"][0].as_u64().expect("id"));
    assert_eq!(comp["author"], json!({"kind": "user", "id": "adam"}));
    assert_eq!(comp["undoes_entry_id"], a);

    // derived data is marked stale until refreshed
    let l = env.ok(&user(), "tainted_list", json!({})).await;
    assert_eq!(l["items"].as_array().map(Vec::len), Some(2));
    assert_eq!(l["items"][0]["address"], "0x401000");
    assert_eq!(l["items"][0]["keys"], json!([TYPE_1000]));
    assert_eq!(l["items"][1]["address"], "0x401040");
    let c = env
        .ok(&user(), "tainted_clear", json!({"address": "0x401000"}))
        .await;
    assert_eq!(c["cleared"], 1);
    let l = env.ok(&user(), "tainted_list", json!({})).await;
    assert_eq!(l["items"].as_array().map(Vec::len), Some(1));

    // a second undo of the same entry is refused
    let e = env
        .err(
            &user(),
            "undo_entry",
            json!({"entry_id": t, "cascade": true}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    // engine and log agree: a rebuild replays everything and finds no drift
    let started = env.ok(&user(), "rebuild", json!({})).await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    assert_eq!(done["result"]["drifted"], json!([]), "{done}");
    assert_eq!(done["result"]["failed"], json!([]));
}

#[tokio::test]
async fn an_older_entry_without_dependents_can_be_undone_alone() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let u = user();
    let first = env
        .ok(
            &u,
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "alpha"}),
        )
        .await;
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "beta"}),
    )
    .await;
    let out = env
        .ok(
            &u,
            "undo_entry",
            json!({"entry_id": first["entry_id"], "cascade": false}),
        )
        .await;
    assert_eq!(out["undone_entry_ids"], json!([first["entry_id"]]));
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");
    assert_eq!(env.engine_name(0x401040).await, "beta");
    // a rename taints nothing
    assert!(out["tainted"].is_null());
    let l = env.ok(&u, "tainted_list", json!({})).await;
    assert_eq!(l["items"], json!([]));
}

#[tokio::test]
async fn a_later_edit_of_the_same_key_is_a_dependent() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let u = user();
    let first = env
        .ok(
            &u,
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "alpha"}),
        )
        .await;
    let second = env
        .ok(
            &u,
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "beta"}),
        )
        .await;
    let e = env
        .err(&u, "undo_entry", json!({"entry_id": first["entry_id"]}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(
        e.details.expect("details")["dependents"][0]["entry"]["id"],
        second["entry_id"]
    );
    env.ok(
        &u,
        "undo_entry",
        json!({"entry_id": first["entry_id"], "cascade": true}),
    )
    .await;
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");
}

#[tokio::test]
async fn agents_can_only_undo_their_own_edits() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let (t, a) = type_and_dependent_rename(&env).await;
    let bot = agent("run-7");

    // the user's type edit is not the agent's to undo
    let e = env.err(&bot, "undo_entry", json!({"entry_id": t})).await;
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    // its own rename is
    let out = env.ok(&bot, "undo_entry", json!({"entry_id": a})).await;
    assert_eq!(out["undone_entry_ids"], json!([a]));
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
}

#[tokio::test]
async fn undo_and_undo_run_still_work_and_report_stale_functions() {
    let env = Setup::new(default_named()).start().await;
    env.analyze().await;
    let u = user();
    env.ok(
        &u,
        "set_type",
        json!({"address": "0x401000", "type_name": "int"}),
    )
    .await;
    let out = env.ok(&u, "undo", json!({})).await;
    assert_eq!(out["status"], "applied");
    assert_eq!(out["tainted"], json!(["0x401000"]));
    let l = env.ok(&u, "tainted_list", json!({})).await;
    assert_eq!(l["items"][0]["address"], "0x401000");

    let a = agent("run-9");
    env.ok(
        &a,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "x"}),
    )
    .await;
    let out = env.ok(&u, "undo_run", json!({"run_id": "run-9"})).await;
    assert_eq!(out["undone_entry_ids"].as_array().map(Vec::len), Some(1));
    assert!(out["tainted"].is_null());
}

#[tokio::test]
async fn cascade_then_rebuild_on_a_perturbed_engine_reports_the_perturbation_only() {
    let base = default_named();
    let perturbed = Perturb {
        base_shift: 0,
        split: vec![Hex64(0x401080)],
        merge: vec![],
    };
    let env = Setup::new(base.clone())
        .per_engine(move |n| {
            if n == 0 {
                base.clone()
            } else {
                perturbed.apply(&base)
            }
        })
        .start()
        .await;
    env.analyze().await;
    let (t, _) = type_and_dependent_rename(&env).await;
    env.ok(
        &user(),
        "undo_entry",
        json!({"entry_id": t, "cascade": true}),
    )
    .await;

    let started = env.ok(&user(), "rebuild", json!({})).await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    let drifted = done["result"]["drifted"].as_array().expect("drifted");
    assert!(
        drifted.iter().any(|d| d["kind"] == "new_after"),
        "the split shows up: {drifted:?}"
    );
    // the undone edits do not come back and the log never disagrees with the rebuilt engine
    assert!(
        drifted.iter().all(|d| d["kind"] != "state_name_mismatch"),
        "{drifted:?}"
    );
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
}

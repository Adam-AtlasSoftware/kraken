//! Byte patches are edit-log entries: they show in the history with their author and run, follow
//! the agent policy and are taken back by undo.

mod common;

use common::*;
use serde_json::{Value, json};

async fn patches(env: &Env) -> Vec<Value> {
    let l = env.ok(&user(), "patch_list", json!({})).await;
    l["items"].as_array().expect("items").clone()
}

#[tokio::test]
async fn an_agents_patch_is_in_the_history_and_its_run_undoes_it() {
    let env = Setup::new(tiny()).start().await;
    let a = agent("run-p");
    let r = env
        .ok(
            &a,
            "patch_set",
            json!({"address": "0x401040", "bytes": "9090", "note": "skip the check"}),
        )
        .await;
    assert_eq!(r["status"], "applied", "{r}");
    let entry = r["entry_id"].as_u64().expect("entry id");
    assert_eq!(r["patch"]["replacement"], "9090");
    assert_eq!(patches(&env).await.len(), 1);

    let h = env.ok(&user(), "history", json!({})).await;
    let e = &h["items"][0];
    assert_eq!(e["id"], entry, "{h}");
    assert_eq!(e["op"], "set_patch");
    assert_eq!(e["author"], json!({"kind": "agent", "id": "bot"}));
    assert_eq!(e["run_id"], "run-p");
    assert!(
        e["description"]["value"]
            .as_str()
            .expect("description")
            .contains("9090"),
        "{e}"
    );

    let undone = env
        .ok(&user(), "undo_run", json!({"run_id": "run-p"}))
        .await;
    assert!(
        !undone["undone_entry_ids"]
            .as_array()
            .expect("ids")
            .is_empty(),
        "{undone}"
    );
    assert!(
        patches(&env).await.is_empty(),
        "undoing the run removes the patch"
    );
}

#[tokio::test]
async fn undoing_a_replacement_or_a_removal_brings_the_earlier_patch_back() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401040", "bytes": "90", "note": "one"}),
    )
    .await;
    let second = env
        .ok(
            &u,
            "patch_set",
            json!({"address": "0x401040", "bytes": "c3c3", "note": "two"}),
        )
        .await;
    assert_eq!(second["status"], "applied");
    env.ok(&u, "undo_entry", json!({"entry_id": second["entry_id"]}))
        .await;
    let p = patches(&env).await;
    assert_eq!(p.len(), 1);
    assert_eq!(
        p[0]["replacement"], "90",
        "the shorter first patch is back: {p:?}"
    );
    assert_eq!(p[0]["note"]["value"], "one");

    let removed = env
        .ok(&u, "patch_remove", json!({"address": "0x401040"}))
        .await;
    assert_eq!(removed["removed"], true, "{removed}");
    assert!(patches(&env).await.is_empty());
    env.ok(&u, "undo", json!({})).await;
    assert_eq!(
        patches(&env).await.len(),
        1,
        "undo puts the removed patch back"
    );

    let none = env
        .ok(&u, "patch_remove", json!({"address": "0x401050"}))
        .await;
    assert_eq!(none["removed"], false);
    assert!(none["entry_id"].is_null(), "removing nothing logs nothing");
}

#[tokio::test]
async fn an_agent_replacing_a_patch_makes_a_proposal() {
    let env = Setup::new(tiny()).start().await;
    env.ok(
        &user(),
        "patch_set",
        json!({"address": "0x401040", "bytes": "90", "note": "mine"}),
    )
    .await;
    let a = agent("run-q");
    let r = env
        .ok(
            &a,
            "patch_set",
            json!({"address": "0x401040", "bytes": "cc"}),
        )
        .await;
    assert_eq!(r["status"], "proposed", "{r}");
    assert_eq!(patches(&env).await[0]["replacement"], "90");
    let r = env
        .ok(&a, "patch_remove", json!({"address": "0x401040"}))
        .await;
    assert_eq!(r["status"], "proposed", "{r}");
    assert_eq!(patches(&env).await.len(), 1);

    let list = env.ok(&user(), "proposals_list", json!({})).await;
    let pid = list["items"][0]["id"].clone();
    env.ok(&user(), "proposal_accept", json!({"id": pid})).await;
    assert_eq!(patches(&env).await[0]["replacement"], "cc");
}

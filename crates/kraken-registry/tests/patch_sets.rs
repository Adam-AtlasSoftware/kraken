//! Patch sets (`patch_group_*`) and the multi-line `patch_asm`: grouping, switching, undo, export
//! of one set, and what an agent may do.

mod common;

use common::*;
use serde_json::{Value, json};

async fn patches(env: &Env) -> Vec<Value> {
    let l = env.ok(&user(), "patch_list", json!({})).await;
    l["items"].as_array().expect("items").clone()
}

async fn two_sets(env: &Env) {
    let u = user();
    env.ok(
        &u,
        "patch_group_set",
        json!({"name": "logging", "description": "turn on debug logging"}),
    )
    .await;
    env.ok(&u, "patch_group_set", json!({"name": "banner"}))
        .await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401040", "bytes": "9090", "group": "logging"}),
    )
    .await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401050", "bytes": "cc", "group": "logging"}),
    )
    .await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401060", "bytes": "c3", "group": "banner"}),
    )
    .await;
}

#[tokio::test]
async fn sets_group_patches_and_switch_together() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    two_sets(&env).await;
    let l = env.ok(&u, "patch_group_list", json!({})).await;
    let groups = l["groups"].as_array().expect("groups");
    assert_eq!(groups.len(), 2, "{l}");
    assert_eq!(groups[1]["name"]["value"], "logging");
    assert_eq!(groups[1]["patches"], 2);
    assert_eq!(groups[1]["state"], "on");
    assert_eq!(l["ungrouped"], 0);

    let off = env
        .ok(
            &u,
            "patch_group_enable",
            json!({"name": "logging", "enabled": false}),
        )
        .await;
    assert_eq!(off["changed"], 2, "{off}");
    assert_eq!(off["group"]["state"], "off");
    let rows = patches(&env).await;
    assert_eq!(rows.iter().filter(|p| p["enabled"] == false).count(), 2);

    // A patch staged into a switched-off set joins it switched off.
    env.ok(&u, "patch_group_set", json!({"name": "logging"}))
        .await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401070", "bytes": "90", "group": "logging"}),
    )
    .await;
    let l = env.ok(&u, "patch_group_list", json!({})).await;
    assert_eq!(l["groups"][1]["state"], "off", "{l}");
    assert_eq!(l["groups"][1]["patches"], 3);

    // Switching is logged per patch, so undo flips one back byte-identically.
    let before = patches(&env).await;
    let on = env
        .ok(
            &u,
            "patch_group_enable",
            json!({"name": "logging", "enabled": true}),
        )
        .await;
    assert_eq!(on["changed"], 3);
    let h = env.ok(&u, "history", json!({"limit": 1})).await;
    let id = h["items"][0]["id"].as_u64().expect("id");
    env.ok(&u, "undo_entry", json!({"entry_id": id})).await;
    let after = patches(&env).await;
    let flipped = after
        .iter()
        .zip(&before)
        .filter(|(a, b)| a["enabled"] != b["enabled"])
        .count();
    assert_eq!(flipped, 2, "one of three went back off");
    for (a, b) in after.iter().zip(&before) {
        assert_eq!(a["replacement"], b["replacement"]);
        assert_eq!(a["original"], b["original"]);
    }
}

#[tokio::test]
async fn assigning_and_removing_sets_follows_the_rules() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    two_sets(&env).await;
    let e = env
        .err(&u, "patch_group_remove", json!({"name": "logging"}))
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
    assert!(e.message.contains("still has 2 patches"), "{}", e.message);

    let moved = env
        .ok(
            &u,
            "patch_group_assign",
            json!({"group": "banner", "addresses": ["0x401040", "0x409999"]}),
        )
        .await;
    assert_eq!(moved["changed"], 1, "{moved}");
    assert_eq!(moved["missing"], json!(["0x409999"]));
    assert_eq!(moved["group"]["patches"], 2);
    let none = env
        .ok(
            &u,
            "patch_group_assign",
            json!({"group": "", "addresses": ["0x401040", "0x401050"]}),
        )
        .await;
    assert_eq!(none["changed"], 2);
    let l = env.ok(&u, "patch_group_list", json!({})).await;
    assert_eq!(l["ungrouped"], 2);

    let e = env
        .err(
            &u,
            "patch_set",
            json!({"address": "0x401080", "bytes": "90", "group": "nope"}),
        )
        .await;
    assert!(e.message.contains("no patch set"), "{}", e.message);

    let removed = env
        .ok(&u, "patch_group_remove", json!({"name": "logging"}))
        .await;
    assert_eq!(removed["removed"], true);
}

#[tokio::test]
async fn an_agent_may_stage_into_a_set_but_moving_and_switching_are_proposals() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let a = agent("run-s");
    two_sets(&env).await;
    let staged = env
        .ok(
            &a,
            "patch_set",
            json!({"address": "0x401090", "bytes": "90", "group": "banner"}),
        )
        .await;
    assert_eq!(staged["status"], "applied", "{staged}");
    let switched = env
        .ok(
            &a,
            "patch_group_enable",
            json!({"name": "logging", "enabled": false}),
        )
        .await;
    assert_eq!(switched["changed"], 0, "{switched}");
    assert_eq!(switched["proposed"], 2);
    assert!(
        patches(&env).await.iter().all(|p| p["enabled"] == true),
        "nothing switched until the person accepts"
    );
    let _ = u;
}

#[tokio::test]
async fn patch_asm_previews_pads_and_records() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let p = env
        .ok(
            &u,
            "patch_asm",
            json!({"address": "0x401040", "text": "xor eax, eax\nret", "preview": true}),
        )
        .await;
    assert_eq!(p["intent"], "asm");
    assert_eq!(p["replacement"], "31c0c3", "{p}");
    assert_eq!(p["preview"], true);
    assert!(patches(&env).await.is_empty(), "a preview records nothing");
    env.ok(
        &u,
        "patch_asm",
        json!({"address": "0x401040", "text": "xor eax, eax; ret", "group": ""}),
    )
    .await;
    let rows = patches(&env).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["replacement"], "31c0c3");
    let e = env
        .err(
            &u,
            "patch_asm",
            json!({"address": "0x401040", "text": "frobnicate"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
}

mod common;

use common::*;
use serde_json::json;

const CSV: &str = "address,name,size,comment\n0x401000,entry_point,0x40,\"starts here, really\"\n0x401040,helper_fn\n0x401080,cleanup\n0x401040,helper_alias\n0x401090,bad name\n";

#[tokio::test]
async fn import_dry_run_changes_nothing_then_undo_run_reverts() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    let dry = env
        .ok(&u, "symbols_import", json!({"text": CSV, "dry_run": true}))
        .await;
    assert_eq!(dry["format"], "csv");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["new"], 4, "{dry}");
    assert_eq!(dry["duplicates"], 1, "{dry}");
    assert!(dry["run_id"].is_null());
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");

    let done = env.ok(&u, "symbols_import", json!({"text": CSV})).await;
    assert_eq!(done["applied"], 4, "{done}");
    let run = done["run_id"].as_str().expect("run id").to_string();
    assert_eq!(env.engine_name(0x401000).await, "entry_point");
    assert_eq!(env.engine_name(0x401040).await, "helper_fn");

    let exp = env.ok(&u, "symbols_export", json!({"format": "csv"})).await;
    let text = exp["text"].as_str().expect("text");
    assert!(text.contains("0x401040,helper_fn"), "{text}");
    assert!(text.contains("\"starts here, really\""), "{text}");

    env.ok(&u, "undo_run", json!({"run_id": run})).await;
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
}

#[tokio::test]
async fn conflicts_follow_the_policy_and_agents_propose() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "mine"}),
    )
    .await;
    let text = "0x401040,theirs\n0x401000,first\n";

    let skip = env.ok(&u, "symbols_import", json!({"text": text})).await;
    assert_eq!(skip["conflicts"], 1, "{skip}");
    assert_eq!(skip["applied"], 1, "{skip}");
    assert_eq!(env.engine_name(0x401040).await, "mine");
    assert_eq!(skip["edits"][0]["status"], "conflict");
    assert_eq!(skip["edits"][0]["existing"], "mine");

    let prop = env
        .ok(
            &u,
            "symbols_import",
            json!({"text": text, "conflicts": "propose"}),
        )
        .await;
    assert_eq!(prop["proposed"], 1, "{prop}");
    assert_eq!(env.engine_name(0x401040).await, "mine");

    let over = env
        .ok(
            &u,
            "symbols_import",
            json!({"text": text, "conflicts": "overwrite"}),
        )
        .await;
    assert_eq!(over["applied"], 1, "{over}");
    assert_eq!(env.engine_name(0x401040).await, "theirs");

    let a = agent("sym-agent");
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401080", "new_name": "keep"}),
    )
    .await;
    let ag = env
        .ok(
            &a,
            "symbols_import",
            json!({"text": "0x401080,other\n", "conflicts": "overwrite"}),
        )
        .await;
    assert_eq!(ag["proposed"], 1, "{ag}");
    assert_eq!(env.engine_name(0x401080).await, "keep");
    let denied = env
        .err(&a, "symbols_import", json!({"path": "/etc/hostname"}))
        .await;
    assert_eq!(
        code(&denied),
        kraken_proto::ErrorCode::RejectedHumanPriority
    );
}

#[tokio::test]
async fn base_offset_and_map_round_trip() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    let map = "Linker script and memory map\n\n                0x0000000000000000                lowfn\n                0x0000000000000040                midfn\n";
    let r = env
        .ok(
            &u,
            "symbols_import",
            json!({"text": map, "base_offset": 0x401000}),
        )
        .await;
    assert_eq!(r["format"], "gnu_map");
    assert_eq!(r["applied"], 2, "{r}");
    assert_eq!(env.engine_name(0x401040).await, "midfn");
    let exp = env
        .ok(
            &u,
            "symbols_export",
            json!({"format": "map", "base_offset": 0x401000}),
        )
        .await;
    let text = exp["text"].as_str().expect("text").to_string();
    assert!(text.contains("lowfn") && text.contains("midfn"), "{text}");
    let back = env
        .ok(
            &u,
            "symbols_import",
            json!({"text": text, "base_offset": 0x401000, "dry_run": true}),
        )
        .await;
    assert_eq!(back["unchanged"], 2, "{back}");
}

#[tokio::test]
async fn input_is_checked() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    let both = env
        .err(&u, "symbols_import", json!({"text": "x", "path": "y"}))
        .await;
    assert_eq!(code(&both), kraken_proto::ErrorCode::InvalidArgument);
    let none = env.err(&u, "symbols_import", json!({})).await;
    assert_eq!(code(&none), kraken_proto::ErrorCode::InvalidArgument);
}

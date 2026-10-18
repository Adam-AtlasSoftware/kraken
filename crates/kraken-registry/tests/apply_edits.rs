mod common;

use common::*;
use kraken_proto::ErrorCode;
use kraken_registry::SessionConfig;
use serde_json::json;

#[tokio::test]
async fn bulk_edits_report_each_item() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("bulk-1");
    let r = env
        .ok(
            &a,
            "apply_edits",
            json!({"edits": [
                {"op": "rename", "address": "0x401040", "name": "alpha"},
                {"op": "comment", "address": "0x401040", "text": "does alpha", "kind": "eol"},
                {"op": "rename", "address": "0x401040", "name": "entry"},
                {"op": "rename", "address": "0x401080"},
                {"op": "rename", "address": "0x401080", "name": "bad name!"},
            ]}),
        )
        .await;
    let res = r["results"].as_array().expect("results");
    assert_eq!(res.len(), 5);
    assert_eq!(res[0]["outcome"], "applied");
    assert_eq!(res[1]["outcome"], "applied");
    // renaming a name set a moment ago overwrites, so it is a proposal
    assert_eq!(res[2]["outcome"], "proposed");
    assert!(res[2]["proposal_id"].is_u64());
    assert_eq!(res[3]["outcome"], "rejected");
    assert_eq!(res[4]["outcome"], "rejected");
    assert_eq!(r["applied"], 2);
    assert_eq!(r["proposed"], 1);
    assert_eq!(r["rejected"], 2);
    assert_eq!(env.engine_name(0x401040).await, "alpha");

    let h = env.ok(&user(), "history", json!({})).await;
    for item in h["items"].as_array().expect("items") {
        assert_eq!(item["run_id"], "bulk-1");
    }
}

#[tokio::test]
async fn bulk_edits_share_the_run_cap() {
    let env = Setup::new(default_named())
        .config(SessionConfig {
            per_run_cap: 1,
            ..SessionConfig::default()
        })
        .start()
        .await;
    let r = env
        .ok(
            &agent("bulk-cap"),
            "apply_edits",
            json!({"edits": [
                {"op": "rename", "address": "0x401000", "name": "one"},
                {"op": "rename", "address": "0x401040", "name": "two"},
            ]}),
        )
        .await;
    assert_eq!(r["results"][0]["outcome"], "applied");
    assert_eq!(r["results"][1]["outcome"], "proposed");
}

#[tokio::test]
async fn bulk_edits_are_capped_and_not_empty() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("bulk-big");
    let many: Vec<_> = (0..201)
        .map(|i| json!({"op": "comment", "address": "0x401000", "text": format!("c{i}")}))
        .collect();
    let e = env.err(&a, "apply_edits", json!({"edits": many})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env.err(&a, "apply_edits", json!({"edits": []})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

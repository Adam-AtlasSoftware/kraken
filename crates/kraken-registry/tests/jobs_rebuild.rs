mod common;

use std::time::Duration;

use common::*;
use kraken_proto::ErrorCode;
use serde_json::json;

#[tokio::test]
async fn analyze_is_a_job_with_progress_and_result() {
    let env = Setup::new(tiny())
        .delay(Duration::from_millis(5))
        .start()
        .await;
    let started = env.ok(&user(), "analyze", json!({})).await;
    assert_eq!(started["already_running"], false);
    let id = started["job_id"].clone();

    // a second analyze joins the running job
    let again = env.ok(&user(), "analyze", json!({})).await;
    assert_eq!(again["job_id"], id);
    assert_eq!(again["already_running"], true);

    let status = env.ok(&user(), "job_status", json!({"job_id": id})).await;
    assert_eq!(status["command"], "analyze");

    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded");
    assert_eq!(done["result"]["function_count"], 3);
    assert_eq!(
        done["result"]["stages_completed"],
        json!(["load", "core", "expensive"])
    );
    assert_eq!(done["progress"]["phase"], "expensive");

    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["analysis"]["phase"], "complete");
    assert_eq!(info["analysis"]["function_count"], 3);
    let meta = std::fs::read_to_string(env.project_dir.join("meta.json")).expect("meta");
    assert!(meta.contains("\"analysis_complete\": true"));

    let e = env
        .err(&user(), "job_status", json!({"job_id": "job-999"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = env
        .err(&user(), "job_status", json!({"job_id": "bogus"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn job_await_times_out_and_job_cancel_ends_the_job() {
    let env = Setup::new(tiny())
        .delay(Duration::from_millis(200))
        .start()
        .await;
    let started = env.ok(&user(), "analyze", json!({})).await;
    let waited = env
        .ok(
            &user(),
            "job_await",
            json!({"job_id": started["job_id"], "timeout_ms": 20}),
        )
        .await;
    assert_eq!(waited["timed_out"], true);
    assert_eq!(waited["status"], "running");
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["analysis"]["phase"], "running");

    env.ok(&user(), "job_cancel", json!({"job_id": started["job_id"]}))
        .await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "cancelled");
    assert_eq!(done["error"]["code"], "cancelled");
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["analysis"]["phase"], "cancelled");

    // analysis can be started again
    let again = env.ok(&user(), "analyze", json!({})).await;
    env.ok(&user(), "job_cancel", json!({"job_id": again["job_id"]}))
        .await;
    env.finish(&again).await;
}

#[tokio::test]
async fn writes_during_analysis_are_queued_and_flushed_afterwards() {
    let env = Setup::new(default_named())
        .delay(Duration::from_millis(40))
        .start()
        .await;
    let started = env.ok(&user(), "analyze", json!({})).await;

    let r = env
        .ok(
            &user(),
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "early"}),
        )
        .await;
    assert_eq!(r["status"], "queued");
    let r2 = env
        .ok(
            &agent("r"),
            "rename_symbol",
            json!({"address": "0x401080", "new_name": "agent_early"}),
        )
        .await;
    assert_eq!(r2["status"], "queued");
    // logged, but the engine has not seen them yet
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["items"][0]["sync"]["kind"], "pending");
    assert_eq!(h["items"][1]["sync"]["kind"], "pending");
    // results are partial while analysis runs
    let f = env.ok(&user(), "list_functions", json!({})).await;
    assert_eq!(f["items"][0]["completeness"]["kind"], "partial");

    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded");
    assert_eq!(done["result"]["flushed_entries"], 2);
    assert_eq!(done["result"]["rejected_entries"], 0);
    assert_eq!(env.engine_name(0x401040).await, "early");
    assert_eq!(env.engine_name(0x401080).await, "agent_early");
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["items"][0]["sync"]["kind"], "pushed");
    assert_eq!(h["items"][1]["sync"]["kind"], "pushed");
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["pending_entries"], 0);
    let f = env.ok(&user(), "list_functions", json!({})).await;
    assert_eq!(f["items"][0]["completeness"]["kind"], "complete");
}

#[tokio::test]
async fn rebuild_replays_the_log_and_reports_no_drift_on_the_fake() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    env.analyze().await;
    env.ok(
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
    env.ok(&u, "undo", json!({})).await;
    env.ok(
        &agent("r"),
        "rename_symbol",
        json!({"address": "0x401080", "new_name": "gamma"}),
    )
    .await;
    env.ok(
        &u,
        "set_comment",
        json!({"address": "0x401000", "kind": "plate", "text": "hi"}),
    )
    .await;
    let before_created = env
        .factory
        .created
        .load(std::sync::atomic::Ordering::SeqCst);

    let started = env.ok(&u, "rebuild", json!({})).await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    let report = &done["result"];
    assert_eq!(report["drifted"], json!([]), "{report}");
    assert_eq!(report["failed"], json!([]));
    // rename, rename, undo (compensation), agent rename, comment
    assert_eq!(report["replayed"], 5);
    assert_eq!(report["functions_before"], 3);
    assert_eq!(report["functions_after"], 3);
    assert_eq!(
        env.factory
            .created
            .load(std::sync::atomic::Ordering::SeqCst),
        before_created + 1
    );

    // the rebuilt engine is the one in use and has the logged state
    assert_eq!(env.engine_name(0x401000).await, "alpha");
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
    assert_eq!(env.engine_name(0x401080).await, "gamma");
    let info = env.ok(&u, "project_info", json!({})).await;
    assert_eq!(info["analysis"]["phase"], "complete");
    assert_eq!(info["pending_entries"], 0);
    let meta: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.project_dir.join("meta.json")).expect("meta"),
    )
    .expect("json");
    assert!(
        meta["engine_dir"]
            .as_str()
            .expect("dir")
            .starts_with("ghidra-rebuild-")
    );
    assert!(
        env.project_dir
            .join(meta["engine_dir"].as_str().expect("dir"))
            .is_dir()
    );

    // edits keep working on the new engine
    let r = env
        .ok(
            &u,
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "after_rebuild"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    assert_eq!(env.engine_name(0x401040).await, "after_rebuild");
}

#[tokio::test]
async fn rebuild_reports_drift_and_replay_failures() {
    let base = default_named();
    let env = Setup::new(base.clone())
        .per_engine(move |n| {
            let mut fx = base.clone();
            if n > 0 {
                // the rebuilt analysis lost the last function
                fx.functions.pop();
            }
            fx
        })
        .start()
        .await;
    let u = user();
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "alpha"}),
    )
    .await;
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401080", "new_name": "omega"}),
    )
    .await;

    let started = env.ok(&u, "rebuild", json!({})).await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    let report = &done["result"];
    assert_eq!(report["replayed"], 1);
    assert_eq!(report["failed"].as_array().expect("failed").len(), 1);
    assert_eq!(report["failed"][0]["code"], "not_found");
    let drifted = report["drifted"].as_array().expect("drifted");
    assert!(
        drifted
            .iter()
            .any(|d| d["kind"] == "missing_after" && d["address"] == "0x401080"),
        "{drifted:?}"
    );
    assert_eq!(report["functions_after"], 2);
}

#[tokio::test]
async fn rebuild_is_refused_while_analysis_runs() {
    let env = Setup::new(tiny())
        .delay(Duration::from_millis(100))
        .start()
        .await;
    let started = env.ok(&user(), "analyze", json!({})).await;
    let e = env.err(&user(), "rebuild", json!({})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    env.ok(&user(), "job_cancel", json!({"job_id": started["job_id"]}))
        .await;
    env.finish(&started).await;
}

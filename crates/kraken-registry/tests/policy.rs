mod common;

use common::*;
use kraken_model::StateValue;
use kraken_proto::ErrorCode;
use kraken_registry::SessionConfig;
use serde_json::json;

const NAME_1000: &str = "native:ram:0x401000:name";
const NAME_1040: &str = "native:ram:0x401040:name";

#[tokio::test]
async fn agent_additive_edit_is_applied() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("run-1");
    let r = env
        .ok(
            &a,
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "parse_args"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
    assert_eq!(env.engine_name(0x401000).await, "parse_args");
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(
        h["items"][0]["author"],
        json!({"kind": "agent", "id": "bot"})
    );
    assert_eq!(h["items"][0]["run_id"], "run-1");
    assert_eq!(h["items"][0]["provenance"], "agent");
    // a new comment is additive too
    let r = env
        .ok(
            &a,
            "set_comment",
            json!({"address": "0x401000", "kind": "eol", "text": "parses argv"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
}

#[tokio::test]
async fn agent_overwrite_becomes_a_proposal_and_accept_applies_it() {
    let env = Setup::new(tiny()).start().await;
    let a = agent("run-1");
    // `main` is not a default name, so renaming it overwrites
    let r = env
        .ok(
            &a,
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "entry"}),
        )
        .await;
    assert_eq!(r["status"], "proposed");
    let pid = r["proposal_id"].as_u64().expect("proposal id");
    assert!(r["reason"].as_str().expect("reason").contains("approval"));
    assert!(r["entry_id"].is_null());
    assert_eq!(env.engine_name(0x401000).await, "main");

    // structural edits are always proposals
    let r = env
        .ok(&a, "delete_function", json!({"address": "0x401080"}))
        .await;
    assert_eq!(r["status"], "proposed");
    let r = env
        .ok(&a, "create_function", json!({"address": "0x402000"}))
        .await;
    assert_eq!(r["status"], "proposed");
    assert_eq!(env.engine_name(0x401080).await, "cleanup");

    let list = env.ok(&user(), "proposals_list", json!({})).await;
    assert_eq!(list["total"], 3);
    assert_eq!(list["items"][0]["id"], pid);
    assert_eq!(list["items"][0]["op"], "rename");
    assert_eq!(list["items"][0]["address"], "0x401000");
    assert_eq!(list["items"][0]["author"]["kind"], "agent");
    assert_eq!(list["items"][0]["status"], "open");
    assert_eq!(list["items"][0]["description"]["untrusted"], true);

    // agents cannot decide on proposals
    let e = env.err(&a, "proposal_accept", json!({"id": pid})).await;
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    let e = env.err(&a, "proposal_reject", json!({"id": pid})).await;
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);

    let r = env.ok(&user(), "proposal_accept", json!({"id": pid})).await;
    assert_eq!(r["status"], "applied");
    assert_eq!(env.engine_name(0x401000).await, "entry");
    let h = env.ok(&user(), "history", json!({"limit": 1})).await;
    // applied as the accepting user, in the proposal's run
    assert_eq!(h["items"][0]["author"]["kind"], "user");
    assert_eq!(h["items"][0]["run_id"], "run-1");

    let e = env
        .err(&user(), "proposal_accept", json!({"id": pid}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(&user(), "proposal_accept", json!({"id": 999}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);

    // reject drops one without touching the engine
    let rest = env.ok(&user(), "proposals_list", json!({})).await;
    assert_eq!(rest["items"].as_array().expect("items").len(), 2);
    let rid = rest["items"][0]["id"].as_u64().expect("id");
    let rej = env.ok(&user(), "proposal_reject", json!({"id": rid})).await;
    assert_eq!(rej["status"], "rejected");
    assert_eq!(env.engine_name(0x401080).await, "cleanup");
    let all = env
        .ok(&user(), "proposals_list", json!({"status": "all"}))
        .await;
    assert_eq!(all["total"], 3);
    let open = env
        .ok(&user(), "proposals_list", json!({"status": "open"}))
        .await;
    assert_eq!(open["total"], 1);
    let info = env.ok(&user(), "project_info", json!({})).await;
    assert_eq!(info["open_proposals"], 1);
}

#[tokio::test]
async fn per_run_cap_turns_further_edits_into_proposals() {
    let env = Setup::new(default_named())
        .config(SessionConfig {
            per_run_cap: 2,
            ..SessionConfig::default()
        })
        .start()
        .await;
    let a = agent("run-cap");
    for (addr, name) in [("0x401000", "alpha"), ("0x401040", "beta")] {
        let r = env
            .ok(
                &a,
                "rename_symbol",
                json!({"address": addr, "new_name": name}),
            )
            .await;
        assert_eq!(r["status"], "applied");
    }
    let r = env
        .ok(
            &a,
            "rename_symbol",
            json!({"address": "0x401080", "new_name": "gamma"}),
        )
        .await;
    assert_eq!(r["status"], "proposed");
    assert!(r["reason"].as_str().expect("reason").contains("limit of 2"));
    assert_eq!(env.engine_name(0x401080).await, "FUN_00401080");
    // another run has its own budget
    let r = env
        .ok(
            &agent("run-other"),
            "rename_symbol",
            json!({"address": "0x401080", "new_name": "gamma"}),
        )
        .await;
    assert_eq!(r["status"], "applied");
}

#[tokio::test]
async fn cap_proposal_accept_applies() {
    let env = Setup::new(default_named())
        .config(SessionConfig {
            per_run_cap: 1,
            ..SessionConfig::default()
        })
        .start()
        .await;
    let a = agent("r");
    env.ok(
        &a,
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "one"}),
    )
    .await;
    let r = env
        .ok(
            &a,
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "two"}),
        )
        .await;
    assert_eq!(r["status"], "proposed");
    let out = env
        .ok(&user(), "proposal_accept", json!({"id": r["proposal_id"]}))
        .await;
    assert_eq!(out["status"], "applied");
    assert_eq!(env.engine_name(0x401040).await, "two");
}

#[tokio::test]
async fn stale_expect_versions_conflict() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "first"}),
    )
    .await;
    // the user read version 0 but the key is at 1 now
    let e = env
        .err(
            &u,
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "second", "expect_versions": {NAME_1040: 0}}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::ConflictStaleRead);
    let stale = &e.details.expect("details")["stale_keys"][0];
    assert_eq!(stale["key"], NAME_1040);
    assert_eq!(stale["expected"], 0);
    assert_eq!(stale["actual"], 1);
    assert_eq!(env.engine_name(0x401040).await, "first");
    // matching versions go through
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "second", "expect_versions": {NAME_1040: 1}}),
    )
    .await;
    assert_eq!(env.engine_name(0x401040).await, "second");

    // an agent holding a wrong version is refused as well, and the attempt is audited
    let e = env
        .err(
            &agent("r"),
            "rename_symbol",
            json!({"address": "0x401000", "new_name": "x", "expect_versions": {NAME_1000: 7}}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::ConflictStaleRead);
    let h = env.ok(&u, "history", json!({"limit": 1})).await;
    assert_eq!(h["items"][0]["status"]["kind"], "rejected");
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");
}

#[tokio::test]
async fn human_edit_beats_a_concurrent_agent_edit() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("run-1");
    // the agent reads the function (nothing written yet) ...
    let g = env
        .ok(&a, "get_function", json!({"address": "0x401040"}))
        .await;
    assert_eq!(g["versions"], json!({}));
    // ... a user renames it meanwhile ...
    env.ok(
        &user(),
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "mine"}),
    )
    .await;
    // ... so the agent's write based on the old read loses
    let e = env
        .err(
            &a,
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "theirs", "expect_versions": {}}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    assert_eq!(env.engine_name(0x401040).await, "mine");
    let h = env.ok(&user(), "history", json!({"limit": 1})).await;
    assert_eq!(h["items"][0]["status"]["kind"], "rejected");
    assert_eq!(h["items"][0]["author"]["kind"], "agent");
    // no proposal was created for it
    let list = env.ok(&user(), "proposals_list", json!({})).await;
    assert_eq!(list["total"], 0);
}

#[tokio::test]
async fn undo_restores_names_in_engine_and_model() {
    let env = Setup::new(default_named()).start().await;
    let u = user();
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "a"}),
    )
    .await;
    env.ok(
        &u,
        "rename_symbol",
        json!({"address": "0x401080", "new_name": "b"}),
    )
    .await;
    assert_eq!(env.engine_name(0x401080).await, "b");

    let r = env.ok(&u, "undo", json!({})).await;
    assert_eq!(r["status"], "applied");
    assert_eq!(r["failed"], json!([]));
    assert_eq!(r["entry_ids"].as_array().expect("ids").len(), 1);
    assert_eq!(r["undone_entry_ids"].as_array().expect("ids").len(), 1);
    assert_eq!(env.engine_name(0x401080).await, "FUN_00401080");
    assert_eq!(env.engine_name(0x401040).await, "a");

    let state = env
        .session
        .project()
        .expect("project")
        .with_store(|st| st.current_state())
        .await
        .expect("state");
    assert_eq!(
        state.get("native:ram:0x401080:name"),
        Some(&StateValue::Name {
            name: "FUN_00401080".into()
        })
    );

    env.ok(&u, "undo", json!({})).await;
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
    let e = env.err(&u, "undo", json!({})).await;
    assert_eq!(e.code, ErrorCode::NotFound);

    let h = env.ok(&u, "history", json!({"limit": 1})).await;
    assert!(h["items"][0]["undoes_entry_id"].is_number());
    let info = env.ok(&u, "project_info", json!({})).await;
    assert_eq!(info["pending_entries"], 0);
}

#[tokio::test]
async fn undo_only_touches_the_callers_own_edits() {
    let env = Setup::new(default_named()).start().await;
    env.ok(
        &user(),
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "mine"}),
    )
    .await;
    let e = env.err(&agent("r"), "undo", json!({})).await;
    assert_eq!(e.code, ErrorCode::NotFound);
    assert_eq!(env.engine_name(0x401040).await, "mine");
}

#[tokio::test]
async fn undo_run_reverts_a_whole_agent_run() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("run-9");
    env.ok(
        &a,
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "x1"}),
    )
    .await;
    env.ok(
        &a,
        "rename_symbol",
        json!({"address": "0x401040", "new_name": "x2"}),
    )
    .await;
    env.ok(
        &a,
        "set_comment",
        json!({"address": "0x401040", "kind": "pre", "text": "hi"}),
    )
    .await;
    // an unrelated run stays
    env.ok(
        &agent("run-other"),
        "rename_symbol",
        json!({"address": "0x401080", "new_name": "keep"}),
    )
    .await;

    let r = env
        .ok(&user(), "undo_run", json!({"run_id": "run-9"}))
        .await;
    assert_eq!(r["status"], "applied");
    assert_eq!(r["entry_ids"].as_array().expect("ids").len(), 3);
    assert_eq!(r["failed"], json!([]));
    assert_eq!(env.engine_name(0x401000).await, "FUN_00401000");
    assert_eq!(env.engine_name(0x401040).await, "FUN_00401040");
    assert_eq!(env.engine_name(0x401080).await, "keep");
    let g = env
        .ok(&user(), "get_function", json!({"address": "0x401040"}))
        .await;
    assert_eq!(g["comments"], json!([]));

    // idempotent: nothing is left to undo, an unknown run is an error
    let again = env
        .ok(&user(), "undo_run", json!({"run_id": "run-9"}))
        .await;
    assert_eq!(again["entry_ids"], json!([]));
    let e = env
        .err(&user(), "undo_run", json!({"run_id": "never"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn invalid_names_are_rejected_before_anything_is_logged() {
    let env = Setup::new(default_named()).start().await;
    let a = agent("r");
    for bad in [
        "has space",
        "1abc",
        "",
        "a+b",
        "\u{1b}[31mred",
        "evil\u{202e}name",
        &"a".repeat(201),
    ] {
        let e = env
            .err(
                &a,
                "rename_symbol",
                json!({"address": "0x401000", "new_name": bad}),
            )
            .await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{bad:?}");
    }
    // users may use characters agents may not, but never control characters or spaces
    env.ok(
        &user(),
        "rename_symbol",
        json!({"address": "0x401000", "new_name": "operator=="}),
    )
    .await;
    let e = env
        .err(
            &user(),
            "rename_symbol",
            json!({"address": "0x401040", "new_name": "a\u{1b}[0m"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(
            &a,
            "set_type",
            json!({"address": "0x401040", "type_name": "bad name"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(
            &a,
            "set_calling_convention",
            json!({"address": "0x401040", "convention": "x y"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let h = env.ok(&user(), "history", json!({})).await;
    assert_eq!(h["total"], 1);
}

#[tokio::test]
async fn comments_are_sanitised_on_the_way_in_and_out() {
    let env = Setup::new(default_named()).start().await;
    env.ok(
        &agent("r"),
        "set_comment",
        json!({"address": "0x401000", "kind": "plate", "text": "ok\u{1b}[31m red\u{202e} bidi"}),
    )
    .await;
    let g = env
        .ok(&user(), "get_function", json!({"address": "0x401000"}))
        .await;
    assert_eq!(g["comments"][0]["text"]["value"], "ok red bidi");
    let long = "x".repeat(5000);
    let e = env
        .err(
            &user(),
            "set_comment",
            json!({"address": "0x401000", "kind": "eol", "text": long}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

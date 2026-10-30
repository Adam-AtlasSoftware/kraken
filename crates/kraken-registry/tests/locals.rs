//! `set_local`: renaming and retyping a local variable is an edit-log entry that follows the
//! agent policy (adding is additive, changing overwrites) and is taken back by undo.

mod common;

use common::*;
use kraken_proto::ErrorCode;
use serde_json::json;

const STORAGE: &str = "stack:0xfffffffffffffff0";

fn args(extra: serde_json::Value) -> serde_json::Value {
    let mut v = json!({"address": "0x401040", "storage": STORAGE});
    if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    v
}

#[tokio::test]
async fn set_local_is_logged_follows_the_policy_and_undoes() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let a = agent("run-l");

    // a name on a variable nobody has named is additive for an agent
    let r = env
        .ok(&a, "set_local", args(json!({"name": "total"})))
        .await;
    assert_eq!(r["status"], "applied", "{r}");
    let h = env.ok(&u, "history", json!({})).await;
    assert_eq!(h["items"][0]["op"], "set_local", "{h}");
    assert_eq!(
        h["items"][0]["author"],
        json!({"kind": "agent", "id": "bot"})
    );

    // changing it is an overwrite: a proposal
    let r = env.ok(&a, "set_local", args(json!({"name": "sum"}))).await;
    assert_eq!(r["status"], "proposed", "{r}");

    // a person may; a type alone keeps the name, and the log records both
    let r = env
        .ok(&u, "set_local", args(json!({"type_name": "my_struct"})))
        .await;
    assert_eq!(r["status"], "applied", "{r}");
    let h = env.ok(&u, "history", json!({})).await;
    assert!(
        h["items"][0]["description"]["value"]
            .as_str()
            .expect("description")
            .contains("total"),
        "{h}"
    );

    // undo takes the type back, undoing the agent's run the name: the agent can name it again
    env.ok(&u, "undo", json!({})).await;
    env.ok(&u, "undo_run", json!({"run_id": "run-l"})).await;
    let r = env
        .ok(&a, "set_local", args(json!({"name": "again"})))
        .await;
    assert_eq!(r["status"], "applied", "{r}");

    // clearing is an overwrite for an agent, free for a person
    let r = env.ok(&a, "set_local", args(json!({"clear": true}))).await;
    assert_eq!(r["status"], "proposed", "{r}");
    let r = env.ok(&u, "set_local", args(json!({"clear": true}))).await;
    assert_eq!(r["status"], "applied", "{r}");
}

#[tokio::test]
async fn set_local_rejects_bad_arguments() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    for (call, why) in [
        (args(json!({})), "nothing to set"),
        (args(json!({"name": "a b"})), "bad name"),
        (
            args(json!({"name": "x", "clear": true})),
            "clear with a name",
        ),
        (
            args(
                json!({"type_name": "a", "data_type": {"kind": "primitive", "class": "int", "size": 4, "signed": true}}),
            ),
            "two types",
        ),
        (
            json!({"address": "0x401040", "storage": "nonsense", "name": "x"}),
            "bad storage",
        ),
        (
            json!({"address": "0x401040", "storage": "const:0x1", "name": "x"}),
            "constant space",
        ),
    ] {
        let e = env.err(&u, "set_local", call).await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{why}: {e:?}");
    }
    let e = env
        .err(
            &u,
            "set_local",
            json!({"address": "0x500000", "storage": STORAGE, "name": "x"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::NotFound);
}

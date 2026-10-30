//! `type_define`, `type_edit_field` and `type_delete` on the fake engine: edits in the log,
//! undo, agent policy and replay into a fresh engine.

mod common;

use common::*;
use serde_json::json;

const PACKET: &str = "struct packet { unsigned short len; char tag; int *data; };";

#[tokio::test]
async fn types_are_defined_edited_deleted_and_undone() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let out = env
        .ok(&u, "type_define", json!({"c_declaration": PACKET}))
        .await;
    assert_eq!(out["types"], json!(["packet"]));
    assert_eq!(out["edits"][0]["status"], "applied");
    let v = env.ok(&u, "type_get", json!({"name": "packet"})).await;
    let c = v["c"]["value"].as_str().unwrap();
    assert!(c.contains("/* +0x8 */"), "{c}");
    assert_eq!(v["size"], 16);

    // rename a field and widen another: the struct is laid out again
    env.ok(
        &u,
        "type_edit_field",
        json!({"type_name": "packet", "field": "len", "new_name": "length", "new_type": "unsigned long"}),
    )
    .await;
    let v = env.ok(&u, "type_get", json!({"name": "packet"})).await;
    assert_eq!(v["definition"]["fields"][0]["name"], "length");
    assert_eq!(v["definition"]["fields"][1]["offset"], 8);
    assert_eq!(v["size"], 24);

    let e = env
        .err(
            &u,
            "type_edit_field",
            json!({"type_name": "packet", "field": "nope", "new_name": "x"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::NotFound);

    // undo the edit, then the definition
    env.ok(&u, "undo", json!({})).await;
    let v = env.ok(&u, "type_get", json!({"name": "packet"})).await;
    assert_eq!(v["definition"]["fields"][0]["name"], "len");
    env.ok(&u, "type_delete", json!({"name": "packet"})).await;
    let e = env.err(&u, "type_get", json!({"name": "packet"})).await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::NotFound);
    env.ok(&u, "undo", json!({})).await;
    env.ok(&u, "type_get", json!({"name": "packet"})).await;

    let hist = env.ok(&u, "history", json!({})).await;
    let text = hist.to_string();
    assert!(
        text.contains("type_define") && text.contains("type_delete"),
        "{text}"
    );
}

#[tokio::test]
async fn parse_errors_name_the_line_and_nothing_is_recorded() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let e = env
        .err(
            &u,
            "type_define",
            json!({"c_declaration": "struct a {\n  int x;\n  nosuch y;\n};"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
    assert!(e.message.contains("line 3"), "{}", e.message);
    // `point` exists in the fixture and gives the size of a by-value member
    env.ok(
        &u,
        "type_define",
        json!({"c_declaration": "struct line2 { struct point a; struct point b; };"}),
    )
    .await;
    let e = env
        .err(
            &u,
            "type_define",
            json!({"c_declaration": "#include <x.h>"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn hostile_declarations_are_refused_without_harm() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let n = 2500;
    let deep = format!(
        "struct t {{ void (*f)({}void{}); }};",
        "void(*)(".repeat(n),
        ")".repeat(n)
    );
    let stars = format!("struct s {{ char {}p; }};", "*".repeat(200));
    let huge = "struct u { char a[4611686018427387904][4]; };".to_string();
    for text in [deep, stars, huge] {
        let e = env
            .err(&u, "type_define", json!({"c_declaration": text}))
            .await;
        assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
    }
    // the daemon is still there and nothing was recorded
    let hist = env.ok(&u, "history", json!({})).await;
    assert!(!hist.to_string().contains("type_define"), "{hist}");
}

#[tokio::test]
async fn agents_add_types_but_changes_wait_for_approval() {
    let env = Setup::new(tiny()).start().await;
    let a = agent("run-1");
    let out = env
        .ok(&a, "type_define", json!({"c_declaration": PACKET}))
        .await;
    assert_eq!(out["edits"][0]["status"], "applied");
    let out = env
        .ok(
            &a,
            "type_define",
            json!({"c_declaration": "struct packet { int only; };"}),
        )
        .await;
    assert_eq!(out["edits"][0]["status"], "proposed", "{out}");
    let del = env.ok(&a, "type_delete", json!({"name": "packet"})).await;
    assert_eq!(del["status"], "proposed");
    let v = env.ok(&user(), "type_get", json!({"name": "packet"})).await;
    assert_eq!(v["size"], 16);
}

#[tokio::test]
async fn defined_types_survive_a_rebuild_of_the_engine() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    env.ok(&u, "type_define", json!({"c_declaration": PACKET}))
        .await;
    env.ok(
        &u,
        "type_define",
        json!({"c_declaration": "enum mode { A, B = 4 };"}),
    )
    .await;
    env.ok(&u, "type_delete", json!({"name": "mode"})).await;
    let started = env.ok(&u, "rebuild", json!({})).await;
    let done = env.finish(&started).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    let v = env.ok(&u, "type_get", json!({"name": "packet"})).await;
    assert_eq!(v["size"], 16);
    let e = env.err(&u, "type_get", json!({"name": "mode"})).await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::NotFound);
}

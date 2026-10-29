//! `types_list` and `type_get` on the fake engine (tiny fixture: point, pt_t, color).

mod common;

use common::*;
use engine_fake::FixtureFile;
use kraken_engine::Cap;
use kraken_proto::{Composite, ErrorCode, Field, TypeDef, TypeRef};
use serde_json::{Value, json};

fn names(v: &Value) -> Vec<String> {
    v["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|t| t["name"]["value"].as_str().expect("name").to_string())
        .collect()
}

#[tokio::test]
async fn types_are_listed_filtered_and_paged() {
    let env = Setup::new(tiny()).start().await;
    let all = env.ok(&user(), "types_list", json!({})).await;
    assert_eq!(names(&all), vec!["color", "point", "pt_t"]);
    let first = &all["items"][1];
    assert_eq!(first["kind"], "struct");
    assert_eq!(first["name"]["untrusted"], true);
    assert!(first["detail"].as_str().unwrap().contains("field"));

    let f = env
        .ok(&user(), "types_list", json!({"name_filter": "PT"}))
        .await;
    assert_eq!(names(&f), vec!["pt_t"]);
    let k = env.ok(&user(), "types_list", json!({"kind": "enum"})).await;
    assert_eq!(names(&k), vec!["color"]);

    // one at a time, following the cursor
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..5 {
        let mut args = json!({"limit": 1});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        let v = env.ok(&user(), "types_list", args).await;
        seen.extend(names(&v));
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(seen, vec!["color", "point", "pt_t"]);

    let e = env
        .err(&user(), "types_list", json!({"kind": "class"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn a_type_is_shown_as_c() {
    let env = Setup::new(tiny()).start().await;
    let v = env.ok(&user(), "type_get", json!({"name": "point"})).await;
    let c = v["c"]["value"].as_str().unwrap();
    assert!(c.starts_with("struct point {"), "{c}");
    assert!(c.contains("/* +0x0 */"), "{c}");
    assert_eq!(v["kind"], "struct");
    assert_eq!(v["definition"]["kind"], "struct");

    let e = env.err(&user(), "type_get", json!({"name": "nope"})).await;
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = env.err(&user(), "type_get", json!({"name": ""})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

fn with_dependent_types() -> FixtureFile {
    let mut fx = tiny();
    let int = |n: &str| TypeRef::Named { name: n.into() };
    let field = |name: &str, off: u64, ty: TypeRef| Field {
        name: name.into(),
        offset: off,
        ty,
        bitfield: None,
    };
    fx.types.push(TypeDef::Struct(Composite {
        name: "line".into(),
        size: 16,
        align: 4,
        fields: vec![
            field("a", 0, int("point")),
            field("b", 8, int("point")),
            field("missing", 16, int("gone_t")),
            field("tint", 20, int("color")),
        ],
    }));
    fx
}

#[tokio::test]
async fn dependencies_come_first_and_unknown_ones_are_reported() {
    let env = Setup::new(with_dependent_types()).start().await;
    let v = env
        .ok(
            &user(),
            "type_get",
            json!({"name": "line", "dependencies": true}),
        )
        .await;
    let c = v["c"]["value"].as_str().unwrap();
    let at = |needle: &str| c.find(needle).unwrap_or_else(|| panic!("{needle} in {c}"));
    assert!(at("struct point {") < at("struct line {"));
    assert!(at("enum color {") < at("struct line {"));
    assert_eq!(c.matches("struct point {").count(), 1, "{c}");
    let undefined: Vec<&str> = v["undefined"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["value"].as_str().unwrap())
        .collect();
    assert_eq!(undefined, vec!["gone_t"]);
    let plain = env.ok(&user(), "type_get", json!({"name": "line"})).await;
    assert!(!plain["c"]["value"].as_str().unwrap().contains("enum color"));
    assert_eq!(plain["references"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn an_engine_without_a_type_store_says_so() {
    let env = Setup::new(tiny()).without(Cap::TypeStore).start().await;
    let e = env.err(&user(), "types_list", json!({})).await;
    assert_eq!(e.code, ErrorCode::Unsupported);
}

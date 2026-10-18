//! `search` (every kind, caps, paging) and the bookmark commands, on the fake engine.

mod common;

use common::*;
use engine_fake::FixtureFile;
use kraken_proto::{ErrorCode, Hex64, Locator, StringEncoding, StringEntry};
use kraken_registry::commands::MAX_SCAN_FUNCTIONS;
use serde_json::{Value, json};

fn items(v: &Value) -> &Vec<Value> {
    v["items"].as_array().expect("items")
}

fn texts(v: &Value) -> Vec<String> {
    items(v)
        .iter()
        .map(|h| h["text"]["value"].as_str().expect("text").to_string())
        .collect()
}

/// Runs a search to the end, following `next_cursor`, and returns every hit.
async fn search_all(env: &Env, query: &str, kind: &str, limit: u32) -> (Vec<Value>, usize) {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let mut args = json!({"query": query, "kind": kind, "limit": limit});
        if let Some(c) = &cursor {
            args["cursor"] = json!(c);
        }
        let v = env.ok(&user(), "search", args).await;
        pages += 1;
        assert!(items(&v).len() <= limit as usize, "page over its limit");
        all.extend(items(&v).iter().cloned());
        match v["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
        assert!(pages < 100, "search never ends");
    }
    (all, pages)
}

#[tokio::test]
async fn names_match_functions_and_exports_and_page() {
    let env = Setup::new(tiny()).start().await;
    let v = env
        .ok(&user(), "search", json!({"query": "HELP", "kind": "names"}))
        .await;
    assert_eq!(texts(&v), vec!["helper"]);
    let hit = &items(&v)[0];
    assert_eq!(hit["kind"], "function");
    assert_eq!(hit["address"], "0x401040");
    assert_eq!(hit["function"], "0x401040");
    assert_eq!(hit["text"]["untrusted"], true);
    assert!(v["next_cursor"].is_null());

    // "main" is a function and (synthesised) the export.
    let (all, pages) = search_all(&env, "main", "names", 1).await;
    let kinds: Vec<&str> = all.iter().map(|h| h["kind"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["function", "export"]);
    assert!(pages >= 2);

    let e = env
        .err(&user(), "search", json!({"query": "  ", "kind": "names"}))
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = env
        .err(
            &user(),
            "search",
            json!({"query": "x", "kind": "names", "cursor": "nonsense"}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn strings_use_the_engine_filter() {
    let mut fx = tiny();
    let s = |a: u64, v: &str| StringEntry {
        address: Hex64(a),
        value: v.into(),
        encoding: StringEncoding::Ascii,
        length: v.len() as u32 + 1,
    };
    fx.strings = Some(vec![
        s(0x402000, "hello world"),
        s(0x402010, "Password: %s"),
        s(0x402020, "bad password"),
        s(0x402030, "other"),
    ]);
    let env = Setup::new(fx).start().await;
    let (all, _) = search_all(&env, "password", "strings", 1).await;
    let addrs: Vec<&str> = all.iter().map(|h| h["address"].as_str().unwrap()).collect();
    assert_eq!(addrs, vec!["0x402010", "0x402020"]);
    assert!(all.iter().all(|h| h["kind"] == "string"));
}

#[tokio::test]
async fn bytes_find_a_pattern_with_wildcards_in_initialized_memory() {
    let env = Setup::new(tiny()).start().await;
    let engine = env.session.engine().expect("engine");
    let b = engine
        .memory_reader()
        .expect("memory")
        .read_bytes(
            &Locator::ram(0x401040),
            4,
            &kraken_engine::CancellationToken::new(),
        )
        .await
        .expect("read")
        .bytes;
    let pattern = format!("{:02x} ?? {:02X}{:02x}", b[0], b[2], b[3]);
    let (all, _) = search_all(&env, &pattern, "bytes", 50).await;
    assert!(
        all.iter().any(|h| h["address"] == "0x401040"),
        "pattern {pattern} not found at 0x401040: {all:?}"
    );
    for h in &all {
        assert_eq!(h["kind"], "bytes");
        let text = h["text"]["value"].as_str().unwrap();
        assert_eq!(text.split(' ').count(), 4, "{text}");
    }

    for bad in ["zz", "?? ??", "123"] {
        let e = env
            .err(&user(), "search", json!({"query": bad, "kind": "bytes"}))
            .await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{bad}");
    }
}

#[tokio::test]
async fn instructions_match_text_name_the_function_and_resume_mid_function() {
    let env = Setup::new(tiny()).start().await;
    let v = env
        .ok(
            &user(),
            "search",
            json!({"query": "call HELPER", "kind": "instructions"}),
        )
        .await;
    let hits = items(&v);
    assert_eq!(hits.len(), 1, "{v}");
    assert_eq!(hits[0]["function"], "0x401000");
    assert_eq!(hits[0]["function_name"]["value"], "main");
    assert_eq!(hits[0]["kind"], "instruction");

    // `mov` appears many times in one function: a small page must resume inside it.
    let (one_by_one, _) = search_all(&env, "mov", "instructions", 3).await;
    let (at_once, pages) = search_all(&env, "mov", "instructions", 200).await;
    assert_eq!(pages, 1);
    assert_eq!(one_by_one, at_once);
    assert!(at_once.len() > 3);
}

/// The tiny fixture plus `n` copies of `cleanup` at new addresses.
fn many_functions(n: usize) -> FixtureFile {
    let mut fx = tiny();
    let template = fx
        .functions
        .iter()
        .find(|f| f.summary.name == "cleanup")
        .expect("cleanup")
        .clone();
    for i in 0..n {
        let mut f = template.clone();
        let loc = Locator::ram(0x500000 + i as u64 * 0x20);
        f.summary.locator = loc.clone();
        f.summary.name = format!("copy_{i}");
        f.decompile.function = loc;
        fx.functions.push(f);
    }
    fx
}

#[tokio::test]
async fn instruction_search_scans_a_bounded_number_of_functions_per_call() {
    let env = Setup::new(many_functions(70)).start().await;
    let v = env
        .ok(
            &user(),
            "search",
            json!({"query": "ret", "kind": "instructions", "limit": 200}),
        )
        .await;
    assert_eq!(items(&v).len(), MAX_SCAN_FUNCTIONS, "one ret per function");
    assert!(v["next_cursor"].is_string());
    let (all, pages) = search_all(&env, "ret", "instructions", 200).await;
    assert_eq!(all.len(), 73);
    assert_eq!(pages, 2);
}

#[tokio::test]
async fn bookmarks_add_replace_list_and_remove() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    let v = env
        .ok(
            &u,
            "bookmark_add",
            json!({"address": "0x401040", "note": "look \u{1b}[31mhere"}),
        )
        .await;
    assert_eq!(v["address"], "0x401040");
    assert_eq!(v["note"]["value"], "look here");
    assert_eq!(v["author_kind"], "user");

    env.ok(&agent("r1"), "bookmark_add", json!({"address": "0x401000"}))
        .await;
    env.ok(
        &u,
        "bookmark_add",
        json!({"address": "0x401040", "note": "the helper"}),
    )
    .await;

    let page = env.ok(&u, "bookmark_list", json!({"limit": 1})).await;
    assert_eq!(page["total"], 2);
    assert_eq!(items(&page)[0]["address"], "0x401000");
    assert_eq!(items(&page)[0]["author_kind"], "agent");
    let rest = env
        .ok(&u, "bookmark_list", json!({"cursor": page["next_cursor"]}))
        .await;
    assert_eq!(items(&rest).len(), 1);
    assert_eq!(items(&rest)[0]["note"]["value"], "the helper");
    assert!(rest["next_cursor"].is_null());

    let r = env
        .ok(&u, "bookmark_remove", json!({"address": "0x401040"}))
        .await;
    assert_eq!(r["removed"], true);
    let r = env
        .ok(&u, "bookmark_remove", json!({"address": "0x401040"}))
        .await;
    assert_eq!(r["removed"], false);

    let e = env
        .err(
            &u,
            "bookmark_add",
            json!({"address": "0x1", "note": "x".repeat(1001)}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument);

    // Bookmarks are not edits: the history stays empty.
    let h = env.ok(&u, "history", json!({})).await;
    assert_eq!(items(&h).len(), 0);
}

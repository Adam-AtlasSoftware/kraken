//! `next_steps` over the recorded fixtures of real corpus programs: what each kind of program is
//! told to do, before and after analysis.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use engine_fake::FixtureFile;
use serde_json::{Value, json};

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

async fn start(fixture: &str, binary: &str) -> Env {
    let fx = FixtureFile::from_path(&corpus(fixture)).expect("fixture");
    let env = Setup::new(fx).start().await;
    std::fs::copy(corpus(binary), &env.binary).expect("copy corpus binary");
    env
}

fn ids(v: &Value) -> Vec<String> {
    v["suggestions"]
        .as_array()
        .expect("suggestions")
        .iter()
        .map(|s| s["id"].as_str().expect("id").to_string())
        .collect()
}

fn find<'a>(v: &'a Value, id: &str) -> &'a Value {
    v["suggestions"]
        .as_array()
        .expect("suggestions")
        .iter()
        .find(|s| s["id"] == id)
        .unwrap_or_else(|| panic!("no {id} in {v}"))
}

#[tokio::test]
async fn a_stripped_program_is_told_to_analyse_then_to_look_for_debug_info() {
    let env = start(
        "fixtures/stripped_calc-O0-stripped.json",
        "bin/stripped_calc-O0-stripped",
    )
    .await;
    let u = user();

    let before = env.ok(&u, "next_steps", json!({})).await;
    assert_eq!(ids(&before)[0], "analyze", "{before}");
    assert_eq!(find(&before, "analyze")["command"], "analyze");
    assert_eq!(before["facts"]["analysed"], false);

    env.analyze().await;
    let after = env.ok(&u, "next_steps", json!({})).await;
    assert!(!ids(&after).contains(&"analyze".to_string()), "{after}");
    assert_eq!(after["facts"]["debug"], "none", "{after}");
    let probe = find(&after, "debug_probe");
    assert_eq!(probe["command"], "debuginfo_probe");
    assert_eq!(probe["args"]["path"], env.binary.to_str().unwrap());
    assert_eq!(probe["runnable"], true);
    let auto = after["facts"]["auto_named"].as_u64().expect("auto_named");
    let total = after["facts"]["function_count"].as_u64().expect("count");
    assert!(total >= auto, "{after}");
    if auto >= 10 && auto * 2 >= total {
        assert_eq!(
            find(&after, "name_functions")["command"],
            "assist_auto_name"
        );
    }
    let limited = env.ok(&u, "next_steps", json!({"limit": 1})).await;
    assert_eq!(limited["suggestions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn a_program_with_debug_info_is_not_sent_to_look_for_it() {
    let env = start("fixtures/stripped_calc-O0.json", "bin/stripped_calc-O0").await;
    let u = user();
    env.analyze().await;
    let out = env.ok(&u, "next_steps", json!({})).await;
    assert_eq!(out["facts"]["debug"], "have", "{out}");
    let got = ids(&out);
    assert!(!got.contains(&"debug_probe".to_string()), "{out}");
    assert!(!got.contains(&"name_functions".to_string()), "{out}");
    assert_eq!(got, ["explore"], "{out}");
    assert_eq!(find(&out, "explore")["command"], "imports");
}

#[tokio::test]
async fn a_windows_dll_without_a_pdb_is_sent_to_the_debug_probe() {
    let env = start(
        "pe/fixtures/win_dll-x64-O0.dll.json",
        "pe/bin/win_dll-x64-O0.dll",
    )
    .await;
    let u = user();
    env.analyze().await;
    let out = env.ok(&u, "next_steps", json!({})).await;
    let probe = find(&out, "debug_probe");
    assert_eq!(probe["command"], "debuginfo_probe", "{out}");
    assert_eq!(out["facts"]["needs_sysroot"], false);
}

#[tokio::test]
async fn patches_without_a_verdict_are_flagged_and_a_function_in_view_is_read() {
    let env = start("fixtures/stripped_calc-O0.json", "bin/stripped_calc-O0").await;
    let u = user();
    env.analyze().await;
    let listed = env.ok(&u, "list_functions", json!({"limit": 1})).await;
    let addr = listed["items"][0]["address"].clone();
    env.ok(&u, "patch_set", json!({"address": addr, "bytes": "90"}))
        .await;
    let out = env.ok(&u, "next_steps", json!({})).await;
    assert_eq!(out["facts"]["patches_on"], 1, "{out}");
    assert_eq!(find(&out, "patch_verify")["command"], "patch_verify");

    let with = env.ok(&u, "next_steps", json!({"function": addr})).await;
    assert!(with["facts"]["current"]["name"].is_string(), "{with}");
}

#[tokio::test]
async fn bad_arguments_are_refused() {
    let env = start("fixtures/stripped_calc-O0.json", "bin/stripped_calc-O0").await;
    let e = env.err(&user(), "next_steps", json!({"bogus": 1})).await;
    assert_eq!(e.code, kraken_proto::ErrorCode::InvalidArgument);
}

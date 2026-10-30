//! The patched view: `disassemble {patched: true}` shows what byte patches do and
//! `decompile_patched` falls back to the plain decompile when nothing is patched.

mod common;

use common::*;
use engine_fake::FixtureFile;
use kraken_proto::{DisasmRow, FlowKind, Hex64, Locator};
use serde_json::json;

fn row(address: u64, bytes: &str, mnemonic: &str, flow: FlowKind) -> DisasmRow {
    DisasmRow {
        address: Hex64(address),
        bytes: bytes.into(),
        mnemonic: mnemonic.into(),
        operands: Vec::new(),
        comment: None,
        labels: Vec::new(),
        flow,
    }
}

fn x86() -> FixtureFile {
    let mut fx = tiny();
    fx.program.arch = "x86:LE:64:default".into();
    let f = fx
        .functions
        .iter_mut()
        .find(|f| matches!(&f.summary.locator, Locator::Native { offset, .. } if offset.0 == 0x401000))
        .expect("function at 0x401000");
    f.disassembly = Some(vec![
        row(0x401000, "83f805", "cmp", FlowKind::Fallthrough),
        row(0x401003, "7510", "jne", FlowKind::ConditionalJump),
        row(0x401005, "b801000000", "mov", FlowKind::Fallthrough),
        row(0x40100a, "0f8410000000", "je", FlowKind::ConditionalJump),
        row(0x401010, "c3", "ret", FlowKind::Return),
    ]);
    fx
}

#[tokio::test]
async fn a_flipped_branch_and_a_nop_show_in_the_patched_listing_only() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    let plain = env
        .ok(&u, "disassemble", json!({"function": "0x401000"}))
        .await;
    // Nothing patched: both views are the same and carry no patch marks.
    let same = env
        .ok(
            &u,
            "disassemble",
            json!({"function": "0x401000", "patched": true}),
        )
        .await;
    assert_eq!(same, plain);

    env.ok(
        &u,
        "patch_branch",
        json!({"address": "0x401003", "mode": "invert", "note": "flip the check"}),
    )
    .await;
    env.ok(
        &u,
        "patch_branch",
        json!({"address": "0x40100a", "mode": "never"}),
    )
    .await;

    let original = env
        .ok(
            &u,
            "disassemble",
            json!({"function": "0x401000", "patched": false}),
        )
        .await;
    assert_eq!(original["items"][1]["mnemonic"], "jne", "{original}");
    assert!(original["items"][1].get("patch").is_none());

    let patched = env
        .ok(
            &u,
            "disassemble",
            json!({"function": "0x401000", "patched": true}),
        )
        .await;
    let items = patched["items"].as_array().expect("items");
    let at = |a: &str| items.iter().find(|i| i["address"] == a).expect(a);
    let flipped = at("0x401003");
    assert_eq!(flipped["mnemonic"], "jz", "{flipped}");
    assert_eq!(flipped["bytes"], "7410");
    assert_eq!(flipped["patch"]["original_bytes"], "7510");
    assert_eq!(flipped["patch"]["note"]["value"], "flip the check");
    assert_eq!(flipped["flow"], "conditional_jump");
    // The 6-byte "never" patch is a NOP the SLEIGH decoder reads back.
    let nop = at("0x40100a");
    assert_eq!(nop["mnemonic"], "nop", "{nop}");
    assert_eq!(nop["patch"]["original_bytes"], "0f8410000000");
    // Untouched instructions are exactly the engine's.
    assert_eq!(at("0x401000"), &original["items"][0]);
    assert_eq!(at("0x401010"), &original["items"][4]);
}

#[tokio::test]
async fn decompile_patched_without_patches_is_the_plain_decompile() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    let plain = env
        .ok(&u, "decompile", json!({"address": "0x401000"}))
        .await;
    let same = env
        .ok(&u, "decompile_patched", json!({"address": "0x401000"}))
        .await;
    assert_eq!(plain["text"], same["text"]);
}

#[tokio::test]
async fn switched_off_patches_are_not_shown_as_patched() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    let plain = env
        .ok(&u, "disassemble", json!({"function": "0x401000"}))
        .await;
    let plain_c = env
        .ok(&u, "decompile", json!({"address": "0x401000"}))
        .await;
    env.ok(&u, "patch_group_set", json!({"name": "flip"})).await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401003", "bytes": "7410", "group": "flip"}),
    )
    .await;
    env.ok(
        &u,
        "patch_group_enable",
        json!({"name": "flip", "enabled": false}),
    )
    .await;
    let patched = env
        .ok(
            &u,
            "disassemble",
            json!({"function": "0x401000", "patched": true}),
        )
        .await;
    assert_eq!(patched, plain);
    let c = env
        .ok(&u, "decompile_patched", json!({"address": "0x401000"}))
        .await;
    assert_eq!(c["text"], plain_c["text"]);
}

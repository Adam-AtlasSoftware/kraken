//! Patch intents (`patch_nop`, `patch_branch`, `patch_return`, `patch_fill`, `patch_constant`)
//! compute their bytes per architecture, record ordinary patches and refuse overlaps.

mod common;

use common::*;
use engine_fake::FixtureFile;
use kraken_proto::{DisasmRow, FlowKind, Hex64, Locator};
use serde_json::{Value, json};

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

/// `tiny` with the listing of its first function replaced by `rows` and the processor `arch`.
fn with_listing(arch: &str, rows: Vec<DisasmRow>) -> FixtureFile {
    let mut fx = tiny();
    fx.program.arch = arch.into();
    let f = fx
        .functions
        .iter_mut()
        .find(|f| matches!(&f.summary.locator, Locator::Native { offset, .. } if offset.0 == 0x401000))
        .expect("function at 0x401000");
    f.disassembly = Some(rows);
    fx
}

fn x86() -> FixtureFile {
    with_listing(
        "x86:LE:64:default",
        vec![
            row(0x401000, "83f805", "cmp", FlowKind::Fallthrough),
            row(0x401003, "7510", "jne", FlowKind::ConditionalJump),
            row(0x401005, "b801000000", "mov", FlowKind::Fallthrough),
            row(0x40100a, "0f8410000000", "je", FlowKind::ConditionalJump),
            row(0x401010, "c3", "ret", FlowKind::Return),
        ],
    )
}

fn aarch64() -> FixtureFile {
    with_listing(
        "AARCH64:LE:64:v8A",
        vec![
            row(0x401000, "1f1400f1", "cmp", FlowKind::Fallthrough),
            row(0x401004, "40000054", "b.eq", FlowKind::ConditionalJump),
            row(0x401008, "20008052", "mov", FlowKind::Fallthrough),
            row(0x40100c, "c0035fd6", "ret", FlowKind::Return),
        ],
    )
}

async fn patches(env: &Env) -> Vec<Value> {
    let l = env.ok(&user(), "patch_list", json!({})).await;
    l["items"].as_array().expect("items").clone()
}

#[tokio::test]
async fn an_x86_branch_is_inverted_forced_or_removed() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    let p = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x401003", "mode": "invert", "preview": true}),
        )
        .await;
    assert_eq!(p["replacement"], "7410");
    assert_eq!(p["original"], "7510");
    assert_eq!(p["preview"], true);
    assert!(patches(&env).await.is_empty(), "a preview records nothing");

    let r = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x401003", "mode": "invert"}),
        )
        .await;
    assert_eq!(r["edit"]["status"], "applied", "{r}");
    assert_eq!(patches(&env).await[0]["replacement"], "7410");

    // always on the near jcc: jmp rel32+1 then a NOP
    let r = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x40100a", "mode": "always"}),
        )
        .await;
    assert_eq!(r["replacement"], "e91100000090", "{r}");
    // never: a 6-byte NOP
    let n = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x40100a", "mode": "never", "preview": true}),
        )
        .await;
    assert_eq!(n["replacement"], "660f1f440000");

    // not a conditional branch: refused with a reason
    let e = env
        .err(
            &u,
            "patch_branch",
            json!({"address": "0x401000", "mode": "invert"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
    assert!(
        e.message.contains("not a conditional branch"),
        "{}",
        e.message
    );
    // no instruction there
    let e = env
        .err(
            &u,
            "patch_branch",
            json!({"address": "0x401001", "mode": "invert"}),
        )
        .await;
    assert!(e.message.contains("no instruction"), "{}", e.message);

    // all of it is undoable
    let h = env.ok(&u, "history", json!({})).await;
    let id = h["items"][0]["id"].as_u64().expect("id");
    env.ok(&u, "undo_entry", json!({"entry_id": id})).await;
    assert_eq!(patches(&env).await.len(), 1);
}

#[tokio::test]
async fn nop_return_fill_and_constant_on_x86() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    let nop = env
        .ok(
            &u,
            "patch_nop",
            json!({"address": "0x401000", "count": 2, "preview": true}),
        )
        .await;
    assert_eq!(nop["original"], "83f8057510");
    assert_eq!(nop["replacement"], "0f1f440000");
    let by_len = env
        .ok(
            &u,
            "patch_nop",
            json!({"address": "0x401000", "length": 5, "preview": true}),
        )
        .await;
    assert_eq!(by_len["replacement"], nop["replacement"]);
    let e = env
        .err(&u, "patch_nop", json!({"address": "0x401000", "length": 4}))
        .await;
    assert!(e.message.contains("inside an instruction"), "{}", e.message);

    let ret = env
        .ok(
            &u,
            "patch_return",
            json!({"address": "0x401000", "value": 1, "preview": true}),
        )
        .await;
    // b8 01000000 c3 is 6 bytes: cmp(3) + jne(2) + mov(5) cover 10, so 4 bytes of NOP follow
    assert_eq!(ret["replacement"], "b801000000c3".to_string() + "0f1f4000");

    let fill = env
        .ok(
            &u,
            "patch_fill",
            json!({"address": "0x401000", "length": 5, "pattern": "cc"}),
        )
        .await;
    assert_eq!(fill["replacement"], "cccccccccc");

    let c = env
        .ok(
            &u,
            "patch_constant",
            json!({"address": "0x401005", "value": 7}),
        )
        .await;
    assert_eq!(c["replacement"], "b807000000");
    // cmp eax, 5 (imm8): 300 does not fit
    let e = env
        .err(
            &u,
            "patch_constant",
            json!({"address": "0x401000", "value": 300}),
        )
        .await;
    assert!(e.message.contains("does not fit"), "{}", e.message);
}

#[tokio::test]
async fn overlapping_patches_are_refused() {
    let env = Setup::new(x86()).start().await;
    let u = user();
    env.ok(
        &u,
        "patch_fill",
        json!({"address": "0x401000", "length": 8, "pattern": "90"}),
    )
    .await;
    let e = env
        .err(
            &u,
            "patch_set",
            json!({"address": "0x401004", "bytes": "9090"}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::InvalidArgument);
    assert!(e.message.contains("overlaps"), "{}", e.message);
    // adjacent is fine, and so is replacing at the same address
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401008", "bytes": "9090"}),
    )
    .await;
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401000", "bytes": "cc"}),
    )
    .await;
    assert_eq!(patches(&env).await.len(), 2);
}

#[tokio::test]
async fn aarch64_intents_are_byte_exact() {
    let env = Setup::new(aarch64()).start().await;
    let u = user();
    let inv = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x401004", "mode": "invert", "preview": true}),
        )
        .await;
    assert_eq!(inv["replacement"], "41000054");
    let always = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x401004", "mode": "always", "preview": true}),
        )
        .await;
    assert_eq!(always["replacement"], "02000014");
    let never = env
        .ok(
            &u,
            "patch_branch",
            json!({"address": "0x401004", "mode": "never", "preview": true}),
        )
        .await;
    assert_eq!(never["replacement"], "1f2003d5");
    let c = env
        .ok(
            &u,
            "patch_constant",
            json!({"address": "0x401008", "value": 9, "preview": true}),
        )
        .await;
    assert_eq!(c["replacement"], "20018052");
    let ret = env
        .ok(
            &u,
            "patch_return",
            json!({"address": "0x401000", "value": 3, "preview": true}),
        )
        .await;
    assert_eq!(ret["replacement"], "600080d2c0035fd6");
    let e = env
        .err(
            &u,
            "patch_branch",
            json!({"address": "0x401008", "mode": "invert"}),
        )
        .await;
    assert!(
        e.message.contains("not a conditional branch"),
        "{}",
        e.message
    );
}

//! `patch_export_diff` and `patch_import`: patches written as files and read back, what an
//! agent may import, and what a foreign file may not do.

mod common;

use common::*;
use kraken_registry::{AutoApprove, CallContext, Surface};
use serde_json::json;
use std::sync::Arc;

fn decode(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64"),
        }
    };
    let mut out = Vec::new();
    for chunk in s.trim_end_matches('=').as_bytes().chunks(4) {
        let mut acc = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            acc |= val(*c) << (18 - 6 * i);
        }
        for i in 0..chunk.len() * 6 / 8 {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    out
}

/// A user who approves dangerous commands.
fn approver() -> CallContext {
    let mut c = CallContext::user("tester", Surface::Test);
    c.approval = Arc::new(AutoApprove);
    c
}

/// Makes the project's binary an ELF whose bytes at 0x401000..0x402000 are the ones the fake
/// engine reports there, so patches set through the engine line up with the file.
async fn real_binary(env: &Env) {
    let r = env
        .ok(
            &user(),
            "read_bytes",
            json!({"address": "0x401000", "length": 4096}),
        )
        .await;
    let mem = decode(r["bytes"].as_str().expect("bytes"));
    assert_eq!(mem.len(), 4096);
    let mut e = vec![0u8; 0x2000];
    e[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    e[4] = 2;
    e[5] = 1;
    e[6] = 1;
    e[16..18].copy_from_slice(&2u16.to_le_bytes());
    e[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    e[20..24].copy_from_slice(&1u32.to_le_bytes());
    e[32..40].copy_from_slice(&0x40u64.to_le_bytes());
    e[52..54].copy_from_slice(&64u16.to_le_bytes());
    e[54..56].copy_from_slice(&56u16.to_le_bytes());
    e[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 0x40;
    e[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    e[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    e[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
    e[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
    e[ph + 32..ph + 40].copy_from_slice(&0x2000u64.to_le_bytes());
    e[ph + 40..ph + 48].copy_from_slice(&0x2000u64.to_le_bytes());
    e[0x1000..0x2000].copy_from_slice(&mem);
    std::fs::write(&env.binary, &e).expect("write binary");
}

async fn three_patches(env: &Env) {
    for (addr, bytes) in [
        ("0x401040", "9090"),
        ("0x401100", "cc"),
        ("0x401200", "b800000000"),
    ] {
        env.ok(
            &user(),
            "patch_set",
            json!({"address": addr, "bytes": bytes, "note": "test"}),
        )
        .await;
    }
}

async fn patch_rows(env: &Env) -> Vec<(String, String)> {
    let l = env.ok(&user(), "patch_list", json!({})).await;
    l["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|p| {
            (
                p["address"].as_str().expect("addr").to_string(),
                p["replacement"].as_str().expect("repl").to_string(),
            )
        })
        .collect()
}

async fn clear_patches(env: &Env) {
    for (a, _) in patch_rows(env).await {
        env.ok(&user(), "patch_remove", json!({"address": a})).await;
    }
}

#[tokio::test]
async fn each_format_exports_and_the_importable_ones_come_back() {
    let env = Setup::new(tiny()).start().await;
    real_binary(&env).await;
    three_patches(&env).await;
    let before = patch_rows(&env).await;
    assert_eq!(before.len(), 3);
    for fmt in ["ips", "ips32", "bps", "json", "1337", "dif"] {
        let path = env.tmp.path().join(format!("out.{fmt}"));
        let r = env
            .ok(
                &approver(),
                "patch_export_diff",
                json!({"output_path": path.to_str().unwrap(), "format": fmt}),
            )
            .await;
        assert_eq!(r["patches"], 3, "{fmt}: {r}");
        assert_eq!(r["format"], fmt);
        assert!(path.exists(), "{fmt}");
        if matches!(fmt, "1337" | "dif") {
            let e = env
                .err(
                    &user(),
                    "patch_import",
                    json!({"path": path.to_str().unwrap(), "format": fmt}),
                )
                .await;
            assert_eq!(code(&e), kraken_proto::ErrorCode::Unsupported, "{fmt}");
            continue;
        }
        clear_patches(&env).await;
        let preview = env
            .ok(
                &user(),
                "patch_import",
                json!({"path": path.to_str().unwrap(), "preview": true}),
            )
            .await;
        assert_eq!(preview["patches"].as_array().expect("p").len(), 3, "{fmt}");
        assert!(patch_rows(&env).await.is_empty(), "preview records nothing");
        let r = env
            .ok(
                &user(),
                "patch_import",
                json!({"path": path.to_str().unwrap()}),
            )
            .await;
        assert_eq!(r["format"], fmt);
        assert_eq!(r["applied"], 3, "{fmt}: {r}");
        assert_eq!(patch_rows(&env).await, before, "{fmt}");
        // One run takes the whole import back.
        let run = r["run_id"].as_str().expect("run").to_string();
        env.ok(&user(), "undo_run", json!({"run_id": run})).await;
        assert!(patch_rows(&env).await.is_empty(), "{fmt}");
        // Restore for the next format.
        three_patches(&env).await;
    }
}

#[tokio::test]
async fn the_format_comes_from_the_extension_and_an_empty_set_is_refused() {
    let env = Setup::new(tiny()).start().await;
    real_binary(&env).await;
    let p = env.tmp.path().join("none.ips");
    let e = env
        .err(
            &approver(),
            "patch_export_diff",
            json!({"output_path": p.to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("no patches"), "{}", e.message);
    three_patches(&env).await;
    let e = env
        .err(
            &approver(),
            "patch_export_diff",
            json!({"output_path": env.tmp.path().join("noext").to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("format"), "{}", e.message);
    let r = env
        .ok(
            &approver(),
            "patch_export_diff",
            json!({"output_path": p.to_str().unwrap()}),
        )
        .await;
    assert_eq!(r["format"], "ips");
    let bytes = std::fs::read(&p).expect("file");
    assert!(bytes.starts_with(b"PATCH") && bytes.ends_with(b"EOF"));
    // Exporting asks first.
    let e = env
        .err(
            &user(),
            "patch_export_diff",
            json!({"output_path": p.to_str().unwrap(), "overwrite": true}),
        )
        .await;
    assert!(e.message.contains("approval"), "{}", e.message);
}

#[tokio::test]
async fn an_agent_import_waits_as_proposals_and_accepting_stages_the_patch() {
    let env = Setup::new(tiny()).start().await;
    real_binary(&env).await;
    three_patches(&env).await;
    let p = env.tmp.path().join("fix.json");
    env.ok(
        &approver(),
        "patch_export_diff",
        json!({"output_path": p.to_str().unwrap()}),
    )
    .await;
    clear_patches(&env).await;

    let a = agent("run-import");
    let r = env
        .ok(&a, "patch_import", json!({"path": p.to_str().unwrap()}))
        .await;
    assert_eq!(r["proposed"], 3, "{r}");
    assert_eq!(r["applied"], 0, "{r}");
    assert!(patch_rows(&env).await.is_empty(), "nothing staged yet");
    let list = env.ok(&user(), "proposals_list", json!({})).await;
    assert_eq!(list["items"].as_array().expect("items").len(), 3, "{list}");
    let id = r["patches"][0]["proposal_id"]
        .as_u64()
        .expect("proposal id");
    env.ok(&user(), "proposal_accept", json!({"id": id})).await;
    assert_eq!(patch_rows(&env).await.len(), 1);
}

#[tokio::test]
async fn files_made_for_another_binary_or_too_big_are_refused_and_stage_nothing() {
    let env = Setup::new(tiny()).start().await;
    real_binary(&env).await;
    three_patches(&env).await;
    let bps = env.tmp.path().join("a.bps");
    let json_file = env.tmp.path().join("a.json");
    for p in [&bps, &json_file] {
        env.ok(
            &approver(),
            "patch_export_diff",
            json!({"output_path": p.to_str().unwrap()}),
        )
        .await;
    }
    clear_patches(&env).await;
    // The binary changes under the patch files.
    let mut b = std::fs::read(&env.binary).expect("binary");
    b[0x1800] ^= 0xff;
    std::fs::write(&env.binary, &b).expect("write");
    for p in [&bps, &json_file] {
        let e = env
            .err(
                &user(),
                "patch_import",
                json!({"path": p.to_str().unwrap()}),
            )
            .await;
        assert!(e.message.contains("different file"), "{}", e.message);
    }
    assert!(patch_rows(&env).await.is_empty());

    // An IPS record outside the file, an IPS that grows it, and junk.
    let hostile = env.tmp.path().join("h.ips");
    let mut ips = b"PATCH".to_vec();
    ips.extend_from_slice(&[0x00, 0x1f, 0xff, 0, 4, 1, 2, 3, 4]);
    ips.extend_from_slice(b"EOF");
    std::fs::write(&hostile, &ips).expect("write");
    let e = env
        .err(
            &user(),
            "patch_import",
            json!({"path": hostile.to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("outside"), "{}", e.message);
    std::fs::write(&hostile, b"hello, not a patch").expect("write");
    let e = env
        .err(
            &user(),
            "patch_import",
            json!({"path": hostile.to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("not an IPS"), "{}", e.message);
    let big = vec![0u8; (16 << 20) + 1];
    std::fs::write(&hostile, &big).expect("write");
    let e = env
        .err(
            &user(),
            "patch_import",
            json!({"path": hostile.to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("at most"), "{}", e.message);
    assert!(patch_rows(&env).await.is_empty());
}

#[tokio::test]
async fn an_import_that_overlaps_a_staged_patch_stages_nothing() {
    let env = Setup::new(tiny()).start().await;
    real_binary(&env).await;
    three_patches(&env).await;
    let p = env.tmp.path().join("o.ips");
    env.ok(
        &approver(),
        "patch_export_diff",
        json!({"output_path": p.to_str().unwrap()}),
    )
    .await;
    clear_patches(&env).await;
    // A staged patch that starts inside the first imported one.
    env.ok(
        &user(),
        "patch_set",
        json!({"address": "0x401041", "bytes": "90"}),
    )
    .await;
    let e = env
        .err(
            &user(),
            "patch_import",
            json!({"path": p.to_str().unwrap()}),
        )
        .await;
    assert!(e.message.contains("overlaps"), "{}", e.message);
    assert_eq!(patch_rows(&env).await.len(), 1, "only the earlier patch");
}

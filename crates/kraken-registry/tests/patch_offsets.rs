//! Patches by file offset: bytes outside every mapped block (file headers, a raw image), kept
//! beside address patches, exported, undone.

mod common;

use common::*;
use kraken_registry::{AutoApprove, CallContext, Surface};
use serde_json::json;
use std::sync::Arc;

fn approver() -> CallContext {
    let mut c = CallContext::user("tester", Surface::Test);
    c.approval = Arc::new(AutoApprove);
    c
}

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

/// An ELF whose bytes at 0x401000..0x402000 are the ones the fake engine reports there.
async fn elf_binary(env: &Env) -> Vec<u8> {
    let r = env
        .ok(
            &user(),
            "read_bytes",
            json!({"address": "0x401000", "length": 4096}),
        )
        .await;
    let mem = decode(r["bytes"].as_str().expect("bytes"));
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
    e
}

async fn export(env: &Env, name: &str) -> Vec<u8> {
    let out = env.tmp.path().join(name);
    env.ok(
        &approver(),
        "patch_export",
        json!({"output_path": out.to_str().unwrap()}),
    )
    .await;
    std::fs::read(out).expect("exported file")
}

#[tokio::test]
async fn an_elf_header_byte_is_patched_by_offset_and_exported() {
    let env = Setup::new(tiny()).start().await;
    let elf = elf_binary(&env).await;
    assert_eq!(elf[0x10], 2, "an executable");
    let r = env
        .ok(
            &user(),
            "patch_set",
            json!({"offset": "0x10", "bytes": "03", "note": "make it a shared object"}),
        )
        .await;
    assert_eq!(r["status"], "applied", "{r}");
    assert_eq!(r["patch"]["target"], "offset");
    assert_eq!(r["patch"]["original"], "02");

    // the same number as an address is a different patch: this one maps to file offset 0x1040
    env.ok(
        &user(),
        "patch_set",
        json!({"address": "0x401040", "bytes": "9090"}),
    )
    .await;
    let l = env.ok(&user(), "patch_list", json!({})).await;
    let items = l["items"].as_array().expect("items");
    assert_eq!(items.len(), 2, "{l}");
    assert_eq!(items[0]["target"], "va");
    assert_eq!(items[1]["target"], "offset");

    let patched = export(&env, "out.elf").await;
    let mut want = elf.clone();
    want[0x10] = 3;
    let mem = &elf[0x1040..0x1042];
    assert_ne!(mem, [0x90, 0x90], "the fixture is not already nops");
    want[0x1040] = 0x90;
    want[0x1041] = 0x90;
    assert_eq!(patched, want);

    // an address patch landing on the offset patch's bytes is refused, and the other way round
    let e = env
        .err(
            &user(),
            "patch_set",
            json!({"address": "0x400010", "bytes": "00"}),
        )
        .await;
    assert!(e.message.contains("same bytes"), "{e}");
    env.ok(
        &user(),
        "patch_set",
        json!({"offset": "0x1100", "bytes": "cc"}),
    )
    .await;
    let e = env
        .err(
            &user(),
            "patch_set",
            json!({"address": "0x401100", "bytes": "90"}),
        )
        .await;
    assert!(e.message.contains("same bytes"), "{e}");
    // and offset patches overlap by their own ranges
    let e = env
        .err(
            &user(),
            "patch_set",
            json!({"offset": "0xf", "bytes": "0000"}),
        )
        .await;
    assert!(e.message.contains("overlaps"), "{e}");
}

#[tokio::test]
async fn a_raw_image_is_patched_beyond_the_mapped_range_and_exported_in_every_format() {
    let env = Setup::new(tiny()).start().await;
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/raw/fw_x86.bin"),
    )
    .expect("corpus raw image");
    std::fs::write(&env.binary, &raw).expect("write binary");
    let last = raw.len() - 1;
    let off = format!("{last:#x}");
    let orig = format!("{:02x}", raw[last]);
    let r = env
        .ok(
            &user(),
            "patch_set",
            json!({"offset": off, "bytes": "5a", "note": "last byte"}),
        )
        .await;
    assert_eq!(r["patch"]["original"], orig, "{r}");
    env.ok(
        &user(),
        "patch_set",
        json!({"offset": "0x0", "bytes": "dead", "note": "first two"}),
    )
    .await;

    // past the end of the file there is nothing to patch
    let e = env
        .err(
            &user(),
            "patch_set",
            json!({"offset": format!("{:#x}", raw.len()), "bytes": "00"}),
        )
        .await;
    assert!(e.message.contains("past the end"), "{e}");
    // a patch needs one of address and offset
    env.err(&user(), "patch_set", json!({"bytes": "00"})).await;

    let mut want = raw.clone();
    want[last] = 0x5a;
    want[0] = 0xde;
    want[1] = 0xad;
    assert_eq!(export(&env, "out.bin").await, want);

    for fmt in ["ips", "bps", "json"] {
        let path = env.tmp.path().join(format!("raw.{fmt}"));
        let r = env
            .ok(
                &approver(),
                "patch_export_diff",
                json!({"output_path": path.to_str().unwrap(), "format": fmt}),
            )
            .await;
        assert_eq!(r["patches"], 2, "{fmt}: {r}");
    }
    // the IPS file applied by hand gives the same bytes
    let ips = std::fs::read(env.tmp.path().join("raw.ips")).expect("ips");
    assert_eq!(&ips[..5], b"PATCH");
    let mut applied = raw.clone();
    let mut at = 5;
    while &ips[at..at + 3] != b"EOF" {
        let o =
            usize::from(ips[at]) << 16 | usize::from(ips[at + 1]) << 8 | usize::from(ips[at + 2]);
        let n = usize::from(ips[at + 3]) << 8 | usize::from(ips[at + 4]);
        applied[o..o + n].copy_from_slice(&ips[at + 5..at + 5 + n]);
        at += 5 + n;
    }
    assert_eq!(applied, want);

    // an address patch cannot be placed in a file that is no object: the export says so
    env.ok(
        &user(),
        "patch_set",
        json!({"address": "0x401040", "bytes": "9090"}),
    )
    .await;
    let out = env.tmp.path().join("bad.bin");
    let e = env
        .err(
            &approver(),
            "patch_export",
            json!({"output_path": out.to_str().unwrap()}),
        )
        .await;
    assert_eq!(code(&e), kraken_proto::ErrorCode::Unsupported, "{e}");
}

#[tokio::test]
async fn undoing_an_offset_patch_leaves_the_address_patch_with_the_same_number() {
    let env = Setup::new(tiny()).start().await;
    elf_binary(&env).await;
    let u = user();
    env.ok(
        &u,
        "patch_set",
        json!({"address": "0x401040", "bytes": "90"}),
    )
    .await;
    let off = env
        .ok(&u, "patch_set", json!({"offset": "0x1050", "bytes": "cc"}))
        .await;
    // 0x1040 is where 0x401040 sits in the file, so those two are the same bytes
    let l = env.ok(&u, "patch_list", json!({})).await;
    assert_eq!(l["items"].as_array().expect("items").len(), 2);
    env.ok(&u, "undo_entry", json!({"entry_id": off["entry_id"]}))
        .await;
    let l = env.ok(&u, "patch_list", json!({})).await;
    let items = l["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{l}");
    assert_eq!(items[0]["target"], "va");
    assert_eq!(items[0]["replacement"], "90");

    // removing by offset and undoing the removal
    let again = env
        .ok(&u, "patch_set", json!({"offset": "0x1050", "bytes": "cc"}))
        .await;
    assert_eq!(again["status"], "applied");
    let removed = env
        .ok(&u, "patch_remove", json!({"offset": "0x1050"}))
        .await;
    assert_eq!(removed["removed"], true);
    let l = env.ok(&u, "patch_list", json!({})).await;
    assert_eq!(l["items"].as_array().expect("items").len(), 1);
    env.ok(&u, "undo_entry", json!({"entry_id": removed["entry_id"]}))
        .await;
    let l = env.ok(&u, "patch_list", json!({})).await;
    assert_eq!(l["items"].as_array().expect("items").len(), 2, "{l}");
    let gone = env
        .ok(&u, "patch_remove", json!({"address": "0x1050"}))
        .await;
    assert_eq!(gone["removed"], false, "no address patch at that number");
}

#[tokio::test]
async fn an_agents_offset_patch_is_additive_and_its_replacement_is_a_proposal() {
    let env = Setup::new(tiny()).start().await;
    elf_binary(&env).await;
    let a = agent("run-off");
    let first = env
        .ok(&a, "patch_set", json!({"offset": "0x20", "bytes": "01"}))
        .await;
    assert_eq!(first["status"], "applied", "{first}");
    let second = env
        .ok(&a, "patch_set", json!({"offset": "0x20", "bytes": "02"}))
        .await;
    assert_eq!(second["status"], "proposed", "{second}");
}

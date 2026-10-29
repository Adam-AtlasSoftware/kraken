//! `emulate_call`: argument checks with the fake engine, and real calls of corpus functions on
//! x86-64, AArch64 and RISC-V.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use kraken_proto::ErrorCode;
use serde_json::{Value, json};

/// The fake engine loads `tiny` at this base; listing address = base + link-time address.
const BASE: u64 = 0x40_0000;

#[tokio::test]
async fn bad_arguments_are_refused_before_anything_runs() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    for args in [
        json!({}),
        json!({"address": "0x401000", "function": "main"}),
        json!({"address": "0x401000", "max_steps": 0}),
        json!({"address": "0x401000", "max_steps": 200_000_001u64}),
        json!({"address": "0x401000", "timeout_seconds": 121}),
        json!({"address": "0x401000", "returns": "banana"}),
        json!({"address": "0x401000", "args": [{}]}),
        json!({"address": "0x401000", "args": [{"int": 1, "string": "a"}]}),
        json!({"address": "0x401000", "args": [{"string": "a", "bits": 8}]}),
        json!({"address": "0x401000", "args": [{"int": 1, "bits": 12}]}),
        json!({"address": "0x401000", "args": [{"int": "zebra"}]}),
        json!({"address": "0x401000", "args": [{"hex": "abc"}]}),
        json!({"address": "0x401000", "args": [{"buffer": 70000}]}),
        json!({"address": "0x401000", "args": [{"string": "a\u{0}b"}]}),
        json!({"address": "0x401000", "unknown": true}),
    ] {
        let e = env.err(&u, "emulate_call", args.clone()).await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{args}: {e}");
    }
    let too_many: Vec<Value> = (0..17).map(|i| json!({"int": i})).collect();
    let e = env
        .err(
            &u,
            "emulate_call",
            json!({"address": "0x401000", "args": too_many}),
        )
        .await;
    assert_eq!(e.code, ErrorCode::InvalidArgument, "{e}");
    let e = env
        .err(&u, "emulate_call", json!({"function": "no_such_function"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound, "{e}");
}

#[tokio::test]
async fn the_command_is_safe_and_documented() {
    let env = Setup::new(tiny()).start().await;
    let spec = env
        .registry
        .get("emulate_call")
        .expect("registered")
        .spec()
        .clone();
    assert_eq!(spec.permission, kraken_registry::Permission::Safe);
    assert!(spec.summary.len() <= 110, "{}", spec.summary);
}

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

/// `KRAKEN_EMU_RUN` unless set, the runner built next to the test binaries.
fn runner() -> PathBuf {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("exe");
    let dir = exe.parent().and_then(Path::parent).expect("target dir");
    dir.join("kraken-emu-run")
}

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().expect("4 bytes"))
}

/// vm_run(vm, code, len) on the bytecode (5 + 7) * 3: returns 36 with the VM left at sp 1,
/// pc 9 and 6 steps.
async fn vm_run_case(env: &Env, binary: &str, link_addr: u64) {
    std::fs::copy(corpus(binary), &env.binary).expect("copy corpus binary");
    let out = env
        .ok(
            &user(),
            "emulate_call",
            json!({
                "address": format!("{:#x}", BASE + link_addr),
                "args": [
                    {"buffer": 144},
                    {"hex": "010501070201030400"},
                    {"int": 9}
                ],
                "returns": "int",
            }),
        )
        .await;
    assert_eq!(out["ended"], "returned", "{binary}: {out}");
    assert_eq!(out["value"]["signed"], 36, "{binary}: {out}");
    let vm = out["buffers"][0]["hex"]["value"].as_str().expect("vm hex");
    let bytes: Vec<u8> = (0..vm.len() / 2)
        .map(|i| u8::from_str_radix(&vm[2 * i..2 * i + 2], 16).expect("hex"))
        .collect();
    assert_eq!(le_u32(&bytes[128..]), 1, "{binary}: sp");
    assert_eq!(le_u32(&bytes[132..]), 9, "{binary}: pc");
    assert_eq!(le_u32(&bytes[136..]), 6, "{binary}: steps");
    assert_eq!(out["buffers"][0]["changed"], true);
    assert_eq!(out["buffers"][1]["changed"], false);
    assert!(out["steps"].as_u64().expect("steps") > 20, "{out}");
}

#[tokio::test]
#[ignore = "needs the SLEIGH tree (KRAKEN_NATIVE_SPECS=~/.cache/kraken-dev/native-sla/Ghidra_12.2_build), \
            Landlock and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn a_corpus_function_is_called_on_three_architectures() {
    let env = Setup::new(tiny()).start().await;
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    vm_run_case(&env, "bin/switch_vm-O0", 0x1255).await;
    vm_run_case(&env, "aarch64/bin/switch_vm-aarch64-O0", 0x930).await;
    vm_run_case(&env, "riscv64/bin/switch_vm-riscv64-O0", 0x838).await;
}

#[tokio::test]
#[ignore = "needs the SLEIGH tree, Landlock and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn library_calls_need_libc_mode_and_then_work() {
    let env = Setup::new(tiny()).start().await;
    // SAFETY: as above.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    std::fs::copy(corpus("bin/static_strops-O0"), &env.binary).expect("copy corpus binary");
    // static_strops is not position independent: listing addresses are the link-time ones.
    let count = json!({
        "address": "0x4017fd",
        "args": [{"string": "mississippi is in it"}, {"int": 105, "bits": 8}],
        "returns": "int",
        "libc": true,
    });
    let out = env.ok(&user(), "emulate_call", count).await;
    assert_eq!(out["ended"], "returned", "{out}");
    assert_eq!(out["value"]["signed"], 7, "{out}");

    // str_upper edits its argument in place.
    let out = env
        .ok(
            &user(),
            "emulate_call",
            json!({"address": "0x401838", "args": [{"string": "Hello, world"}],
                   "returns": "void", "libc": true}),
        )
        .await;
    assert_eq!(out["buffers"][0]["text"]["value"], "HELLO, WORLD", "{out}");
    assert_eq!(out["buffers"][0]["changed"], true);
    assert_eq!(out["value"], Value::Null);

    // is_palindrome uses strlen, which is behind an IRELATIVE relocation: without libc the call
    // stops there and says so.
    let image_only = env
        .ok(
            &user(),
            "emulate_call",
            json!({"address": "0x40187e", "args": [{"string": "level"}]}),
        )
        .await;
    assert_ne!(image_only["ended"], "returned", "{image_only}");
    let full = env
        .ok(
            &user(),
            "emulate_call",
            json!({"address": "0x40187e", "args": [{"string": "level"}], "libc": true}),
        )
        .await;
    assert_eq!(full["value"]["signed"], 1, "{full}");
}

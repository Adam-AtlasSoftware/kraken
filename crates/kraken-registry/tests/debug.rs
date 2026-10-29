//! `debug_*`: argument checks and policy with the fake engine, and a real session on a corpus
//! program in the confined emulator.
#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};

use common::*;
use kraken_proto::ErrorCode;
use serde_json::json;

const NAMES: [&str; 15] = [
    "debug_start",
    "debug_step",
    "debug_step_over",
    "debug_step_out",
    "debug_continue",
    "debug_run_to",
    "debug_break_set",
    "debug_break_remove",
    "debug_break_list",
    "debug_regs",
    "debug_mem_read",
    "debug_disasm",
    "debug_state",
    "debug_sessions",
    "debug_stop",
];

#[tokio::test]
async fn the_commands_are_safe_documented_and_bounded() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    for n in NAMES {
        let spec = env.registry.get(n).expect("registered").spec().clone();
        assert_eq!(spec.permission, kraken_registry::Permission::Safe, "{n}");
        assert!(spec.summary.len() <= 110, "{n}: {}", spec.summary);
    }
    for (name, args) in [
        ("debug_step", json!({"session": 1, "count": 0})),
        ("debug_step", json!({"session": 1, "count": 1_000_001})),
        ("debug_continue", json!({"session": 1, "max_steps": 0})),
        (
            "debug_continue",
            json!({"session": 1, "timeout_seconds": 121}),
        ),
        (
            "debug_mem_read",
            json!({"session": 1, "address": "0x10", "length": 4097}),
        ),
        ("debug_disasm", json!({"session": 1, "count": 201})),
        ("debug_start", json!({"argv": ["a\u{0}b"]})),
        ("debug_regs", json!({"session": 0})),
    ] {
        let e = env.err(&u, name, args.clone()).await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{name} {args}: {e}");
    }
    let e = env.err(&u, "debug_regs", json!({"session": 99})).await;
    assert_eq!(e.code, ErrorCode::NotFound, "{e}");
    let gone = env.ok(&u, "debug_stop", json!({"session": 99})).await;
    assert_eq!(gone["ended"], false);
}

fn corpus_binary(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/bin")
        .join(name)
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

#[tokio::test]
#[ignore = "needs KRAKEN_NATIVE_SPECS=~/.cache/kraken-dev/native-sla/Ghidra_12.2_build, Landlock \
            and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn a_corpus_program_is_stepped_to_main() {
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(corpus_binary("static_strops-O0"), &env.binary).expect("copy corpus binary");
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let u = user();

    let start = env.ok(&u, "debug_start", json!({"argv": ["x"]})).await;
    let id = start["session"].as_u64().expect("session");
    assert_eq!(start["arch"], "x86_64", "{start}");
    let entry = start["pc"].as_str().expect("pc").to_string();

    // To main by symbol; the registers then say the program counter is there.
    let stop = env
        .ok(&u, "debug_run_to", json!({"session": id, "symbol": "main"}))
        .await;
    assert_eq!(stop["stop"]["kind"], "reached", "{stop}");
    let main_pc = stop["stop"]["pc"].as_str().expect("pc").to_string();
    assert_ne!(main_pc, entry);
    let regs = env.ok(&u, "debug_regs", json!({"session": id})).await;
    assert_eq!(regs["pc"], json!(main_pc), "{regs}");
    let rsp = regs["registers"]
        .as_array()
        .expect("registers")
        .iter()
        .find(|r| r["name"] == "RSP")
        .expect("RSP")["value"]
        .as_str()
        .expect("value")
        .to_string();

    // Memory: the stack is mapped, main's own bytes are the disassembled ones.
    let stack = env
        .ok(
            &u,
            "debug_mem_read",
            json!({"session": id, "address": rsp, "length": 16, "emulator_address": true}),
        )
        .await;
    assert_eq!(stack["hex"].as_str().expect("hex").len(), 32);
    let code = env
        .ok(
            &u,
            "debug_mem_read",
            json!({"session": id, "address": main_pc, "length": 4}),
        )
        .await;
    let dis = env
        .ok(&u, "debug_disasm", json!({"session": id, "count": 3}))
        .await;
    let insns = dis["instructions"].as_array().expect("instructions");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0]["is_pc"], true);
    assert_eq!(insns[0]["address"], json!(main_pc));
    assert!(
        code["hex"]
            .as_str()
            .expect("hex")
            .starts_with(insns[0]["bytes"].as_str().expect("bytes")),
        "{code} {dis}"
    );

    // A breakpoint ahead of the program counter stops the run there.
    let ahead = insns[1]["address"].as_str().expect("address").to_string();
    env.ok(
        &u,
        "debug_break_set",
        json!({"session": id, "address": ahead}),
    )
    .await;
    let hit = env.ok(&u, "debug_continue", json!({"session": id})).await;
    assert_eq!(hit["stop"]["kind"], "breakpoint", "{hit}");
    assert_eq!(hit["stop"]["pc"], json!(ahead));
    env.ok(
        &u,
        "debug_break_remove",
        json!({"session": id, "address": ahead}),
    )
    .await;

    // Stepping moves the counter; a call is stepped over; breakpoints round trip.
    let one = env.ok(&u, "debug_step", json!({"session": id})).await;
    assert_eq!(one["stop"]["kind"], "stepped");
    assert_ne!(one["stop"]["pc"], json!(main_pc));
    let over = env.ok(&u, "debug_step_over", json!({"session": id})).await;
    assert!(over["instructions"].as_u64().expect("n") >= 2, "{over}");
    let set = env
        .ok(
            &u,
            "debug_break_set",
            json!({"session": id, "symbol": "main"}),
        )
        .await;
    assert_eq!(set["changed"], true);
    assert_eq!(set["breakpoints"], json!([main_pc]));
    let list = env.ok(&u, "debug_break_list", json!({"session": id})).await;
    assert_eq!(list["breakpoints"], json!([main_pc]));
    let rm = env
        .ok(
            &u,
            "debug_break_remove",
            json!({"session": id, "address": main_pc}),
        )
        .await;
    assert_eq!(rm["breakpoints"], json!([]));

    // Run to the end: the program's output arrives and the session reports it finished.
    let end = env.ok(&u, "debug_continue", json!({"session": id})).await;
    assert_eq!(end["stop"]["kind"], "exited", "{end}");
    assert_eq!(end["stop"]["exit"], json!({"kind": "code", "value": 0}));
    assert!(
        end["stdout_new"]["value"]
            .as_str()
            .expect("stdout")
            .contains("hash=6490"),
        "{end}"
    );
    assert_eq!(end["stdout_new"]["untrusted"], true);
    let state = env.ok(&u, "debug_state", json!({"session": id})).await;
    assert_eq!(state["finished"], true);
    let all = env.ok(&u, "debug_sessions", json!({})).await;
    assert_eq!(all["sessions"].as_array().expect("sessions").len(), 1);

    let stopped = env.ok(&u, "debug_stop", json!({"session": id})).await;
    assert_eq!(stopped["ended"], true);
    let e = env.err(&u, "debug_state", json!({"session": id})).await;
    assert_eq!(e.code, ErrorCode::NotFound);

    // At most four sessions at once.
    for _ in 0..4 {
        env.ok(&u, "debug_start", json!({})).await;
    }
    let e = env.err(&u, "debug_start", json!({})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument, "{e}");
}

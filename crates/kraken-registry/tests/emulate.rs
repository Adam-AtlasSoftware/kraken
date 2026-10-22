//! `emulate_run`: argument checks with the fake engine, and a real run of a corpus binary.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use kraken_proto::ErrorCode;
use serde_json::json;

#[tokio::test]
async fn bad_arguments_are_refused_before_anything_runs() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    for args in [
        json!({"max_steps": 0}),
        json!({"max_steps": 200_000_001u64}),
        json!({"timeout_seconds": 0}),
        json!({"timeout_seconds": 121}),
        json!({"stdin": 5}),
        json!({"argv": "x"}),
        json!({"argv": ["a", 3]}),
        json!({"max_steps": "many"}),
        json!({"unknown": true}),
        json!({"argv": ["a\u{0}b"]}),
    ] {
        let e = env.err(&u, "emulate_run", args.clone()).await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{args}: {e}");
    }
}

#[tokio::test]
async fn a_file_that_is_not_an_elf_is_refused_with_a_reason() {
    let env = Setup::new(tiny()).start().await;
    // The project's stand-in binary is `\x7fELF fake binary contents`.
    let e = env.err(&user(), "emulate_run", json!({})).await;
    assert!(
        matches!(e.code, ErrorCode::Unsupported | ErrorCode::Internal),
        "{e}"
    );
    assert!(
        e.message.contains("kraken-emu-run") || e.message.contains("ELF"),
        "{e}"
    );
}

#[tokio::test]
async fn the_command_is_safe_and_documented() {
    let env = Setup::new(tiny()).start().await;
    let spec = env
        .registry
        .get("emulate_run")
        .expect("registered")
        .spec()
        .clone();
    assert_eq!(spec.permission, kraken_registry::Permission::Safe);
    assert!(spec.summary.len() <= 110, "{}", spec.summary);
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
#[ignore = "needs the SLEIGH tree (KRAKEN_NATIVE_SPECS=~/.cache/kraken-dev/native-sla/Ghidra_12.1.4_build), \
            Landlock and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn a_corpus_program_runs_under_emulation() {
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(corpus_binary("static_strops-O0"), &env.binary).expect("copy corpus binary");
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let out = env
        .ok(
            &user(),
            "emulate_run",
            json!({"stdin": "ignored\n", "argv": ["x"]}),
        )
        .await;
    assert_eq!(out["exit"], json!({"kind": "code", "value": 0}), "{out}");
    let stdout = out["stdout"]["value"].as_str().expect("stdout");
    assert!(stdout.contains("hash=6490"), "{out}");
    assert_eq!(out["stdout"]["untrusted"], true);
    assert_eq!(out["truncated"], false);
    assert!(out["steps"].as_u64().expect("steps") > 1000, "{out}");

    let small = env
        .ok(&user(), "emulate_run", json!({"max_steps": 1000}))
        .await;
    assert_eq!(small["exit"]["kind"], "step_limit", "{small}");
    assert_eq!(small["exit"]["value"], json!(null));
}

/// A real dynamically linked x86-64 program (`KRAKEN_EMU_TEST_BINARY`) with the x86_64 sysroot
/// of `cargo xtask emu-sysroots`: it must prompt and run to the end on two inputs.
#[tokio::test]
#[ignore = "needs KRAKEN_EMU_TEST_BINARY=<x86-64 program>, the x86_64 sysroot and the SLEIGH tree"]
async fn a_real_dynamic_x86_64_program_runs_with_the_sysroot() {
    let Some(binary) = std::env::var_os("KRAKEN_EMU_TEST_BINARY")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    else {
        eprintln!("KRAKEN_EMU_TEST_BINARY is not set to a file: skipped");
        return;
    };
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(&binary, &env.binary).expect("copy the program");
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    for stdin in ["hunter2\n".to_string(), format!("{}\n", "A".repeat(32))] {
        let out = env
            .ok(
                &user(),
                "emulate_run",
                json!({"stdin": stdin, "max_steps": 200_000_000u64, "timeout_seconds": 120}),
            )
            .await;
        println!("stdin {stdin:?}\n{out:#}");
        println!(
            "stdout: {}\nstderr: {}\nexit: {}\nsteps: {}",
            out["stdout"]["value"], out["stderr"]["value"], out["exit"], out["steps"]
        );
        assert_eq!(out["exit"]["kind"], "code", "{out}");
        let stdout = out["stdout"]["value"].as_str().expect("stdout");
        assert!(stdout.contains("password>"), "{out}");
    }
}

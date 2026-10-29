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
#[ignore = "needs the SLEIGH tree (KRAKEN_NATIVE_SPECS=~/.cache/kraken-dev/native-sla/Ghidra_12.2_build), \
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

#[tokio::test]
async fn new_run_inputs_are_bounded_and_compare_needs_something_to_compare() {
    let env = Setup::new(tiny()).start().await;
    let u = user();
    for args in [
        json!({"env": {"A=B": "x"}}),
        json!({"env": {"": "x"}}),
        json!({"argv0": "a\u{0}b"}),
        json!({"inputs": [{"name": "../x", "text": "a"}]}),
        json!({"inputs": [{"name": "/etc/passwd", "text": "a"}]}),
        json!({"inputs": [{"name": "a"}]}),
        json!({"inputs": [{"name": "a", "text": "x", "hex": "00"}]}),
        json!({"inputs": [{"name": "a", "hex": "abc"}]}),
        json!({"inputs": [{"name": "a", "text": "x"}, {"name": "a", "text": "y"}]}),
    ] {
        let e = env.err(&u, "emulate_run", args.clone()).await;
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{args}: {e}");
    }
    // No patches in the project: the default comparison has nothing to compare.
    let e = env.err(&u, "emulate_compare", json!({})).await;
    assert_eq!(e.code, ErrorCode::InvalidArgument, "{e}");
    assert!(e.message.contains("no byte patches"), "{e}");
    let e = env
        .err(&u, "emulate_compare", json!({"b": "/nonexistent/prog"}))
        .await;
    assert_eq!(e.code, ErrorCode::NotFound, "{e}");
    let spec = env
        .registry
        .get("emulate_compare")
        .expect("registered")
        .spec()
        .clone();
    assert_eq!(spec.permission, kraken_registry::Permission::Safe);
    assert!(spec.summary.len() <= 110, "{}", spec.summary);
}

/// Builds a freestanding x86-64 probe (raw system calls, no libc) that reads `MODE`, `/work/in.txt` and writes `/work/out.txt`.
fn build_probe(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"static long sc(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return r;
}
static long len(const char *s) { long n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { sc(1, 1, (long)s, len(s)); }
static int starts(const char *s, const char *p) { while (*p) if (*s++ != *p++) return 0; return 1; }
void real_main(long *sp) {
    long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    const char *mode = "(unset)";
    for (char **e = envp; *e; e++) if (starts(*e, "MODE=")) mode = *e + 5;
    out("argv0="); out(argv[0]); out(" mode="); out(mode); out("\n");
    char buf[64] = {0};
    long fd = sc(2, (long)"/work/in.txt", 0, 0);
    if (fd >= 0) { sc(0, fd, (long)buf, 63); sc(3, fd, 0, 0); }
    out("in="); out(buf);
    sc(41, 2, 1, 0);
    long o = sc(2, (long)"/work/out.txt", 0x241, 0644);
    if (o >= 0) {
        sc(1, o, (long)"mode=", 5); sc(1, o, (long)mode, len(mode));
        sc(1, o, (long)" in=", 4); sc(1, o, (long)buf, len(buf)); sc(3, o, 0, 0);
    }
    sc(231, mode[0] == 'x' ? 3 : 0, 0, 0);
}
__asm__(".globl _start\n_start:\n mov %rsp, %rdi\n and $-16, %rsp\n call real_main\n");
"#,
    )
    .ok()?;
    let out = dir.join("probe");
    let ok = std::process::Command::new("gcc")
        .args(["-static", "-nostdlib", "-O1", "-fno-stack-protector", "-o"])
        .arg(&out)
        .arg(&src)
        .status()
        .ok()?
        .success();
    ok.then_some(out)
}

#[tokio::test]
#[ignore = "needs gcc with static libc, the SLEIGH tree, Landlock and `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn inputs_env_files_and_a_comparison_work_on_a_real_program() {
    let env = Setup::new(tiny()).start().await;
    let scratch = tempfile::tempdir().expect("tempdir");
    let Some(probe) = build_probe(scratch.path()) else {
        eprintln!("no gcc -static: skipped");
        return;
    };
    std::fs::copy(&probe, &env.binary).expect("copy probe");
    // SAFETY: set before any other thread reads it; this test is the only one in the binary
    // that touches the variable.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner()) };
    let u = user();
    let run = json!({
        "env": {"MODE": "fast"},
        "argv0": "tool",
        "inputs": [{"name": "in.txt", "text": "hello\n"}],
        "return_files": true,
    });
    let out = env.ok(&u, "emulate_run", run).await;
    assert_eq!(out["exit"], json!({"kind": "code", "value": 0}), "{out}");
    let stdout = out["stdout"]["value"].as_str().expect("stdout");
    assert!(stdout.contains("argv0=tool mode=fast"), "{out}");
    assert!(stdout.contains("in=hello"), "{out}");
    let files = out["files"].as_array().expect("files");
    assert_eq!(files.len(), 1, "the seeded input is not written: {out}");
    assert_eq!(files[0]["name"], "out.txt");
    assert_eq!(files[0]["preview"]["value"], "mode=fast in=hello\n");
    let notes = out["notes"].to_string();
    assert!(
        notes.contains("socket (41)"),
        "named, not numbered: {notes}"
    );

    let same = env
        .ok(
            &u,
            "emulate_compare",
            json!({"a": probe, "b": probe, "env": {"MODE": "x"}}),
        )
        .await;
    assert_eq!(same["same"], true, "{same}");
    assert_eq!(same["a"]["exit"]["value"], 3);

    let mut bytes = std::fs::read(&probe).expect("read probe");
    let at = bytes
        .windows(4)
        .position(|w| w == b"in=\0")
        .expect("format string");
    bytes[at] = b'I';
    let other = scratch.path().join("probe-patched");
    std::fs::write(&other, &bytes).expect("write variant");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    let diff = env
        .ok(
            &u,
            "emulate_compare",
            json!({
                "a": probe,
                "b": other,
                "inputs": [{"name": "in.txt", "text": "hello\n"}],
            }),
        )
        .await;
    assert_eq!(diff["same"], false, "{diff}");
    let first = diff["first_divergence"]["value"].as_str().expect("first");
    assert!(first.starts_with("stdout: line 2"), "{diff}");
    assert!(
        first.contains("in=hello") && first.contains("In=hello"),
        "{diff}"
    );
    assert_eq!(
        diff["differences"].as_array().expect("diffs").len(),
        2,
        "{diff}"
    );
}

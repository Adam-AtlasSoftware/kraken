//! `emulate_run` of a dynamically linked program without an extracted sysroot: the run gets
//! private copies of this computer's loader and of the libraries the program names, and no other
//! host file is visible to the guest. Its own test binary, because it sets process environment.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use serde_json::json;

/// The runner built next to the test binaries, unless `KRAKEN_EMU_RUN` names one.
fn runner() -> PathBuf {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("exe");
    let dir = exe.parent().and_then(Path::parent).expect("target dir");
    dir.join("kraken-emu-run")
}

#[tokio::test]
#[ignore = "needs an x86-64 Linux host, the SLEIGH tree (KRAKEN_NATIVE_SPECS), Landlock and \
            `cargo build -p kraken-emu --bin kraken-emu-run`"]
async fn a_dynamic_program_sees_only_its_own_libraries() {
    let cat = Path::new("/usr/bin/cat");
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) || !cat.is_file() {
        eprintln!("needs /usr/bin/cat on an x86-64 Linux host: skipped");
        return;
    }
    let no_sysroots = tempfile::tempdir().expect("tempdir");
    // SAFETY: set before the daemon under test starts any thread that reads them; this binary
    // has only this test.
    unsafe {
        std::env::set_var("KRAKEN_EMU_RUN", runner());
        std::env::set_var("KRAKEN_EMU_SYSROOTS", no_sysroots.path());
    }
    let env = Setup::new(tiny()).start().await;
    std::fs::copy(cat, &env.binary).expect("copy the program");
    let out = env
        .ok(
            &user(),
            "emulate_run",
            json!({"argv": ["/etc/passwd"], "max_steps": 200_000_000u64, "timeout_seconds": 120}),
        )
        .await;
    println!("{out:#}");
    let notes = out["notes"].to_string();
    assert!(notes.contains("private sysroot"), "{out}");
    let stdout = out["stdout"]["value"].as_str().unwrap_or_default();
    assert!(
        !stdout.contains("root:"),
        "the guest read the host's /etc/passwd: {out}"
    );
    // On a host whose libc uses AVX the run stops at the first such instruction instead.
    if out["exit"]["kind"] == "code" {
        assert_ne!(out["exit"]["value"], 0, "{out}");
        let stderr = out["stderr"]["value"].as_str().unwrap_or_default();
        assert!(stderr.contains("No such file"), "{out}");
    }
}

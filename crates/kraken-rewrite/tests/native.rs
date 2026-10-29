//! The native side without an emulator: the allowlist lint, the confined compile step, the
//! confined runner and the confined export build. These need only a Rust toolchain; where the
//! host cannot confine (no Landlock ABI 4 or no network barrier) they skip.

use std::process::Command;
use std::time::{Duration, Instant};

use kraken_rewrite::abi::{Arg, Param, Ret, Signature, Termination};
use kraken_rewrite::export::build_in_sandbox;
use kraken_rewrite::native::{Build, build, build_with_timeout};
use kraken_rewrite::sandbox::{self, Confinement, ReadScope, confine, run_captured, scratch_dir};

fn sig() -> Signature {
    Signature {
        name: "cmp_id".into(),
        params: vec![Param::Buf, Param::Buf],
        ret: Ret::Int {
            bits: 32,
            signed: true,
        },
    }
}

fn record(id: i32) -> Arg {
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&id.to_le_bytes());
    Arg::Buf { data: b }
}

fn can_confine() -> bool {
    sandbox::enforced_or_skip()
}

const CMP_ID: &str = include_str!("../references/cmp_id.rs");

#[test]
fn the_reference_translation_builds_and_runs_confined() {
    if !can_confine() {
        return;
    }
    let Build::Ready(runner) = build(&sig(), CMP_ID, &Confinement::default()).expect("build")
    else {
        panic!("reference translation was rejected");
    };
    assert!(runner.build_confinement.label().starts_with("landlock-v"));
    let obs = runner.run(&[record(10), record(3)]).expect("run");
    assert_eq!(obs.termination, Termination::Returned);
    assert_eq!(obs.ret, Some(7));
}

/// Each of these slipped past the old substring blacklist (finding H1).
#[test]
fn lint_bypasses_are_rejected_before_any_compiler_runs() {
    let secret = tempfile::NamedTempFile::new().expect("secret");
    std::fs::write(secret.path(), "SECRET-CONTENT").expect("write");
    let p = secret.path().display();
    let attempts = [
        format!(r#"pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 {{ include_str !("{p}").len() as i32 }}"#),
        format!(r#"pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 {{ include_bytes !("{p}")[0] as i32 }}"#),
        "use std::{fs, process::Command}; pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 { 0 }".into(),
        r#"extern "C" { fn socket(d: i32, t: i32, p: i32) -> i32; } pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 { unsafe { socket(2, 2, 0) } }"#.into(),
        format!(r##"#[path = "{p}"] mod x; pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 {{ 0 }}"##),
        r#"#[ link(name = "c")] unsafe extern "C" {} pub fn cmp_id(_: *mut u8, _: *mut u8) -> i32 { 0 }"#.into(),
    ];
    for code in attempts {
        // Rejected by the lint alone, so this holds even on a host that cannot confine: the
        // lint runs before the confinement check.
        match build(&sig(), &code, &Confinement::default()) {
            Ok(Build::Rejected(why)) => {
                assert!(
                    why.contains("not allowed") || why.contains("does not compile"),
                    "{why}"
                );
                assert!(!why.contains("SECRET-CONTENT"));
            }
            other => panic!("not rejected: {code}\n{other:?}"),
        }
    }
}

/// Even code the lint would let through cannot read outside the toolchain, system libraries and
/// its run directory at compile time: the compile step itself is confined (H1).
#[test]
fn the_compile_step_cannot_read_files_outside_its_scope() {
    if !can_confine() {
        return;
    }
    let secret_dir = tempfile::tempdir().expect("secret dir");
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, "LEAK-ME-12345").expect("write");
    let run = scratch_dir("kraken-compile-scope-").expect("scratch");
    let src = run.path().join("t.rs");
    std::fs::write(
        &src,
        format!(
            "const S: &str = include_str!({:?});\nfn main() {{ println!(\"{{S}}\"); }}\n",
            secret.display().to_string()
        ),
    )
    .expect("write");
    let tc = sandbox::toolchain().expect("toolchain");
    let mut cmd = Command::new(&tc.rustc);
    cmd.args(["--error-format", "short", "-o"])
        .arg(run.path().join("t"))
        .arg(&src);
    confine(
        &mut cmd,
        run.path(),
        ReadScope::Toolchain,
        &Confinement::default(),
    )
    .expect("confine");
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(60),
        1 << 20,
        Duration::from_millis(10),
    )
    .expect("run");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.is_some_and(|s| s.success()),
        "the include succeeded:\n{text}"
    );
    assert!(!text.contains("LEAK-ME-12345"), "{text}");
    assert!(!run.path().join("t").exists());

    // Control: the same include of a file inside the run directory works.
    let inside = run.path().join("inside.txt");
    std::fs::write(&inside, "ok").expect("write");
    std::fs::write(
        &src,
        format!(
            "const S: &str = include_str!({:?});\nfn main() {{ println!(\"{{S}}\"); }}\n",
            inside.display().to_string()
        ),
    )
    .expect("write");
    let mut cmd = Command::new(&tc.rustc);
    cmd.args(["-o"]).arg(run.path().join("t")).arg(&src);
    confine(
        &mut cmd,
        run.path(),
        ReadScope::Toolchain,
        &Confinement::default(),
    )
    .expect("confine");
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(60),
        1 << 20,
        Duration::from_millis(10),
    )
    .expect("run");
    assert!(
        out.status.is_some_and(|s| s.success()),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_compile_that_overruns_its_deadline_is_stopped() {
    if !can_confine() {
        return;
    }
    let t = Instant::now();
    match build_with_timeout(
        &sig(),
        CMP_ID,
        &Confinement::default(),
        Duration::from_millis(30),
    )
    .expect("build")
    {
        Build::Rejected(why) => assert!(why.contains("did not finish"), "{why}"),
        Build::Ready(_) => panic!("a 30 ms compile cannot have finished"),
    }
    assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
}

#[test]
fn a_looping_translation_times_out_without_hanging_the_caller() {
    if !can_confine() {
        return;
    }
    let code = r#"
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn cmp_id(a: *const u8, _b: *const u8) -> i32 {
            let mut i: u64 = 0;
            loop { i = i.wrapping_add(2 * (unsafe { *a } as u64 + 1)); if i == 7 { return 0; } }
        }
    "#;
    let Build::Ready(runner) = build(&sig(), code, &Confinement::default()).expect("build") else {
        panic!("rejected");
    };
    let t = Instant::now();
    let obs = runner.run(&[record(0), record(0)]).expect("run");
    assert!(
        matches!(
            obs.termination,
            Termination::Timeout | Termination::Fault { .. }
        ),
        "{:?}",
        obs.termination
    );
    assert!(t.elapsed() < Duration::from_secs(60), "{:?}", t.elapsed());
}

#[test]
fn the_export_build_runs_confined_in_a_private_directory() {
    if !can_confine() {
        return;
    }
    let ws = tempfile::tempdir().expect("ws");
    std::fs::create_dir_all(ws.path().join("src")).expect("mkdir");
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"probe-ffi\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n\
         [lib]\ncrate-type = [\"cdylib\"]\n",
    )
    .expect("manifest");
    std::fs::write(
        ws.path().join("src/lib.rs"),
        "#[unsafe(no_mangle)]\npub extern \"C\" fn probe_fn() -> i32 { 7 }\n",
    )
    .expect("lib");
    let built = build_in_sandbox(ws.path(), "probe-ffi", &Confinement::default()).expect("build");
    assert!(built.symbols.contains("probe_fn"), "{:?}", built.symbols);
    assert!(built.sandbox.starts_with("landlock-v"), "{}", built.sandbox);
}

#[test]
fn a_build_script_cannot_read_the_home_directory_or_use_the_network() {
    if !can_confine() {
        return;
    }
    // A build script is arbitrary code run by cargo; it stands in for a hostile rustc wrapper or
    // linker. It must neither read a file outside the allowed paths nor open a socket.
    let secret_dir = tempfile::tempdir().expect("secret dir");
    let secret = secret_dir.path().join("secret.txt");
    std::fs::write(&secret, "HOME-SECRET").expect("write");
    let ws = tempfile::tempdir().expect("ws");
    std::fs::create_dir_all(ws.path().join("src")).expect("mkdir");
    std::fs::write(
        ws.path().join("Cargo.toml"),
        "[package]\nname = \"probe-ffi\"\nversion = \"0.0.0\"\nedition = \"2024\"\nbuild = \"build.rs\"\n\n\
         [lib]\ncrate-type = [\"cdylib\"]\n",
    )
    .expect("manifest");
    std::fs::write(ws.path().join("src/lib.rs"), "").expect("lib");
    std::fs::write(
        ws.path().join("build.rs"),
        format!(
            "fn main() {{\n\
               if std::fs::read_to_string({:?}).is_ok() {{ panic!(\"READ-OK\"); }}\n\
               if std::net::UdpSocket::bind(\"0.0.0.0:0\").and_then(|s| s.send_to(b\"x\", \"192.0.2.1:9\")).is_ok() {{ panic!(\"NET-OK\"); }}\n\
             }}\n",
            secret.display().to_string()
        ),
    )
    .expect("build.rs");
    let r = build_in_sandbox(ws.path(), "probe-ffi", &Confinement::default());
    // The script ran (the build succeeded) and both of its attempts were refused.
    let msg = match &r {
        Ok(_) => String::new(),
        Err(e) => e.to_string(),
    };
    assert!(r.is_ok(), "{msg}");
    assert!(!msg.contains("READ-OK"), "{msg}");
    assert!(!msg.contains("NET-OK"), "{msg}");
    assert!(!msg.contains("HOME-SECRET"), "{msg}");
}

//! Tests of [`super`]: the confinement is exercised by a small probe program that tries what a
//! confined child must not be able to do.

use std::os::unix::process::CommandExt;

use super::*;

/// A small program, built unconfined by the test, that tries things a confined child must not
/// be able to do and prints one `key=value` line each.
const PROBE: &str = r#"
use std::io::Read;
unsafe extern "C" {
    fn socket(d: i32, t: i32, p: i32) -> i32;
    fn sendto(fd: i32, b: *const u8, n: usize, f: i32, a: *const u8, l: u32) -> isize;
    fn fork() -> i32;
    fn getppid() -> i32;
}
fn readable(p: &str) -> &'static str {
    let mut s = Vec::new();
    match std::fs::File::open(p).and_then(|mut f| f.read_to_end(&mut s).map(|_| ())) {
        Ok(()) => "ok",
        Err(_) => "blocked",
    }
}
fn main() {
    unsafe {
        let fd = socket(2, 2, 0);
        let udp = if fd < 0 {
            "blocked"
        } else {
            // sockaddr_in 192.0.2.1:9
            let a: [u8; 16] = [2, 0, 0, 9, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
            if sendto(fd, b"x".as_ptr(), 1, 0, a.as_ptr(), 16) < 0 { "blocked" } else { "SENT" }
        };
        println!("udp={udp}");
        println!("unix={}", if socket(1, 1, 0) < 0 { "blocked" } else { "ok" });
        println!("fork={}", if fork() < 0 { "blocked" } else { "FORKED" });
        println!("parent_cmdline={}", readable(&format!("/proc/{}/cmdline", getppid())));
    }
    println!("etc_passwd={}", readable("/etc/passwd"));
    println!("proc_self_maps={}", readable("/proc/self/maps"));
    println!("write_cwd={}", if std::fs::write("probe-out.txt", "x").is_ok() { "ok" } else { "blocked" });
}
"#;

fn rustc() -> Option<PathBuf> {
    let c = std::env::var_os("RUSTC")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("rustc"));
    Command::new(&c)
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .ok()
        .filter(|s| s.success())
        .map(|_| c)
}

fn run_probe(scope: ReadScope, opts: &Confinement) -> Option<(String, ConfinementReport)> {
    if landlock_abi_version() < LANDLOCK_ABI_FLOOR {
        eprintln!(
            "skipped: Landlock ABI {} is below the floor",
            landlock_abi_version()
        );
        return None;
    }
    let Some(rustc) = rustc() else {
        eprintln!("skipped: no rustc to build the probe");
        return None;
    };
    let dir = scratch_dir("kraken-sandbox-test-").expect("scratch");
    std::fs::write(dir.path().join("probe.rs"), PROBE).expect("write");
    let exe = dir.path().join("probe");
    let st = Command::new(&rustc)
        .args(["--edition", "2024", "-o"])
        .arg(&exe)
        .arg(dir.path().join("probe.rs"))
        .status()
        .expect("rustc");
    assert!(st.success());
    let mut cmd = Command::new(&exe);
    let report = confine(&mut cmd, dir.path(), scope, opts).expect("confine");
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(20),
        1 << 16,
        Duration::from_millis(5),
    )
    .expect("run");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.is_some_and(|s| s.success()),
        "probe failed: {:?}\n{text}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    Some((text, report))
}

fn assert_lines(text: &str, wants: &[&str]) {
    for want in wants {
        assert!(
            text.lines().any(|l| l == *want),
            "missing `{want}` in:\n{text}"
        );
    }
}

const RUNNER_EXPECTED: &[&str] = &[
    "udp=blocked",
    "unix=blocked",
    "fork=blocked",
    "parent_cmdline=blocked",
    "etc_passwd=blocked",
    "proc_self_maps=ok",
    "write_cwd=ok",
];

#[test]
fn a_runner_has_no_network_no_fork_and_reads_only_its_own_proc() {
    let Some((text, report)) = run_probe(ReadScope::SystemLibraries, &Confinement::default())
    else {
        return;
    };
    assert_lines(&text, RUNNER_EXPECTED);
    assert!(report.landlock_abi >= LANDLOCK_ABI_FLOOR);
    assert_ne!(report.network, NetworkIsolation::None);
}

#[test]
fn the_seccomp_fallback_alone_keeps_a_runner_off_the_network() {
    let opts = Confinement {
        seccomp_only: true,
        ..Confinement::default()
    };
    let Some((text, report)) = run_probe(ReadScope::SystemLibraries, &opts) else {
        return;
    };
    assert_eq!(report.network, NetworkIsolation::Seccomp);
    assert!(report.label().ends_with("+seccomp"));
    assert_lines(&text, RUNNER_EXPECTED);
}

#[test]
fn the_compile_scope_allows_unix_sockets_but_not_inet_and_cannot_read_etc() {
    let opts = Confinement {
        seccomp_only: true,
        ..Confinement::default()
    };
    let Some((text, _)) = run_probe(ReadScope::Toolchain, &opts) else {
        return;
    };
    assert_lines(
        &text,
        &[
            "udp=blocked",
            "unix=ok",
            "etc_passwd=blocked",
            "parent_cmdline=blocked",
        ],
    );
}

#[test]
fn a_host_below_the_abi_floor_or_without_network_isolation_refuses() {
    let e = imp::refusal_for_test(3, NetworkIsolation::Namespace).to_string();
    assert!(e.contains("below the required 4"), "{e}");
    let e = imp::refusal_for_test(6, NetworkIsolation::None).to_string();
    assert!(e.contains("no network isolation"), "{e}");
    assert!(e.contains("allow_unconfined"), "{e}");
}

#[test]
fn seccomp_programs_are_well_formed() {
    for scope in [ReadScope::Toolchain, ReadScope::SystemLibraries] {
        let p = imp::seccomp_program_for_test(scope);
        assert!(p.len() < 64);
        // Every jump lands inside the program, and the last instruction returns.
        for (i, ins) in p.iter().enumerate() {
            if ins.code == 0x15 || ins.code == 0x45 {
                assert!(i + 1 + (ins.jt as usize).max(ins.jf as usize) < p.len());
            }
        }
        assert_eq!(p.last().map(|i| i.code), Some(0x06));
    }
}

#[test]
fn a_timeout_kills_the_whole_process_group_and_returns_promptly() {
    let dir = tempfile::tempdir().expect("dir");
    let pidfile = dir.path().join("grandchild.pid");
    let mut cmd = Command::new("sh");
    cmd.arg("-c")
        .arg(format!(
            "sleep 300 & echo $! > '{}'; sleep 300",
            pidfile.display()
        ))
        .process_group(0);
    let t = Instant::now();
    let out = run_captured(
        &mut cmd,
        Duration::from_millis(600),
        1024,
        Duration::from_millis(5),
    )
    .expect("run");
    assert!(out.status.is_none(), "should have timed out");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    let pid: i32 = std::fs::read_to_string(&pidfile)
        .expect("pid file")
        .trim()
        .parse()
        .expect("pid");
    // The grandchild is gone (or a zombie awaiting its reaper) shortly after.
    let mut alive = true;
    for _ in 0..100 {
        // SAFETY: signal 0 only checks that the process exists.
        alive = unsafe { libc::kill(pid, 0) } == 0
            && std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|s| !s.contains(") Z "));
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!alive, "grandchild {pid} survived the timeout");
}

#[test]
fn a_background_process_holding_the_pipe_is_killed_with_its_group() {
    let mut cmd = Command::new("sh");
    // The shell exits at once; its background job keeps stdout open but is in the group and
    // gets killed.
    cmd.arg("-c").arg("sleep 300 & echo hi").process_group(0);
    let t = Instant::now();
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(20),
        1024,
        Duration::from_millis(5),
    )
    .expect("run");
    assert!(out.status.is_some_and(|s| s.success()));
    assert_eq!(out.stdout, b"hi\n");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
}

#[test]
fn a_descendant_that_escaped_the_group_still_cannot_hang_the_caller() {
    let mut cmd = Command::new("sh");
    // `setsid` puts the sleeper in another session: the group kill misses it, its reader thread
    // stays blocked on the pipe, and the bounded wait must still return.
    cmd.arg("-c")
        .arg("setsid sleep 6 & echo hi")
        .process_group(0);
    let t = Instant::now();
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(20),
        1024,
        Duration::from_millis(5),
    )
    .expect("run");
    assert!(out.status.is_some_and(|s| s.success()));
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
}

#[test]
fn scratch_directories_are_private_and_not_under_a_shared_tmp() {
    use std::os::unix::fs::MetadataExt;
    let d = scratch_dir("kraken-scratch-test-").expect("scratch");
    let root = d.path().parent().expect("root");
    let md = std::fs::metadata(root).expect("meta");
    assert_eq!(md.mode() & 0o077, 0, "{:o}", md.mode());
    // SAFETY: geteuid cannot fail.
    assert_eq!(md.uid(), unsafe { libc::geteuid() });
    assert_ne!(root, Path::new("/tmp"));
    assert_eq!(std::fs::metadata(d.path()).expect("meta").mode() & 0o077, 0);
}

#[test]
fn a_cargo_config_above_the_scratch_root_is_refused() {
    let base = tempfile::tempdir().expect("dir");
    let root = base.path().join("a/b");
    std::fs::create_dir_all(&root).expect("mkdir");
    // The system temp dir may itself sit below a cargo config; only the new one matters.
    let before = check_no_cargo_config(&root);
    std::fs::create_dir_all(base.path().join(".cargo")).expect("mkdir");
    std::fs::write(
        base.path().join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"/tmp/evil\"\n",
    )
    .expect("write");
    let after = check_no_cargo_config(&root).expect_err("must refuse");
    assert!(after.contains("config.toml"), "{after}");
    if let Err(e) = before {
        assert!(!e.contains(&base.path().display().to_string()), "{e}");
    }
}

// ----- extra read paths, no-exec directories, limits -----

/// Runs `sh -c script` confined in a fresh scratch directory; `None` when the host cannot
/// confine.
fn run_sh(script: &str, opts: &Confinement) -> Option<String> {
    if landlock_abi_version() < LANDLOCK_ABI_FLOOR || !enforced() {
        eprintln!("skipped: the host cannot confine");
        return None;
    }
    let dir = scratch_dir("kraken-confine-test-").expect("scratch");
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c").arg(script);
    confine(&mut cmd, dir.path(), ReadScope::Toolchain, opts).expect("confine");
    let out = run_captured(
        &mut cmd,
        Duration::from_secs(20),
        1 << 16,
        Duration::from_millis(5),
    )
    .expect("run");
    Some(String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr))
}

const WRITE_AND_RUN: &str = "cat /usr/bin/true > t; chmod +x t; ./t; echo rc=$?";

#[test]
fn a_file_written_in_the_working_dir_runs_unless_exec_is_denied() {
    let Some(allowed) = run_sh(WRITE_AND_RUN, &Confinement::default()) else {
        return;
    };
    assert!(allowed.contains("rc=0"), "{allowed}");
    let opts = Confinement {
        deny_exec_in_dir: true,
        ..Confinement::default()
    };
    let denied = run_sh(WRITE_AND_RUN, &opts).expect("same host");
    assert!(
        denied.contains("rc=126") || denied.contains("rc=127"),
        "{denied}"
    );
    assert!(!denied.contains("rc=0"), "{denied}");
}

#[test]
fn an_extra_read_path_is_readable_and_not_writable() {
    let extra = tempfile::tempdir().expect("dir");
    let file = extra.path().join("sample.txt");
    std::fs::write(&file, "payload").expect("write");
    let opts = Confinement {
        extra_read_paths: vec![extra.path().to_path_buf()],
        deny_exec_in_dir: true,
        ..Confinement::default()
    };
    let script = format!(
        "cat '{f}'; echo x > '{f}' && echo WROTE; echo y > '{d}/new' && echo CREATED; echo done",
        f = file.display(),
        d = extra.path().display()
    );
    let Some(out) = run_sh(&script, &opts) else {
        return;
    };
    assert!(out.contains("payload"), "{out}");
    assert!(!out.contains("WROTE") && !out.contains("CREATED"), "{out}");
    assert!(out.contains("done"), "{out}");
    assert_eq!(std::fs::read_to_string(&file).expect("read"), "payload");
    // Without the extra path the file is invisible.
    let plain = run_sh(
        &format!("cat '{}'", file.display()),
        &Confinement::default(),
    );
    if let Some(plain) = plain {
        assert!(!plain.contains("payload"), "{plain}");
    }
}

#[test]
fn limits_are_applied_in_the_child() {
    let opts = Confinement {
        limits: Some(Limits {
            address_space: 3 << 30,
            cpu_seconds: 17,
            file_size: 5 << 20,
            processes: 100_000,
        }),
        ..Confinement::default()
    };
    let Some(out) = run_sh("cat /proc/self/limits", &opts) else {
        return;
    };
    let value = |name: &str| {
        out.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l[name.len()..].split_whitespace().next())
            .map(str::to_owned)
            .unwrap_or_default()
    };
    assert_eq!(
        value("Max address space"),
        (3u64 << 30).to_string(),
        "{out}"
    );
    assert_eq!(value("Max cpu time"), "17", "{out}");
    assert_eq!(value("Max file size"), (5u64 << 20).to_string(), "{out}");
    assert_eq!(value("Max processes"), "100000", "{out}");
}

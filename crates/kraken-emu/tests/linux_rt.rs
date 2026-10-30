//! The `corpus/linux-rt` programs (descriptors, pipes, directories, sleeping, polling) run under
//! emulation on x86-64 and AArch64: stdout and exit status must equal what the x86-64 build
//! printed natively (`corpus/linux-rt/build.sh record`).

mod common;

use common::*;
use kraken_emu::{Arch, Exit, RunSpec, run_program};

const PROGRAMS: [&str; 5] = ["fd_dup", "pipes", "dirs", "sleeping", "polling"];

fn expected(name: &str) -> (String, i32) {
    let dir = corpus().join("linux-rt/expected");
    let out = std::fs::read_to_string(dir.join(format!("{name}.stdout"))).expect("expected stdout");
    let code = std::fs::read_to_string(dir.join(format!("{name}.exit")))
        .expect("expected exit")
        .trim()
        .parse()
        .expect("exit code");
    (out, code)
}

fn run_all(arch: Arch, suffix: &str) {
    let _ = specs(arch);
    for name in PROGRAMS {
        let (want, code) = expected(name);
        let mut spec = RunSpec::new(bin("linux-rt", &format!("{name}-{suffix}")));
        spec.stdin = b"go".to_vec();
        let out = run_program(&spec).unwrap_or_else(|e| panic!("{name}-{suffix}: {e}"));
        eprintln!(
            "{name}-{suffix}: {} | {} insns; unknown {:?}",
            out.exit.describe(),
            out.instructions,
            out.unknown_syscalls
        );
        assert_eq!(out.exit, Exit::Code { code }, "{name}-{suffix}");
        assert!(out.unknown_syscalls.is_empty(), "{name}-{suffix}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            want,
            "{name}-{suffix}"
        );
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn linux_rt_programs_match_the_native_run_on_x86_64() {
    run_all(Arch::X86_64, "x86_64");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn linux_rt_programs_match_the_native_run_on_aarch64() {
    run_all(Arch::Aarch64, "aarch64");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn sleeping_is_virtual_time_and_costs_no_wall_clock() {
    let _ = specs(Arch::X86_64);
    let mut spec = RunSpec::new(bin("linux-rt", "sleeping-x86_64"));
    spec.timeout_ms = 5_000;
    let out = run_program(&spec).expect("run");
    assert_eq!(out.exit, Exit::Code { code: 0 });
    // About 8 seconds of sleeping must pass in far less than that of real time.
    assert!(out.elapsed_ms < 4_000, "{} ms", out.elapsed_ms);
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn directories_made_by_the_guest_stay_in_its_work_directory() {
    let _ = specs(Arch::X86_64);
    let dir = tempfile::tempdir().expect("tmp");
    let mut spec = RunSpec::new(bin("linux-rt", "dirs-x86_64"));
    spec.workdir = Some(dir.path().to_path_buf());
    let out = run_program(&spec).expect("run");
    assert_eq!(out.exit, Exit::Code { code: 0 });
    assert!(dir.path().join("sub/b.txt").is_file());
    assert!(dir.path().join("sub/d.txt").is_file());
    assert!(dir.path().join("inner2").is_dir());
    assert!(!dir.path().join("a.txt").exists());
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn stepping_back_over_sleeps_replays_the_same_clock() {
    use kraken_emu::session::{Session, SessionStop, Target};
    let _ = specs(Arch::X86_64);
    let spec = RunSpec::new(bin("linux-rt", "sleeping-x86_64"));
    let whole = Session::new(Target::Program(spec.clone())).expect("session");
    assert!(matches!(
        whole.run(10_000_000).expect("run"),
        SessionStop::Exited { .. }
    ));
    let end = whole.icount().expect("icount");
    // Just before the exit: every sleep and clock read is behind, their times on the stack.
    let s = Session::new(Target::Program(spec)).expect("session");
    let state = |s: &Session| {
        let sp = s.read_reg("RSP").expect("sp");
        (
            s.registers().expect("registers"),
            s.read_memory(sp - 0x200, 0x400).expect("stack"),
        )
    };
    assert_eq!(s.step(end - 20).expect("step"), SessionStop::Stepped);
    let first = state(&s);
    assert_eq!(
        s.reverse_step(end).expect("back"),
        SessionStop::HistoryStart
    );
    assert_eq!(s.step(end - 20).expect("again"), SessionStop::Stepped);
    assert_eq!(state(&s), first, "the replay read the same clock");
}

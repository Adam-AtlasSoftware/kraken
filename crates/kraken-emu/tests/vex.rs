//! The x86-64-v3 instruction set against a real CPU: `corpus/linux-rt/src/vex_ops.c` runs one
//! instruction per case from a fixed state and prints what changed; `expected/vex_ops.stdout` was
//! recorded on real hardware (`corpus/linux-rt/build.sh record`), so this test needs none. Programs
//! built for x86-64-v3 are checked on a C library of that kind when `KRAKEN_EMU_V3_SYSROOT` names
//! one (Ubuntu's `libc6:amd64v3`, or the libraries of such a host).

mod common;

use common::*;
use kraken_emu::{Arch, Exit, RunSpec, run_program};

fn case_name(line: &str) -> &str {
    line.split(':').next().unwrap_or(line)
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn every_vex_case_matches_the_recorded_cpu() {
    let _ = specs(Arch::X86_64);
    let dir = corpus().join("linux-rt");
    let want = std::fs::read_to_string(dir.join("expected/vex_ops.stdout")).expect("expected");
    let mut spec = RunSpec::new(bin("linux-rt", "vex_ops-x86_64"));
    spec.max_instructions = 200_000_000;
    spec.timeout_ms = 120_000;
    let out = run_program(&spec).expect("run");
    let got = String::from_utf8_lossy(&out.stdout);
    let got: Vec<&str> = got.lines().collect();
    let want: Vec<&str> = want.lines().collect();
    let bad: Vec<String> = want
        .iter()
        .zip(&got)
        .filter(|(w, g)| w != g)
        .map(|(w, g)| format!("{}\n  want{w}\n  got {g}", case_name(w)))
        .collect();
    assert!(
        bad.is_empty(),
        "{} of {} cases differ:\n{}",
        bad.len(),
        want.len(),
        bad.join("\n")
    );
    assert_eq!(
        out.exit,
        Exit::Code { code: 0 },
        "stopped after {}: {}",
        got.last().map_or("(no case)", |l| case_name(l)),
        out.exit.describe()
    );
    assert_eq!(got.len(), want.len());
}

#[test]
#[ignore = "needs Ghidra processor sources and KRAKEN_EMU_V3_SYSROOT"]
fn dynamic_programs_run_on_a_c_library_built_for_x86_64_v3() {
    let Some(root) = std::env::var_os("KRAKEN_EMU_V3_SYSROOT").filter(|v| !v.is_empty()) else {
        eprintln!("SKIP: KRAKEN_EMU_V3_SYSROOT is not set");
        return;
    };
    let _ = specs(Arch::X86_64);
    for program in ["pie_list-O2", "stripped_calc-O2", "switch_vm-O2"] {
        let mut spec = RunSpec::new(bin("", program));
        spec.sysroot = Some(root.clone().into());
        let out = run_program(&spec).unwrap_or_else(|e| panic!("{program}: {e}"));
        let name = program.split('-').next().unwrap_or(program);
        assert_eq!(out.exit, Exit::Code { code: 0 }, "{program}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            expected_stdout(name),
            "{program}"
        );
    }
}

//! Whole-program runs of the cross-architecture corpus under emulation, compared with the
//! outputs `corpus/<set>/QEMU-CHECK.txt` and `corpus/expected` record.

mod common;

use common::*;
use kraken_emu::{EmuError, Exit, RunSpec, run_program};

const IGNORE: &str =
    "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)";

fn run(set: &str, name: &str, sysroot: Option<std::path::PathBuf>) -> kraken_emu::ProgramOutcome {
    let path = bin(set, name);
    let _ = specs(set_arch(set));
    let mut spec = RunSpec::new(&path);
    spec.sysroot = sysroot;
    let out = run_program(&spec).unwrap_or_else(|e| panic!("{name}: {e}"));
    eprintln!(
        "{name}: {} | {} insns in {} ms ({:.1} M insn/s), setup {} ms; syscalls {:?}; unknown {:?}",
        out.exit.describe(),
        out.instructions,
        out.elapsed_ms,
        out.ips() / 1e6,
        out.setup_ms,
        out.syscalls,
        out.unknown_syscalls
    );
    out
}

fn check(set: &str, program: &str, name: &str, out: &kraken_emu::ProgramOutcome) {
    let want = want_stdout(set, program);
    assert_eq!(
        out.exit,
        Exit::Code { code: 0 },
        "{name}: stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), want, "{name}");
    assert!(
        out.stderr.is_empty(),
        "{name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn static_set(set: &str) {
    for opt in ["O0", "O2", "O0-stripped", "O2-stripped"] {
        let name = format!("static_strops-{set}-{opt}");
        let out = run(set, &name, None);
        check(set, "static_strops", &name, &out);
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn static_strops_runs_on_arm32() {
    let _ = IGNORE;
    static_set("arm32");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn static_strops_runs_on_aarch64() {
    static_set("aarch64");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn static_strops_runs_on_riscv64() {
    static_set("riscv64");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn static_strops_runs_on_x86_64() {
    let name = "static_strops-O0";
    let path = corpus().join("bin").join(name);
    let _ = specs(kraken_emu::Arch::X86_64);
    let out = run_program(&RunSpec::new(&path)).expect("run");
    check("elf", "static_strops", name, &out);
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn every_riscv32_binary_runs() {
    for program in ["pie_list", "static_strops", "stripped_calc", "switch_vm"] {
        for opt in ["O0", "O2", "O0-stripped", "O2-stripped"] {
            let name = format!("{program}-riscv32-{opt}");
            let out = run("riscv32", &name, None);
            check("riscv32", program, &name, &out);
        }
    }
}

fn dynamic_set(set: &str) {
    let sysroot = sysroot(set);
    let mut names = Vec::new();
    // The 32-bit x86 set has pie_list and switch_vm only, named `-i386-`.
    let (programs, tag): (&[&str], &str) = if set == "elf32" {
        (&["pie_list", "switch_vm"], "i386")
    } else {
        (&["pie_list", "stripped_calc", "switch_vm"], set)
    };
    for program in programs {
        for opt in ["O0", "O2", "O0-stripped", "O2-stripped"] {
            names.push((*program, format!("{program}-{tag}-{opt}")));
        }
    }
    if set == "arm32" {
        for opt in ["O0", "O2", "O0-stripped", "O2-stripped"] {
            names.push(("switch_vm", format!("switch_vm-arm32-thumb-{opt}")));
        }
    }
    for (program, name) in names {
        match &sysroot {
            Some(root) => {
                let out = run(set, &name, Some(root.clone()));
                check(set, program, &name, &out);
            }
            None => {
                let path = bin(set, &name);
                match run_program(&RunSpec::new(&path)) {
                    Err(EmuError::NeedsSysroot { interp, .. }) => {
                        eprintln!("{name}: refused without a sysroot (interpreter {interp})");
                    }
                    other => panic!("{name}: expected a sysroot refusal, got {other:?}"),
                }
            }
        }
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn dynamic_x86_programs_run_with_a_sysroot_or_are_refused() {
    dynamic_set("elf32");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn dynamic_arm32_programs_run_with_a_sysroot_or_are_refused() {
    dynamic_set("arm32");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn dynamic_aarch64_programs_run_with_a_sysroot_or_are_refused() {
    dynamic_set("aarch64");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn dynamic_riscv64_programs_run_with_a_sysroot_or_are_refused() {
    dynamic_set("riscv64");
}

#[test]
fn a_dynamic_program_without_a_sysroot_is_refused_before_any_spec_is_needed() {
    let path = bin("aarch64", "switch_vm-aarch64-O0");
    let mut spec = RunSpec::new(&path);
    spec.spec_roots = vec!["/nonexistent".into()];
    match run_program(&spec) {
        Err(e @ EmuError::NeedsSysroot { .. }) => {
            let msg = e.to_string();
            assert!(msg.contains("ld-linux-aarch64.so.1"), "{msg}");
            assert!(msg.contains("emu-sysroots"), "{msg}");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

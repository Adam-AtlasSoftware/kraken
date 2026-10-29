//! The stepping API on every Linux architecture: break at `main`, step, step over a call, read
//! registers and memory, disassemble, snapshot and restore, run to the exit.

mod common;

use common::*;
use kraken_emu::session::{Session, SessionStop, Target};
use kraken_emu::{Exit, RunSpec};

const BUDGET: u64 = 50_000_000;

fn walk(set: &str, name: &str, sysroot: Option<std::path::PathBuf>) {
    let path = bin(set, name);
    let arch = set_arch(set);
    let _ = specs(arch);
    let mut spec = RunSpec::new(&path);
    spec.sysroot = sysroot;
    let s = Session::new(Target::Program(spec)).expect("session");
    assert_eq!(s.arch(), arch);
    let main = s.symbol("main").expect("symbol").expect("main");
    assert!(s.add_breakpoint(main).expect("bp"));
    assert_eq!(s.breakpoints().expect("bps"), vec![main & !1]);
    match s.run(BUDGET).expect("run") {
        SessionStop::Breakpoint { pc } => assert_eq!(pc, main & !1, "{name}"),
        other => panic!("{name}: expected the main breakpoint, got {other:?}"),
    }
    assert_eq!(s.pc().expect("pc"), main & !1);
    assert_eq!(s.thumb().expect("thumb"), main & 1 == 1, "{name}");
    let regs = s.registers().expect("regs");
    let pc_name = arch.pc_reg();
    let pc_reg = regs
        .iter()
        .find(|(n, _)| n == pc_name)
        .expect("pc register");
    assert_eq!(pc_reg.1, main & !1);
    let sp = s.read_reg(arch.sp_reg()).expect("sp");
    assert_eq!(s.read_memory(sp, 16).expect("stack").len(), 16);
    let listing = s.disasm(None, 4).expect("disasm");
    assert_eq!(listing.len(), 4, "{name}: {listing:?}");
    assert!(listing.iter().all(|i| !i.text.is_empty() && i.len > 0));
    eprintln!(
        "{name}: main at {main:#x}: {}",
        listing
            .iter()
            .map(|i| i.text.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    );

    // Single steps are exact.
    let before = s.icount().expect("icount");
    assert_eq!(s.step(3).expect("step"), SessionStop::Stepped);
    assert_eq!(s.icount().expect("icount") - before, 3, "{name}");

    // Stepping over every instruction of main until the first call has been stepped over: the
    // program counter always lands in main, never in a callee.
    let snap = s.snapshot().expect("snapshot");
    let mut stepped_over_call = false;
    for _ in 0..200 {
        let pc = s.pc().expect("pc");
        let len = s.disasm(None, 1).expect("disasm")[0].len;
        let icount = s.icount().expect("icount");
        match s.step_over(BUDGET).expect("step over") {
            SessionStop::Stepped => {}
            other => panic!("{name}: step over ended with {other:?}"),
        }
        let now = s.pc().expect("pc");
        if now == pc + len && s.icount().expect("icount") - icount > 1 {
            stepped_over_call = true;
            break;
        }
    }
    assert!(stepped_over_call, "{name}: no call stepped over in main");

    // To the end, then again from the snapshot: the same output.
    s.remove_breakpoint(main).expect("remove");
    let end = s.run(BUDGET).expect("run");
    assert_eq!(
        end,
        SessionStop::Exited {
            exit: Exit::Code { code: 0 }
        },
        "{name}"
    );
    let (out1, _) = s.output().expect("output");
    let program = name.split('-').next().expect("program");
    assert_eq!(
        String::from_utf8_lossy(&out1),
        want_stdout(set, program),
        "{name}"
    );
    s.restore(snap).expect("restore");
    let end = s.run(BUDGET).expect("run");
    assert_eq!(
        end,
        SessionStop::Exited {
            exit: Exit::Code { code: 0 }
        },
        "{name}"
    );
    let (out2, _) = s.output().expect("output");
    assert_eq!(out1, out2, "{name}: replay from the snapshot");
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn stepping_through_static_programs_on_every_architecture() {
    for set in ["arm32", "aarch64", "riscv64", "riscv32"] {
        walk(set, &format!("static_strops-{set}-O0"), None);
    }
    walk("riscv32", "switch_vm-riscv32-O2", None);
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn stepping_through_thumb_code() {
    let Some(root) = sysroot("arm32") else {
        eprintln!("SKIP: no arm32 sysroot (cargo xtask emu-sysroots)");
        return;
    };
    walk("arm32", "switch_vm-arm32-thumb-O2", Some(root));
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs (KRAKEN_GHIDRA_HOME or the dev cache)"]
fn a_function_session_steps_to_the_return() {
    use kraken_emu::call::{Callee, RetKind, Value};
    let path = bin("riscv32", "switch_vm-riscv32-O0");
    let _ = specs(kraken_emu::Arch::Riscv32);
    let s = Session::new(Target::Function {
        program: path,
        callee: Callee::Symbol("op_name".into()),
        args: vec![Value::i32(2)],
        ret: RetKind::Int { bits: 32 },
        pie_bias: 0,
        spec_roots: Vec::new(),
    })
    .expect("session");
    assert_eq!(s.step(1).expect("step"), SessionStop::Stepped);
    match s.run(10_000).expect("run") {
        SessionStop::Returned { ret: Some(p) } => {
            let name = s.read_memory(p, 4).expect("string");
            assert_eq!(&name, b"add\0");
        }
        other => panic!("expected a return, got {other:?}"),
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs"]
fn an_interrupt_stops_a_run_and_the_session_goes_on() {
    let _ = specs(kraken_emu::Arch::Riscv32);
    let s = Session::new(Target::Program(RunSpec::new(bin(
        "riscv32",
        "switch_vm-riscv32-O2",
    ))))
    .expect("session");
    s.interrupter().interrupt();
    let stop = s.run(1_000_000_000).expect("run");
    assert_eq!(stop, SessionStop::Interrupted);
    assert!(matches!(
        s.run(1_000_000_000).expect("run on"),
        SessionStop::Exited { .. }
    ));
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs"]
fn a_breakpoint_inside_an_executed_block_stops_the_run() {
    let _ = specs(kraken_emu::Arch::X86_64);
    let s =
        Session::new(Target::Program(RunSpec::new(bin("", "static_strops-O0")))).expect("session");
    let main = s.symbol("main").expect("symbols").expect("main");
    assert!(matches!(
        s.run_to(main, BUDGET).expect("to main"),
        SessionStop::Reached { .. }
    ));
    let insns = s.disasm(None, 4).expect("disasm");
    let ahead = insns[1].addr;
    s.add_breakpoint(ahead).expect("break");
    let stop = s.run(BUDGET).expect("run");
    assert_eq!(stop, SessionStop::Breakpoint { pc: ahead });
    assert_eq!(s.pc().expect("pc"), ahead);
}

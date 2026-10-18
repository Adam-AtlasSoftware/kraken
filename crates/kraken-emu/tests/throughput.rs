//! Emulation speed per architecture: switch_vm's `vm_run` on a loop of 720 000 iterations (about
//! 2.2 million VM operations), timed, and checked for the same result everywhere. Run it with
//! `--release` for meaningful numbers.

mod common;

use std::time::Instant;

use common::*;
use kraken_emu::Arch;
use kraken_emu::call::{CallSpec, CallTermination, Callee, FunctionCaller, RetKind, Value};

/// PUSH 120; PUSH 120; MUL; PUSH 50; MUL; loop: DEC; DUP; JNZ loop; HALT.
const LOOP: &[u8] = &[1, 120, 1, 120, 4, 1, 50, 4, 10, 5, 9, 8, 0];

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs; a measurement, best with --release"]
fn vm_run_throughput_per_architecture() {
    let targets = [
        corpus().join("bin/switch_vm-O2"),
        corpus().join("elf32/bin/switch_vm-i386-O2"),
        bin("arm32", "switch_vm-arm32-O2"),
        bin("arm32", "switch_vm-arm32-thumb-O2"),
        bin("aarch64", "switch_vm-aarch64-O2"),
        bin("riscv64", "switch_vm-riscv64-O2"),
        bin("riscv32", "switch_vm-riscv32-O2"),
    ];
    for t in targets {
        let data = std::fs::read(&t).expect("read");
        let arch = Arch::from_elf(&data).expect("arch");
        let mut fc = FunctionCaller::load_elf(&data, 0x5555_5555_0000, &specs(arch)).expect("load");
        let vm = fc.alloc(&[0u8; 144]).expect("vm");
        let code = fc.alloc(LOOP).expect("code");
        let start = Instant::now();
        let out = fc
            .call(&CallSpec {
                callee: Callee::Symbol("vm_run".into()),
                args: vec![
                    Value::ptr(arch, vm),
                    Value::ptr(arch, code),
                    Value::i32(LOOP.len() as i32),
                ],
                ret: RetKind::Int { bits: 32 },
                max_instructions: 2_000_000_000,
            })
            .expect("call");
        let secs = start.elapsed().as_secs_f64();
        assert_eq!(
            out.termination,
            CallTermination::Returned,
            "{}",
            t.display()
        );
        assert_eq!(out.ret, Some(0));
        let steps = fc.machine().read_uint(vm + 136, 4).expect("steps");
        assert_eq!(steps, 5 + 720_000 * 3 + 1);
        eprintln!(
            "{:<28} {:>11} instructions in {:>6.2} s: {:>6.1} M instructions/s",
            t.file_name().unwrap().to_string_lossy(),
            out.instructions,
            secs,
            out.instructions as f64 / secs / 1e6
        );
    }
}

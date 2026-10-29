//! Which watched instruction addresses run: the evidence behind block coverage.
//!
//! A diamond (`if (x == 0) y = 2; else y = 1;`) in hand-assembled x86-64 code: with a non-zero
//! argument the entry, the "else" arm and the join run, never the "then" arm.

use kraken_emu::{Arch, Machine, Perm, Stop};

const CODE: u64 = 0x1000;
const STACK: u64 = 0x8000;
const RETURN: u64 = 0x9000;

// 0x1000 cmp edi, 0
// 0x1003 je   0x100c
// 0x1005 mov  eax, 1
// 0x100a jmp  0x1011
// 0x100c mov  eax, 2
// 0x1011 ret
const DIAMOND: [u8; 18] = [
    0x83, 0xff, 0x00, 0x74, 0x07, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xeb, 0x05, 0xb8, 0x02, 0x00, 0x00,
    0x00, 0xc3,
];
const BLOCKS: [u64; 4] = [0x1000, 0x1005, 0x100c, 0x1011];

/// The machine, or `None` (skipped) when the SLEIGH specs are missing and `KRAKEN_REQUIRE_SPECS`
/// is not set.
fn machine() -> Option<Machine> {
    let specs = kraken_emu::SpecRoots::discover();
    if specs.processors_for(Arch::X86_64).is_err() {
        assert!(
            std::env::var("KRAKEN_REQUIRE_SPECS").is_err(),
            "KRAKEN_REQUIRE_SPECS is set but no SLEIGH specs were found"
        );
        eprintln!("skipped: no SLEIGH specs");
        return None;
    }
    let mut m = Machine::new(Arch::X86_64, &specs).expect("machine");
    m.map(CODE, 0x1000, Perm::RWX).expect("code");
    m.map(STACK - 0x1000, 0x2000, Perm::RW).expect("stack");
    m.map(RETURN, 0x1000, Perm::RX).expect("return page");
    m.write_mem(CODE, &DIAMOND).expect("write code");
    m.add_breakpoint(RETURN);
    Some(m)
}

fn call(m: &mut Machine, arg: u64) -> u64 {
    m.write_reg("RDI", arg).expect("rdi");
    m.set_sp(STACK);
    m.write_ptr(STACK, RETURN).expect("return address");
    m.set_pc(CODE);
    match m.run(10_000) {
        Stop::Breakpoint { pc } => assert_eq!(pc, RETURN),
        other => panic!("expected the return breakpoint, got {other:?}"),
    }
    m.read_reg("RAX").expect("rax") & 0xffff_ffff
}

#[test]
fn only_the_arm_that_ran_is_reported() {
    let Some(mut m) = machine() else { return };
    let log = m.track_addresses(&BLOCKS);

    assert_eq!(call(&mut m, 5), 1);
    let hit: Vec<u64> = log.take().into_iter().collect();
    assert_eq!(hit, [0x1000, 0x1005, 0x1011], "the 0x100c arm did not run");

    // The log was emptied, and the other arm shows up on its own.
    assert_eq!(call(&mut m, 0), 2);
    let hit: Vec<u64> = log.take().into_iter().collect();
    assert_eq!(hit, [0x1000, 0x100c, 0x1011], "the 0x1005 arm did not run");
    assert!(log.take().is_empty(), "nothing runs between calls");
}

#[test]
fn a_machine_without_a_watch_records_nothing_and_still_runs() {
    let Some(mut m) = machine() else { return };
    assert_eq!(call(&mut m, 1), 1);
    assert_eq!(call(&mut m, 0), 2);
}

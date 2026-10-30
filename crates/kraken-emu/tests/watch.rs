//! Watchpoints and reverse execution on `pie_list-O0`: a write watch on the head of the list
//! stops with the new node as its value, stepping back and forward again reproduces registers
//! and memory exactly, and reverse-continue finds the earlier write.

mod common;

use common::*;
use kraken_emu::session::{Session, SessionStop, Target, WatchKind};
use kraken_emu::{Arch, RunSpec};

const BUDGET: u64 = 200_000_000;

fn start() -> Option<Session> {
    let _ = specs(Arch::X86_64);
    let Some(root) = sysroot("x86_64") else {
        eprintln!("SKIP: no x86_64 sysroot (cargo xtask emu-sysroots)");
        return None;
    };
    let mut spec = RunSpec::new(bin("", "pie_list-O0"));
    spec.sysroot = Some(root);
    Some(Session::new(Target::Program(spec)).expect("session"))
}

/// Registers and the memory around the stack pointer.
fn state(s: &Session) -> (Vec<(String, u64)>, Vec<u8>, u64) {
    let regs = s.registers().expect("registers");
    let sp = s.read_reg("RSP").expect("sp");
    let mem = s.read_memory(sp - 0x100, 0x200).expect("stack");
    (regs, mem, s.icount().expect("icount"))
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and the x86_64 emulator sysroot"]
fn a_write_watch_on_a_list_head_reports_the_new_node() {
    let Some(s) = start() else { return };
    let push = s.symbol("list_push").expect("symbols").expect("list_push");
    s.add_breakpoint(push).expect("bp");
    assert_eq!(
        s.run(BUDGET).expect("run"),
        SessionStop::Breakpoint { pc: push }
    );
    s.remove_breakpoint(push).expect("remove bp");
    let list = s.read_reg("RDI").expect("rdi");
    let node = s.read_reg("RSI").expect("rsi");
    assert!(s.add_watchpoint(list, 8, WatchKind::Write).expect("watch"));
    assert!(!s.add_watchpoint(list, 8, WatchKind::Write).expect("again"));
    match s.run(BUDGET).expect("run") {
        SessionStop::Watch {
            addr,
            len,
            access,
            old,
            new,
            ..
        } => {
            assert_eq!((addr, len, access), (list, 8, WatchKind::Write));
            assert_eq!(new, node.to_le_bytes(), "the head is the new node");
            assert_eq!(old, vec![0; 8], "the list was empty");
        }
        other => panic!("expected a watch stop, got {other:?}"),
    }
    assert_eq!(s.read_memory(list, 8).expect("head"), node.to_le_bytes());
    // The next push writes the head again: old is the first node.
    match s.run(BUDGET).expect("run") {
        SessionStop::Watch { old, new, .. } => {
            assert_eq!(old, node.to_le_bytes());
            assert_ne!(new, old);
        }
        other => panic!("expected a second watch stop, got {other:?}"),
    }
    assert!(
        s.remove_watchpoint(list, 8, WatchKind::Write)
            .expect("remove")
    );
    assert!(s.watchpoints().expect("watches").is_empty());
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and the x86_64 emulator sysroot"]
fn a_read_watch_stops_on_a_load() {
    let Some(s) = start() else { return };
    let push = s.symbol("list_push").expect("symbols").expect("list_push");
    s.add_breakpoint(push).expect("bp");
    s.run(BUDGET).expect("run");
    s.remove_breakpoint(push).expect("remove bp");
    let list = s.read_reg("RDI").expect("rdi");
    // list_push reads the head (n->next = l->head) before writing it.
    s.add_watchpoint(list, 8, WatchKind::Read).expect("watch");
    match s.run(BUDGET).expect("run") {
        SessionStop::Watch { access, .. } => assert_eq!(access, WatchKind::Read),
        other => panic!("expected a read stop, got {other:?}"),
    }
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and the x86_64 emulator sysroot"]
fn stepping_back_and_forward_again_is_exact() {
    let Some(s) = start() else { return };
    let main = s.symbol("main").expect("symbols").expect("main");
    s.add_breakpoint(main).expect("bp");
    assert_eq!(
        s.run(BUDGET).expect("run"),
        SessionStop::Breakpoint { pc: main }
    );
    s.remove_breakpoint(main).expect("remove bp");
    // Run on past the first segment of the history, then step.
    assert_eq!(s.step(30_000).expect("step"), SessionStop::Stepped);
    let a = state(&s);
    assert_eq!(s.step(100).expect("step"), SessionStop::Stepped);
    let b = state(&s);
    assert_ne!(a.0, b.0);
    assert_eq!(s.reverse_step(100).expect("back"), SessionStop::Stepped);
    let a2 = state(&s);
    assert_eq!(a, a2, "stepping back 100 instructions restores the state");
    assert_eq!(s.step(100).expect("forward"), SessionStop::Stepped);
    assert_eq!(b, state(&s), "and forward again reaches the same state");
    // One at a time, across the snapshot boundary at 20 000 instructions.
    for _ in 0..3 {
        s.reverse_step(1).expect("back one");
    }
    assert_eq!(state(&s).2, b.2 - 3);
    // Past the start of the history.
    assert_eq!(
        s.reverse_step(u64::MAX / 2).expect("to the start"),
        SessionStop::HistoryStart
    );
    assert_eq!(s.icount().expect("icount"), 0);
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and the x86_64 emulator sysroot"]
fn reverse_continue_finds_the_earlier_write_and_the_breakpoint() {
    let Some(s) = start() else { return };
    let push = s.symbol("list_push").expect("symbols").expect("list_push");
    s.add_breakpoint(push).expect("bp");
    s.run(BUDGET).expect("run");
    let list = s.read_reg("RDI").expect("rdi");
    s.add_watchpoint(list, 8, WatchKind::Write).expect("watch");
    let first = s.run(BUDGET).expect("first write");
    assert!(matches!(first, SessionStop::Watch { .. }), "{first:?}");
    // The second push: its breakpoint, then its write.
    assert_eq!(
        s.run(BUDGET).expect("second push"),
        SessionStop::Breakpoint { pc: push }
    );
    let second = s.run(BUDGET).expect("second write");
    let SessionStop::Watch { old, new, .. } = &second else {
        panic!("expected a watch stop, got {second:?}");
    };
    let after = state(&s);

    // Back to just before the writing instruction: the old value is in memory.
    let back = s.reverse_continue(BUDGET).expect("reverse");
    let SessionStop::Watch {
        old: o2, new: n2, ..
    } = &back
    else {
        panic!("expected a watch stop, got {back:?}");
    };
    assert_eq!((o2, n2), (old, new));
    assert_eq!(s.read_memory(list, 8).expect("head"), *old);
    // Forward again: the same write.
    assert_eq!(s.run(BUDGET).expect("forward"), second);
    assert_eq!(state(&s), after);

    // Reverse to the breakpoint (the watch event of this write is found first, then the
    // breakpoint of this push).
    s.reverse_continue(BUDGET).expect("to the write");
    assert_eq!(
        s.reverse_continue(BUDGET).expect("to the breakpoint"),
        SessionStop::Breakpoint { pc: push }
    );
    assert_eq!(s.pc().expect("pc"), push);
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and the x86_64 emulator sysroot"]
fn a_reverse_continue_that_runs_out_of_budget_stays_where_it_started() {
    let Some(s) = start() else { return };
    let main = s.symbol("main").expect("symbols").expect("main");
    s.add_breakpoint(main).expect("bp");
    s.run(BUDGET).expect("to main");
    s.remove_breakpoint(main).expect("remove bp");
    let here = state(&s);
    assert!(here.2 > 40_000, "the loader ran first: {}", here.2);
    // No event to find: the search scans the last two history segments, then the budget ends it
    // partway through the history.
    let budget = here.2 % 20_000 + 20_000 + 1;
    assert_eq!(
        s.reverse_continue(budget).expect("reverse"),
        SessionStop::Budget
    );
    assert_eq!(
        state(&s),
        here,
        "the session is back where the search began"
    );
}

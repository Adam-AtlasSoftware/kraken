//! The oracle runs original functions of the corpus binaries under emulation. Expected values
//! are computed by hand from `corpus/src/*.c`.

mod common;

use common::{corpus_bin, oracle};
use kraken_rewrite::abi::{Arg, Param, Ret, Signature, Termination};

fn int(v: i64) -> Arg {
    Arg::Int { value: v as u64 }
}

fn buf(data: Vec<u8>) -> Arg {
    Arg::Buf { data }
}

fn record(id: i32, x: i32, y: i32) -> Vec<u8> {
    // struct record { int id; char name[16]; struct point pos; double weight; } (40 bytes)
    let mut b = vec![0u8; 40];
    b[0..4].copy_from_slice(&id.to_le_bytes());
    b[20..24].copy_from_slice(&x.to_le_bytes());
    b[24..28].copy_from_slice(&y.to_le_bytes());
    b
}

fn cmp_sig(name: &str) -> Signature {
    Signature {
        name: name.into(),
        params: vec![Param::Buf, Param::Buf],
        ret: Ret::Int {
            bits: 32,
            signed: true,
        },
    }
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn cmp_id_and_cmp_dist_match_the_c_source() {
    let mut o = oracle(&corpus_bin("pie_list-O0"));
    let cmp_id = o.symbol("cmp_id").expect("cmp_id");
    let cmp_dist = o.symbol("cmp_dist").expect("cmp_dist");

    // return a->id - b->id;
    let r = o
        .call(
            cmp_id,
            &cmp_sig("cmp_id"),
            &[buf(record(7, 0, 0)), buf(record(3, 0, 0))],
        )
        .expect("call");
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(4));
    assert!(r.global_writes.is_empty(), "{:?}", r.global_writes);
    assert_eq!(r.buffers[0], record(7, 0, 0), "inputs are not modified");

    let r = o
        .call(
            cmp_id,
            &cmp_sig("cmp_id"),
            &[buf(record(3, 0, 0)), buf(record(7, 0, 0))],
        )
        .expect("call");
    assert_eq!(r.ret, Some(u64::from((-4i32) as u32)));

    // int wraps: i32::MIN - 1 == i32::MAX in two's complement (C leaves it undefined, the
    // generated code subtracts).
    let r = o
        .call(
            cmp_id,
            &cmp_sig("cmp_id"),
            &[buf(record(i32::MIN, 0, 0)), buf(record(1, 0, 0))],
        )
        .expect("call");
    assert_eq!(r.ret, Some(u64::from(i32::MAX as u32)));

    // da = 3*3+4*4 = 25; db = 1*1+2*2 = 5; 25 - 5 = 20.
    let r = o
        .call(
            cmp_dist,
            &cmp_sig("cmp_dist"),
            &[buf(record(0, 3, 4)), buf(record(0, 1, 2))],
        )
        .expect("call");
    assert_eq!(r.ret, Some(20));
}

fn vm_run_sig() -> Signature {
    Signature {
        name: "vm_run".into(),
        params: vec![
            Param::Buf,
            Param::Buf,
            Param::Int {
                bits: 32,
                signed: false,
            },
        ],
        ret: Ret::Int {
            bits: 32,
            signed: true,
        },
    }
}

/// struct vm { int32_t stack[32]; int sp; unsigned pc; unsigned long steps; } (144 bytes)
fn vm_state() -> Vec<u8> {
    vec![0u8; 144]
}

fn run(code: &[u8]) -> kraken_rewrite::abi::Observation {
    let mut o = oracle(&corpus_bin("switch_vm-O0"));
    let entry = o.symbol("vm_run").expect("vm_run");
    let mut padded = code.to_vec();
    padded.extend_from_slice(&[0; 8]);
    o.call(
        entry,
        &vm_run_sig(),
        &[
            buf(vm_state()),
            buf(padded),
            Arg::Int {
                value: code.len() as u64,
            },
        ],
    )
    .expect("call")
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_computes_and_updates_state() {
    // PUSH 6; PUSH 7; MUL; HALT -> 42, sp == 1, pc == 6, steps == 4
    let r = run(&[1, 6, 1, 7, 4, 0]);
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(42));
    let vm = &r.buffers[0];
    assert_eq!(i32::from_le_bytes(vm[0..4].try_into().unwrap()), 42);
    assert_eq!(i32::from_le_bytes(vm[128..132].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(vm[132..136].try_into().unwrap()), 6);
    assert_eq!(u64::from_le_bytes(vm[136..144].try_into().unwrap()), 4);
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_print_goes_through_the_printf_stub() {
    // PUSH -5; PRINT; HALT
    let r = run(&[1, 0xfb, 11, 0]);
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.stdout, b"out: -5\n");
    assert_eq!(r.ret, Some(u64::from((-5i32) as u32)));
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_failure_path_reaches_exit_with_stderr() {
    // ADD on an empty stack: vm_fail("stack underflow", pc) -> fprintf(stderr) + exit(42).
    let r = run(&[2, 0]);
    assert_eq!(r.termination, Termination::Exited { status: 42 });
    assert_eq!(r.stderr, b"vm error at pc=1: stack underflow\n");
    assert_eq!(r.ret, None);
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn jump_table_loop_counts_down() {
    // PUSH 3; loop(2): DEC; DUP; JNZ 2; HALT -> 0 after 3 iterations.
    let r = run(&[1, 3, 10, 5, 9, 2, 0]);
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(0));
    let steps = u64::from_le_bytes(r.buffers[0][136..144].try_into().unwrap());
    assert_eq!(steps, 1 + 3 * 3 + 1);
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn unknown_import_is_reported_not_guessed() {
    // pie_list main-less: call list_sort's callee through a null function pointer faults, and an
    // import with no model ends the call as unsupported. node_new calls calloc.
    let mut o = oracle(&corpus_bin("pie_list-O0"));
    let entry = o.symbol("node_new").expect("node_new");
    let sig = Signature {
        name: "node_new".into(),
        params: vec![
            Param::Int {
                bits: 32,
                signed: true,
            },
            Param::Buf,
            Param::Int {
                bits: 32,
                signed: true,
            },
            Param::Int {
                bits: 32,
                signed: true,
            },
        ],
        ret: Ret::Int {
            bits: 64,
            signed: false,
        },
    };
    let r = o
        .call(
            entry,
            &sig,
            &[int(1), buf(b"abc\0".to_vec()), int(2), int(3)],
        )
        .expect("call");
    assert!(
        matches!(&r.termination, Termination::Unsupported { detail } if detail.contains("calloc")),
        "{:?}",
        r.termination
    );
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn calls_are_independent() {
    let mut o = oracle(&corpus_bin("switch_vm-O0"));
    let entry = o.symbol("vm_run").expect("vm_run");
    let go = |o: &mut kraken_rewrite::oracle::FunctionOracle| {
        o.call(
            entry,
            &vm_run_sig(),
            &[
                buf(vm_state()),
                buf(vec![1, 5, 0, 0, 0, 0, 0, 0, 0, 0]),
                int(3),
            ],
        )
        .expect("call")
    };
    let a = go(&mut o);
    let b = go(&mut o);
    assert_eq!(a, b);
    assert_eq!(a.ret, Some(5));
}

//! The emulation side of the call description beyond integers and flat buffers: `double`
//! parameters and results in `xmm` registers, host callbacks for function-pointer parameters,
//! and pointer graphs placed where the native runner places them. The functions are a few
//! hand-assembled instructions in a minimal ELF, so the expected values are the instructions'.
//!
//! These need the SLEIGH specs of a Ghidra install (`KRAKEN_GHIDRA_HOME`).

mod common;

use common::config;
use kraken_rewrite::abi::{
    Arg, Callback, Link, Observation, Param, Ret, Signature, Termination, place_object,
};
use kraken_rewrite::oracle::FunctionOracle;

const BASE: u64 = 0x40_0000;
const CODE_AT: u64 = 120;

/// An x86-64 ELF executable whose only content is `code` at `BASE + CODE_AT`.
fn elf_with_code(code: &[u8]) -> Vec<u8> {
    let total = CODE_AT as usize + code.len();
    let mut b = vec![0u8; total];
    b[0..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&(BASE + CODE_AT).to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64;
    b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
    b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
    b[ph + 16..ph + 24].copy_from_slice(&BASE.to_le_bytes());
    b[ph + 24..ph + 32].copy_from_slice(&BASE.to_le_bytes());
    b[ph + 32..ph + 40].copy_from_slice(&(total as u64).to_le_bytes());
    b[ph + 40..ph + 48].copy_from_slice(&(total as u64).to_le_bytes());
    b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    b[CODE_AT as usize..].copy_from_slice(code);
    b
}

fn call(code: &[u8], sig: &Signature, args: &[Arg]) -> Observation {
    let elf = elf_with_code(code);
    let mut o =
        FunctionOracle::from_bytes(&elf, &config()).expect("oracle (needs a Ghidra install)");
    o.call(BASE + CODE_AT, sig, args).expect("call")
}

fn sig(params: Vec<Param>, ret: Ret) -> Signature {
    Signature {
        name: "f".into(),
        params,
        ret,
    }
}

fn dbl(v: f64) -> Arg {
    Arg::Double { bits: v.to_bits() }
}

fn i32_ret() -> Ret {
    Ret::Int {
        bits: 32,
        signed: true,
    }
}

fn i32_param() -> Param {
    Param::Int {
        bits: 32,
        signed: true,
    }
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn doubles_are_passed_in_xmm_registers_and_returned_in_xmm0() {
    // addsd xmm0, xmm1; ret
    let r = call(
        &[0xf2, 0x0f, 0x58, 0xc1, 0xc3],
        &sig(vec![Param::Double, Param::Double], Ret::Double),
        &[dbl(1.5), dbl(2.25)],
    );
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(3.75f64.to_bits()));

    // cvtsi2sd xmm1, edi; mulsd xmm0, xmm1; ret: f(int a, double b) = b * a. The integer and
    // the double are numbered separately: `a` is in edi and `b` in xmm0.
    let r = call(
        &[0xf2, 0x0f, 0x2a, 0xcf, 0xf2, 0x0f, 0x59, 0xc1, 0xc3],
        &sig(vec![i32_param(), Param::Double], Ret::Double),
        &[
            Arg::Int {
                value: (-3i64) as u64,
            },
            dbl(2.5),
        ],
    );
    assert_eq!(r.ret, Some((-7.5f64).to_bits()));
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn a_callback_is_called_recorded_and_answers_like_the_native_side() {
    // f(cb, a, b) = cb(a, b):
    //   mov rax, rdi; mov rdi, rsi; mov rsi, rdx; sub rsp, 8; call rax; add rsp, 8; ret
    let code = [
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x83, 0xec, 0x08, 0xff, 0xd0,
        0x48, 0x83, 0xc4, 0x08, 0xc3,
    ];
    let s = sig(vec![Param::FnPtr, Param::Buf, Param::Buf], i32_ret());
    let buf = |v: i32| {
        let mut d = v.to_le_bytes().to_vec();
        d.extend([0u8; 12]);
        Arg::Buf { data: d }
    };
    let r = call(
        &code,
        &s,
        &[
            Arg::FnPtr {
                callback: Callback::Ascending,
            },
            buf(12),
            buf(7),
        ],
    );
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(5));
    // The same text the native runner writes for the same call.
    assert_eq!(r.callbacks, ["cb0(o0+0=c,o1+0=7)=5"]);
    let r = call(
        &code,
        &s,
        &[
            Arg::FnPtr {
                callback: Callback::Descending,
            },
            buf(12),
            buf(7),
        ],
    );
    assert_eq!(r.ret, Some(u64::from((-5i32) as u32)));
    assert_eq!(r.callbacks, ["cb1(o0+0=c,o1+0=7)=fffffffffffffffb"]);
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn graph_objects_sit_where_the_native_runner_puts_them() {
    // mov rax, [rdi]; mov eax, [rax]; ret: the first int of the object the first word points to.
    let code = [0x48, 0x8b, 0x07, 0x8b, 0x00, 0xc3];
    let mut head = vec![0u8; 16];
    head[8] = 1;
    let mut node = vec![0u8; 8];
    node[0..4].copy_from_slice(&1234i32.to_le_bytes());
    let graph = Arg::Graph {
        objects: vec![head, node],
        links: vec![Link {
            from: 0,
            offset: 0,
            to: 1,
            to_offset: 0,
        }],
    };
    let r = call(&code, &sig(vec![Param::Buf], i32_ret()), &[graph]);
    assert_eq!(r.termination, Termination::Returned);
    assert_eq!(r.ret, Some(1234));
    // The pointer stored in the first object is the address `place_object` gives the second.
    let (_, _, at) = place_object(1, 8);
    assert_eq!(&r.buffers[0][0..8], &at.to_le_bytes());
    assert_eq!(r.buffers.len(), 2);
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn reading_one_byte_past_an_object_faults() {
    // movzx eax, byte [rdi + 8]; ret
    let code = [0x0f, 0xb6, 0x47, 0x08, 0xc3];
    let s = sig(vec![Param::Buf], i32_ret());
    let inside = call(&code, &s, &[Arg::Buf { data: vec![1; 9] }]);
    assert_eq!(inside.termination, Termination::Returned);
    let outside = call(&code, &s, &[Arg::Buf { data: vec![1; 8] }]);
    assert!(
        matches!(outside.termination, Termination::Fault { .. }),
        "{:?}",
        outside.termination
    );
}

fn diff(
    code: &[u8],
    s: &Signature,
    rust: &str,
    spec: kraken_rewrite::difftest::InputSpec,
) -> kraken_rewrite::difftest::DiffReport {
    let elf = elf_with_code(code);
    let mut o =
        FunctionOracle::from_bytes(&elf, &config()).expect("oracle (needs a Ghidra install)");
    let opts = kraken_rewrite::difftest::DiffOptions {
        random_cases: 40,
        ..kraken_rewrite::difftest::DiffOptions::default()
    };
    kraken_rewrite::difftest::run_differential(&mut o, BASE + CODE_AT, s, rust, &spec, &opts)
        .expect("differential run")
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn doubles_and_callbacks_go_through_the_differential_test_end_to_end() {
    use kraken_rewrite::difftest::Verdict;
    // f(int a, double b) = b * a, and a wrong Rust version of it.
    let code = [0xf2, 0x0f, 0x2a, 0xcf, 0xf2, 0x0f, 0x59, 0xc1, 0xc3];
    let s = sig(vec![i32_param(), Param::Double], Ret::Double);
    let right = "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn f(a: i32, b: f64) -> f64 { b * a as f64 }";
    let wrong = "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn f(a: i32, b: f64) -> f64 { b * (a as f64) + 0.5 }";
    let spec = kraken_rewrite::infer::generic_inputs(&s);
    let ok = diff(&code, &s, right, spec.clone());
    assert_eq!(
        ok.verdict,
        Verdict::Pass,
        "{:#?}",
        ok.counterexamples.first()
    );
    assert!(ok.cases_run > 40);
    let bad = diff(&code, &s, wrong, spec);
    assert_eq!(bad.verdict, Verdict::Fail);
    assert!(bad.counterexamples[0].differences[0].contains("return value"));

    // f(cb, a, b) = cb(a, b), against Rust that calls the callback with the arguments swapped:
    // the result differs and so does the recorded call.
    let code = [
        0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6, 0x48, 0x83, 0xec, 0x08, 0xff, 0xd0,
        0x48, 0x83, 0xc4, 0x08, 0xc3,
    ];
    let s = sig(vec![Param::FnPtr, Param::Buf, Param::Buf], i32_ret());
    let right = "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn f(cb: Option<unsafe extern \"C\" fn(*mut u8, *mut u8) -> i32>, a: *mut u8, b: *mut u8) -> i32 { unsafe { cb.unwrap()(a, b) } }";
    let wrong = right.replace("cb.unwrap()(a, b)", "cb.unwrap()(b, a)");
    let spec = kraken_rewrite::infer::generic_inputs(&s);
    let ok = diff(&code, &s, right, spec.clone());
    assert_eq!(
        ok.verdict,
        Verdict::Pass,
        "{:#?}",
        ok.counterexamples.first()
    );
    let bad = diff(&code, &s, &wrong, spec);
    assert_eq!(bad.verdict, Verdict::Fail);
    let d = bad.counterexamples[0].differences.join(" | ");
    assert!(d.contains("callback") || d.contains("return value"), "{d}");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn the_generic_inputs_accept_the_reference_comparator() {
    use kraken_rewrite::difftest::{DiffOptions, Verdict, run_differential};
    use kraken_rewrite::targets::target;
    let t = target("cmp_id").expect("target");
    let mut o = common::oracle(&common::corpus_bin("pie_list-O0"));
    let entry = o.symbol("cmp_id").expect("symbol");
    let spec = kraken_rewrite::infer::generic_inputs(&t.signature);
    let opts = DiffOptions {
        random_cases: 100,
        ..DiffOptions::default()
    };
    let r = run_differential(&mut o, entry, &t.signature, t.reference, &spec, &opts)
        .expect("differential run");
    assert_eq!(r.verdict, Verdict::Pass, "{:#?}", r.counterexamples.first());
}

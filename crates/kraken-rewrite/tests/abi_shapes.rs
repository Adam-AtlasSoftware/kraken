//! The System V x86-64 calling-convention shapes of `corpus/src/abi_shapes.c`: every function of
//! the program runs under the oracle (the original, emulated) and as a hand-written Rust
//! reference (compiled and run natively), on generated inputs, and the two must agree. No model
//! is involved: the Rust is the reference translation, so a disagreement is a bug in how one of
//! the two sides places arguments or reads results.
//!
//! Needs the SLEIGH spec files (`KRAKEN_NATIVE_SPECS`) and a Rust toolchain.

mod common;

use common::{config, corpus_bin};
use kraken_rewrite::abi::{Arg, Param, Ret, Scalar, Signature, StructShape};
use kraken_rewrite::difftest::{
    DiffOptions, Generator, InputSpec, IntGen, ParamGen, Verdict, run_differential,
};
use kraken_rewrite::fpolicy::FloatPolicy;
use kraken_rewrite::oracle::FunctionOracle;

const I32: Scalar = Scalar::Int {
    bits: 32,
    signed: true,
};
const I64: Scalar = Scalar::Int {
    bits: 64,
    signed: true,
};

fn shape(name: &str, fields: &[Scalar]) -> StructShape {
    StructShape {
        name: name.into(),
        fields: fields.to_vec(),
    }
}

fn small() -> StructShape {
    shape("Small", &[I32, I32])
}
fn mixed() -> StructShape {
    shape("Mixed", &[I64, Scalar::Double])
}
fn vec2() -> StructShape {
    shape("Vec2", &[Scalar::Double, Scalar::Double])
}
fn fpair() -> StructShape {
    shape("FPair", &[Scalar::Float, Scalar::Float])
}
fn large() -> StructShape {
    shape("Large", &[I64, I64, I64, I64])
}

fn long() -> Param {
    Param::Int {
        bits: 64,
        signed: true,
    }
}
fn int() -> Param {
    Param::Int {
        bits: 32,
        signed: true,
    }
}
fn ret_long() -> Ret {
    Ret::Int {
        bits: 64,
        signed: true,
    }
}

struct Shape {
    name: &'static str,
    params: Vec<Param>,
    ret: Ret,
    variadic_from: Option<usize>,
    rust: &'static str,
    /// Generators per parameter; `None` entries use the type's default.
    gens: Vec<Option<ParamGen>>,
}

fn default_gen(p: &Param) -> ParamGen {
    match p {
        Param::Int { bits, signed } => ParamGen::Int(IntGen::full(*bits, *signed)),
        Param::Double => ParamGen::Double,
        Param::Float => ParamGen::Float,
        Param::Struct(s) => ParamGen::ByValue(s.clone()),
        other => panic!("no default generator for {other:?}"),
    }
}

fn small_range(bits: u8, hi: i64) -> Option<ParamGen> {
    Some(ParamGen::Int(IntGen {
        bits,
        signed: true,
        range: Some((0, hi)),
    }))
}

const CVT: &str = "fn cvt(d: f64) -> i64 {\n    \
    if d.is_nan() || d >= 9.223372036854775807e18 || d < -9.223372036854775808e18 { i64::MIN } \
    else { d as i64 }\n}\n";

fn shapes() -> Vec<Shape> {
    vec![
        Shape {
            name: "small_swap",
            params: vec![Param::Struct(small())],
            ret: Ret::Struct(small()),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn small_swap(a0: Small) -> Small { Small { f0: a0.f1, f1: a0.f0 } }",
            gens: vec![None],
        },
        Shape {
            name: "small_dot",
            params: vec![Param::Struct(small()), int()],
            ret: ret_long(),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn small_dot(a0: Small, k: i32) -> i64 { (a0.f0 as i64).wrapping_mul(k as i64).wrapping_add((a0.f1 as i64).wrapping_mul(k as i64 + 1)) }",
            gens: vec![None, None],
        },
        Shape {
            name: "mixed_scale",
            params: vec![Param::Struct(mixed()), long()],
            ret: Ret::Struct(mixed()),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn mixed_scale(m: Mixed, k: i64) -> Mixed { Mixed { f0: m.f0.wrapping_mul(k), f1: m.f1 * k as f64 } }",
            gens: vec![None, None],
        },
        Shape {
            name: "vec2_rot",
            params: vec![Param::Struct(vec2()), Param::Double],
            ret: Ret::Struct(vec2()),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn vec2_rot(v: Vec2, c: f64) -> Vec2 { Vec2 { f0: v.f0 * c - v.f1, f1: v.f1 * c + v.f0 } }",
            gens: vec![None, None],
        },
        Shape {
            name: "fpair_mix",
            params: vec![Param::Struct(fpair()), Param::Float],
            ret: Ret::Struct(fpair()),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn fpair_mix(p: FPair, k: f32) -> FPair { FPair { f0: p.f0 * k + p.f1, f1: p.f1 * k - p.f0 } }",
            gens: vec![None, None],
        },
        Shape {
            name: "large_make",
            params: vec![long()],
            ret: Ret::Struct(large()),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn large_make(seed: i64) -> Large { Large { f0: seed, f1: seed.wrapping_mul(2), f2: seed.wrapping_mul(3), f3: seed.wrapping_mul(seed) } }",
            gens: vec![None],
        },
        Shape {
            name: "large_sum",
            params: vec![Param::Struct(large()), long()],
            ret: ret_long(),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn large_sum(l: Large, k: i64) -> i64 { l.f0.wrapping_mul(k).wrapping_add(l.f1).wrapping_sub(l.f2).wrapping_add(l.f3.wrapping_mul(2)) }",
            gens: vec![None, None],
        },
        Shape {
            name: "late_struct",
            params: vec![
                long(),
                long(),
                long(),
                long(),
                long(),
                long(),
                Param::Struct(small()),
                long(),
            ],
            ret: ret_long(),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn late_struct(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, s: Small, g: i64) -> i64 { a.wrapping_add(b.wrapping_mul(2)).wrapping_add(c.wrapping_mul(3)).wrapping_add(d.wrapping_mul(4)).wrapping_add(e.wrapping_mul(5)).wrapping_add(f.wrapping_mul(6)).wrapping_add((s.f0 as i64).wrapping_mul(7)).wrapping_add((s.f1 as i64).wrapping_mul(8)).wrapping_add(g.wrapping_mul(9)) }",
            gens: vec![None; 8],
        },
        Shape {
            name: "eight_args",
            params: vec![long(); 8],
            ret: ret_long(),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn eight_args(a: i64, b: i64, c: i64, d: i64, e: i64, f: i64, g: i64, h: i64) -> i64 { a.wrapping_add(b.wrapping_mul(2)).wrapping_add(c.wrapping_mul(3)).wrapping_add(d.wrapping_mul(4)).wrapping_add(e.wrapping_mul(5)).wrapping_add(f.wrapping_mul(6)).wrapping_add(g.wrapping_mul(7)).wrapping_add(h.wrapping_mul(8)) }",
            gens: vec![None; 8],
        },
        Shape {
            name: "ten_doubles",
            params: vec![Param::Double; 10],
            ret: Ret::Double,
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn ten_doubles(a: f64, b: f64, c: f64, d: f64, e: f64, f: f64, g: f64, h: f64, i: f64, j: f64) -> f64 { a + 2.0 * b + 3.0 * c + 4.0 * d + 5.0 * e + 6.0 * f + 7.0 * g + 8.0 * h + 9.0 * i + 10.0 * j }",
            gens: vec![None; 10],
        },
        Shape {
            name: "mixed_stack",
            params: vec![
                int(),
                Param::Double,
                int(),
                Param::Double,
                int(),
                int(),
                int(),
                int(),
                int(),
                int(),
                Param::Double,
            ],
            ret: ret_long(),
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn mixed_stack(a: i32, x: f64, b: i32, y: f64, c: i32, d: i32, e: i32, f: i32, g: i32, h: i32, z: f64) -> i64 { (a as i64).wrapping_add(2 * b as i64).wrapping_add(3 * c as i64).wrapping_add(4 * d as i64).wrapping_add(5 * e as i64).wrapping_add(6 * f as i64).wrapping_add(7 * g as i64).wrapping_add(8 * h as i64).wrapping_add(cvt(x * 10.0 + y * 100.0 + z * 1000.0)) }",
            gens: vec![None; 11],
        },
        Shape {
            name: "sum_ints",
            params: vec![int(), int(), int(), int()],
            ret: Ret::Int {
                bits: 32,
                signed: true,
            },
            variadic_from: Some(1),
            rust: "pub unsafe extern \"C\" fn sum_ints(n: i32, a: i32, b: i32, c: i32) -> i32 { let v = [a, b, c]; let mut s = 0i32; for i in 0..n.max(0) as usize { s = s.wrapping_add(v[i].wrapping_mul(i as i32 + 1)); } s }",
            gens: vec![small_range(32, 3), None, None, None],
        },
        Shape {
            name: "sum_doubles",
            params: vec![int(), Param::Double, Param::Double, Param::Double],
            ret: Ret::Double,
            variadic_from: Some(1),
            rust: "pub unsafe extern \"C\" fn sum_doubles(n: i32, a: f64, b: f64, c: f64) -> f64 { let v = [a, b, c]; let mut s = 0.0f64; for i in 0..n.max(0) as usize { s += v[i] * (i as i32 + 1) as f64; } s }",
            gens: vec![small_range(32, 3), None, None, None],
        },
        Shape {
            name: "float_fma",
            params: vec![Param::Float, Param::Float],
            ret: Ret::Float,
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn float_fma(a: f32, b: f32) -> f32 { a * b + a }",
            gens: vec![None, None],
        },
        Shape {
            name: "poly",
            params: vec![Param::Double],
            ret: Ret::Double,
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn poly(x: f64) -> f64 { ((3.0 * x + 2.0) * x - 5.0) * x + 7.0 }",
            gens: vec![None],
        },
        Shape {
            name: "fdiv_sum",
            params: vec![Param::Float, Param::Double],
            ret: Ret::Float,
            variadic_from: None,
            rust: "pub unsafe extern \"C\" fn fdiv_sum(a: f32, b: f64) -> f32 { (a as f64 / if b == 0.0 { 1.0 } else { b }) as f32 }",
            gens: vec![None, None],
        },
    ]
}

fn run_shape(oracle: &mut FunctionOracle, s: &Shape, policy: FloatPolicy) -> Verdict {
    let sig = Signature {
        name: s.name.into(),
        params: s.params.clone(),
        ret: s.ret.clone(),
        variadic_from: s.variadic_from,
    };
    sig.check().expect("signature");
    let entry = oracle.symbol(s.name).expect("symbol");
    let gens: Vec<ParamGen> = s
        .params
        .iter()
        .zip(&s.gens)
        .map(|(p, g)| g.clone().unwrap_or_else(|| default_gen(p)))
        .collect();
    let spec = InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(gens),
    };
    let opts = DiffOptions {
        random_cases: 60,
        float_policy: policy,
        ..DiffOptions::default()
    };
    let code = format!("{CVT}#[unsafe(no_mangle)]\n{}", s.rust);
    let report = run_differential(oracle, entry, &sig, &code, &spec, &opts)
        .unwrap_or_else(|e| panic!("{}: {e}", s.name));
    if report.verdict != Verdict::Pass {
        panic!(
            "{}: {:?}\nfirst counterexample: {:#?}",
            s.name,
            report.verdict,
            report.counterexamples.first()
        );
    }
    assert!(
        report.cases_run >= 60,
        "{}: {} cases",
        s.name,
        report.cases_run
    );
    Verdict::Pass
}

fn all_shapes_at(opt: &str) {
    if !common::need_specs() {
        return;
    }
    let mut oracle =
        FunctionOracle::load(&corpus_bin(&format!("abi_shapes-{opt}")), &config()).expect("oracle");
    for s in shapes() {
        run_shape(&mut oracle, &s, FloatPolicy::Exact);
    }
}

#[test]
fn every_abi_shape_agrees_between_the_oracle_and_native_rust_at_o0() {
    all_shapes_at("O0");
}

#[test]
fn every_abi_shape_agrees_between_the_oracle_and_native_rust_at_o2() {
    all_shapes_at("O2");
}

/// `(a + b) + c` against `a + (b + c)`: one unit in the last place apart on the numbers below.
#[test]
fn float_policy_decides_whether_a_last_bit_difference_is_a_difference() {
    if !common::need_specs() {
        return;
    }
    let mut oracle = FunctionOracle::load(&corpus_bin("abi_shapes-O2"), &config()).expect("oracle");
    let sig = Signature {
        name: "sum3".into(),
        params: vec![Param::Double; 3],
        ret: Ret::Double,
        variadic_from: None,
    };
    let case = vec![
        Arg::Double {
            bits: 0.1f64.to_bits(),
        },
        Arg::Double {
            bits: 0.2f64.to_bits(),
        },
        Arg::Double {
            bits: 0.3f64.to_bits(),
        },
    ];
    let spec = InputSpec {
        fixed: vec![case],
        generator: Generator::Params(vec![ParamGen::Double; 3]),
    };
    let entry = oracle.symbol("sum3").expect("symbol");
    let reordered = "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn sum3(a: f64, b: f64, c: f64) -> f64 { a + (b + c) }";
    let run = |oracle: &mut FunctionOracle, policy| {
        let opts = DiffOptions {
            random_cases: 0,
            float_policy: policy,
            ..DiffOptions::default()
        };
        run_differential(oracle, entry, &sig, reordered, &spec, &opts)
            .expect("run")
            .verdict
    };
    assert_eq!(run(&mut oracle, FloatPolicy::Exact), Verdict::Fail);
    assert_eq!(run(&mut oracle, FloatPolicy::from_ulps(1)), Verdict::Pass);
}

/// A reference that mishandles the second eightbyte of a mixed structure is caught.
#[test]
fn a_wrong_structure_reference_fails() {
    if !common::need_specs() {
        return;
    }
    let mut oracle = FunctionOracle::load(&corpus_bin("abi_shapes-O2"), &config()).expect("oracle");
    let mut s = shapes()
        .into_iter()
        .find(|s| s.name == "mixed_scale")
        .expect("shape");
    s.rust = "pub unsafe extern \"C\" fn mixed_scale(m: Mixed, k: i64) -> Mixed { Mixed { f0: m.f0.wrapping_mul(k), f1: m.f1 } }";
    let sig = Signature {
        name: s.name.into(),
        params: s.params.clone(),
        ret: s.ret.clone(),
        variadic_from: None,
    };
    let spec = InputSpec {
        fixed: Vec::new(),
        generator: Generator::Params(s.params.iter().map(default_gen).collect()),
    };
    let entry = oracle.symbol(s.name).expect("symbol");
    let report = run_differential(
        &mut oracle,
        entry,
        &sig,
        &format!("#[unsafe(no_mangle)]\n{}", s.rust),
        &spec,
        &DiffOptions {
            random_cases: 20,
            ..DiffOptions::default()
        },
    )
    .expect("run");
    assert_eq!(report.verdict, Verdict::Fail);
    assert!(
        report.counterexamples[0]
            .differences
            .iter()
            .any(|d| d.contains("structure result")),
        "{:?}",
        report.counterexamples[0].differences
    );
}

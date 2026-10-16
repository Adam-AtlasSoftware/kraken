//! Differential tests: the checked-in reference translations pass against the original under
//! emulation, and deliberately wrong translations fail with a counterexample.

mod common;

use common::{corpus_bin, oracle};
use kraken_rewrite::abi::{Arg, Termination};
use kraken_rewrite::difftest::{DiffOptions, DiffReport, Verdict, run_differential};
use kraken_rewrite::targets::{Target, target};

fn run(t: &Target, code: &str, random_cases: usize) -> DiffReport {
    let mut o = oracle(&corpus_bin(t.binary));
    let entry = o.symbol(t.function).expect("symbol");
    let opts = DiffOptions {
        random_cases,
        ..DiffOptions::default()
    };
    run_differential(&mut o, entry, &t.signature, code, &t.inputs, &opts).expect("differential run")
}

fn t(id: &str) -> Target {
    target(id).expect("target")
}

fn assert_pass(id: &str) {
    let tgt = t(id);
    let r = run(&tgt, tgt.reference, 150);
    assert!(
        r.verdict == Verdict::Pass,
        "{id}: {:?}\n{:#?}",
        r.verdict,
        r.counterexamples.first()
    );
    assert!(r.cases_run >= 150, "{id}: only {} cases ran", r.cases_run);
    assert_eq!(r.passed, r.cases_run);
    assert_eq!(r.skipped, 0, "{id}: oracle skipped cases");
}

/// `reference` with `from` replaced by `to`; the replacement must apply.
fn mutate(reference: &str, from: &str, to: &str) -> String {
    assert!(reference.contains(from), "mutation `{from}` does not apply");
    reference.replacen(from, to, 1)
}

fn assert_caught(id: &str, from: &str, to: &str) -> DiffReport {
    let tgt = t(id);
    let wrong = mutate(tgt.reference, from, to);
    let r = run(&tgt, &wrong, 150);
    assert_eq!(r.verdict, Verdict::Fail, "{id}: wrong translation passed");
    assert!(!r.counterexamples.is_empty());
    let c = &r.counterexamples[0];
    assert!(!c.differences.is_empty());
    r
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn cmp_id_reference_passes() {
    assert_pass("cmp_id");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn cmp_dist_reference_passes() {
    assert_pass("cmp_dist");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_reference_passes() {
    assert_pass("vm_run");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn evaluate_reference_passes() {
    assert_pass("evaluate");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn cmp_id_returning_the_sign_instead_of_the_difference_fails() {
    // The "nicer" comparator: same ordering, different return value.
    let r = assert_caught(
        "cmp_id",
        "(*a).id.wrapping_sub((*b).id)",
        "(*a).id.cmp(&(*b).id) as i32",
    );
    let c = &r.counterexamples[0];
    assert!(
        c.differences[0].starts_with("return value"),
        "{:?}",
        c.differences
    );
    // The smallest counterexample is one of the hand-picked ones: ids 7 and 3, original 4.
    assert_eq!(c.original.ret, Some(4));
    assert_eq!(c.translation.ret, Some(1));
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn cmp_dist_without_wrapping_fails_on_overflow() {
    // Plain operators panic on overflow (the runner is built with overflow checks): the
    // original wraps, so the translation faults where the original returns.
    let r = assert_caught(
        "cmp_dist",
        "p.x.wrapping_mul(p.x).wrapping_add(p.y.wrapping_mul(p.y))",
        "p.x * p.x + p.y * p.y",
    );
    let c = &r.counterexamples[0];
    assert_eq!(c.original.termination, Termination::Returned);
    assert!(
        matches!(c.translation.termination, Termination::Fault { .. }),
        "{:?}",
        c.translation
    );
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_with_swapped_sub_operands_fails() {
    let r = assert_caught(
        "vm_run",
        "push(vm, a.wrapping_sub(b));",
        "push(vm, b.wrapping_sub(a));",
    );
    // Counterexamples are ordered smallest input first; every one involves SUB (opcode 3).
    for c in &r.counterexamples {
        let Arg::Buf { data } = &c.args[1] else {
            panic!("code buffer expected");
        };
        assert!(data.contains(&3), "{:?}", c.args);
    }
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn vm_run_with_a_wrong_error_message_fails_through_stderr() {
    let r = assert_caught("vm_run", "\"stack underflow\"", "\"stack underrun\"");
    let c = &r.counterexamples[0];
    assert!(
        c.differences.iter().any(|d| d.starts_with("stderr")),
        "{:?}",
        c.differences
    );
    assert_eq!(c.original.termination, Termination::Exited { status: 42 });
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn evaluate_with_euclidean_remainder_fails_on_negative_operands() {
    let r = assert_caught("evaluate", "v % r", "v.rem_euclid(r)");
    let c = &r.counterexamples[0];
    let Arg::Buf { data } = &c.args[0] else {
        panic!("text buffer expected");
    };
    let text = String::from_utf8_lossy(data);
    assert!(text.contains('%'), "{text:?}");
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn a_translation_that_does_not_compile_is_rejected_not_an_error() {
    let tgt = t("cmp_id");
    let r = run(&tgt, "this is not rust", 5);
    assert!(
        matches!(&r.verdict, Verdict::Rejected { reason } if reason.contains("does not compile")),
        "{:?}",
        r.verdict
    );
}

#[test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
fn translations_that_reach_for_the_system_are_refused_before_building() {
    let tgt = t("cmp_id");
    for bad in [
        "use std::fs; #[unsafe(no_mangle)] pub unsafe extern \"C\" fn cmp_id(a: *const u8, b: *const u8) -> i32 { let _ = std::fs::read(\"/etc/passwd\"); 0 }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn cmp_id(a: *const u8, b: *const u8) -> i32 { let _ = include_str!(\"/etc/passwd\"); 0 }",
        "#[unsafe(no_mangle)] pub unsafe extern \"C\" fn cmp_id(a: *const u8, b: *const u8) -> i32 { std::process::Command::new(\"id\"); 0 }",
    ] {
        let r = run(&tgt, bad, 2);
        assert!(
            matches!(&r.verdict, Verdict::Rejected { reason } if reason.contains("not allowed")),
            "{bad}: {:?}",
            r.verdict
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn the_runner_is_confined_by_landlock() {
    use kraken_rewrite::native::{Build, build};
    use kraken_rewrite::sandbox::Confinement;

    // `std::fs` is refused by the lint; spelling the path in two parts gets past it, so this
    // checks the sandbox itself: the file exists, but the runner must not be able to read it.
    assert!(
        std::fs::read("/etc/passwd").is_ok(),
        "test needs /etc/passwd"
    );
    let code = r#"
use std as s;
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cmp_id(_a: *const u8, _b: *const u8) -> i32 {
    match s::fs::read("/etc/passwd") { Ok(_) => 1, Err(_) => 0 }
}
"#;
    let tgt = t("cmp_id");
    let Build::Ready(runner) = build(&tgt.signature, code, &Confinement::default()).expect("build")
    else {
        panic!("should compile");
    };
    assert!(
        runner.build_confinement.landlock_abi > 0,
        "Landlock must be enforced here"
    );
    let obs = runner
        .run(&[
            Arg::Buf { data: vec![0; 40] },
            Arg::Buf { data: vec![0; 40] },
        ])
        .expect("run");
    assert_eq!(obs.termination, Termination::Returned);
    assert_eq!(obs.ret, Some(0), "the runner could read /etc/passwd");
}

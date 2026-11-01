//! C++ exceptions in the runtime shim: a throw inside `rt::try_catch` is caught and handed to
//! the handler, one that nobody catches ends the program as libstdc++ does, and a handler can
//! pass the exception on. Native side only (no emulator); needs a sandbox.

use kraken_rewrite::abi::{Arg, Param, Ret, Signature, Termination};
use kraken_rewrite::difftest::DiffOptions;
use kraken_rewrite::native::{Build, NativeRunner, build_full};
use kraken_rewrite::sandbox;

fn runner(code: &str) -> Option<NativeRunner> {
    if !sandbox::enforced() {
        eprintln!("skipped: this host cannot confine generated code");
        return None;
    }
    let sig = Signature {
        name: "f".into(),
        params: vec![Param::Int {
            bits: 32,
            signed: true,
        }],
        ret: Ret::Int {
            bits: 32,
            signed: true,
        },
        variadic_from: None,
    };
    let opts = DiffOptions {
        trusted_prelude: kraken_rewrite::rt_module_source(),
        ..DiffOptions::default()
    };
    match build_full(&sig, code, &opts).expect("build") {
        Build::Ready(r) => Some(*r),
        Build::Rejected(why) => panic!("rejected: {why}"),
    }
}

fn arg(v: i32) -> Vec<Arg> {
    vec![Arg::Int {
        value: i64::from(v) as u64,
    }]
}

const CATCHING: &str = r#"
unsafe fn risky(n: i32) -> i32 {
    if n < 0 {
        rt::throw("std::runtime_error", "negative");
    }
    if n == 0 {
        rt::throw("std::logic_error", "zero");
    }
    n * 2
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn f(n: i32) -> i32 {
    match rt::try_catch(|| unsafe { risky(n) }) {
        Ok(v) => v,
        Err(e) if e.type_name == "std::runtime_error" => -(e.what.len() as i32),
        Err(e) => rt::rethrow(e),
    }
}
"#;

#[test]
fn a_caught_exception_reaches_its_handler() {
    let Some(r) = runner(CATCHING) else { return };
    let ok = r.run(&arg(21)).expect("run");
    assert_eq!(ok.termination, Termination::Returned);
    assert_eq!(ok.ret, Some(42));
    let caught = r.run(&arg(-1)).expect("run");
    assert_eq!(caught.termination, Termination::Returned);
    // "negative" has eight characters.
    assert_eq!(caught.ret, Some(u64::from(-8i32 as u32)));
    // The panic machinery stays silent for a C++ exception.
    assert!(caught.stderr.is_empty(), "{:?}", caught.stderr);
}

#[test]
fn an_exception_the_handler_does_not_take_ends_the_program_like_terminate() {
    let Some(r) = runner(CATCHING) else { return };
    // The handler rethrows `std::logic_error`; nothing else is active, so libstdc++'s
    // terminate message follows and the process aborts.
    let obs = r.run(&arg(0)).expect("run");
    assert!(
        matches!(obs.termination, Termination::Fault { .. }),
        "{:?}",
        obs.termination
    );
    let err = String::from_utf8_lossy(&obs.stderr);
    assert!(
        err.contains("terminate called after throwing an instance of 'std::logic_error'")
            && err.contains("what():  zero"),
        "{err}"
    );
}

#[test]
fn an_exception_with_no_handler_at_all_terminates() {
    let Some(r) = runner(
        r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn f(n: i32) -> i32 {
    if n > 0 { unsafe { rt::throw_out_of_range(b"index 9\0".as_ptr()) } }
    n
}
"#,
    ) else {
        return;
    };
    assert_eq!(
        r.run(&arg(-3)).expect("run").ret,
        Some(u64::from(-3i32 as u32))
    );
    let obs = r.run(&arg(1)).expect("run");
    assert!(matches!(obs.termination, Termination::Fault { .. }));
    assert!(
        String::from_utf8_lossy(&obs.stderr)
            .contains("terminate called after throwing an instance of 'std::out_of_range'")
    );
}

#[test]
fn handlers_nest_and_a_rethrow_reaches_the_outer_one() {
    let Some(r) = runner(
        r#"
#[unsafe(no_mangle)]
pub unsafe extern "C" fn f(n: i32) -> i32 {
    let outer = rt::try_catch(|| {
        let inner = rt::try_catch(|| {
            if n > 0 { rt::throw("int", "7") }
            n
        });
        match inner {
            Ok(v) => v,
            Err(e) => { rt::rethrow(e) }
        }
    });
    match outer {
        Ok(v) => v,
        Err(e) => 100 + e.what.parse::<i32>().unwrap_or(0),
    }
}
"#,
    ) else {
        return;
    };
    assert_eq!(r.run(&arg(5)).expect("run").ret, Some(107));
    assert_eq!(r.run(&arg(0)).expect("run").ret, Some(0));
}

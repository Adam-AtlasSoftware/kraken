// Reference translation of stripped_calc `main`; the entry point of the program. Calls the
// translated `evaluate` and prints through the runtime shim.

/// Evaluates seven fixed expressions and prints each result or `error`, then the error count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fn_1014c1() -> i32 {
    const CASES: [&[u8]; 7] = [
        b"1 + 2 * 3\0",
        b"(1 + 2) * 3\0",
        b"100 / (5 - 5)\0",
        b"-(4 + 6) % 7\0",
        b"2 * (3 + 4) * 5\0",
        b"12 +\0",
        b"((7))\0",
    ];
    let mut bad: i32 = 0;
    for case in CASES.iter() {
        let mut v: i64 = 0;
        unsafe {
            if evaluate(case.as_ptr() as _, &mut v as *mut i64 as _) == 0 {
                rt::printf(
                    b"%-18s = %ld\n\0".as_ptr(),
                    &[rt::Arg::Ptr(case.as_ptr()), rt::Arg::Int(v)],
                );
            } else {
                rt::printf(
                    b"%-18s : error\n\0".as_ptr(),
                    &[rt::Arg::Ptr(case.as_ptr())],
                );
                bad += 1;
            }
        }
    }
    unsafe {
        rt::printf(b"errors: %d\n\0".as_ptr(), &[rt::Arg::Int(i64::from(bad))]);
    }
    0
}

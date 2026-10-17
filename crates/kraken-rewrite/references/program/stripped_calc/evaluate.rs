// Reference translation of stripped_calc `evaluate`; calls the translated `parse_expr` and
// `skip_ws`.

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

/// Evaluates the NUL-terminated `text`; stores the value in `*out` and returns 0, or returns -1
/// (leaving `*out` alone) on a syntax error, trailing text or division by zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn evaluate(text: *const u8, out: *mut i64) -> i32 {
    let mut ps = Parser { p: text, err: 0 };
    unsafe {
        let v = parse_expr(&mut ps as *mut Parser as _);
        skip_ws(&mut ps as *mut Parser as _);
        if ps.err != 0 || *ps.p != 0 {
            return -1;
        }
        *out = v;
    }
    0
}

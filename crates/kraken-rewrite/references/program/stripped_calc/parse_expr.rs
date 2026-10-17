// Reference translation of stripped_calc `parse_expr`; calls the translated `skip_ws` and
// `parse_term`.

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

/// expr = term (('+' | '-') term)*
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_expr(ps: *mut Parser) -> i64 {
    unsafe {
        let mut v = parse_term(ps as _);
        loop {
            skip_ws(ps as _);
            let op = *(*ps).p;
            if op != b'+' && op != b'-' {
                return v;
            }
            (*ps).p = (*ps).p.add(1);
            let r = parse_term(ps as _);
            v = if op == b'+' {
                v.wrapping_add(r)
            } else {
                v.wrapping_sub(r)
            };
        }
    }
}

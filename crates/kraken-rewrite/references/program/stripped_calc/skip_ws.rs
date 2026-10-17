// Reference translation of stripped_calc `skip_ws` (corpus/src/stripped_calc.c), written by hand
// and checked against the C source; program mode (the runtime shim `rt` is in scope).

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

/// Advances `ps.p` past C-locale whitespace.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn skip_ws(ps: *mut Parser) {
    unsafe {
        while rt::isspace(i32::from(*(*ps).p)) != 0 {
            (*ps).p = (*ps).p.add(1);
        }
    }
}

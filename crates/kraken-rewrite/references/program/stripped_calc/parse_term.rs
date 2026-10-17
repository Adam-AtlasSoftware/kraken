// Reference translation of stripped_calc `parse_term`; calls the translated `skip_ws` and
// `parse_atom`.

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

/// term = atom (('*' | '/' | '%') atom)*; division by zero sets `err` and keeps the value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_term(ps: *mut Parser) -> i64 {
    unsafe {
        let mut v = parse_atom(ps as _);
        loop {
            skip_ws(ps as _);
            let op = *(*ps).p;
            if op != b'*' && op != b'/' && op != b'%' {
                return v;
            }
            (*ps).p = (*ps).p.add(1);
            let r = parse_atom(ps as _);
            if op == b'*' {
                v = v.wrapping_mul(r);
            } else if r == 0 {
                (*ps).err = 1;
            } else {
                v = if op == b'/' { v / r } else { v % r };
            }
        }
    }
}

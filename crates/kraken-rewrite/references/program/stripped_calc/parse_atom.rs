// Reference translation of stripped_calc `parse_atom`. parse_atom, parse_term and parse_expr
// call each other, so this translation carries the other two as private helpers; it calls the
// translated `skip_ws` and `parse_number`.

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

unsafe fn cur(ps: *mut Parser) -> u8 {
    unsafe { *(*ps).p }
}

unsafe fn advance(ps: *mut Parser) {
    unsafe { (*ps).p = (*ps).p.add(1) }
}

unsafe fn parse_term(ps: *mut Parser) -> i64 {
    unsafe {
        let mut v = parse_atom(ps);
        loop {
            skip_ws(ps as _);
            let op = cur(ps);
            if op != b'*' && op != b'/' && op != b'%' {
                return v;
            }
            advance(ps);
            let r = parse_atom(ps);
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

unsafe fn parse_expr(ps: *mut Parser) -> i64 {
    unsafe {
        let mut v = parse_term(ps);
        loop {
            skip_ws(ps as _);
            let op = cur(ps);
            if op != b'+' && op != b'-' {
                return v;
            }
            advance(ps);
            let r = parse_term(ps);
            v = if op == b'+' {
                v.wrapping_add(r)
            } else {
                v.wrapping_sub(r)
            };
        }
    }
}

/// atom = '(' expr ')' | '-' atom | number
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_atom(ps: *mut Parser) -> i64 {
    unsafe {
        skip_ws(ps as _);
        if cur(ps) == b'(' {
            advance(ps);
            let v = parse_expr(ps);
            skip_ws(ps as _);
            if cur(ps) != b')' {
                (*ps).err = 1;
            } else {
                advance(ps);
            }
            return v;
        }
        if cur(ps) == b'-' {
            advance(ps);
            return parse_atom(ps).wrapping_neg();
        }
        parse_number(ps as _)
    }
}

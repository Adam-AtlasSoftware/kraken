// Reference translation of stripped_calc `parse_number`; calls the translated `skip_ws`.

#[repr(C)]
pub struct Parser {
    pub p: *const u8,
    pub err: i32,
}

/// Reads decimal digits (after whitespace); sets `err` when there are none.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn parse_number(ps: *mut Parser) -> i64 {
    let mut v: i64 = 0;
    let mut any = false;
    unsafe {
        skip_ws(ps as _);
        while rt::isdigit(i32::from(*(*ps).p)) != 0 {
            v = v
                .wrapping_mul(10)
                .wrapping_add(i64::from(*(*ps).p - b'0'));
            (*ps).p = (*ps).p.add(1);
            any = true;
        }
        if !any {
            (*ps).err = 1;
        }
    }
    v
}

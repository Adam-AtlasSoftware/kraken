// Reference translation of static_strops `str_upper`: ASCII upper-casing in place.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn str_upper(s: *mut u8) {
    let mut p = s;
    unsafe {
        while *p != 0 {
            if *p >= b'a' && *p <= b'z' {
                *p = *p - b'a' + b'A';
            }
            p = p.add(1);
        }
    }
}

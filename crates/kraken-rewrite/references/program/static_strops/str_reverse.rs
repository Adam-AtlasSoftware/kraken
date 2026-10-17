// Reference translation of static_strops `str_reverse`: reverses a C string in place.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn str_reverse(s: *mut u8) {
    unsafe {
        let n = rt::strlen(s);
        let mut i = 0usize;
        while i < n / 2 {
            let t = *s.add(i);
            *s.add(i) = *s.add(n - 1 - i);
            *s.add(n - 1 - i) = t;
            i += 1;
        }
    }
}

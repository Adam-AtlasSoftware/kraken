// Reference translation of static_strops `is_palindrome`.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn is_palindrome(s: *const u8) -> i32 {
    unsafe {
        let n = rt::strlen(s);
        let mut i = 0usize;
        while i < n / 2 {
            if *s.add(i) != *s.add(n - 1 - i) {
                return 0;
            }
            i += 1;
        }
    }
    1
}

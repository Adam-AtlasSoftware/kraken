// Reference translation of static_strops `str_count_char`: occurrences of `c` in a C string.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn str_count_char(s: *const u8, c: i8) -> i32 {
    let mut count: i32 = 0;
    let mut p = s;
    unsafe {
        while *p != 0 {
            if *p as i8 == c {
                count += 1;
            }
            p = p.add(1);
        }
    }
    count
}

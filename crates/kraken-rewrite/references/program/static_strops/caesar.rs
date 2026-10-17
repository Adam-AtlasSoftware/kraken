// Reference translation of static_strops `caesar`: shifts lower-case letters, returns how many.
// C `%` keeps the sign of the dividend, as Rust's does.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn caesar(s: *mut u8, shift: i32) -> i32 {
    let mut changed: i32 = 0;
    let mut p = s;
    unsafe {
        while *p != 0 {
            if *p >= b'a' && *p <= b'z' {
                let v = (i32::from(*p) - i32::from(b'a')).wrapping_add(shift) % 26;
                *p = i32::from(b'a').wrapping_add(v) as u8;
                changed += 1;
            }
            p = p.add(1);
        }
    }
    changed
}

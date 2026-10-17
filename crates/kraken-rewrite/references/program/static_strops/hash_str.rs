// Reference translation of static_strops `hash_str` (corpus/src/static_strops.c): djb2 xor variant.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash_str(s: *const u8) -> u64 {
    let mut h: u64 = 5381;
    let mut p = s;
    unsafe {
        while *p != 0 {
            h = h.wrapping_shl(5).wrapping_add(h) ^ u64::from(*p);
            p = p.add(1);
        }
    }
    h
}

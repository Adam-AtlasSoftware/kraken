// Reference translation of static_strops `join_words`: joins `n` words with `sep` into `out`
// (capacity `cap`); returns the length, or -1 when it would not fit.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn join_words(
    out: *mut u8,
    cap: u64,
    words: *const *const u8,
    n: i32,
    sep: i8,
) -> i32 {
    let cap = cap as usize;
    let mut used: usize = 0;
    let mut i: i32 = 0;
    unsafe {
        while i < n {
            let w = *words.add(i as usize);
            let wl = rt::strlen(w);
            if used.wrapping_add(wl).wrapping_add(2) > cap {
                return -1;
            }
            rt::memcpy(out.add(used), w, wl);
            used += wl;
            if i + 1 < n {
                *out.add(used) = sep as u8;
                used += 1;
            }
            i += 1;
        }
        *out.add(used) = 0;
    }
    used as i32
}

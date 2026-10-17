// Reference translation of static_strops `main`; the entry point of the program. Calls the
// translated helpers and prints through the runtime shim.

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fn_401a5e() -> i32 {
    let words: [*const u8; 5] = [
        b"static\0".as_ptr(),
        b"linking\0".as_ptr(),
        b"keeps\0".as_ptr(),
        b"libc\0".as_ptr(),
        b"inside\0".as_ptr(),
    ];
    let mut buf = [0u8; 128];
    let mut tmp = [0u8; 128];
    let mut total: u64 = 0;
    unsafe {
        let len = join_words(buf.as_mut_ptr() as _, 128, words.as_ptr() as _, 5, 32);
        if len < 0 {
            return 1;
        }
        rt::printf(
            b"joined: %s (%d)\n\0".as_ptr(),
            &[rt::Arg::Ptr(buf.as_ptr()), rt::Arg::Int(i64::from(len))],
        );
        total = total.wrapping_add(hash_str(buf.as_ptr() as _));

        rt::strcpy(tmp.as_mut_ptr(), buf.as_ptr());
        str_reverse(tmp.as_mut_ptr() as _);
        rt::printf(b"reversed: %s\n\0".as_ptr(), &[rt::Arg::Ptr(tmp.as_ptr())]);
        total = total.wrapping_add(hash_str(tmp.as_ptr() as _));

        str_upper(tmp.as_mut_ptr() as _);
        rt::printf(b"upper: %s\n\0".as_ptr(), &[rt::Arg::Ptr(tmp.as_ptr())]);
        rt::printf(
            b"count of i: %d\n\0".as_ptr(),
            &[rt::Arg::Int(i64::from(str_count_char(
                buf.as_ptr() as _,
                b'i' as _,
            )))],
        );
        rt::printf(
            b"palindrome(level)=%d palindrome(buf)=%d\n\0".as_ptr(),
            &[
                rt::Arg::Int(i64::from(is_palindrome(b"level\0".as_ptr() as _))),
                rt::Arg::Int(i64::from(is_palindrome(buf.as_ptr() as _))),
            ],
        );

        let ch = caesar(buf.as_mut_ptr() as _, 3);
        rt::printf(
            b"caesar changed %d chars: %s\n\0".as_ptr(),
            &[rt::Arg::Int(i64::from(ch)), rt::Arg::Ptr(buf.as_ptr())],
        );

        let heap = rt::malloc(64);
        if heap.is_null() {
            return 2;
        }
        rt::snprintf(
            heap,
            64,
            b"hash=%lu\0".as_ptr(),
            &[rt::Arg::UInt(total % 100_000)],
        );
        rt::printf(b"%s\n\0".as_ptr(), &[rt::Arg::Ptr(heap)]);
        rt::free(heap);
    }
    0
}

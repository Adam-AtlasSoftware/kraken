//! The runtime shim (`kraken_rewrite::rt`): C semantics on Rust std, and its embedding rules.

use std::ffi::CString;

use kraken_rewrite::rt::{self, Arg};
use kraken_rewrite::{RT_PROMPT, RT_SOURCE, lint::lint_translation, rt_module_source};

fn fmt(format: &str, args: &[Arg]) -> String {
    let f = CString::new(format).expect("format");
    let out = unsafe { rt::format_c(f.as_ptr().cast(), args) };
    String::from_utf8(out).expect("utf8")
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

#[test]
fn printf_formats_like_c() {
    let s = cstr("abc");
    let p = |c: &CString| Arg::Ptr(c.as_ptr().cast());
    assert_eq!(fmt("plain\n", &[]), "plain\n");
    assert_eq!(fmt("%d|%i", &[Arg::Int(-5), Arg::Int(7)]), "-5|7");
    assert_eq!(
        fmt("%5d|%-5d|%05d", &[Arg::Int(42); 3]),
        "   42|42   |00042"
    );
    assert_eq!(fmt("%+d|% d", &[Arg::Int(3), Arg::Int(3)]), "+3| 3");
    assert_eq!(fmt("%.3d|%.0d|", &[Arg::Int(7), Arg::Int(0)]), "007||");
    // The value is narrowed to the C width.
    assert_eq!(fmt("%d", &[Arg::Int(0x1_0000_0001)]), "1");
    assert_eq!(fmt("%u", &[Arg::Int(-1)]), "4294967295");
    assert_eq!(fmt("%lu", &[Arg::Int(-1)]), "18446744073709551615");
    assert_eq!(fmt("%ld", &[Arg::Int(i64::MIN)]), "-9223372036854775808");
    assert_eq!(
        fmt("%hhd|%hd", &[Arg::Int(200), Arg::Int(70000)]),
        "-56|4464"
    );
    assert_eq!(
        fmt("%x|%X|%#x|%#o|%o", &[Arg::UInt(255); 5]),
        "ff|FF|0xff|0377|377"
    );
    assert_eq!(fmt("%#x", &[Arg::UInt(0)]), "0");
    assert_eq!(fmt("%08.3x", &[Arg::UInt(255)]), "     0ff");
    assert_eq!(fmt("%c%c", &[Arg::Int(72), Arg::Int(105)]), "Hi");
    assert_eq!(
        fmt("%s|%5s|%-5s|%.2s", &[p(&s), p(&s), p(&s), p(&s)]),
        "abc|  abc|abc  |ab"
    );
    assert_eq!(fmt("%s", &[Arg::Ptr(std::ptr::null())]), "(null)");
    assert_eq!(
        fmt("%-18s=%ld", &[p(&s), Arg::Int(9)]),
        "abc               =9"
    );
    assert_eq!(
        fmt(
            "%*d|%-*d|",
            &[Arg::Int(4), Arg::Int(1), Arg::Int(3), Arg::Int(2)]
        ),
        "   1|2  |"
    );
    assert_eq!(fmt("100%%", &[]), "100%");
    assert_eq!(
        fmt("%p|%p", &[Arg::Ptr(std::ptr::null()), Arg::UInt(0x10)]),
        "(nil)|0x10"
    );
    // Missing arguments read as zero; unknown conversions pass through.
    assert_eq!(fmt("%d %d", &[Arg::Int(1)]), "1 0");
    assert_eq!(fmt("%y", &[]), "%y");
    assert_eq!(fmt("trailing %", &[]), "trailing %");
}

#[test]
fn snprintf_truncates_and_reports_the_full_length() {
    let f = cstr("hash=%lu");
    let mut buf = [0xaau8; 16];
    let n = unsafe {
        rt::snprintf(
            buf.as_mut_ptr(),
            16,
            f.as_ptr().cast(),
            &[Arg::UInt(123_456)],
        )
    };
    assert_eq!((n, &buf[..12]), (11, &b"hash=123456\0"[..]));
    let mut small = [0xaau8; 4];
    let n = unsafe { rt::snprintf(small.as_mut_ptr(), 4, f.as_ptr().cast(), &[Arg::UInt(7)]) };
    assert_eq!((n, &small), (6, b"has\0"));
    let mut none = [0xaau8; 2];
    assert_eq!(
        unsafe { rt::snprintf(none.as_mut_ptr(), 0, f.as_ptr().cast(), &[Arg::UInt(7)]) },
        6
    );
    assert_eq!(none, [0xaa; 2], "n == 0 writes nothing");
}

#[test]
fn printf_formats_floating_point_like_c() {
    assert_eq!(fmt("%f", &[Arg::Double(1.234_56)]), "1.234560");
    assert_eq!(
        fmt("%.2f|%8.3f|%-8.1f|", &[Arg::Double(2.5); 3]),
        "2.50|   2.500|2.5     |"
    );
    assert_eq!(fmt("%f", &[Arg::Double(-0.5)]), "-0.500000");
    assert_eq!(fmt("%e", &[Arg::Double(12345.678)]), "1.234568e+04");
    assert_eq!(fmt("%.1E", &[Arg::Double(0.00012)]), "1.2E-04");
    assert_eq!(
        fmt(
            "%g|%g|%g",
            &[Arg::Double(100000.0), Arg::Double(1e6), Arg::Double(0.0001)]
        ),
        "100000|1e+06|0.0001"
    );
    assert_eq!(fmt("%g", &[Arg::Double(0.5)]), "0.5");
    assert_eq!(fmt("%f", &[Arg::Double(f64::INFINITY)]), "inf");
}

#[test]
fn string_functions_follow_libc() {
    let a = cstr("apple");
    let b = cstr("apricot");
    let pa = a.as_ptr().cast::<u8>();
    let pb = b.as_ptr().cast::<u8>();
    unsafe {
        assert_eq!(rt::strlen(pa), 5);
        assert_eq!(rt::strnlen(pa, 3), 3);
        assert!(rt::strcmp(pa, pb) < 0 && rt::strcmp(pb, pa) > 0);
        assert_eq!(rt::strcmp(pa, pa), 0);
        assert_eq!(rt::strncmp(pa, pb, 2), 0);
        assert!(rt::strncmp(pa, pb, 3) != 0);
        // Unsigned comparison of bytes, as libc does.
        let hi = [0xffu8, 0];
        let lo = [0x01u8, 0];
        assert!(rt::strcmp(hi.as_ptr(), lo.as_ptr()) > 0);

        let mut buf = [0xaau8; 16];
        rt::strcpy(buf.as_mut_ptr(), pa);
        assert_eq!(&buf[..6], b"apple\0");
        rt::strcat(buf.as_mut_ptr(), pb);
        assert_eq!(&buf[..13], b"appleapricot\0");
        let mut n = [0xaau8; 8];
        rt::strncpy(n.as_mut_ptr(), pa, 8);
        assert_eq!(&n, b"apple\0\0\0");
        let mut t = [0xaau8; 3];
        rt::strncpy(t.as_mut_ptr(), pa, 3);
        assert_eq!(&t, b"app");

        assert_eq!(rt::strchr(pa, i32::from(b'p')) as usize - pa as usize, 1);
        assert_eq!(rt::strrchr(pa, i32::from(b'p')) as usize - pa as usize, 2);
        assert!(rt::strchr(pa, i32::from(b'z')).is_null());
        assert_eq!(rt::strchr(pa, 0) as usize - pa as usize, 5);
        let needle = cstr("ple");
        assert_eq!(
            rt::strstr(pa, needle.as_ptr().cast()) as usize - pa as usize,
            2
        );
        assert!(rt::strstr(pa, cstr("zz").as_ptr().cast()).is_null());

        let d = rt::strdup(pa);
        assert_eq!(rt::strcmp(d, pa), 0);
        rt::free(d);

        let mut m = [0u8; 6];
        rt::memset(m.as_mut_ptr(), 7, 4);
        assert_eq!(m, [7, 7, 7, 7, 0, 0]);
        rt::memcpy(m.as_mut_ptr().add(2), pa, 4);
        assert_eq!(&m, b"\x07\x07appl");
        rt::memmove(m.as_mut_ptr().add(1), m.as_ptr(), 4);
        assert_eq!(rt::memcmp(m.as_ptr(), m.as_ptr(), 6), 0);
        assert!(rt::memcmp(pa, pb, 5) < 0);
        assert_eq!(rt::memchr(pa, i32::from(b'l'), 5) as usize - pa as usize, 3);
        assert!(rt::memchr(pa, i32::from(b'l'), 3).is_null());
    }
}

#[test]
fn ctype_is_the_c_locale() {
    for c in 0..256i32 {
        let ch = c as u8 as char;
        assert_eq!(rt::isdigit(c) != 0, c < 128 && ch.is_ascii_digit(), "{c}");
        assert_eq!(
            rt::isalpha(c) != 0,
            c < 128 && ch.is_ascii_alphabetic(),
            "{c}"
        );
        assert_eq!(
            rt::isalnum(c) != 0,
            c < 128 && ch.is_ascii_alphanumeric(),
            "{c}"
        );
        assert_eq!(
            rt::isupper(c) != 0,
            c < 128 && ch.is_ascii_uppercase(),
            "{c}"
        );
        assert_eq!(
            rt::islower(c) != 0,
            c < 128 && ch.is_ascii_lowercase(),
            "{c}"
        );
        assert_eq!(
            rt::isxdigit(c) != 0,
            c < 128 && ch.is_ascii_hexdigit(),
            "{c}"
        );
        assert_eq!(
            rt::ispunct(c) != 0,
            c < 128 && ch.is_ascii_punctuation(),
            "{c}"
        );
        assert_eq!(rt::isprint(c) != 0, (0x20..0x7f).contains(&c), "{c}");
        // C isspace: space, \t \n \v \f \r (Rust's is_ascii_whitespace leaves out \v).
        assert_eq!(
            rt::isspace(c) != 0,
            c == 0x20 || (0x09..=0x0d).contains(&c),
            "{c}"
        );
        assert_eq!(
            rt::toupper(c),
            if c < 128 {
                i32::from(ch.to_ascii_uppercase() as u8)
            } else {
                c
            }
        );
        assert_eq!(
            rt::tolower(c),
            if c < 128 {
                i32::from(ch.to_ascii_lowercase() as u8)
            } else {
                c
            }
        );
    }
}

#[test]
fn malloc_is_aligned_zeroed_by_calloc_and_reallocs_keep_data() {
    unsafe {
        let p = rt::malloc(40);
        assert!(!p.is_null());
        assert_eq!(p as usize % 16, 0);
        std::ptr::write_bytes(p, 0x5a, 40);
        let q = rt::realloc(p, 100);
        assert_eq!(std::slice::from_raw_parts(q, 40), [0x5au8; 40]);
        let r = rt::realloc(q, 8);
        assert_eq!(std::slice::from_raw_parts(r, 8), [0x5au8; 8]);
        rt::free(r);
        rt::free(std::ptr::null_mut());

        let z = rt::calloc(5, 8);
        assert_eq!(std::slice::from_raw_parts(z, 40), [0u8; 40]);
        rt::free(z);
        assert!(rt::calloc(usize::MAX, 2).is_null());
        assert!(rt::malloc(usize::MAX).is_null());
        let zero = rt::malloc(0);
        assert!(!zero.is_null());
        rt::free(zero);
        assert!(rt::realloc(std::ptr::null_mut(), 4) as usize != 0);
    }
}

#[test]
fn numbers_parse_like_strtol() {
    unsafe {
        let parse = |s: &str, base: i32| {
            let c = cstr(s);
            let mut end: *const u8 = std::ptr::null();
            let v = rt::strtol(c.as_ptr().cast(), &mut end, base);
            (v, end as usize - c.as_ptr() as usize)
        };
        assert_eq!(parse("42abc", 10), (42, 2));
        assert_eq!(parse("  -17 rest", 10), (-17, 5));
        assert_eq!(parse("+8", 10), (8, 2));
        assert_eq!(parse("0x1F", 0), (31, 4));
        assert_eq!(parse("0x1F", 16), (31, 4));
        assert_eq!(parse("017", 0), (15, 3));
        assert_eq!(parse("017", 10), (17, 3));
        assert_eq!(parse("zz", 36), (35 * 36 + 35, 2));
        assert_eq!(parse("abc", 10), (0, 0));
        assert_eq!(parse("99999999999999999999999", 10).0, i64::MAX);
        assert_eq!(parse("-99999999999999999999999", 10).0, i64::MIN);
        assert_eq!(parse("-9223372036854775808", 10).0, i64::MIN);
        assert_eq!(rt::atoi(cstr("  123x").as_ptr().cast()), 123);
        assert_eq!(rt::atol(cstr("-5").as_ptr().cast()), -5);
        assert_eq!(rt::abs(-3), 3);
        assert_eq!(rt::abs(i32::MIN), i32::MIN);
        assert_eq!(rt::labs(-3), 3);
    }
}

#[test]
fn the_embedded_shim_passes_the_translation_lint_and_is_the_compiled_one() {
    assert_eq!(lint_translation(&rt_module_source()), None);
    assert!(RT_SOURCE.contains("pub unsafe fn format_c("));
    let module = rt_module_source();
    assert!(module.starts_with("#[allow(dead_code, unused)]\nmod rt {"));
    assert!(!module.contains("//!"), "inner documentation is dropped");
}

#[test]
fn the_prompt_lists_only_functions_the_shim_has() {
    let mut named = 0;
    for part in RT_PROMPT.split("`rt::").skip(1) {
        let name: String = part
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name == "Arg" {
            continue;
        }
        named += 1;
        let ok = [format!("pub fn {name}("), format!("pub unsafe fn {name}(")]
            .iter()
            .any(|d| RT_SOURCE.contains(d));
        assert!(
            ok,
            "the prompt names rt::{name}, which the shim does not define"
        );
    }
    assert!(named > 40, "{named}");
}

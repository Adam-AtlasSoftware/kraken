//! KRAKEN runtime shim: the libc calls rewritten programs make, mapped to Rust `std`.
//!
//! This file is compiled into `kraken-rewrite` (so it is tested like any module) and embedded as
//! text ([`crate::RT_SOURCE`]): the generated program crate gets it as `src/rt.rs`, and the
//! function-level test of a translation gets it as a private `mod rt` in front of the code. It
//! therefore stays inside what the translation lint allows (std only, no attributes but outer
//! lint levels and derives, no `cfg`, no inner attributes) and uses no `crate::` paths.
//!
//! C strings are `*const u8` to NUL-terminated bytes. Nothing here is thread-safe in the way libc
//! is: the programs it serves are single-threaded. Output goes through Rust's stdout and stderr,
//! which flush at every newline (libc buffers stdout fully when it is a pipe); only the order of
//! stdout against stderr could show the difference, and the program-level test captures them
//! separately.

use std::io::Write;

/// One variadic argument of [`printf`] and friends, as the translation passes it.
#[derive(Clone, Copy, Debug)]
pub enum Arg {
    /// A signed integer of any C width (widen with `as i64`).
    Int(i64),
    /// An unsigned integer of any C width (widen with `as u64`).
    UInt(u64),
    /// A pointer (`%s` reads a C string through it, `%p` prints it).
    Ptr(*const u8),
    /// A double.
    Double(f64),
}

fn next_int(args: &[Arg], at: &mut usize) -> i64 {
    let v = match args.get(*at) {
        Some(Arg::Int(v)) => *v,
        Some(Arg::UInt(v)) => *v as i64,
        Some(Arg::Ptr(p)) => *p as usize as i64,
        Some(Arg::Double(d)) => *d as i64,
        None => 0,
    };
    *at += 1;
    v
}

fn pad(out: &mut Vec<u8>, body: &[u8], width: usize, left: bool, zero: bool, sign_len: usize) {
    if body.len() >= width {
        out.extend_from_slice(body);
    } else if left {
        out.extend_from_slice(body);
        out.resize(out.len() + (width - body.len()), b' ');
    } else if zero {
        out.extend_from_slice(&body[..sign_len]);
        out.resize(out.len() + (width - body.len()), b'0');
        out.extend_from_slice(&body[sign_len..]);
    } else {
        out.resize(out.len() + (width - body.len()), b' ');
        out.extend_from_slice(body);
    }
}

fn exp_form(v: f64, prec: usize, upper: bool) -> String {
    let s = format!("{:.*e}", prec, v);
    let (mant, exp) = s.split_once('e').unwrap_or((&s, "0"));
    let e: i32 = exp.parse().unwrap_or(0);
    let sign = if e < 0 { '-' } else { '+' };
    let r = format!("{mant}e{sign}{:02}", e.abs());
    if upper { r.to_uppercase() } else { r }
}

fn general_form(v: f64, prec: usize, upper: bool, keep_zeros: bool) -> String {
    let p = if prec == 0 { 1 } else { prec };
    if v == 0.0 {
        return if keep_zeros && p > 1 {
            format!("{:.*}", p - 1, 0.0)
        } else {
            "0".to_string()
        };
    }
    let exp = format!("{:.*e}", p - 1, v)
        .split_once('e')
        .and_then(|(_, e)| e.parse::<i32>().ok())
        .unwrap_or(0);
    let mut s = if exp < -4 || exp >= p as i32 {
        exp_form(v, p - 1, upper)
    } else {
        format!("{:.*}", (p as i32 - 1 - exp).max(0) as usize, v)
    };
    if !keep_zeros {
        let (mant, rest) = match s.find(['e', 'E']) {
            Some(i) => (s[..i].to_string(), s[i..].to_string()),
            None => (s.clone(), String::new()),
        };
        let mant = if mant.contains('.') {
            mant.trim_end_matches('0').trim_end_matches('.').to_string()
        } else {
            mant
        };
        s = format!("{mant}{rest}");
    }
    s
}

/// Formats like C `printf`: flags `-+ #0`, width and precision (also `*`), length modifiers
/// `hh h l ll z j t L`, conversions `d i u x X o c s p f F e E g G %`. A missing argument reads
/// as zero, an unknown conversion is copied through.
///
/// # Safety
/// `fmt` must point to a NUL-terminated string, and every `Arg::Ptr` used by `%s` must point to
/// one.
pub unsafe fn format_c(fmt: *const u8, args: &[Arg]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut at = 0usize;
    let mut i = 0usize;
    loop {
        let c = unsafe { *fmt.add(i) };
        if c == 0 {
            break;
        }
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        let start = i - 1;
        let (mut left, mut plus, mut space, mut alt, mut zero) =
            (false, false, false, false, false);
        loop {
            match unsafe { *fmt.add(i) } {
                b'-' => left = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alt = true,
                b'0' => zero = true,
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if unsafe { *fmt.add(i) } == b'*' {
            let w = next_int(args, &mut at);
            if w < 0 {
                left = true;
            }
            width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while unsafe { *fmt.add(i) }.is_ascii_digit() {
                width = width * 10 + usize::from(unsafe { *fmt.add(i) } - b'0');
                i += 1;
            }
        }
        let mut prec: Option<usize> = None;
        if unsafe { *fmt.add(i) } == b'.' {
            i += 1;
            let mut p = 0usize;
            if unsafe { *fmt.add(i) } == b'*' {
                let v = next_int(args, &mut at);
                prec = if v < 0 { None } else { Some(v as usize) };
                i += 1;
            } else {
                while unsafe { *fmt.add(i) }.is_ascii_digit() {
                    p = p * 10 + usize::from(unsafe { *fmt.add(i) } - b'0');
                    i += 1;
                }
                prec = Some(p);
            }
        }
        // Length: 0 = int, 1 = hh, 2 = h, 3 = long-sized.
        let mut len = 0u8;
        loop {
            match unsafe { *fmt.add(i) } {
                b'h' => len = if len == 2 { 1 } else { 2 },
                b'l' | b'z' | b'j' | b't' | b'q' => len = 3,
                b'L' => len = 3,
                _ => break,
            }
            i += 1;
        }
        let conv = unsafe { *fmt.add(i) };
        if conv == 0 {
            out.extend_from_slice(unsafe { std::slice::from_raw_parts(fmt.add(start), i - start) });
            break;
        }
        i += 1;
        match conv {
            b'%' => out.push(b'%'),
            b'd' | b'i' => {
                let raw = next_int(args, &mut at);
                let v: i64 = match len {
                    1 => raw as i8 as i64,
                    2 => raw as i16 as i64,
                    3 => raw,
                    _ => raw as i32 as i64,
                };
                let mut digits = v.unsigned_abs().to_string();
                if let Some(p) = prec {
                    if p == 0 && v == 0 {
                        digits.clear();
                    }
                    while digits.len() < p {
                        digits.insert(0, '0');
                    }
                }
                let sign = if v < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                let body = format!("{sign}{digits}");
                pad(
                    &mut out,
                    body.as_bytes(),
                    width,
                    left,
                    zero && prec.is_none(),
                    sign.len(),
                );
            }
            b'u' | b'x' | b'X' | b'o' => {
                let raw = next_int(args, &mut at) as u64;
                let v: u64 = match len {
                    1 => raw as u8 as u64,
                    2 => raw as u16 as u64,
                    3 => raw,
                    _ => raw as u32 as u64,
                };
                let mut digits = match conv {
                    b'u' => v.to_string(),
                    b'x' => format!("{v:x}"),
                    b'X' => format!("{v:X}"),
                    _ => format!("{v:o}"),
                };
                if let Some(p) = prec {
                    if p == 0 && v == 0 {
                        digits.clear();
                    }
                    while digits.len() < p {
                        digits.insert(0, '0');
                    }
                }
                let prefix = match (alt, conv) {
                    (true, b'x') if v != 0 => "0x",
                    (true, b'X') if v != 0 => "0X",
                    (true, b'o') if !digits.starts_with('0') => "0",
                    _ => "",
                };
                let body = format!("{prefix}{digits}");
                pad(
                    &mut out,
                    body.as_bytes(),
                    width,
                    left,
                    zero && prec.is_none(),
                    prefix.len(),
                );
            }
            b'c' => {
                let v = next_int(args, &mut at) as u8;
                pad(&mut out, &[v], width, left, false, 0);
            }
            b's' => {
                let p = match args.get(at) {
                    Some(Arg::Ptr(p)) => *p,
                    Some(Arg::Int(v)) => *v as usize as *const u8,
                    Some(Arg::UInt(v)) => *v as usize as *const u8,
                    _ => std::ptr::null(),
                };
                at += 1;
                let bytes: Vec<u8> = if p.is_null() {
                    b"(null)".to_vec()
                } else {
                    let mut n = 0usize;
                    while unsafe { *p.add(n) } != 0 && prec.is_none_or(|m| n < m) {
                        n += 1;
                    }
                    unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
                };
                pad(&mut out, &bytes, width, left, false, 0);
            }
            b'p' => {
                let v = next_int(args, &mut at) as u64;
                let body = if v == 0 {
                    "(nil)".to_string()
                } else {
                    format!("{v:#x}")
                };
                pad(&mut out, body.as_bytes(), width, left, false, 0);
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' => {
                let v = match args.get(at) {
                    Some(Arg::Double(d)) => *d,
                    Some(Arg::Int(n)) => *n as f64,
                    Some(Arg::UInt(n)) => *n as f64,
                    _ => 0.0,
                };
                at += 1;
                let p = prec.unwrap_or(6);
                let mut body = if v.is_nan() {
                    "nan".to_string()
                } else if v.is_infinite() {
                    "inf".to_string()
                } else {
                    match conv {
                        b'f' | b'F' => format!("{:.*}", p, v.abs()),
                        b'e' | b'E' => exp_form(v.abs(), p, conv == b'E'),
                        _ => general_form(v.abs(), p, conv == b'G', alt),
                    }
                };
                if conv.is_ascii_uppercase() {
                    body = body.to_uppercase();
                }
                let sign = if v.is_sign_negative() && !v.is_nan() {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                let body = format!("{sign}{body}");
                pad(
                    &mut out,
                    body.as_bytes(),
                    width,
                    left,
                    zero && v.is_finite(),
                    sign.len(),
                );
            }
            _ => out.extend_from_slice(unsafe {
                std::slice::from_raw_parts(fmt.add(start), i - start)
            }),
        }
    }
    out
}

fn write_stdout(bytes: &[u8]) {
    let _ = std::io::stdout().write_all(bytes);
}

fn write_stderr(bytes: &[u8]) {
    let _ = std::io::stderr().write_all(bytes);
}

/// `printf`.
///
/// # Safety
/// See [`format_c`].
pub unsafe fn printf(fmt: *const u8, args: &[Arg]) -> i32 {
    let bytes = unsafe { format_c(fmt, args) };
    write_stdout(&bytes);
    bytes.len() as i32
}

/// `fprintf(stderr, ...)`.
///
/// # Safety
/// See [`format_c`].
pub unsafe fn eprintf(fmt: *const u8, args: &[Arg]) -> i32 {
    let bytes = unsafe { format_c(fmt, args) };
    write_stderr(&bytes);
    bytes.len() as i32
}

/// `snprintf`: writes at most `n - 1` bytes and a NUL (nothing when `n` is 0) and returns the
/// length the whole output has.
///
/// # Safety
/// `dst` writable for `n` bytes; see [`format_c`].
pub unsafe fn snprintf(dst: *mut u8, n: usize, fmt: *const u8, args: &[Arg]) -> i32 {
    let bytes = unsafe { format_c(fmt, args) };
    if n > 0 {
        let k = bytes.len().min(n - 1);
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, k);
            *dst.add(k) = 0;
        }
    }
    bytes.len() as i32
}

/// `puts`: the string and a newline.
///
/// # Safety
/// `s` must be NUL-terminated.
pub unsafe fn puts(s: *const u8) -> i32 {
    let n = unsafe { strlen(s) };
    let mut b = unsafe { std::slice::from_raw_parts(s, n) }.to_vec();
    b.push(b'\n');
    write_stdout(&b);
    1
}

/// `fputs(s, stdout)`: the string without a newline.
///
/// # Safety
/// `s` must be NUL-terminated.
pub unsafe fn fputs(s: *const u8) -> i32 {
    let n = unsafe { strlen(s) };
    write_stdout(unsafe { std::slice::from_raw_parts(s, n) });
    1
}

/// `fputs(s, stderr)`.
///
/// # Safety
/// `s` must be NUL-terminated.
pub unsafe fn eputs(s: *const u8) -> i32 {
    let n = unsafe { strlen(s) };
    write_stderr(unsafe { std::slice::from_raw_parts(s, n) });
    1
}

/// `putchar`.
pub fn putchar(c: i32) -> i32 {
    write_stdout(&[c as u8]);
    c as u8 as i32
}

/// `fputc(c, stderr)`.
pub fn eputc(c: i32) -> i32 {
    write_stderr(&[c as u8]);
    c as u8 as i32
}

/// `fflush(stdout)`.
pub fn fflush_stdout() -> i32 {
    let _ = std::io::stdout().flush();
    0
}

/// `exit`: flushes stdout like libc and ends the process.
pub fn exit(code: i32) -> ! {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// `abort`.
pub fn abort() -> ! {
    let _ = std::io::stdout().flush();
    std::process::abort()
}

// ----- <string.h> -----

/// `strlen`.
///
/// # Safety
/// `s` must be NUL-terminated.
pub unsafe fn strlen(s: *const u8) -> usize {
    let mut n = 0usize;
    while unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `strnlen`.
///
/// # Safety
/// `s` must be readable up to its NUL or `max` bytes.
pub unsafe fn strnlen(s: *const u8, max: usize) -> usize {
    let mut n = 0usize;
    while n < max && unsafe { *s.add(n) } != 0 {
        n += 1;
    }
    n
}

/// `strcmp`: the difference of the first differing bytes, as unsigned chars.
///
/// # Safety
/// Both must be NUL-terminated.
pub unsafe fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0usize;
    loop {
        let (x, y) = (unsafe { *a.add(i) }, unsafe { *b.add(i) });
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
}

/// `strncmp`.
///
/// # Safety
/// Both must be readable up to their NUL or `n` bytes.
pub unsafe fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i < n {
        let (x, y) = (unsafe { *a.add(i) }, unsafe { *b.add(i) });
        if x != y || x == 0 {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
    0
}

/// `strcpy`.
///
/// # Safety
/// `src` NUL-terminated, `dst` large enough, no overlap.
pub unsafe fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    let mut i = 0usize;
    loop {
        let c = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = c };
        if c == 0 {
            return dst;
        }
        i += 1;
    }
}

/// `strncpy`: pads with NULs up to `n`, does not terminate a truncated copy.
///
/// # Safety
/// `dst` writable for `n` bytes, `src` readable up to its NUL or `n` bytes.
pub unsafe fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0usize;
    while i < n && unsafe { *src.add(i) } != 0 {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
    while i < n {
        unsafe { *dst.add(i) = 0 };
        i += 1;
    }
    dst
}

/// `strcat`.
///
/// # Safety
/// As `strcpy`, and `dst` NUL-terminated.
pub unsafe fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    let n = unsafe { strlen(dst) };
    unsafe { strcpy(dst.add(n), src) };
    dst
}

/// `strchr`: also finds the terminating NUL when `c` is 0.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn strchr(s: *const u8, c: i32) -> *mut u8 {
    let target = c as u8;
    let mut i = 0usize;
    loop {
        let x = unsafe { *s.add(i) };
        if x == target {
            return unsafe { s.add(i) } as *mut u8;
        }
        if x == 0 {
            return std::ptr::null_mut();
        }
        i += 1;
    }
}

/// `strrchr`.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn strrchr(s: *const u8, c: i32) -> *mut u8 {
    let target = c as u8;
    let mut found: *mut u8 = std::ptr::null_mut();
    let mut i = 0usize;
    loop {
        let x = unsafe { *s.add(i) };
        if x == target {
            found = unsafe { s.add(i) } as *mut u8;
        }
        if x == 0 {
            return found;
        }
        i += 1;
    }
}

/// `strstr`.
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn strstr(hay: *const u8, needle: *const u8) -> *mut u8 {
    let n = unsafe { strlen(needle) };
    if n == 0 {
        return hay as *mut u8;
    }
    let mut i = 0usize;
    while unsafe { *hay.add(i) } != 0 {
        if unsafe { strncmp(hay.add(i), needle, n) } == 0 {
            return unsafe { hay.add(i) } as *mut u8;
        }
        i += 1;
    }
    std::ptr::null_mut()
}

/// `strdup`.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn strdup(s: *const u8) -> *mut u8 {
    let n = unsafe { strlen(s) };
    let p = unsafe { malloc(n + 1) };
    if !p.is_null() {
        unsafe { std::ptr::copy_nonoverlapping(s, p, n + 1) };
    }
    p
}

/// `memcpy`.
///
/// # Safety
/// Valid for `n` bytes, no overlap.
pub unsafe fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { std::ptr::copy_nonoverlapping(src, dst, n) };
    dst
}

/// `memmove`.
///
/// # Safety
/// Valid for `n` bytes.
pub unsafe fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    unsafe { std::ptr::copy(src, dst, n) };
    dst
}

/// `memset`.
///
/// # Safety
/// `dst` writable for `n` bytes.
pub unsafe fn memset(dst: *mut u8, c: i32, n: usize) -> *mut u8 {
    unsafe { std::ptr::write_bytes(dst, c as u8, n) };
    dst
}

/// `memcmp`.
///
/// # Safety
/// Readable for `n` bytes.
pub unsafe fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i < n {
        let (x, y) = (unsafe { *a.add(i) }, unsafe { *b.add(i) });
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        i += 1;
    }
    0
}

/// `memchr`.
///
/// # Safety
/// Readable for `n` bytes.
pub unsafe fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0usize;
    while i < n {
        if unsafe { *s.add(i) } == c as u8 {
            return unsafe { s.add(i) } as *mut u8;
        }
        i += 1;
    }
    std::ptr::null_mut()
}

// ----- <ctype.h>, C locale -----

/// `isspace`.
pub fn isspace(c: i32) -> i32 {
    i32::from(matches!(c, 0x20 | 0x09..=0x0d))
}

/// `isdigit`.
pub fn isdigit(c: i32) -> i32 {
    i32::from((0x30..=0x39).contains(&c))
}

/// `isalpha`.
pub fn isalpha(c: i32) -> i32 {
    i32::from((0x41..=0x5a).contains(&c) || (0x61..=0x7a).contains(&c))
}

/// `isalnum`.
pub fn isalnum(c: i32) -> i32 {
    i32::from(isalpha(c) != 0 || isdigit(c) != 0)
}

/// `isupper`.
pub fn isupper(c: i32) -> i32 {
    i32::from((0x41..=0x5a).contains(&c))
}

/// `islower`.
pub fn islower(c: i32) -> i32 {
    i32::from((0x61..=0x7a).contains(&c))
}

/// `isxdigit`.
pub fn isxdigit(c: i32) -> i32 {
    i32::from(isdigit(c) != 0 || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c))
}

/// `isprint`.
pub fn isprint(c: i32) -> i32 {
    i32::from((0x20..=0x7e).contains(&c))
}

/// `ispunct`.
pub fn ispunct(c: i32) -> i32 {
    i32::from(isprint(c) != 0 && c != 0x20 && isalnum(c) == 0)
}

/// `toupper`.
pub fn toupper(c: i32) -> i32 {
    if islower(c) != 0 { c - 0x20 } else { c }
}

/// `tolower`.
pub fn tolower(c: i32) -> i32 {
    if isupper(c) != 0 { c + 0x20 } else { c }
}

// ----- <stdlib.h> -----

/// Bytes in front of every block that `malloc` returns: the block size, kept 16-aligned.
const HEADER: usize = 16;

/// `malloc`: 16-byte aligned, null on failure; `malloc(0)` returns a valid unique pointer.
///
/// # Safety
/// The result must be released with [`free`] or [`realloc`] only.
pub unsafe fn malloc(n: usize) -> *mut u8 {
    let Some(total) = n.checked_add(HEADER) else {
        return std::ptr::null_mut();
    };
    let Ok(layout) = std::alloc::Layout::from_size_align(total, 16) else {
        return std::ptr::null_mut();
    };
    let base = unsafe { std::alloc::alloc(layout) };
    if base.is_null() {
        return base;
    }
    unsafe { *(base as *mut usize) = n };
    unsafe { base.add(HEADER) }
}

/// `calloc`: zeroed, null when `count * size` overflows.
///
/// # Safety
/// As [`malloc`].
pub unsafe fn calloc(count: usize, size: usize) -> *mut u8 {
    let Some(n) = count.checked_mul(size) else {
        return std::ptr::null_mut();
    };
    let p = unsafe { malloc(n) };
    if !p.is_null() {
        unsafe { std::ptr::write_bytes(p, 0, n) };
    }
    p
}

/// `free`; null is a no-op.
///
/// # Safety
/// `p` must come from [`malloc`], [`calloc`], [`realloc`] or [`strdup`] and not be freed twice.
pub unsafe fn free(p: *mut u8) {
    if p.is_null() {
        return;
    }
    let base = unsafe { p.sub(HEADER) };
    let n = unsafe { *(base as *mut usize) };
    let layout = unsafe { std::alloc::Layout::from_size_align_unchecked(n + HEADER, 16) };
    unsafe { std::alloc::dealloc(base, layout) };
}

/// `realloc`.
///
/// # Safety
/// As [`free`].
pub unsafe fn realloc(p: *mut u8, n: usize) -> *mut u8 {
    if p.is_null() {
        return unsafe { malloc(n) };
    }
    let old = unsafe { *(p.sub(HEADER) as *mut usize) };
    let q = unsafe { malloc(n) };
    if q.is_null() {
        return q;
    }
    unsafe { std::ptr::copy_nonoverlapping(p, q, old.min(n)) };
    unsafe { free(p) };
    q
}

/// `abs`.
pub fn abs(v: i32) -> i32 {
    v.wrapping_abs()
}

/// `labs`.
pub fn labs(v: i64) -> i64 {
    v.wrapping_abs()
}

/// `strtol`: base 0, 2 to 36; sets `*end` (when not null) past the digits read; saturates on
/// overflow like libc. `errno` is not modelled.
///
/// # Safety
/// `s` NUL-terminated; `end`, when not null, writable.
pub unsafe fn strtol(s: *const u8, end: *mut *const u8, base: i32) -> i64 {
    let mut i = 0usize;
    while isspace(i32::from(unsafe { *s.add(i) })) != 0 {
        i += 1;
    }
    let mut neg = false;
    match unsafe { *s.add(i) } {
        b'-' => {
            neg = true;
            i += 1;
        }
        b'+' => i += 1,
        _ => {}
    }
    let mut base = base as u32;
    let is_hex_prefix = unsafe { *s.add(i) } == b'0'
        && matches!(unsafe { *s.add(i + 1) }, b'x' | b'X')
        && unsafe { *s.add(i + 2) }.is_ascii_hexdigit();
    if (base == 0 || base == 16) && is_hex_prefix {
        i += 2;
        base = 16;
    } else if base == 0 {
        base = if unsafe { *s.add(i) } == b'0' { 8 } else { 10 };
    }
    let digits_start = i;
    let mut acc: u128 = 0;
    let mut overflow = false;
    while let Some(d) = (unsafe { *s.add(i) } as char).to_digit(36) {
        if d >= base {
            break;
        }
        acc = acc * u128::from(base) + u128::from(d);
        if acc > u128::from(u64::MAX) {
            overflow = true;
            acc = u128::from(u64::MAX);
        }
        i += 1;
    }
    if !end.is_null() {
        let at = if i == digits_start { 0 } else { i };
        unsafe { *end = s.add(at) };
    }
    let limit = if neg { 1u128 << 63 } else { (1u128 << 63) - 1 };
    if overflow || acc > limit {
        return if neg { i64::MIN } else { i64::MAX };
    }
    if neg {
        (acc as i128).wrapping_neg() as i64
    } else {
        acc as i64
    }
}

/// `atoi`.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn atoi(s: *const u8) -> i32 {
    unsafe { strtol(s, std::ptr::null_mut(), 10) as i32 }
}

/// `atol`.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn atol(s: *const u8) -> i64 {
    unsafe { strtol(s, std::ptr::null_mut(), 10) }
}

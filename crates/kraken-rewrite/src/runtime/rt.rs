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
                // glibc prints the sign of a NaN too (`-nan`).
                let sign = if v.is_sign_negative() {
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

// ----- tracing: where did this output byte come from? -----
//
// The program-level repair asks the rewritten program for the call stack at the moment it writes
// the first byte that differs from the original, or at `exit`. The generated `main` arms this
// from `KRAKEN_TRACE_AT` (`out:<byte>`, `err:<byte>` or `exit`); without it nothing happens.

static TRACE_KIND: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static TRACE_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static OUT_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static ERR_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static TRACE_FILE: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

/// A write of `len` bytes at offset `from` of the file `name`: traced when it covers the armed
/// byte of that file.
fn trace_file(name: &str, from: u64, len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    if TRACE_KIND.load(Relaxed) != 4 {
        return;
    }
    let at = TRACE_AT.load(Relaxed) as u64;
    let same = TRACE_FILE
        .lock()
        .map(|f| *f == name.trim_start_matches("./"))
        .unwrap_or(false);
    if same && from <= at && at < from + len as u64 {
        trace_emit("file");
    }
}

/// Arms the trace: `out:<n>` (the call that writes byte `n` of stdout), `err:<n>` (of stderr) or
/// `exit`. Anything else leaves it off.
pub fn trace_arm(spec: &str) {
    use std::sync::atomic::Ordering::Relaxed;
    let (kind, at) = match spec.split_once(':') {
        Some(("out", n)) => (1, n.parse::<usize>().unwrap_or(0)),
        Some(("err", n)) => (2, n.parse::<usize>().unwrap_or(0)),
        Some(("file", rest)) => match rest.split_once(':') {
            Some((n, name)) => {
                if let Ok(mut f) = TRACE_FILE.lock() {
                    *f = name.trim_start_matches("./").to_string();
                }
                (4, n.parse::<usize>().unwrap_or(0))
            }
            None => (0, 0),
        },
        None if spec == "exit" => (3, 0),
        _ => (0, 0),
    };
    TRACE_AT.store(at, Relaxed);
    TRACE_KIND.store(kind, Relaxed);
}

fn trace_emit(what: &str) {
    let bt = std::backtrace::Backtrace::force_capture();
    let text = format!("KRAKEN-TRACE-BEGIN {what}\n{bt}\nKRAKEN-TRACE-END\n");
    let _ = std::io::stderr().write_all(text.as_bytes());
}

fn trace_note(stream: usize, len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    let counter = if stream == 1 { &OUT_BYTES } else { &ERR_BYTES };
    let before = counter.fetch_add(len, Relaxed);
    if TRACE_KIND.load(Relaxed) == stream {
        let at = TRACE_AT.load(Relaxed);
        if before <= at && at < before + len {
            trace_emit(if stream == 1 { "out" } else { "err" });
        }
    }
}

fn write_stdout(bytes: &[u8]) {
    trace_note(1, bytes.len());
    let _ = std::io::stdout().write_all(bytes);
}

fn write_stderr(bytes: &[u8]) {
    trace_note(2, bytes.len());
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

/// `fputs(s, stream)`: the string without a newline; `EOF` (-1) on an error.
///
/// # Safety
/// `s` must be NUL-terminated; `stream` comes from [`fopen`] or is a standard stream.
pub unsafe fn fputs(s: *const u8, stream: *mut FILE) -> i32 {
    let n = unsafe { strlen(s) };
    if unsafe { stream_write(stream, std::slice::from_raw_parts(s, n)) } {
        1
    } else {
        -1
    }
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

/// `exit`: runs the `atexit` handlers (last registered first), flushes stdout like libc and ends
/// the process.
pub fn exit(code: i32) -> ! {
    if TRACE_KIND.load(std::sync::atomic::Ordering::Relaxed) == 3 {
        trace_emit("exit");
    }
    loop {
        let next = AT_EXIT.lock().map(|mut l| l.pop()).unwrap_or(None);
        match next {
            Some((f, arg)) => unsafe { f(arg as *mut u8) },
            None => break,
        }
    }
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    std::process::exit(code)
}

/// `abort`: ends the process with `SIGABRT`, as libc does.
pub fn abort() -> ! {
    let _ = std::io::stdout().flush();
    std::process::abort()
}

type ExitFn = unsafe extern "C" fn(*mut u8);

static AT_EXIT: std::sync::Mutex<Vec<(ExitFn, usize)>> = std::sync::Mutex::new(Vec::new());

/// `atexit`: `f` runs at [`exit`] (and when `main` returns), last registered first.
pub fn atexit(f: unsafe extern "C" fn()) -> i32 {
    // An `extern "C" fn()` called with one ignored argument is sound on this ABI.
    let g: ExitFn = unsafe { std::mem::transmute::<unsafe extern "C" fn(), ExitFn>(f) };
    cxa_atexit(g, std::ptr::null_mut(), std::ptr::null_mut())
}

/// `__cxa_atexit`: registers a destructor of a static object; it runs at [`exit`].
pub fn cxa_atexit(f: unsafe extern "C" fn(*mut u8), arg: *mut u8, _dso: *mut u8) -> i32 {
    match AT_EXIT.lock() {
        Ok(mut l) => {
            l.push((f, arg as usize));
            0
        }
        Err(_) => -1,
    }
}

fn die(message: &str) -> ! {
    let _ = std::io::stdout().flush();
    write_stderr(message.as_bytes());
    std::process::abort()
}

// ----- the program image (globals) -----
//
// A whole-program rewrite installs the original program's loadable data once, before `main`,
// and every translation reaches the program's globals through `g(address)`. The generated
// `image.rs` holds the tables; see `kraken_rewrite::image`.

/// The original program's data and how to relocate it (generated per program).
pub struct Image {
    /// The bytes of the loadable segments (zeros for `.bss`).
    pub bytes: &'static [u8],
    /// The address the decompile shows for `bytes[0]`.
    pub low: u64,
    /// `(slot, target)`: the 8 bytes at offset `slot` point to offset `target`.
    pub relative: &'static [(u32, u32)],
    /// `(slot, stream)`: the program's own copy of `stdin` (0), `stdout` (1) or `stderr` (2).
    pub copies: &'static [(u32, u8)],
    /// `(slot, stream)`: a pointer to such a stream variable.
    pub refs: &'static [(u32, u8)],
    /// `(offset, length)`: the ranges a function-level test compares for writes to globals.
    pub writable: &'static [(u32, u32)],
}

static IMAGE_AT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static IMAGE_LOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static IMAGE_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Installs `img`: copies the bytes to `at` (or to fresh page-aligned memory when `at` is null),
/// then applies the relocations.
///
/// # Safety
/// `at`, when not null, must be writable for `img.bytes.len()` bytes and stay valid.
pub unsafe fn image_install(img: &Image, at: *mut u8) {
    use std::sync::atomic::Ordering::Relaxed;
    let len = img.bytes.len();
    let base = if at.is_null() {
        let Ok(layout) = std::alloc::Layout::from_size_align(len.max(1), 4096) else {
            die("the program image is too large\n");
        };
        let p = unsafe { std::alloc::alloc_zeroed(layout) };
        if p.is_null() {
            die("cannot allocate the program image\n");
        }
        p
    } else {
        at
    };
    unsafe { std::ptr::copy_nonoverlapping(img.bytes.as_ptr(), base, len) };
    IMAGE_AT.store(base as usize, Relaxed);
    IMAGE_LOW.store(img.low, Relaxed);
    IMAGE_LEN.store(len, Relaxed);
    for &(slot, target) in img.relative {
        if (slot as usize) + 8 <= len {
            let v = base as usize + target as usize;
            unsafe { (base.add(slot as usize) as *mut usize).write_unaligned(v) };
        }
    }
    for &(slot, s) in img.copies {
        if (slot as usize) + 8 <= len {
            let v = stream_of(s) as usize;
            unsafe { (base.add(slot as usize) as *mut usize).write_unaligned(v) };
        }
    }
    for &(slot, s) in img.refs {
        if (slot as usize) + 8 <= len {
            let v = stream_cell(s) as usize;
            unsafe { (base.add(slot as usize) as *mut usize).write_unaligned(v) };
        }
    }
}

/// Uses memory that already holds the program's data (the original program's own, when the
/// exported functions run inside it): `at` is where the data that the decompile shows at `low`
/// lives, `len` how far it goes.
pub fn image_attach(at: *mut u8, low: u64, len: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    IMAGE_AT.store(at as usize, Relaxed);
    IMAGE_LOW.store(low, Relaxed);
    IMAGE_LEN.store(len, Relaxed);
}

/// The installed image: where it is, the address it starts at and its length (null when none).
pub fn image_region() -> (*mut u8, u64, usize) {
    use std::sync::atomic::Ordering::Relaxed;
    (
        IMAGE_AT.load(Relaxed) as *mut u8,
        IMAGE_LOW.load(Relaxed),
        IMAGE_LEN.load(Relaxed),
    )
}

/// An address as a translation may spell it: any integer type, or a pointer.
pub trait Address {
    /// The address.
    fn address(self) -> u64;
}

macro_rules! address_from_int {
    ($($t:ty),*) => {$(
        impl Address for $t {
            fn address(self) -> u64 {
                self as u64
            }
        }
    )*};
}
address_from_int!(u64, usize, i64, isize, u32, i32);

impl<T> Address for *const T {
    fn address(self) -> u64 {
        self as usize as u64
    }
}

impl<T> Address for *mut T {
    fn address(self) -> u64 {
        self as usize as u64
    }
}

/// The program data at `address` (as the decompile shows it): globals, static locals, constant
/// tables, string literals.
pub fn g(address: impl Address) -> *mut u8 {
    let address = address.address();
    let (at, low, len) = image_region();
    if at.is_null() {
        die("rt::g: the program image is not installed\n");
    }
    match address.checked_sub(low) {
        Some(off) if (off as usize) < len => unsafe { at.add(off as usize) },
        _ => die(&format!(
            "rt::g({address:#x}): the address is outside the program image ({low:#x} to {:#x})\n",
            low + len as u64
        )),
    }
}

/// Writes the pointer `value` (a translated function, a stream) into the image at `address`.
///
/// # Safety
/// `address` must be the start of an 8-byte slot of the image.
pub unsafe fn image_put(address: u64, value: usize) {
    unsafe { (g(address) as *mut usize).write_unaligned(value) };
}

// ----- streams: <stdio.h> -----

/// A C stream: a standard stream or an open file.
pub struct FILE {
    kind: u8,
    file: Option<std::fs::File>,
    eof: bool,
    err: bool,
    unget: Option<u8>,
    /// The path it was opened with (for the trace).
    name: String,
}

fn std_streams() -> &'static [usize; 3] {
    static STREAMS: std::sync::OnceLock<[usize; 3]> = std::sync::OnceLock::new();
    STREAMS.get_or_init(|| {
        [0u8, 1, 2].map(|kind| {
            Box::into_raw(Box::new(FILE {
                kind,
                file: None,
                eof: false,
                err: false,
                unget: None,
                name: String::new(),
            })) as usize
        })
    })
}

fn stream_of(n: u8) -> *mut FILE {
    std_streams()[usize::from(n.min(2))] as *mut FILE
}

/// The address of a variable holding standard stream `n` (what a program's `&stdout` is).
fn stream_cell(n: u8) -> *mut *mut FILE {
    static CELLS: std::sync::OnceLock<[usize; 3]> = std::sync::OnceLock::new();
    let cells =
        CELLS.get_or_init(|| [0u8, 1, 2].map(|k| Box::into_raw(Box::new(stream_of(k))) as usize));
    cells[usize::from(n.min(2))] as *mut *mut FILE
}

/// `stdin`.
pub fn stdin() -> *mut FILE {
    stream_of(0)
}

/// `stdout`.
pub fn stdout() -> *mut FILE {
    stream_of(1)
}

/// `stderr`.
pub fn stderr() -> *mut FILE {
    stream_of(2)
}

static ERRNO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// `errno`.
pub fn errno() -> i32 {
    ERRNO.load(std::sync::atomic::Ordering::Relaxed)
}

/// `__errno_location()`: where `errno` lives.
pub fn errno_location() -> *mut i32 {
    ERRNO.as_ptr()
}

fn set_errno(e: &std::io::Error) {
    ERRNO.store(
        e.raw_os_error().unwrap_or(5),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Writes `bytes` to `stream`; false on an error.
///
/// # Safety
/// `stream` comes from [`fopen`] or is a standard stream.
unsafe fn stream_write(stream: *mut FILE, bytes: &[u8]) -> bool {
    let Some(f) = (unsafe { stream.as_mut() }) else {
        die("Segmentation fault: write to a null FILE\n");
    };
    match f.kind {
        1 => write_stdout(bytes),
        2 => write_stderr(bytes),
        _ => match f.file.as_mut().map(|file| {
            use std::io::Seek;
            if let Ok(at) = file.stream_position() {
                trace_file(&f.name, at, bytes.len());
            }
            file.write_all(bytes)
        }) {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                set_errno(&e);
                f.err = true;
                return false;
            }
            None => {
                f.err = true;
                return false;
            }
        },
    }
    true
}

/// Reads up to `buf.len()` bytes from `stream`; the count (0 at the end or on an error).
///
/// # Safety
/// As [`stream_write`].
unsafe fn stream_read(stream: *mut FILE, buf: &mut [u8]) -> usize {
    use std::io::Read;
    let Some(f) = (unsafe { stream.as_mut() }) else {
        die("Segmentation fault: read from a null FILE\n");
    };
    if buf.is_empty() {
        return 0;
    }
    let mut n = 0;
    if let Some(c) = f.unget.take() {
        buf[0] = c;
        n = 1;
    }
    while n < buf.len() {
        let r = match f.kind {
            0 => std::io::stdin().read(&mut buf[n..]),
            3 => match f.file.as_mut() {
                Some(file) => file.read(&mut buf[n..]),
                None => Ok(0),
            },
            _ => Ok(0),
        };
        match r {
            Ok(0) => {
                f.eof = true;
                break;
            }
            Ok(k) => n += k,
            Err(e) => {
                set_errno(&e);
                f.err = true;
                break;
            }
        }
    }
    n
}

unsafe fn c_str_bytes<'a>(s: *const u8) -> &'a [u8] {
    unsafe { std::slice::from_raw_parts(s, strlen(s)) }
}

/// `fopen`: modes `r`, `w`, `a` with `+` and `b`; null with `errno` set when it fails.
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn fopen(path: *const u8, mode: *const u8) -> *mut FILE {
    let p = c_path(unsafe { c_str_bytes(path) });
    let p = std::path::Path::new(&p);
    let m = unsafe { c_str_bytes(mode) };
    let plus = m.contains(&b'+');
    let mut o = std::fs::OpenOptions::new();
    match m.first() {
        Some(b'r') => o.read(true).write(plus),
        Some(b'w') => o.write(true).create(true).truncate(true).read(plus),
        Some(b'a') => o.append(true).create(true).read(plus),
        _ => {
            ERRNO.store(22, std::sync::atomic::Ordering::Relaxed);
            return std::ptr::null_mut();
        }
    };
    match o.open(p) {
        Ok(file) => Box::into_raw(Box::new(FILE {
            kind: 3,
            file: Some(file),
            eof: false,
            err: false,
            unget: None,
            name: p.display().to_string(),
        })),
        Err(e) => {
            set_errno(&e);
            std::ptr::null_mut()
        }
    }
}

/// `fclose`: closes a file (a standard stream is only flushed).
///
/// # Safety
/// `stream` comes from [`fopen`] and is not used afterwards, or is a standard stream.
pub unsafe fn fclose(stream: *mut FILE) -> i32 {
    if stream.is_null() {
        return -1;
    }
    if unsafe { (*stream).kind } < 3 {
        return fflush(stream);
    }
    drop(unsafe { Box::from_raw(stream) });
    0
}

/// `fflush`.
pub fn fflush(stream: *mut FILE) -> i32 {
    let _ = std::io::stdout().flush();
    if let Some(f) = unsafe { stream.as_mut() }
        && let Some(file) = f.file.as_mut()
    {
        let _ = file.flush();
    }
    0
}

/// `fwrite`: the number of whole items written.
///
/// # Safety
/// `ptr` readable for `size * n` bytes; see [`fputs`].
pub unsafe fn fwrite(ptr: *const u8, size: usize, n: usize, stream: *mut FILE) -> usize {
    let total = size.saturating_mul(n);
    if total == 0 {
        return 0;
    }
    if unsafe { stream_write(stream, std::slice::from_raw_parts(ptr, total)) } {
        n
    } else {
        0
    }
}

/// `fread`: the number of whole items read.
///
/// # Safety
/// `ptr` writable for `size * n` bytes; see [`fputs`].
pub unsafe fn fread(ptr: *mut u8, size: usize, n: usize, stream: *mut FILE) -> usize {
    let total = size.saturating_mul(n);
    if total == 0 {
        return 0;
    }
    let got = unsafe { stream_read(stream, std::slice::from_raw_parts_mut(ptr, total)) };
    got / size
}

/// `fputc` / `putc`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn fputc(c: i32, stream: *mut FILE) -> i32 {
    if unsafe { stream_write(stream, &[c as u8]) } {
        c as u8 as i32
    } else {
        -1
    }
}

/// `fgetc` / `getc`: the byte, or `EOF` (-1).
///
/// # Safety
/// See [`fputs`].
pub unsafe fn fgetc(stream: *mut FILE) -> i32 {
    let mut b = [0u8; 1];
    if unsafe { stream_read(stream, &mut b) } == 1 {
        i32::from(b[0])
    } else {
        -1
    }
}

/// `getchar`.
pub fn getchar() -> i32 {
    unsafe { fgetc(stdin()) }
}

/// `ungetc`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn ungetc(c: i32, stream: *mut FILE) -> i32 {
    match unsafe { stream.as_mut() } {
        Some(f) if c >= 0 => {
            f.unget = Some(c as u8);
            f.eof = false;
            c & 0xff
        }
        _ => -1,
    }
}

/// `fgets`: reads a line (with its newline) of at most `n - 1` bytes and a NUL; null at the end.
///
/// # Safety
/// `buf` writable for `n` bytes; see [`fputs`].
pub unsafe fn fgets(buf: *mut u8, n: i32, stream: *mut FILE) -> *mut u8 {
    if n <= 0 {
        return std::ptr::null_mut();
    }
    let mut i = 0usize;
    while i + 1 < n as usize {
        let c = unsafe { fgetc(stream) };
        if c < 0 {
            break;
        }
        unsafe { *buf.add(i) = c as u8 };
        i += 1;
        if c == i32::from(b'\n') {
            break;
        }
    }
    if i == 0 {
        return std::ptr::null_mut();
    }
    unsafe { *buf.add(i) = 0 };
    buf
}

/// `feof`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn feof(stream: *mut FILE) -> i32 {
    unsafe { stream.as_ref() }.map_or(0, |f| i32::from(f.eof))
}

/// `ferror`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn ferror(stream: *mut FILE) -> i32 {
    unsafe { stream.as_ref() }.map_or(0, |f| i32::from(f.err))
}

/// `fseek` (`whence` 0 set, 1 current, 2 end).
///
/// # Safety
/// See [`fputs`].
pub unsafe fn fseek(stream: *mut FILE, offset: i64, whence: i32) -> i32 {
    use std::io::{Seek, SeekFrom};
    let Some(f) = (unsafe { stream.as_mut() }) else {
        return -1;
    };
    let to = match whence {
        0 => SeekFrom::Start(offset.max(0) as u64),
        1 => SeekFrom::Current(offset),
        _ => SeekFrom::End(offset),
    };
    f.unget = None;
    match f.file.as_mut().map(|file| file.seek(to)) {
        Some(Ok(_)) => {
            f.eof = false;
            0
        }
        Some(Err(e)) => {
            set_errno(&e);
            -1
        }
        None => -1,
    }
}

/// `ftell`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn ftell(stream: *mut FILE) -> i64 {
    use std::io::Seek;
    match unsafe { stream.as_mut() }.and_then(|f| f.file.as_mut()) {
        Some(file) => file.stream_position().map_or(-1, |p| p as i64),
        None => -1,
    }
}

/// `rewind`.
///
/// # Safety
/// See [`fputs`].
pub unsafe fn rewind(stream: *mut FILE) {
    unsafe { fseek(stream, 0, 0) };
}

/// `fprintf(stream, ...)`.
///
/// # Safety
/// See [`format_c`] and [`fputs`].
pub unsafe fn fprintf(stream: *mut FILE, fmt: *const u8, args: &[Arg]) -> i32 {
    let bytes = unsafe { format_c(fmt, args) };
    if unsafe { stream_write(stream, &bytes) } {
        bytes.len() as i32
    } else {
        -1
    }
}

/// `sprintf`: like [`snprintf`] without a limit.
///
/// # Safety
/// `dst` large enough; see [`format_c`].
pub unsafe fn sprintf(dst: *mut u8, fmt: *const u8, args: &[Arg]) -> i32 {
    let bytes = unsafe { format_c(fmt, args) };
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
        *dst.add(bytes.len()) = 0;
    }
    bytes.len() as i32
}

/// `strerror`: glibc's text for the common error numbers.
pub fn strerror(e: i32) -> *const u8 {
    let s: &'static [u8] = match e {
        0 => b"Success\0",
        1 => b"Operation not permitted\0",
        2 => b"No such file or directory\0",
        3 => b"No such process\0",
        4 => b"Interrupted system call\0",
        5 => b"Input/output error\0",
        9 => b"Bad file descriptor\0",
        12 => b"Cannot allocate memory\0",
        13 => b"Permission denied\0",
        17 => b"File exists\0",
        20 => b"Not a directory\0",
        21 => b"Is a directory\0",
        22 => b"Invalid argument\0",
        24 => b"Too many open files\0",
        27 => b"File too large\0",
        28 => b"No space left on device\0",
        30 => b"Read-only file system\0",
        32 => b"Broken pipe\0",
        33 => b"Numerical argument out of domain\0",
        34 => b"Numerical result out of range\0",
        36 => b"File name too long\0",
        38 => b"Function not implemented\0",
        _ => b"Unknown error\0",
    };
    s.as_ptr()
}

/// `perror(s)`: `s: <strerror(errno)>` and a newline on stderr (just the text when `s` is null
/// or empty).
///
/// # Safety
/// `s` null or NUL-terminated.
pub unsafe fn perror(s: *const u8) {
    let mut out = Vec::new();
    if !s.is_null() && unsafe { *s } != 0 {
        out.extend_from_slice(unsafe { c_str_bytes(s) });
        out.extend_from_slice(b": ");
    }
    out.extend_from_slice(unsafe { c_str_bytes(strerror(errno())) });
    out.push(b'\n');
    write_stderr(&out);
}

/// `remove`.
///
/// # Safety
/// `path` NUL-terminated.
pub unsafe fn remove(path: *const u8) -> i32 {
    let p = c_path(unsafe { c_str_bytes(path) });
    let p = std::path::Path::new(&p);
    match std::fs::remove_file(p) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(&e);
            -1
        }
    }
}

/// `getenv`: null when unset.
///
/// # Safety
/// `name` NUL-terminated.
pub unsafe fn getenv(name: *const u8) -> *const u8 {
    let key = c_path(unsafe { c_str_bytes(name) });
    match std::env::var_os(key) {
        Some(v) => {
            let mut b = v.to_string_lossy().into_owned().into_bytes();
            b.push(0);
            Box::leak(b.into_boxed_slice()).as_ptr()
        }
        None => std::ptr::null(),
    }
}

/// A file name or variable name from C bytes (names that are not UTF-8 are read lossily).
fn c_path(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ----- <math.h> (the C library's own functions, so results match bit for bit) -----

/// `sqrt`.
pub fn sqrt(x: f64) -> f64 {
    x.sqrt()
}
/// `sqrtf`.
pub fn sqrtf(x: f32) -> f32 {
    x.sqrt()
}
/// `sin`.
pub fn sin(x: f64) -> f64 {
    x.sin()
}
/// `sinf`.
pub fn sinf(x: f32) -> f32 {
    x.sin()
}
/// `cos`.
pub fn cos(x: f64) -> f64 {
    x.cos()
}
/// `cosf`.
pub fn cosf(x: f32) -> f32 {
    x.cos()
}
/// `tan`.
pub fn tan(x: f64) -> f64 {
    x.tan()
}
/// `tanf`.
pub fn tanf(x: f32) -> f32 {
    x.tan()
}
/// `atan`.
pub fn atan(x: f64) -> f64 {
    x.atan()
}
/// `atan2`.
pub fn atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}
/// `atan2f`.
pub fn atan2f(y: f32, x: f32) -> f32 {
    y.atan2(x)
}
/// `exp`.
pub fn exp(x: f64) -> f64 {
    x.exp()
}
/// `expf`.
pub fn expf(x: f32) -> f32 {
    x.exp()
}
/// `exp2`.
pub fn exp2(x: f64) -> f64 {
    x.exp2()
}
/// `exp2f`.
pub fn exp2f(x: f32) -> f32 {
    x.exp2()
}
/// `log`.
pub fn log(x: f64) -> f64 {
    x.ln()
}
/// `logf`.
pub fn logf(x: f32) -> f32 {
    x.ln()
}
/// `log2`.
pub fn log2(x: f64) -> f64 {
    x.log2()
}
/// `log2f`.
pub fn log2f(x: f32) -> f32 {
    x.log2()
}
/// `log10`.
pub fn log10(x: f64) -> f64 {
    x.log10()
}
/// `log10f`.
pub fn log10f(x: f32) -> f32 {
    x.log10()
}
/// `pow`.
pub fn pow(x: f64, y: f64) -> f64 {
    x.powf(y)
}
/// `powf`.
pub fn powf(x: f32, y: f32) -> f32 {
    x.powf(y)
}
/// `floor`.
pub fn floor(x: f64) -> f64 {
    x.floor()
}
/// `floorf`.
pub fn floorf(x: f32) -> f32 {
    x.floor()
}
/// `ceil`.
pub fn ceil(x: f64) -> f64 {
    x.ceil()
}
/// `ceilf`.
pub fn ceilf(x: f32) -> f32 {
    x.ceil()
}
/// `round`: halves away from zero.
pub fn round(x: f64) -> f64 {
    x.round()
}
/// `roundf`.
pub fn roundf(x: f32) -> f32 {
    x.round()
}
/// `trunc`.
pub fn trunc(x: f64) -> f64 {
    x.trunc()
}
/// `truncf`.
pub fn truncf(x: f32) -> f32 {
    x.trunc()
}
/// `rint` / `nearbyint`: halves to even (the default rounding mode).
pub fn rint(x: f64) -> f64 {
    x.round_ties_even()
}
/// `rintf` / `nearbyintf`.
pub fn rintf(x: f32) -> f32 {
    x.round_ties_even()
}
/// `lround`; out of range gives `i64::MIN`, as on x86-64.
pub fn lround(x: f64) -> i64 {
    to_long(x.round())
}
/// `lroundf`.
pub fn lroundf(x: f32) -> i64 {
    to_long(f64::from(x.round()))
}
/// `lrint`.
pub fn lrint(x: f64) -> i64 {
    to_long(x.round_ties_even())
}
/// `lrintf`.
pub fn lrintf(x: f32) -> i64 {
    to_long(f64::from(x.round_ties_even()))
}
fn to_long(r: f64) -> i64 {
    if r.is_nan() || r >= i64::MAX as f64 || r < i64::MIN as f64 {
        i64::MIN
    } else {
        r as i64
    }
}
/// `fabs`.
pub fn fabs(x: f64) -> f64 {
    x.abs()
}
/// `fabsf`.
pub fn fabsf(x: f32) -> f32 {
    x.abs()
}
/// `fmod`.
pub fn fmod(x: f64, y: f64) -> f64 {
    x % y
}
/// `fmodf`.
pub fn fmodf(x: f32, y: f32) -> f32 {
    x % y
}
/// `fmin`.
pub fn fmin(x: f64, y: f64) -> f64 {
    x.min(y)
}
/// `fmax`.
pub fn fmax(x: f64, y: f64) -> f64 {
    x.max(y)
}
/// `fminf`.
pub fn fminf(x: f32, y: f32) -> f32 {
    x.min(y)
}
/// `fmaxf`.
pub fn fmaxf(x: f32, y: f32) -> f32 {
    x.max(y)
}
/// `hypot`.
pub fn hypot(x: f64, y: f64) -> f64 {
    x.hypot(y)
}
/// `ldexp`.
pub fn ldexp(x: f64, e: i32) -> f64 {
    x * 2f64.powi(e)
}

// ----- C++ runtime basics -----

/// `operator new` / `operator new[]`: never null (out of memory ends the program like an
/// uncaught `std::bad_alloc`).
pub fn operator_new(n: usize) -> *mut u8 {
    let p = unsafe { malloc(n.max(1)) };
    if p.is_null() {
        throw("std::bad_alloc", "std::bad_alloc");
    }
    p
}

/// `operator delete` / `operator delete[]`, sized or not.
///
/// # Safety
/// As [`free`].
pub unsafe fn operator_delete(p: *mut u8) {
    unsafe { free(p) }
}

/// An exception nobody catches, as libstdc++ reports it: the `terminate` message on stderr, then
/// `abort`. The rewrite does not model catching exceptions.
pub fn throw(type_name: &str, what: &str) -> ! {
    die(&format!(
        "terminate called after throwing an instance of '{type_name}'\n  what():  {what}\n"
    ))
}

/// `std::__throw_length_error(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_length_error(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::length_error", &w)
}

/// `std::__throw_out_of_range(what)` (also `__throw_out_of_range_fmt` with its text).
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_out_of_range(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::out_of_range", &w)
}

/// `std::__throw_bad_alloc()`.
pub fn throw_bad_alloc() -> ! {
    throw("std::bad_alloc", "std::bad_alloc")
}

/// `std::__throw_logic_error(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_logic_error(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::logic_error", &w)
}

/// `std::__throw_invalid_argument(what)`.
///
/// # Safety
/// `what` NUL-terminated.
pub unsafe fn throw_invalid_argument(what: *const u8) -> ! {
    let w = String::from_utf8_lossy(unsafe { c_str_bytes(what) }).into_owned();
    throw("std::invalid_argument", &w)
}

/// `__cxa_pure_virtual`.
pub fn cxa_pure_virtual() -> ! {
    die("pure virtual method called\nterminate called without an active exception\n")
}

/// `__stack_chk_fail`.
pub fn stack_chk_fail() -> ! {
    die("*** stack smashing detected ***: terminated\n")
}

/// `_Unwind_Resume` (and anything else that would unwind): the rewrite does not model exceptions.
pub fn unwind_resume() -> ! {
    die("terminate called without an active exception\n")
}

/// `__cxa_guard_acquire`: 1 when the caller must run the initialiser of a function-local static.
///
/// # Safety
/// `guard` points to the 8-byte guard of the static (in the program image).
pub unsafe fn cxa_guard_acquire(guard: *mut u64) -> i32 {
    i32::from(unsafe { *(guard as *const u8) } == 0)
}

/// `__cxa_guard_release`: marks the static initialised.
///
/// # Safety
/// As [`cxa_guard_acquire`].
pub unsafe fn cxa_guard_release(guard: *mut u64) {
    unsafe { *(guard as *mut u8) = 1 };
}

/// `__cxa_guard_abort`.
pub fn cxa_guard_abort(_guard: *mut u64) {}

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

/// `strtoul`: as [`strtol`], negated values wrap like C's.
///
/// # Safety
/// As [`strtol`].
pub unsafe fn strtoul(s: *const u8, end: *mut *const u8, base: i32) -> u64 {
    let mut i = 0usize;
    while isspace(i32::from(unsafe { *s.add(i) })) != 0 {
        i += 1;
    }
    let neg = unsafe { *s.add(i) } == b'-';
    if neg {
        let v = unsafe { strtol(s.add(i + 1), end, base) };
        if v == i64::MAX {
            return u64::MAX;
        }
        return (v as u64).wrapping_neg();
    }
    let v = unsafe { strtol(s, end, base) };
    if v == i64::MAX {
        // strtol saturated: read again as unsigned.
        let mut acc: u128 = 0;
        let mut j = i + usize::from(unsafe { *s.add(i) } == b'+');
        let b = if base == 0 { 10 } else { base as u32 };
        while let Some(d) = (unsafe { *s.add(j) } as char).to_digit(b.max(2)) {
            acc = (acc * u128::from(b) + u128::from(d)).min(u128::from(u64::MAX) + 1);
            j += 1;
        }
        return if acc > u128::from(u64::MAX) {
            u64::MAX
        } else {
            acc as u64
        };
    }
    v as u64
}

/// `strtoll`.
///
/// # Safety
/// As [`strtol`].
pub unsafe fn strtoll(s: *const u8, end: *mut *const u8, base: i32) -> i64 {
    unsafe { strtol(s, end, base) }
}

/// `strtoull`.
///
/// # Safety
/// As [`strtol`].
pub unsafe fn strtoull(s: *const u8, end: *mut *const u8, base: i32) -> u64 {
    unsafe { strtoul(s, end, base) }
}

/// The length of the longest prefix of `s` that C's `strtod` reads, and that text in the form
/// Rust's parser takes.
unsafe fn float_prefix(s: *const u8) -> (usize, String) {
    let at = |i: usize| unsafe { *s.add(i) };
    let mut i = 0usize;
    while isspace(i32::from(at(i))) != 0 {
        i += 1;
    }
    let start = i;
    let mut text = String::new();
    if at(i) == b'+' || at(i) == b'-' {
        text.push(at(i) as char);
        i += 1;
    }
    let lower = |k: usize| at(k).to_ascii_lowercase();
    let word = |k: usize, w: &[u8]| (0..w.len()).all(|j| lower(k + j) == w[j]);
    if word(i, b"infinity") {
        return (i + 8, format!("{text}inf"));
    }
    if word(i, b"inf") {
        return (i + 3, format!("{text}inf"));
    }
    if word(i, b"nan") {
        let mut j = i + 3;
        if at(j) == b'(' {
            let mut k = j + 1;
            while at(k).is_ascii_alphanumeric() || at(k) == b'_' {
                k += 1;
            }
            if at(k) == b')' {
                j = k + 1;
            }
        }
        return (j, format!("{text}NaN"));
    }
    if at(i) == b'0' && lower(i + 1) == b'x' {
        // Hexadecimal: mantissa digits with an optional point, optional binary exponent.
        let mut j = i + 2;
        let mut mant: u128 = 0;
        let mut exp: i64 = 0;
        let mut digits = 0;
        let mut point = false;
        loop {
            let c = at(j);
            if let Some(d) = (c as char).to_digit(16) {
                if mant < (1u128 << 120) {
                    mant = mant * 16 + u128::from(d);
                    if point {
                        exp -= 4;
                    }
                } else if !point {
                    exp += 4;
                }
                digits += 1;
            } else if c == b'.' && !point {
                point = true;
            } else {
                break;
            }
            j += 1;
        }
        if digits == 0 {
            // Just the `0`.
            return (i + 1, format!("{text}0"));
        }
        if lower(j) == b'p' {
            let mut k = j + 1;
            let neg = at(k) == b'-';
            if at(k) == b'+' || at(k) == b'-' {
                k += 1;
            }
            if at(k).is_ascii_digit() {
                let mut e: i64 = 0;
                while at(k).is_ascii_digit() {
                    e = (e * 10 + i64::from(at(k) - b'0')).min(100_000);
                    k += 1;
                }
                exp += if neg { -e } else { e };
                j = k;
            }
        }
        let v = (mant as f64) * 2f64.powi(exp.clamp(-2000, 2000) as i32);
        let v = if text.starts_with('-') { -v } else { v };
        return (j, format!("{v:e}"));
    }
    let mut digits = 0;
    while at(i).is_ascii_digit() {
        text.push(at(i) as char);
        i += 1;
        digits += 1;
    }
    if at(i) == b'.' {
        text.push('.');
        i += 1;
        while at(i).is_ascii_digit() {
            text.push(at(i) as char);
            i += 1;
            digits += 1;
        }
    }
    if digits == 0 {
        return (start, String::new());
    }
    if lower(i) == b'e' {
        let mut k = i + 1;
        let mut e = String::from("e");
        if at(k) == b'+' || at(k) == b'-' {
            e.push(at(k) as char);
            k += 1;
        }
        if at(k).is_ascii_digit() {
            while at(k).is_ascii_digit() {
                e.push(at(k) as char);
                k += 1;
            }
            text.push_str(&e);
            i = k;
        }
    }
    (i, text)
}

/// `strtod`: decimal, hexadecimal, `inf` and `nan`, correctly rounded like glibc; `*end` past
/// what was read (at `s` when nothing was).
///
/// # Safety
/// `s` NUL-terminated; `end`, when not null, writable.
pub unsafe fn strtod(s: *const u8, end: *mut *const u8) -> f64 {
    let (n, text) = unsafe { float_prefix(s) };
    if !end.is_null() {
        unsafe { *end = if text.is_empty() { s } else { s.add(n) } };
    }
    if text.is_empty() {
        return 0.0;
    }
    let v: f64 = text.parse().unwrap_or(0.0);
    if v.is_infinite() && !text.contains("inf") {
        ERRNO.store(34, std::sync::atomic::Ordering::Relaxed);
    }
    v
}

/// `strtof`.
///
/// # Safety
/// As [`strtod`].
pub unsafe fn strtof(s: *const u8, end: *mut *const u8) -> f32 {
    let (n, text) = unsafe { float_prefix(s) };
    if !end.is_null() {
        unsafe { *end = if text.is_empty() { s } else { s.add(n) } };
    }
    text.parse().unwrap_or(0.0)
}

/// `atof`.
///
/// # Safety
/// `s` NUL-terminated.
pub unsafe fn atof(s: *const u8) -> f64 {
    unsafe { strtod(s, std::ptr::null_mut()) }
}

/// `strspn`: the length of the prefix of `s` made of bytes in `accept`.
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn strspn(s: *const u8, accept: *const u8) -> usize {
    let set = unsafe { c_str_bytes(accept) };
    let mut n = 0usize;
    while unsafe { *s.add(n) } != 0 && set.contains(&unsafe { *s.add(n) }) {
        n += 1;
    }
    n
}

/// `strcspn`: the length of the prefix of `s` without bytes of `reject`.
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn strcspn(s: *const u8, reject: *const u8) -> usize {
    let set = unsafe { c_str_bytes(reject) };
    let mut n = 0usize;
    while unsafe { *s.add(n) } != 0 && !set.contains(&unsafe { *s.add(n) }) {
        n += 1;
    }
    n
}

/// `strpbrk`.
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn strpbrk(s: *const u8, accept: *const u8) -> *mut u8 {
    let n = unsafe { strcspn(s, accept) };
    if unsafe { *s.add(n) } == 0 {
        std::ptr::null_mut()
    } else {
        unsafe { s.add(n) as *mut u8 }
    }
}

/// `strncat`: appends at most `n` bytes and a NUL.
///
/// # Safety
/// `dst` NUL-terminated with room; `src` readable up to its NUL or `n` bytes.
pub unsafe fn strncat(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let d = unsafe { strlen(dst) };
    let k = unsafe { strnlen(src, n) };
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst.add(d), k);
        *dst.add(d + k) = 0;
    }
    dst
}

/// `strcasecmp` (C locale).
///
/// # Safety
/// Both NUL-terminated.
pub unsafe fn strcasecmp(a: *const u8, b: *const u8) -> i32 {
    unsafe { strncasecmp(a, b, usize::MAX) }
}

/// `strncasecmp` (C locale).
///
/// # Safety
/// Both readable up to their NUL or `n` bytes.
pub unsafe fn strncasecmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i < n {
        let (x, y) = (
            tolower(i32::from(unsafe { *a.add(i) })),
            tolower(i32::from(unsafe { *b.add(i) })),
        );
        if x != y || x == 0 {
            return x - y;
        }
        i += 1;
    }
    0
}

/// `qsort`: a stable merge sort (glibc's `qsort` sorts with a merge sort when it can allocate),
/// so elements that compare equal keep their order.
///
/// # Safety
/// `base` holds `n` elements of `size` bytes; `cmp` is a valid comparison function.
pub unsafe fn qsort(
    base: *mut u8,
    n: usize,
    size: usize,
    cmp: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) {
    if n < 2 || size == 0 {
        return;
    }
    let mut idx: Vec<usize> = (0..n).collect();
    let copy: Vec<u8> = unsafe { std::slice::from_raw_parts(base, n * size) }.to_vec();
    let at = |i: usize| unsafe { copy.as_ptr().add(i * size) };
    let mut tmp = idx.clone();
    let mut width = 1;
    while width < n {
        let mut lo = 0;
        while lo < n {
            let mid = (lo + width).min(n);
            let hi = (lo + 2 * width).min(n);
            let (mut i, mut j, mut k) = (lo, mid, lo);
            while i < mid && j < hi {
                if unsafe { cmp(at(idx[i]), at(idx[j])) } <= 0 {
                    tmp[k] = idx[i];
                    i += 1;
                } else {
                    tmp[k] = idx[j];
                    j += 1;
                }
                k += 1;
            }
            tmp[k..k + (mid - i)].copy_from_slice(&idx[i..mid]);
            k += mid - i;
            tmp[k..k + (hi - j)].copy_from_slice(&idx[j..hi]);
            lo = hi;
        }
        std::mem::swap(&mut idx, &mut tmp);
        width *= 2;
    }
    for (dst, src) in idx.iter().enumerate() {
        unsafe { std::ptr::copy_nonoverlapping(at(*src), base.add(dst * size), size) };
    }
}

/// `bsearch`.
///
/// # Safety
/// As [`qsort`], with `key` what `cmp` expects first.
pub unsafe fn bsearch(
    key: *const u8,
    base: *const u8,
    n: usize,
    size: usize,
    cmp: unsafe extern "C" fn(*const u8, *const u8) -> i32,
) -> *mut u8 {
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let p = unsafe { base.add(mid * size) };
        let c = unsafe { cmp(key, p) };
        if c == 0 {
            return p as *mut u8;
        }
        if c < 0 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    std::ptr::null_mut()
}

/// glibc's `random()` state (the default `TYPE_3` additive feedback generator).
struct RandState {
    r: Vec<i32>,
}

impl RandState {
    fn seeded(seed: u32) -> Self {
        let mut r: Vec<i32> = vec![0; 34];
        r[0] = if seed == 0 { 1 } else { seed as i32 };
        for i in 1..31 {
            // 16807 * r[i-1] % 2147483647, computed without overflow as glibc does.
            let hi = r[i - 1] / 127_773;
            let lo = r[i - 1] % 127_773;
            let mut word = 16_807 * lo - 2_836 * hi;
            if word < 0 {
                word += 2_147_483_647;
            }
            r[i] = word;
        }
        for i in 31..34 {
            r[i] = r[i - 31];
        }
        let mut st = RandState { r };
        for _ in 34..344 {
            st.step();
        }
        st
    }

    fn step(&mut self) -> i32 {
        let n = self.r.len();
        let v = self.r[n - 31].wrapping_add(self.r[n - 3]);
        self.r.push(v);
        if self.r.len() > 64 {
            self.r.drain(..self.r.len() - 34);
        }
        ((v as u32) >> 1) as i32
    }
}

static RAND: std::sync::Mutex<Option<RandState>> = std::sync::Mutex::new(None);

/// `srand` / `srandom`.
pub fn srand(seed: u32) {
    if let Ok(mut s) = RAND.lock() {
        *s = Some(RandState::seeded(seed));
    }
}

/// `rand` / `random`: glibc's sequence (seed 1 until [`srand`]).
pub fn rand() -> i32 {
    match RAND.lock() {
        Ok(mut s) => s.get_or_insert_with(|| RandState::seeded(1)).step(),
        Err(_) => 0,
    }
}

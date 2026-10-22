//! The native side of a differential test: compile the Rust translation into a small runner
//! program with `rustc`, then run it once per test case, confined (see [`crate::sandbox`]).
//!
//! The runner is one process per case on purpose. A translation that calls `exit`, panics,
//! overflows (the runner is built with overflow checks on), loops or crashes is observed as that
//! outcome instead of taking the test process down.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::abi::{
    Arg, GlobalWrite, Observation, Param, Ret, Signature, Termination, check_graph, from_hex, mask,
    to_hex,
};
use crate::error::RewriteError;
use crate::image::ProgramImage;
use crate::sandbox::{
    Confinement, ConfinementReport, ReadScope, confine, run_captured, scratch_dir, toolchain,
};

/// Wall-clock limit per case.
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on captured output per stream.
const OUTPUT_CAP: usize = 1 << 20;
/// Wall-clock limit for compiling a translation.
const COMPILE_TIMEOUT: Duration = Duration::from_secs(120);

pub use crate::lint::lint_translation;

/// A compiled runner.
#[derive(Debug)]
pub struct NativeRunner {
    dir: tempfile::TempDir,
    exe: PathBuf,
    sig: Signature,
    confinement: Confinement,
    /// How the build step was confined.
    pub build_confinement: ConfinementReport,
    /// The runner installs the program image and reports writes to globals.
    image: bool,
}

/// Result of building a translation.
#[derive(Debug)]
pub enum Build {
    /// Ready to run.
    Ready(NativeRunner),
    /// The translation was refused or did not compile; the text says why.
    Rejected(String),
}

/// Generates the runner's `main.rs` for `sig`.
///
/// The case file has one line per argument: `i <hex>` (integer), `d <hex>` (double bits),
/// `f <n>` (callback number), `b <hex>` (buffer) or `g <objects> <links>` followed by that many
/// `o <hex>` lines and `l <from> <offset> <to> <to_offset>` lines (a graph). Objects are laid out
/// in that order, which is also the order of the `buf` lines of the result.
fn runner_source(sig: &Signature, image: Option<&RunnerImage>, shim: bool) -> String {
    let call_args: Vec<String> = sig
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| match p {
            Param::Double => format!("f64::from_bits(vals[{i}])"),
            Param::Float => format!("f32::from_bits(vals[{i}] as u32)"),
            Param::FnPtr => {
                format!("unsafe {{ std::mem::transmute::<usize, _>(vals[{i}] as usize) }}")
            }
            _ => format!("vals[{i}] as _"),
        })
        .collect();
    let call = format!(
        "unsafe {{ translation::{}({}) }}",
        sig.name,
        call_args.join(", ")
    );
    let body = match sig.ret {
        Ret::Void => format!("{call};\n    let ret: Option<u64> = None;"),
        Ret::Int { bits, .. } => format!(
            "let r = {call};\n    let ret: Option<u64> = Some((r as u64) & {:#x}u64);",
            mask(bits)
        ),
        // A pointer result is described by what it points at, as the oracle does: heap blocks
        // differ in address between the two sides (see `ptrdesc`).
        Ret::Ptr => {
            let (track, blocks) = if shim {
                (
                    "translation::rt::track_blocks();\n    ",
                    "translation::rt::tracked_blocks()",
                )
            } else {
                ("", "Vec::new()")
            };
            format!(
                "{track}let r = {call};\n    let ret: Option<u64> = None;\n    \
                 let ret_object = Some(ptrdesc::describe_pointer(r as u64, &{blocks}, &mut |a, n| \
                 unsafe {{ std::slice::from_raw_parts(a as *const u8, n) }}.to_vec()));"
            )
        }
        Ret::Double => {
            format!("let r: f64 = {call};\n    let ret: Option<u64> = Some(r.to_bits());")
        }
        Ret::Float => format!(
            "let r: f32 = {call};\n    let ret: Option<u64> = Some(u64::from(r.to_bits()));"
        ),
    };
    let body = if sig.ret == Ret::Ptr {
        body
    } else {
        format!("{body}\n    let ret_object: Option<String> = None;")
    };
    let ptrdesc_mod = if sig.ret == Ret::Ptr {
        format!("mod ptrdesc {{\n{}}}\n", crate::PTRDESC_SOURCE)
    } else {
        String::new()
    };
    // With the program image: installed where the emulator has the same bytes, then every
    // changed range of the compared parts is reported as the oracle reports writes to globals.
    let (image_mod, install, report) = match image {
        None => (String::new(), String::new(), String::new()),
        Some(img) => (
            "mod image;\nuse translation::rt;\n".to_string(),
            format!(
                r#"    let want = {at:#x}u64;
    let len = image::IMAGE.bytes.len();
    let map = (len + 0xfff) & !0xfff;
    let got = unsafe {{ mmap(want as *mut u8, map.max(0x1000), 3, 0x2 | 0x20 | 0x100000, -1, 0) }};
    let at = if got as u64 == want {{ got }} else {{ std::ptr::null_mut() }};
    image::install(at);
    let (img_at, _, img_len) = rt::image_region();
    let initial: Vec<u8> = unsafe {{ std::slice::from_raw_parts(img_at, img_len) }}.to_vec();
"#,
                at = img.at,
            ),
            format!(
                r#"    let mut shown = 0usize;
    let now = unsafe {{ std::slice::from_raw_parts(img_at, img_len) }};
    'ranges: for &(off, n) in image::IMAGE.writable {{
        let (lo, hi) = (off as usize, (off as usize + n as usize).min(img_len));
        let mut i = lo;
        while i < hi {{
            if now[i] == initial[i] {{
                i += 1;
                continue;
            }}
            let s = i;
            while i < hi && now[i] != initial[i] {{
                i += 1;
            }}
            let hex = |b: &[u8]| b.iter().map(|x| format!("{{:02x}}", x)).collect::<String>();
            writeln!(out, "gw {{:x}} {{}} {{}}", {low_vaddr:#x}u64 + s as u64, hex(&initial[s..i]), hex(&now[s..i])).unwrap();
            shown += 1;
            if shown >= 64 {{
                break 'ranges;
            }}
        }}
    }}
"#,
                low_vaddr = img.image.low_vaddr,
            ),
        ),
    };
    format!(
        r#"#![allow(warnings)]
mod translation;
{image_mod}{ptrdesc_mod}
use std::cell::RefCell;
use std::fmt::Write as _;

unsafe extern "C" {{
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
}}

// An object sits at the address the oracle gives it (`abi::place_object`): its own mapping of
// whole pages, the data flush against the end, nothing mapped around it. A read or write outside
// the object faults here as it does in the emulator, and a pointer stored in one object has the
// same value on both sides.
struct Buf {{
    at: *mut u8,
    len: usize,
}}

impl Buf {{
    fn new(n: usize, data: &[u8]) -> Buf {{
        let base = {object_base}u64 + {object_stride}u64 * n as u64;
        let map = ((data.len().max(1) as u64 + 0xfff) / 0x1000) * 0x1000;
        // PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE
        let got = unsafe {{ mmap(base as *mut u8, map as usize, 3, 0x2 | 0x20 | 0x100000, -1, 0) }};
        if got as u64 != base {{
            eprintln!("runner: cannot place an object at {{:#x}}", base);
            std::process::exit(99);
        }}
        let at = ((base + map - data.len() as u64) & !7) as *mut u8;
        unsafe {{ std::ptr::copy_nonoverlapping(data.as_ptr(), at, data.len()) }};
        Buf {{ at, len: data.len() }}
    }}
    fn ptr(&mut self) -> *mut u8 {{
        self.at
    }}
    fn bytes(&mut self) -> &mut [u8] {{
        unsafe {{ std::slice::from_raw_parts_mut(self.at, self.len) }}
    }}
}}

fn unhex(s: &str) -> Vec<u8> {{
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}}

thread_local! {{
    static OBJECTS: RefCell<Vec<(u64, usize)>> = RefCell::new(Vec::new());
    static EVENTS: RefCell<Vec<String>> = RefCell::new(Vec::new());
}}

// Mirrors `abi::callback_tag` of the host: the same text for the same situation.
fn tag(v: u64, objs: &[(u64, usize)]) -> String {{
    for (j, &(base, len)) in objs.iter().enumerate() {{
        if v >= base && v < base.saturating_add(len.max(1) as u64) {{
            let off = v - base;
            if (len as u64).saturating_sub(off) >= 4 {{
                let x = unsafe {{ (v as *const i32).read_unaligned() }};
                return format!("o{{}}+{{}}={{:x}}", j, off, x as u32);
            }}
            return format!("o{{}}+{{}}", j, off);
        }}
    }}
    if v > 0xffff {{ "p".to_string() }} else {{ format!("i{{:x}}", v) }}
}}

fn callback(k: u32, a: u64, b: u64) -> i64 {{
    let objs = OBJECTS.with(|o| o.borrow().clone());
    let inside = |v: u64| {{
        objs.iter()
            .any(|&(base, len)| v >= base && v < base + len as u64 && (len as u64 - (v - base)) >= 4)
    }};
    let ret = if inside(a) && inside(b) {{
        let x = unsafe {{ (a as *const i32).read_unaligned() }};
        let y = unsafe {{ (b as *const i32).read_unaligned() }};
        let d = i64::from(x.wrapping_sub(y));
        if k == 0 {{ d }} else {{ -d }}
    }} else {{
        0
    }};
    let ev = format!("cb{{}}({{}},{{}})={{:x}}", k, tag(a, &objs), tag(b, &objs), ret as u64);
    EVENTS.with(|e| e.borrow_mut().push(ev));
    ret
}}

unsafe extern "C" fn cb0(a: u64, b: u64) -> i64 {{ callback(0, a, b) }}
unsafe extern "C" fn cb1(a: u64, b: u64) -> i64 {{ callback(1, a, b) }}

fn main() {{
    let argv: Vec<String> = std::env::args().collect();
{install}    let case = std::fs::read_to_string(&argv[1]).unwrap();
    let mut bufs: Vec<Buf> = Vec::new();
    // Per argument: (is a pointer to bufs[idx], plain value or index).
    let mut slots: Vec<(bool, u64)> = Vec::new();
    let mut links: Vec<(usize, usize, usize, usize, usize)> = Vec::new(); // first, from, off, to, to_off
    let mut lines = case.lines();
    while let Some(line) = lines.next() {{
        let (kind, rest) = line.split_once(' ').unwrap_or((line, ""));
        match kind {{
            "i" | "d" => slots.push((false, u64::from_str_radix(rest, 16).unwrap())),
            "f" => {{
                let k: u32 = rest.parse().unwrap();
                let addr = if k == 0 {{ cb0 as usize as u64 }} else {{ cb1 as usize as u64 }};
                slots.push((false, addr));
            }}
            "b" => {{
                bufs.push(Buf::new(bufs.len(), &unhex(rest)));
                slots.push((true, (bufs.len() - 1) as u64));
            }}
            "g" => {{
                let mut it = rest.split(' ');
                let n: usize = it.next().unwrap().parse().unwrap();
                let m: usize = it.next().unwrap().parse().unwrap();
                let first = bufs.len();
                for _ in 0..n {{
                    let l = lines.next().unwrap();
                    bufs.push(Buf::new(bufs.len(), &unhex(l.strip_prefix("o ").unwrap_or(""))));
                }}
                for _ in 0..m {{
                    let l = lines.next().unwrap();
                    let v: Vec<usize> = l[2..].split(' ').map(|x| x.parse().unwrap()).collect();
                    links.push((first, v[0], v[1], v[2], v[3]));
                }}
                slots.push((true, first as u64));
            }}
            _ => {{}}
        }}
    }}
    let addrs: Vec<u64> = bufs.iter_mut().map(|b| b.ptr() as u64).collect();
    for &(first, from, off, to, to_off) in &links {{
        let target = addrs[first + to] + to_off as u64;
        bufs[first + from].bytes()[off..off + 8].copy_from_slice(&target.to_le_bytes());
    }}
    let objs: Vec<(u64, usize)> = bufs.iter().zip(&addrs).map(|(b, a)| (*a, b.len)).collect();
    OBJECTS.with(|o| *o.borrow_mut() = objs.clone());
    let vals: Vec<u64> = slots
        .iter()
        .map(|&(is_buf, v)| if is_buf {{ addrs[v as usize] }} else {{ v }})
        .collect();
    {body}
    let mut out = String::new();
    match ret {{
        Some(r) => writeln!(out, "ret {{:x}}", r).unwrap(),
        None => writeln!(out, "ret none").unwrap(),
    }}
    if let Some(o) = &ret_object {{
        writeln!(out, "ro {{}}", o).unwrap();
    }}
    for (i, b) in bufs.iter_mut().enumerate() {{
        let mut hex = String::new();
        for byte in b.bytes().iter() {{
            write!(hex, "{{:02x}}", byte).unwrap();
        }}
        writeln!(out, "buf {{}} {{}}", i, hex).unwrap();
    }}
    EVENTS.with(|e| {{
        for ev in e.borrow().iter() {{
            writeln!(out, "cb {{}}", ev).unwrap();
        }}
    }});
{report}    std::fs::write(&argv[2], out).unwrap();
}}
"#,
        object_base = crate::abi::OBJECT_BASE,
        object_stride = crate::abi::OBJECT_STRIDE,
    )
}

/// The program image a runner installs before the call (see [`crate::image`]).
#[derive(Debug, Clone)]
pub struct RunnerImage {
    /// The image.
    pub image: std::sync::Arc<ProgramImage>,
    /// Where the emulator has its first byte: the runner maps it there when the address is free,
    /// so pointers stored in the data have the same values on both sides.
    pub at: u64,
}

/// Builds the runner for `rust_code`, a translation defining `extern "C" fn <sig.name>`.
pub fn build(
    sig: &Signature,
    rust_code: &str,
    confinement: &Confinement,
) -> Result<Build, RewriteError> {
    build_with_timeout(sig, rust_code, confinement, COMPILE_TIMEOUT)
}

/// [`build`] with an explicit compile deadline.
pub fn build_with_timeout(
    sig: &Signature,
    rust_code: &str,
    confinement: &Confinement,
    compile_timeout: Duration,
) -> Result<Build, RewriteError> {
    build_parts(sig, "", rust_code, None, confinement, compile_timeout)
}

/// [`build`] with the trusted prelude and the program image of `opts`: the prelude (the runtime
/// shim) is compiled in front of the code without going through the lint, and the runner
/// installs the image before each call and reports the writes to globals.
pub fn build_full(
    sig: &Signature,
    rust_code: &str,
    opts: &crate::difftest::DiffOptions,
) -> Result<Build, RewriteError> {
    build_parts(
        sig,
        &opts.trusted_prelude,
        rust_code,
        opts.image.as_ref(),
        &opts.confinement,
        COMPILE_TIMEOUT,
    )
}

fn build_parts(
    sig: &Signature,
    trusted: &str,
    rust_code: &str,
    image: Option<&RunnerImage>,
    confinement: &Confinement,
    compile_timeout: Duration,
) -> Result<Build, RewriteError> {
    if let Some(why) = lint_translation(rust_code) {
        return Ok(Build::Rejected(why));
    }
    if !sig.fits_registers() {
        return Err(RewriteError::Unsupported(
            "more than six integer or eight floating-point parameters".into(),
        ));
    }
    let tc = toolchain()?;
    let dir = scratch_dir("kraken-rewrite-")?;
    let wr = |name: &str, text: &str| {
        std::fs::write(dir.path().join(name), text)
            .map_err(|e| RewriteError::Compile(format!("{name}: {e}")))
    };
    wr("translation.rs", &format!("{trusted}{rust_code}"))?;
    wr(
        "main.rs",
        &runner_source(sig, image, trusted.contains("mod rt {")),
    )?;
    if let Some(img) = image {
        std::fs::write(dir.path().join("image.bin"), &img.image.bytes)
            .map_err(|e| RewriteError::Compile(format!("image.bin: {e}")))?;
        wr("image.rs", &img.image.module_source(&[]))?;
    }
    let exe = dir.path().join("runner");
    let mut cmd = Command::new(&tc.rustc);
    cmd.args([
        "--edition",
        "2024",
        "--crate-type",
        "bin",
        "--crate-name",
        "runner",
        "-C",
        "opt-level=0",
        "-C",
        "debuginfo=0",
        "-C",
        "overflow-checks=on",
        "-A",
        "warnings",
        "--error-format",
        "short",
        "-o",
    ])
    .arg(&exe)
    .arg(dir.path().join("main.rs"));
    cmd.env("TMPDIR", dir.path());
    let report = confine(&mut cmd, dir.path(), ReadScope::Toolchain, confinement)?;
    let out = run_captured(
        &mut cmd,
        compile_timeout,
        OUTPUT_CAP,
        Duration::from_millis(10),
    )
    .map_err(|e| RewriteError::Compile(format!("cannot run rustc: {e}")))?;
    let Some(status) = out.status else {
        return Ok(Build::Rejected(format!(
            "does not compile: the compiler did not finish within {:.1} s",
            compile_timeout.as_secs_f32()
        )));
    };
    if !status.success() {
        let text = String::from_utf8_lossy(&out.stderr);
        return Ok(Build::Rejected(format!(
            "does not compile: {}",
            text.lines().take(12).collect::<Vec<_>>().join("\n")
        )));
    }
    Ok(Build::Ready(NativeRunner {
        dir,
        exe,
        sig: sig.clone(),
        confinement: confinement.clone(),
        build_confinement: report,
        image: image.is_some(),
    }))
}

impl NativeRunner {
    /// The directory the runner lives in (for diagnostics).
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    /// Runs one case.
    pub fn run(&self, args: &[Arg]) -> Result<Observation, RewriteError> {
        if args.len() != self.sig.params.len() {
            return Err(RewriteError::Unsupported("argument count".into()));
        }
        let mut case = String::new();
        for (p, a) in self.sig.params.iter().zip(args) {
            match (p, a) {
                (Param::Int { bits, .. }, Arg::Int { value }) => {
                    case.push_str(&format!("i {:x}\n", value & mask(*bits)));
                }
                (Param::Buf, Arg::Buf { data }) => {
                    case.push_str(&format!("b {}\n", to_hex(data)));
                }
                (Param::Double, Arg::Double { bits }) => {
                    case.push_str(&format!("d {bits:x}\n"));
                }
                (Param::Float, Arg::Float { bits }) => {
                    case.push_str(&format!("d {bits:x}\n"));
                }
                (Param::FnPtr, Arg::FnPtr { callback }) => {
                    case.push_str(&format!("f {}\n", callback.index()));
                }
                (Param::Buf, Arg::Graph { objects, links }) => {
                    check_graph(objects, links).map_err(RewriteError::Unsupported)?;
                    case.push_str(&format!("g {} {}\n", objects.len(), links.len()));
                    for o in objects {
                        case.push_str(&format!("o {}\n", to_hex(o)));
                    }
                    for l in links {
                        case.push_str(&format!(
                            "l {} {} {} {}\n",
                            l.from, l.offset, l.to, l.to_offset
                        ));
                    }
                }
                _ => return Err(RewriteError::Unsupported("argument kind".into())),
            }
        }
        let case_path = self.dir.path().join("case.txt");
        let result_path = self.dir.path().join("result.txt");
        let _ = std::fs::remove_file(&result_path);
        std::fs::write(&case_path, case).map_err(|e| RewriteError::Native(e.to_string()))?;

        let mut cmd = Command::new(&self.exe);
        cmd.arg(&case_path).arg(&result_path);
        confine(
            &mut cmd,
            self.dir.path(),
            ReadScope::SystemLibraries,
            &self.confinement,
        )?;
        let out = run_captured(&mut cmd, CASE_TIMEOUT, OUTPUT_CAP, Duration::from_millis(1))
            .map_err(|e| RewriteError::Native(format!("cannot start runner: {e}")))?;
        let (status, stdout, stderr) = (out.status, out.stdout, out.stderr);

        let termination = match status {
            None => Termination::Timeout,
            Some(s) if s.success() && result_path.is_file() => Termination::Returned,
            Some(s) => match s.code() {
                Some(101) => Termination::Fault {
                    detail: format!(
                        "panic: {}",
                        String::from_utf8_lossy(&stderr)
                            .lines()
                            .take(2)
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                },
                Some(code) => Termination::Exited { status: code },
                None => Termination::Fault {
                    detail: format!("killed by a signal ({s})"),
                },
            },
        };
        let mut obs = Observation::failed(termination.clone());
        obs.stdout = stdout;
        obs.stderr = stderr;
        obs.global_writes_observed = self.image;
        if termination == Termination::Returned {
            let text = std::fs::read_to_string(&result_path)
                .map_err(|e| RewriteError::Native(format!("result file: {e}")))?;
            for line in text.lines() {
                let mut it = line.split(' ');
                match (it.next(), it.next(), it.next()) {
                    (Some("ret"), Some("none"), _) => {}
                    (Some("ret"), Some(v), _) => {
                        obs.ret = Some(
                            u64::from_str_radix(v, 16)
                                .map_err(|e| RewriteError::Native(format!("bad ret: {e}")))?,
                        );
                    }
                    (Some("buf"), Some(_), Some(h)) => {
                        obs.buffers.push(
                            from_hex(h).ok_or_else(|| RewriteError::Native("bad buffer".into()))?,
                        );
                    }
                    (Some("buf"), Some(_), None) => obs.buffers.push(Vec::new()),
                    (Some("cb"), Some(ev), _) => obs.callbacks.push(ev.to_string()),
                    (Some("ro"), Some(_), _) => {
                        obs.ret_object = line.strip_prefix("ro ").map(str::to_string);
                    }
                    (Some("gw"), Some(v), Some(before)) => {
                        let after = it.next().unwrap_or("");
                        let bad = || RewriteError::Native("bad global write".into());
                        obs.global_writes.push(GlobalWrite {
                            vaddr: u64::from_str_radix(v, 16).map_err(|_| bad())?,
                            before: from_hex(before).ok_or_else(bad)?,
                            after: from_hex(after).ok_or_else(bad)?,
                        });
                    }
                    _ => {}
                }
            }
        }
        Ok(obs)
    }
}

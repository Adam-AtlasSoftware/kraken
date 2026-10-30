//! `emulate_call`: call one function of the project's program in the emulator.
//!
//! The function runs on `kraken-emu`'s [`kraken_emu::FunctionCaller`] inside the sandbox child
//! `kraken-emu-run`, like `emulate_run`. Without `libc` only the program image is loaded (a pure
//! function runs; a call into an import ends the call and is reported by name); with `libc` the
//! program first runs to `main` (or `startup_address`) so the C library is initialised.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use kraken_emu::call::{CallTermination, RetKind, StartAt, Value};
use kraken_emu::confined::{
    CallArg, CallReply, CallRequest, CallTarget, call_function_confined, find_runner,
};
use kraken_emu::{Arch, RunSpec};
use kraken_engine::unsupported;
use kraken_proto::{ErrorCode, Hex64, PageRequest, ProtoError, Untrusted, hex_bytes, sanitize};
use kraken_sidecar::ConfinementOptions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::debug::is_pie;
use super::emulate::{invalid, problem, with_sysroot};
use super::locator_in;
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{Session, blocking};
use crate::views::locator_parts;

/// Most arguments of a call.
pub const MAX_CALL_ARGS: usize = 16;
/// Largest buffer argument, in bytes.
pub const MAX_BUFFER: usize = 64 * 1024;
/// Largest buffer arguments together, in bytes.
pub const MAX_BUFFERS_TOTAL: usize = 1 << 20;
/// Default instruction budget of a call.
pub const DEFAULT_CALL_STEPS: u64 = 10_000_000;
/// Largest instruction budget of a call.
pub const MAX_CALL_STEPS: u64 = 200_000_000;
/// Instruction budget of the startup to `main` in `libc` mode.
const STARTUP_BUDGET: u64 = 50_000_000;
/// Characters of each output stream returned.
const OUTPUT_CHARS: usize = 4000;
/// Bytes of a buffer shown as hexadecimal digits.
const HEX_PREVIEW: usize = 256;
/// Pages of `list_functions` scanned to find a function by name.
const NAME_SCAN_PAGES: usize = 100;

/// One argument of the call. Give exactly one of `int`, `ptr`, `string`, `hex`, `buffer`, `f32`
/// and `f64`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallArgIn {
    /// An integer (decimal, or a string such as `"0x10"` or `"-3"`).
    #[serde(default)]
    pub int: Option<IntText>,
    /// Width of `int` in bits: 8, 16, 32 or 64 (default 32 when the value fits, else 64).
    #[serde(default)]
    pub bits: Option<u8>,
    /// A raw pointer-sized value, for example an address in the program (`0x...`).
    #[serde(default)]
    pub ptr: Option<Hex64>,
    /// Text placed in the emulator's memory with a terminating zero byte; the function gets its
    /// address. Returned after the call, so a function that edits it in place shows.
    #[serde(default)]
    pub string: Option<String>,
    /// Bytes placed in the emulator's memory, as hexadecimal digits (no terminating zero).
    #[serde(default)]
    pub hex: Option<String>,
    /// A zero-filled buffer of this many bytes (at most 65536) for the function to write into.
    #[serde(default)]
    pub buffer: Option<usize>,
    /// A `float`.
    #[serde(default)]
    pub f32: Option<f32>,
    /// A `double`.
    #[serde(default)]
    pub f64: Option<f64>,
}

/// An integer given as a JSON number or as text (`"0xff"`, `"-1"`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum IntText {
    /// A JSON number.
    Num(i64),
    /// Text.
    Text(String),
}

impl IntText {
    fn parse(&self) -> Option<i128> {
        match self {
            IntText::Num(n) => Some(i128::from(*n)),
            IntText::Text(t) => {
                let t = t.trim();
                let (neg, body) = t.strip_prefix('-').map_or((false, t), |r| (true, r));
                let v = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
                    Some(h) => i128::from_str_radix(h, 16).ok()?,
                    None => body.parse::<i128>().ok()?,
                };
                Some(if neg { -v } else { v })
            }
        }
    }
}

/// Arguments of `emulate_call`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulateCallArgs {
    /// Address of the function, as `0x...` (the listing address). Give this or `function`.
    #[serde(default)]
    pub address: Option<Hex64>,
    /// Name of the function as `list_functions` shows it. Give this or `address`.
    #[serde(default)]
    pub function: Option<String>,
    /// Arguments in order (at most 16).
    #[serde(default)]
    pub args: Vec<CallArgIn>,
    /// What the function returns: `void`, `int` (32 bits), `long` or `ptr` (pointer-sized),
    /// `i8` `i16` `i32` `i64` `u8` `u16` `u32` `u64`, `f32` or `f64` (default `int`).
    #[serde(default)]
    pub returns: Option<String>,
    /// Instruction budget (default 10000000, at most 200000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit in seconds (default 20, at most 120).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Start the whole program up to `main` first so the C library works (needed when the
    /// function calls `strlen`, `malloc`, `printf` and the like; default false).
    #[serde(default)]
    pub libc: bool,
    /// With `libc`: stop the startup at this address instead of `main` (a stripped program has
    /// no `main` symbol; the decompiler's `main` is found by name when it has one).
    #[serde(default)]
    pub startup_address: Option<Hex64>,
    /// Call a copy with the project's byte patches applied (default false).
    #[serde(default)]
    pub patched: bool,
}

/// The value a call returned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallValue {
    /// The return kind used.
    pub kind: String,
    /// The value as an unsigned number in hexadecimal (raw bits for `f32` and `f64`).
    pub hex: String,
    /// The value as a signed decimal number (absent for floats).
    pub signed: Option<i64>,
    /// The value as an unsigned decimal number (absent for floats).
    pub unsigned: Option<u64>,
    /// The value as a floating-point number (`f32` and `f64` only).
    pub float: Option<f64>,
}

/// A buffer argument after the call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallBufferOut {
    /// Index of its argument.
    pub arg: usize,
    /// Where it was placed in the emulator's memory.
    pub address: Hex64,
    /// Size in bytes.
    pub size: usize,
    /// The bytes as hexadecimal digits (first 256 bytes). Program data, so untrusted.
    pub hex: Untrusted<String>,
    /// The bytes as text up to the first zero byte. Untrusted.
    pub text: Untrusted<String>,
    /// True when the function changed the buffer.
    pub changed: bool,
}

/// Result of `emulate_call`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateCallOut {
    /// The function's listing address.
    pub address: Hex64,
    /// Its name, when the engine knows one.
    pub name: Option<Untrusted<String>>,
    /// How the call ended: `returned`, `import` (it reached a library function the image-only
    /// mode cannot run; see `detail`), `fault`, `syscall`, `exited` or `step_limit`.
    pub ended: String,
    /// What `ended` means here (the import name, the fault, how the program exited).
    pub detail: Option<Untrusted<String>>,
    /// The value, when the call returned a value.
    pub value: Option<CallValue>,
    /// The buffer arguments after the call.
    pub buffers: Vec<CallBufferOut>,
    /// What the call wrote to standard output (`libc` mode). Untrusted.
    pub stdout: Untrusted<String>,
    /// What the call wrote to standard error (`libc` mode). Untrusted.
    pub stderr: Untrusted<String>,
    /// Instructions executed by the call.
    pub steps: u64,
    /// Facts about the call.
    pub notes: Vec<String>,
}

/// Calls a function of the program in the emulator.
pub struct EmulateCall;

#[async_trait]
impl Command for EmulateCall {
    type Args = EmulateCallArgs;
    type Output = EmulateCallOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "emulate_call",
            "Call one function in the emulator with the given arguments; returns its value and written buffers",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Runs one function of the program under emulation: give its `address` or \
             `function` name, `args` (numbers, strings and byte buffers placed in emulated \
             memory, floats) and what it `returns`. Answers with the `value`, the `buffers` \
             after the call (what it wrote), `stdout`, `stderr` and how the call `ended`. With \
             `libc` the program starts up to `main` first so libc works; without it a library \
             call ends the call with `ended: import`. Nothing in the project changes.\n\
             Example: emulate_call {\"function\": \"str_count_char\", \"args\": [{\"string\": \"mississippi\"}, {\"int\": 115, \"bits\": 8}], \"returns\": \"int\", \"libc\": true}",
        )
        .details(
            "Built on `kraken-emu`'s function caller (x86, x86-64, ARM, AArch64, RISC-V) in the \
             sandboxed child `kraken-emu-run`. Arguments follow the C calling convention of the \
             architecture; `string` and `hex` and `buffer` arguments are copied into scratch \
             memory and the function gets their address. In the default image-only mode the \
             program's own code runs and its imports are stubs, so a pure function (a parser, a \
             hash, a state machine) works; with `libc` the program is started up to `main` \
             (for a stripped program give `startup_address`), which needs a sysroot for a \
             dynamically linked program as `emulate_run` explains. A function that reads \
             globals sees the program's initial data. Decompiled prototypes are guesses: check \
             the argument kinds with the listing.",
        )
        .needs(&[kraken_engine::Cap::FunctionLister])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: EmulateCallArgs,
    ) -> Result<EmulateCallOut, ProtoError> {
        let plan = validate(&args)?;
        let project = s.project()?;
        let engine = project.engine();
        let lister = engine
            .function_lister()
            .ok_or_else(|| unsupported("function_lister"))?;
        let engine_base = project.program().base.0;
        let binary = PathBuf::from(project.meta().binary_path);

        let (entry, mut name, signature) = match (args.address, &args.function) {
            (Some(a), None) => {
                let found = lister
                    .get_function(&locator_in(a, None)?, &ctx.cancel)
                    .await;
                match found {
                    Ok(f) => (
                        locator_parts(&f.locator).1.0,
                        Some(f.name),
                        f.signature.clone(),
                    ),
                    Err(_) => (a.0, None, None),
                }
            }
            (None, Some(n)) => {
                let want = n.trim();
                let mut cursor = None;
                let mut hit = None;
                for _ in 0..NAME_SCAN_PAGES {
                    let page = lister
                        .list_functions(
                            &PageRequest {
                                cursor: cursor.clone(),
                                limit: Some(200),
                            },
                            &ctx.cancel,
                        )
                        .await?;
                    hit = page.items.into_iter().find(|f| f.name == want);
                    if hit.is_some() || page.next_cursor.is_none() {
                        break;
                    }
                    cursor = page.next_cursor;
                }
                let f = hit.ok_or_else(|| {
                    problem(
                        ErrorCode::NotFound,
                        format!(
                            "no function named {:?} (names are exact; try list_functions)",
                            sanitize(want)
                        ),
                    )
                })?;
                (locator_parts(&f.locator).1.0, Some(f.name), f.signature)
            }
            _ => return Err(invalid("give exactly one of address and function")),
        };
        name = name.map(|n| sanitize(&n));

        let startup = if args.libc {
            Some(match args.startup_address {
                Some(a) => a.0,
                None => main_address(lister, &ctx.cancel).await.unwrap_or(0),
            })
        } else {
            None
        };
        let patches = if args.patched {
            project.with_store(|st| st.active_patches(None)).await?
        } else {
            Vec::new()
        };
        let patched = super::emulate::Patched {
            patches,
            engine_base,
        };
        let out =
            blocking(move || run_call(&binary, &args, plan, entry, startup, &patched, engine_base))
                .await?;
        let mut out = out;
        out.address = Hex64(entry);
        out.name = name.map(Untrusted);
        if let Some(sig) = signature {
            out.notes.push(format!("signature: {}", sanitize(&sig)));
        }
        Ok(out)
    }
}

async fn main_address(
    lister: &dyn kraken_engine::FunctionLister,
    cancel: &kraken_engine::CancellationToken,
) -> Option<u64> {
    let mut cursor = None;
    for _ in 0..NAME_SCAN_PAGES {
        let page = lister
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(200),
                },
                cancel,
            )
            .await
            .ok()?;
        if let Some(f) = page.items.iter().find(|f| f.name == "main") {
            return Some(locator_parts(&f.locator).1.0);
        }
        cursor = page.next_cursor;
        cursor.as_ref()?;
    }
    None
}

/// Validated numeric inputs.
#[derive(Debug, Clone, Copy)]
struct Plan {
    steps: u64,
    seconds: u64,
}

fn validate(args: &EmulateCallArgs) -> Result<Plan, ProtoError> {
    let steps = args.max_steps.unwrap_or(DEFAULT_CALL_STEPS);
    if steps == 0 || steps > MAX_CALL_STEPS {
        return Err(invalid(format!(
            "max_steps must be between 1 and {MAX_CALL_STEPS}"
        )));
    }
    let seconds = args.timeout_seconds.unwrap_or(20);
    if seconds == 0 || seconds > 120 {
        return Err(invalid("timeout_seconds must be between 1 and 120"));
    }
    if args.args.len() > MAX_CALL_ARGS {
        return Err(invalid(format!("at most {MAX_CALL_ARGS} arguments")));
    }
    if args.address.is_some() == args.function.is_some() {
        return Err(invalid("give exactly one of address and function"));
    }
    let mut total = 0usize;
    for (i, a) in args.args.iter().enumerate() {
        let given = [
            a.int.is_some(),
            a.ptr.is_some(),
            a.string.is_some(),
            a.hex.is_some(),
            a.buffer.is_some(),
            a.f32.is_some(),
            a.f64.is_some(),
        ]
        .iter()
        .filter(|g| **g)
        .count();
        if given != 1 {
            return Err(invalid(format!(
                "argument {i}: give exactly one of int, ptr, string, hex, buffer, f32, f64"
            )));
        }
        if a.bits.is_some() && a.int.is_none() {
            return Err(invalid(format!("argument {i}: bits goes with int")));
        }
        if let Some(b) = a.bits
            && ![8, 16, 32, 64].contains(&b)
        {
            return Err(invalid(format!("argument {i}: bits is 8, 16, 32 or 64")));
        }
        if let Some(n) = &a.int
            && n.parse().is_none()
        {
            return Err(invalid(format!("argument {i}: int is not a number")));
        }
        let size = match (&a.string, &a.hex, a.buffer) {
            (Some(t), _, _) => {
                if t.contains('\0') {
                    return Err(invalid(format!("argument {i}: string contains a NUL byte")));
                }
                t.len() + 1
            }
            (_, Some(h), _) => hex_decode(h)
                .ok_or_else(|| invalid(format!("argument {i}: hex is not an even run of digits")))?
                .len(),
            (_, _, Some(n)) => n,
            _ => 0,
        };
        if size > MAX_BUFFER {
            return Err(invalid(format!(
                "argument {i}: a buffer is at most {MAX_BUFFER} bytes"
            )));
        }
        total += size;
    }
    if total > MAX_BUFFERS_TOTAL {
        return Err(invalid("buffer arguments are too large together"));
    }
    ret_kind(args.returns.as_deref(), Arch::X86_64)?;
    Ok(Plan { steps, seconds })
}

fn hex_decode(h: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = h.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

/// The return kind and whether it is signed.
fn ret_kind(text: Option<&str>, arch: Arch) -> Result<(RetKind, bool, String), ProtoError> {
    let t = text.unwrap_or("int").trim().to_ascii_lowercase();
    let ptr = arch.bits() as u8;
    let (kind, signed, label) = match t.as_str() {
        "void" => (RetKind::Void, false, "void"),
        "int" | "i32" => (RetKind::Int { bits: 32 }, true, "i32"),
        "uint" | "u32" => (RetKind::Int { bits: 32 }, false, "u32"),
        "long" => (RetKind::Int { bits: ptr }, true, "long"),
        "ulong" => (RetKind::Int { bits: ptr }, false, "ulong"),
        "ptr" | "pointer" => (RetKind::Int { bits: ptr }, false, "ptr"),
        "i8" | "char" => (RetKind::Int { bits: 8 }, true, "i8"),
        "u8" => (RetKind::Int { bits: 8 }, false, "u8"),
        "i16" | "short" => (RetKind::Int { bits: 16 }, true, "i16"),
        "u16" => (RetKind::Int { bits: 16 }, false, "u16"),
        "i64" => (RetKind::Int { bits: 64 }, true, "i64"),
        "u64" => (RetKind::Int { bits: 64 }, false, "u64"),
        "f32" | "float" => (RetKind::F32, false, "f32"),
        "f64" | "double" => (RetKind::F64, false, "f64"),
        other => {
            return Err(invalid(format!(
                "returns {:?}: use void, int, long, ptr, i8 i16 i32 i64, u8 u16 u32 u64, f32 or f64",
                sanitize(other)
            )));
        }
    };
    Ok((kind, signed, label.to_string()))
}

fn run_call(
    binary: &std::path::Path,
    args: &EmulateCallArgs,
    plan: Plan,
    entry: u64,
    startup: Option<u64>,
    patched: &super::emulate::Patched,
    engine_base: u64,
) -> Result<EmulateCallOut, ProtoError> {
    let runner = find_runner().filter(|p| p.is_file()).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            "the emulator's child program `kraken-emu-run` was not found next to this executable: \
             build it (`cargo build -p kraken-emu --bin kraken-emu-run`) or set KRAKEN_EMU_RUN \
             to its path",
        )
    })?;
    if !binary.is_file() {
        return Err(problem(
            ErrorCode::NotFound,
            format!(
                "the project's binary {} is not there any more",
                binary.display()
            ),
        ));
    }
    let work = tempfile::Builder::new()
        .prefix("kraken-call-")
        .tempdir()
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    let mut notes = Vec::new();
    let program = if args.patched && !patched.patches.is_empty() {
        notes.push(format!(
            "called a patched copy with {} byte patch(es) applied",
            patched.patches.len()
        ));
        super::emulate::build_patched_copy(binary, &patched.patches, work.path(), engine_base)?
    } else {
        if args.patched {
            notes.push("the project has no byte patches; called the original".into());
        }
        binary.to_path_buf()
    };
    let head = std::fs::read(&program)
        .map_err(|e| problem(ErrorCode::Internal, format!("{}: {e}", program.display())))?;
    let arch = Arch::from_elf(&head).map_err(|e| super::emulate::emulation_error(e, binary))?;
    let (ret, signed, label) = ret_kind(args.returns.as_deref(), arch)?;

    let mut call_args = Vec::new();
    for a in &args.args {
        call_args.push(to_call_arg(a, arch)?);
    }
    // The emulator's addresses are link-time ones plus the load bias.
    let vaddr = if is_pie(&program) {
        entry.wrapping_sub(engine_base)
    } else {
        entry
    };
    let start_at = match startup {
        None => None,
        Some(0) => Some(StartAt::Symbol {
            name: "main".into(),
        }),
        Some(a) => Some(StartAt::Vaddr {
            value: if is_pie(&program) {
                a.wrapping_sub(engine_base)
            } else {
                a
            },
        }),
    };
    let req = CallRequest {
        target: CallTarget::Vaddr { value: vaddr },
        args: call_args,
        ret,
        max_instructions: plan.steps,
        start_at,
        startup_budget: STARTUP_BUDGET,
    };
    let mut spec = RunSpec::new(&program);
    spec.workdir = Some(work.path().to_path_buf());
    spec.timeout_ms = Duration::from_secs(plan.seconds).as_millis() as u64;
    let guest = work.path().join("guest");
    std::fs::create_dir(&guest)
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    spec.workdir = Some(guest);

    let call =
        |spec: &RunSpec| call_function_confined(spec, &req, &runner, ConfinementOptions::default());
    let ((reply, report), _libs) = with_sysroot(&mut spec, &program, binary, &mut notes, call)
        .map_err(|e| {
            if req.start_at.is_some() && e.message.contains("no function symbol") {
                problem(
                    ErrorCode::NotFound,
                    format!(
                        "{}; the program has no `main` symbol: give startup_address (the \
                         address of its main function)",
                        e.message
                    ),
                )
            } else {
                e
            }
        })?;
    if !report.is_confined() {
        notes.push(format!(
            "the emulator child ran with limited confinement: {report}"
        ));
    }
    Ok(present(
        reply,
        ret,
        signed,
        &label,
        req.args.as_slice(),
        notes,
    ))
}

fn to_call_arg(a: &CallArgIn, arch: Arch) -> Result<CallArg, ProtoError> {
    if let Some(n) = &a.int {
        let v = n
            .parse()
            .ok_or_else(|| invalid("an int argument is not a number"))?;
        let fits32 = (-(1i128 << 31)..(1i128 << 32)).contains(&v);
        let bits = a.bits.unwrap_or(if fits32 { 32 } else { 64 });
        if bits == 64 && arch.bits() == 32 && !fits32 {
            return Err(invalid("a 64-bit integer argument on a 32-bit program"));
        }
        let lo = if bits >= 64 {
            i128::from(i64::MIN)
        } else {
            -(1i128 << (bits - 1))
        };
        let hi = if bits >= 64 {
            i128::from(u64::MAX)
        } else {
            (1i128 << bits) - 1
        };
        if v < lo || v > hi {
            return Err(invalid(format!("{v} does not fit in {bits} bits")));
        }
        return Ok(CallArg::Value {
            value: Value::Int {
                bits,
                signed: v < 0,
                value: v as i64 as u64,
            },
        });
    }
    if let Some(p) = a.ptr {
        return Ok(CallArg::Value {
            value: Value::ptr(arch, p.0),
        });
    }
    if let Some(t) = &a.string {
        return Ok(CallArg::Buffer {
            data: t.clone().into_bytes(),
            nul: true,
        });
    }
    if let Some(h) = &a.hex {
        return Ok(CallArg::Buffer {
            data: hex_decode(h).ok_or_else(|| invalid("hex is not an even run of digits"))?,
            nul: false,
        });
    }
    if let Some(n) = a.buffer {
        return Ok(CallArg::Buffer {
            data: vec![0; n],
            nul: false,
        });
    }
    if let Some(f) = a.f32 {
        return Ok(CallArg::Value {
            value: Value::f32(f),
        });
    }
    if let Some(f) = a.f64 {
        return Ok(CallArg::Value {
            value: Value::f64(f),
        });
    }
    Err(invalid("an argument is empty"))
}

fn text_of(bytes: &[u8]) -> Untrusted<String> {
    let all = String::from_utf8_lossy(bytes);
    let kept: String = all.chars().take(OUTPUT_CHARS).collect();
    Untrusted(sanitize(&kept))
}

fn present(
    reply: CallReply,
    ret: RetKind,
    signed: bool,
    label: &str,
    sent: &[CallArg],
    mut notes: Vec<String>,
) -> EmulateCallOut {
    let CallReply {
        outcome,
        buffers,
        stdout,
        stderr,
        arch,
        ..
    } = reply;
    notes.insert(0, format!("architecture {arch}"));
    let (ended, detail) = match &outcome.termination {
        CallTermination::Returned => ("returned", None),
        CallTermination::Import { name } => {
            notes.push(format!(
                "the function reached the library function `{}`, which the image-only mode \
                 does not run: set libc to start the program first",
                sanitize(name)
            ));
            ("import", Some(name.clone()))
        }
        CallTermination::Fault { detail, pc } => ("fault", Some(format!("{detail} at {pc:#x}"))),
        CallTermination::Syscall => {
            notes.push("the function made a system call; set libc".into());
            ("syscall", None)
        }
        CallTermination::Exited { exit } => ("exited", Some(exit.describe())),
        CallTermination::Budget => ("step_limit", None),
    };
    let value = outcome.ret.and_then(|bits| match ret {
        RetKind::Void => None,
        RetKind::F32 => {
            let f = f32::from_bits(bits as u32);
            Some(CallValue {
                kind: label.into(),
                hex: format!("{:#x}", bits as u32),
                signed: None,
                unsigned: None,
                float: Some(f64::from(f)),
            })
        }
        RetKind::F64 => Some(CallValue {
            kind: label.into(),
            hex: format!("{bits:#x}"),
            signed: None,
            unsigned: None,
            float: Some(f64::from_bits(bits)),
        }),
        RetKind::Int { bits: w } => {
            let sv = if signed && w < 64 && bits >> (w - 1) & 1 == 1 {
                (bits | !((1u64 << w) - 1)) as i64
            } else {
                bits as i64
            };
            Some(CallValue {
                kind: label.into(),
                hex: format!("{bits:#x}"),
                signed: Some(sv),
                unsigned: Some(bits),
                float: None,
            })
        }
    });
    let buffers = buffers
        .into_iter()
        .map(|b| {
            let before: Vec<u8> = match sent.get(b.arg) {
                Some(CallArg::Buffer { data, nul }) => {
                    let mut d = data.clone();
                    if *nul {
                        d.push(0);
                    }
                    d
                }
                _ => Vec::new(),
            };
            let end = b.data.iter().position(|c| *c == 0).unwrap_or(b.data.len());
            CallBufferOut {
                arg: b.arg,
                address: Hex64(b.address),
                size: b.data.len(),
                hex: Untrusted(hex_bytes(&b.data[..b.data.len().min(HEX_PREVIEW)])),
                text: text_of(&b.data[..end]),
                changed: before != b.data,
            }
        })
        .collect();
    EmulateCallOut {
        address: Hex64(0),
        name: None,
        ended: ended.into(),
        detail: detail.map(|d| Untrusted(sanitize(&d))),
        value,
        buffers,
        stdout: text_of(&stdout),
        stderr: text_of(&stderr),
        steps: outcome.instructions,
        notes,
    }
}

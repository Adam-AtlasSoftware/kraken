//! The arguments and result of `emulate_call`, on every platform (the command itself runs only
//! where the emulator sandbox exists).

use kraken_proto::{Hex64, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub(crate) fn parse(&self) -> Option<i128> {
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

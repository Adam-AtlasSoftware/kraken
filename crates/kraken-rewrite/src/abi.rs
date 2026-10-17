//! The call description shared by the oracle (original code under emulation) and the native
//! runner (the Rust translation): a System V AMD64 signature, concrete argument values and what
//! a call did.

use serde::{Deserialize, Serialize};

/// One parameter of the function under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Param {
    /// An integer in a general purpose register (`bits` is 8, 16, 32 or 64).
    Int { bits: u8, signed: bool },
    /// A pointer to a caller-allocated buffer. Its contents are compared after the call.
    /// Buffers must not contain pointers (the spike cannot relocate them).
    Buf,
}

/// The return type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ret {
    /// Nothing.
    Void,
    /// An integer in RAX.
    Int { bits: u8, signed: bool },
    /// A pointer in RAX. Addresses are not comparable between the original (emulated or native)
    /// and the Rust build, so a function with this result cannot be compared by the function-level
    /// differential test; it is only compiled (see `Check::CompileOnly` in the service).
    Ptr,
}

/// The ABI of one function: the C-level view, which the Rust `extern "C"` signature must map to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Function name (also the Rust symbol the runner calls).
    pub name: String,
    /// Parameters in order (at most six: the oracle passes only register arguments).
    pub params: Vec<Param>,
    /// Return type.
    pub ret: Ret,
}

impl Signature {
    /// The Rust `extern "C"` declaration this signature maps to, with pointers as `*mut u8`.
    pub fn rust_prototype(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| match p {
                Param::Int { bits, signed } => format!("a{i}: {}", int_ty(*bits, *signed)),
                Param::Buf => format!("a{i}: *mut u8"),
            })
            .collect();
        let ret = match self.ret {
            Ret::Void => String::new(),
            Ret::Int { bits, signed } => format!(" -> {}", int_ty(bits, signed)),
            Ret::Ptr => " -> *const u8".to_string(),
        };
        format!(
            "pub unsafe extern \"C\" fn {}({}){ret}",
            self.name,
            params.join(", ")
        )
    }
}

pub(crate) fn int_ty(bits: u8, signed: bool) -> String {
    format!("{}{bits}", if signed { 'i' } else { 'u' })
}

/// A concrete argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Arg {
    /// An integer, given as the raw 64-bit pattern (sign-extended for signed values).
    Int { value: u64 },
    /// Initial buffer contents; the buffer is exactly this long.
    Buf { data: Vec<u8> },
}

/// How a call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Termination {
    /// The function returned.
    Returned,
    /// The program called `exit` (or `_exit`) with this status.
    Exited { status: i32 },
    /// A fault: unmapped access, illegal instruction, panic, signal.
    Fault { detail: String },
    /// The instruction or time budget ran out.
    Timeout,
    /// The original called something the oracle cannot model.
    Unsupported { detail: String },
}

/// A write to global memory (the image's writable segments) made by the original.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalWrite {
    /// Virtual address within the ELF (before any load bias).
    pub vaddr: u64,
    /// Bytes before the call.
    pub before: Vec<u8>,
    /// Bytes after the call.
    pub after: Vec<u8>,
}

/// Everything observable about one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// How the call ended.
    pub termination: Termination,
    /// Return value masked to the return width; `None` for void or when not returned.
    pub ret: Option<u64>,
    /// Final contents of each buffer argument, in parameter order (empty unless returned).
    pub buffers: Vec<Vec<u8>>,
    /// What the function wrote to stdout.
    pub stdout: Vec<u8>,
    /// What the function wrote to stderr.
    pub stderr: Vec<u8>,
    /// Writes to globals (oracle only: the native side has no such memory).
    pub global_writes: Vec<GlobalWrite>,
    /// Instructions emulated (oracle only).
    #[serde(default)]
    pub instructions: u64,
}

impl Observation {
    /// An observation of a call that ended abnormally.
    pub fn failed(termination: Termination) -> Self {
        Observation {
            termination,
            ret: None,
            buffers: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            global_writes: Vec::new(),
            instructions: 0,
        }
    }
}

/// Mask for a return value of `bits` width.
pub(crate) fn mask(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Hex-encodes bytes.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes hex produced by [`to_hex`].
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

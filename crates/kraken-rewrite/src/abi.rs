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
    /// A pointer to a caller-allocated buffer. Its contents are compared after the call. A plain
    /// buffer holds no pointers; one that does is passed as [`Arg::Graph`] to the same parameter.
    Buf,
    /// A `double` in an SSE register (`xmm0` to `xmm7`, numbered separately from the integer
    /// registers).
    Double,
    /// A `float` in an SSE register (the low 32 bits; numbered with the `double`s).
    Float,
    /// A pointer to a function. The test passes one of the host's callbacks (see [`Callback`]),
    /// which both sides implement identically and which records every call it receives.
    FnPtr,
}

/// The return type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ret {
    /// Nothing.
    Void,
    /// An integer in RAX.
    Int { bits: u8, signed: bool },
    /// A `double` in XMM0, compared by its bit pattern.
    Double,
    /// A `float` in the low 32 bits of XMM0, compared by its bit pattern.
    Float,
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
    /// Whether every parameter fits a register: at most six in integer registers (integers,
    /// pointers, function pointers) and eight `double`s and `float`s.
    pub fn fits_registers(&self) -> bool {
        let doubles = self.params.iter().filter(|p| p.is_sse()).count();
        self.params.len() - doubles <= 6 && doubles <= 8
    }

    /// The Rust `extern "C"` declaration this signature maps to, with pointers as `*mut u8`.
    pub fn rust_prototype(&self) -> String {
        let params: Vec<String> = self
            .params
            .iter()
            .enumerate()
            .map(|(i, p)| match p {
                Param::Int { bits, signed } => format!("a{i}: {}", int_ty(*bits, *signed)),
                Param::Buf => format!("a{i}: *mut u8"),
                Param::Double => format!("a{i}: f64"),
                Param::Float => format!("a{i}: f32"),
                Param::FnPtr => format!("a{i}: usize"),
            })
            .collect();
        let ret = match self.ret {
            Ret::Void => String::new(),
            Ret::Int { bits, signed } => format!(" -> {}", int_ty(bits, signed)),
            Ret::Ptr => " -> *const u8".to_string(),
            Ret::Double => " -> f64".to_string(),
            Ret::Float => " -> f32".to_string(),
        };
        format!(
            "pub unsafe extern \"C\" fn {}({}){ret}",
            self.name,
            params.join(", ")
        )
    }
}

impl Param {
    /// Passed in an SSE register (`double` or `float`).
    pub fn is_sse(&self) -> bool {
        matches!(self, Param::Double | Param::Float)
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
    /// A `double`, given as its IEEE-754 bit pattern.
    Double { bits: u64 },
    /// A `float`, given as its IEEE-754 bit pattern.
    Float { bits: u32 },
    /// A callback (see [`Callback`]).
    FnPtr { callback: Callback },
    /// A pointer to the first of several objects that point to each other. Each object is a
    /// separate allocation of exactly its length; the listed links are written into them as
    /// addresses before the call.
    Graph {
        /// The objects; the argument points to `objects[0]`.
        objects: Vec<Vec<u8>>,
        /// Embedded pointers.
        links: Vec<Link>,
    },
}

/// One embedded pointer of an [`Arg::Graph`]: the 8 bytes at `offset` of object `from` hold the
/// address of byte `to_offset` of object `to`. A pointer the case wants null is left zero in the
/// object data and has no link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// The object holding the pointer.
    pub from: usize,
    /// Byte offset of the pointer in it.
    pub offset: usize,
    /// The object it points into.
    pub to: usize,
    /// Byte offset inside that object.
    pub to_offset: usize,
}

/// The function pointers a test can pass. Both sides implement them the same way: the callback
/// takes up to two arguments in integer registers; a value that points into one of the case's
/// objects counts as that object and offset, anything else as a plain number (an address the
/// test did not create is opaque). The result is the signed difference of the first 32 bits the
/// first two pointer arguments point to (negated for [`Callback::Descending`]), 0 when they do
/// not both point into objects. Every call is recorded in [`Observation::callbacks`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Callback {
    /// First 32 bits of the first minus the second.
    Ascending,
    /// The opposite.
    Descending,
}

impl Callback {
    /// Both callbacks.
    pub const ALL: [Callback; 2] = [Callback::Ascending, Callback::Descending];

    /// Position in the stub tables.
    pub fn index(self) -> u64 {
        match self {
            Callback::Ascending => 0,
            Callback::Descending => 1,
        }
    }

    /// The result for 32-bit values `a` and `b` read through the two pointers.
    pub fn result(self, a: i32, b: i32) -> i64 {
        let d = i64::from(a.wrapping_sub(b));
        match self {
            Callback::Ascending => d,
            Callback::Descending => -d,
        }
    }
}

/// How a callback argument is written in [`Observation::callbacks`]: `o<object>+<offset>` for an
/// address inside object `object` (the pointee's first 32 bits follow as `=<hex>` when there are
/// four bytes to read), `p` for another large value (an address the test did not create), `i<hex>`
/// for a small number. `objects` are the base address and length of each object of the case.
pub fn callback_tag(
    value: u64,
    objects: &[(u64, usize)],
    read32: &mut dyn FnMut(u64) -> Option<i32>,
) -> String {
    for (j, &(base, len)) in objects.iter().enumerate() {
        if value >= base && value < base.saturating_add(len.max(1) as u64) {
            let off = value - base;
            let readable = (len as u64).saturating_sub(off) >= 4;
            return match readable.then(|| read32(value)).flatten() {
                Some(v) => format!("o{j}+{off}={:x}", v as u32),
                None => format!("o{j}+{off}"),
            };
        }
    }
    if value > 0xffff {
        "p".to_string()
    } else {
        format!("i{value:x}")
    }
}

/// Where the first object of a call is placed, for the oracle's memory and for the native runner
/// alike. Both sides put object `n` at the same address, so pointers held inside the objects have
/// the same value on both sides and buffers compare byte for byte, and both leave the space
/// around an object unmapped, so a read or write outside it faults on both sides.
pub const OBJECT_BASE: u64 = 0x6000_0000_0000;
/// Distance between the allocations of consecutive objects.
pub const OBJECT_STRIDE: u64 = 0x100_0000;
/// Size of a page for object placement.
pub const OBJECT_PAGE: u64 = 0x1000;

/// For the `n`th object of `len` bytes: the start of its mapping, the mapping's length (whole
/// pages) and the address of its first byte: against the end of the mapping, rounded down to 8 bytes
/// so that integers, pointers and doubles in the object are aligned (a misaligned access is a panic
/// in the runner).
pub fn place_object(n: usize, len: usize) -> (u64, u64, u64) {
    let base = OBJECT_BASE + OBJECT_STRIDE * n as u64;
    let map = (len.max(1) as u64).div_ceil(OBJECT_PAGE) * OBJECT_PAGE;
    (base, map, (base + map - len as u64) & !7)
}

/// [`place_object`] for a program with `bits`-bit pointers: the same addresses on 64-bit
/// targets, a layout below 4 GiB (base `0x6000_0000`, 2 MiB apart) on 32-bit ones, which the
/// native x86-64 runner does not use.
pub fn place_object_for(bits: u32, n: usize, len: usize) -> (u64, u64, u64) {
    if bits == 64 {
        return place_object(n, len);
    }
    let base = 0x6000_0000 + 0x20_0000 * n as u64;
    let map = (len.max(1) as u64).div_ceil(OBJECT_PAGE) * OBJECT_PAGE;
    (base, map, (base + map - len as u64) & !7)
}

/// Checks a graph argument's structure: at least one object, links inside the objects.
pub fn check_graph(objects: &[Vec<u8>], links: &[Link]) -> Result<(), String> {
    if objects.is_empty() {
        return Err("a graph needs at least one object".into());
    }
    if objects.len() > 64 || objects.iter().any(|o| o.len() > 1 << 20) {
        return Err("a graph has at most 64 objects of at most 1 MiB".into());
    }
    for l in links {
        let ok = objects.get(l.from).is_some_and(|o| l.offset + 8 <= o.len())
            && objects.get(l.to).is_some_and(|o| l.to_offset <= o.len());
        if !ok {
            return Err(format!("link {l:?} lies outside the objects"));
        }
    }
    Ok(())
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
    /// Writes to globals: the oracle's, and the native side's when it ran with the program image
    /// (see `global_writes_observed`).
    pub global_writes: Vec<GlobalWrite>,
    /// The native side ran with the program image and reports its writes to globals, so the two
    /// lists can be compared. Without it a write of the original cannot be reproduced.
    #[serde(default)]
    pub global_writes_observed: bool,
    /// Every call the function made to a callback it was given, as [`callback_tag`] texts.
    #[serde(default)]
    pub callbacks: Vec<String>,
    /// Instructions emulated (oracle only).
    #[serde(default)]
    pub instructions: u64,
    /// For a pointer result, what it points at ([`crate::ptrdesc::describe_pointer`]).
    #[serde(default)]
    pub ret_object: Option<String>,
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
            global_writes_observed: false,
            callbacks: Vec::new(),
            instructions: 0,
            ret_object: None,
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

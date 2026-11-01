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
    /// A structure by value (see [`StructShape`] for how it is classified and passed).
    Struct(StructShape),
}

/// One scalar field of a [`StructShape`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Scalar {
    /// An integer or pointer of `bits` (8, 16, 32 or 64).
    Int { bits: u8, signed: bool },
    /// A `float`.
    Float,
    /// A `double`.
    Double,
}

impl Scalar {
    fn size(self) -> usize {
        match self {
            Scalar::Int { bits, .. } => usize::from(bits) / 8,
            Scalar::Float => 4,
            Scalar::Double => 8,
        }
    }

    fn rust_ty(self) -> String {
        match self {
            Scalar::Int { bits, signed } => int_ty(bits, signed),
            Scalar::Float => "f32".into(),
            Scalar::Double => "f64".into(),
        }
    }
}

/// How the System V ABI classifies one eightbyte of a structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EightByte {
    /// General purpose register (`rdi`.. for arguments, `rax`/`rdx` for results).
    Int,
    /// SSE register (`xmm0`.. ; `xmm0`/`xmm1` for results).
    Sse,
}

/// A structure of scalar fields in C layout, passed or returned by value. Up to 16 bytes it is
/// split in eightbytes that go in registers (INTEGER if any field in the eightbyte is an integer
/// or pointer, SSE if all are `float`/`double`); when the registers left do not hold all of it,
/// or it is larger than 16 bytes (class MEMORY), it is copied to the stack. A MEMORY result is
/// written through a hidden first argument (`rdi`, the "sret" pointer) which is also returned in
/// `rax`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructShape {
    /// The Rust type name the translation uses (a plain identifier). KRAKEN defines it as a
    /// `#[repr(C)]` struct with fields `f0`, `f1`, ... in front of the translation.
    pub name: String,
    /// The fields in order.
    pub fields: Vec<Scalar>,
}

impl StructShape {
    /// Field offsets, total size and alignment as C lays the fields out.
    pub fn layout(&self) -> (Vec<usize>, usize, usize) {
        let mut off = 0usize;
        let mut align = 1usize;
        let mut offsets = Vec::with_capacity(self.fields.len());
        for f in &self.fields {
            let sz = f.size().max(1);
            off = off.div_ceil(sz) * sz;
            offsets.push(off);
            off += sz;
            align = align.max(sz);
        }
        (offsets, off.div_ceil(align) * align, align)
    }

    /// Size in bytes.
    pub fn size(&self) -> usize {
        self.layout().1
    }

    /// Checks the shape: a usable name, one to 32 fields, at most 128 bytes, integer widths.
    pub fn validate(&self) -> Result<(), String> {
        let ident = !self.name.is_empty()
            && self.name.len() <= 48
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !self.name.starts_with(|c: char| c.is_ascii_digit());
        if !ident {
            return Err(format!("`{}` is not a usable structure name", self.name));
        }
        if self.fields.is_empty() || self.fields.len() > 32 {
            return Err("a structure has one to 32 fields".into());
        }
        if self
            .fields
            .iter()
            .any(|f| matches!(f, Scalar::Int { bits, .. } if ![8, 16, 32, 64].contains(bits)))
        {
            return Err("integer fields are 8, 16, 32 or 64 bits".into());
        }
        if self.size() > 128 {
            return Err("a structure by value is at most 128 bytes".into());
        }
        Ok(())
    }

    /// The class of each eightbyte, or `None` for class MEMORY (over 16 bytes).
    pub fn classes(&self) -> Option<Vec<EightByte>> {
        let (offsets, size, _) = self.layout();
        if size > 16 {
            return None;
        }
        let mut classes = vec![EightByte::Sse; size.div_ceil(8).max(1)];
        for (f, off) in self.fields.iter().zip(&offsets) {
            if matches!(f, Scalar::Int { .. }) {
                classes[off / 8] = EightByte::Int;
            }
        }
        Some(classes)
    }

    /// Zeroes the padding bytes of a value of this shape (two builds may leave anything there).
    pub fn zero_padding(&self, bytes: &mut [u8]) {
        let (offsets, _, _) = self.layout();
        let mut keep = vec![false; bytes.len()];
        for (f, off) in self.fields.iter().zip(&offsets) {
            for k in keep.iter_mut().skip(*off).take(f.size()) {
                *k = true;
            }
        }
        for (b, k) in bytes.iter_mut().zip(keep) {
            if !k {
                *b = 0;
            }
        }
    }

    /// The `#[repr(C)]` definition of the type.
    pub fn rust_def(&self) -> String {
        let fields: Vec<String> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| format!("    pub f{i}: {},\n", f.rust_ty()))
            .collect();
        format!(
            "#[repr(C)]\n#[derive(Clone, Copy, Debug)]\npub struct {} {{\n{}}}\n",
            self.name,
            fields.concat()
        )
    }
}

/// One 64-bit word of a structure argument as the oracle places it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructWord {
    /// In the next general purpose argument register.
    Int(u64),
    /// In the next SSE argument register.
    Sse(u64),
    /// On the stack, in argument order.
    Mem(u64),
}

/// How a structure argument is passed, given how many integer and SSE argument registers the
/// earlier arguments took: its eightbytes in registers if they all fit, else all on the stack.
pub fn struct_words(
    shape: &StructShape,
    data: &[u8],
    ints_used: usize,
    sse_used: usize,
) -> Vec<StructWord> {
    let word = |j: usize| -> u64 {
        let mut w = [0u8; 8];
        let chunk = data.get(j * 8..).unwrap_or(&[]);
        let n = chunk.len().min(8);
        w[..n].copy_from_slice(&chunk[..n]);
        u64::from_le_bytes(w)
    };
    let words = data.len().div_ceil(8).max(1);
    if let Some(classes) = shape.classes() {
        let need_int = classes.iter().filter(|c| **c == EightByte::Int).count();
        let need_sse = classes.len() - need_int;
        if ints_used + need_int <= 6 && sse_used + need_sse <= 8 {
            return classes
                .iter()
                .enumerate()
                .map(|(j, c)| match c {
                    EightByte::Int => StructWord::Int(word(j)),
                    EightByte::Sse => StructWord::Sse(word(j)),
                })
                .collect();
        }
    }
    (0..words).map(|j| StructWord::Mem(word(j))).collect()
}

/// A structure result as bytes: the registers `RAX`, `RDX`, `XMM0`, `XMM1` taken in class order,
/// cut to the size of the shape. `read` gives a register by name. `None` for class MEMORY.
pub fn struct_result(shape: &StructShape, read: &mut dyn FnMut(&str) -> u64) -> Option<Vec<u8>> {
    let classes = shape.classes()?;
    let (mut ints, mut sses) = (["RAX", "RDX"].into_iter(), ["XMM0", "XMM1"].into_iter());
    let mut out = Vec::new();
    for c in classes {
        let reg = match c {
            EightByte::Int => ints.next(),
            EightByte::Sse => sses.next(),
        }?;
        out.extend_from_slice(&read(reg).to_le_bytes());
    }
    out.truncate(shape.size());
    Some(out)
}

/// The return type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// A structure by value: in registers (`rax`, `rdx`, `xmm0`, `xmm1` by class) up to 16
    /// bytes, otherwise through the hidden first argument. Compared field by field
    /// ([`Observation::ret_bytes`], padding zeroed).
    Struct(StructShape),
}

/// The ABI of one function: the C-level view, which the Rust `extern "C"` signature must map to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// Function name (also the Rust symbol the runner calls).
    pub name: String,
    /// Parameters in order. Integers and pointers beyond the sixth and `float`/`double`s beyond
    /// the eighth go on the stack.
    pub params: Vec<Param>,
    /// Return type.
    pub ret: Ret,
    /// For a variadic function: the index of the first variadic argument. The checks pass
    /// concrete values for it (a `float` as a `double`, as C promotes it), and the caller sets
    /// `al` to the number of SSE registers used, as the ABI requires. The Rust translation takes
    /// all of them as ordinary parameters (stable Rust cannot define a C-variadic function); the
    /// call is the same.
    #[serde(default)]
    pub variadic_from: Option<usize>,
}

impl Signature {
    /// Checks what the oracle and the runner rely on: valid structure shapes, a variadic index
    /// inside the parameters, a bounded count.
    pub fn check(&self) -> Result<(), String> {
        if self.params.len() > 32 {
            return Err("at most 32 parameters".into());
        }
        for p in &self.params {
            if let Param::Struct(s) = p {
                s.validate()?;
            }
        }
        if let Ret::Struct(s) = &self.ret {
            s.validate()?;
        }
        if self.variadic_from.is_some_and(|v| v > self.params.len()) {
            return Err("the variadic index is past the last parameter".into());
        }
        Ok(())
    }

    /// The structure types the signature uses, each once, as `#[repr(C)]` Rust definitions.
    pub fn type_defs(&self) -> String {
        let mut seen: Vec<&str> = Vec::new();
        let mut out = String::new();
        let shapes = self
            .params
            .iter()
            .filter_map(|p| match p {
                Param::Struct(s) => Some(s),
                _ => None,
            })
            .chain(match &self.ret {
                Ret::Struct(s) => Some(s),
                _ => None,
            });
        for s in shapes {
            if !seen.contains(&s.name.as_str()) {
                seen.push(&s.name);
                out.push_str(&s.rust_def());
            }
        }
        out
    }

    /// What the translation prompt says about the shapes beyond plain integers and pointers
    /// (trusted operator text; empty when the signature has none).
    pub fn prompt_notes(&self) -> String {
        let mut notes = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        let shapes = self
            .params
            .iter()
            .filter_map(|p| match p {
                Param::Struct(s) => Some(s),
                _ => None,
            })
            .chain(match &self.ret {
                Ret::Struct(s) => Some(s),
                _ => None,
            });
        for s in shapes {
            if seen.contains(&s.name.as_str()) {
                continue;
            }
            seen.push(&s.name);
            let (offsets, size, _) = s.layout();
            let fields: Vec<String> = s
                .fields
                .iter()
                .zip(&offsets)
                .enumerate()
                .map(|(i, (f, off))| format!("f{i}: {} at offset {off}", f.rust_ty()))
                .collect();
            let how = match s.classes() {
                None => "copied to the stack when passed and returned through a hidden pointer",
                Some(_) => "passed and returned in registers",
            };
            notes.push(format!(
                "`{}` is a `#[repr(C)]` structure of {size} bytes ({}), {how}. It is already \
                 defined in front of your code with `Clone` and `Copy`; do not define it again. \
                 Take and return it by value as the prototype does and Rust's `extern \"C\"` \
                 passes it as C does.",
                s.name,
                fields.join(", ")
            ));
        }
        if let Some(v) = self.variadic_from {
            notes.push(format!(
                "The C function is variadic: parameters from index {v} stand for the variadic \
                 arguments the checks pass (a `float` arrives as `f64`). They are ordinary \
                 parameters in the Rust prototype; read as many of them as the C function \
                 reads and ignore the rest."
            ));
        }
        notes.join("\n")
    }

    /// Whether the result is a structure of class MEMORY, written through the hidden first
    /// argument.
    pub fn returns_in_memory(&self) -> bool {
        matches!(&self.ret, Ret::Struct(s) if s.classes().is_none())
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
                Param::Struct(s) => format!("a{i}: {}", s.name),
            })
            .collect();
        let ret = match &self.ret {
            Ret::Void => String::new(),
            Ret::Int { bits, signed } => format!(" -> {}", int_ty(*bits, *signed)),
            Ret::Ptr => " -> *const u8".to_string(),
            Ret::Double => " -> f64".to_string(),
            Ret::Float => " -> f32".to_string(),
            Ret::Struct(s) => format!(" -> {}", s.name),
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
    /// A structure by value: its bytes in C layout (the size of its [`StructShape`]).
    Struct { data: Vec<u8> },
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
    /// For a structure result: its bytes with the padding zeroed.
    #[serde(default)]
    pub ret_bytes: Option<Vec<u8>>,
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
            ret_bytes: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    const I32: Scalar = Scalar::Int {
        bits: 32,
        signed: true,
    };
    const I64: Scalar = Scalar::Int {
        bits: 64,
        signed: true,
    };

    fn shape(fields: &[Scalar]) -> StructShape {
        StructShape {
            name: "S".into(),
            fields: fields.to_vec(),
        }
    }

    fn word(b: &[u8]) -> u64 {
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    }

    #[test]
    fn eightbytes_are_classified_like_the_abi_says() {
        use EightByte::{Int, Sse};
        assert_eq!(shape(&[I32, I32]).classes(), Some(vec![Int]));
        assert_eq!(
            shape(&[I64, Scalar::Double]).classes(),
            Some(vec![Int, Sse])
        );
        assert_eq!(
            shape(&[Scalar::Double, I64]).classes(),
            Some(vec![Sse, Int])
        );
        assert_eq!(
            shape(&[Scalar::Double, Scalar::Double]).classes(),
            Some(vec![Sse, Sse])
        );
        // Two floats share one SSE eightbyte; an int next to a float makes it INTEGER.
        assert_eq!(
            shape(&[Scalar::Float, Scalar::Float]).classes(),
            Some(vec![Sse])
        );
        assert_eq!(shape(&[Scalar::Float, I32]).classes(), Some(vec![Int]));
        assert_eq!(shape(&[I64, I64, I64]).classes(), None);
        let s = shape(&[I32, Scalar::Float, Scalar::Double]);
        assert_eq!(s.classes(), Some(vec![Int, Sse]));
        let s = shape(&[
            Scalar::Int {
                bits: 8,
                signed: false,
            },
            I64,
        ]);
        assert_eq!(s.size(), 16);
        let mut v = vec![0xffu8; 16];
        s.zero_padding(&mut v);
        assert_eq!(&v[..2], &[0xff, 0]);
        assert_eq!(&v[8..], &[0xff; 8]);
    }

    #[test]
    fn a_structure_that_does_not_fit_the_registers_goes_to_the_stack_whole() {
        let s = shape(&[I64, Scalar::Double]);
        let data: Vec<u8> = (0..16).collect();
        let w = struct_words(&s, &data, 0, 0);
        assert!(matches!(w[0], StructWord::Int(_)) && matches!(w[1], StructWord::Sse(_)));
        // Six integer registers taken: both eightbytes go to memory, though SSE registers are free.
        let w = struct_words(&s, &data, 6, 0);
        assert!(w.iter().all(|x| matches!(x, StructWord::Mem(_))) && w.len() == 2);
        let big = shape(&[I64, I64, I64]);
        let w = struct_words(&big, &[0u8; 24], 0, 0);
        assert!(w.iter().all(|x| matches!(x, StructWord::Mem(_))) && w.len() == 3);
    }

    #[test]
    fn results_are_read_from_the_registers_their_classes_name() {
        let mut regs = |r: &str| match r {
            "RAX" => 0x1111,
            "RDX" => 0x2222,
            "XMM0" => 0x3333,
            _ => 0x4444,
        };
        let b = struct_result(&shape(&[I64, Scalar::Double]), &mut regs).expect("registers");
        assert_eq!((word(&b[..8]), word(&b[8..])), (0x1111, 0x3333));
        let b = struct_result(&shape(&[Scalar::Double, I64]), &mut regs).expect("registers");
        assert_eq!((word(&b[..8]), word(&b[8..])), (0x3333, 0x1111));
        let b = struct_result(&shape(&[I64, I64]), &mut regs).expect("registers");
        assert_eq!((word(&b[..8]), word(&b[8..])), (0x1111, 0x2222));
        assert!(struct_result(&shape(&[I64, I64, I64]), &mut regs).is_none());
    }

    #[test]
    fn shapes_are_validated_and_rendered() {
        assert!(shape(&[I32]).validate().is_ok());
        let mut bad = shape(&[I32]);
        bad.name = "a b; fn evil".into();
        assert!(bad.validate().is_err());
        assert!(shape(&[]).validate().is_err());
        let def = shape(&[I32, Scalar::Double]).rust_def();
        assert!(
            def.contains("#[repr(C)]") && def.contains("pub f1: f64"),
            "{def}"
        );
        let sig = Signature {
            name: "f".into(),
            params: vec![
                Param::Struct(shape(&[I32])),
                Param::Int {
                    bits: 32,
                    signed: true,
                },
            ],
            ret: Ret::Struct(shape(&[I32])),
            variadic_from: Some(1),
        };
        assert_eq!(
            sig.rust_prototype(),
            "pub unsafe extern \"C\" fn f(a0: S, a1: i32) -> S"
        );
        assert_eq!(sig.type_defs().matches("struct S").count(), 1);
        let notes = sig.prompt_notes();
        assert!(
            notes.contains("already defined") && notes.contains("variadic"),
            "{notes}"
        );
    }
}

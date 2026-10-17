//! Ghidra's C++ decompiler and Sleigh, built from source, behind a small KRAKEN shim.
//!
//! The decompiler library keeps global state (capability registries, the language list, static
//! caches) and is not thread-safe, so every call into it takes one process-wide lock. A crash or
//! hang in the C++ code takes the whole process with it; the plan (ADR 0014) is to move
//! [`Session`] into a confined child process once the in-process phase has proven the glue.
//!
//! When the crate was built without the Ghidra sources (see `build.rs`), [`available`] is false
//! and every call returns [`NativeError::Unavailable`].

use std::path::Path;
#[cfg(kraken_native)]
use std::sync::{Mutex, MutexGuard};

/// Errors from the native library.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeError {
    /// The crate was built without the decompiler, or the library was not started.
    #[error("native decompiler unavailable: {0}")]
    Unavailable(String),
    /// The C++ side raised an error.
    #[error("{0}")]
    Native(String),
}

/// Result of native calls.
pub type NativeResult<T> = Result<T, NativeError>;

/// One loaded range of the program image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// First address.
    pub start: u64,
    /// File-backed bytes; the rest of `mem_size` reads as zero.
    pub data: Vec<u8>,
    /// Size in memory (at least `data.len()`).
    pub mem_size: u64,
    /// Whether the decompiler may treat the contents as constant.
    pub readonly: bool,
}

/// The bytes the decompiler and Sleigh read, as a list of segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    /// Non-overlapping segments.
    pub segments: Vec<Segment>,
}

impl Image {
    /// Fills `buf` with the bytes at `addr`; unmapped bytes past the first read as zero. False
    /// when `addr` itself is unmapped.
    pub fn read(&self, addr: u64, buf: &mut [u8]) -> bool {
        buf.fill(0);
        let mut first_mapped = false;
        for s in &self.segments {
            let end = s.start.saturating_add(s.mem_size);
            if addr >= end || addr.saturating_add(buf.len() as u64) <= s.start {
                continue;
            }
            if (s.start..end).contains(&addr) {
                first_mapped = true;
            }
            let lo = addr.max(s.start);
            let hi = end.min(addr.saturating_add(buf.len() as u64));
            for a in lo..hi {
                let off = (a - s.start) as usize;
                if let Some(b) = s.data.get(off) {
                    buf[(a - addr) as usize] = *b;
                }
            }
        }
        first_mapped
    }

    #[cfg(any(kraken_native, test))]
    fn readonly_pairs(&self) -> Vec<u64> {
        self.segments
            .iter()
            .filter(|s| s.readonly && s.mem_size > 0)
            .flat_map(|s| [s.start, s.start.saturating_add(s.mem_size)])
            .collect()
    }
}

/// How control leaves an instruction, derived from its p-code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Flow {
    /// Continues with the next instruction.
    Fallthrough,
    /// Unconditional branch to `targets[0]`.
    Jump,
    /// Conditional branch; also falls through.
    ConditionalJump,
    /// Direct call; also falls through.
    Call,
    /// Return.
    Return,
    /// Computed jump.
    IndirectJump,
    /// Computed call; also falls through.
    IndirectCall,
}

impl Flow {
    #[cfg(kraken_native)]
    fn from_code(c: u8) -> Flow {
        match c {
            1 => Flow::Jump,
            2 => Flow::ConditionalJump,
            3 => Flow::Call,
            4 => Flow::Return,
            5 => Flow::IndirectJump,
            6 => Flow::IndirectCall,
            _ => Flow::Fallthrough,
        }
    }
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    /// Address.
    pub addr: u64,
    /// Length in bytes.
    pub length: u32,
    /// Mnemonic as Sleigh prints it (such as `MOV`).
    pub mnemonic: String,
    /// Operand text as Sleigh prints it.
    pub body: String,
    /// Control flow out of the instruction.
    pub flow: Flow,
    /// Whether execution can continue with the next instruction.
    pub fallthrough: bool,
    /// An indirect jump whose target is loaded from a constant address (a stub, not a switch).
    pub via_pointer: bool,
    /// Branch and call targets in the default code space.
    pub targets: Vec<u64>,
    /// Address-sized constants and absolute memory operands (candidate references), deduplicated.
    pub refs: Vec<u64>,
}

/// A p-code varnode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Varnode {
    /// Address-space name (`ram`, `register`, `unique`, `const`).
    pub space: String,
    /// Offset in the space.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

/// One raw p-code operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcodeOp {
    /// Address of the instruction it belongs to.
    pub addr: u64,
    /// Index within the instruction.
    pub seq: u32,
    /// Opcode name such as `COPY` or `INT_ADD`.
    pub opcode: String,
    /// Output varnode, if any.
    pub output: Option<Varnode>,
    /// Input varnodes.
    pub inputs: Vec<Varnode>,
}

/// Category of a decompiler token, as PrintC tags it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// Keyword.
    Keyword,
    /// Local, parameter or global variable.
    Variable,
    /// Function name.
    Function,
    /// Type name.
    Type,
    /// Structure field.
    Field,
    /// Constant.
    Constant,
    /// Comment.
    Comment,
    /// Operator or punctuation.
    Op,
    /// Anything else (labels).
    Other,
}

impl TokenKind {
    #[cfg(kraken_native)]
    fn from_code(c: u8) -> TokenKind {
        match c {
            0 => TokenKind::Keyword,
            1 => TokenKind::Variable,
            2 => TokenKind::Function,
            3 => TokenKind::Type,
            4 => TokenKind::Field,
            5 => TokenKind::Constant,
            6 => TokenKind::Comment,
            7 => TokenKind::Op,
            _ => TokenKind::Other,
        }
    }
}

/// A span of decompiled text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Start byte offset.
    pub start: u32,
    /// End byte offset (exclusive).
    pub end: u32,
    /// Category.
    pub kind: TokenKind,
    /// Symbol name for variables, functions, types, fields and labels.
    pub symbol: Option<String>,
    /// Address the token refers to (callees, globals, the function itself).
    pub target: Option<u64>,
    /// Varnode as `space:0xoffset:size`.
    pub varnode: Option<String>,
}

/// A decompiled function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decompiled {
    /// C text.
    pub text: String,
    /// Token spans in increasing start order.
    pub tokens: Vec<Token>,
    /// Warnings the decompiler reported.
    pub warnings: Vec<String>,
}

#[cfg(kraken_native)]
static LOCK: Mutex<()> = Mutex::new(());

#[cfg(kraken_native)]
fn lock() -> MutexGuard<'static, ()> {
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(kraken_native)]
mod real {
    use super::*;

    /// Rust side of the load image callback.
    pub struct ImageSource(pub Image);

    impl ImageSource {
        fn load_fill(&self, addr: u64, buf: &mut [u8]) -> bool {
            self.0.read(addr, buf)
        }
        fn readonly_ranges(&self) -> Vec<u64> {
            self.0.readonly_pairs()
        }
    }

    #[cxx::bridge(namespace = "kraken")]
    pub mod ffi {
        struct InsnOut {
            addr: u64,
            length: u32,
            mnemonic: String,
            body: String,
            flow: u8,
            fallthrough: bool,
            via_pointer: bool,
            targets: Vec<u64>,
            refs: Vec<u64>,
        }

        struct VarnodeOut {
            space: String,
            offset: u64,
            size: u32,
        }

        struct PcodeOpOut {
            addr: u64,
            seq: u32,
            opcode: String,
            has_output: bool,
            output: VarnodeOut,
            inputs: Vec<VarnodeOut>,
        }

        struct TokenOut {
            start: u32,
            end: u32,
            kind: u8,
            symbol: String,
            has_target: bool,
            target: u64,
            varnode: String,
        }

        struct DecompOut {
            text: String,
            tokens: Vec<TokenOut>,
            warnings: Vec<String>,
        }

        extern "Rust" {
            type ImageSource;
            fn load_fill(self: &ImageSource, addr: u64, buf: &mut [u8]) -> bool;
            fn readonly_ranges(self: &ImageSource) -> Vec<u64>;
        }

        unsafe extern "C++" {
            include!("engine-native-sys/shim/kraken_shim.hh");

            type Session;

            fn start_library(sleigh_home: &str) -> Result<()>;
            fn has_language(language_id: &str) -> Result<bool>;
            fn new_session(
                language_id: &str,
                compiler_id: &str,
                image: Box<ImageSource>,
            ) -> Result<UniquePtr<Session>>;
            fn add_function(self: Pin<&mut Session>, addr: u64, name: &str) -> Result<()>;
            fn decode(self: Pin<&mut Session>, addr: u64, max: u32) -> Result<Vec<InsnOut>>;
            fn lift(self: Pin<&mut Session>, start: u64, end: u64) -> Result<Vec<PcodeOpOut>>;
            fn decompile(self: Pin<&mut Session>, addr: u64) -> Result<DecompOut>;
            fn jump_targets(self: Pin<&mut Session>, addr: u64) -> Result<Vec<u64>>;
        }
    }

    // SAFETY: a Session is only touched while holding the global LOCK, and it owns everything it
    // points to (architecture, translator, load image with its boxed ImageSource).
    unsafe impl Send for ffi::Session {}

    pub fn err(e: cxx::Exception) -> NativeError {
        NativeError::Native(e.what().to_string())
    }
}

/// Whether this build contains the native decompiler.
pub fn available() -> bool {
    cfg!(kraken_native)
}

/// Starts the library once per process, registering the languages of the Ghidra install at
/// `ghidra_home` (whose `Ghidra/Processors/*/data/languages` hold the `.ldefs` and `.sla` files).
/// Later calls are no-ops, whatever path they pass.
pub fn start(ghidra_home: &Path) -> NativeResult<()> {
    #[cfg(kraken_native)]
    {
        let home = ghidra_home
            .to_str()
            .ok_or_else(|| NativeError::Native("Ghidra path is not UTF-8".into()))?;
        let _g = lock();
        real::ffi::start_library(home).map_err(real::err)
    }
    #[cfg(not(kraken_native))]
    {
        let _ = ghidra_home;
        Err(unavailable())
    }
}

/// Whether the started library knows `language_id` (such as `x86:LE:64:default`).
pub fn has_language(language_id: &str) -> NativeResult<bool> {
    #[cfg(kraken_native)]
    {
        let _g = lock();
        real::ffi::has_language(language_id).map_err(real::err)
    }
    #[cfg(not(kraken_native))]
    {
        let _ = language_id;
        Err(unavailable())
    }
}

#[cfg(not(kraken_native))]
fn unavailable() -> NativeError {
    NativeError::Unavailable(
        "engine-native-sys was built without the Ghidra decompiler sources (cargo xtask \
         native-src)"
            .into(),
    )
}

/// A decompiler and Sleigh instance over one program image.
pub struct Session {
    #[cfg(kraken_native)]
    inner: cxx::UniquePtr<real::ffi::Session>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// Builds a session for `language_id` and `compiler_id` (such as `gcc` or `default`).
    /// [`start`] must have run.
    pub fn new(language_id: &str, compiler_id: &str, image: Image) -> NativeResult<Session> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let inner = real::ffi::new_session(
                language_id,
                compiler_id,
                Box::new(real::ImageSource(image)),
            )
            .map_err(real::err)?;
            if inner.is_null() {
                return Err(NativeError::Native("new_session returned null".into()));
            }
            Ok(Session { inner })
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (language_id, compiler_id, image);
            Err(unavailable())
        }
    }

    /// Adds a function symbol, or renames the one at `addr`.
    pub fn add_function(&mut self, addr: u64, name: &str) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            self.pinned()?.add_function(addr, name).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, name);
            Err(unavailable())
        }
    }

    /// Decodes up to `max` consecutive instructions from `addr`; stops early at bytes that do not
    /// decode.
    pub fn decode(&mut self, addr: u64, max: u32) -> NativeResult<Vec<Instruction>> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let rows = self.pinned()?.decode(addr, max).map_err(real::err)?;
            Ok(rows
                .into_iter()
                .map(|r| {
                    let mut refs = r.refs;
                    refs.sort_unstable();
                    refs.dedup();
                    Instruction {
                        addr: r.addr,
                        length: r.length,
                        mnemonic: r.mnemonic,
                        body: r.body,
                        flow: Flow::from_code(r.flow),
                        fallthrough: r.fallthrough,
                        via_pointer: r.via_pointer,
                        targets: r.targets,
                        refs,
                    }
                })
                .collect())
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, max);
            Err(unavailable())
        }
    }

    /// Raw p-code of the instructions in `[start, end)`.
    pub fn lift(&mut self, start: u64, end: u64) -> NativeResult<Vec<PcodeOp>> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let ops = self.pinned()?.lift(start, end).map_err(real::err)?;
            let vn = |v: real::ffi::VarnodeOut| Varnode {
                space: v.space,
                offset: v.offset,
                size: v.size,
            };
            Ok(ops
                .into_iter()
                .map(|o| PcodeOp {
                    addr: o.addr,
                    seq: o.seq,
                    opcode: o.opcode,
                    output: o.has_output.then(|| vn(o.output)),
                    inputs: o.inputs.into_iter().map(vn).collect(),
                })
                .collect())
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (start, end);
            Err(unavailable())
        }
    }

    /// Decompiles the function at `addr` to C with token spans.
    pub fn decompile(&mut self, addr: u64) -> NativeResult<Decompiled> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let out = self.pinned()?.decompile(addr).map_err(real::err)?;
            let opt = |s: String| (!s.is_empty()).then_some(s);
            Ok(Decompiled {
                text: out.text,
                tokens: out
                    .tokens
                    .into_iter()
                    .map(|t| Token {
                        start: t.start,
                        end: t.end,
                        kind: TokenKind::from_code(t.kind),
                        symbol: opt(t.symbol),
                        target: t.has_target.then_some(t.target),
                        varnode: opt(t.varnode),
                    })
                    .collect(),
                warnings: out.warnings,
            })
        }
        #[cfg(not(kraken_native))]
        {
            let _ = addr;
            Err(unavailable())
        }
    }

    /// Runs the decompiler's flow and switch analysis on the function at `addr` and returns the
    /// targets of the jump tables it recovered, sorted and deduplicated.
    pub fn jump_targets(&mut self, addr: u64) -> NativeResult<Vec<u64>> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let mut t = self.pinned()?.jump_targets(addr).map_err(real::err)?;
            t.sort_unstable();
            t.dedup();
            Ok(t)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = addr;
            Err(unavailable())
        }
    }

    #[cfg(kraken_native)]
    fn pinned(&mut self) -> NativeResult<std::pin::Pin<&mut real::ffi::Session>> {
        self.inner
            .as_mut()
            .ok_or_else(|| NativeError::Native("session is null".into()))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // the C++ destructor runs under the library lock too
        #[cfg(kraken_native)]
        {
            let _g = lock();
            drop(std::mem::replace(&mut self.inner, cxx::UniquePtr::null()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_reads_zero_fill_and_report_mapping() {
        let img = Image {
            segments: vec![Segment {
                start: 0x1000,
                data: vec![1, 2, 3],
                mem_size: 8,
                readonly: true,
            }],
        };
        let mut buf = [0xffu8; 4];
        assert!(img.read(0x1001, &mut buf));
        assert_eq!(buf, [2, 3, 0, 0]);
        assert!(!img.read(0x0fff, &mut buf[..1]));
        let mut tail = [0xffu8; 4];
        assert!(img.read(0x1006, &mut tail));
        assert_eq!(tail, [0, 0, 0, 0]);
        assert_eq!(img.readonly_pairs(), vec![0x1000, 0x1008]);
    }
}

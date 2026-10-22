//! Ghidra's C++ decompiler and Sleigh, built from source, behind a small KRAKEN shim.
//!
//! The decompiler library keeps some global state (capability registries, the language list,
//! operator tables set up with a session, the C parser), so every call into it takes one
//! process-wide lock: exclusively for the calls that reach that state (starting the library,
//! creating and dropping a session, parsing C declarations and prototypes), shared for the calls
//! that touch nothing but their own session (decoding, lifting, the switch analysis, decompiling,
//! and the function, mark, convention and comment edits), so the analysis of one program can run
//! on several sessions at once. Several sessions for one program are kept alike through the
//! session's [`Journal`] of its edits ([`Session::fork`]). A crash or
//! hang in the C++ code takes the whole process with it; the plan (ADR 0014) is to move
//! [`Session`] into a confined child process once the in-process phase has proven the glue.
//!
//! When the crate was built without the Ghidra sources (see `build.rs`), [`available`] is false
//! and every call returns [`NativeError::Unavailable`].

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(kraken_native)]
use std::sync::atomic::Ordering;
#[cfg(kraken_native)]
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

/// Errors from the native library.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NativeError {
    /// The crate was built without the decompiler, or the library was not started.
    #[error("native decompiler unavailable: {0}")]
    Unavailable(String),
    /// The C++ side raised an error.
    #[error("{0}")]
    Native(String),
    /// A decompile ran past its time limit and was abandoned at an action break point.
    #[error("decompile timed out after {0:?}")]
    Timeout(Duration),
    /// A decompile was abandoned because the session's stop flag was raised.
    #[error("decompile interrupted")]
    Interrupted,
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

/// A Sleigh context variable painted over an address range when a session starts, such as
/// ARM's `TMode` (1 where the code is Thumb).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRange {
    /// Name of the context variable in the language's specification (`TMode`).
    pub name: String,
    /// First address.
    pub start: u64,
    /// One past the last address.
    pub end: u64,
    /// The value it takes there.
    pub value: u32,
}

/// The bytes the decompiler and Sleigh read, as a list of segments, and the context values a
/// session starts with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    /// Non-overlapping segments.
    pub segments: Vec<Segment>,
    /// Context variables over address ranges, applied in order (later ones win); addresses
    /// outside them keep the language's defaults.
    pub context: Vec<ContextRange>,
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
    /// Constants and absolute memory operands (candidate references), one per address, sorted.
    pub refs: Vec<Reference>,
    /// Registers the instruction's p-code reads, as (offset in the register space, size),
    /// sorted and deduplicated.
    pub reg_reads: Vec<(u64, u32)>,
    /// Registers the instruction's p-code writes, as (offset, size), sorted and deduplicated.
    pub reg_writes: Vec<(u64, u32)>,
}

/// What an instruction does with an address it mentions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    /// A constant narrower than an address (`mov edi, imm32`); weak evidence.
    Immediate,
    /// An address-sized constant (`lea`, `mov r64, imm64`): the address is taken.
    Data,
    /// The instruction reads memory at the address.
    Read,
    /// The instruction writes memory at the address (possibly reading it too).
    Write,
}

impl RefKind {
    #[cfg(kraken_native)]
    fn from_code(c: u8) -> RefKind {
        match c {
            1 => RefKind::Read,
            2 => RefKind::Write,
            3 => RefKind::Immediate,
            _ => RefKind::Data,
        }
    }
}

/// An address an instruction mentions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reference {
    /// The address.
    pub addr: u64,
    /// How it is used.
    pub kind: RefKind,
}

/// One entry of a recovered jump table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JumpEdge {
    /// Address of the computed jump.
    pub op: u64,
    /// One of its targets.
    pub target: u64,
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

/// Where a user comment shows in decompiled C, as the decompiler's comment types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommentSlot {
    /// In the function header (Ghidra's plate comments).
    Header,
    /// Before the statement at the address (pre comments).
    Pre,
    /// At the statement (end-of-line comments).
    Eol,
    /// After the statement (post comments).
    Post,
}

impl CommentSlot {
    /// The decompiler's `Comment::comment_type` bit.
    #[cfg_attr(not(kraken_native), allow(dead_code))]
    fn code(self) -> u8 {
        match self {
            CommentSlot::Eol => 1,
            CommentSlot::Pre => 2,
            CommentSlot::Post => 4,
            CommentSlot::Header => 8,
        }
    }
}

/// A user comment handed to the decompiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserComment {
    /// Address the comment is attached to.
    pub addr: u64,
    /// Where it shows.
    pub slot: CommentSlot,
    /// The text.
    pub text: String,
}

/// Registers packed as `offset << 8 | size` by the shim, unpacked, sorted and deduplicated.
#[cfg(kraken_native)]
fn unpack_regs(packed: &[u64]) -> Vec<(u64, u32)> {
    let mut v: Vec<(u64, u32)> = packed.iter().map(|p| (p >> 8, (p & 0xff) as u32)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(kraken_native)]
static LOCK: RwLock<()> = RwLock::new(());

/// The exclusive lock every call takes unless it is one of the read-only analysis calls below.
#[cfg(kraken_native)]
fn lock() -> RwLockWriteGuard<'static, ()> {
    LOCK.write().unwrap_or_else(|p| p.into_inner())
}

/// The shared lock of the calls that touch only their own session (its program image, Sleigh
/// translator, symbol table, types and actions; no process-wide state): calls on different
/// sessions may overlap, but never with an exclusive call. `tests/parallel.rs` of `engine-native`
/// runs them side by side, and ThreadSanitizer found no race there (see the native engine's
/// notes).
#[cfg(kraken_native)]
fn lock_shared() -> RwLockReadGuard<'static, ()> {
    LOCK.read().unwrap_or_else(|p| p.into_inner())
}

#[cfg(kraken_native)]
mod real {
    use super::*;

    /// Rust side of the load image callback, plus the stop flag decompiles poll.
    pub struct ImageSource(pub Arc<Image>, pub Arc<AtomicBool>);

    impl ImageSource {
        fn load_fill(&self, addr: u64, buf: &mut [u8]) -> bool {
            self.0.read(addr, buf)
        }
        fn readonly_ranges(&self) -> Vec<u64> {
            self.0.readonly_pairs()
        }
        fn context_ranges(&self) -> Vec<ffi::ContextOut> {
            self.0
                .context
                .iter()
                .filter(|c| c.end > c.start)
                .map(|c| ffi::ContextOut {
                    name: c.name.clone(),
                    start: c.start,
                    end: c.end,
                    value: c.value,
                })
                .collect()
        }
        fn interrupted(&self) -> bool {
            self.1.load(Ordering::Relaxed)
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
            ref_kinds: Vec<u8>,
            reg_reads: Vec<u64>,
            reg_writes: Vec<u64>,
        }

        struct JumpEdgeOut {
            op: u64,
            target: u64,
        }

        struct ContextOut {
            name: String,
            start: u64,
            end: u64,
            value: u32,
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

        struct CommentIn {
            addr: u64,
            kind: u8,
            text: String,
        }

        struct DecompOut {
            text: String,
            tokens: Vec<TokenOut>,
            warnings: Vec<String>,
            timed_out: bool,
            interrupted: bool,
        }

        extern "Rust" {
            type ImageSource;
            fn load_fill(self: &ImageSource, addr: u64, buf: &mut [u8]) -> bool;
            fn readonly_ranges(self: &ImageSource) -> Vec<u64>;
            fn context_ranges(self: &ImageSource) -> Vec<ContextOut>;
            fn interrupted(self: &ImageSource) -> bool;
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
            fn ensure_function(self: Pin<&mut Session>, addr: u64) -> Result<()>;
            fn decode(self: Pin<&mut Session>, addr: u64, max: u32) -> Result<Vec<InsnOut>>;
            fn lift(self: Pin<&mut Session>, start: u64, end: u64) -> Result<Vec<PcodeOpOut>>;
            fn decompile(self: Pin<&mut Session>, addr: u64, timeout_ms: u32) -> Result<DecompOut>;
            fn jump_tables(self: Pin<&mut Session>, addr: u64) -> Result<Vec<JumpEdgeOut>>;
            fn declare_type(self: Pin<&mut Session>, decl: &str) -> Result<()>;
            fn set_prototype(self: Pin<&mut Session>, addr: u64, decl: &str) -> Result<()>;
            fn set_noreturn(self: Pin<&mut Session>, addr: u64, noreturn: bool) -> Result<()>;
            fn remove_function(self: Pin<&mut Session>, addr: u64) -> Result<()>;
            fn set_convention(self: Pin<&mut Session>, addr: u64, name: &str) -> Result<()>;
            fn set_comments(
                self: Pin<&mut Session>,
                fad: u64,
                comments: &[CommentIn],
            ) -> Result<()>;
        }
    }

    // SAFETY: a Session is only touched through `&mut` while holding the global LOCK (shared
    // only by calls that reach nothing outside their own session), and it owns everything it
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

/// What a session was built for: its language, compiler and program image. Cheap to clone (the
/// image is shared).
// the stub build makes no sessions
#[cfg_attr(not(kraken_native), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct Origin {
    language: String,
    compiler: String,
    image: Arc<Image>,
}

/// One edit of a session's state, as recorded in its [`Journal`].
// the stub build makes no sessions
#[cfg_attr(not(kraken_native), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    AddFunction(u64, String),
    /// A function a decompile or switch analysis created with its default name.
    EnsureFunction(u64),
    DeclareType(String),
    SetPrototype(u64, String),
    SetNoreturn(u64, bool),
    RemoveFunction(u64),
    SetConvention(u64, String),
}

/// The edits made to a session (functions and their names, types, prototypes, marks and
/// conventions, and the functions decompiles created), in order. Replayed on a new session over
/// the same [`Origin`] it gives a session the decompiler sees the same way. User comments are not
/// in it: they are set before each decompile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Journal {
    calls: Vec<Call>,
}

impl Journal {
    /// Number of edits.
    pub fn len(&self) -> usize {
        self.calls.len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }
}

/// A decompiler and Sleigh instance over one program image.
pub struct Session {
    #[cfg(kraken_native)]
    inner: cxx::UniquePtr<real::ffi::Session>,
    stop: Arc<AtomicBool>,
    origin: Origin,
    journal: Journal,
    /// Addresses whose function a decompile or switch analysis created (or found), journaled once.
    #[cfg_attr(not(kraken_native), allow(dead_code))]
    touched: HashSet<u64>,
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
        Session::from_origin(&Origin {
            language: language_id.to_string(),
            compiler: compiler_id.to_string(),
            image: Arc::new(image),
        })
    }

    /// A fresh session for `origin`, with no edits.
    pub fn from_origin(origin: &Origin) -> NativeResult<Session> {
        #[cfg(kraken_native)]
        {
            let _g = lock();
            let stop = Arc::new(AtomicBool::new(false));
            let inner = real::ffi::new_session(
                &origin.language,
                &origin.compiler,
                Box::new(real::ImageSource(origin.image.clone(), stop.clone())),
            )
            .map_err(real::err)?;
            if inner.is_null() {
                return Err(NativeError::Native("new_session returned null".into()));
            }
            Ok(Session {
                inner,
                stop,
                origin: origin.clone(),
                journal: Journal::default(),
                touched: HashSet::new(),
            })
        }
        #[cfg(not(kraken_native))]
        {
            let _ = origin;
            Err(unavailable())
        }
    }

    /// What this session was built for, to build more like it ([`Session::from_origin`]).
    pub fn origin(&self) -> Origin {
        self.origin.clone()
    }

    /// Number of edits in the journal so far.
    pub fn journal_len(&self) -> usize {
        self.journal.len()
    }

    /// The edits from the `from`-th on.
    pub fn journal_since(&self, from: usize) -> Journal {
        Journal {
            calls: self.journal.calls.get(from..).unwrap_or_default().to_vec(),
        }
    }

    /// Makes the edits of `journal` on this session, in order. An edit that fails here failed
    /// the same way on the session it was recorded on, and is passed over.
    pub fn replay(&mut self, journal: &Journal) -> NativeResult<()> {
        for call in &journal.calls {
            let r = match call {
                Call::AddFunction(a, n) => self.add_function(*a, n),
                Call::EnsureFunction(a) => self.ensure_function(*a),
                Call::DeclareType(d) => self.declare_type(d),
                Call::SetPrototype(a, d) => self.set_prototype(*a, d),
                Call::SetNoreturn(a, n) => self.set_noreturn(*a, *n),
                Call::RemoveFunction(a) => self.remove_function(*a),
                Call::SetConvention(a, n) => self.set_convention(*a, n),
            };
            if let Err(e @ NativeError::Unavailable(_)) = r {
                return Err(e);
            }
        }
        Ok(())
    }

    /// A new session over the same program with the same edits: the decompiler gives the same
    /// answers on it, and it can run beside this one.
    pub fn fork(&self) -> NativeResult<Session> {
        let mut s = Session::from_origin(&self.origin)?;
        s.replay(&self.journal)?;
        Ok(s)
    }

    #[cfg(kraken_native)]
    fn touch(&mut self, addr: u64) {
        if self.touched.insert(addr) {
            self.journal.calls.push(Call::EnsureFunction(addr));
        }
    }

    /// The flag a running decompile polls at every action break point; raising it abandons the
    /// decompile with [`NativeError::Interrupted`]. It is not lowered automatically. The flag
    /// can be raised from any thread while another holds the session.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    /// Adds a function symbol, or renames the one at `addr`.
    pub fn add_function(&mut self, addr: u64, name: &str) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal
                .calls
                .push(Call::AddFunction(addr, name.to_string()));
            let _g = lock_shared();
            self.pinned()?.add_function(addr, name).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, name);
            Err(unavailable())
        }
    }

    /// Creates the function at `addr` with its default name (`FUN_` and the address) unless
    /// there is one, as a decompile of an unknown address does.
    pub fn ensure_function(&mut self, addr: u64) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.touch(addr);
            let _g = lock_shared();
            self.pinned()?.ensure_function(addr).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = addr;
            Err(unavailable())
        }
    }

    /// Decodes up to `max` consecutive instructions from `addr`; stops early at bytes that do not
    /// decode.
    pub fn decode(&mut self, addr: u64, max: u32) -> NativeResult<Vec<Instruction>> {
        #[cfg(kraken_native)]
        {
            let _g = lock_shared();
            let rows = self.pinned()?.decode(addr, max).map_err(real::err)?;
            Ok(rows
                .into_iter()
                .map(|r| {
                    let mut refs: Vec<Reference> = r
                        .refs
                        .iter()
                        .zip(r.ref_kinds.iter().chain(std::iter::repeat(&0)))
                        .map(|(a, k)| Reference {
                            addr: *a,
                            kind: RefKind::from_code(*k),
                        })
                        .collect();
                    // one entry per address, keeping the strongest use
                    refs.sort_unstable_by(|a, b| a.addr.cmp(&b.addr).then(b.kind.cmp(&a.kind)));
                    refs.dedup_by_key(|r| r.addr);
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
                        reg_reads: unpack_regs(&r.reg_reads),
                        reg_writes: unpack_regs(&r.reg_writes),
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
            let _g = lock_shared();
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

    /// Decompiles the function at `addr` to C with token spans. With a `timeout`, the decompile
    /// is abandoned at the first action break point past it ([`NativeError::Timeout`]); a single
    /// long action is not interrupted. The stop flag ([`Session::stop_flag`]) abandons it the
    /// same way.
    pub fn decompile(&mut self, addr: u64, timeout: Option<Duration>) -> NativeResult<Decompiled> {
        #[cfg(kraken_native)]
        {
            let ms = timeout.map_or(0, |t| t.as_millis().clamp(1, u128::from(u32::MAX)) as u32);
            self.touch(addr);
            let _g = lock_shared();
            let out = self.pinned()?.decompile(addr, ms).map_err(real::err)?;
            if out.interrupted {
                return Err(NativeError::Interrupted);
            }
            if out.timed_out {
                return Err(NativeError::Timeout(timeout.unwrap_or_default()));
            }
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
            let _ = (addr, timeout);
            Err(unavailable())
        }
    }

    /// Runs the decompiler's flow and switch analysis on the function at `addr` and returns the
    /// entries of the jump tables it recovered, sorted and deduplicated.
    pub fn jump_tables(&mut self, addr: u64) -> NativeResult<Vec<JumpEdge>> {
        #[cfg(kraken_native)]
        {
            self.touch(addr);
            let _g = lock_shared();
            let mut t: Vec<JumpEdge> = self
                .pinned()?
                .jump_tables(addr)
                .map_err(real::err)?
                .into_iter()
                .map(|e| JumpEdge {
                    op: e.op,
                    target: e.target,
                })
                .collect();
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

    /// The targets of [`Session::jump_tables`], sorted and deduplicated.
    pub fn jump_targets(&mut self, addr: u64) -> NativeResult<Vec<u64>> {
        let mut t: Vec<u64> = self.jump_tables(addr)?.iter().map(|e| e.target).collect();
        t.sort_unstable();
        t.dedup();
        Ok(t)
    }

    /// Parses one C declaration (a typedef, struct, union or enum, in Ghidra's type names such
    /// as `uint` and `undefined8`) into the decompiler's type factory.
    pub fn declare_type(&mut self, decl: &str) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal.calls.push(Call::DeclareType(decl.to_string()));
            let _g = lock();
            self.pinned()?.declare_type(decl).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = decl;
            Err(unavailable())
        }
    }

    /// Parses a C prototype (`int printf(char *format,...)`) and locks it onto the function at
    /// `addr`, which is created when unknown. Callers then decompile with its parameter types.
    pub fn set_prototype(&mut self, addr: u64, decl: &str) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal
                .calls
                .push(Call::SetPrototype(addr, decl.to_string()));
            let _g = lock();
            self.pinned()?.set_prototype(addr, decl).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, decl);
            Err(unavailable())
        }
    }

    /// Marks the function at `addr` as never returning (or clears the mark), so the decompiler
    /// ends flow after calls to it.
    pub fn set_noreturn(&mut self, addr: u64, noreturn: bool) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal.calls.push(Call::SetNoreturn(addr, noreturn));
            let _g = lock_shared();
            self.pinned()?
                .set_noreturn(addr, noreturn)
                .map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, noreturn);
            Err(unavailable())
        }
    }

    /// Removes the function symbol at `addr`, and with it its prototype and marks. A later
    /// decompile at `addr` creates a fresh one with a default name.
    pub fn remove_function(&mut self, addr: u64) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal.calls.push(Call::RemoveFunction(addr));
            self.touched.remove(&addr);
            let _g = lock_shared();
            self.pinned()?.remove_function(addr).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = addr;
            Err(unavailable())
        }
    }

    /// Sets and locks the calling convention (prototype model, such as `__stdcall` or `MSABI`
    /// for x86-64) of the function at `addr`; an empty name restores the default model.
    pub fn set_convention(&mut self, addr: u64, name: &str) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            self.journal
                .calls
                .push(Call::SetConvention(addr, name.to_string()));
            let _g = lock_shared();
            self.pinned()?.set_convention(addr, name).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (addr, name);
            Err(unavailable())
        }
    }

    /// Replaces the user comments of the function at `fad`; the next decompile prints them.
    pub fn set_comments(&mut self, fad: u64, comments: &[UserComment]) -> NativeResult<()> {
        #[cfg(kraken_native)]
        {
            let list: Vec<real::ffi::CommentIn> = comments
                .iter()
                .map(|c| real::ffi::CommentIn {
                    addr: c.addr,
                    kind: c.slot.code(),
                    text: c.text.clone(),
                })
                .collect();
            let _g = lock_shared();
            self.pinned()?.set_comments(fad, &list).map_err(real::err)
        }
        #[cfg(not(kraken_native))]
        {
            let _ = (fad, comments);
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
            context: Vec::new(),
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

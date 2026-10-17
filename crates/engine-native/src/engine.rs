//! The engine: capability traits over the loaded program, Sleigh and the decompiler.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use engine_native_sys::{Instruction, NativeError, Session, TokenKind as NativeKind};
use kraken_engine::{
    Analyzer, Cap, Decompiler, DisasmRequest, Disassembler, Engine, EngineCaps, EngineRejected,
    EngineResult, FlowGraph, FunctionLister, Loader, LoaderSpec, MemoryReader, Mutator,
    ProgramInfo, StringLister, SymbolLister, TypeStore, Watermark, XrefProvider,
};
use kraken_proto::{
    AddressRange, BytesRead, Completeness, DecompileResult, DisasmRow, DisasmScope, ErrorCode,
    FlowKind, FunctionSummary, Hex64, LANGUAGE_C, Locator, MemoryBlock, OperandKind, OperandToken,
    Page, PageRequest, ProtoError, StringEntry, SymbolEntry, Token, TokenKind, TypeDef,
    VersionedLogOp, hex_bytes,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::ctypes::{base_definitions, parse_prototype};
use crate::discover::{Func, discover};
use crate::elf::{Loaded, load};
use crate::listing::{flow_kind, operands};
use crate::mutate::{Defined, Edits, Journaled, STATE_FILE, STATE_FORMAT};
use crate::refs::RefIndex;
use crate::typestore::TypeModel;
use crate::worker::Isolation;

/// Build id in the handshake.
pub const BUILD: &str = concat!(
    "kraken-native/",
    env!("CARGO_PKG_VERSION"),
    " ghidra-12.1.4"
);

/// The Ghidra source tag the library and the compiled `.sla` files come from.
pub const SOURCE_TAG: &str = "Ghidra_12.1.4_build";

/// Default limit for one decompile.
pub const DEFAULT_DECOMPILE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where the engine finds what it needs at run time, and where the decompiler runs.
#[derive(Debug, Clone)]
pub struct NativeConfig {
    /// A directory laid out like a Ghidra install (`Ghidra/Processors/*/data/languages` with
    /// `.ldefs`, `.pspec`, `.cspec` and compiled `.sla` files): the tree `cargo xtask native-sla`
    /// compiles from the pinned sources, or an actual Ghidra install. No JVM is started.
    pub spec_root: PathBuf,
    /// Seed discovery with the symbol table. Off approximates a stripped binary.
    pub use_symbols: bool,
    /// Limit for one decompile, checked at the decompiler's action break points; `None` for no
    /// limit.
    pub decompile_timeout: Option<Duration>,
    /// Where the decompiler runs: a confined worker process (the default) or this process.
    pub isolation: Isolation,
    /// Where `save` and the end of an analysis write the engine's state: the applied edit-log
    /// operations, the types defined through the type store and the analysed signatures (put
    /// it in the engine directory of a project). Opening the same binary again restores them.
    /// `None` keeps everything in memory only.
    pub state_dir: Option<PathBuf>,
}

impl NativeConfig {
    /// A config over `spec_root` with symbols on, the default decompile limit and the confined
    /// worker.
    pub fn new(spec_root: impl Into<PathBuf>) -> NativeConfig {
        NativeConfig {
            spec_root: spec_root.into(),
            use_symbols: true,
            decompile_timeout: Some(DEFAULT_DECOMPILE_TIMEOUT),
            isolation: Isolation::default(),
            state_dir: None,
        }
    }

    /// The first usable spec tree of: `KRAKEN_NATIVE_SPECS`, the tree compiled by `cargo xtask
    /// native-sla` (`~/.cache/kraken-dev/native-sla/Ghidra_12.1.4_build`), `KRAKEN_GHIDRA_HOME`,
    /// and the newest Ghidra install under `~/.cache/kraken-dev/ghidra`.
    pub fn discover() -> Option<NativeConfig> {
        if let Some(p) = std::env::var_os("KRAKEN_NATIVE_SPECS") {
            return Some(NativeConfig::new(p));
        }
        if let Some(p) = compiled_specs_dir().filter(|p| has_specs(p)) {
            return Some(NativeConfig::new(p));
        }
        Self::discover_ghidra()
    }

    /// Like [`NativeConfig::discover`] but only a Ghidra install (`KRAKEN_GHIDRA_HOME`, else the
    /// newest one under `~/.cache/kraken-dev/ghidra`), for comparing against its `.sla` files.
    pub fn discover_ghidra() -> Option<NativeConfig> {
        if let Some(p) = std::env::var_os("KRAKEN_GHIDRA_HOME") {
            return Some(NativeConfig::new(p));
        }
        let dir = PathBuf::from(std::env::var_os("HOME")?).join(".cache/kraken-dev/ghidra");
        let mut kids: Vec<PathBuf> = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| has_specs(p))
            .collect();
        kids.sort();
        kids.pop().map(NativeConfig::new)
    }
}

/// Where `cargo xtask native-sla` puts the spec tree it compiles.
pub fn compiled_specs_dir() -> Option<PathBuf> {
    Some(
        PathBuf::from(std::env::var_os("HOME")?)
            .join(".cache/kraken-dev/native-sla")
            .join(SOURCE_TAG),
    )
}

/// Whether `root` holds the x86-64 Sleigh specification.
pub fn has_specs(root: &Path) -> bool {
    root.join("Ghidra/Processors/x86/data/languages/x86-64.sla")
        .is_file()
}

/// A function table: functions by entry, and the function each body instruction belongs to.
#[derive(Debug, Clone, Default)]
pub(crate) struct Funcs {
    pub(crate) map: BTreeMap<u64, Func>,
    /// The function each body instruction belongs to (the lowest entry when bodies share code).
    owner: BTreeMap<u64, u64>,
}

impl Funcs {
    pub(crate) fn new(map: BTreeMap<u64, Func>) -> Funcs {
        let mut owner = BTreeMap::new();
        for f in map.values() {
            for a in &f.insns {
                owner.entry(*a).or_insert(f.entry);
            }
        }
        Funcs { map, owner }
    }

    pub(crate) fn get(&self, entry: u64) -> Option<&Func> {
        self.map.get(&entry)
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    pub(crate) fn containing(&self, addr: u64) -> Option<&Func> {
        if let Some(f) = self.map.get(&addr) {
            return Some(f);
        }
        if let Some(e) = self.owner.get(&addr) {
            return self.map.get(e);
        }
        self.map.values().find(|f| f.contains(addr))
    }

    /// Entries of the functions named `name`.
    pub(crate) fn named(&self, name: &str) -> Vec<u64> {
        self.map
            .values()
            .filter(|f| f.name == name)
            .map(|f| f.entry)
            .collect()
    }
}

pub(crate) struct Program {
    pub(crate) info: ProgramInfo,
    pub(crate) loaded: Loaded,
    /// The current functions: the discovered ones with the mutator's edits applied.
    funcs: RwLock<Arc<Funcs>>,
    /// The functions as discovery found them.
    pub(crate) discovered: Arc<Funcs>,
    /// Edits applied through the mutator (labels, comments, prototypes, ...).
    pub(crate) edits: Mutex<Edits>,
    /// Prototype declarations the type store locked onto functions (library prototypes and
    /// named function types), reapplied when a function symbol is rebuilt.
    pub(crate) locked: Mutex<BTreeMap<u64, String>>,
    pub(crate) insns: Mutex<BTreeMap<u64, Instruction>>,
    session: Mutex<Session>,
    /// Raised to abandon the decompile in flight (see `Session::stop_flag`).
    stop: Arc<AtomicBool>,
    /// One decompile at a time, so a cancellation only stops its own decompile.
    decompile_slot: tokio::sync::Mutex<()>,
    pub(crate) refs: RefIndex,
    pub(crate) imports: Vec<SymbolEntry>,
    pub(crate) exports: Vec<SymbolEntry>,
    strings: Mutex<BTreeMap<u32, Arc<Vec<StringEntry>>>>,
    pub(crate) types: Mutex<TypeModel>,
    /// Rendered prototypes: known ones at load, the decompiler's after analysis.
    pub(crate) signatures: Mutex<BTreeMap<u64, String>>,
    /// Entries of functions that never return.
    pub(crate) noreturn: BTreeSet<u64>,
    pub(crate) discovery_rounds: usize,
    /// Saved operations that did not apply again when the program was opened.
    replay_failed: AtomicUsize,
}

impl Program {
    pub(crate) fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn insns(&self) -> MutexGuard<'_, BTreeMap<u64, Instruction>> {
        self.insns.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn types(&self) -> MutexGuard<'_, TypeModel> {
        self.types.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn signatures(&self) -> MutexGuard<'_, BTreeMap<u64, String>> {
        self.signatures.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn edits(&self) -> MutexGuard<'_, Edits> {
        self.edits.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn locked(&self) -> MutexGuard<'_, BTreeMap<u64, String>> {
        self.locked.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A snapshot of the current function table.
    pub(crate) fn funcs(&self) -> Arc<Funcs> {
        self.funcs.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Replaces the function table (the mutator's edits).
    pub(crate) fn set_funcs(&self, funcs: Funcs) {
        *self.funcs.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(funcs);
    }

    /// Ghidra's function hash: SHA-256 of the body bytes in address order.
    pub(crate) fn fn_hash(&self, f: &Func) -> String {
        let mut h = Sha256::new();
        for (s, e) in &f.ranges {
            let mut buf = vec![0u8; (e - s) as usize];
            if self.loaded.image.read(*s, &mut buf) {
                h.update(&buf);
            }
        }
        hex_bytes(&h.finalize())
    }

    pub(crate) fn summary(&self, f: &Func) -> FunctionSummary {
        FunctionSummary {
            locator: Locator::ram(f.entry),
            name: f.name.clone(),
            size: Some(f.size()),
            signature: self.signature(f),
            fn_hash: Some(self.fn_hash(f)),
            completeness: Completeness::Complete,
        }
    }

    /// A user prototype (rendered with the current name), else the known or analysed one with
    /// the function's current name.
    fn signature(&self, f: &Func) -> Option<String> {
        let user = self.edits().protos.get(&f.entry).cloned();
        if let Some(p) = user {
            return Some(crate::ctypes::prototype(&p, &f.name, &|_| true));
        }
        self.signatures()
            .get(&f.entry)
            .map(|s| crate::mutate::with_name(s, &f.name))
    }

    /// Entries of the functions named `name`.
    pub(crate) fn named(&self, name: &str) -> Vec<u64> {
        self.funcs().named(name)
    }

    pub(crate) fn strings(&self, min_len: u32) -> Arc<Vec<StringEntry>> {
        let mut cache = self.strings.lock().unwrap_or_else(|p| p.into_inner());
        cache
            .entry(min_len)
            .or_insert_with(|| {
                Arc::new(crate::strings::scan(
                    &self.loaded.image,
                    &self.loaded.blocks,
                    min_len,
                    &self.refs.data_targets(),
                ))
            })
            .clone()
    }

    fn instruction(&self, addr: u64) -> EngineResult<Option<Instruction>> {
        if let Some(i) = self.insns().get(&addr) {
            return Ok(Some(i.clone()));
        }
        let run = self.session().decode(addr, 32).map_err(native)?;
        let mut cache = self.insns();
        for i in run {
            cache.entry(i.addr).or_insert(i);
        }
        Ok(cache.get(&addr).cloned())
    }

    /// The function name and the user label at `addr`, sorted as Ghidra lists them.
    fn labels_at(funcs: &Funcs, edits: &Edits, addr: u64) -> Vec<String> {
        let mut labels = Vec::new();
        if let Some(f) = funcs.get(addr) {
            labels.push(f.name.clone());
        }
        if let Some(l) = edits.labels.get(&addr) {
            labels.push(l.clone());
        }
        labels.sort();
        labels.dedup();
        labels
    }

    fn row(&self, funcs: &Funcs, i: &Instruction) -> DisasmRow {
        let mut bytes = vec![0u8; i.length as usize];
        self.loaded.image.read(i.addr, &mut bytes);
        let edits = self.edits();
        DisasmRow {
            address: Hex64(i.addr),
            bytes: hex_bytes(&bytes),
            mnemonic: i.mnemonic.clone(),
            operands: operands(
                &i.body,
                |a| {
                    funcs
                        .get(a)
                        .map(|f| f.name.clone())
                        .or_else(|| edits.labels.get(&a).cloned())
                },
                |a| self.mapped(a),
            ),
            comment: edits.listing_comment(i.addr),
            labels: Self::labels_at(funcs, &edits, i.addr),
            flow: flow_kind(i.flow),
        }
    }

    /// A row for a data item the mutator defined at `addr`, and its length.
    fn data_row(&self, funcs: &Funcs, addr: u64) -> Option<(DisasmRow, u64)> {
        let edits = self.edits();
        let Some(Defined::Data { ty, len }) = edits.defined.get(&addr) else {
            return None;
        };
        let len = (*len).clamp(1, 4096);
        let mut bytes = vec![0u8; len as usize];
        self.loaded.image.read(addr, &mut bytes);
        let mnemonic = ty
            .as_ref()
            .map(|t| crate::ctypes::declarator(t, "", &|_| true))
            .unwrap_or_else(|| "undefined".into());
        let operands = match len {
            1 | 2 | 4 | 8 => {
                let mut v = [0u8; 8];
                v[..len as usize].copy_from_slice(&bytes);
                vec![OperandToken {
                    text: format!("{:#x}", u64::from_le_bytes(v)),
                    kind: OperandKind::Immediate,
                    target: None,
                }]
            }
            _ => Vec::new(),
        };
        let row = DisasmRow {
            address: Hex64(addr),
            bytes: hex_bytes(&bytes),
            mnemonic,
            operands,
            comment: edits.listing_comment(addr),
            labels: Self::labels_at(funcs, &edits, addr),
            flow: FlowKind::Fallthrough,
        };
        Some((row, len))
    }

    pub(crate) fn mapped(&self, addr: u64) -> bool {
        self.loaded
            .blocks
            .iter()
            .any(|b| b.start.0 <= addr && addr < b.end.0)
    }

    /// Decompiles `at` on a blocking thread; a cancelled `cancel` abandons it at the next action
    /// break point through the stop flag.
    pub(crate) async fn decompile(
        self: &Arc<Self>,
        at: u64,
        timeout: Option<Duration>,
        cancel: &CancellationToken,
    ) -> EngineResult<engine_native_sys::Decompiled> {
        let _slot = self.decompile_slot.lock().await;
        check(cancel)?;
        self.stop.store(false, Ordering::Relaxed);
        let stop = self.stop.clone();
        let token = cancel.clone();
        let watcher = tokio::spawn(async move {
            token.cancelled().await;
            stop.store(true, Ordering::Relaxed);
        });
        let p = self.clone();
        let comments = {
            let funcs = self.funcs();
            let edits = self.edits();
            funcs
                .get(at)
                .map(|f| edits.decompiler_comments(f))
                .unwrap_or_default()
        };
        let r = blocking(move || {
            let mut s = p.session();
            s.set_comments(at, &comments).map_err(native)?;
            s.decompile(at, timeout).map_err(native)
        })
        .await;
        watcher.abort();
        self.stop.store(false, Ordering::Relaxed);
        r
    }
}

/// The engine with the decompiler in the calling process: what the worker process runs, and
/// what [`crate::InProcessEngine`] uses with [`Isolation::InProcess`]. Create it with
/// [`InProcessEngine::new`], then open a binary through [`Loader`]; the other capabilities answer
/// `invalid_argument` until then.
pub struct InProcessEngine {
    pub(crate) config: NativeConfig,
    program: Mutex<Option<Arc<Program>>>,
}

impl std::fmt::Debug for InProcessEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

pub(crate) fn native(e: NativeError) -> ProtoError {
    match e {
        NativeError::Unavailable(m) => ProtoError::new(ErrorCode::Unsupported, m),
        NativeError::Native(m) => ProtoError::new(ErrorCode::Internal, m),
        NativeError::Timeout(d) => ProtoError::new(
            ErrorCode::Timeout,
            format!("decompile timed out after {d:?}"),
        ),
        NativeError::Interrupted => cancelled(),
    }
}

pub(crate) fn cancelled() -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, "cancelled")
}

pub(crate) fn check(cancel: &CancellationToken) -> EngineResult<()> {
    if cancel.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

pub(crate) fn ram_offset(l: &Locator) -> EngineResult<u64> {
    match l {
        Locator::Native { space, offset } if space == "ram" => Ok(offset.0),
        Locator::Native { space, .. } => Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("no functions in space {space}"),
        )),
        _ => Err(ProtoError::new(
            ErrorCode::Unsupported,
            "only native locators are supported",
        )),
    }
}

fn parse_cursor(c: &str) -> EngineResult<u64> {
    c.strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .ok_or_else(|| ProtoError::new(ErrorCode::InvalidArgument, format!("bad cursor {c:?}")))
}

/// A page of `all` from an offset cursor (`"@<n>"`).
pub(crate) fn page_of<T: Clone>(all: &[T], page: &PageRequest) -> EngineResult<Page<T>> {
    let from = match page.cursor.as_deref() {
        None => 0,
        Some(c) => c
            .strip_prefix('@')
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= all.len())
            .ok_or_else(|| {
                ProtoError::new(ErrorCode::InvalidArgument, format!("bad cursor {c:?}"))
            })?,
    };
    let limit = page.effective_limit() as usize;
    let end = (from + limit).min(all.len());
    Ok(Page {
        items: all[from..end].to_vec(),
        next_cursor: (end < all.len()).then(|| format!("@{end}")),
        total: Some(all.len() as u64),
    })
}

/// Fails with `invalid_argument` when `page` has a malformed offset cursor.
pub(crate) fn check_cursor(page: &PageRequest) -> EngineResult<()> {
    match page.cursor.as_deref() {
        Some(c)
            if c.strip_prefix('@')
                .and_then(|n| n.parse::<usize>().ok())
                .is_none() =>
        {
            Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("bad cursor {c:?}"),
            ))
        }
        _ => Ok(()),
    }
}

fn token_kind(k: NativeKind) -> TokenKind {
    match k {
        NativeKind::Keyword => TokenKind::Keyword,
        NativeKind::Variable => TokenKind::Variable,
        NativeKind::Function => TokenKind::Function,
        NativeKind::Type => TokenKind::Type,
        NativeKind::Field => TokenKind::Field,
        NativeKind::Constant => TokenKind::Constant,
        NativeKind::Comment => TokenKind::Comment,
        NativeKind::Op => TokenKind::Op,
        NativeKind::Other => TokenKind::Other,
    }
}

pub(crate) async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> EngineResult<T> + Send + 'static,
) -> EngineResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("native worker failed: {e}")))?
}

/// The declaration line of decompiled C, such as `int cmp_id(int *param_1,int *param_2)`.
pub(crate) fn signature_of(text: &str, name: &str) -> Option<String> {
    let head = &text[..text.find('{')?];
    let start = head.find(&format!("{name}("))?;
    let line_start = head[..start].rfind('\n').map_or(0, |i| i + 1);
    let end = head.rfind(')')? + 1;
    let sig: String = head[line_start..end]
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    (!sig.is_empty()).then_some(sig)
}

/// Loads, discovers and prepares a program (blocking).
fn build_program(
    path: &Path,
    spec: &LoaderSpec,
    config: &NativeConfig,
    token: &CancellationToken,
) -> EngineResult<Program> {
    let data = std::fs::read(path).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let loaded = load(&data, spec.base.map(|b| b.0))?;
    if let Some(a) = spec.arch.as_deref()
        && a != loaded.language.id
    {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "language override {a:?} differs from the detected {}",
                loaded.language.id
            ),
        ));
    }
    engine_native_sys::start(&config.spec_root).map_err(native)?;
    if !engine_native_sys::has_language(loaded.language.id).map_err(native)? {
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "no Sleigh specification for {} under {}",
                loaded.language.id,
                config.spec_root.display()
            ),
        ));
    }
    let mut session = Session::new(
        loaded.language.id,
        loaded.language.compiler,
        loaded.image.clone(),
    )
    .map_err(native)?;
    let Some(found) = discover(&loaded, &mut session, config.use_symbols, token).map_err(native)?
    else {
        return Err(cancelled());
    };
    for f in found.functions.values() {
        session.add_function(f.entry, &f.name).map_err(native)?;
    }

    // types: the base typedefs, then the prototypes of known library functions present here
    let mut by_name: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for f in found.functions.values() {
        by_name.entry(f.name.as_str()).or_default().push(f.entry);
    }
    let named = |n: &str| by_name.get(n).cloned().unwrap_or_default();
    let mut types = TypeModel::default();
    let mut signatures = BTreeMap::new();
    for d in base_definitions() {
        types.define(d, &mut session, &named)?;
    }
    let mut noreturn: BTreeSet<u64> = found
        .functions
        .values()
        .filter(|f| f.noreturn)
        .map(|f| f.entry)
        .collect();
    for src in crate::libc::PROTOTYPES {
        let (name, proto) =
            parse_prototype(src).map_err(|e| ProtoError::new(ErrorCode::Internal, e))?;
        if !by_name.contains_key(name.as_str()) {
            continue;
        }
        if proto.noreturn {
            noreturn.extend(named(&name));
        }
        for (at, text) in types.define(TypeDef::Function(proto), &mut session, &named)? {
            signatures.insert(at, text);
        }
    }
    drop(by_name);

    let funcs = Arc::new(Funcs::new(found.functions));
    // straight-line code reached only through GOT slots (the lazy PLT entries)
    let mut orphans = Vec::new();
    for at in &loaded.got_code {
        if !loaded.is_code(*at) || funcs.owner.contains_key(at) {
            continue;
        }
        for i in session.decode(*at, 8).map_err(native)? {
            let last = i.flow != engine_native_sys::Flow::Fallthrough;
            orphans.push(i);
            if last {
                break;
            }
        }
    }
    let refs = RefIndex::build(&loaded, &funcs.map, &found.insns, &orphans);
    let imports = crate::symbols::imports(&loaded);
    let exports = crate::symbols::exports(&loaded, &funcs.map);
    let info = ProgramInfo {
        arch: loaded.language.id.to_string(),
        format: "elf".into(),
        base: Hex64(loaded.base),
        sha256: hex_bytes(&Sha256::digest(&data)),
        size: data.len() as u64,
    };
    let stop = session.stop_flag();
    Ok(Program {
        info,
        loaded,
        discovered: funcs.clone(),
        funcs: RwLock::new(funcs),
        edits: Mutex::new(Edits::default()),
        locked: Mutex::new(signatures.clone()),
        insns: Mutex::new(found.insns),
        session: Mutex::new(session),
        stop,
        decompile_slot: tokio::sync::Mutex::new(()),
        refs,
        imports,
        exports,
        strings: Mutex::new(BTreeMap::new()),
        types: Mutex::new(types),
        signatures: Mutex::new(signatures),
        noreturn,
        discovery_rounds: found.rounds,
        replay_failed: AtomicUsize::new(0),
    })
}

/// What a state directory holds for one binary: the analysed signatures and the journal.
#[derive(Debug, Default)]
struct SavedState {
    signatures: BTreeMap<u64, String>,
    entries: Vec<Journaled>,
}

/// The saved state of `binary_sha256` in `dir`; empty when there is none (or another binary's).
fn read_state(dir: &Path, binary_sha256: &str) -> SavedState {
    let Ok(text) = std::fs::read_to_string(dir.join(STATE_FILE)) else {
        return SavedState::default();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return SavedState::default();
    };
    if v["format"] != STATE_FORMAT || v["binary_sha256"] != binary_sha256 {
        return SavedState::default();
    }
    let signatures = v["signatures"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, s)| {
                    let at = u64::from_str_radix(k.strip_prefix("0x")?, 16).ok()?;
                    Some((at, s.as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    SavedState {
        signatures,
        entries: serde_json::from_value(v["entries"].clone()).unwrap_or_default(),
    }
}

/// Writes the program's state to `dir` atomically (a temporary file renamed over the old one).
pub(crate) fn persist(p: &Program, dir: &Path) -> EngineResult<()> {
    let io = |what: &str, e: std::io::Error| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("cannot {what} the engine state in {}: {e}", dir.display()),
        )
    };
    let entries = p.edits().journal.clone();
    let signatures: serde_json::Map<String, serde_json::Value> = p
        .signatures()
        .iter()
        .map(|(at, s)| (format!("{at:#x}"), serde_json::Value::String(s.clone())))
        .collect();
    let doc = serde_json::json!({
        "format": STATE_FORMAT,
        "binary_sha256": p.info.sha256,
        "signatures": signatures,
        "entries": entries,
    });
    let text = serde_json::to_vec_pretty(&doc)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
    std::fs::create_dir_all(dir).map_err(|e| io("create", e))?;
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    std::fs::write(&tmp, text).map_err(|e| io("write", e))?;
    std::fs::rename(&tmp, dir.join(STATE_FILE)).map_err(|e| io("replace", e))
}

impl InProcessEngine {
    /// An engine with no program loaded.
    pub fn new(config: NativeConfig) -> InProcessEngine {
        InProcessEngine {
            config,
            program: Mutex::new(None),
        }
    }

    /// Whether this build has the native decompiler and `config` points at usable specs.
    pub fn is_usable(config: &NativeConfig) -> bool {
        engine_native_sys::available() && has_specs(&config.spec_root)
    }

    pub(crate) fn program(&self) -> EngineResult<Arc<Program>> {
        self.program
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .ok_or_else(|| ProtoError::new(ErrorCode::InvalidArgument, "no binary is open"))
    }

    /// Raw p-code of the instructions in `[start, end)` (Sleigh lifting).
    pub fn lift(&self, start: u64, end: u64) -> EngineResult<Vec<engine_native_sys::PcodeOp>> {
        let p = self.program()?;
        let ops = p.session().lift(start, end).map_err(native)?;
        Ok(ops)
    }

    /// Facts about the open program that the traits do not carry: functions that never return
    /// (entries), discovery rounds, reference count and type names still waiting for the
    /// decompiler.
    pub fn stats(&self) -> EngineResult<NativeStats> {
        let p = self.program()?;
        let pending = p.types().pending().map(str::to_string).collect();
        Ok(NativeStats {
            noreturn: p.noreturn.iter().copied().collect(),
            discovery_rounds: p.discovery_rounds,
            references: p.refs.len(),
            landing_pads: p.loaded.landing_pads.values().map(Vec::len).sum(),
            pending_types: pending,
            edits: p.edits().journal.len(),
            replay_failed: p.replay_failed.load(Ordering::Relaxed),
        })
    }
}

/// See [`InProcessEngine::stats`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NativeStats {
    /// Entries of functions that never return, ascending.
    pub noreturn: Vec<u64>,
    /// Discovery rounds (more than one when noreturn propagation changed bodies).
    pub discovery_rounds: usize,
    /// Number of cross-references.
    pub references: usize,
    /// Number of exception landing pads found in `.gcc_except_table`.
    pub landing_pads: usize,
    /// Type definitions the decompiler has not accepted yet.
    pub pending_types: Vec<String>,
    /// Edit-log operations applied and types defined (including those replayed from the
    /// state directory).
    pub edits: usize,
    /// Saved operations that did not apply again when the binary was opened.
    pub replay_failed: usize,
}

impl Engine for InProcessEngine {
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            BUILD,
            [
                Cap::Loader,
                Cap::Analyzer,
                Cap::Decompiler,
                Cap::TypeStore,
                Cap::FunctionLister,
                Cap::Mutator,
                Cap::Memory,
                Cap::Disassembler,
                Cap::Xrefs,
                Cap::Cfg,
                Cap::Strings,
                Cap::Symbols,
            ],
        )
    }
    fn loader(&self) -> Option<&dyn Loader> {
        Some(self)
    }
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        Some(self)
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        Some(self)
    }
    fn type_store(&self) -> Option<&dyn TypeStore> {
        Some(self)
    }
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        Some(self)
    }
    fn memory_reader(&self) -> Option<&dyn MemoryReader> {
        Some(self)
    }
    fn disassembler(&self) -> Option<&dyn Disassembler> {
        Some(self)
    }
    fn xref_provider(&self) -> Option<&dyn XrefProvider> {
        Some(self)
    }
    fn flow_graph(&self) -> Option<&dyn FlowGraph> {
        Some(self)
    }
    fn string_lister(&self) -> Option<&dyn StringLister> {
        Some(self)
    }
    fn symbol_lister(&self) -> Option<&dyn SymbolLister> {
        Some(self)
    }
    fn mutator(&self) -> Option<&dyn Mutator> {
        Some(self)
    }
}

#[async_trait]
impl Loader for InProcessEngine {
    async fn open_binary(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo> {
        check(cancel)?;
        if let Some(f) = spec.format.as_deref()
            && f != "elf"
        {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("format {f:?} is not supported by the native engine"),
            ));
        }
        let path = path.to_path_buf();
        let spec = spec.clone();
        let config = self.config.clone();
        let token = cancel.clone();
        let program = blocking(move || {
            let p = build_program(&path, &spec, &config, &token)?;
            if let Some(dir) = &config.state_dir {
                let saved = read_state(dir, &p.info.sha256);
                p.signatures().extend(saved.signatures);
                for entry in saved.entries {
                    let ok = match entry {
                        Journaled::Op(op) => crate::mutate::apply(&p, &op).is_ok(),
                        Journaled::TypeDef(def) => crate::data::define(&p, def).is_ok(),
                    };
                    if !ok {
                        p.replay_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Ok(p)
        })
        .await?;
        check(cancel)?;
        let info = program.info.clone();
        *self.program.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(program));
        Ok(info)
    }
}

#[async_trait]
impl Mutator for InProcessEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        check(cancel)?;
        op.check_version()?;
        let p = self.program()?;
        let op = op.clone();
        tokio::task::spawn_blocking(move || crate::mutate::apply(&p, &op))
            .await
            .map_err(|e| {
                EngineRejected::new(ErrorCode::Internal, format!("native worker failed: {e}"))
            })?
    }

    async fn save(&self, cancel: &CancellationToken) -> EngineResult<Watermark> {
        check(cancel)?;
        let p = self.program()?;
        let dir = self.config.state_dir.clone();
        blocking(move || {
            let mark = p.edits().watermark();
            if let Some(dir) = dir {
                persist(&p, &dir)?;
            }
            Ok(Watermark(mark))
        })
        .await
    }
}

#[async_trait]
impl FunctionLister for InProcessEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        check(cancel)?;
        let p = self.program()?;
        let from = match page.cursor.as_deref() {
            Some(c) => parse_cursor(c)?,
            None => 0,
        };
        let limit = page.effective_limit() as usize;
        let funcs = p.funcs();
        let mut it = funcs.map.range(from..);
        let items: Vec<FunctionSummary> =
            it.by_ref().take(limit).map(|(_, f)| p.summary(f)).collect();
        let next_cursor = it.next().map(|(a, _)| format!("{a:#x}"));
        Ok(Page {
            items,
            next_cursor,
            total: Some(funcs.len() as u64),
        })
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        check(cancel)?;
        let p = self.program()?;
        let at = ram_offset(locator)?;
        p.funcs()
            .get(at)
            .map(|f| p.summary(f))
            .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no function at {at:#x}")))
    }
}

#[async_trait]
impl Decompiler for InProcessEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        check(cancel)?;
        let p = self.program()?;
        let at = ram_offset(locator)?;
        if p.funcs().get(at).is_none() {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function at {at:#x}"),
            ));
        }
        let d = p
            .decompile(at, self.config.decompile_timeout, cancel)
            .await?;
        check(cancel)?;
        Ok(DecompileResult {
            function: Locator::ram(at),
            language: LANGUAGE_C.to_string(),
            text: d.text,
            tokens: d
                .tokens
                .into_iter()
                .map(|t| Token {
                    start: t.start,
                    end: t.end,
                    kind: token_kind(t.kind),
                    target: t.target.map(Locator::ram),
                    symbol: t.symbol,
                    varnode: t.varnode,
                })
                .collect(),
            warnings: d.warnings,
            completeness: Completeness::Complete,
        })
    }
}

#[async_trait]
impl MemoryReader for InProcessEngine {
    async fn memory_map(&self, cancel: &CancellationToken) -> EngineResult<Vec<MemoryBlock>> {
        check(cancel)?;
        Ok(self.program()?.loaded.blocks.clone())
    }

    async fn read_bytes(
        &self,
        start: &Locator,
        length: u32,
        cancel: &CancellationToken,
    ) -> EngineResult<BytesRead> {
        check(cancel)?;
        if length == 0 {
            return Err(ProtoError::new(ErrorCode::InvalidArgument, "length is 0"));
        }
        let p = self.program()?;
        let at = ram_offset(start)?;
        let blocks = &p.loaded.blocks;
        let Some(mut idx) = blocks.iter().position(|b| b.start.0 <= at && at < b.end.0) else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("{at:#x} is not mapped"),
            ));
        };
        let want = at.saturating_add(u64::from(length));
        let mut bytes = Vec::with_capacity(length as usize);
        let mut uninit: Vec<AddressRange> = Vec::new();
        let mut pos = at;
        while pos < want {
            let b = &blocks[idx];
            let end = b.end.0.min(want);
            let n = (end - pos) as usize;
            let mut chunk = vec![0u8; n];
            if b.initialized {
                p.loaded.image.read(pos, &mut chunk);
            } else {
                match uninit.last_mut() {
                    Some(r) if r.end.0 == pos => r.end = Hex64(end),
                    _ => uninit.push(AddressRange {
                        space: "ram".into(),
                        start: Hex64(pos),
                        end: Hex64(end),
                    }),
                }
            }
            bytes.extend_from_slice(&chunk);
            pos = end;
            // continue only into an adjacent block
            match blocks.get(idx + 1) {
                Some(next) if pos < want && next.start.0 == pos => idx += 1,
                _ => break,
            }
        }
        Ok(BytesRead {
            start: Hex64(at),
            bytes,
            uninitialized: uninit,
        })
    }
}

#[async_trait]
impl Disassembler for InProcessEngine {
    async fn disassemble(
        &self,
        req: &DisasmRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<DisasmRow>> {
        check(cancel)?;
        let p = self.program()?;
        let cursor = page.cursor.as_deref().map(parse_cursor).transpose()?;
        let limit = page.effective_limit() as usize;
        match req.scope {
            DisasmScope::Function => {
                let funcs = p.funcs();
                let f = funcs.containing(req.start.0).ok_or_else(|| {
                    ProtoError::new(
                        ErrorCode::NotFound,
                        format!("no function contains {}", req.start),
                    )
                })?;
                let from = cursor.unwrap_or(0);
                let mut addrs = f.insns.iter().copied().filter(|a| *a >= from);
                let mut items = Vec::new();
                for a in addrs.by_ref().take(limit) {
                    if let Some(i) = p.instruction(a)? {
                        items.push(p.row(&funcs, &i));
                    }
                }
                let next_cursor = addrs.next().map(|a| format!("{a:#x}"));
                Ok(Page {
                    items,
                    next_cursor,
                    total: Some(f.insns.len() as u64),
                })
            }
            DisasmScope::Linear => {
                let mut at = cursor.unwrap_or(req.start.0);
                if !p.mapped(at) {
                    return Err(ProtoError::new(
                        ErrorCode::NotFound,
                        format!("{at:#x} is not mapped"),
                    ));
                }
                let funcs = p.funcs();
                let mut items = Vec::new();
                let mut skipped = 0;
                while items.len() < limit && p.mapped(at) && skipped < 4096 {
                    if let Some((row, len)) = p.data_row(&funcs, at) {
                        items.push(row);
                        at += len;
                        continue;
                    }
                    match p.instruction(at)? {
                        Some(i) => {
                            at += u64::from(i.length);
                            items.push(p.row(&funcs, &i));
                        }
                        None => {
                            // bytes that do not decode are skipped
                            at += 1;
                            skipped += 1;
                        }
                    }
                }
                let next_cursor = p.mapped(at).then(|| format!("{at:#x}"));
                Ok(Page {
                    items,
                    next_cursor,
                    total: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_the_declaration() {
        let text = "\nint cmp_id(int *param_1,\n  int *param_2)\n\n{\n  return 0;\n}\n";
        assert_eq!(
            signature_of(text, "cmp_id").as_deref(),
            Some("int cmp_id(int *param_1, int *param_2)")
        );
        assert_eq!(signature_of("no body", "f"), None);
    }

    #[test]
    fn offset_cursors_page_and_reject_garbage() {
        let all: Vec<u32> = (0..5).collect();
        let req = |cursor: Option<&str>, limit| PageRequest {
            cursor: cursor.map(str::to_string),
            limit: Some(limit),
        };
        let p = page_of(&all, &req(None, 2)).expect("first");
        assert_eq!(p.items, vec![0, 1]);
        let p = page_of(&all, &req(p.next_cursor.as_deref(), 2)).expect("second");
        assert_eq!(p.items, vec![2, 3]);
        let p = page_of(&all, &req(p.next_cursor.as_deref(), 2)).expect("last");
        assert_eq!((p.items, p.next_cursor), (vec![4], None));
        assert!(page_of(&all, &req(Some("not-a-cursor"), 2)).is_err());
        assert!(page_of(&all, &req(Some("@9"), 2)).is_err());
    }
}

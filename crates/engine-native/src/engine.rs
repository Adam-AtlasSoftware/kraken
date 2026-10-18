//! The engine: capability traits over the loaded program, Sleigh and the decompiler.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
    Page, PageRequest, ProtoError, StringEntry, SymbolEntry, Token, TokenKind, TypeDef, TypeRef,
    VersionedLogOp, hex_bytes,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::ctypes::{base_definitions_in, parse_prototype_in, signature};
use crate::discover::{Func, discover};
use crate::elf::{Loaded, load};
use crate::listing::{flow_kind, operands};
use crate::mutate::{Defined, Edits, Journaled, PROTO_NAME, STATE_FILE, STATE_FORMAT};
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
    /// How many decompiler sessions the first open of a big binary uses (see
    /// [`crate::discover::default_threads`]); `None` takes that default. The confined worker has
    /// no environment and cannot read the memory figures, so its parent decides.
    pub discovery_threads: Option<usize>,
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
            discovery_threads: None,
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
    owner: Arc<BTreeMap<u64, u64>>,
}

impl Funcs {
    pub(crate) fn new(map: BTreeMap<u64, Func>) -> Funcs {
        let mut owner = BTreeMap::new();
        for f in map.values() {
            for a in f.insns.iter() {
                owner.entry(*a).or_insert(f.entry);
            }
        }
        Funcs {
            map,
            owner: Arc::new(owner),
        }
    }

    /// The table `map`, which differs from `old` only in what is not a body (names, flags), so
    /// the owner of each instruction is the same.
    pub(crate) fn same_bodies(map: BTreeMap<u64, Func>, old: &Funcs) -> Funcs {
        let same = map.len() == old.map.len()
            && map
                .iter()
                .zip(old.map.iter())
                .all(|((ka, a), (kb, b))| ka == kb && Arc::ptr_eq(&a.insns, &b.insns));
        if same {
            Funcs {
                map,
                owner: old.owner.clone(),
            }
        } else {
            Funcs::new(map)
        }
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
    /// Code reached only through data (the lazy PLT entries), indexed with the bodies.
    orphans: Vec<Instruction>,
    session: Mutex<Session>,
    /// Raised to abandon the decompile in flight (see `Session::stop_flag`).
    stop: Arc<AtomicBool>,
    /// One decompile at a time, so a cancellation only stops its own decompile.
    decompile_slot: tokio::sync::Mutex<()>,
    /// References, exports and the noreturn set of the current function table, rebuilt after
    /// structural edits (see [`Program::reindex`]).
    refs: RwLock<Arc<RefIndex>>,
    pub(crate) imports: Vec<SymbolEntry>,
    exports: RwLock<Arc<Vec<SymbolEntry>>>,
    /// Symbol-table names at function entries that differ from the function's name (mangled
    /// C++ names, aliases), shown as labels as Ghidra shows them.
    symbol_labels: BTreeMap<u64, Vec<String>>,
    /// The mangled name of each function whose name is demangled or from DWARF.
    mangled: BTreeMap<u64, String>,
    strings: Mutex<BTreeMap<u32, Arc<Vec<StringEntry>>>>,
    pub(crate) types: Mutex<TypeModel>,
    /// Rendered prototypes: known ones at load, the decompiler's after analysis.
    pub(crate) signatures: Mutex<BTreeMap<u64, String>>,
    /// Entries of functions that never return.
    noreturn: RwLock<Arc<BTreeSet<u64>>>,
    /// The noreturn set at load (by name, propagation, library and DWARF prototypes).
    found_noreturn: BTreeSet<u64>,
    pub(crate) discovery_rounds: usize,
    /// Saved operations that did not apply again when the program was opened.
    replay_failed: AtomicUsize,
    /// Decompiler output of the functions looked at recently, valid until the next edit.
    decompiled: Mutex<DecompileCache>,
    /// Counts edits (see [`Program::touch`]); a cached decompile from an older count is stale.
    epoch: AtomicU64,
}

/// How many decompiled functions to keep.
const DECOMPILE_CACHE_ENTRIES: usize = 128;
/// Budget for the text and tokens of the cached decompiles, in bytes (roughly).
const DECOMPILE_CACHE_BYTES: usize = 128 * 1024 * 1024;

/// The most recent decompiles, oldest dropped first. One decompile depends on the names, types,
/// prototypes and comments of the whole program, so every edit empties the cache.
#[derive(Default)]
struct DecompileCache {
    epoch: u64,
    order: std::collections::VecDeque<u64>,
    items: BTreeMap<u64, Arc<engine_native_sys::Decompiled>>,
    bytes: usize,
}

impl DecompileCache {
    fn size_of(d: &engine_native_sys::Decompiled) -> usize {
        d.text.len() + d.tokens.len() * std::mem::size_of::<engine_native_sys::Token>() + 256
    }

    fn clear_for(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.order.clear();
            self.items.clear();
            self.bytes = 0;
            self.epoch = epoch;
        }
    }

    fn get(&mut self, at: u64, epoch: u64) -> Option<Arc<engine_native_sys::Decompiled>> {
        self.clear_for(epoch);
        let d = self.items.get(&at)?.clone();
        if let Some(i) = self.order.iter().position(|a| *a == at) {
            self.order.remove(i);
        }
        self.order.push_back(at);
        Some(d)
    }

    fn put(&mut self, at: u64, epoch: u64, d: Arc<engine_native_sys::Decompiled>) {
        self.clear_for(epoch);
        let size = Self::size_of(&d);
        if size > DECOMPILE_CACHE_BYTES / 2 {
            return;
        }
        if let Some(old) = self.items.insert(at, d) {
            self.bytes -= Self::size_of(&old);
            if let Some(i) = self.order.iter().position(|a| *a == at) {
                self.order.remove(i);
            }
        }
        self.order.push_back(at);
        self.bytes += size;
        while self.items.len() > DECOMPILE_CACHE_ENTRIES || self.bytes > DECOMPILE_CACHE_BYTES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(old) = self.items.remove(&oldest) {
                self.bytes -= Self::size_of(&old);
            }
        }
    }
}

impl Program {
    /// Marks the program as edited: the decompiles cached so far no longer apply. Called before
    /// and after every change to names, types, prototypes, comments or the function table.
    pub(crate) fn touch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

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

    /// The current references.
    pub(crate) fn refs(&self) -> Arc<RefIndex> {
        self.refs.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The current exports.
    pub(crate) fn exports(&self) -> Arc<Vec<SymbolEntry>> {
        self.exports
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Entries of the functions that never return.
    pub(crate) fn noreturn(&self) -> Arc<BTreeSet<u64>> {
        self.noreturn
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// The name a function at `at` gets when the log names none: the one discovery gave it,
    /// else its symbol's (demangled, or from DWARF), else `FUN_<entry>`.
    pub(crate) fn base_name(&self, at: u64) -> String {
        if let Some(f) = self.discovered.get(at) {
            return f.name.clone();
        }
        match self.loaded.functions.get(&at) {
            Some(raw) => crate::symbols::default_name(&self.loaded, at, raw),
            None => crate::discover::default_name(at),
        }
    }

    /// The reference index of the function table `funcs`: the bodies of the current functions,
    /// plus code no function holds any more, which stays code as in Ghidra, and addresses defined
    /// as code.
    fn build_refs(&self, funcs: &Arc<Funcs>, edits: &Edits) -> RefIndex {
        let insns = self.insns();
        let mut loose: Vec<Instruction> = self.orphans.clone();
        if !Arc::ptr_eq(funcs, &self.discovered) || !edits.defined.is_empty() {
            let data: Vec<(u64, u64)> = edits
                .defined
                .iter()
                .filter_map(|(a, d)| match d {
                    Defined::Data { len, .. } => Some((*a, a + len)),
                    Defined::Code => None,
                })
                .collect();
            let is_data = |a: u64| data.iter().any(|(s, e)| *s <= a && a < *e);
            let held = |a: u64| funcs.owner.contains_key(&a);
            let gone = self
                .discovered
                .map
                .values()
                .filter(|d| funcs.get(d.entry).is_none_or(|f| f.insns != d.insns))
                .flat_map(|d| d.insns.iter().copied());
            let defined_code = edits
                .defined
                .iter()
                .filter(|(_, d)| matches!(d, Defined::Code))
                .map(|(a, _)| *a);
            let mut seen: BTreeSet<u64> = BTreeSet::new();
            for a in gone.chain(defined_code) {
                if held(a) || is_data(a) || !seen.insert(a) {
                    continue;
                }
                if let Some(i) = insns.get(&a) {
                    loose.push(i.clone());
                }
            }
        }
        RefIndex::build(&self.loaded, &funcs.map, &insns, &loose)
    }

    /// Rebuilds what depends on the function table: the reference index (the bodies of the
    /// current functions, plus code no function holds any more, which stays code as in Ghidra,
    /// and addresses defined as code), the exports (a renamed function renames its export) and
    /// the noreturn set (functions created or re-bounded since discovery are judged by the
    /// propagation rule; the decompiler learns the changes).
    pub(crate) fn reindex(&self) {
        self.reindex_with(true);
    }

    /// [`Program::reindex`] for edits that leave the bodies of the functions alone (a rename, a
    /// prototype): the reference index stays as it is, which is most of the work.
    pub(crate) fn reindex_names(&self) {
        self.reindex_with(false);
    }

    fn reindex_with(&self, rebuild_refs: bool) {
        let funcs = self.funcs();
        let (refs, noreturn_protos) = {
            let edits = self.edits();
            let refs = if rebuild_refs {
                Arc::new(self.build_refs(&funcs, &edits))
            } else {
                self.refs()
            };
            let protos: BTreeSet<u64> = edits
                .protos
                .iter()
                .filter(|(_, p)| p.noreturn)
                .map(|(a, _)| *a)
                .collect();
            (refs, protos)
        };

        // noreturn: the set found at load for unchanged bodies, the rule for changed ones
        let unchanged = |f: &Func| {
            self.discovered
                .get(f.entry)
                .is_some_and(|d| d.insns == f.insns)
        };
        let mut noreturn: BTreeSet<u64> = funcs
            .map
            .values()
            .filter(|f| self.found_noreturn.contains(&f.entry) && unchanged(f))
            .map(|f| f.entry)
            .collect();
        noreturn.extend(noreturn_protos.iter().filter(|a| funcs.get(**a).is_some()));
        let changed: Vec<&Func> = funcs.map.values().filter(|f| !unchanged(f)).collect();
        loop {
            let mut grew = false;
            for f in &changed {
                if f.returns || noreturn.contains(&f.entry) {
                    continue;
                }
                if f.tail_calls.iter().any(|(_, t)| !noreturn.contains(t)) {
                    continue;
                }
                let calls_noreturn = f.insns.iter().any(|a| {
                    refs.from(*a)
                        .iter()
                        .any(|r| r.kind == kraken_proto::XrefKind::Call && noreturn.contains(&r.to))
                });
                if calls_noreturn {
                    noreturn.insert(f.entry);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        let renamed = |a: u64| {
            let f = funcs.get(a)?;
            (f.name != self.base_name(a)).then(|| f.name.clone())
        };
        let exports = crate::symbols::exports(&self.loaded, &funcs.map, &renamed);

        let before = self.noreturn();
        {
            let mut s = self.session();
            for a in noreturn.difference(&before) {
                let _ = s.set_noreturn(*a, true);
            }
            for a in before.difference(&noreturn) {
                if funcs.get(*a).is_some() {
                    let _ = s.set_noreturn(*a, false);
                }
            }
        }
        if rebuild_refs {
            *self.refs.write().unwrap_or_else(|p| p.into_inner()) = refs;
            self.strings
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
        }
        *self.exports.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(exports);
        *self.noreturn.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(noreturn);
        self.touch();
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
            mangled: self.mangled.get(&f.entry).cloned(),
        }
    }

    /// A user prototype (rendered with the current name), else the known or analysed one with
    /// the function's current name.
    fn signature(&self, f: &Func) -> Option<String> {
        let user = self.edits().protos.get(&f.entry).cloned();
        if let Some(p) = user {
            return Some(crate::ctypes::prototype(&p, &f.name, &|_| true));
        }
        let sig = self.signatures().get(&f.entry).cloned()?;
        // the signature carries the name it was made with: the function's at the time
        let base = self.base_name(f.entry);
        let raw = self
            .loaded
            .functions
            .get(&f.entry)
            .cloned()
            .unwrap_or_default();
        Some(crate::mutate::renamed_signature(
            &sig,
            &[base.as_str(), raw.as_str()],
            &f.name,
        ))
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
                    &self.refs().data_targets(),
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

    /// The function name, the other symbol-table names (mangled ones) and the user label at
    /// `addr`, sorted as Ghidra lists them.
    fn labels_at(&self, funcs: &Funcs, edits: &Edits, addr: u64) -> Vec<String> {
        let mut labels = Vec::new();
        if let Some(f) = funcs.get(addr) {
            labels.push(f.name.clone());
        }
        if let Some(names) = self.symbol_labels.get(&addr) {
            labels.extend(names.iter().cloned());
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
            labels: self.labels_at(funcs, &edits, i.addr),
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
            labels: self.labels_at(funcs, &edits, addr),
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
    /// break point through the stop flag. The result of an earlier decompile of `at` is returned
    /// while nothing has been edited since; `remember` keeps the result for the next call (the
    /// analysis job, which decompiles everything once, does not).
    pub(crate) async fn decompile(
        self: &Arc<Self>,
        at: u64,
        timeout: Option<Duration>,
        remember: bool,
        cancel: &CancellationToken,
    ) -> EngineResult<Arc<engine_native_sys::Decompiled>> {
        let _slot = self.decompile_slot.lock().await;
        check(cancel)?;
        let epoch = self.epoch.load(Ordering::SeqCst);
        if let Some(d) = self
            .decompiled
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(at, epoch)
        {
            return Ok(d);
        }
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
        let d = Arc::new(r?);
        // an edit that raced the decompile may or may not be in it
        if remember && self.epoch.load(Ordering::SeqCst) == epoch {
            self.decompiled
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .put(at, epoch, d.clone());
        }
        Ok(d)
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

/// Returns freed heap pages to the system (glibc keeps them, one arena per thread, otherwise).
fn release_free_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim only releases memory the allocator already considers free.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// Loads, discovers and prepares a program (blocking).
fn build_program(
    path: &Path,
    spec: &LoaderSpec,
    config: &NativeConfig,
    token: &CancellationToken,
    progress: Option<&(dyn Fn(usize, usize) + Sync)>,
) -> EngineResult<Program> {
    let data = std::fs::read(path).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read {}: {e}", path.display()),
        )
    })?;
    let mut loaded = load(&data, spec.base.map(|b| b.0))?;
    if !config.use_symbols {
        // a stripped binary has neither
        loaded.debug = crate::dwarf::Debug::default();
        loaded.code_symbols.clear();
    }
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
    // the switch analysis dominates opening a big binary; the state directory keeps its answers
    let sha256 = hex_bytes(&Sha256::digest(&data));
    let cache = config
        .state_dir
        .as_deref()
        .map_or_else(Default::default, |d| {
            crate::jumpcache::load(d, &sha256, config.use_symbols)
        });
    let Some(mut found) = discover(
        &loaded,
        &mut session,
        token,
        crate::discover::Options {
            cache,
            progress,
            threads: config
                .discovery_threads
                .unwrap_or_else(crate::discover::default_threads),
            ..crate::discover::Options::new(config.use_symbols)
        },
    )
    .map_err(native)?
    else {
        return Err(cancelled());
    };
    // the sessions of the other threads are gone; give their memory back
    release_free_memory();
    if let Some(dir) = config.state_dir.as_deref()
        && found.recovered > 0
    {
        crate::jumpcache::save(dir, &sha256, config.use_symbols, &found.jumps);
    }
    // names as Ghidra shows them: from DWARF, else demangled; the symbol-table names stay as
    // labels and as the mangled name
    let raw_names: BTreeMap<u64, String> = found
        .functions
        .values()
        .map(|f| (f.entry, f.name.clone()))
        .collect();
    let mut mangled_names: BTreeMap<u64, String> = BTreeMap::new();
    let mut symbol_labels: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for f in found.functions.values_mut() {
        let raw = f.name.clone();
        f.name = crate::symbols::default_name(&loaded, f.entry, &raw);
        let linkage = loaded
            .debug
            .functions
            .get(&f.entry)
            .and_then(|d| d.linkage.clone())
            .filter(|l| crate::demangle::is_mangled(l));
        if let Some(m) = crate::demangle::mangled(&raw).or(linkage) {
            mangled_names.insert(f.entry, m);
        }
        let others: Vec<String> = loaded
            .code_symbols
            .get(&f.entry)
            .into_iter()
            .flatten()
            .filter(|n| **n != f.name)
            .cloned()
            .collect();
        if !others.is_empty() {
            symbol_labels.insert(f.entry, others);
        }
    }
    for f in found.functions.values() {
        session.add_function(f.entry, &f.name).map_err(native)?;
        if f.noreturn {
            // a renamed symbol is a new decompiler function
            session.set_noreturn(f.entry, true).map_err(native)?;
        }
    }

    // the functions PE imports stand for (IAT slots point at them), so calls through the slots
    // name and type their callee
    for (at, name) in &loaded.externals {
        session.add_function(*at, name).map_err(native)?;
    }

    // types: the base typedefs, then the prototypes of known library functions present here
    // (by their symbol-table names; x86 PE names also without their decoration, `_printf`)
    let model = loaded.data_model();
    let mut by_name: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (entry, name) in raw_names.iter().chain(&loaded.externals) {
        by_name.entry(name.clone()).or_default().push(*entry);
        if loaded.is_pe()
            && model.pointer == 4
            && let Some(c) = crate::pe::undecorate(name)
        {
            by_name.entry(c).or_default().push(*entry);
        }
    }
    let named = |n: &str| by_name.get(n).cloned().unwrap_or_default();
    let mut types = TypeModel::new(model);
    let mut signatures = BTreeMap::new();
    let mut base = base_definitions_in(model);
    if loaded.is_pe() {
        // Windows' wchar_t is UTF-16
        for d in &mut base {
            if let TypeDef::Typedef(t) = d
                && t.name == "wchar_t"
            {
                t.target = TypeRef::Primitive(kraken_proto::Primitive {
                    class: kraken_proto::PrimitiveClass::Char,
                    size: 2,
                    signed: true,
                });
            }
        }
        base.extend(crate::win32::base_definitions(model));
    }
    for d in base {
        types.define(d, &mut session, &named)?;
    }
    let mut noreturn: BTreeSet<u64> = found
        .functions
        .values()
        .filter(|f| f.noreturn)
        .map(|f| f.entry)
        .collect();
    let mut library_conventions: Vec<(u64, String)> = Vec::new();
    let tables: &[&[&str]] = if loaded.is_pe() {
        &[crate::libc::PROTOTYPES, crate::win32::PROTOTYPES]
    } else {
        &[crate::libc::PROTOTYPES]
    };
    for src in tables.iter().flat_map(|t| t.iter()) {
        let (name, mut proto) =
            parse_prototype_in(src, model).map_err(|e| ProtoError::new(ErrorCode::Internal, e))?;
        if !by_name.contains_key(name.as_str()) {
            continue;
        }
        // the parameter names of the C library headers, as Ghidra shows them (`__format`);
        // the Windows tables carry the Windows headers' names
        if !loaded.is_pe() {
            for param in &mut proto.params {
                if let Some(n) = param.name.as_mut().filter(|n| !n.starts_with("__")) {
                    n.insert_str(0, "__");
                }
            }
        } else if let Some((_, names)) = crate::win32::CRT_PARAMETER_NAMES
            .iter()
            .find(|(n, p)| *n == name && p.len() == proto.params.len())
        {
            for (param, n) in proto.params.iter_mut().zip(names.iter()) {
                param.name = Some((*n).to_string());
            }
        }
        // one convention on x86-64 Windows
        if model.pointer == 8 {
            proto.calling_convention.clear();
        } else if loaded.is_pe() && proto.calling_convention.is_empty() {
            // the 32-bit Windows default is `__stdcall` with the stack purge left open; the C
            // runtime's functions are `__cdecl`
            proto.calling_convention = "__cdecl".into();
        }
        if proto.noreturn {
            noreturn.extend(named(&name));
        }
        let convention = proto.calling_convention.clone();
        for (at, text) in types.define(TypeDef::Function(proto), &mut session, &named)? {
            if !convention.is_empty() {
                library_conventions.push((at, convention.clone()));
            }
            signatures.insert(at, text);
        }
    }
    drop(by_name);
    // conventions from decorations, and the library's, kept for rebuilt decompiler functions
    for (at, c) in library_conventions {
        loaded.conventions.entry(at).or_insert(c);
    }
    for (at, c) in &loaded.conventions {
        // a convention the compiler spec does not have leaves the default
        let _ = session.set_convention(*at, c);
    }
    // the listed signatures are the functions', not the stand-ins' of imports
    for at in loaded.externals.keys() {
        signatures.remove(at);
        noreturn.remove(at);
    }
    let mut locked = signatures.clone();

    // DWARF: its named types, then the prototypes of the functions it describes
    for def in loaded.debug.types.iter().cloned() {
        if kraken_engine::type_def_name(&def).is_some_and(crate::typestore::is_core) {
            continue;
        }
        // a definition the decompiler refuses leaves the type out
        let _ = types.define(def, &mut session, &|_| Vec::new());
    }
    // listed signatures show the type names as Ghidra does
    let display = &loaded.debug.display;
    let by_display: BTreeMap<&str, &str> = display
        .iter()
        .map(|(c, g)| (g.as_str(), c.as_str()))
        .collect();
    for (at, d) in &loaded.debug.functions {
        let Some(f) = found.functions.get(at) else {
            continue;
        };
        let known = |n: &str| types.knows(by_display.get(n).copied().unwrap_or(n));
        let shown = crate::typestore::renamed_proto(&d.prototype, &|n| {
            display.get(n).cloned().unwrap_or_else(|| n.to_string())
        });
        let decl = types.prototype_text(&d.prototype, PROTO_NAME);
        if session.set_prototype(*at, &decl).is_err() {
            continue;
        }
        if d.prototype.noreturn {
            session.set_noreturn(*at, true).map_err(native)?;
            noreturn.insert(*at);
        }
        signatures.insert(*at, signature(&shown, &f.name, &known));
        locked.insert(*at, decl);
    }

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
    let imports = crate::symbols::imports(&loaded);
    let info = ProgramInfo {
        arch: loaded.language.id.to_string(),
        format: loaded.format.into(),
        base: Hex64(loaded.base),
        sha256,
        size: data.len() as u64,
    };
    let stop = session.stop_flag();
    let p = Program {
        info,
        loaded,
        discovered: funcs.clone(),
        funcs: RwLock::new(funcs),
        edits: Mutex::new(Edits::default()),
        locked: Mutex::new(locked),
        insns: Mutex::new(found.insns),
        orphans,
        session: Mutex::new(session),
        stop,
        decompile_slot: tokio::sync::Mutex::new(()),
        refs: RwLock::new(Arc::new(RefIndex::default())),
        imports,
        exports: RwLock::new(Arc::new(Vec::new())),
        symbol_labels,
        mangled: mangled_names,
        strings: Mutex::new(BTreeMap::new()),
        types: Mutex::new(types),
        signatures: Mutex::new(signatures),
        noreturn: RwLock::new(Arc::new(noreturn.clone())),
        found_noreturn: noreturn,
        discovery_rounds: found.rounds,
        replay_failed: AtomicUsize::new(0),
        decompiled: Mutex::new(DecompileCache::default()),
        epoch: AtomicU64::new(0),
    };
    p.reindex();
    Ok(p)
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
            noreturn: p.noreturn().iter().copied().collect(),
            discovery_rounds: p.discovery_rounds,
            references: p.refs().len(),
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
        self.open_reporting(path, spec, cancel, None).await
    }
}

/// Called while a program opens with the number of functions found and the number still to walk.
pub(crate) type OpenReport = Arc<dyn Fn(usize, usize) + Send + Sync>;

impl InProcessEngine {
    /// [`Loader::open_binary`] that reports how discovery is getting on, which can take many
    /// minutes on a big binary the first time.
    pub(crate) async fn open_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: Option<OpenReport>,
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
            let progress = report
                .as_deref()
                .map(|f| f as &(dyn Fn(usize, usize) + Sync));
            let p = build_program(&path, &spec, &config, &token, progress)?;
            if let Some(dir) = &config.state_dir {
                let saved = read_state(dir, &p.info.sha256);
                p.signatures().extend(saved.signatures);
                let replayed = !saved.entries.is_empty();
                for entry in saved.entries {
                    let ok = match entry {
                        // one rebuild of the references at the end instead of one per edit
                        Journaled::Op(op) => crate::mutate::apply_deferred(&p, &op).is_ok(),
                        Journaled::TypeDef(def) => crate::data::define(&p, def).is_ok(),
                    };
                    if !ok {
                        p.replay_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                if replayed {
                    p.reindex();
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
            .decompile(at, self.config.decompile_timeout, true, cancel)
            .await?;
        check(cancel)?;
        Ok(DecompileResult {
            function: Locator::ram(at),
            language: LANGUAGE_C.to_string(),
            text: d.text.clone(),
            tokens: d
                .tokens
                .iter()
                .map(|t| Token {
                    start: t.start,
                    end: t.end,
                    kind: token_kind(t.kind),
                    target: t.target.map(Locator::ram),
                    symbol: t.symbol.clone(),
                    varnode: t.varnode.clone(),
                })
                .collect(),
            warnings: d.warnings.clone(),
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

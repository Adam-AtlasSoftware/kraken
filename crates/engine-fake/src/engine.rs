//! The fake engine.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{
    AnalysisJob, AnalysisSummary, AnalyzeRequest, Analyzer, Assembler, CancellationToken, Cap,
    Decompiler, DisasmRequest, Disassembler, Engine, EngineCaps, EngineRejected, EngineResult,
    FlowGraph, FunctionLister, Loader, LoaderSpec, MemoryReader, Mutator, OpenReporter,
    ProgramInfo, Progress, Stage, StringLister, StringsRequest, SymbolLister, TypeStore, Watermark,
    XrefProvider, XrefRequest, type_def_name,
};
use kraken_proto::{
    BytesRead, Cfg, DecompileResult, DisasmRow, ErrorCode, FunctionSummary, Locator, LogOp,
    MemoryBlock, OpenStage, OpenUpdate, OperandKind, Page, PageRequest, ProtoError, StringEntry,
    SymbolEntry, TypeDef, VersionedLogOp, Xref,
};

use crate::data::DataView;
use crate::fixture::{FixtureFile, FixtureFunction, Perturb, key_of, stub_decompile};
use crate::text::{rename_in_result, replace_word};

const STEPS_PER_STAGE: u64 = 3;
const DEFAULT_STAGE_DELAY: Duration = Duration::from_millis(2);

type FnKey = (String, u64);

#[derive(Debug)]
struct State {
    program: ProgramInfo,
    functions: BTreeMap<FnKey, FixtureFunction>,
    types: BTreeMap<String, TypeDef>,
    applied: Vec<VersionedLogOp>,
    saved: usize,
    memory: Option<Vec<MemoryBlock>>,
    strings: Option<Vec<StringEntry>>,
    imports: Option<Vec<SymbolEntry>>,
    exports: Option<Vec<SymbolEntry>>,
}

/// An in-memory engine serving a [`FixtureFile`]. See the crate docs for semantics.
#[derive(Debug)]
pub struct FakeEngine {
    state: Mutex<State>,
    ghidra_version: String,
    caps: BTreeSet<Cap>,
    stage_delay: Duration,
    open_delay: Duration,
    open_functions: Option<u64>,
    state_dir: Option<PathBuf>,
}

/// File in the state directory that holds the saved ops of an engine with one.
pub const FAKE_STATE_FILE: &str = "fake-state.json";

fn cancelled() -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, "operation cancelled")
}

fn check(cancel: &CancellationToken) -> EngineResult<()> {
    if cancel.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

fn not_found(what: impl std::fmt::Display) -> EngineRejected {
    EngineRejected::new(ErrorCode::NotFound, format!("{what} not found"))
}

fn fn_key(l: &Locator) -> EngineResult<FnKey> {
    match l {
        Locator::Native { .. } | Locator::Managed { .. } => Ok(key_of(l)),
        _ => Err(ProtoError::new(
            ErrorCode::Unsupported,
            "unsupported locator kind",
        )),
    }
}

impl FakeEngine {
    /// An engine with every capability serving `fixture`.
    pub fn new(fixture: FixtureFile) -> Self {
        let functions = fixture
            .functions
            .into_iter()
            .map(|f| (key_of(&f.summary.locator), f))
            .collect();
        let types = fixture
            .types
            .into_iter()
            .filter_map(|t| type_def_name(&t).map(|n| (n.to_string(), t.clone())))
            .collect();
        FakeEngine {
            state: Mutex::new(State {
                program: fixture.program,
                functions,
                types,
                applied: Vec::new(),
                saved: 0,
                memory: fixture.memory,
                strings: fixture.strings,
                imports: fixture.imports,
                exports: fixture.exports,
            }),
            ghidra_version: fixture.ghidra_version,
            caps: Cap::ALL.into_iter().collect(),
            stage_delay: DEFAULT_STAGE_DELAY,
            open_delay: Duration::ZERO,
            open_functions: None,
            state_dir: None,
        }
    }

    /// Parses `json` as a [`FixtureFile`] and serves it.
    pub fn from_json(json: &str) -> EngineResult<Self> {
        Ok(Self::new(FixtureFile::from_json(json)?))
    }

    /// Serves the fixture after applying `perturb` (decision 49).
    pub fn perturbed(fixture: FixtureFile, perturb: Perturb) -> Self {
        Self::new(perturb.apply(&fixture))
    }

    /// Removes a capability: the accessor returns `None` and the handshake omits it.
    pub fn without(mut self, cap: Cap) -> Self {
        self.caps.remove(&cap);
        self
    }

    /// Sets the sleep per analysis step (three steps per stage); zero makes analysis instant.
    pub fn with_stage_delay(mut self, delay: Duration) -> Self {
        self.stage_delay = delay;
        self
    }

    /// Makes a reported open take `delay`, spread over the scripted steps of finding functions
    /// (for progress displays and cancelling an open); zero by default.
    pub fn with_open_delay(mut self, delay: Duration) -> Self {
        self.open_delay = delay;
        self
    }

    /// Makes the scripted function search of a reported open count to `n` functions instead
    /// of the fixture's (screenshots of a big program opening).
    pub fn with_open_functions(mut self, n: u64) -> Self {
        self.open_functions = Some(n);
        self
    }

    /// Keeps the applied ops in `dir` like a real engine keeps its state: `save` writes them to
    /// [`FAKE_STATE_FILE`] and opening a binary applies the saved ones again. The checkpoint then
    /// names the ops (their count and a hash), and [`Mutator::current_checkpoint`] reports it.
    pub fn with_state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Log ops applied so far, in order.
    pub fn applied_ops(&self) -> Vec<VersionedLogOp> {
        self.lock().applied.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has(&self, cap: Cap) -> bool {
        self.caps.contains(&cap)
    }
}

impl Engine for FakeEngine {
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            format!("engine-fake (fixture ghidra {})", self.ghidra_version),
            self.caps.iter().copied(),
        )
    }
    fn loader(&self) -> Option<&dyn Loader> {
        self.has(Cap::Loader).then_some(self as &dyn Loader)
    }
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        self.has(Cap::Analyzer).then_some(self as &dyn Analyzer)
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        self.has(Cap::Decompiler).then_some(self as &dyn Decompiler)
    }
    fn type_store(&self) -> Option<&dyn TypeStore> {
        self.has(Cap::TypeStore).then_some(self as &dyn TypeStore)
    }
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        self.has(Cap::FunctionLister)
            .then_some(self as &dyn FunctionLister)
    }
    fn mutator(&self) -> Option<&dyn Mutator> {
        self.has(Cap::Mutator).then_some(self as &dyn Mutator)
    }
    fn memory_reader(&self) -> Option<&dyn MemoryReader> {
        self.has(Cap::Memory).then_some(self as &dyn MemoryReader)
    }
    fn disassembler(&self) -> Option<&dyn Disassembler> {
        self.has(Cap::Disassembler)
            .then_some(self as &dyn Disassembler)
    }
    fn xref_provider(&self) -> Option<&dyn XrefProvider> {
        self.has(Cap::Xrefs).then_some(self as &dyn XrefProvider)
    }
    fn flow_graph(&self) -> Option<&dyn FlowGraph> {
        self.has(Cap::Cfg).then_some(self as &dyn FlowGraph)
    }
    fn string_lister(&self) -> Option<&dyn StringLister> {
        self.has(Cap::Strings).then_some(self as &dyn StringLister)
    }
    fn symbol_lister(&self) -> Option<&dyn SymbolLister> {
        self.has(Cap::Symbols).then_some(self as &dyn SymbolLister)
    }
    fn assembler(&self) -> Option<&dyn Assembler> {
        self.has(Cap::Assembler).then_some(self as &dyn Assembler)
    }
}

/// A few x86 instructions, enough to exercise the patch dialog in tests and the demo. A real
/// engine runs its processor's assembler.
fn fake_assemble(text: &str) -> Option<Vec<Vec<u8>>> {
    let t = text.trim().to_ascii_lowercase();
    let t: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
    let one = |b: &[u8]| Some(vec![b.to_vec()]);
    match t.as_str() {
        "nop" => one(&[0x90]),
        "ret" => one(&[0xc3]),
        "int3" => one(&[0xcc]),
        "xor eax, eax" | "xor eax,eax" => Some(vec![vec![0x31, 0xc0], vec![0x33, 0xc0]]),
        _ => {
            let imm = t
                .strip_prefix("mov eax, ")
                .or_else(|| t.strip_prefix("mov eax,"))?
                .trim();
            let v = match imm.strip_prefix("0x") {
                Some(h) => u32::from_str_radix(h, 16).ok()?,
                None => imm.parse::<u32>().ok()?,
            };
            let mut b = vec![0xb8];
            b.extend_from_slice(&v.to_le_bytes());
            one(&b)
        }
    }
}

#[async_trait]
impl Assembler for FakeEngine {
    async fn assemble(
        &self,
        _at: &Locator,
        text: &str,
        _cancel: &CancellationToken,
    ) -> EngineResult<Vec<Vec<u8>>> {
        fake_assemble(text).ok_or_else(|| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "`{}` is not an instruction the fake engine knows",
                    text.trim()
                ),
            )
        })
    }
}

#[async_trait]
impl Loader for FakeEngine {
    async fn open_binary(
        &self,
        _path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
    ) -> EngineResult<ProgramInfo> {
        check(cancel)?;
        let mut info = self.lock().program.clone();
        if let Some(f) = &spec.format
            && *f != info.format
            && !spec.is_raw()
        {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("format {f} is not supported"),
            ));
        }
        if let Some(a) = &spec.arch {
            info.arch = a.clone();
        }
        if let Some(b) = spec.base {
            info.base = b;
        }
        if let Some(dir) = &self.state_dir {
            let saved = read_saved(dir)?;
            let mut st = self.lock();
            st.applied.clear();
            for op in saved {
                // like a real engine, an op that no longer applies is dropped from the state
                if st.apply_op(&op.op).is_ok() {
                    st.applied.push(op);
                }
            }
            st.saved = st.applied.len();
        }
        Ok(info)
    }

    async fn open_binary_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: OpenReporter,
    ) -> EngineResult<ProgramInfo> {
        check(cancel)?;
        report(OpenUpdate::stage(OpenStage::ReadFile, "Reading the file"));
        report(OpenUpdate::stage(
            OpenStage::Symbols,
            "Loading symbols and debug info",
        ));
        let (total, code) = {
            let st = self.lock();
            (
                self.open_functions.unwrap_or(st.functions.len() as u64),
                st.program.size.max(1),
            )
        };
        let step = self.open_delay / OPEN_STEPS as u32;
        for i in 0..=OPEN_STEPS {
            let found = total * i / OPEN_STEPS;
            report(OpenUpdate {
                stage_fraction: Some(i as f64 / OPEN_STEPS as f64),
                found: Some(found),
                queued: Some(total - found),
                covered_bytes: Some(code * i / OPEN_STEPS),
                code_bytes: Some(code),
                ..OpenUpdate::stage(
                    OpenStage::Functions,
                    format!("{found} functions found, {} to look at", total - found),
                )
            });
            if i < OPEN_STEPS && !step.is_zero() {
                tokio::select! {
                    () = tokio::time::sleep(step) => {}
                    () = cancel.cancelled() => return Err(cancelled()),
                }
            }
        }
        report(OpenUpdate::stage(OpenStage::Types, "Types and signatures"));
        self.open_binary(path, spec, cancel).await
    }
}

/// Steps of the scripted function search of a reported open.
const OPEN_STEPS: u64 = 10;

#[async_trait]
impl Analyzer for FakeEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        check(&cancel)?;
        let count = self.lock().functions.len() as u64;
        let delay = self.stage_delay;
        Ok(AnalysisJob::spawn(cancel, move |tx, cancel| async move {
            let mut done = Vec::new();
            for stage in Stage::ALL {
                if req.resume_from.is_some_and(|r| stage < r) {
                    continue;
                }
                for step in 1..=STEPS_PER_STAGE {
                    tokio::select! {
                        biased;
                        () = cancel.cancelled() => return Err(cancelled()),
                        () = tokio::time::sleep(delay) => {}
                    }
                    tx.send(Progress {
                        stage,
                        done: step,
                        total: STEPS_PER_STAGE,
                        message: format!("{} pass {step}/{STEPS_PER_STAGE}", stage.as_str()),
                        step: None,
                    });
                }
                done.push(stage);
            }
            Ok(AnalysisSummary {
                stages_completed: done,
                function_count: count,
            })
        }))
    }
}

#[async_trait]
impl Decompiler for FakeEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        check(cancel)?;
        let key = fn_key(locator)?;
        self.lock()
            .functions
            .get(&key)
            .map(|f| f.decompile.clone())
            .ok_or_else(|| ProtoError::from(not_found(format!("function at {key:?}"))))
    }
}

#[async_trait]
impl TypeStore for FakeEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        check(cancel)?;
        self.lock()
            .types
            .get(name)
            .cloned()
            .ok_or_else(|| not_found(format!("type {name}")).into())
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        let Some(name) = type_def_name(&def).map(str::to_string) else {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "anonymous types cannot be defined",
            ));
        };
        if name.is_empty() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "empty type name",
            ));
        }
        self.lock().types.insert(name, def);
        Ok(())
    }

    async fn remove_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        self.lock()
            .types
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| not_found(format!("type {name}")).into())
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        check(cancel)?;
        let after =
            match &page.cursor {
                None => None,
                Some(c) => Some(c.strip_prefix("t:").map(str::to_string).ok_or_else(|| {
                    ProtoError::new(ErrorCode::InvalidArgument, "malformed cursor")
                })?),
            };
        let limit = page.effective_limit() as usize;
        let st = self.lock();
        let lower = after.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut it = st.types.range::<str, _>((lower, Bound::Unbounded));
        let items: Vec<(&String, &TypeDef)> = it.by_ref().take(limit).collect();
        let more = it.next().is_some();
        let next_cursor = more
            .then(|| items.last().map(|(k, _)| format!("t:{k}")))
            .flatten();
        Ok(Page {
            items: items.into_iter().map(|(_, v)| v.clone()).collect(),
            next_cursor,
            total: Some(st.types.len() as u64),
        })
    }
}

fn parse_cursor(c: &str) -> EngineResult<FnKey> {
    let bad = || ProtoError::new(ErrorCode::InvalidArgument, "malformed cursor");
    let (space, off) = c.rsplit_once(':').ok_or_else(bad)?;
    let off = u64::from_str_radix(off, 16).map_err(|_| bad())?;
    Ok((space.to_string(), off))
}

#[async_trait]
impl FunctionLister for FakeEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        check(cancel)?;
        let after = page.cursor.as_deref().map(parse_cursor).transpose()?;
        let limit = page.effective_limit() as usize;
        let st = self.lock();
        let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut it = st.functions.range((lower, Bound::Unbounded));
        let items: Vec<(&FnKey, &FixtureFunction)> = it.by_ref().take(limit).collect();
        let more = it.next().is_some();
        let next_cursor = more
            .then(|| items.last().map(|(k, _)| format!("{}:{:x}", k.0, k.1)))
            .flatten();
        Ok(Page {
            items: items.into_iter().map(|(_, f)| f.summary.clone()).collect(),
            next_cursor,
            total: Some(st.functions.len() as u64),
        })
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        check(cancel)?;
        let key = fn_key(locator)?;
        self.lock()
            .functions
            .get(&key)
            .map(|f| f.summary.clone())
            .ok_or_else(|| ProtoError::from(not_found(format!("function at {key:?}"))))
    }
}

impl State {
    fn view(&self) -> DataView<'_> {
        DataView {
            functions: &self.functions,
            base: self.program.base.0,
            memory: self.memory.as_deref(),
            strings: self.strings.as_deref(),
            imports: self.imports.as_deref(),
            exports: self.exports.as_deref(),
        }
    }
}

#[async_trait]
impl MemoryReader for FakeEngine {
    async fn memory_map(&self, cancel: &CancellationToken) -> EngineResult<Vec<MemoryBlock>> {
        check(cancel)?;
        Ok(self.lock().view().memory_map())
    }

    async fn read_bytes(
        &self,
        start: &Locator,
        length: u32,
        cancel: &CancellationToken,
    ) -> EngineResult<BytesRead> {
        check(cancel)?;
        self.lock().view().read_bytes(start, length)
    }
}

#[async_trait]
impl Disassembler for FakeEngine {
    async fn disassemble(
        &self,
        req: &DisasmRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<DisasmRow>> {
        check(cancel)?;
        self.lock().view().disassemble(req, page)
    }
}

#[async_trait]
impl XrefProvider for FakeEngine {
    async fn xrefs(
        &self,
        req: &XrefRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<Xref>> {
        check(cancel)?;
        self.lock().view().xrefs(req, page)
    }
}

#[async_trait]
impl FlowGraph for FakeEngine {
    async fn cfg(&self, function: &Locator, cancel: &CancellationToken) -> EngineResult<Cfg> {
        check(cancel)?;
        self.lock().view().cfg(function)
    }
}

#[async_trait]
impl StringLister for FakeEngine {
    async fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<StringEntry>> {
        check(cancel)?;
        self.lock().view().strings(req, page)
    }
}

#[async_trait]
impl SymbolLister for FakeEngine {
    async fn imports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check(cancel)?;
        self.lock().view().imports(page)
    }

    async fn exports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check(cancel)?;
        self.lock().view().exports(page)
    }
}

/// Follows a function rename through recorded listing data: labels, symbol operands and the
/// function names in references.
fn rename_in_listing(functions: &mut BTreeMap<FnKey, FixtureFunction>, old: &str, new: &str) {
    for f in functions.values_mut() {
        for row in f.disassembly.iter_mut().flatten() {
            for l in &mut row.labels {
                if l == old {
                    *l = new.to_string();
                }
            }
            for op in &mut row.operands {
                if op.kind == OperandKind::Symbol && op.text == old {
                    op.text = new.to_string();
                }
            }
        }
        for x in f.xrefs.iter_mut().flatten() {
            for r in [&mut x.from_function, &mut x.to_function]
                .into_iter()
                .flatten()
            {
                if r.name == old {
                    r.name = new.to_string();
                }
            }
        }
    }
}

fn anchor_of(op: &LogOp) -> Option<&kraken_proto::Anchor> {
    Some(match op {
        LogOp::Rename { anchor, .. }
        | LogOp::SetType { anchor, .. }
        | LogOp::SetComment { anchor, .. }
        | LogOp::CreateFunction { anchor, .. }
        | LogOp::DeleteFunction { anchor, .. }
        | LogOp::SetFunctionBounds { anchor, .. }
        | LogOp::SetCodeData { anchor, .. }
        | LogOp::SetCallingConvention { anchor, .. }
        | LogOp::SetLocal { anchor, .. }
        | LogOp::SetPatch { anchor, .. } => anchor,
        LogOp::DefineType { .. } => return None,
    })
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && !n.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn check_hash(f: &FixtureFunction, anchor_hash: &str) -> Result<(), EngineRejected> {
    match &f.summary.fn_hash {
        Some(h) if !anchor_hash.is_empty() && h != anchor_hash => Err(EngineRejected::new(
            ErrorCode::ConflictStaleRead,
            format!("function hash is {h}, anchor has {anchor_hash}"),
        )),
        _ => Ok(()),
    }
}

impl State {
    /// Renames and comments on managed anchors (`<module>:<0xtoken>`) for fixtures of methods
    /// with managed locators; anything else on a managed anchor is unsupported.
    fn apply_managed_op(
        &mut self,
        op: &LogOp,
        module: &str,
        token: u32,
    ) -> Result<(), EngineRejected> {
        let f = self
            .functions
            .get_mut(&(format!("managed:{module}"), u64::from(token)))
            .ok_or_else(|| not_found(format!("method {token:#x} of module {module}")))?;
        match op {
            LogOp::Rename {
                old_name, new_name, ..
            } => {
                if !valid_name(new_name) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "invalid function name",
                    ));
                }
                let current = f.summary.name.clone();
                if &current == new_name {
                    return Ok(());
                }
                if old_name.as_ref().is_some_and(|o| *o != current) {
                    return Err(EngineRejected::new(
                        ErrorCode::ConflictStaleRead,
                        format!("method is named {current}"),
                    ));
                }
                rename_in_result(&mut f.decompile, &current, new_name);
                f.summary.signature = f
                    .summary
                    .signature
                    .as_ref()
                    .map(|s| replace_word(s, &current, new_name));
                f.summary.name = new_name.clone();
                rename_in_listing(&mut self.functions, &current, new_name);
                Ok(())
            }
            LogOp::SetComment { .. } => Ok(()),
            _ => Err(EngineRejected::new(
                ErrorCode::Unsupported,
                "the fake takes renames and comments on managed anchors only",
            )),
        }
    }

    fn apply_op(&mut self, op: &LogOp) -> Result<(), EngineRejected> {
        if let Some((module, token)) = anchor_of(op).and_then(|a| a.managed_parts()) {
            return self.apply_managed_op(op, module, token);
        }
        match op {
            LogOp::Rename {
                anchor,
                old_name,
                new_name,
            } => {
                let (space, offset, entry, hash) = anchor.native()?;
                if offset != entry {
                    return Err(EngineRejected::new(
                        ErrorCode::Unsupported,
                        "the fake only renames functions",
                    ));
                }
                let f = self
                    .functions
                    .get_mut(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                if !valid_name(new_name) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "invalid function name",
                    ));
                }
                let current = f.summary.name.clone();
                if &current == new_name {
                    return Ok(());
                }
                if old_name.as_ref().is_some_and(|o| *o != current) {
                    return Err(EngineRejected::new(
                        ErrorCode::ConflictStaleRead,
                        format!("function is named {current}"),
                    ));
                }
                rename_in_result(&mut f.decompile, &current, new_name);
                f.summary.signature = f
                    .summary
                    .signature
                    .as_ref()
                    .map(|s| replace_word(s, &current, new_name));
                f.summary.name = new_name.clone();
                rename_in_listing(&mut self.functions, &current, new_name);
                Ok(())
            }
            LogOp::CreateFunction { anchor, name, body } => {
                let (space, _, entry, hash) = anchor.native()?;
                let key = (space.to_string(), entry.0);
                let name = name
                    .clone()
                    .unwrap_or_else(|| format!("FUN_{:08x}", entry.0));
                if !valid_name(&name) {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "invalid function name",
                    ));
                }
                if let Some(existing) = self.functions.get(&key) {
                    let same = existing.summary.name == name
                        && existing.summary.fn_hash.as_deref().unwrap_or("") == hash;
                    return if same {
                        Ok(())
                    } else {
                        Err(EngineRejected::rejected(format!(
                            "a function already exists at {space}:{entry}"
                        )))
                    };
                }
                let locator = Locator::Native {
                    space: space.to_string(),
                    offset: entry,
                };
                let mut decompile = stub_decompile(&locator, &name);
                decompile.function = locator.clone();
                let summary = FunctionSummary {
                    locator,
                    name: name.clone(),
                    size: body.as_ref().map(|b| b.end.0.saturating_sub(b.start.0)),
                    signature: Some(format!("void {name}(void)")),
                    fn_hash: (!hash.is_empty()).then(|| hash.to_string()),
                    completeness: kraken_proto::Completeness::Complete,
                    mangled: None,
                };
                self.functions
                    .insert(key, FixtureFunction::new(summary, decompile));
                Ok(())
            }
            LogOp::DeleteFunction { anchor, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let key = (space.to_string(), entry.0);
                let f = self
                    .functions
                    .get(&key)
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                self.functions.remove(&key);
                Ok(())
            }
            LogOp::SetFunctionBounds { anchor, new, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let f = self
                    .functions
                    .get_mut(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)?;
                if new.start != entry || new.end < new.start {
                    return Err(EngineRejected::new(
                        ErrorCode::InvalidArgument,
                        "bounds must start at the function entry",
                    ));
                }
                f.summary.size = Some(new.end.0 - new.start.0);
                // recorded listing data no longer matches the body
                f.disassembly = None;
                f.cfg = None;
                f.xrefs = None;
                Ok(())
            }
            LogOp::SetType { anchor, .. }
            | LogOp::SetComment { anchor, .. }
            | LogOp::SetCodeData { anchor, .. }
            | LogOp::SetLocal { anchor, .. }
            | LogOp::SetCallingConvention { anchor, .. } => {
                let (space, _, entry, hash) = anchor.native()?;
                let f = self
                    .functions
                    .get(&(space.to_string(), entry.0))
                    .ok_or_else(|| not_found(format!("function at {space}:{entry}")))?;
                check_hash(f, hash)
            }
            LogOp::DefineType { name, new, .. } => match new {
                Some(def) => {
                    if type_def_name(def) != Some(name.as_str()) {
                        return Err(EngineRejected::new(
                            ErrorCode::InvalidArgument,
                            "the definition's name differs from the op's",
                        ));
                    }
                    self.types.insert(name.clone(), def.clone());
                    Ok(())
                }
                None => {
                    self.types.remove(name);
                    Ok(())
                }
            },
            // Patches stay in the project; the registry never pushes them.
            LogOp::SetPatch { .. } => Ok(()),
        }
    }
}

#[async_trait]
impl Mutator for FakeEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        check(cancel)?;
        op.check_version()?;
        let mut st = self.lock();
        st.apply_op(&op.op)?;
        st.applied.push(op.clone());
        Ok(())
    }

    async fn save(&self, cancel: &CancellationToken) -> EngineResult<Watermark> {
        check(cancel)?;
        let mut st = self.lock();
        st.saved = st.applied.len();
        let Some(dir) = &self.state_dir else {
            return Ok(Watermark(format!("fake-{}", st.saved)));
        };
        let json = serde_json::to_string(&st.applied)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        let path = dir.join(FAKE_STATE_FILE);
        std::fs::write(&path, json).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("cannot write {}: {e}", path.display()),
            )
        })?;
        Ok(ops_checkpoint(&st.applied))
    }

    async fn current_checkpoint(
        &self,
        cancel: &CancellationToken,
    ) -> EngineResult<Option<Watermark>> {
        check(cancel)?;
        Ok(self
            .state_dir
            .as_ref()
            .map(|_| ops_checkpoint(&self.lock().applied)))
    }
}

/// Names a list of ops: their count and an FNV-1a hash of their JSON.
fn ops_checkpoint(ops: &[VersionedLogOp]) -> Watermark {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for op in ops {
        for b in serde_json::to_vec(op).unwrap_or_default() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= u64::from(b'\n');
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    Watermark(format!("fake-{}-{h:016x}", ops.len()))
}

fn read_saved(dir: &Path) -> EngineResult<Vec<VersionedLogOp>> {
    let path = dir.join(FAKE_STATE_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("{} is damaged: {e}", path.display()),
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(ProtoError::new(
            ErrorCode::Internal,
            format!("cannot read {}: {e}", path.display()),
        )),
    }
}

//! The engine: capability traits over the loaded program, Sleigh and the decompiler.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use engine_native_sys::{Instruction, NativeError, Session, TokenKind as NativeKind};
use kraken_engine::{
    Cap, Decompiler, DisasmRequest, Disassembler, Engine, EngineCaps, EngineResult, FunctionLister,
    Loader, LoaderSpec, MemoryReader, ProgramInfo,
};
use kraken_proto::{
    AddressRange, BytesRead, Completeness, DecompileResult, DisasmRow, DisasmScope, ErrorCode,
    FunctionSummary, Hex64, LANGUAGE_C, Locator, MemoryBlock, Page, PageRequest, ProtoError, Token,
    TokenKind, hex_bytes,
};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::discover::{Func, discover};
use crate::elf::{Loaded, load};
use crate::listing::{flow_kind, operands};

/// Build id in the handshake.
pub const BUILD: &str = concat!(
    "kraken-native/",
    env!("CARGO_PKG_VERSION"),
    " ghidra-12.1.4"
);

/// Where the engine finds what it needs at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeConfig {
    /// A Ghidra install root; only its `Ghidra/Processors/*/data/languages` (`.ldefs`, `.pspec`,
    /// `.cspec`, precompiled `.sla`) are read. No JVM is started.
    pub ghidra_home: PathBuf,
    /// Seed discovery with the symbol table. Off approximates a stripped binary.
    pub use_symbols: bool,
}

impl NativeConfig {
    /// `KRAKEN_GHIDRA_HOME`, else the newest install under `~/.cache/kraken-dev/ghidra` that has
    /// the x86-64 `.sla`.
    pub fn discover() -> Option<NativeConfig> {
        let home = match std::env::var_os("KRAKEN_GHIDRA_HOME") {
            Some(p) => PathBuf::from(p),
            None => {
                let dir = PathBuf::from(std::env::var_os("HOME")?).join(".cache/kraken-dev/ghidra");
                let mut kids: Vec<PathBuf> = std::fs::read_dir(dir)
                    .ok()?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| has_specs(p))
                    .collect();
                kids.sort();
                kids.pop()?
            }
        };
        Some(NativeConfig {
            ghidra_home: home,
            use_symbols: true,
        })
    }
}

/// Whether `home` holds the x86-64 Sleigh specification.
pub fn has_specs(home: &Path) -> bool {
    home.join("Ghidra/Processors/x86/data/languages/x86-64.sla")
        .is_file()
}

struct Program {
    info: ProgramInfo,
    loaded: Loaded,
    functions: BTreeMap<u64, Func>,
    insns: Mutex<BTreeMap<u64, Instruction>>,
    session: Mutex<Session>,
}

impl Program {
    fn session(&self) -> MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn insns(&self) -> MutexGuard<'_, BTreeMap<u64, Instruction>> {
        self.insns.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn summary(&self, f: &Func) -> FunctionSummary {
        let mut h = Sha256::new();
        for (s, e) in &f.ranges {
            let mut buf = vec![0u8; (e - s) as usize];
            if self.loaded.image.read(*s, &mut buf) {
                h.update(&buf);
            }
        }
        FunctionSummary {
            locator: Locator::ram(f.entry),
            name: f.name.clone(),
            size: Some(f.size()),
            signature: None,
            fn_hash: Some(hex_bytes(&h.finalize())),
            completeness: Completeness::Complete,
        }
    }

    fn function_containing(&self, addr: u64) -> Option<&Func> {
        if let Some(f) = self.functions.get(&addr) {
            return Some(f);
        }
        self.functions.values().find(|f| f.contains(addr))
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

    fn row(&self, i: &Instruction) -> DisasmRow {
        let mut bytes = vec![0u8; i.length as usize];
        self.loaded.image.read(i.addr, &mut bytes);
        let mut labels = Vec::new();
        if let Some(f) = self.functions.get(&i.addr) {
            labels.push(f.name.clone());
        }
        DisasmRow {
            address: Hex64(i.addr),
            bytes: hex_bytes(&bytes),
            mnemonic: i.mnemonic.clone(),
            operands: operands(
                &i.body,
                |a| self.functions.get(&a).map(|f| f.name.clone()),
                |a| self.mapped(a),
            ),
            comment: None,
            labels,
            flow: flow_kind(i.flow),
        }
    }

    fn mapped(&self, addr: u64) -> bool {
        self.loaded
            .blocks
            .iter()
            .any(|b| b.start.0 <= addr && addr < b.end.0)
    }
}

/// The native engine. Create it with [`NativeEngine::new`], then open a binary through
/// [`Loader`]; the other capabilities answer `invalid_argument` until then.
pub struct NativeEngine {
    config: NativeConfig,
    program: Mutex<Option<Arc<Program>>>,
}

impl std::fmt::Debug for NativeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

fn native(e: NativeError) -> ProtoError {
    match e {
        NativeError::Unavailable(m) => ProtoError::new(ErrorCode::Unsupported, m),
        NativeError::Native(m) => ProtoError::new(ErrorCode::Internal, m),
    }
}

fn cancelled() -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, "cancelled")
}

fn check(cancel: &CancellationToken) -> EngineResult<()> {
    if cancel.is_cancelled() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

fn ram_offset(l: &Locator) -> EngineResult<u64> {
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

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> EngineResult<T> + Send + 'static,
) -> EngineResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("native worker failed: {e}")))?
}

impl NativeEngine {
    /// An engine with no program loaded.
    pub fn new(config: NativeConfig) -> NativeEngine {
        NativeEngine {
            config,
            program: Mutex::new(None),
        }
    }

    /// Whether this build has the native decompiler and `config` points at usable specs.
    pub fn is_usable(config: &NativeConfig) -> bool {
        engine_native_sys::available() && has_specs(&config.ghidra_home)
    }

    fn program(&self) -> EngineResult<Arc<Program>> {
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
}

impl Engine for NativeEngine {
    fn capabilities(&self) -> EngineCaps {
        EngineCaps::new(
            BUILD,
            [
                Cap::Loader,
                Cap::Decompiler,
                Cap::FunctionLister,
                Cap::Memory,
                Cap::Disassembler,
            ],
        )
    }
    fn loader(&self) -> Option<&dyn Loader> {
        Some(self)
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
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
}

#[async_trait]
impl Loader for NativeEngine {
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
            let data = std::fs::read(&path).map_err(|e| {
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
            engine_native_sys::start(&config.ghidra_home).map_err(native)?;
            if !engine_native_sys::has_language(loaded.language.id).map_err(native)? {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "no Sleigh specification for {} under {}",
                        loaded.language.id,
                        config.ghidra_home.display()
                    ),
                ));
            }
            let mut session = Session::new(
                loaded.language.id,
                loaded.language.compiler,
                loaded.image.clone(),
            )
            .map_err(native)?;
            let Some(found) =
                discover(&loaded, &mut session, config.use_symbols, &token).map_err(native)?
            else {
                return Err(cancelled());
            };
            for f in found.functions.values() {
                session.add_function(f.entry, &f.name).map_err(native)?;
            }
            let info = ProgramInfo {
                arch: loaded.language.id.to_string(),
                format: "elf".into(),
                base: Hex64(loaded.base),
                sha256: hex_bytes(&Sha256::digest(&data)),
                size: data.len() as u64,
            };
            Ok(Program {
                info,
                loaded,
                functions: found.functions,
                insns: Mutex::new(found.insns),
                session: Mutex::new(session),
            })
        })
        .await?;
        check(cancel)?;
        let info = program.info.clone();
        *self.program.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(program));
        Ok(info)
    }
}

#[async_trait]
impl FunctionLister for NativeEngine {
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
        let mut it = p.functions.range(from..);
        let items: Vec<FunctionSummary> =
            it.by_ref().take(limit).map(|(_, f)| p.summary(f)).collect();
        let next_cursor = it.next().map(|(a, _)| format!("{a:#x}"));
        Ok(Page {
            items,
            next_cursor,
            total: Some(p.functions.len() as u64),
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
        p.functions
            .get(&at)
            .map(|f| p.summary(f))
            .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no function at {at:#x}")))
    }
}

#[async_trait]
impl Decompiler for NativeEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        check(cancel)?;
        let p = self.program()?;
        let at = ram_offset(locator)?;
        if !p.functions.contains_key(&at) {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no function at {at:#x}"),
            ));
        }
        // the C++ decompiler cannot be interrupted; cancellation is checked around it
        let d = blocking(move || p.session().decompile(at).map_err(native)).await?;
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
impl MemoryReader for NativeEngine {
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
impl Disassembler for NativeEngine {
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
                let f = p.function_containing(req.start.0).ok_or_else(|| {
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
                        items.push(p.row(&i));
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
                let mut items = Vec::new();
                let mut skipped = 0;
                while items.len() < limit && p.mapped(at) && skipped < 4096 {
                    match p.instruction(at)? {
                        Some(i) => {
                            at += u64::from(i.length);
                            items.push(p.row(&i));
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

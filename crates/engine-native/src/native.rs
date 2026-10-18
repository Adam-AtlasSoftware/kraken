//! [`NativeEngine`]: the capability traits over either the confined worker or an in-process
//! engine, chosen by [`NativeConfig::isolation`].

use std::path::Path;
#[cfg(unix)]
use std::sync::Arc;

use async_trait::async_trait;
use kraken_engine::{
    AnalysisJob, AnalyzeRequest, Analyzer, Decompiler, DisasmRequest, Disassembler, Engine,
    EngineCaps, EngineRejected, EngineResult, FlowGraph, FunctionLister, Loader, LoaderSpec,
    MemoryReader, Mutator, OpenReporter, ProgramInfo, StringLister, StringsRequest, SymbolLister,
    TypeStore, XrefProvider, XrefRequest,
};
use kraken_proto::{
    BytesRead, Cfg, DecompileResult, DisasmRow, FunctionSummary, Locator, MemoryBlock, Page,
    PageRequest, StringEntry, SymbolEntry, TypeDef, VersionedLogOp, Xref,
};
use kraken_sidecar::ConfinementReport;
#[cfg(unix)]
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[cfg(unix)]
use crate::engine::check;
use crate::engine::{InProcessEngine, NativeConfig, NativeStats};
use crate::worker::Isolation;
#[cfg(unix)]
use crate::worker::client::WorkerEngine;

enum Backend {
    Local(Box<InProcessEngine>),
    #[cfg(unix)]
    Worker(Arc<WorkerEngine>),
}

/// The native engine. Create it with [`NativeEngine::new`], then open a binary through
/// [`Loader`]; the other capabilities answer `invalid_argument` until then.
///
/// With [`Isolation::Worker`] (the default) the program lives in a confined
/// `kraken-native-worker` process, started when a binary is opened and restarted (re-opening the
/// binary) after it crashed or was killed by the watchdog; see [`crate::worker`]. With
/// [`Isolation::InProcess`] it lives in this process. Platforms without the sidecar spawner
/// always run in-process.
pub struct NativeEngine {
    config: NativeConfig,
    backend: Backend,
}

impl std::fmt::Debug for NativeEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

macro_rules! route {
    ($self:ident, $local:ident => $l:expr, $worker:ident => $w:expr) => {
        match &$self.backend {
            Backend::Local($local) => $l,
            #[cfg(unix)]
            Backend::Worker($worker) => $w,
        }
    };
}

impl NativeEngine {
    /// An engine with no program loaded.
    pub fn new(config: NativeConfig) -> NativeEngine {
        let backend = match &config.isolation {
            #[cfg(unix)]
            Isolation::Worker(opts) => {
                Backend::Worker(Arc::new(WorkerEngine::new(config.clone(), opts.clone())))
            }
            _ => Backend::Local(Box::new(InProcessEngine::new(config.clone()))),
        };
        NativeEngine { config, backend }
    }

    /// Whether this build has the native decompiler and `config` points at usable specs.
    pub fn is_usable(config: &NativeConfig) -> bool {
        InProcessEngine::is_usable(config)
    }

    /// Whether the program runs in a worker process.
    pub fn is_isolated(&self) -> bool {
        route!(self, _l => false, _w => true)
    }

    /// The confinement applied to the current (or last) worker; `None` in-process or before the
    /// first open.
    pub fn confinement(&self) -> Option<ConfinementReport> {
        route!(self, _l => None, w => w.confinement())
    }

    /// The current (or last) worker's process id.
    pub fn worker_pid(&self) -> Option<u32> {
        route!(self, _l => None, w => w.pid())
    }

    /// How many times the worker was restarted after a crash or a watchdog kill.
    pub fn worker_restarts(&self) -> u64 {
        route!(self, _l => 0, w => w.restarts())
    }

    /// The last `n` lines the current worker wrote to stdout and stderr.
    pub async fn worker_log(&self, n: usize) -> Vec<String> {
        route!(self, _l => { let _ = n; Vec::new() }, w => w.log_tail(n).await)
    }

    /// Raw p-code of the instructions in `[start, end)` (Sleigh lifting).
    pub async fn lift(
        &self,
        start: u64,
        end: u64,
    ) -> EngineResult<Vec<engine_native_sys::PcodeOp>> {
        route!(self,
            l => l.lift(start, end),
            w => {
                let ops: Vec<crate::worker::WirePcodeOp> = w
                    .call(
                        "lift",
                        json!({ "start": start, "end": end }),
                        w.request_limits(),
                        &CancellationToken::new(),
                    )
                    .await?;
                Ok(ops.into_iter().map(Into::into).collect())
            }
        )
    }

    /// Facts about the open program that the traits do not carry (see [`NativeStats`]).
    pub async fn stats(&self) -> EngineResult<NativeStats> {
        route!(self,
            l => l.stats(),
            w => w.call("stats", json!({}), w.request_limits(), &CancellationToken::new()).await
        )
    }

    /// Calls a test-only worker method (`test_hang`, `test_crash`, `test_probe`); needs
    /// [`crate::WorkerOptions::test_hooks`].
    #[doc(hidden)]
    pub async fn worker_test_hook(
        &self,
        method: &str,
        cancel: &CancellationToken,
    ) -> EngineResult<serde_json::Value> {
        route!(self,
            _l => {
                let _ = (method, cancel);
                Err(kraken_engine::unsupported("worker test hooks in-process"))
            },
            w => w.call(method, json!({}), w.request_limits(), cancel).await
        )
    }
}

impl Engine for NativeEngine {
    fn capabilities(&self) -> EngineCaps {
        route!(self, l => l.capabilities(), _w => {
            InProcessEngine::new(self.config.clone()).capabilities()
        })
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
impl Mutator for NativeEngine {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        route!(self,
            l => l.apply(op, cancel).await,
            w => {
                check(cancel)?;
                op.check_version()?;
                Ok(w.apply(op, cancel).await?)
            }
        )
    }

    async fn save(&self, cancel: &CancellationToken) -> EngineResult<kraken_engine::Watermark> {
        route!(self,
            l => l.save(cancel).await,
            w => w.save(cancel).await
        )
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
        self.open(path, spec, cancel, None).await
    }

    async fn open_binary_reporting(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: OpenReporter,
    ) -> EngineResult<ProgramInfo> {
        self.open(path, spec, cancel, Some(report)).await
    }
}

impl NativeEngine {
    async fn open(
        &self,
        path: &Path,
        spec: &LoaderSpec,
        cancel: &CancellationToken,
        report: Option<OpenReporter>,
    ) -> EngineResult<ProgramInfo> {
        route!(self,
            l => match report {
                Some(r) => l.open_binary_reporting(path, spec, cancel, r).await,
                None => l.open_binary(path, spec, cancel).await,
            },
            w => {
                check(cancel)?;
                if let Some(f) = spec.format.as_deref()
                    && !matches!(f, "elf" | "pe" | "coff" | "ar")
                {
                    return Err(kraken_proto::ProtoError::new(
                        kraken_proto::ErrorCode::Unsupported,
                        format!("format {f:?} is not supported by the native engine"),
                    ));
                }
                // the worker may only read the binary itself, so resolve links here
                let path = std::fs::canonicalize(path).map_err(|e| {
                    kraken_proto::ProtoError::new(
                        kraken_proto::ErrorCode::NotFound,
                        format!("cannot read {}: {e}", path.display()),
                    )
                })?;
                w.open(path, spec.clone(), cancel, report.as_ref()).await
            }
        )
    }
}

#[async_trait]
impl Analyzer for NativeEngine {
    async fn analyze(
        &self,
        req: AnalyzeRequest,
        cancel: CancellationToken,
    ) -> EngineResult<AnalysisJob> {
        route!(self,
            l => l.analyze(req, cancel).await,
            w => {
                // fail now, not in the job, when nothing is open
                w.call::<NativeStats>("stats", json!({}), w.request_limits(), &cancel)
                    .await?;
                let w = w.clone();
                Ok(AnalysisJob::spawn(cancel, move |tx, token| async move {
                    w.analyze(req, tx, token).await
                }))
            }
        )
    }
}

#[async_trait]
impl FunctionLister for NativeEngine {
    async fn list_functions(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<FunctionSummary>> {
        route!(self,
            l => l.list_functions(page, cancel).await,
            w => w.call("list_functions", json!({ "page": page }), w.request_limits(), cancel).await
        )
    }

    async fn get_function(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<FunctionSummary> {
        route!(self,
            l => l.get_function(locator, cancel).await,
            w => w.call("get_function", json!({ "locator": locator }), w.request_limits(), cancel).await
        )
    }
}

#[async_trait]
impl Decompiler for NativeEngine {
    async fn decompile(
        &self,
        locator: &Locator,
        cancel: &CancellationToken,
    ) -> EngineResult<DecompileResult> {
        route!(self,
            l => l.decompile(locator, cancel).await,
            w => w.call("decompile", json!({ "locator": locator }), w.decompile_limits(), cancel).await
        )
    }
}

#[async_trait]
impl MemoryReader for NativeEngine {
    async fn memory_map(&self, cancel: &CancellationToken) -> EngineResult<Vec<MemoryBlock>> {
        route!(self,
            l => l.memory_map(cancel).await,
            w => w.call("memory_map", json!({}), w.request_limits(), cancel).await
        )
    }

    async fn read_bytes(
        &self,
        start: &Locator,
        length: u32,
        cancel: &CancellationToken,
    ) -> EngineResult<BytesRead> {
        route!(self,
            l => l.read_bytes(start, length, cancel).await,
            w => w.call(
                "read_bytes",
                json!({ "start": start, "length": length }),
                w.request_limits(),
                cancel,
            ).await
        )
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
        route!(self,
            l => l.disassemble(req, page, cancel).await,
            w => w.call(
                "disassemble",
                json!({ "req": req, "page": page }),
                w.request_limits(),
                cancel,
            ).await
        )
    }
}

#[async_trait]
impl XrefProvider for NativeEngine {
    async fn xrefs(
        &self,
        req: &XrefRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<Xref>> {
        route!(self,
            l => l.xrefs(req, page, cancel).await,
            w => w.call("xrefs", json!({ "req": req, "page": page }), w.request_limits(), cancel).await
        )
    }
}

#[async_trait]
impl FlowGraph for NativeEngine {
    async fn cfg(&self, function: &Locator, cancel: &CancellationToken) -> EngineResult<Cfg> {
        route!(self,
            l => l.cfg(function, cancel).await,
            w => w.call("cfg", json!({ "function": function }), w.request_limits(), cancel).await
        )
    }
}

#[async_trait]
impl StringLister for NativeEngine {
    async fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<StringEntry>> {
        route!(self,
            l => l.strings(req, page, cancel).await,
            w => w.call("strings", json!({ "req": req, "page": page }), w.request_limits(), cancel).await
        )
    }
}

#[async_trait]
impl SymbolLister for NativeEngine {
    async fn imports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        route!(self,
            l => l.imports(page, cancel).await,
            w => w.call("imports", json!({ "page": page }), w.request_limits(), cancel).await
        )
    }

    async fn exports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        route!(self,
            l => l.exports(page, cancel).await,
            w => w.call("exports", json!({ "page": page }), w.request_limits(), cancel).await
        )
    }
}

#[async_trait]
impl TypeStore for NativeEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        route!(self,
            l => l.get_type(name, cancel).await,
            w => w.call("get_type", json!({ "name": name }), w.request_limits(), cancel).await
        )
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        route!(self,
            l => l.define_type(def, cancel).await,
            w => w.define_type(def, cancel).await
        )
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        route!(self,
            l => l.list_types(page, cancel).await,
            w => w.call("list_types", json!({ "page": page }), w.request_limits(), cancel).await
        )
    }
}

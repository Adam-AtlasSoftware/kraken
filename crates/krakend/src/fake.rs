//! A scripted engine factory for tests (cargo feature `fake-engine`).
//!
//! [`FakeFactory`] serves a fixture through `engine-fake` and lets a test steer it through
//! [`FakeControl`]: make pushes fail the way a dying sidecar does, add latency, emit sidecar
//! lifecycle events, and observe how many pushes ran at once. The daemon selects it with the
//! hidden `--fake-engine <fixture>` flag; nothing else in a normal run touches this module.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::{
    Analyzer, CancellationToken, Decompiler, Disassembler, Engine, EngineCaps, EngineRejected,
    FlowGraph, FunctionLister, Loader, MemoryReader, Mutator, SharedEngine, StringLister,
    SymbolLister, TypeStore, Watermark, XrefProvider,
};
use kraken_host::{EngineDiagnostics, EngineEvent, FactoryEvent, ManagedFactory};
use kraken_proto::{ErrorCode, ProtoError, VersionedLogOp};
use kraken_registry::EngineFactory;
use serde_json::json;
use tokio::sync::broadcast;

/// Knobs and counters shared by a factory and the engines it creates.
pub struct FakeControl {
    /// When set, every push is refused with `cancelled`, which leaves the log entry pending (as
    /// when a sidecar dies mid-push).
    pub fail_pushes_as_cancelled: AtomicBool,
    /// Latency of every push in milliseconds.
    pub push_delay_ms: AtomicU64,
    /// How long opening a binary takes, in milliseconds (engines created afterwards).
    pub open_delay_ms: AtomicU64,
    /// Pushes running right now.
    pub pushes_in_flight: AtomicUsize,
    /// Most pushes that ever ran at the same time.
    pub max_pushes_in_flight: AtomicUsize,
    /// Pushes that reached the engine.
    pub pushes: AtomicUsize,
    /// Calls to `restart_engine`.
    pub restarts: AtomicUsize,
    /// Engines created.
    pub created: AtomicUsize,
    /// Directories passed to `shutdown_under`.
    pub closed: Mutex<Vec<PathBuf>>,
    events: broadcast::Sender<FactoryEvent>,
}

impl FakeControl {
    fn new() -> Self {
        FakeControl {
            fail_pushes_as_cancelled: AtomicBool::new(false),
            push_delay_ms: AtomicU64::new(0),
            open_delay_ms: AtomicU64::new(0),
            pushes_in_flight: AtomicUsize::new(0),
            max_pushes_in_flight: AtomicUsize::new(0),
            pushes: AtomicUsize::new(0),
            restarts: AtomicUsize::new(0),
            created: AtomicUsize::new(0),
            closed: Mutex::new(Vec::new()),
            events: broadcast::channel(64).0,
        }
    }

    /// Emits a sidecar lifecycle event for the engine of `engine_dir`.
    pub fn emit(&self, engine_dir: &Path, event: EngineEvent) {
        let _ = self.events.send(FactoryEvent {
            engine_dir: engine_dir.to_path_buf(),
            event,
        });
    }
}

struct Controlled {
    inner: Arc<FakeEngine>,
    mutator: ControlledMutator,
}

struct ControlledMutator {
    inner: Arc<FakeEngine>,
    ctl: Arc<FakeControl>,
}

#[async_trait]
impl Mutator for ControlledMutator {
    async fn apply(
        &self,
        op: &VersionedLogOp,
        cancel: &CancellationToken,
    ) -> Result<(), EngineRejected> {
        let ctl = &self.ctl;
        ctl.pushes.fetch_add(1, Ordering::SeqCst);
        if ctl.fail_pushes_as_cancelled.load(Ordering::SeqCst) {
            return Err(EngineRejected::new(
                ErrorCode::Cancelled,
                "simulated: the sidecar went away during the push",
            ));
        }
        let now = ctl.pushes_in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        ctl.max_pushes_in_flight.fetch_max(now, Ordering::SeqCst);
        let delay = ctl.push_delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        let r = match self.inner.mutator() {
            Some(m) => m.apply(op, cancel).await,
            None => Err(EngineRejected::new(ErrorCode::Unsupported, "no mutator")),
        };
        ctl.pushes_in_flight.fetch_sub(1, Ordering::SeqCst);
        r
    }

    async fn save(&self, cancel: &CancellationToken) -> Result<Watermark, ProtoError> {
        match self.inner.mutator() {
            Some(m) => m.save(cancel).await,
            None => Err(ProtoError::new(ErrorCode::Unsupported, "no mutator")),
        }
    }
}

impl Engine for Controlled {
    fn capabilities(&self) -> EngineCaps {
        self.inner.capabilities()
    }
    fn loader(&self) -> Option<&dyn Loader> {
        self.inner.loader()
    }
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        self.inner.analyzer()
    }
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        self.inner.decompiler()
    }
    fn type_store(&self) -> Option<&dyn TypeStore> {
        self.inner.type_store()
    }
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        self.inner.function_lister()
    }
    fn mutator(&self) -> Option<&dyn Mutator> {
        Some(&self.mutator)
    }
    fn memory_reader(&self) -> Option<&dyn MemoryReader> {
        self.inner.memory_reader()
    }
    fn disassembler(&self) -> Option<&dyn Disassembler> {
        self.inner.disassembler()
    }
    fn xref_provider(&self) -> Option<&dyn XrefProvider> {
        self.inner.xref_provider()
    }
    fn flow_graph(&self) -> Option<&dyn FlowGraph> {
        self.inner.flow_graph()
    }
    fn string_lister(&self) -> Option<&dyn StringLister> {
        self.inner.string_lister()
    }
    fn symbol_lister(&self) -> Option<&dyn SymbolLister> {
        self.inner.symbol_lister()
    }
    fn assembler(&self) -> Option<&dyn kraken_engine::Assembler> {
        self.inner.assembler()
    }
}

/// An [`EngineFactory`] over `engine-fake`. Every engine it creates starts from the same fixture
/// and is not persistent: reopening a project gives a fresh engine.
pub struct FakeFactory {
    fixture: FixtureFile,
    stage_delay: Duration,
    ctl: Arc<FakeControl>,
    dirs: Mutex<Vec<PathBuf>>,
}

impl FakeFactory {
    /// A factory serving `fixture`; analysis steps take `stage_delay` each (zero = instant).
    pub fn new(fixture: FixtureFile, stage_delay: Duration) -> Self {
        FakeFactory {
            fixture,
            stage_delay,
            ctl: Arc::new(FakeControl::new()),
            dirs: Mutex::new(Vec::new()),
        }
    }

    /// The knobs and counters.
    pub fn control(&self) -> Arc<FakeControl> {
        self.ctl.clone()
    }
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        self.ctl.created.fetch_add(1, Ordering::SeqCst);
        self.dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(engine_dir.to_path_buf());
        let open_delay = Duration::from_millis(self.ctl.open_delay_ms.load(Ordering::SeqCst));
        let inner = Arc::new(
            FakeEngine::new(self.fixture.clone())
                .with_stage_delay(self.stage_delay)
                .with_open_delay(open_delay),
        );
        Ok(Arc::new(Controlled {
            mutator: ControlledMutator {
                inner: inner.clone(),
                ctl: self.ctl.clone(),
            },
            inner,
        }))
    }
}

#[async_trait]
impl ManagedFactory for FakeFactory {
    async fn shutdown(&self) {
        self.dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    async fn shutdown_under(&self, project_dir: &Path) {
        self.dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|d| !d.starts_with(project_dir));
        self.ctl
            .closed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(project_dir.to_path_buf());
    }

    fn subscribe_events(&self) -> Option<broadcast::Receiver<FactoryEvent>> {
        Some(self.ctl.events.subscribe())
    }

    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        self.dirs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|d| EngineDiagnostics {
                engine_dir: d.clone(),
                value: json!({
                    "state": "running",
                    "engine": "fake",
                    "restarts": self.ctl.restarts.load(Ordering::SeqCst),
                    "confinement": {"filesystem": "none (fake engine)"},
                }),
            })
            .collect()
    }

    async fn restart_engine(&self, engine_dir: &Path) -> Result<(), ProtoError> {
        self.ctl.restarts.fetch_add(1, Ordering::SeqCst);
        self.ctl.emit(engine_dir, EngineEvent::Restarted);
        Ok(())
    }
}

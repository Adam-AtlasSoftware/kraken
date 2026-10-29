//! The fake launcher over the shared in-process fake peer (tests only).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_sidecar::sandbox::ConfinementReport;
pub use kraken_sidecar::testutil::{FakeSide, Handler, Reply, spawn_peer};
use serde_json::json;
use tokio::net::UnixStream;

use crate::launch::{LaunchPlan, Launched, Launcher, Session};
use crate::log::LogSink;

struct FakeSession(FakeSide);

impl Session for FakeSession {
    fn kill(&self) {
        self.0.kill();
    }
}

impl Drop for FakeSession {
    fn drop(&mut self) {
        self.0.kill();
    }
}

type StartHook = Box<dyn Fn(&FakeSide, u32) + Send + Sync>;

/// A launcher whose sidecars are in-process fakes.
pub struct FakeLauncher {
    handler: Handler,
    /// Launches so far.
    pub launches: AtomicU32,
    /// Launches numbered above this fail (default: unlimited).
    pub fail_after: AtomicU32,
    /// Called on every started fake before it serves (to send `ready`).
    pub on_start: StartHook,
    /// Every started side, newest last.
    pub sides: Mutex<Vec<FakeSide>>,
}

impl FakeLauncher {
    pub fn new(handler: Handler) -> Arc<Self> {
        Self::with_start(handler, |side, _| {
            side.notify("ready", json!({"ghidra_version": "12.2", "init_ms": 1}));
        })
    }

    pub fn with_start(
        handler: Handler,
        on_start: impl Fn(&FakeSide, u32) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(FakeLauncher {
            handler,
            launches: AtomicU32::new(0),
            fail_after: AtomicU32::new(u32::MAX),
            on_start: Box::new(on_start),
            sides: Mutex::default(),
        })
    }
}

#[async_trait]
impl Launcher for FakeLauncher {
    async fn launch(&self, _plan: &LaunchPlan) -> Result<Launched, ProtoError> {
        let n = self.launches.fetch_add(1, Ordering::SeqCst) + 1;
        if n > self.fail_after.load(Ordering::SeqCst) {
            return Err(ProtoError::new(ErrorCode::Internal, "fake launch failure"));
        }
        let (a, b) = UnixStream::pair().expect("socketpair");
        let side = spawn_peer(b, self.handler.clone());
        (self.on_start)(&side, n);
        self.sides
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(side.clone());
        let (reader, writer) = a.into_split();
        let log = LogSink::default();
        log.push(format!("fake sidecar #{n} started"));
        Ok(Launched {
            reader: Box::new(reader),
            writer: Box::new(writer),
            exit: side.exit_watch(),
            log,
            report: ConfinementReport::none(),
            pid: None,
            session: Box::new(FakeSession(side)),
        })
    }
}

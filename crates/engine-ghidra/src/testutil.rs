//! An in-process fake sidecar speaking the wire protocol over a socketpair (tests only).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::launch::{LaunchPlan, Launched, Launcher, Session};
use crate::log::LogSink;
use crate::rpc::{RpcClient, read_frame, write_frame};
use crate::sandbox::{ConfinementReport, ExitInfo};

/// What the fake does with a request.
pub enum Reply {
    /// Respond with this result.
    Result(Value),
    /// Respond with a KRAKEN error.
    Error(&'static str, &'static str),
    /// Respond after a delay.
    Delayed(Duration, Value),
    /// Never respond.
    Never,
    /// The handler answers later through the [`FakeSide`].
    Manual,
    /// Die without answering.
    Hangup,
}

/// `(method, params, request id, side)`.
pub type Handler = Arc<dyn Fn(&str, &Value, &Value, &FakeSide) -> Reply + Send + Sync>;

/// The fake peer's end: pushes frames and can kill the "process".
#[derive(Clone)]
pub struct FakeSide {
    out: mpsc::UnboundedSender<Vec<u8>>,
    aborts: Arc<Mutex<Vec<AbortHandle>>>,
    exit: Arc<watch::Sender<Option<ExitInfo>>>,
}

fn encode(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap_or_default()
}

impl FakeSide {
    pub fn notify(&self, method: &str, params: Value) {
        let _ = self.out.send(encode(
            json!({"jsonrpc": "2.0", "method": method, "params": params}),
        ));
    }

    pub fn respond(&self, id: &Value, result: Value) {
        let _ = self.out.send(encode(
            json!({"jsonrpc": "2.0", "id": id, "result": result}),
        ));
    }

    pub fn fail(&self, id: &Value, code: &str, message: &str) {
        let _ = self.out.send(encode(json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": -32000, "message": message, "data": {"code": code}},
        })));
    }

    pub fn raw(&self, body: Vec<u8>) {
        let _ = self.out.send(body);
    }

    /// Kills the fake process: closes the socket and reports an exit.
    pub fn kill(&self) {
        for h in self
            .aborts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            h.abort();
        }
        self.exit.send_replace(Some(ExitInfo {
            code: None,
            signal: Some(9),
        }));
    }

    pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.exit.subscribe()
    }
}

/// Runs the fake peer on `stream`.
pub fn spawn_peer(stream: UnixStream, handler: Handler) -> FakeSide {
    let (mut rd, mut wr) = stream.into_split();
    let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
    let side = FakeSide {
        out,
        aborts: Arc::default(),
        exit: Arc::new(watch::channel(None).0),
    };
    let writer = tokio::spawn(async move {
        while let Some(body) = frames.recv().await {
            if write_frame(&mut wr, &body).await.is_err() {
                break;
            }
        }
    });
    let reply_side = side.clone();
    let reader = tokio::spawn(async move {
        while let Ok(Some(body)) = read_frame(&mut rd).await {
            let Ok(req) = serde_json::from_slice::<Value>(&body) else {
                continue;
            };
            let method = req["method"].as_str().unwrap_or_default().to_string();
            let id = req["id"].clone();
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            match handler(&method, &params, &id, &reply_side) {
                Reply::Result(v) => reply_side.respond(&id, v),
                Reply::Error(code, message) => reply_side.fail(&id, code, message),
                Reply::Delayed(d, v) => {
                    let s = reply_side.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(d).await;
                        s.respond(&id, v);
                    });
                }
                Reply::Never | Reply::Manual => {}
                Reply::Hangup => {
                    reply_side.kill();
                    break;
                }
            }
        }
    });
    side.aborts
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .extend([writer.abort_handle(), reader.abort_handle()]);
    side
}

/// A connected client + fake peer pair.
pub fn pair(handler: Handler) -> (RpcClient, FakeSide) {
    let (a, b) = UnixStream::pair().expect("socketpair");
    let side = spawn_peer(b, handler);
    let (rd, wr) = a.into_split();
    (RpcClient::new(rd, wr), side)
}

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
            side.notify("ready", json!({"ghidra_version": "12.1.4", "init_ms": 1}));
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

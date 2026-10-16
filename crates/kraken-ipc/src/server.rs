//! Async RPC server generic over a handler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::frame::{MAX_FRAME_LEN, read_frame, write_frame};
use crate::idle::{Counter, Shutdown};
use crate::transport::Listener;
use crate::wire::{
    ClientKind, HELLO_METHOD, HelloParams, HelloResult, Inbound, notification, parse,
    protocol_mismatch, response, unauthorized,
};

/// How long a new connection has to send its hello frame.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends server-to-client notifications on one connection.
#[derive(Debug, Clone)]
pub struct Notifier {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl Notifier {
    /// Queues a notification. Returns false if the connection is gone or the message is too big.
    pub fn notify(&self, method: &str, params: Value) -> bool {
        let bytes = notification(method, params);
        bytes.len() <= MAX_FRAME_LEN && self.tx.send(bytes).is_ok()
    }
}

/// Per-connection information passed to the handler.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// Server-unique connection id.
    pub id: u64,
    /// Kind announced in the hello.
    pub client_kind: ClientKind,
    /// Client build announced in the hello.
    pub client_build: String,
    /// Sender for events to this client.
    pub notifier: Notifier,
}

/// Application logic behind the RPC transport.
#[async_trait]
pub trait RpcHandler: Send + Sync + 'static {
    /// Handles one request. Called concurrently for concurrent requests.
    async fn call(&self, conn: &ConnInfo, method: &str, params: Value)
    -> Result<Value, ProtoError>;
}

/// Identity and credentials the server presents and demands.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Required auth token.
    pub token: String,
    /// Protocol version spoken.
    pub protocol: u32,
    /// Build id reported in the hello reply.
    pub build: String,
    /// Daemon pid reported in the hello reply.
    pub pid: u32,
}

struct Inner<H> {
    handler: H,
    cfg: ServerConfig,
    connections: Counter,
    shutdown: Shutdown,
    notifiers: Mutex<HashMap<u64, Notifier>>,
    next_conn: AtomicU64,
}

/// The RPC server. Cheap to clone.
pub struct Server<H> {
    inner: Arc<Inner<H>>,
}

impl<H> Clone for Server<H> {
    fn clone(&self) -> Self {
        Server {
            inner: self.inner.clone(),
        }
    }
}

impl<H: RpcHandler> Server<H> {
    /// Creates a server with its own connection counter and shutdown signal.
    pub fn new(handler: H, cfg: ServerConfig) -> Self {
        Self::with_parts(handler, cfg, Counter::new(), Shutdown::new())
    }

    /// Creates a server wired to an existing client counter (e.g. `IdleMonitor::clients`) and
    /// shutdown signal.
    pub fn with_parts(
        handler: H,
        cfg: ServerConfig,
        connections: Counter,
        shutdown: Shutdown,
    ) -> Self {
        Server {
            inner: Arc::new(Inner {
                handler,
                cfg,
                connections,
                shutdown,
                notifiers: Mutex::new(HashMap::new()),
                next_conn: AtomicU64::new(1),
            }),
        }
    }

    /// Number of authenticated connected clients.
    pub fn connections(&self) -> &Counter {
        &self.inner.connections
    }

    /// The shutdown signal; triggering it stops `serve` and drops all connections.
    pub fn shutdown(&self) -> &Shutdown {
        &self.inner.shutdown
    }

    /// Sends a notification to every connected client; returns how many accepted it.
    pub fn broadcast(&self, method: &str, params: &Value) -> usize {
        let map = self
            .inner
            .notifiers
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        map.values()
            .filter(|n| n.notify(method, params.clone()))
            .count()
    }

    /// Accepts connections until shutdown is triggered.
    pub async fn serve(&self, mut listener: Listener) -> std::io::Result<()> {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                () = self.inner.shutdown.wait() => break,
                accepted = listener.accept() => match accepted {
                    Ok(stream) => {
                        let me = self.clone();
                        conns.spawn(async move { me.serve_connection(stream).await });
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                },
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
        Ok(())
    }

    /// Runs the handshake and request loop on one already-connected stream.
    pub async fn serve_connection<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut wr, &frame).await.is_err() {
                    break;
                }
            }
        });

        let notifier = Notifier { tx: tx.clone() };
        if let Some(conn) = self.handshake(&mut rd, &tx, notifier).await {
            let conn = Arc::new(conn);
            let _count = self.inner.connections.guard();
            self.inner
                .notifiers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(conn.id, conn.notifier.clone());
            self.request_loop(&mut rd, &tx, &conn).await;
            self.inner
                .notifiers
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&conn.id);
        }
        drop(tx);
        let _ = writer.await;
    }

    async fn handshake<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
        tx: &mpsc::UnboundedSender<Vec<u8>>,
        notifier: Notifier,
    ) -> Option<ConnInfo> {
        let frame = tokio::time::timeout(HELLO_TIMEOUT, read_frame(rd))
            .await
            .ok()?
            .ok()??;
        let (id, params) = match parse(&frame) {
            Ok(Inbound::Request { id, method, params }) if method == HELLO_METHOD => (id, params),
            Ok(Inbound::Request { id, .. }) => {
                let e = ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "hello must be the first request",
                );
                let _ = tx.send(response(&id, Err(e)));
                return None;
            }
            Ok(_) => return None,
            Err(e) => {
                let _ = tx.send(response(&Value::Null, Err(e)));
                return None;
            }
        };
        let hello: HelloParams = match serde_json::from_value(params) {
            Ok(h) => h,
            Err(e) => {
                let e = ProtoError::new(ErrorCode::InvalidArgument, format!("bad hello: {e}"));
                let _ = tx.send(response(&id, Err(e)));
                return None;
            }
        };
        let cfg = &self.inner.cfg;
        if !crate::token::tokens_match(&cfg.token, &hello.token) {
            let _ = tx.send(response(&id, Err(unauthorized())));
            return None;
        }
        if hello.protocol != cfg.protocol {
            let e = protocol_mismatch(cfg.protocol, hello.protocol, &cfg.build);
            let _ = tx.send(response(&id, Err(e)));
            return None;
        }
        let result = HelloResult {
            protocol: cfg.protocol,
            build: cfg.build.clone(),
            daemon_pid: cfg.pid,
        };
        let value = serde_json::to_value(result).unwrap_or(Value::Null);
        let _ = tx.send(response(&id, Ok(value)));
        Some(ConnInfo {
            id: self.inner.next_conn.fetch_add(1, Ordering::Relaxed),
            client_kind: hello.client_kind,
            client_build: hello.build,
            notifier,
        })
    }

    async fn request_loop<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
        tx: &mpsc::UnboundedSender<Vec<u8>>,
        conn: &Arc<ConnInfo>,
    ) {
        // Dropping the set on exit aborts requests still running for a vanished client.
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            let frame = match read_frame(rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    let e = ProtoError::new(ErrorCode::InvalidArgument, e.to_string());
                    let _ = tx.send(response(&Value::Null, Err(e)));
                    break;
                }
            };
            while tasks.try_join_next().is_some() {}
            match parse(&frame) {
                Ok(Inbound::Request { id, method, params }) => {
                    let me = self.clone();
                    let conn = conn.clone();
                    let tx = tx.clone();
                    tasks.spawn(async move {
                        let res = if method == HELLO_METHOD {
                            Err(ProtoError::new(
                                ErrorCode::InvalidArgument,
                                "already greeted",
                            ))
                        } else {
                            me.inner.handler.call(&conn, &method, params).await
                        };
                        let mut bytes = response(&id, res);
                        if bytes.len() > MAX_FRAME_LEN {
                            let e = ProtoError::new(
                                ErrorCode::Internal,
                                "response exceeds the frame limit",
                            );
                            bytes = response(&id, Err(e));
                        }
                        let _ = tx.send(bytes);
                    });
                }
                Ok(Inbound::Notification { .. } | Inbound::Response { .. }) => {}
                Err(e) => {
                    let _ = tx.send(response(&Value::Null, Err(e)));
                }
            }
        }
    }
}

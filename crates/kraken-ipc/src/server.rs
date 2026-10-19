//! Async RPC server generic over a handler.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::frame::{MAX_FRAME_LEN, read_frame, read_frame_limited, write_frame};
use crate::idle::{Counter, Shutdown};
use crate::transport::Listener;
use crate::wire::{
    ClientKind, CredentialClass, HELLO_METHOD, HelloParams, HelloResult, Inbound, notification,
    parse, protocol_mismatch, response, unauthorized,
};

/// How long a new connection has to send its hello frame.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest frame accepted before the hello has authenticated the peer.
pub const HELLO_MAX_FRAME_LEN: usize = 64 * 1024;

/// Bounds on what peers can make the daemon hold or run at once. Anything that can reach the
/// socket (any process of the same user, including a confined sidecar) can open connections and
/// send frames before it has proven anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Connections open at once, authenticated or not; further ones are closed on accept.
    pub max_connections: usize,
    /// Connections that have not finished the hello; further ones are closed on accept.
    pub max_unauthenticated: usize,
    /// Requests running at once on one connection. The next frame is not read until one ends.
    pub max_inflight_per_connection: usize,
    /// Requests running at once across all connections.
    pub max_inflight_total: usize,
    /// Messages queued towards one client. Notifications beyond it are dropped (the client can
    /// catch up with the `events` method); responses wait for room.
    pub outbound_queue: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: 128,
            max_unauthenticated: 16,
            max_inflight_per_connection: 64,
            max_inflight_total: 256,
            outbound_queue: 1024,
        }
    }
}

/// Sends server-to-client notifications on one connection.
#[derive(Debug, Clone)]
pub struct Notifier {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Notifier {
    /// Queues a notification. Returns false if the connection is gone, the client is not keeping
    /// up (its queue is full) or the message is too big.
    pub fn notify(&self, method: &str, params: Value) -> bool {
        let bytes = notification(method, params);
        bytes.len() <= MAX_FRAME_LEN && self.tx.try_send(bytes).is_ok()
    }
}

/// Per-connection information passed to the handler.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// Server-unique connection id.
    pub id: u64,
    /// Kind announced in the hello. Connections with the agent credential are always `Mcp`,
    /// whatever they announced.
    pub client_kind: ClientKind,
    /// What the presented token entitles this connection to.
    pub class: CredentialClass,
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

    /// Called once when an authenticated connection has ended (closed by the client, broken, or
    /// dropped at shutdown), after its requests were aborted. Whatever the connection held is
    /// released here.
    fn disconnected(&self, _conn: &ConnInfo) {}
}

/// Identity and credentials the server presents and demands.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Token of the user credential class (GUI and CLI).
    pub token: String,
    /// Token of the agent credential class (MCP servers and other agent-side clients); `None`
    /// refuses agent-class connections.
    pub agent_token: Option<String>,
    /// Connection and concurrency bounds.
    pub limits: Limits,
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
    conn_slots: Arc<Semaphore>,
    unauth_slots: Arc<Semaphore>,
    inflight_total: Arc<Semaphore>,
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
        let limits = cfg.limits;
        Server {
            inner: Arc::new(Inner {
                handler,
                conn_slots: Arc::new(Semaphore::new(limits.max_connections.max(1))),
                unauth_slots: Arc::new(Semaphore::new(limits.max_unauthenticated.max(1))),
                inflight_total: Arc::new(Semaphore::new(limits.max_inflight_total.max(1))),
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
                        // Over the limit: close at once, before reading a byte.
                        let slots = (
                            self.inner.conn_slots.clone().try_acquire_owned(),
                            self.inner.unauth_slots.clone().try_acquire_owned(),
                        );
                        if let (Ok(conn), Ok(unauth)) = slots {
                            let me = self.clone();
                            conns.spawn(async move {
                                me.serve_with_permits(stream, Some(conn), Some(unauth)).await;
                            });
                        }
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                },
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
        Ok(())
    }

    /// Runs the handshake and request loop on one already-connected stream (the connection
    /// limits apply to connections accepted by [`serve`](Self::serve) only).
    pub async fn serve_connection<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        self.serve_with_permits(stream, None, None).await;
    }

    async fn serve_with_permits<S>(
        &self,
        stream: S,
        conn_permit: Option<OwnedSemaphorePermit>,
        unauth_permit: Option<OwnedSemaphorePermit>,
    ) where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let _conn_permit = conn_permit;
        let (mut rd, mut wr) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(self.inner.cfg.limits.outbound_queue.max(1));
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                if write_frame(&mut wr, &frame).await.is_err() {
                    break;
                }
            }
        });

        let notifier = Notifier { tx: tx.clone() };
        let greeted = self.handshake(&mut rd, &tx, notifier).await;
        drop(unauth_permit);
        if let Some(conn) = greeted {
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
            self.inner.handler.disconnected(&conn);
        }
        drop(tx);
        let _ = writer.await;
    }

    async fn handshake<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
        tx: &mpsc::Sender<Vec<u8>>,
        notifier: Notifier,
    ) -> Option<ConnInfo> {
        let frame =
            tokio::time::timeout(HELLO_TIMEOUT, read_frame_limited(rd, HELLO_MAX_FRAME_LEN))
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
                let _ = tx.send(response(&id, Err(e))).await;
                return None;
            }
            Ok(_) => return None,
            Err(e) => {
                let _ = tx.send(response(&Value::Null, Err(e))).await;
                return None;
            }
        };
        let hello: HelloParams = match serde_json::from_value(params) {
            Ok(h) => h,
            Err(e) => {
                let e = ProtoError::new(ErrorCode::InvalidArgument, format!("bad hello: {e}"));
                let _ = tx.send(response(&id, Err(e))).await;
                return None;
            }
        };
        let cfg = &self.inner.cfg;
        // Both comparisons always run, so the time taken does not say which token was close.
        let is_user = crate::token::tokens_match(&cfg.token, &hello.token);
        let is_agent = cfg
            .agent_token
            .as_deref()
            .is_some_and(|t| crate::token::tokens_match(t, &hello.token));
        let class = if is_user {
            CredentialClass::User
        } else if is_agent {
            CredentialClass::Agent
        } else {
            let _ = tx.send(response(&id, Err(unauthorized()))).await;
            return None;
        };
        if hello.protocol != cfg.protocol {
            let e = protocol_mismatch(cfg.protocol, hello.protocol, &cfg.build);
            let _ = tx.send(response(&id, Err(e))).await;
            return None;
        }
        let result = HelloResult {
            protocol: cfg.protocol,
            build: cfg.build.clone(),
            daemon_pid: cfg.pid,
        };
        let value = serde_json::to_value(result).unwrap_or(Value::Null);
        let _ = tx.send(response(&id, Ok(value))).await;
        Some(ConnInfo {
            id: self.inner.next_conn.fetch_add(1, Ordering::Relaxed),
            client_kind: match class {
                CredentialClass::User => hello.client_kind,
                CredentialClass::Agent => ClientKind::Mcp,
            },
            class,
            client_build: hello.build,
            notifier,
        })
    }

    async fn request_loop<R: AsyncRead + Unpin>(
        &self,
        rd: &mut R,
        tx: &mpsc::Sender<Vec<u8>>,
        conn: &Arc<ConnInfo>,
    ) {
        // Dropping the set on exit aborts requests still running for a vanished client.
        let mut tasks: JoinSet<()> = JoinSet::new();
        let per_conn = Arc::new(Semaphore::new(
            self.inner.cfg.limits.max_inflight_per_connection.max(1),
        ));
        loop {
            let frame = match read_frame(rd).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    let e = ProtoError::new(ErrorCode::InvalidArgument, e.to_string());
                    let _ = tx.try_send(response(&Value::Null, Err(e)));
                    break;
                }
            };
            while tasks.try_join_next().is_some() {}
            match parse(&frame) {
                Ok(Inbound::Request { id, method, params }) => {
                    // Not reading the next frame until there is room keeps a flooding client's
                    // work (and memory) bounded by the limits, not by what it sends.
                    let Ok(mine) = per_conn.clone().acquire_owned().await else {
                        break;
                    };
                    let Ok(shared) = self.inner.inflight_total.clone().acquire_owned().await else {
                        break;
                    };
                    let me = self.clone();
                    let conn = conn.clone();
                    let tx = tx.clone();
                    tasks.spawn(async move {
                        let _permits = (mine, shared);
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
                        let _ = tx.send(bytes).await;
                    });
                }
                Ok(Inbound::Notification { .. } | Inbound::Response { .. }) => {}
                Err(e) => {
                    let _ = tx.try_send(response(&Value::Null, Err(e)));
                }
            }
        }
    }
}

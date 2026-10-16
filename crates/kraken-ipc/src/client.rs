//! Async RPC client with request-id multiplexing and server notification delivery.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kraken_proto::ProtoError;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};

use crate::frame::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
use crate::paths::RuntimeDir;
use crate::wire::{
    ClientKind, HELLO_METHOD, HelloParams, HelloResult, Inbound, PROTOCOL_VERSION, parse, request,
};

/// Client-side failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Transport I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Framing failure.
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    /// The server answered with a protocol error.
    #[error("{0}")]
    Proto(ProtoError),
    /// The connection is closed.
    #[error("connection closed")]
    Closed,
    /// The peer sent something that is not valid JSON-RPC.
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// Token file problem.
    #[error("token: {0}")]
    Token(String),
}

impl ClientError {
    /// True when the server asked us to restart the daemon (protocol mismatch).
    pub fn restart_required(&self) -> bool {
        matches!(self, ClientError::Proto(e) if crate::wire::is_restart_required(e))
    }
}

/// A server-initiated event.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// Event method name.
    pub method: String,
    /// Event payload.
    pub params: Value,
}

/// What the client announces about itself (the token is read from disk).
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// Protocol version.
    pub protocol: u32,
    /// Build id.
    pub build: String,
    /// Client kind.
    pub client_kind: ClientKind,
}

impl ClientHello {
    /// Hello for this crate's protocol version.
    pub fn new(client_kind: ClientKind, build: impl Into<String>) -> Self {
        ClientHello {
            protocol: PROTOCOL_VERSION,
            build: build.into(),
            client_kind,
        }
    }
}

type Pending = HashMap<u64, oneshot::Sender<Result<Value, ProtoError>>>;

struct Inner {
    out: mpsc::UnboundedSender<Vec<u8>>,
    next_id: AtomicU64,
    pending: Mutex<Option<Pending>>,
    notifications: Mutex<Option<mpsc::UnboundedReceiver<Notification>>>,
    hello: HelloResult,
}

/// A connected, authenticated client. Cheap to clone; clones share the connection.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Connects to the daemon in `dir`, reading the token from `daemon.token`.
    pub async fn connect(dir: &RuntimeDir, hello: &ClientHello) -> Result<Client, ClientError> {
        let token = crate::token::read_token(&dir.token_path()).map_err(|e| match e {
            crate::error::IpcError::Io(io) => ClientError::Io(io),
            other => ClientError::Token(other.to_string()),
        })?;
        let stream = crate::transport::connect(dir).await?;
        Client::from_stream(stream, hello, token).await
    }

    /// Performs the hello handshake over an existing stream and starts the I/O tasks.
    pub async fn from_stream<S>(
        stream: S,
        hello: &ClientHello,
        token: String,
    ) -> Result<Client, ClientError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut rd, mut wr) = tokio::io::split(stream);
        let params = HelloParams {
            token,
            protocol: hello.protocol,
            build: hello.build.clone(),
            client_kind: hello.client_kind,
        };
        let params =
            serde_json::to_value(params).map_err(|e| ClientError::Protocol(e.to_string()))?;
        write_frame(&mut wr, &request(0, HELLO_METHOD, params)).await?;
        let frame = read_frame(&mut rd).await?.ok_or(ClientError::Closed)?;
        let result = match parse(&frame).map_err(|e| ClientError::Protocol(e.message))? {
            Inbound::Response { result, .. } => result.map_err(ClientError::Proto)?,
            _ => return Err(ClientError::Protocol("expected hello response".into())),
        };
        let hello_result: HelloResult =
            serde_json::from_value(result).map_err(|e| ClientError::Protocol(e.to_string()))?;

        let (out, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (note_tx, note_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            out,
            next_id: AtomicU64::new(1),
            pending: Mutex::new(Some(HashMap::new())),
            notifications: Mutex::new(Some(note_rx)),
            hello: hello_result,
        });

        tokio::spawn(async move {
            while let Some(frame) = out_rx.recv().await {
                if write_frame(&mut wr, &frame).await.is_err() {
                    break;
                }
            }
        });

        let reader_inner = inner.clone();
        tokio::spawn(async move {
            while let Ok(Some(frame)) = read_frame(&mut rd).await {
                match parse(&frame) {
                    Ok(Inbound::Response { id, result }) => {
                        let Some(id) = id.as_u64() else { continue };
                        let tx = reader_inner
                            .pending
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .as_mut()
                            .and_then(|m| m.remove(&id));
                        if let Some(tx) = tx {
                            let _ = tx.send(result);
                        }
                    }
                    Ok(Inbound::Notification { method, params }) => {
                        let _ = note_tx.send(Notification { method, params });
                    }
                    Ok(Inbound::Request { .. }) | Err(_) => {}
                }
            }
            // Dropping the senders wakes every waiter with `Closed`.
            reader_inner
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take();
        });

        Ok(Client { inner })
    }

    /// What the daemon reported in the handshake.
    pub fn server_info(&self) -> &HelloResult {
        &self.inner.hello
    }

    /// Whether the connection has ended.
    pub fn is_closed(&self) -> bool {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_none()
    }

    /// Takes the stream of server notifications (only the first caller gets it).
    pub fn take_notifications(&self) -> Option<mpsc::UnboundedReceiver<Notification>> {
        self.inner
            .notifications
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    /// Calls `method`; any number of calls may be in flight at once.
    pub async fn call(&self, method: &str, params: Value) -> Result<Value, ClientError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let bytes = request(id, method, params);
        if bytes.len() > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge(bytes.len()).into());
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut p = self.inner.pending.lock().unwrap_or_else(|p| p.into_inner());
            p.as_mut().ok_or(ClientError::Closed)?.insert(id, tx);
        }
        if self.inner.out.send(bytes).is_err() {
            return Err(ClientError::Closed);
        }
        match rx.await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(ClientError::Proto(e)),
            Err(_) => Err(ClientError::Closed),
        }
    }
}

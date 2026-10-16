//! Length-prefixed JSON-RPC 2.0 client with request-id multiplexing.
//!
//! Framing: 4-byte big-endian length, then a UTF-8 JSON message (decisions 41, 87). One reader
//! task dispatches responses to waiting callers by id and notifications (`ready`, `progress`) to
//! their subscribers; one writer task serialises outgoing frames. When the channel closes every
//! in-flight request fails with `internal: sidecar exited`.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_proto::{ErrorCode, ProtoError};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

/// Largest accepted frame body (matches the Java side).
pub const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;
/// Message of the error returned to requests that were in flight when the sidecar went away.
pub const SIDECAR_EXITED: &str = "sidecar exited";

/// Writes one frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "frame of {} bytes exceeds the {MAX_FRAME_LEN} byte limit",
                body.len()
            ),
        ));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf).await?;
    w.flush().await
}

/// Reads one frame; `None` on a clean EOF at a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    if r.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..]).await?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad frame length {n}"),
        ));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Payload of the sidecar's `ready` notification.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReadyInfo {
    /// Ghidra version the JVM runs.
    pub ghidra_version: String,
    /// Time Ghidra took to initialise.
    #[serde(default)]
    pub init_ms: u64,
}

/// A `progress` notification as it arrives on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct WireProgress {
    /// Job the event belongs to.
    pub job_id: String,
    /// `"core"` or `"expensive"` (or `"-"` before the first stage starts).
    pub stage: String,
    /// Stages finished so far in this job.
    pub done: u64,
    /// Stages this job will run.
    pub total: u64,
    /// Ghidra's current task text.
    #[serde(default)]
    pub message: String,
}

fn exited() -> ProtoError {
    ProtoError::new(ErrorCode::Internal, SIDECAR_EXITED)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

type Reply = Result<Value, ProtoError>;

#[derive(Default)]
struct Table {
    pending: HashMap<u64, oneshot::Sender<Reply>>,
    closed: bool,
}

struct Inner {
    table: Mutex<Table>,
    jobs: Mutex<HashMap<String, mpsc::UnboundedSender<WireProgress>>>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    next_id: AtomicU64,
    ready: watch::Sender<Option<ReadyInfo>>,
    closed: watch::Sender<bool>,
}

impl Inner {
    /// Marks the channel closed and fails everything in flight.
    fn close(&self) {
        let drained = {
            let mut t = lock(&self.table);
            t.closed = true;
            std::mem::take(&mut t.pending)
        };
        for (_, tx) in drained {
            let _ = tx.send(Err(exited()));
        }
        lock(&self.jobs).clear();
        self.closed.send_replace(true);
    }

    fn forget(&self, id: u64) {
        lock(&self.table).pending.remove(&id);
    }

    fn dispatch(&self, msg: Value) {
        let id = msg.get("id").filter(|v| !v.is_null());
        let method = msg.get("method").and_then(Value::as_str);
        match (id, method) {
            (Some(id), None) => {
                let Some(id) = id.as_u64() else {
                    tracing::warn!("response with a non-numeric id: {id}");
                    return;
                };
                let tx = lock(&self.table).pending.remove(&id);
                let reply = match msg.get("error") {
                    Some(err) => Err(map_rpc_error(err)),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                match tx {
                    Some(tx) => {
                        let _ = tx.send(reply);
                    }
                    None => tracing::debug!("late or unknown response id {id} dropped"),
                }
            }
            (None, Some(method)) => self.notification(method, msg.get("params")),
            (Some(id), Some(method)) => {
                tracing::warn!("sidecar sent a request `{method}`; answering method-not-found");
                let reply = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": format!("method not found: {method}"),
                              "data": {"code": "unsupported"}},
                });
                if let Ok(body) = serde_json::to_vec(&reply) {
                    let _ = self.out.send(body);
                }
            }
            (None, None) => {
                tracing::warn!("ignoring a message that is neither request nor response")
            }
        }
    }

    fn notification(&self, method: &str, params: Option<&Value>) {
        let params = params.cloned().unwrap_or(Value::Null);
        match method {
            "ready" => match serde_json::from_value::<ReadyInfo>(params) {
                Ok(info) => {
                    self.ready.send_replace(Some(info));
                }
                Err(e) => tracing::warn!("malformed ready notification: {e}"),
            },
            "progress" => match serde_json::from_value::<WireProgress>(params) {
                Ok(p) => {
                    let jobs = lock(&self.jobs);
                    match jobs.get(&p.job_id) {
                        Some(tx) => {
                            let _ = tx.send(p);
                        }
                        None => tracing::debug!("progress for unknown job {}", p.job_id),
                    }
                }
                Err(e) => tracing::warn!("malformed progress notification: {e}"),
            },
            other => tracing::debug!("ignoring notification `{other}`"),
        }
    }
}

/// Maps a JSON-RPC error object to a [`ProtoError`]: `data.code` is authoritative, the numeric
/// code is the fallback.
pub fn map_rpc_error(err: &Value) -> ProtoError {
    let message = err
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("sidecar error")
        .to_string();
    let data = err.get("data");
    let code = data
        .and_then(|d| d.get("code"))
        .and_then(|c| serde_json::from_value::<ErrorCode>(c.clone()).ok())
        .unwrap_or_else(|| match err.get("code").and_then(Value::as_i64) {
            Some(-32602) => ErrorCode::InvalidArgument,
            Some(-32601) => ErrorCode::Unsupported,
            _ => ErrorCode::Internal,
        });
    let mut e = ProtoError::new(code, message);
    if let Some(details) = data.and_then(|d| d.get("details")) {
        e = e.with_details(details.clone());
    }
    e
}

async fn reader_loop<R: AsyncRead + Unpin>(inner: Arc<Inner>, mut reader: R) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some(body)) => match serde_json::from_slice::<Value>(&body) {
                Ok(msg) => inner.dispatch(msg),
                Err(e) => tracing::warn!("sidecar sent invalid JSON: {e}"),
            },
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("sidecar channel read failed: {e}");
                break;
            }
        }
    }
    inner.close();
}

async fn writer_loop<W: AsyncWrite + Unpin>(
    inner: Arc<Inner>,
    mut writer: W,
    mut frames: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(body) = frames.recv().await {
        if let Err(e) = write_frame(&mut writer, &body).await {
            tracing::debug!("sidecar channel write failed: {e}");
            break;
        }
    }
    inner.close();
}

struct AbortOnDrop(Vec<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

struct PendingGuard<'a> {
    inner: &'a Inner,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.inner.forget(self.id);
    }
}

/// Receives the progress notifications of one job; unsubscribes on drop.
pub struct JobSubscription {
    inner: Arc<Inner>,
    job_id: String,
    /// Events in arrival order.
    pub events: mpsc::UnboundedReceiver<WireProgress>,
}

impl Drop for JobSubscription {
    fn drop(&mut self) {
        lock(&self.inner.jobs).remove(&self.job_id);
    }
}

/// Multiplexing JSON-RPC client. Cheap to clone; tasks stop when the last clone is dropped.
#[derive(Clone)]
pub struct RpcClient {
    inner: Arc<Inner>,
    _tasks: Arc<AbortOnDrop>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcClient")
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl RpcClient {
    /// Starts the reader and writer tasks on the current tokio runtime.
    pub fn new<R, W>(reader: R, writer: W) -> RpcClient
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out, frames) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            table: Mutex::default(),
            jobs: Mutex::default(),
            out,
            next_id: AtomicU64::new(0),
            ready: watch::channel(None).0,
            closed: watch::channel(false).0,
        });
        let r = tokio::spawn(reader_loop(inner.clone(), reader));
        let w = tokio::spawn(writer_loop(inner.clone(), writer, frames));
        RpcClient {
            inner,
            _tasks: Arc::new(AbortOnDrop(vec![r.abort_handle(), w.abort_handle()])),
        }
    }

    /// Whether the channel has closed (the sidecar is gone).
    pub fn is_closed(&self) -> bool {
        *self.inner.closed.borrow()
    }

    /// Waits for the channel to close.
    pub async fn closed(&self) {
        let mut rx = self.inner.closed.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    /// Waits for the `ready` notification.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<ReadyInfo, ProtoError> {
        let mut ready = self.inner.ready.subscribe();
        let mut closed = self.inner.closed.subscribe();
        let wait = async {
            loop {
                if let Some(info) = ready.borrow_and_update().clone() {
                    return Ok(info);
                }
                if *closed.borrow_and_update() {
                    return Err(exited());
                }
                tokio::select! {
                    _ = ready.changed() => {}
                    _ = closed.changed() => {}
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or_else(|_| {
                Err(ProtoError::new(
                    ErrorCode::Timeout,
                    format!("the sidecar did not report ready within {timeout:?}"),
                ))
            })
    }

    /// Registers for the progress events of `job_id`.
    pub fn subscribe_progress(&self, job_id: &str) -> JobSubscription {
        let (tx, events) = mpsc::unbounded_channel();
        lock(&self.inner.jobs).insert(job_id.to_string(), tx);
        JobSubscription {
            inner: self.inner.clone(),
            job_id: job_id.to_string(),
            events,
        }
    }

    /// Sends a request and waits for its response.
    ///
    /// `deadline` yields `timeout`; a fired `cancel` yields `cancelled` (the sidecar is not told;
    /// use its own `cancel` method for jobs). A closed channel yields `internal: sidecar exited`.
    pub async fn call(
        &self,
        method: &str,
        params: Value,
        deadline: Option<Duration>,
        cancel: Option<&CancellationToken>,
    ) -> Result<Value, ProtoError> {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        {
            let mut t = lock(&self.inner.table);
            if t.closed {
                return Err(exited());
            }
            t.pending.insert(id, tx);
        }
        let _guard = PendingGuard {
            inner: &self.inner,
            id,
        };
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": id, "method": method, "params": params,
        }))
        .map_err(|e| {
            ProtoError::new(ErrorCode::Internal, format!("cannot encode {method}: {e}"))
        })?;
        if self.inner.out.send(body).is_err() {
            return Err(exited());
        }
        let cancelled = async {
            match cancel {
                Some(c) => c.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let timed_out = async {
            match deadline {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            r = rx => r.unwrap_or_else(|_| Err(exited())),
            () = cancelled => Err(ProtoError::new(ErrorCode::Cancelled, format!("{method} cancelled"))),
            () = timed_out => Err(ProtoError::new(
                ErrorCode::Timeout,
                format!("{method} timed out after {:?}", deadline.unwrap_or_default()),
            )),
        }
    }

    /// [`call`](Self::call) with the result deserialised into `T`.
    pub async fn call_typed<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
        deadline: Option<Duration>,
        cancel: Option<&CancellationToken>,
    ) -> Result<T, ProtoError> {
        let v = self.call(method, params, deadline, cancel).await?;
        serde_json::from_value(v).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("malformed `{method}` result from the sidecar: {e}"),
            )
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::testutil::{Handler, Reply, pair};

    fn echo() -> Handler {
        Arc::new(|method, params, _, _| match method {
            "echo" => Reply::Result(params.clone()),
            "slow" => Reply::Delayed(Duration::from_millis(150), json!("slow")),
            "fast" => Reply::Result(json!("fast")),
            "fail" => Reply::Error("conflict_stale_read", "stale"),
            "hang" => Reply::Never,
            "die" => Reply::Hangup,
            _ => Reply::Error("unsupported", "no such method"),
        })
    }

    #[tokio::test]
    async fn frames_round_trip_and_reject_oversize() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"{\"a\":1}").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"{\"a\":1}");
        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none());

        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_frame(&mut b).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[0, 0, 0, 9, b'x']).await.unwrap();
        drop(a);
        assert_eq!(
            read_frame(&mut b).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    async fn responses_are_matched_by_id_out_of_order() {
        let (client, _side) = pair(echo());
        let slow = client.call("slow", json!({}), None, None);
        let fast = client.call("fast", json!({}), None, None);
        let (slow, fast) = tokio::join!(slow, fast);
        assert_eq!(slow.unwrap(), json!("slow"));
        assert_eq!(fast.unwrap(), json!("fast"));

        let handles: Vec<_> = (0..32)
            .map(|i| {
                let c = client.clone();
                tokio::spawn(async move { c.call("echo", json!({"i": i}), None, None).await })
            })
            .collect();
        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.await.unwrap().unwrap(), json!({"i": i}));
        }
    }

    #[tokio::test]
    async fn errors_map_to_proto_codes() {
        let (client, _side) = pair(echo());
        let e = client
            .call("fail", json!({}), None, None)
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, e.message.as_str()),
            (ErrorCode::ConflictStaleRead, "stale")
        );
        let e = client
            .call("nope", json!({}), None, None)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);

        assert_eq!(
            map_rpc_error(&json!({"code": -32602, "message": "m"})).code,
            ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_rpc_error(&json!({"code": -32601, "message": "m"})).code,
            ErrorCode::Unsupported
        );
        assert_eq!(
            map_rpc_error(&json!({"code": -1, "message": "m"})).code,
            ErrorCode::Internal
        );
        let e = map_rpc_error(&json!({
            "code": -32000, "message": "m",
            "data": {"code": "cancelled", "details": {"job_id": "j"}}
        }));
        assert_eq!(e.code, ErrorCode::Cancelled);
        assert_eq!(e.details, Some(json!({"job_id": "j"})));
    }

    #[tokio::test]
    async fn deadline_yields_timeout_and_late_replies_are_ignored() {
        let (client, _side) = pair(echo());
        let e = client
            .call("slow", json!({}), Some(Duration::from_millis(20)), None)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Timeout);
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            client.call("fast", json!({}), None, None).await.unwrap(),
            json!("fast")
        );
    }

    #[tokio::test]
    async fn cancel_token_yields_cancelled() {
        let (client, _side) = pair(echo());
        let token = CancellationToken::new();
        let t2 = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            t2.cancel();
        });
        let e = client
            .call("hang", json!({}), None, Some(&token))
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn peer_exit_fails_in_flight_and_later_calls() {
        let (client, _side) = pair(echo());
        let hang = client.call("hang", json!({}), None, None);
        let die = client.call("die", json!({}), None, None);
        let (hang, die) = tokio::join!(hang, die);
        for r in [hang, die] {
            let e = r.unwrap_err();
            assert_eq!(
                (e.code, e.message.as_str()),
                (ErrorCode::Internal, SIDECAR_EXITED)
            );
        }
        assert!(client.is_closed());
        let e = client
            .call("fast", json!({}), None, None)
            .await
            .unwrap_err();
        assert_eq!(e.message, SIDECAR_EXITED);
        client.closed().await;
    }

    #[tokio::test]
    async fn ready_and_progress_notifications_are_routed() {
        let (client, side) = pair(echo());
        assert_eq!(
            client
                .wait_ready(Duration::from_millis(20))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Timeout
        );
        side.notify("ready", json!({"ghidra_version": "12.1.4", "init_ms": 7}));
        let ready = client.wait_ready(Duration::from_secs(1)).await.unwrap();
        assert_eq!(
            (ready.ghidra_version.as_str(), ready.init_ms),
            ("12.1.4", 7)
        );

        let mut a = client.subscribe_progress("a");
        let mut b = client.subscribe_progress("b");
        for (job, stage) in [
            ("a", "core"),
            ("b", "expensive"),
            ("zzz", "core"),
            ("a", "expensive"),
        ] {
            side.notify(
                "progress",
                json!({"job_id": job, "stage": stage, "done": 0, "total": 2, "message": "m"}),
            );
        }
        side.notify("garbage", json!(null));
        side.raw(b"not json".to_vec());
        // a response after the notifications proves they were processed in order
        client.call("fast", json!({}), None, None).await.unwrap();
        assert_eq!(a.events.recv().await.unwrap().stage, "core");
        assert_eq!(a.events.recv().await.unwrap().stage, "expensive");
        assert_eq!(b.events.recv().await.unwrap().stage, "expensive");
        drop(a);
        side.notify(
            "progress",
            json!({"job_id": "a", "stage": "core", "done": 0, "total": 1}),
        );
        client.call("fast", json!({}), None, None).await.unwrap();
        assert!(b.events.try_recv().is_err());
    }

    #[tokio::test]
    async fn wait_ready_fails_when_the_peer_hangs_up() {
        let (client, _side) = pair(echo());
        let _ = client.call("die", json!({}), None, None).await;
        let e = client.wait_ready(Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(e.message, SIDECAR_EXITED);
    }
}

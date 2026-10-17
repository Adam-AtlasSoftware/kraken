//! The worker side: serves an [`InProcessEngine`] over the protocol socketpair on fd 0.
//!
//! Requests carry an `op` number chosen by the parent; `cancel {op}` fires that request's
//! cancellation token. Each request runs on its own task, so cheap queries are answered while a
//! decompile runs (decompiles themselves stay serialized in the engine). The worker exits when
//! the parent closes the channel.

use std::collections::HashMap;
use std::io;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_engine::{
    AnalyzeRequest, Analyzer, Decompiler, DisasmRequest, Disassembler, FlowGraph, FunctionLister,
    Loader, MemoryReader, Mutator, StringLister, StringsRequest, SymbolLister, TypeStore,
    XrefProvider, XrefRequest,
};
use kraken_proto::{ErrorCode, Locator, PageRequest, ProtoError, TypeDef, VersionedLogOp};
use kraken_sidecar::rpc::{read_frame, write_frame};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{CORE_DUMPS_ARG, OpenParams, TEST_HOOKS_ARG, WirePcodeOp, rpc_error};
use crate::engine::{InProcessEngine, NativeConfig};
use crate::worker::Isolation;

struct State {
    engine: Mutex<Option<Arc<InProcessEngine>>>,
    ops: Mutex<HashMap<u64, CancellationToken>>,
    out: mpsc::UnboundedSender<Vec<u8>>,
    hooks: bool,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl State {
    fn send(&self, msg: &Value) {
        if let Ok(body) = serde_json::to_vec(msg) {
            let _ = self.out.send(body);
        }
    }

    fn engine(&self) -> Result<Arc<InProcessEngine>, ProtoError> {
        lock(&self.engine)
            .clone()
            .ok_or_else(|| ProtoError::new(ErrorCode::InvalidArgument, "no binary is open"))
    }
}

/// Entry point of `kraken-native-worker`; returns the process exit code.
pub fn main() -> i32 {
    let hooks = std::env::args().any(|a| a == TEST_HOOKS_ARG);
    if !std::env::args().any(|a| a == CORE_DUMPS_ARG) {
        no_core_dumps();
    }
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("kraken-native-worker: cannot start the runtime: {e}");
            return 2;
        }
    };
    match rt.block_on(serve(hooks)) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("kraken-native-worker: {e}");
            1
        }
    }
}

/// Marks the process non-dumpable, so a crash ends it at once instead of after a core dump.
fn no_core_dumps() {
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_DUMPABLE only changes a flag of the calling process.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

async fn serve(hooks: bool) -> io::Result<()> {
    let fd = io::stdin().as_fd().try_clone_to_owned()?;
    let channel = std::os::unix::net::UnixStream::from(fd);
    channel.set_nonblocking(true)?;
    let stream = tokio::net::UnixStream::from_std(channel)?;
    let (mut reader, mut writer) = stream.into_split();
    let (out, mut frames) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_task = tokio::spawn(async move {
        while let Some(body) = frames.recv().await {
            if write_frame(&mut writer, &body).await.is_err() {
                break;
            }
        }
    });
    let state = Arc::new(State {
        engine: Mutex::new(None),
        ops: Mutex::new(HashMap::new()),
        out,
        hooks,
    });
    state.send(&json!({
        "jsonrpc": "2.0",
        "method": "ready",
        "params": {"ghidra_version": "12.1.4", "init_ms": 0},
    }));
    while let Some(body) = read_frame(&mut reader).await? {
        let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
            eprintln!("kraken-native-worker: ignoring a frame that is not JSON");
            continue;
        };
        let (Some(id), Some(method)) = (
            msg.get("id").cloned(),
            msg.get("method")
                .and_then(Value::as_str)
                .map(str::to_string),
        ) else {
            continue;
        };
        let params = msg.get("params").cloned().unwrap_or(Value::Null);
        let state = state.clone();
        tokio::spawn(async move {
            let op = params.get("op").and_then(Value::as_u64);
            let token = CancellationToken::new();
            if let Some(op) = op {
                lock(&state.ops).insert(op, token.clone());
            }
            let r = handle(&state, &method, &params, &token).await;
            if let Some(op) = op {
                lock(&state.ops).remove(&op);
            }
            let reply = match r {
                Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": rpc_error(&e)}),
            };
            state.send(&reply);
        });
    }
    // the parent closed the channel: drop everything and leave
    drop(state);
    writer_task.abort();
    Ok(())
}

fn arg<T: DeserializeOwned>(params: &Value, key: &str) -> Result<T, ProtoError> {
    let v = params.get(key).cloned().unwrap_or(Value::Null);
    serde_json::from_value(v).map_err(|e| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("bad parameter `{key}`: {e}"),
        )
    })
}

fn page(params: &Value) -> Result<PageRequest, ProtoError> {
    arg(params, "page")
}

fn out<T: Serialize>(v: T) -> Result<Value, ProtoError> {
    serde_json::to_value(v)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot encode a result: {e}")))
}

async fn handle(
    state: &State,
    method: &str,
    params: &Value,
    c: &CancellationToken,
) -> Result<Value, ProtoError> {
    match method {
        "cancel" => {
            let op: u64 = arg(params, "target")?;
            if let Some(t) = lock(&state.ops).get(&op) {
                t.cancel();
            }
            Ok(Value::Null)
        }
        "open" => {
            let p: OpenParams = arg(params, "open")?;
            let config = NativeConfig {
                spec_root: p.spec_root,
                use_symbols: p.use_symbols,
                decompile_timeout: p.decompile_timeout_ms.map(Duration::from_millis),
                isolation: Isolation::InProcess,
                state_dir: p.state_dir,
            };
            let engine = Arc::new(InProcessEngine::new(config));
            let info = engine.open_binary(&p.path, &p.spec, c).await?;
            *lock(&state.engine) = Some(engine);
            out(info)
        }
        "test_hang" | "test_crash" | "test_probe" if state.hooks => test_hook(method).await,
        _ => {
            let e = state.engine()?;
            dispatch(state, &e, method, params, c).await
        }
    }
}

async fn dispatch(
    state: &State,
    e: &InProcessEngine,
    method: &str,
    params: &Value,
    c: &CancellationToken,
) -> Result<Value, ProtoError> {
    match method {
        "list_functions" => out(e.list_functions(&page(params)?, c).await?),
        "get_function" => out(e
            .get_function(&arg::<Locator>(params, "locator")?, c)
            .await?),
        "decompile" => out(e.decompile(&arg::<Locator>(params, "locator")?, c).await?),
        "memory_map" => out(e.memory_map(c).await?),
        "read_bytes" => out(e
            .read_bytes(&arg::<Locator>(params, "start")?, arg(params, "length")?, c)
            .await?),
        "disassemble" => out(e
            .disassemble(&arg::<DisasmRequest>(params, "req")?, &page(params)?, c)
            .await?),
        "xrefs" => out(e
            .xrefs(&arg::<XrefRequest>(params, "req")?, &page(params)?, c)
            .await?),
        "cfg" => out(e.cfg(&arg::<Locator>(params, "function")?, c).await?),
        "strings" => out(e
            .strings(&arg::<StringsRequest>(params, "req")?, &page(params)?, c)
            .await?),
        "imports" => out(e.imports(&page(params)?, c).await?),
        "exports" => out(e.exports(&page(params)?, c).await?),
        "get_type" => out(e.get_type(&arg::<String>(params, "name")?, c).await?),
        "define_type" => out(e.define_type(arg::<TypeDef>(params, "def")?, c).await?),
        "list_types" => out(e.list_types(&page(params)?, c).await?),
        "apply" => {
            let op: VersionedLogOp = arg(params, "log_op")?;
            e.apply(&op, c)
                .await
                .map_err(|r| ProtoError::new(r.code, r.reason))?;
            Ok(Value::Null)
        }
        "save" => out(e.save(c).await?),
        "stats" => out(e.stats()?),
        "lift" => {
            let ops = e.lift(arg(params, "start")?, arg(params, "end")?)?;
            out(ops.into_iter().map(WirePcodeOp::from).collect::<Vec<_>>())
        }
        "analyze" => {
            let job_id: String = arg(params, "job_id")?;
            let req: AnalyzeRequest = arg(params, "req")?;
            let mut job = e.analyze(req, c.clone()).await?;
            while let Some(p) = job.next_progress().await {
                state.send(&json!({
                    "jsonrpc": "2.0",
                    "method": "progress",
                    "params": {
                        "job_id": job_id,
                        "stage": p.stage,
                        "done": p.done,
                        "total": p.total,
                        "message": p.message,
                    },
                }));
            }
            out(job.wait().await?)
        }
        other => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!("the native worker has no method `{other}`"),
        )),
    }
}

/// Test-only behaviour, enabled by `--test-hooks`.
async fn test_hook(method: &str) -> Result<Value, ProtoError> {
    match method {
        // a decompile stuck in one long action: never answers and ignores cancellation
        "test_hang" => std::future::pending().await,
        "test_crash" => std::process::abort(),
        _ => Ok(probe()),
    }
}

/// What the confinement lets this process do.
fn probe() -> Value {
    fn res<T>(r: io::Result<T>) -> Value {
        match r {
            Ok(_) => json!("ok"),
            Err(e) => json!(e.to_string()),
        }
    }
    let tmp = std::env::temp_dir();
    json!({
        "tcp_connect": res(std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
            Duration::from_millis(200),
        )),
        "tcp_bind": res(std::net::TcpListener::bind("127.0.0.1:0")),
        "udp_bind": res(std::net::UdpSocket::bind("127.0.0.1:0")),
        "tcp6_bind": res(std::net::TcpListener::bind("[::1]:0")),
        "unix_socket": res(std::os::unix::net::UnixDatagram::unbound()),
        "unix_pair": res(std::os::unix::net::UnixStream::pair()),
        "read_etc_passwd": res(std::fs::read("/etc/passwd")),
        "write_tmp_home": res(std::fs::write(tmp.join("probe"), b"x")),
        // the directory holding the worker's home is not granted
        "write_outside_home": res(std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .and_then(|h| h.parent().map(|p| p.join("kraken-probe-outside")))
            .ok_or_else(|| io::Error::other("no HOME"))
            .and_then(|p| std::fs::write(p, b"x"))),
        "env": std::env::vars_os()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
    })
}

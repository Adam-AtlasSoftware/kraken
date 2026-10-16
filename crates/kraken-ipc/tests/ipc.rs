#![cfg(unix)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use kraken_ipc::frame::{MAX_FRAME_LEN, read_frame, write_frame};
use kraken_ipc::transport::Listener;
use kraken_ipc::{
    Client, ClientError, ClientHello, ClientKind, ConnInfo, DaemonGuard, DaemonInfo, EnsureError,
    IpcError, PROTOCOL_VERSION, RpcHandler, RuntimeDir, Server, Shutdown, ensure_daemon,
};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

struct Handler;

#[async_trait]
impl RpcHandler for Handler {
    async fn call(
        &self,
        conn: &ConnInfo,
        method: &str,
        params: Value,
    ) -> Result<Value, ProtoError> {
        match method {
            "echo" => Ok(params),
            "sleep" => {
                let ms = params["ms"].as_u64().unwrap_or(0);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Ok(json!({"slept": ms}))
            }
            "emit" => {
                for i in 0..params["n"].as_u64().unwrap_or(0) {
                    conn.notifier.notify("event", json!({"i": i}));
                }
                Ok(json!("done"))
            }
            "kind" => Ok(json!(conn.client_kind)),
            _ => Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no method {method}"),
            )),
        }
    }
}

fn runtime_dir() -> (tempfile::TempDir, RuntimeDir) {
    let t = tempfile::tempdir().unwrap();
    let d = RuntimeDir::from_dir(t.path().join("k")).unwrap();
    (t, d)
}

struct Running {
    server: Server<Handler>,
    task: tokio::task::JoinHandle<()>,
}

fn start(dir: &RuntimeDir, protocol: u32) -> Running {
    let guard = DaemonGuard::acquire(dir, protocol, "test-build").unwrap();
    let listener = Listener::bind(dir).unwrap();
    let server = Server::new(Handler, guard.server_config());
    let s = server.clone();
    let task = tokio::spawn(async move {
        let _guard = guard;
        let _ = s.serve(listener).await;
    });
    Running { server, task }
}

impl Running {
    async fn stop(self) {
        self.server.shutdown().trigger();
        let _ = self.task.await;
    }
}

fn hello() -> ClientHello {
    ClientHello::new(ClientKind::Cli, "client-build")
}

#[tokio::test]
async fn hello_and_echo() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    let c = Client::connect(&dir, &hello()).await.unwrap();
    assert_eq!(c.server_info().build, "test-build");
    assert_eq!(c.server_info().daemon_pid, std::process::id());
    assert_eq!(
        c.call("echo", json!({"a": 1})).await.unwrap(),
        json!({"a": 1})
    );
    assert_eq!(c.call("kind", Value::Null).await.unwrap(), json!("cli"));
    let err = c.call("nope", Value::Null).await.unwrap_err();
    assert!(matches!(err, ClientError::Proto(e) if e.code == ErrorCode::NotFound));
    assert_eq!(r.server.connections().get(), 1);
    r.stop().await;
}

#[tokio::test]
async fn wrong_token_rejected() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    let stream = UnixStream::connect(dir.socket_path()).await.unwrap();
    let err = Client::from_stream(stream, &hello(), "0".repeat(64))
        .await
        .err()
        .unwrap();
    match err {
        ClientError::Proto(e) => assert!(kraken_ipc::wire::is_unauthorized(&e)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(r.server.connections().get(), 0);
    r.stop().await;
}

#[tokio::test]
async fn protocol_mismatch_asks_for_restart() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION + 1);
    let err = Client::connect(&dir, &hello()).await.err().unwrap();
    assert!(err.restart_required(), "{err:?}");
    r.stop().await;
}

#[tokio::test]
async fn multiplexed_concurrent_calls() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    let c = Client::connect(&dir, &hello()).await.unwrap();
    let order = Arc::new(Mutex::new(Vec::new()));
    let mut joins = Vec::new();
    for ms in [150u64, 100, 50, 0] {
        let c = c.clone();
        let order = order.clone();
        joins.push(tokio::spawn(async move {
            let v = c.call("sleep", json!({"ms": ms})).await.unwrap();
            order.lock().unwrap().push(ms);
            assert_eq!(v, json!({"slept": ms}));
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
    assert_eq!(*order.lock().unwrap(), vec![0, 50, 100, 150]);
    r.stop().await;
}

#[tokio::test]
async fn server_notifications_and_broadcast() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    let c = Client::connect(&dir, &hello()).await.unwrap();
    let mut events = c.take_notifications().unwrap();
    assert!(c.take_notifications().is_none());
    assert_eq!(
        c.call("emit", json!({"n": 3})).await.unwrap(),
        json!("done")
    );
    for i in 0..3 {
        let n = events.recv().await.unwrap();
        assert_eq!((n.method.as_str(), n.params), ("event", json!({"i": i})));
    }
    assert_eq!(r.server.broadcast("tick", &json!(7)), 1);
    let n = events.recv().await.unwrap();
    assert_eq!((n.method.as_str(), n.params), ("tick", json!(7)));
    r.stop().await;
}

#[tokio::test]
async fn oversize_frame_closes_connection() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    let token = kraken_ipc::token::read_token(&dir.token_path()).unwrap();
    let mut s = UnixStream::connect(dir.socket_path()).await.unwrap();
    let hello = json!({"jsonrpc":"2.0","id":0,"method":"hello","params":
        {"token":token,"protocol":PROTOCOL_VERSION,"build":"b","client_kind":"cli"}});
    write_frame(&mut s, hello.to_string().as_bytes())
        .await
        .unwrap();
    let reply = read_frame(&mut s).await.unwrap().unwrap();
    assert!(String::from_utf8(reply).unwrap().contains("daemon_pid"));
    s.write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    let err = read_frame(&mut s).await.unwrap().unwrap();
    assert!(String::from_utf8(err).unwrap().contains("invalid_argument"));
    assert!(read_frame(&mut s).await.unwrap().is_none());
    r.stop().await;
}

#[tokio::test]
async fn second_daemon_refused() {
    let (_t, dir) = runtime_dir();
    let r = start(&dir, PROTOCOL_VERSION);
    assert!(matches!(
        DaemonGuard::acquire(&dir, PROTOCOL_VERSION, "x"),
        Err(IpcError::AlreadyRunning)
    ));
    r.stop().await;
    // Sibling tests fork children that briefly inherit the released lock's file description.
    let mut again = None;
    for _ in 0..200 {
        match DaemonGuard::acquire(&dir, PROTOCOL_VERSION, "x") {
            Ok(g) => {
                again = Some(g);
                break;
            }
            Err(IpcError::AlreadyRunning) => tokio::time::sleep(Duration::from_millis(10)).await,
            Err(e) => panic!("{e}"),
        }
    }
    assert!(again.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_concurrent_ensure_daemon_spawn_once() {
    let (_t, dir) = runtime_dir();
    let spawns = Arc::new(AtomicUsize::new(0));
    let stops: Arc<Mutex<Vec<Shutdown>>> = Arc::default();
    let mut joins = Vec::new();
    for _ in 0..8 {
        let (dir, spawns, stops) = (dir.clone(), spawns.clone(), stops.clone());
        joins.push(tokio::spawn(async move {
            let d2 = dir.clone();
            let spawn = move || {
                spawns.fetch_add(1, Ordering::SeqCst);
                let guard = DaemonGuard::acquire(&d2, PROTOCOL_VERSION, "b")
                    .map_err(std::io::Error::other)?;
                let listener = Listener::bind(&d2)?;
                let server = Server::new(Handler, guard.server_config());
                stops.lock().unwrap().push(server.shutdown().clone());
                tokio::spawn(async move {
                    let _guard = guard;
                    let _ = server.serve(listener).await;
                });
                std::process::Command::new("true").spawn()
            };
            let c = ensure_daemon(&dir, &hello(), spawn, Duration::from_secs(10))
                .await
                .unwrap();
            c.call("echo", json!(1)).await.unwrap();
        }));
    }
    for j in joins {
        j.await.unwrap();
    }
    assert_eq!(spawns.load(Ordering::SeqCst), 1);
    for s in stops.lock().unwrap().iter() {
        s.trigger();
    }
}

fn dead_pid() -> u32 {
    let mut c = std::process::Command::new("true").spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

fn leave_stale_socket(dir: &RuntimeDir) {
    drop(std::os::unix::net::UnixListener::bind(dir.socket_path()).unwrap());
    assert!(dir.socket_path().exists());
}

#[tokio::test]
async fn stale_socket_with_dead_pid_is_cleaned() {
    let (_t, dir) = runtime_dir();
    leave_stale_socket(&dir);
    DaemonInfo {
        pid: dead_pid(),
        start_token: "old".into(),
        protocol: PROTOCOL_VERSION,
        build: "old".into(),
    }
    .write(&dir.info_path())
    .unwrap();

    let stop: Arc<Mutex<Option<Shutdown>>> = Arc::default();
    let (d2, stop2) = (dir.clone(), stop.clone());
    let spawn = move || {
        assert!(
            !d2.socket_path().exists(),
            "stale socket must be removed first"
        );
        let guard =
            DaemonGuard::acquire(&d2, PROTOCOL_VERSION, "b").map_err(std::io::Error::other)?;
        let listener = Listener::bind(&d2)?;
        let server = Server::new(Handler, guard.server_config());
        *stop2.lock().unwrap() = Some(server.shutdown().clone());
        tokio::spawn(async move {
            let _guard = guard;
            let _ = server.serve(listener).await;
        });
        std::process::Command::new("true").spawn()
    };
    let c = ensure_daemon(&dir, &hello(), spawn, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(c.call("echo", json!("ok")).await.unwrap(), json!("ok"));
    stop.lock().unwrap().as_ref().unwrap().trigger();
}

#[tokio::test]
async fn live_pid_socket_is_not_removed_or_respawned() {
    let (_t, dir) = runtime_dir();
    leave_stale_socket(&dir);
    DaemonInfo::for_current_process(PROTOCOL_VERSION, "b")
        .unwrap()
        .write(&dir.info_path())
        .unwrap();
    let spawn = || -> std::io::Result<std::process::Child> { panic!("must not spawn") };
    let err = ensure_daemon(&dir, &hello(), spawn, Duration::from_millis(300))
        .await
        .err()
        .unwrap();
    assert!(matches!(err, EnsureError::Timeout));
    assert!(dir.socket_path().exists());
}

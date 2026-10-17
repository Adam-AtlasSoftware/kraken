//! The confined worker: confinement, the watchdog's hard deadline, crash recovery and hard
//! cancellation. Needs the native build and a spec tree like `native.rs`; skipped otherwise.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::time::Duration;

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, TypeStore};
use kraken_proto::{
    Composite, ErrorCode, Field, Locator, PageRequest, Primitive, PrimitiveClass, TypeDef, TypeRef,
};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn options() -> WorkerOptions {
    WorkerOptions {
        test_hooks: true,
        request_timeout: Duration::from_secs(3),
        cancel_grace: Duration::from_millis(300),
        ..WorkerOptions::with_program(env!("CARGO_BIN_EXE_kraken-native-worker"))
    }
}

async fn open(opts: WorkerOptions) -> Option<NativeEngine> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = Isolation::Worker(opts);
    let e = NativeEngine::new(c);
    e.open_binary(
        &root().join("corpus/bin/pie_list-O0"),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open in the worker");
    Some(e)
}

fn record() -> TypeDef {
    TypeDef::Struct(Composite {
        name: "worker_rec".into(),
        size: 8,
        align: 4,
        fields: vec![Field {
            name: "id".into(),
            offset: 0,
            ty: TypeRef::Primitive(Primitive {
                class: PrimitiveClass::Int,
                size: 4,
                signed: true,
            }),
            bitfield: None,
        }],
    })
}

async fn alive(e: &NativeEngine) {
    let c = CancellationToken::new();
    let page = e
        .list_functions(&PageRequest::default(), &c)
        .await
        .expect("list after restart");
    assert!(!page.items.is_empty());
    let r = e
        .decompile(&Locator::ram(0x10124e), &c)
        .await
        .expect("decompile after restart");
    assert!(r.text.contains("cmp_id"), "{}", r.text);
}

fn gone(pid: u32) -> bool {
    for _ in 0..100 {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn denied(probe: &Value, key: &str) {
    let v = probe[key].as_str().unwrap_or_default();
    assert_ne!(
        v, "ok",
        "{key} should be refused inside the worker: {probe}"
    );
    assert!(!v.is_empty(), "{key} missing from the probe: {probe}");
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_is_confined() {
    let Some(e) = open(options()).await else {
        return;
    };
    assert!(e.is_isolated());
    let pid = e.worker_pid().expect("worker pid");
    assert_ne!(pid, std::process::id());
    let report = e.confinement().expect("report");
    assert!(report.is_confined(), "{report}");
    assert!(
        report.sockets_denied && report.network_blocked(),
        "{report}"
    );
    let probe = e
        .worker_test_hook("test_probe", &CancellationToken::new())
        .await
        .expect("probe");
    eprintln!("probe: {probe}");
    for key in [
        "tcp_connect",
        "tcp_bind",
        "udp_bind",
        "tcp6_bind",
        "unix_socket",
        "read_etc_passwd",
    ] {
        denied(&probe, key);
    }
    assert_eq!(probe["write_tmp_home"], "ok", "{probe}");
    let mut env: Vec<&str> = probe["env"]
        .as_array()
        .expect("env")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    env.sort_unstable();
    assert_eq!(env, ["HOME", "LANG", "TMPDIR"], "scrubbed environment");
    drop(e);
    assert!(gone(pid), "the worker outlives its engine");
}

#[tokio::test(flavor = "multi_thread")]
async fn hard_deadline_kills_and_restarts_the_worker() {
    let Some(e) = open(WorkerOptions {
        request_timeout: Duration::from_millis(1500),
        ..options()
    })
    .await
    else {
        return;
    };
    let c = CancellationToken::new();
    e.define_type(record(), &c).await.expect("define");
    let first = e.worker_pid().expect("pid");
    let started = std::time::Instant::now();
    let err = e.worker_test_hook("test_hang", &c).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout, "{err}");
    let d = err.details.clone().expect("details");
    assert_eq!(d["worker"], "killed", "{err:?}");
    assert_eq!(d["method"], "test_hang", "{err:?}");
    assert_eq!(d["deadline_ms"], 1500, "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(gone(first), "the hung worker was not killed");
    // the next request restarts the worker, re-opens the program and replays the types
    alive(&e).await;
    let second = e.worker_pid().expect("pid");
    assert_ne!(first, second);
    assert_eq!(e.worker_restarts(), 1);
    assert_eq!(
        e.get_type("worker_rec", &c).await.expect("replayed"),
        record()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn crash_is_reported_and_the_next_request_restarts() {
    let Some(e) = open(options()).await else {
        return;
    };
    let c = CancellationToken::new();
    let first = e.worker_pid().expect("pid");
    let err = e.worker_test_hook("test_crash", &c).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Internal, "{err}");
    let d = err.details.clone().expect("details");
    assert_eq!(d["worker"], "crashed", "{err:?}");
    assert_eq!(d["method"], "test_crash", "{err:?}");
    assert_eq!(d["signal"], libc_sigabrt(), "{err:?}");
    assert!(err.message.contains("signal"), "{err}");
    alive(&e).await;
    assert_ne!(e.worker_pid(), Some(first));
    assert_eq!(e.worker_restarts(), 1);
    // and again: every crash costs one request
    let err = e.worker_test_hook("test_crash", &c).await.unwrap_err();
    assert_eq!(err.details.expect("details")["worker"], "crashed");
    alive(&e).await;
    assert_eq!(e.worker_restarts(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_that_does_not_stop_kills_the_worker() {
    let Some(e) = open(options()).await else {
        return;
    };
    let c = CancellationToken::new();
    let c2 = c.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        c2.cancel();
    });
    let err = e.worker_test_hook("test_hang", &c).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Cancelled, "{err}");
    assert_eq!(err.details.expect("details")["worker"], "killed");
    alive(&e).await;
    assert_eq!(e.worker_restarts(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn nothing_open_and_missing_worker_are_clean_errors() {
    let Some(mut c) = NativeConfig::discover() else {
        return;
    };
    c.isolation = Isolation::Worker(options());
    let e = NativeEngine::new(c.clone());
    let err = e
        .list_functions(&PageRequest::default(), &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument, "{err}");
    assert_eq!(e.worker_pid(), None);

    c.isolation = Isolation::Worker(WorkerOptions::with_program("/nonexistent/worker"));
    let e = NativeEngine::new(c);
    let err = e
        .open_binary(
            &root().join("corpus/bin/pie_list-O0"),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported, "{err}");
    assert!(err.message.contains("does not exist"), "{err}");
}

fn libc_sigabrt() -> i32 {
    6
}

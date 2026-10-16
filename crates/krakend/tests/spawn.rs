//! The built `krakend` binary, started the way clients start it: `ensure_daemon` spawning it with
//! a private runtime directory (`KRAKEN_RUNTIME_DIR`) and the hidden `--fake-engine` flag.

#![cfg(unix)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kraken_host::daemon::{CallParams, DaemonClient, StartOptions};
use kraken_ipc::{ClientKind, DaemonInfo, ENV_RUNTIME_DIR, RuntimeDir};
use kraken_model::AuthorKind;
use serde_json::{Value, json};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json")
}

struct Env {
    tmp: tempfile::TempDir,
    dir: RuntimeDir,
}

fn env() -> Env {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-spawn")
        .tempdir()
        .expect("tempdir");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    Env { tmp, dir }
}

fn start_options(e: &Env, extra_env: &[(&str, &str)]) -> StartOptions {
    let mut env: Vec<(OsString, OsString)> =
        vec![(ENV_RUNTIME_DIR.into(), e.dir.path().as_os_str().to_owned())];
    env.extend(extra_env.iter().map(|(k, v)| ((*k).into(), (*v).into())));
    StartOptions {
        krakend: Some(env!("CARGO_BIN_EXE_krakend").into()),
        extra_args: vec!["--fake-engine".into(), fixture().into_os_string()],
        env,
        timeout: Duration::from_secs(20),
    }
}

async fn connect(e: &Env, opts: &StartOptions) -> DaemonClient {
    DaemonClient::connect_or_start(&e.dir, ClientKind::Cli, env!("CARGO_PKG_VERSION"), opts)
        .await
        .expect("connect or start")
}

fn params(dir: &Path, command: &str, args: Value) -> CallParams {
    CallParams {
        project_dir: dir.to_string_lossy().into_owned(),
        command: command.into(),
        args,
        author_kind: AuthorKind::User,
        author_id: Some("tester".into()),
        run_id: None,
        surface: None,
        approved: false,
    }
}

async fn wait_gone(e: &Env) {
    for _ in 0..400 {
        if !e.dir.info_path().exists() && !e.dir.socket_path().exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the daemon's files were not removed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_starts_the_daemon_once_and_stops_it() {
    let e = env();
    let opts = start_options(&e, &[]);
    assert!(!e.dir.info_path().exists());

    // Eight racing clients: exactly one daemon.
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (dir, opts) = (e.dir.clone(), opts.clone());
        tasks.push(tokio::spawn(async move {
            DaemonClient::connect_or_start(&dir, ClientKind::Cli, env!("CARGO_PKG_VERSION"), &opts)
                .await
                .expect("connect or start")
        }));
    }
    let mut clients = Vec::new();
    for t in tasks {
        clients.push(t.await.unwrap());
    }
    let pid = clients[0].daemon_pid();
    assert!(
        clients.iter().all(|c| c.daemon_pid() == pid),
        "one daemon serves all"
    );
    assert_ne!(pid, std::process::id());
    let info = DaemonInfo::read(&e.dir.info_path()).unwrap().unwrap();
    assert_eq!(info.pid, pid);
    assert_eq!(clients[0].daemon_build(), env!("CARGO_PKG_VERSION"));

    // It serves the fake engine it was told to.
    let c = &clients[0];
    let proj = e.tmp.path().join("proj");
    let bin = e.tmp.path().join("prog.bin");
    std::fs::write(&bin, b"\x7fELF fake").unwrap();
    let created = c
        .call(&params(
            &proj,
            "project_create",
            json!({"binary": bin, "project_dir": proj}),
        ))
        .await
        .unwrap();
    assert_eq!(created.result["program"]["format"], "elf");
    let list = c
        .call(&params(&proj, "list_functions", json!({})))
        .await
        .unwrap();
    assert_eq!(list.result["items"].as_array().unwrap().len(), 3);
    let status = c.status().await.unwrap();
    assert_eq!(status["daemon"]["pid"], pid);
    assert_eq!(status["sessions"].as_array().unwrap().len(), 1);

    // A later client finds the same daemon without starting another.
    let again = connect(&e, &opts).await;
    assert_eq!(again.daemon_pid(), pid);

    // The log file in the runtime dir tells what happened.
    let log = std::fs::read_to_string(e.dir.path().join("krakend.log")).unwrap();
    assert!(log.contains("krakend started"), "{log}");

    c.shutdown().await.unwrap();
    wait_gone(&e).await;
    let log = std::fs::read_to_string(e.dir.path().join("krakend.log")).unwrap();
    assert!(log.contains("krakend stopped"), "{log}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daemon_exits_by_itself_when_idle() {
    let e = env();
    let opts = start_options(&e, &[("KRAKEN_DAEMON_IDLE_SECS", "1")]);
    let c = connect(&e, &opts).await;
    let pid = c.daemon_pid();
    assert!(kraken_ipc::pid_alive(pid));
    drop(c);
    // No clients and no jobs for a second: the daemon leaves and cleans up.
    wait_gone(&e).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_broken_binary_is_reported_not_waited_for() {
    let e = env();
    let mut opts = start_options(&e, &[]);
    opts.extra_args = vec!["--no-such-flag".into()];
    opts.timeout = Duration::from_secs(10);
    let err = DaemonClient::connect_or_start(&e.dir, ClientKind::Cli, "x", &opts)
        .await
        .err()
        .expect("must fail");
    assert!(err.to_string().contains("exited"), "{err}");
}

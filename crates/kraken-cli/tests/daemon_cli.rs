//! The CLI's daemon routing: `kraken daemon ...`, `--no-daemon`, the fallback to direct mode.

#![cfg(unix)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use kraken_cli::{CliEnv, DaemonAuto, DaemonMode};
use kraken_host::KrakenConfig;
use kraken_host::daemon::StartOptions;
use kraken_ipc::{RuntimeDir, SystemClock};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory as DaemonFakeFactory;
use krakend::{Daemon, DaemonOptions};
use serde_json::Value;

struct Rig {
    work: Workdir,
    dir: RuntimeDir,
    daemon: Option<Daemon>,
}

fn rig() -> Rig {
    let work = workdir();
    let dir = RuntimeDir::from_dir(work.tmp.path().join("rt")).expect("runtime dir");
    let daemon = krakend::start(DaemonOptions {
        runtime_dir: dir.clone(),
        factory: Arc::new(DaemonFakeFactory::new(default_named(), Duration::ZERO)),
        registry: Arc::new(Registry::standard()),
        settings: Default::default(),
        session_config: SessionConfig::default(),
        clock: Arc::new(SystemClock::new()),
        poll: Duration::from_millis(20),
        build: kraken_cli::BUILD.into(),
    })
    .expect("daemon starts");
    Rig {
        work,
        dir,
        daemon: Some(daemon),
    }
}

fn env_for(dir: &RuntimeDir, vars: Vec<(&'static str, String)>) -> CliEnv {
    let mut env = fresh_env(KrakenConfig::default(), vars);
    env.daemon = DaemonMode::Auto(DaemonAuto {
        runtime_dir: Some(dir.clone()),
        start: StartOptions {
            krakend: Some("/nonexistent/krakend".into()),
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
    });
    env
}

fn p(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn commands_go_through_a_running_daemon_by_default() {
    let r = rig();
    let env = env_for(&r.dir, vec![]);
    let proj = p(&r.work.tmp.path().join("proj"));
    let created = kraken(
        &env,
        &[
            "--json",
            "project-create",
            "--binary",
            &p(&r.work.binary),
            "--project-dir",
            &proj,
        ],
    )
    .await;
    assert_eq!(created.code, 0, "{}", created.stderr);
    assert!(created.stderr.is_empty(), "no warnings: {}", created.stderr);

    // The edit stays in the daemon's session although the fake engine is not persistent.
    let rename = kraken(
        &env,
        &[
            "--json",
            "--project",
            &proj,
            "rename-symbol",
            "--address",
            "0x401000",
            "--new-name",
            "kept_by_daemon",
        ],
    )
    .await;
    assert_eq!(rename.code, 0, "{}", rename.stderr);
    let list = kraken(
        &env,
        &[
            "--json",
            "--project",
            &proj,
            "list-functions",
            "--name-filter",
            "kept_by",
        ],
    )
    .await;
    assert_eq!(list.json()["items"].as_array().map(Vec::len), Some(1));

    // Errors keep their exit codes.
    let missing = kraken(
        &env,
        &[
            "--json",
            "--project",
            &proj,
            "decompile",
            "--address",
            "0x999",
        ],
    )
    .await;
    assert_eq!(missing.code, 3, "{}", missing.stderr);
    let none = kraken(&env, &["--json", "list-functions"]).await;
    assert_eq!(none.code, 2, "{}", none.stderr);
    r.daemon.as_ref().unwrap().shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_status_stop_and_start() {
    let mut r = rig();
    let env = env_for(&r.dir, vec![]);
    let proj = p(&r.work.tmp.path().join("proj"));
    kraken(
        &env,
        &[
            "--json",
            "project-create",
            "--binary",
            &p(&r.work.binary),
            "--project-dir",
            &proj,
        ],
    )
    .await;

    let st = kraken(&env, &["--json", "daemon", "status"]).await;
    assert_eq!(st.code, 0, "{}", st.stderr);
    let v = st.json();
    assert_eq!(v["running"], true);
    assert_eq!(v["sessions"].as_array().map(Vec::len), Some(1));
    assert_eq!(v["daemon"]["build"], kraken_cli::BUILD);

    let human = kraken(&env, &["daemon", "status"]).await;
    assert_eq!(human.code, 0);
    assert!(human.stdout.contains("running"), "{}", human.stdout);
    assert!(human.stdout.contains("proj"), "{}", human.stdout);
    assert!(human.stdout.contains("engine "), "{}", human.stdout);

    let started = kraken(&env, &["--json", "daemon", "start"]).await;
    assert_eq!(started.code, 0, "{}", started.stderr);
    assert_eq!(started.json()["started"], false, "already running");

    let stop = kraken(&env, &["--json", "daemon", "stop"]).await;
    assert_eq!(stop.code, 0, "{}", stop.stderr);
    assert_eq!(stop.json()["stopped"], true);
    let d = r.daemon.take().unwrap();
    tokio::time::timeout(Duration::from_secs(10), d.wait())
        .await
        .expect("the daemon is gone");

    let after = kraken(&env, &["--json", "daemon", "status"]).await;
    assert_eq!(after.code, 0);
    assert_eq!(after.json()["running"], false);
    let human = kraken(&env, &["daemon", "status"]).await;
    assert!(human.stdout.contains("not running"));
    let again = kraken(&env, &["daemon", "stop"]).await;
    assert_eq!(again.code, 0);
    assert!(again.stdout.contains("not running"));
}

#[tokio::test(flavor = "multi_thread")]
async fn no_daemon_flag_and_variable_keep_the_command_in_process() {
    let r = rig();
    let proj_flag = p(&r.work.tmp.path().join("by-flag"));
    let env = env_for(&r.dir, vec![]);
    let out = kraken(
        &env,
        &[
            "--no-daemon",
            "--json",
            "project-create",
            "--binary",
            &p(&r.work.binary),
            "--project-dir",
            &proj_flag,
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.stderr);

    let env_var = env_for(&r.dir, vec![("KRAKEN_NO_DAEMON", "1".into())]);
    let proj_var = p(&r.work.tmp.path().join("by-var"));
    let out = kraken(
        &env_var,
        &[
            "--json",
            "project-create",
            "--binary",
            &p(&r.work.binary),
            "--project-dir",
            &proj_var,
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.stderr);

    let st = kraken(&env, &["--json", "daemon", "status"]).await.json();
    assert_eq!(
        st["sessions"].as_array().map(Vec::len),
        Some(0),
        "the daemon saw nothing: {st}"
    );
    r.daemon.as_ref().unwrap().shutdown();
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unstartable_daemon_falls_back_to_direct_mode_with_a_warning() {
    let work = workdir();
    // Nothing runs in this runtime dir and the krakend path does not exist.
    let dir = RuntimeDir::from_dir(work.tmp.path().join("rt")).expect("runtime dir");
    let env = env_for(&dir, vec![]);
    let proj = p(&work.tmp.path().join("proj"));
    let out = kraken(
        &env,
        &[
            "--json",
            "project-create",
            "--binary",
            &p(&work.binary),
            "--project-dir",
            &proj,
        ],
    )
    .await;
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stderr.contains("cannot use krakend"), "{}", out.stderr);
    assert!(out.stderr.contains("--no-daemon"), "{}", out.stderr);
    let v: Value = out.json();
    assert_eq!(v["program"]["format"], "elf");
    // `daemon start` has no fallback: it reports the failure.
    let start = kraken(&env, &["daemon", "start"]).await;
    assert_ne!(start.code, 0);
    assert!(start.stderr.contains("krakend"), "{}", start.stderr);
}

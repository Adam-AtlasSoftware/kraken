//! `kraken infer ...`: argument parsing, the daemon path against an in-process krakend that hosts
//! the fake inference server, `--use` writing the provider into a temporary config, and the
//! `--no-daemon` path. No network, no real model, no developer daemon.

#![cfg(unix)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::*;
use kraken_cli::{CliEnv, DaemonAuto, DaemonMode, build_cli};
use kraken_host::KrakenConfig;
use kraken_host::daemon::StartOptions;
use kraken_host::infer::InferManager;
use kraken_infer::testing::{fake_manifest, fake_server_path};
use kraken_infer::{BackendRegistry, GenericOpenAiServerBackend};
use kraken_ipc::{RuntimeDir, SystemClock};
use kraken_registry::{Registry, SessionConfig};
use krakend::fake::FakeFactory as DaemonFakeFactory;
use krakend::{Daemon, DaemonOptions};

const GIB: u64 = 1024 * 1024 * 1024;

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

struct Rig {
    work: Workdir,
    dir: RuntimeDir,
    config: PathBuf,
    model: PathBuf,
    daemon: Option<Daemon>,
}

fn rig() -> Rig {
    let work = workdir();
    let dir = RuntimeDir::from_dir(work.tmp.path().join("rt")).expect("runtime dir");
    let mut reg = BackendRegistry::new();
    reg.register(Arc::new(
        GenericOpenAiServerBackend::from_manifest_str(&fake_manifest("fake", &fake_server_path()))
            .expect("manifest"),
    ));
    let infer = Arc::new(InferManager::with_registry(reg).with_total_memory(8 * GIB, None));
    let daemon = krakend::start_with_infer(
        DaemonOptions {
            runtime_dir: dir.clone(),
            factory: Arc::new(DaemonFakeFactory::new(default_named(), Duration::ZERO)),
            registry: Arc::new(Registry::standard()),
            settings: Default::default(),
            session_config: SessionConfig::default(),
            clock: Arc::new(SystemClock::new()),
            poll: Duration::from_millis(20),
            build: kraken_cli::BUILD.into(),
        },
        infer,
    )
    .expect("daemon starts");
    let model = work.tmp.path().join("tiny.gguf");
    std::fs::write(&model, vec![0u8; 2048]).expect("model");
    Rig {
        config: work.tmp.path().join("config.toml"),
        work,
        dir,
        model,
        daemon: Some(daemon),
    }
}

impl Rig {
    fn env(&self) -> CliEnv {
        let mut env = fresh_env(
            KrakenConfig::default(),
            vec![
                ("KRAKEN_CONFIG", s(&self.config)),
                ("XDG_DATA_HOME", s(&self.work.tmp.path().join("data"))),
                ("HOME", s(&self.work.tmp.path().join("home"))),
            ],
        );
        env.daemon = DaemonMode::Auto(DaemonAuto {
            runtime_dir: Some(self.dir.clone()),
            start: StartOptions {
                krakend: Some("/nonexistent/krakend".into()),
                timeout: Duration::from_secs(2),
                ..Default::default()
            },
        });
        env
    }

    async fn finish(mut self) {
        let d = self.daemon.take().expect("daemon");
        d.shutdown();
        tokio::time::timeout(Duration::from_secs(10), d.wait())
            .await
            .expect("daemon stops");
    }
}

#[test]
fn the_command_line_parses() {
    let cli = build_cli(&Registry::standard());
    let m = cli
        .clone()
        .try_get_matches_from([
            "kraken",
            "infer",
            "start",
            "llama-server",
            "--model",
            "m.gguf",
            "--set",
            "gpu_layers=99",
            "--set",
            "n_cpu_moe=30",
            "--use",
        ])
        .expect("parses");
    let (_, infer) = m.subcommand().expect("infer");
    let (name, start) = infer.subcommand().expect("start");
    assert_eq!(name, "start");
    assert_eq!(start.get_one::<String>("engine").unwrap(), "llama-server");
    assert_eq!(start.get_one::<String>("model").unwrap(), "m.gguf");
    let sets: Vec<&String> = start.get_many::<String>("set").unwrap().collect();
    assert_eq!(sets, ["gpu_layers=99", "n_cpu_moe=30"]);
    assert!(start.get_flag("use") && !start.get_flag("no-wait"));

    for ok in [
        vec!["infer", "list"],
        vec!["infer", "status"],
        vec!["infer", "stop"],
        vec!["infer", "logs", "--tail", "5", "--follow"],
        vec!["infer", "setup", "llama", "--variant", "vulkan", "--yes"],
        vec!["infer", "start", "x", "--no-wait"],
    ] {
        let argv: Vec<&str> = std::iter::once("kraken")
            .chain(ok.iter().copied())
            .collect();
        cli.clone()
            .try_get_matches_from(argv)
            .unwrap_or_else(|e| panic!("{ok:?}: {e}"));
    }
    for bad in [
        vec!["infer"],
        vec!["infer", "start"],
        vec!["infer", "setup"],
        vec!["infer", "start", "x", "--use", "--no-wait"],
        vec!["infer", "frobnicate"],
    ] {
        let argv: Vec<&str> = std::iter::once("kraken")
            .chain(bad.iter().copied())
            .collect();
        assert!(cli.clone().try_get_matches_from(argv).is_err(), "{bad:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn list_start_use_status_logs_stop_through_the_daemon() {
    let r = rig();
    let env = r.env();
    // Other settings in the file survive `--use`.
    std::fs::write(&r.config, "max_heap_mb = 2048\n").unwrap();

    let list = kraken(&env, &["--json", "infer", "list"]).await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert_eq!(list.json()["backends"][0]["id"], "fake");
    let human = kraken(&env, &["infer", "list"]).await;
    assert_eq!(human.code, 0, "{}", human.stderr);
    assert!(human.stdout.contains("fake"), "{}", human.stdout);
    assert!(
        human.stdout.contains("model (string, required)"),
        "{}",
        human.stdout
    );

    let model = s(&r.model);
    let started = kraken(
        &env,
        &[
            "--json",
            "infer",
            "start",
            "fake",
            "--model",
            &model,
            "--set",
            "ready_after=0.4",
            "--set",
            "ctx=2048",
            "--set",
            "flash=off",
            "--use",
        ],
    )
    .await;
    assert_eq!(started.code, 0, "{}", started.stderr);
    let v = started.json();
    assert_eq!(v["ready"], true);
    let url = v["base_url"].as_str().unwrap().to_string();
    assert!(url.starts_with("http://127.0.0.1:"), "{url}");

    let cfg = std::fs::read_to_string(&r.config).unwrap();
    let parsed = KrakenConfig::from_toml(&cfg).unwrap();
    assert_eq!(parsed.max_heap_mb, Some(2048), "{cfg}");
    let provider = parsed.provider.expect("provider table");
    assert_eq!(provider["kind"], "openai_compatible");
    assert_eq!(provider["base_url"], url.as_str());
    assert_eq!(provider["model"], "tiny.gguf");
    // The same table is accepted by the assistant's provider loader.
    kraken_agent::ProviderConfig::from_toml(&cfg).expect("a valid [provider]");

    let st = kraken(&env, &["--json", "infer", "status"]).await;
    assert_eq!(st.code, 0, "{}", st.stderr);
    assert_eq!(st.json()["phase"], "ready");
    let st = kraken(&env, &["infer", "status"]).await;
    assert!(st.stdout.contains("ready"), "{}", st.stdout);
    assert!(st.stdout.contains(&url), "{}", st.stdout);

    let logs = kraken(&env, &["infer", "logs", "--tail", "50"]).await;
    assert_eq!(logs.code, 0, "{}", logs.stderr);
    assert!(logs.stdout.contains("listening on"), "{}", logs.stdout);

    // The daemon status counts the model.
    let ds = kraken(&env, &["--json", "daemon", "status"]).await;
    assert_eq!(ds.code, 0, "{}", ds.stderr);
    assert_eq!(ds.json()["daemon"]["loaded_models"], 1);

    let stop = kraken(&env, &["infer", "stop"]).await;
    assert_eq!(stop.code, 0, "{}", stop.stderr);
    assert!(stop.stdout.contains("Stopped"), "{}", stop.stdout);
    let again = kraken(&env, &["infer", "stop"]).await;
    assert!(
        again.stdout.contains("No model was running"),
        "{}",
        again.stdout
    );
    r.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn mistakes_are_explained_and_use_needs_the_model_to_be_ready() {
    let r = rig();
    let env = r.env();
    let model = s(&r.model);

    let e = kraken(&env, &["infer", "start", "nope", "--model", &model]).await;
    assert_eq!(e.code, 3, "{}", e.stderr);
    assert!(e.stderr.contains("fake"), "{}", e.stderr);

    let e = kraken(
        &env,
        &[
            "infer", "start", "fake", "--model", &model, "--set", "bogus=1",
        ],
    )
    .await;
    assert_eq!(e.code, 2, "{}", e.stderr);
    assert!(e.stderr.contains("model, ready_after, ctx"), "{}", e.stderr);

    let e = kraken(
        &env,
        &[
            "infer", "start", "fake", "--model", &model, "--set", "ctx=lots",
        ],
    )
    .await;
    assert_eq!(e.code, 2, "{}", e.stderr);
    assert!(e.stderr.contains("whole number"), "{}", e.stderr);

    // No model setting given: the engine's own error comes back.
    let e = kraken(&env, &["infer", "start", "fake"]).await;
    assert_eq!(e.code, 2, "{}", e.stderr);
    assert!(e.stderr.contains("model"), "{}", e.stderr);
    assert!(!r.config.exists(), "nothing written on failure");

    // A relative model path is made absolute before it reaches the daemon.
    let rel = pathdiff(&r.model);
    let e = kraken(
        &env,
        &["infer", "start", "fake", "--model", &rel, "--no-wait"],
    )
    .await;
    assert_eq!(e.code, 0, "{}", e.stderr);
    let stop = kraken(&env, &["infer", "stop"]).await;
    assert_eq!(stop.code, 0);
    r.finish().await;
}

/// A path to `p` relative to the current directory.
fn pathdiff(p: &Path) -> String {
    let cwd = std::env::current_dir().unwrap();
    let mut up = PathBuf::new();
    for _ in cwd.components().skip(1) {
        up.push("..");
    }
    s(&up.join(p.strip_prefix("/").unwrap()))
}

#[tokio::test(flavor = "multi_thread")]
async fn read_only_commands_without_a_daemon_do_not_start_one() {
    let work = workdir();
    let dir = RuntimeDir::from_dir(work.tmp.path().join("rt")).expect("runtime dir");
    let mut env = fresh_env(
        KrakenConfig::default(),
        vec![
            ("XDG_DATA_HOME", s(&work.tmp.path().join("data"))),
            ("HOME", s(&work.tmp.path().join("home"))),
            ("PATH", "/nonexistent-kraken".into()),
        ],
    );
    env.daemon = DaemonMode::Auto(DaemonAuto {
        runtime_dir: Some(dir.clone()),
        start: StartOptions {
            krakend: Some("/nonexistent/krakend".into()),
            timeout: Duration::from_secs(2),
            ..Default::default()
        },
    });
    let st = kraken(&env, &["infer", "status"]).await;
    assert_eq!(st.code, 0, "{}", st.stderr);
    assert!(st.stdout.contains("No krakend is running"), "{}", st.stdout);
    let st = kraken(&env, &["--json", "infer", "status"]).await;
    assert_eq!(st.json()["running"], false);

    let e = kraken(&env, &["infer", "stop"]).await;
    assert_eq!(e.code, 3, "{}", e.stderr);
    let e = kraken(&env, &["infer", "logs"]).await;
    assert_eq!(e.code, 3, "{}", e.stderr);

    // `list` works from this process alone and says how to get llama-server.
    let l = kraken(&env, &["infer", "list"]).await;
    assert_eq!(l.code, 0, "{}", l.stderr);
    assert!(l.stdout.contains("llama-server"), "{}", l.stdout);
    assert!(
        l.stdout.contains("kraken infer setup llama"),
        "{}",
        l.stdout
    );
    assert!(!dir.socket_path().exists(), "no daemon was started");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_daemon_runs_the_model_inside_the_command_and_still_writes_the_provider() {
    let work = workdir();
    let manifests = work.tmp.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    std::fs::write(
        manifests.join("fake.toml"),
        fake_manifest("fake", &fake_server_path()),
    )
    .unwrap();
    let model = work.tmp.path().join("m.gguf");
    std::fs::write(&model, [0u8; 64]).unwrap();
    let config = work.tmp.path().join("cfg/config.toml");
    let env = fresh_env(
        KrakenConfig::default(),
        vec![
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_INFER_MANIFESTS", s(&manifests)),
            ("KRAKEN_CONFIG", s(&config)),
            ("XDG_DATA_HOME", s(&work.tmp.path().join("data"))),
            ("HOME", s(&work.tmp.path().join("home"))),
        ],
    );
    let r = kraken(
        &env,
        &["infer", "start", "fake", "--model", &s(&model), "--use"],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("Ready at http://127.0.0.1:"),
        "{}",
        r.stdout
    );
    assert!(
        r.stderr.contains("stops when this command ends"),
        "{}",
        r.stderr
    );
    let cfg = std::fs::read_to_string(&config).expect("config written");
    assert!(cfg.contains("openai_compatible"), "{cfg}");
    assert!(cfg.contains("m.gguf"), "{cfg}");
}

#[tokio::test(flavor = "multi_thread")]
async fn setup_llama_asks_before_downloading_and_rejects_unknown_variants() {
    let work = workdir();
    let env = fresh_env(
        KrakenConfig::default(),
        vec![
            ("XDG_DATA_HOME", s(&work.tmp.path().join("data"))),
            ("HOME", s(&work.tmp.path().join("home"))),
        ],
    );
    // Tests run without a terminal on stdin: no approval, no download.
    let r = kraken(&env, &["infer", "setup", "llama"]).await;
    assert_eq!(r.code, 2, "{}", r.stderr);
    assert!(r.stderr.contains("--yes"), "{}", r.stderr);
    let r = kraken(
        &env,
        &["infer", "setup", "llama", "--variant", "does-not-exist"],
    )
    .await;
    assert_ne!(r.code, 0);
    assert!(
        r.stderr.contains("does-not-exist") || r.stderr.contains("no pinned"),
        "{}",
        r.stderr
    );
    assert!(!work.tmp.path().join("data/kraken/llama/downloads").exists());
}

/// A computer with one model set up, `llama-server` being the fake inference server.
fn llama_rig(role: bool) -> (Workdir, CliEnv, PathBuf) {
    let work = workdir();
    let bin = work.tmp.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(fake_server_path(), bin.join("llama-server")).unwrap();
    let model = work.tmp.path().join("tiny.gguf");
    std::fs::write(&model, [0u8; 64]).unwrap();
    let config = work.tmp.path().join("cfg/config.toml");
    let mut cfg = KrakenConfig::default();
    cfg.local_models.push(kraken_host::infer::new_local_model(
        "tiny",
        kraken_proto::infer::LocalEngine::Llama,
        model,
    ));
    if role {
        cfg.provider = Some(kraken_host::infer::local_provider_table("tiny"));
    }
    cfg.save(&config).unwrap();
    let env = fresh_env(
        KrakenConfig::default(),
        vec![
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_CONFIG", s(&config)),
            ("PATH", s(&bin)),
            ("XDG_DATA_HOME", s(&work.tmp.path().join("data"))),
            ("HOME", s(&work.tmp.path().join("home"))),
        ],
    );
    (work, env, config)
}

#[tokio::test(flavor = "multi_thread")]
async fn infer_start_by_model_id_is_a_pinned_start_and_use_writes_the_local_form() {
    let (_work, env, config) = llama_rig(false);
    let r = kraken(&env, &["infer", "start", "tiny", "--use"]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout.contains("Ready: tiny at http://127.0.0.1:"),
        "{}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("key"),
        "the per-run key stays private: {}",
        r.stdout
    );
    let cfg = KrakenConfig::from_file(&config).unwrap();
    assert_eq!(
        cfg.provider,
        Some(kraken_host::infer::local_provider_table("tiny"))
    );
    let unknown = kraken(&env, &["infer", "start", "nope"]).await;
    assert_eq!(unknown.code, 3, "{}", unknown.stderr);
    assert!(unknown.stderr.contains("tiny"), "{}", unknown.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn infer_start_with_an_engine_and_use_adds_a_model_entry() {
    let (work, env, config) = llama_rig(false);
    let file = work.tmp.path().join("other.gguf");
    std::fs::write(&file, [0u8; 64]).unwrap();
    let r = kraken(
        &env,
        &[
            "infer",
            "start",
            "llama-server",
            "--model",
            &s(&file),
            "--set",
            "context_size=2048",
            "--use",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{} {}", r.stderr, r.stdout);
    let cfg = KrakenConfig::from_file(&config).unwrap();
    let m = cfg
        .local_models
        .iter()
        .find(|m| m.id == "other")
        .expect("model entry added");
    assert_eq!(m.model_path, file);
    assert_eq!(
        cfg.provider,
        Some(kraken_host::infer::local_provider_table("other"))
    );
    assert_eq!(cfg.local_models.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn infer_start_use_takes_the_model_file_from_set_too() {
    let (work, env, config) = llama_rig(false);
    let file = work.tmp.path().join("viaset.gguf");
    std::fs::write(&file, [0u8; 64]).unwrap();
    let r = kraken(
        &env,
        &[
            "infer",
            "start",
            "llama-server",
            "--set",
            &format!("model_path={}", s(&file)),
            "--use",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{} {}", r.stderr, r.stdout);
    let cfg = KrakenConfig::from_file(&config).unwrap();
    let m = cfg
        .local_models
        .iter()
        .find(|m| m.id == "viaset")
        .expect("model entry added");
    assert_eq!(m.model_path, file);
    assert!(
        m.extra.is_none(),
        "the file is not kept as an extra setting"
    );
    assert_eq!(
        cfg.provider,
        Some(kraken_host::infer::local_provider_table("viaset"))
    );
    // Neither --model nor the setting: the message says both ways.
    let r = kraken(&env, &["infer", "start", "llama-server", "--use"]).await;
    assert_ne!(r.code, 0);
    assert!(r.stderr.contains("--set model_path=<file>"), "{}", r.stderr);
}

#[tokio::test(flavor = "multi_thread")]
async fn serve_local_holds_the_role_model_while_the_command_runs() {
    let (_work, env, _config) = llama_rig(true);
    let r = kraken(
        &env,
        &[
            "--serve-local",
            "--json",
            "local-model-status",
            "--model",
            "tiny",
        ],
    )
    .await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stderr.contains("serving local model tiny"),
        "{}",
        r.stderr
    );
    let v = r.json();
    // Held, so started: it may still be loading when the status is read.
    let state = v["model"]["state"]["kind"].as_str().unwrap_or_default();
    assert!(matches!(state, "loading" | "ready"), "{v}");
    assert_eq!(v["model"]["holders"], 1, "{v}");
    assert!(!v.to_string().contains("api_key"), "{v}");
    // Without the flag nothing starts the model.
    let (_w2, env2, _c2) = llama_rig(true);
    let r = kraken(&env2, &["--json", "local-model-status", "--model", "tiny"]).await;
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.json()["model"]["state"]["kind"], "stopped");
}

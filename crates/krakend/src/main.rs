//! The `krakend` binary. Clients start it on demand (`kraken_host::daemon::spawn_krakend`); it
//! exits by itself after the idle timeout.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use kraken_host::{GhidraEngineFactory, KrakenConfig, ManagedFactory};
use kraken_ipc::{RuntimeDir, SystemClock};
use kraken_registry::Registry;
use krakend::logfile::{DEFAULT_KEEP, DEFAULT_MAX_BYTES, RotatingLog};
use krakend::{DaemonError, DaemonOptions};
use tracing_subscriber::EnvFilter;

const HELP: &str = "krakend: the KRAKEN daemon

Normally started on demand by `kraken`; it exits after the idle timeout.

USAGE: krakend [--log-stderr] [--help] [--version]

  --log-stderr   log to stderr instead of <runtime dir>/krakend.log

Configuration comes from ~/.config/kraken/config.toml ([daemon] idle_secs, session_idle_secs,
max_sessions) and the environment (KRAKEN_DAEMON_IDLE_SECS, KRAKEN_SESSION_IDLE_SECS,
KRAKEN_MAX_SESSIONS, KRAKEN_RUNTIME_DIR, KRAKEN_LOG, KRAKEN_GHIDRA_HOME, ...).
";

struct Args {
    log_stderr: bool,
    fake_engine: Option<PathBuf>,
    fake_stage_delay_ms: u64,
}

fn parse_args() -> Result<Args, ExitCode> {
    let mut a = Args {
        log_stderr: false,
        // Hidden, for tests of binaries that start the daemon without extra arguments.
        fake_engine: std::env::var_os("KRAKEN_FAKE_ENGINE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from),
        fake_stage_delay_ms: std::env::var("KRAKEN_FAKE_STAGE_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{HELP}");
                return Err(ExitCode::SUCCESS);
            }
            "--version" | "-V" => {
                println!("krakend {}", env!("CARGO_PKG_VERSION"));
                return Err(ExitCode::SUCCESS);
            }
            "--log-stderr" => a.log_stderr = true,
            // Hidden, for tests: serve a fixture through the scripted fake engine.
            "--fake-engine" => match it.next() {
                Some(p) => a.fake_engine = Some(PathBuf::from(p)),
                None => {
                    eprintln!("krakend: --fake-engine needs a fixture path");
                    return Err(ExitCode::from(2));
                }
            },
            "--fake-stage-delay-ms" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => a.fake_stage_delay_ms = n,
                None => {
                    eprintln!("krakend: --fake-stage-delay-ms needs a number");
                    return Err(ExitCode::from(2));
                }
            },
            other => {
                eprintln!("krakend: unknown argument `{other}`\n\n{HELP}");
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(a)
}

fn init_logging(dir: &RuntimeDir, to_stderr: bool) {
    let filter = EnvFilter::try_from_env("KRAKEN_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    if !to_stderr
        && let Ok(log) = RotatingLog::open(
            dir.path().join("krakend.log"),
            DEFAULT_MAX_BYTES,
            DEFAULT_KEEP,
        )
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(log)
            .init();
        return;
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(feature = "fake-engine")]
fn fake_factory(a: &Args) -> Result<Option<Arc<dyn ManagedFactory>>, String> {
    let Some(path) = &a.fake_engine else {
        return Ok(None);
    };
    let fixture = engine_fake::FixtureFile::from_path(path)
        .map_err(|e| format!("cannot load fixture {}: {}", path.display(), e.message))?;
    Ok(Some(Arc::new(krakend::fake::FakeFactory::new(
        fixture,
        Duration::from_millis(a.fake_stage_delay_ms),
    ))))
}

#[cfg(not(feature = "fake-engine"))]
fn fake_factory(a: &Args) -> Result<Option<Arc<dyn ManagedFactory>>, String> {
    if a.fake_engine.is_some() {
        return Err("this build has no fake engine".into());
    }
    Ok(None)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };
    let dir = match RuntimeDir::resolve() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("krakend: {e}");
            return ExitCode::from(1);
        }
    };
    init_logging(&dir, args.log_stderr);
    std::panic::set_hook(Box::new(|info| tracing::error!("panic: {info}")));

    let config = match KrakenConfig::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("krakend: {e}");
            return ExitCode::from(2);
        }
    };
    let factory: Arc<dyn ManagedFactory> = match fake_factory(&args) {
        Ok(Some(f)) => f,
        Ok(None) => Arc::new(GhidraEngineFactory::new(config.clone())),
        Err(e) => {
            tracing::error!("{e}");
            eprintln!("krakend: {e}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("krakend: cannot start the async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let opts = DaemonOptions {
        runtime_dir: dir,
        factory,
        registry: Arc::new(Registry::standard()),
        settings: config.daemon.clone(),
        session_config: config.session_config(),
        clock: Arc::new(SystemClock::new()),
        poll: Duration::from_millis(250),
        build: env!("CARGO_PKG_VERSION").to_string(),
    };
    runtime.block_on(async move {
        let daemon = match krakend::start_with(
            opts,
            Some(kraken_rewrite::RewriteService::standard().into_backend()),
        ) {
            Ok(d) => d,
            Err(DaemonError::AlreadyRunning) => {
                tracing::info!("another krakend is already running");
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                tracing::error!("cannot start: {e}");
                eprintln!("krakend: {e}");
                return ExitCode::from(1);
            }
        };
        tracing::info!(
            pid = std::process::id(),
            build = env!("CARGO_PKG_VERSION"),
            "krakend started"
        );
        wait_for_signal_then_stop(&daemon);
        daemon.wait().await;
        ExitCode::SUCCESS
    })
}

/// Stops the daemon on SIGINT / SIGTERM (Ctrl-C elsewhere).
fn wait_for_signal_then_stop(daemon: &krakend::Daemon) {
    let stop = daemon.stop_handle();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let (Ok(mut term), Ok(mut int)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) else {
                return;
            };
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        tracing::info!("signal received, stopping");
        stop.trigger();
    });
}

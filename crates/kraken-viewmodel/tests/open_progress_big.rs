//! The loading progress of big programs, measured through the GUI view-model and a spawned
//! `krakend` with the native engine: time to the first update, the update rate, whether the
//! fraction only grows and ends at 100 %, the total time, the reopen time, and that Cancel stops an
//! open in the middle (no worker left, no session left).
//!
//! Ignored: a first open of a big library takes minutes and a lot of memory. Run one program at a
//! time against a release build:
//!
//! ```text
//! cargo build --release -p krakend -p engine-native --bins
//! KRAKEN_KRAKEND=target/release/krakend KRAKEN_BIG_BINARIES=/tmp/x/libpython3.14.so.1.0 \
//!   cargo test -p kraken-viewmodel --test open_progress_big -- --ignored --nocapture
//! ```
//!
//! `KRAKEN_BIG_BINARIES` is a `:`-separated list (copies of system files, never the originals);
//! `KRAKEN_BIG_DIR` is the scratch folder for the projects (a short path: socket paths are limited
//! to 100 bytes); `KRAKEN_BIG_SKIP_CANCEL=1` leaves the cancel check out.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_host::daemon::{StartOptions, find_krakend, wait_until_stopped};
use kraken_ipc::{DaemonInfo, RuntimeDir};
use kraken_proto::OpenStage;
use kraken_registry::EngineChoice;
use kraken_viewmodel::{
    BackendOptions, Connection, DaemonClientBackend, ViewModel, start_connector,
};

const OPEN_LIMIT: Duration = Duration::from_secs(3 * 3600);

struct Daemon {
    rt: Arc<tokio::runtime::Runtime>,
    dir: RuntimeDir,
    backend: Arc<DaemonClientBackend>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let b = self.backend.clone();
        self.rt.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(5), b.shutdown_daemon()).await;
        });
        let stopped = self
            .rt
            .block_on(wait_until_stopped(&self.dir, Duration::from_secs(30)));
        if !stopped && let Ok(Some(info)) = DaemonInfo::read(&self.dir.info_path()) {
            let _ = std::process::Command::new("kill")
                .arg(info.pid.to_string())
                .status();
        }
    }
}

/// One progress report as the view-model saw it.
#[derive(Debug, Clone)]
struct Sample {
    at: Duration,
    stage: OpenStage,
    fraction: Option<f64>,
    found: Option<u64>,
    from_cache: bool,
}

/// What one open looked like.
#[derive(Debug)]
struct Run {
    samples: Vec<Sample>,
    total: Duration,
    ok: bool,
}

impl Run {
    fn summary(&self, what: &str) -> String {
        let first = self.samples.first().map_or(-1.0, |s| s.at.as_secs_f64());
        let n = self.samples.len();
        let span = match (self.samples.first(), self.samples.last()) {
            (Some(a), Some(b)) => (b.at - a.at).as_secs_f64(),
            _ => 0.0,
        };
        let rate = if span > 0.0 {
            (n as f64 - 1.0) / span
        } else {
            0.0
        };
        let gap = self
            .samples
            .windows(2)
            .map(|w| (w[1].at - w[0].at).as_secs_f64())
            .fold(0.0, f64::max);
        let fractions: Vec<f64> = self.samples.iter().filter_map(|s| s.fraction).collect();
        let monotonic = fractions.windows(2).all(|w| w[0] <= w[1]);
        let last = fractions.last().copied().unwrap_or(0.0);
        let indeterminate = self.samples.iter().filter(|s| s.fraction.is_none()).count();
        let found = self
            .samples
            .iter()
            .filter_map(|s| s.found)
            .max()
            .unwrap_or(0);
        let cached = self.samples.iter().any(|s| s.from_cache);
        let mut stages: Vec<&str> = Vec::new();
        for s in &self.samples {
            if stages.last() != Some(&s.stage.as_str()) {
                stages.push(s.stage.as_str());
            }
        }
        let stages = stages.join(">");
        format!(
            "{what}: ok={} total={:.1}s first_update={first:.2}s updates={n} rate={rate:.2}/s \
             max_gap={gap:.1}s monotonic={monotonic} last_fraction={last:.3} \
             indeterminate_updates={indeterminate} max_found={found} saved_results={cached} stages={stages}",
            self.ok,
            self.total.as_secs_f64(),
        )
    }
}

/// Watches the view-model until the open ends, recording every new report.
fn watch(vm: &mut ViewModel, started: Instant) -> Run {
    let mut samples: Vec<Sample> = Vec::new();
    let mut last_update: Option<Instant> = None;
    while started.elapsed() < OPEN_LIMIT {
        vm.poll();
        if let Some(l) = &vm.loading
            && l.updated != last_update
        {
            last_update = l.updated;
            if let Some(p) = &l.progress {
                samples.push(Sample {
                    at: started.elapsed(),
                    stage: p.stage,
                    fraction: p.fraction,
                    found: p.found,
                    from_cache: p.from_cache,
                });
            }
        }
        if !matches!(vm.connection, Connection::Opening(_)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Run {
        samples,
        total: started.elapsed(),
        ok: vm.connection == Connection::Open,
    }
}

/// Every `open_progress` event the daemon sent, with when it arrived.
type Events = Arc<std::sync::Mutex<Vec<(Instant, serde_json::Value)>>>;

/// The raw event stream of one open: how many, how often, and whether the fraction only grew to 1.
fn raw_summary(events: &Events, project: &Path, since: Instant) -> String {
    let key = kraken_host::daemon::canonical_prefix(project);
    let evs: Vec<(Instant, serde_json::Value)> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|(at, v)| {
            *at >= since && v["project_dir"].as_str().map(Path::new) == Some(key.as_path())
        })
        .cloned()
        .collect();
    let n = evs.len();
    let first = evs
        .first()
        .map_or(-1.0, |(at, _)| (*at - since).as_secs_f64());
    let gap = evs
        .windows(2)
        .map(|w| (w[1].0 - w[0].0).as_secs_f64())
        .fold(0.0, f64::max);
    let span = match (evs.first(), evs.last()) {
        (Some(a), Some(b)) => (b.0 - a.0).as_secs_f64(),
        _ => 0.0,
    };
    let fractions: Vec<f64> = evs
        .iter()
        .filter_map(|(_, v)| v["fraction"].as_f64())
        .collect();
    let monotonic = fractions.windows(2).all(|w| w[0] <= w[1]);
    let last = evs.last().map(|(_, v)| {
        format!(
            "{} {}",
            v["stage"].as_str().unwrap_or("?"),
            v["fraction"].as_f64().unwrap_or(-1.0)
        )
    });
    format!(
        "events={n} first_event={first:.2}s rate={:.2}/s max_gap={gap:.1}s monotonic={monotonic} \
         last={}",
        if span > 0.0 {
            (n as f64 - 1.0) / span
        } else {
            0.0
        },
        last.unwrap_or_default()
    )
}

/// Running copies of this build's worker (other checkouts' workers do not count).
fn workers(worker: &Path) -> usize {
    std::process::Command::new("pgrep")
        .args(["-c", "-f"])
        .arg(worker)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
#[ignore = "opens big programs for minutes; run by hand (see the module docs)"]
fn big_programs_report_honest_progress_and_cancel_cleanly() {
    let binaries: Vec<PathBuf> = std::env::var("KRAKEN_BIG_BINARIES")
        .expect("set KRAKEN_BIG_BINARIES")
        .split(':')
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect();
    let krakend = find_krakend().expect("set KRAKEN_KRAKEND to a release krakend");
    let worker = krakend.with_file_name("kraken-native-worker");
    assert!(worker.is_file(), "no kraken-native-worker next to krakend");
    let worker_path = worker.clone();
    let scratch = std::env::var_os("KRAKEN_BIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let tmp = tempfile::Builder::new()
        .prefix("kb")
        .tempdir_in(&scratch)
        .expect("temp dir");
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "").expect("empty config");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let start = StartOptions {
        krakend: Some(krakend),
        env: vec![
            ("KRAKEN_RUNTIME_DIR".into(), dir.path().into()),
            ("KRAKEN_CONFIG".into(), config.into()),
            ("KRAKEN_DAEMON_IDLE_SECS".into(), "36000".into()),
            ("KRAKEN_NATIVE_WORKER".into(), worker.into()),
        ],
        timeout: Duration::from_secs(60),
        ..Default::default()
    };
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let backend = Arc::new(
        rt.block_on(DaemonClientBackend::connect(
            start_connector(dir.clone(), start),
            BackendOptions::default(),
        ))
        .expect("krakend starts"),
    );
    let _daemon = Daemon {
        rt: rt.clone(),
        dir: dir.clone(),
        backend: backend.clone(),
    };
    let skip_cancel = std::env::var_os("KRAKEN_BIG_SKIP_CANCEL").is_some();
    let events: Events = Arc::default();
    {
        let watcher = rt
            .block_on(kraken_host::daemon::DaemonClient::connect_running(
                &dir,
                kraken_ipc::ClientKind::Cli,
                kraken_viewmodel::daemon::BUILD,
            ))
            .expect("connect")
            .expect("the daemon runs");
        let mut rx = watcher.take_events().expect("events");
        let events = events.clone();
        rt.spawn(async move {
            let _keep = watcher;
            while let Some(n) = rx.recv().await {
                if n.params["kind"] == "open_progress" {
                    events.lock().unwrap().push((Instant::now(), n.params));
                }
            }
        });
    }

    for (i, bin) in binaries.iter().enumerate() {
        let name = bin
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let project = |tag: &str| -> PathBuf { tmp.path().join(format!("p{i}-{tag}")) };
        let path = |p: &Path| p.to_string_lossy().into_owned();

        if !skip_cancel {
            // Cancel once the function search has run for a while.
            let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
            let started = Instant::now();
            vm.create_project_with(
                path(bin),
                path(&project("cancel")),
                Some(EngineChoice::Native),
            );
            let mid = vm.block_until(Duration::from_secs(600), |v| {
                v.loading.as_ref().is_some_and(|l| {
                    l.stage() == OpenStage::Functions
                        && l.started.elapsed() >= Duration::from_secs(8)
                }) || !matches!(v.connection, Connection::Opening(_))
            });
            assert!(mid, "{name}: reached the function search");
            if matches!(vm.connection, Connection::Opening(_)) {
                let busy = workers(&worker_path);
                let pressed = Instant::now();
                vm.cancel_open();
                let stopped = vm.block_until(Duration::from_secs(60), |v| {
                    v.connection == Connection::NoProject
                });
                let took = pressed.elapsed();
                std::thread::sleep(Duration::from_secs(1));
                let status = rt.block_on(backend.status()).expect("status");
                let sessions = status["sessions"].as_array().map_or(0, Vec::len);
                println!(
                    "{name} cancel: at={:.1}s stopped={stopped} took={:.2}s workers_before={busy} \
                     workers_after={} sessions_after={sessions}",
                    (pressed - started).as_secs_f64(),
                    took.as_secs_f64(),
                    workers(&worker_path),
                );
                assert!(stopped, "{name}: Cancel stops the open");
                assert_eq!(sessions, 0, "{name}: no half-open session");
            } else {
                println!("{name} cancel: the open finished before the cancel point");
            }
        }

        // The first open.
        let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
        let started = Instant::now();
        vm.create_project_with(
            path(bin),
            path(&project("open")),
            Some(EngineChoice::Native),
        );
        let first = watch(&mut vm, started);
        println!("{}", first.summary(&format!("{name} first open")));
        println!(
            "{name} first open raw: {}",
            raw_summary(&events, &project("open"), started)
        );
        assert!(first.ok, "{name}: {:?}", vm.toasts);
        let fractions: Vec<f64> = first.samples.iter().filter_map(|s| s.fraction).collect();
        assert!(
            fractions.windows(2).all(|w| w[0] <= w[1]),
            "{name}: monotonic"
        );

        // The reopen, from the saved results. The first view-model goes away first, so nothing
        // of it asks the daemon to open the project behind the second one's back.
        vm.block_until_idle(Duration::from_secs(120));
        vm.close_project();
        drop(vm);
        std::thread::sleep(Duration::from_secs(2));
        let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
        let started = Instant::now();
        vm.open_project(path(&project("open")));
        let again = watch(&mut vm, started);
        println!("{}", again.summary(&format!("{name} reopen")));
        println!(
            "{name} reopen raw: {}",
            raw_summary(&events, &project("open"), started)
        );
        assert!(
            again.ok,
            "{name}: reopen {:?} {:?}",
            vm.connection, vm.toasts
        );
        vm.block_until_idle(Duration::from_secs(120));
        vm.close_project();
        drop(vm);
        std::thread::sleep(Duration::from_secs(2));
    }
}

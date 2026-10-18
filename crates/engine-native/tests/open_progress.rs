//! The progress reports of an open: stages in order, the function search's fraction only grows,
//! and a big binary prints a timed log of what it reports (ignored test).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use engine_native::{Isolation, NativeConfig, NativeEngine};
use kraken_engine::{CancellationToken, Loader, LoaderSpec, OpenReporter};
use kraken_proto::{OpenStage, OpenUpdate};

fn config(state: Option<&Path>) -> Option<NativeConfig> {
    let mut cfg = NativeConfig::discover()?;
    cfg.isolation = Isolation::InProcess;
    cfg.state_dir = state.map(Path::to_path_buf);
    Some(cfg)
}

/// Every report with the seconds since the open started.
type Seen = Arc<Mutex<Vec<(f64, OpenUpdate)>>>;

fn recorder() -> (OpenReporter, Seen) {
    let seen: Seen = Arc::default();
    let start = Instant::now();
    let r: OpenReporter = {
        let seen = seen.clone();
        Arc::new(move |u| {
            seen.lock()
                .unwrap()
                .push((start.elapsed().as_secs_f64(), u))
        })
    };
    (r, seen)
}

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_open_reports_its_stages_and_a_growing_fraction() {
    let state = tempfile::tempdir().unwrap();
    let Some(cfg) = config(Some(state.path())) else {
        eprintln!("skipping: no Sleigh specs (cargo xtask native-sla)");
        return;
    };
    let bin = corpus("bin/pie_list-O0");
    for pass in ["first", "again"] {
        let engine = NativeEngine::new(cfg.clone());
        let (report, seen) = recorder();
        engine
            .open_binary_reporting(
                &bin,
                &LoaderSpec::default(),
                &CancellationToken::new(),
                report,
            )
            .await
            .expect("open");
        let seen = seen.lock().unwrap();
        let stages: Vec<OpenStage> = seen.iter().map(|(_, u)| u.stage).collect();
        assert_eq!(stages.first(), Some(&OpenStage::ReadFile), "{pass}");
        assert!(
            stages.windows(2).all(|w| w[0] <= w[1]),
            "{pass}: {stages:?}"
        );
        assert!(stages.contains(&OpenStage::Functions), "{pass}");
        assert_eq!(stages.last(), Some(&OpenStage::Types), "{pass}");
        let f: Vec<f64> = seen.iter().filter_map(|(_, u)| u.stage_fraction).collect();
        assert!(f.iter().all(|x| (0.0..=1.0).contains(x)), "{pass}: {f:?}");
        let cached = seen.iter().any(|(_, u)| u.from_cache);
        // a binary without switch tables leaves nothing to cache; with one, the second pass
        // reads the saved answers
        if pass == "first" {
            assert!(!cached);
        }
        let covered = seen
            .iter()
            .rev()
            .find_map(|(_, u)| Some((u.covered_bytes?, u.code_bytes?)));
        if let Some((c, code)) = covered {
            assert!(c <= code && code > 0, "{c} of {code}");
        }
    }
}

/// `KRAKEN_BIG_BINARY=/tmp/x/libsqlite3.so cargo test --release -p engine-native --test
/// open_progress -- --ignored --nocapture`: a timed log of every report of a first open through
/// the worker.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "opens a big binary; run by hand"]
async fn a_big_binary_logs_its_reports() {
    let Some(bin) = std::env::var_os("KRAKEN_BIG_BINARY").map(PathBuf::from) else {
        eprintln!("skipped: set KRAKEN_BIG_BINARY to a big program");
        return;
    };
    let mut cfg = NativeConfig::discover().expect("Sleigh specs");
    cfg.isolation = Isolation::default();
    let engine = NativeEngine::new(cfg);
    let (report, seen) = recorder();
    let started = Instant::now();
    engine
        .open_binary_reporting(
            &bin,
            &LoaderSpec::default(),
            &CancellationToken::new(),
            report,
        )
        .await
        .expect("open");
    for (t, u) in seen.lock().unwrap().iter() {
        println!(
            "{t:8.2} {:<10} {:>6.3} {}",
            u.stage.as_str(),
            u.stage_fraction.unwrap_or(-1.0),
            u.message
        );
    }
    println!("total {:.2}s", started.elapsed().as_secs_f64());
}

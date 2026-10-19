use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_infer::port::pick_free_port;
use kraken_infer::stats::{StatsKind, StatsSampler, SystemEnv, Target};
use kraken_infer::{ManagedProcess, Phase, ProcessSpec};
use kraken_proto::infer::{ModelState, TokSource};

const FAKE: &str = env!("CARGO_BIN_EXE_kraken-fake-server");
const T: Duration = Duration::from_secs(20);

fn spec(extra: &[&str]) -> ProcessSpec {
    let port = pick_free_port().unwrap();
    let mut s = ProcessSpec::new(FAKE, port, "/health");
    s.args = ["--port".to_string(), port.to_string()]
        .into_iter()
        .chain(extra.iter().map(|a| (*a).to_string()))
        .collect();
    s.health.interval = Duration::from_millis(50);
    s.grace = Duration::from_millis(300);
    s.progress_parser = Some(|l| l.strip_prefix("load_progress=")?.parse().ok());
    s
}

#[tokio::test]
async fn load_steps_report_progress_then_ready() {
    let p = ManagedProcess::start(spec(&["--load-steps", "5"])).unwrap();
    let mut seen = Vec::new();
    let start = Instant::now();
    while p.status().phase != Phase::Ready {
        assert!(start.elapsed() < T, "never ready");
        if let Some(f) = p.status().fraction {
            seen.push(f);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(seen.iter().any(|f| *f > 0.0 && *f < 1.0), "saw {seen:?}");
    p.stop().await;
}

#[tokio::test]
async fn sampler_reads_prometheus_counters_from_the_fake_server() {
    let spec = spec(&["--prometheus"]);
    let port = spec.port;
    let p = ManagedProcess::start(spec).unwrap();
    p.wait_ready(T).await.unwrap();
    let s = StatsSampler::new(Arc::new(SystemEnv));
    s.register(Target {
        model: "m".into(),
        kind: StatsKind::Llama,
        port,
        pid: p.status().pid,
        devices: Vec::new(),
        api_key: None,
    });
    s.set_phase("m", ModelState::Ready, None);
    s.tick().await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    s.tick().await;
    let st = s.snapshot("m").unwrap();
    let rate = st.tok_s.expect("rate after two scrapes");
    assert!((rate - 100.0).abs() < 1.0, "rate {rate}");
    assert_eq!(st.tok_s_source, Some(TokSource::Engine));
    assert!(st.ram_bytes > 0, "RAM of the fake server process");
    p.stop().await;
}

#[tokio::test]
async fn sampler_reads_strata_json_from_the_fake_server() {
    let file = std::env::temp_dir().join(format!("kraken-metrics-{}.json", std::process::id()));
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/stats/strata-metrics-generating.json"
        ),
        &file,
    )
    .unwrap();
    let spec = spec(&["--metrics-json", file.to_str().unwrap()]);
    let port = spec.port;
    let p = ManagedProcess::start(spec).unwrap();
    p.wait_ready(T).await.unwrap();
    let s = StatsSampler::new(Arc::new(SystemEnv));
    s.register(Target {
        model: "m".into(),
        kind: StatsKind::Strata,
        port,
        pid: None,
        devices: Vec::new(),
        api_key: None,
    });
    s.set_phase("m", ModelState::Ready, None);
    s.tick().await;
    assert_eq!(s.snapshot("m").unwrap().tok_s, Some(31.4));
    p.stop().await;
    let _ = std::fs::remove_file(file);
}

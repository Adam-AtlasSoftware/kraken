use std::time::{Duration, Instant};

use kraken_infer::supervisor::DEFAULT_ENV_ALLOWLIST;
use kraken_infer::{
    BackendRegistry, GenericOpenAiServerBackend, ManagedProcess, MemoryBudget, Phase, ProcessSpec,
    port::pick_free_port,
};
use serde_json::json;

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
    s.restart.initial_backoff = Duration::from_millis(50);
    s.grace = Duration::from_millis(300);
    s
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < T, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn start_health_logs_stop() {
    let p = ManagedProcess::start(spec(&[])).unwrap();
    p.wait_ready(T).await.unwrap();
    assert!(p.health().await);
    assert_eq!(p.status().phase, Phase::Ready);

    until("log lines", || {
        let l = p.logs();
        l.iter().any(|x| x.text.contains("listening on 127.0.0.1"))
            && l.iter().any(|x| x.text == "fake-server stderr line")
    })
    .await;

    p.stop().await;
    assert_eq!(p.status().phase, Phase::Stopped);
    assert!(!p.health().await);
    assert!(p.logs().iter().any(|l| l.text.contains("stopped:")));
}

#[tokio::test]
async fn env_is_filtered() {
    let mut s = spec(&[]);
    s.env.push(("KRAKEN_TEST_EXTRA".into(), "1".into()));
    let p = ManagedProcess::start(s).unwrap();
    p.wait_ready(T).await.unwrap();
    until("env dump", || {
        p.logs()
            .iter()
            .any(|l| l.text.starts_with("fake-server listening"))
    })
    .await;
    let names: Vec<String> = p
        .logs()
        .iter()
        .filter_map(|l| l.text.strip_prefix("ENV ").map(str::to_string))
        .collect();
    assert!(names.contains(&"KRAKEN_TEST_EXTRA".to_string()));
    for n in &names {
        assert!(
            n == "KRAKEN_TEST_EXTRA"
                || DEFAULT_ENV_ALLOWLIST
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(n)),
            "leaked env var {n}"
        );
    }
    p.stop().await;
}

#[tokio::test]
async fn crash_triggers_restart_then_recovers() {
    let mut s = spec(&["--crash-after", "1"]);
    s.restart.max_restarts = 5;
    let p = ManagedProcess::start(s).unwrap();
    p.wait_ready(T).await.unwrap();
    let first_pid = p.status().pid;
    until("a restart", || p.status().restarts >= 1).await;
    p.wait_ready(T).await.unwrap();
    assert_ne!(p.status().pid, first_pid);
    assert!(p.logs().iter().any(|l| l.text.contains("exit code 3")));
    p.stop().await;
}

#[tokio::test]
async fn gives_up_after_max_restarts() {
    let mut s = spec(&["--crash-after", "0.2"]);
    s.restart.max_restarts = 1;
    let p = ManagedProcess::start(s).unwrap();
    until("failed", || p.status().phase == Phase::Failed).await;
    assert!(p.wait_ready(Duration::from_secs(1)).await.is_err());
    p.stop().await;
}

#[tokio::test]
async fn sigkill_after_grace_when_term_ignored() {
    let p = ManagedProcess::start(spec(&["--ignore-term"])).unwrap();
    p.wait_ready(T).await.unwrap();
    let t = Instant::now();
    p.stop().await;
    assert!(
        t.elapsed() >= Duration::from_millis(250),
        "returned before grace"
    );
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(p.logs().iter().any(|l| l.text.contains("signal 9")));
}

#[tokio::test]
async fn clean_sigterm_is_fast() {
    let p = ManagedProcess::start(spec(&[])).unwrap();
    p.wait_ready(T).await.unwrap();
    let t = Instant::now();
    p.stop().await;
    assert!(t.elapsed() < Duration::from_millis(250));
    assert!(p.logs().iter().any(|l| l.text.contains("signal 15")));
}

#[tokio::test]
async fn slow_loading_reports_starting_then_ready() {
    let p = ManagedProcess::start(spec(&["--ready-after", "1"])).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_ne!(p.status().phase, Phase::Ready);
    assert!(!p.health().await);
    p.wait_ready(T).await.unwrap();
    p.stop().await;
}

#[tokio::test]
async fn missing_binary_fails_at_start() {
    let s = ProcessSpec::new("/nonexistent/engine", 1, "/health");
    assert!(ManagedProcess::start(s).is_err());
}

#[tokio::test]
async fn generic_backend_end_to_end() {
    let manifest = format!(
        r#"
id = "fake"
license = "MIT"
command = ["{FAKE}", "--port", "{{port}}", "--ready-after", "{{delay}}"]
health_path = "/v1/models"
[capabilities]
os = ["linux"]
arch = ["x86_64"]
[settings_schema.properties.delay]
type = "number"
default = 0
"#
    );
    let b = GenericOpenAiServerBackend::from_manifest_str(&manifest).unwrap();
    let mut reg = BackendRegistry::new();
    reg.register(std::sync::Arc::new(b));
    let b = reg.get("fake").unwrap();
    let budget = MemoryBudget::new(64 << 30, None);
    let run = b.start(json!({}), &budget).await.unwrap();
    run.wait_ready(T).await.unwrap();
    assert!(run.base_url().starts_with("http://127.0.0.1:"));
    assert!(run.base_url().ends_with("/v1"));
    assert!(run.health().await);
    run.stop().await;

    let tiny = MemoryBudget::new(1 << 20, None);
    assert!(b.start(json!({}), &tiny).await.is_err());
}

#[tokio::test]
async fn a_taken_port_is_retried_once_on_a_new_port() {
    let taken = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let first = taken.local_addr().unwrap().port();
    let (p, port) = kraken_infer::port::start_with_port_retry(
        first,
        |port| {
            let mut s = ProcessSpec::new(FAKE, port, "/health");
            s.args = vec!["--port".into(), port.to_string()];
            s.health.interval = Duration::from_millis(50);
            s.restart.initial_backoff = Duration::from_millis(50);
            s.grace = Duration::from_millis(300);
            s
        },
        T,
    )
    .await
    .unwrap();
    assert_ne!(port, first);
    assert!(p.health().await);
    p.stop().await;
}

#[tokio::test]
async fn a_managed_port_ignores_the_port_setting() {
    let manifest = format!(
        r#"
id = "m"
license = "MIT"
managed_port = true
command = ['{FAKE}', '--port', '{{port}}']
health_path = "/health"
[capabilities]
gpu_apis = ["cpu"]
"#
    );
    let backend = GenericOpenAiServerBackend::from_manifest_str(&manifest).unwrap();
    let budget = MemoryBudget::new(64 << 30, None);
    let run = kraken_infer::InferenceBackend::start(&backend, json!({"port": 1}), &budget)
        .await
        .unwrap();
    assert_ne!(run.process().port(), 1);
    run.stop().await;
}

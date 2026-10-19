//! Test-only stand-in for an inference server: answers /health and /v1/models on 127.0.0.1.
//!
//! Flags: `--port N` (required), `--ready-after SECS` (/health is 503 until then),
//! `--crash-after SECS` (exit code 3), `--ignore-term` (ignore SIGTERM),
//! `--load-steps N` (prints `load_progress=F` N times, 100 ms apart; /health is 503 until the last),
//! `--metrics-json FILE` (GET /metrics answers the file's current contents),
//! `--prometheus` (llama-server style counters that advance at exactly 100 tokens per second;
//! on /metrics, or on /metrics/prometheus when `--metrics-json` is also given).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

struct Config {
    ready_after: Duration,
    metrics_json: Option<String>,
    prometheus: bool,
}

fn prometheus_text(elapsed: Duration) -> String {
    let secs = elapsed.as_secs_f64();
    let tokens = (secs * 200.0).round();
    format!(
        "# TYPE llamacpp:tokens_predicted_total counter\nllamacpp:tokens_predicted_total {tokens}\n\
         # TYPE llamacpp:tokens_predicted_seconds_total counter\nllamacpp:tokens_predicted_seconds_total {}\n\
         # TYPE llamacpp:requests_processing gauge\nllamacpp:requests_processing 0\n",
        tokens / 100.0
    )
}

fn handle(mut s: TcpStream, started: Instant, cfg: &Config) {
    let mut buf = [0u8; 2048];
    let mut n = 0;
    while n < buf.len() {
        match s.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(r) => {
                n += r;
                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split(' ').nth(1).unwrap_or("/");
    let json_metrics = cfg
        .metrics_json
        .as_ref()
        .and_then(|f| std::fs::read_to_string(f).ok());
    let (status, body) = match path {
        "/health" if started.elapsed() >= cfg.ready_after => {
            ("200 OK", r#"{"status":"ok"}"#.to_string())
        }
        "/health" => (
            "503 Service Unavailable",
            r#"{"error":"Loading model"}"#.to_string(),
        ),
        "/v1/models" => (
            "200 OK",
            r#"{"object":"list","data":[{"id":"fake"}]}"#.to_string(),
        ),
        "/metrics" if json_metrics.is_some() => ("200 OK", json_metrics.unwrap_or_default()),
        "/metrics" | "/metrics/prometheus" if cfg.prometheus => {
            ("200 OK", prometheus_text(started.elapsed()))
        }
        _ => ("404 Not Found", "{}".to_string()),
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = s.write_all(resp.as_bytes());
}

fn main() {
    let mut port: Option<u16> = None;
    let mut ready_after = Duration::ZERO;
    let mut crash_after: Option<Duration> = None;
    let mut ignore_term = false;
    let mut load_steps = 0u32;
    let mut metrics_json = None;
    let mut prometheus = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => port = args.next().and_then(|v| v.parse().ok()),
            "--ready-after" => {
                ready_after = Duration::from_secs_f64(
                    args.next().and_then(|v| v.parse().ok()).unwrap_or(0.0),
                );
            }
            "--crash-after" => {
                crash_after = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .map(Duration::from_secs_f64);
            }
            "--ignore-term" => ignore_term = true,
            "--load-steps" => load_steps = args.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            "--metrics-json" => metrics_json = args.next(),
            "--prometheus" => prometheus = true,
            _ => {}
        }
    }
    let Some(port) = port else {
        eprintln!("--port required");
        std::process::exit(2);
    };

    #[cfg(unix)]
    if ignore_term {
        // SAFETY: installing SIG_IGN for SIGTERM is a plain signal-disposition syscall.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    #[cfg(not(unix))]
    let _ = ignore_term;

    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("bind failed: {e}");
            std::process::exit(1);
        }
    };
    for (k, _) in std::env::vars() {
        println!("ENV {k}");
    }
    println!("fake-server listening on 127.0.0.1:{port}");
    eprintln!("fake-server stderr line");

    let started = Instant::now();
    ready_after = ready_after.max(STEP * load_steps);
    let cfg = std::sync::Arc::new(Config {
        ready_after,
        metrics_json,
        prometheus,
    });
    if load_steps > 0 {
        std::thread::spawn(move || {
            for i in 1..=load_steps {
                std::thread::sleep(STEP);
                println!("load_progress={:.2}", f64::from(i) / f64::from(load_steps));
            }
        });
    }
    if let Some(d) = crash_after {
        std::thread::spawn(move || {
            std::thread::sleep(d);
            eprintln!("fake-server crashing");
            std::process::exit(3);
        });
    }
    for conn in listener.incoming().flatten() {
        let cfg = std::sync::Arc::clone(&cfg);
        std::thread::spawn(move || handle(conn, started, &cfg));
    }
}

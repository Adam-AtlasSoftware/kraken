//! Test-only stand-in for an inference server: answers /health and /v1/models on 127.0.0.1.
//!
//! Flags: `--port N` (required), `--ready-after SECS` (/health is 503 until then),
//! `--crash-after SECS` (exit code 3), `--ignore-term` (ignore SIGTERM).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn handle(mut s: TcpStream, started: Instant, ready_after: Duration) {
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
    let (status, body) = match path {
        "/health" if started.elapsed() >= ready_after => ("200 OK", r#"{"status":"ok"}"#),
        "/health" => ("503 Service Unavailable", r#"{"error":"Loading model"}"#),
        "/v1/models" => ("200 OK", r#"{"object":"list","data":[{"id":"fake"}]}"#),
        _ => ("404 Not Found", "{}"),
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
    if let Some(d) = crash_after {
        std::thread::spawn(move || {
            std::thread::sleep(d);
            eprintln!("fake-server crashing");
            std::process::exit(3);
        });
    }
    for conn in listener.incoming().flatten() {
        std::thread::spawn(move || handle(conn, started, ready_after));
    }
}

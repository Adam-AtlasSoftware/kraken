use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::time::Duration;

use crate::error::{InferError, Result};
use crate::logring::LogLine;
use crate::supervisor::{ManagedProcess, ProcessSpec};

/// Address every supervised engine must bind to.
pub const LOOPBACK: &str = "127.0.0.1";

/// Binds an ephemeral port on 127.0.0.1 only and returns the listener.
pub fn bind_loopback() -> Result<TcpListener> {
    Ok(TcpListener::bind(SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        0,
    )))?)
}

/// Picks a free loopback port. The port is released before returning, so another process can in
/// principle grab it before the engine does; the supervisor reuses the same port on restart.
pub fn pick_free_port() -> Result<u16> {
    let l = bind_loopback()?;
    Ok(l.local_addr()?.port())
}

/// Phrases engines and their runtimes print when the port is taken (lowercase).
const BIND_FAILURE_MARKERS: &[&str] = &[
    "address already in use",
    "address in use",
    "eaddrinuse",
    "couldn't bind",
    "failed to bind",
    "only one usage of each socket address",
];

/// Whether the engine's output says it could not take its port.
pub fn shows_bind_failure(logs: &[LogLine]) -> bool {
    logs.iter().any(|l| {
        let t = l.text.to_ascii_lowercase();
        BIND_FAILURE_MARKERS.iter().any(|m| t.contains(m))
    })
}

/// Starts an engine on `first_port` and waits until it is ready. If it could not take the port
/// (another process grabbed it between picking and binding), it is stopped and started once more
/// on a new port. `make_spec` builds the process description for a port. Returns the running
/// process and the port it ended up on.
pub async fn start_with_port_retry<F>(
    first_port: u16,
    mut make_spec: F,
    ready_timeout: Duration,
) -> Result<(ManagedProcess, u16)>
where
    F: FnMut(u16) -> ProcessSpec,
{
    let mut port = first_port;
    for attempt in 0..2 {
        let process = ManagedProcess::start(make_spec(port))?;
        let outcome = {
            let ready = process.wait_ready(ready_timeout);
            tokio::pin!(ready);
            let mut poll = tokio::time::interval(Duration::from_millis(100));
            loop {
                tokio::select! {
                    r = &mut ready => break r,
                    _ = poll.tick() => {
                        if shows_bind_failure(&process.logs()) {
                            break Err(InferError::NotReady(format!("port {port} is in use")));
                        }
                    }
                }
            }
        };
        match outcome {
            Ok(()) => return Ok((process, port)),
            Err(e) => {
                let taken = shows_bind_failure(&process.logs());
                process.stop().await;
                if !taken || attempt == 1 {
                    return Err(e);
                }
                port = loop {
                    let p = pick_free_port()?;
                    if p != port {
                        break p;
                    }
                };
            }
        }
    }
    Err(InferError::NotReady("could not take a port".into()))
}

/// A fresh random API key (256 bits, hex) for one engine run.
pub fn generate_api_key() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b)
        .map_err(|e| crate::error::InferError::Unsupported(format!("no OS randomness: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[cfg(test)]
mod tests {
    #[test]
    fn api_keys_are_long_hex_and_unique() {
        let (a, b) = (
            super::generate_api_key().unwrap(),
            super::generate_api_key().unwrap(),
        );
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    use super::*;
    use crate::logring::LogStream;

    #[test]
    fn recognises_bind_failures() {
        let ring = crate::logring::LogRing::new(10);
        ring.push(LogStream::Stderr, "main: couldn't bind HTTP server socket");
        assert!(shows_bind_failure(&ring.snapshot()));
        let ring = crate::logring::LogRing::new(10);
        ring.push(
            LogStream::Stderr,
            "bind failed: Address already in use (os error 98)",
        );
        assert!(shows_bind_failure(&ring.snapshot()));
        let ring = crate::logring::LogRing::new(10);
        ring.push(LogStream::Stdout, "loading model");
        assert!(!shows_bind_failure(&ring.snapshot()));
    }

    #[test]
    fn binds_loopback_only() {
        let l = bind_loopback().unwrap();
        let addr = l.local_addr().unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.ip().to_string(), LOOPBACK);
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn picked_port_is_bindable_on_loopback() {
        let p = pick_free_port().unwrap();
        assert!(TcpListener::bind((LOOPBACK, p)).is_ok());
    }
}

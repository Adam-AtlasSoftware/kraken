use std::net::{Ipv4Addr, SocketAddr, TcpListener};

use crate::error::Result;

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

#[cfg(test)]
mod tests {
    use super::*;

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

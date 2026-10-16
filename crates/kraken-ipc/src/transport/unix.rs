//! Unix domain socket transport.

use std::io;
use std::os::unix::fs::PermissionsExt;

use tokio::net::{UnixListener, UnixStream};

use crate::paths::RuntimeDir;

/// Connected stream type.
pub type Stream = UnixStream;

/// Listening socket bound at `daemon.sock`, mode 0600.
pub struct Listener {
    inner: UnixListener,
}

impl Listener {
    /// Binds the socket. A leftover socket file must already have been cleaned up.
    pub fn bind(dir: &RuntimeDir) -> io::Result<Self> {
        let path = dir.socket_path();
        let inner = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Listener { inner })
    }

    /// Accepts the next connection.
    pub async fn accept(&mut self) -> io::Result<Stream> {
        Ok(self.inner.accept().await?.0)
    }
}

/// Connects to the daemon socket.
pub async fn connect(dir: &RuntimeDir) -> io::Result<Stream> {
    UnixStream::connect(dir.socket_path()).await
}

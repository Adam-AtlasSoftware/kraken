//! Windows named pipe transport (`\\.\pipe\kraken-<user>`).
//!
//! The first pipe instance is created with `first_pipe_instance(true)` so a squatter that created
//! the name earlier makes `bind` fail, and remote clients are rejected. TODO: pass an explicit
//! owner-only security descriptor via `create_with_security_attributes_raw` (needs windows-sys
//! `Win32_Security*`); until then the default DACL applies and the auth token is the access gate.
//! This module is compile-checked only on Windows targets.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

use crate::paths::RuntimeDir;

/// A connected pipe, either end.
pub enum Stream {
    /// Server side.
    Server(NamedPipeServer),
    /// Client side.
    Client(NamedPipeClient),
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            Stream::Server($s) => $e,
            Stream::Client($s) => $e,
        }
    };
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_read(cx, buf))
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_write(cx, buf))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_flush(cx))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        delegate!(self, s => std::pin::Pin::new(s).poll_shutdown(cx))
    }
}

/// Pipe listener.
pub struct Listener {
    name: String,
    next: Option<NamedPipeServer>,
}

impl Listener {
    /// Creates the first pipe instance.
    pub fn bind(dir: &RuntimeDir) -> io::Result<Self> {
        let name = dir.pipe_name();
        let next = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)?;
        Ok(Listener {
            name,
            next: Some(next),
        })
    }

    /// Waits for a client and prepares the next instance.
    pub async fn accept(&mut self) -> io::Result<Stream> {
        let server = match self.next.take() {
            Some(s) => s,
            None => ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)?,
        };
        server.connect().await?;
        self.next = Some(
            ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)?,
        );
        Ok(Stream::Server(server))
    }
}

/// Opens the pipe, retrying briefly while all instances are busy.
pub async fn connect(dir: &RuntimeDir) -> io::Result<Stream> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let name = dir.pipe_name();
    loop {
        match ClientOptions::new().open(&name) {
            Ok(c) => return Ok(Stream::Client(c)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

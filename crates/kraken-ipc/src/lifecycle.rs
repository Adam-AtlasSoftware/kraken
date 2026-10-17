//! Single-instance daemon lifecycle: the daemon-side guard and the client-side `ensure_daemon`.
//!
//! Two locks are involved. `daemon.lock` serialises *spawning*: only its holder starts a daemon.
//! `daemon.run.lock` is held by the daemon for its whole life and is the single-instance proof;
//! they are separate so the spawner can keep the spawn lock while the new daemon takes the run lock.

use std::fs::{File, TryLockError};
use std::io;
use std::process::Child;
use std::time::{Duration, Instant};

use crate::client::{Client, ClientError, ClientHello};
use crate::error::IpcError;
use crate::info::{DaemonInfo, pid_alive};
use crate::paths::RuntimeDir;
use crate::server::Limits;
use crate::server::ServerConfig;
use crate::token::{generate_token, write_token};

fn open_lock(path: &std::path::Path) -> io::Result<File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Held by the running daemon: proves single instance and publishes token and info files.
/// Dropping it removes the socket, token and info files.
#[derive(Debug)]
pub struct DaemonGuard {
    _lock: File,
    dir: RuntimeDir,
    token: String,
    agent_token: String,
    info: DaemonInfo,
}

impl DaemonGuard {
    /// Takes the run lock (failing with `AlreadyRunning` if a live daemon holds it), removes any
    /// leftover socket (safe, since holding the lock proves no live daemon), then writes a fresh
    /// token and `daemon.json`. Bind the listener after this returns.
    pub fn acquire(dir: &RuntimeDir, protocol: u32, build: &str) -> Result<Self, IpcError> {
        let lock = open_lock(&dir.run_lock_path())?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(IpcError::AlreadyRunning),
            Err(TryLockError::Error(e)) => return Err(e.into()),
        }
        match std::fs::remove_file(dir.socket_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let token = generate_token()?;
        let agent_token = generate_token()?;
        // Agent token first: a client that finds `daemon.token` can rely on `agent.token`.
        write_token(&dir.agent_token_path(), &agent_token)?;
        write_token(&dir.token_path(), &token)?;
        let info = DaemonInfo::for_current_process(protocol, build)?;
        info.write(&dir.info_path())?;
        Ok(DaemonGuard {
            _lock: lock,
            dir: dir.clone(),
            token,
            agent_token,
            info,
        })
    }

    /// The token a person's clients (GUI, CLI) present.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The token agent-side clients (MCP servers) present.
    pub fn agent_token(&self) -> &str {
        &self.agent_token
    }

    /// The published daemon info.
    pub fn info(&self) -> &DaemonInfo {
        &self.info
    }

    /// Server configuration matching the published token and info.
    pub fn server_config(&self) -> ServerConfig {
        ServerConfig {
            token: self.token.clone(),
            agent_token: Some(self.agent_token.clone()),
            limits: Limits::default(),
            protocol: self.info.protocol,
            build: self.info.build.clone(),
            pid: self.info.pid,
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.dir.socket_path());
        let _ = std::fs::remove_file(self.dir.info_path());
        let _ = std::fs::remove_file(self.dir.token_path());
        let _ = std::fs::remove_file(self.dir.agent_token_path());
    }
}

/// Failure of [`ensure_daemon`].
#[derive(Debug, thiserror::Error)]
pub enum EnsureError {
    /// No daemon became reachable in time.
    #[error("timed out waiting for the daemon")]
    Timeout,
    /// The spawn closure failed.
    #[error("failed to spawn daemon: {0}")]
    Spawn(io::Error),
    /// The spawned process exited unsuccessfully before the daemon came up.
    #[error("spawned daemon exited early: {0}")]
    SpawnExited(std::process::ExitStatus),
    /// A non-retryable client error (e.g. protocol mismatch; see `restart_required`).
    #[error("{0}")]
    Client(#[from] ClientError),
    /// State-file I/O failure.
    #[error("{0}")]
    Ipc(#[from] IpcError),
}

fn retryable(e: &ClientError) -> bool {
    use io::ErrorKind::*;
    match e {
        ClientError::Io(e) => matches!(
            e.kind(),
            NotFound
                | ConnectionRefused
                | ConnectionReset
                | ConnectionAborted
                | BrokenPipe
                | UnexpectedEof
        ),
        ClientError::Frame(crate::frame::FrameError::Io(e)) => e.kind() == UnexpectedEof,
        ClientError::Frame(_) => false,
        ClientError::Closed => true,
        ClientError::Proto(p) => crate::wire::is_unauthorized(p),
        ClientError::Protocol(_) | ClientError::Token(_) => false,
    }
}

fn daemon_alive(dir: &RuntimeDir) -> bool {
    matches!(DaemonInfo::read(&dir.info_path()), Ok(Some(i)) if pid_alive(i.pid))
}

/// Connects to the daemon, starting it if needed. Race-free across tasks and processes: only the
/// holder of `daemon.lock` may call `spawn`, and it does so only if no live daemon is recorded in
/// `daemon.json`. A leftover socket is removed only when that pid is dead.
pub async fn ensure_daemon<F>(
    dir: &RuntimeDir,
    hello: &ClientHello,
    spawn: F,
    timeout: Duration,
) -> Result<Client, EnsureError>
where
    F: FnOnce() -> io::Result<Child>,
{
    let deadline = Instant::now() + timeout;
    let mut spawn = Some(spawn);
    let mut lock: Option<File> = None;
    let mut child: Option<Child> = None;
    loop {
        match Client::connect(dir, hello).await {
            Ok(c) => return Ok(c),
            Err(e) if retryable(&e) => {}
            Err(e) => return Err(e.into()),
        }
        if Instant::now() >= deadline {
            return Err(EnsureError::Timeout);
        }
        if lock.is_none() {
            let f = open_lock(&dir.lock_path()).map_err(IpcError::from)?;
            match f.try_lock() {
                Ok(()) => {
                    lock = Some(f);
                    // Whoever held the lock before us may have finished starting the daemon.
                    continue;
                }
                Err(TryLockError::WouldBlock) => {}
                Err(TryLockError::Error(e)) => return Err(IpcError::from(e).into()),
            }
        }
        if lock.is_some()
            && spawn.is_some()
            && !daemon_alive(dir)
            && let Some(spawn) = spawn.take()
        {
            match std::fs::remove_file(dir.socket_path()) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(IpcError::from(e).into()),
            }
            child = Some(spawn().map_err(EnsureError::Spawn)?);
        }
        if let Some(c) = child.as_mut()
            && let Ok(Some(status)) = c.try_wait()
        {
            if !status.success() {
                return Err(EnsureError::SpawnExited(status));
            }
            child = None;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

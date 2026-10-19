//! Errors for paths, token and daemon-info handling.

use std::path::PathBuf;

/// Failure while resolving or using the per-user runtime directory and its files.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Underlying I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The runtime directory exists but is not private to the current user.
    #[error("runtime dir {path:?} is insecure: {reason}")]
    InsecureDir {
        /// Offending directory.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// The socket path would not fit in `sockaddr_un.sun_path`.
    #[error("socket path {} is {len} bytes; the limit is {limit}. {advice}", path.display())]
    SocketPathTooLong {
        /// Offending path.
        path: PathBuf,
        /// Its length in bytes.
        len: usize,
        /// The enforced limit.
        limit: usize,
        /// Which setting produced the path and how to fix it.
        advice: String,
    },
    /// A state file could not be parsed.
    #[error("malformed {what}: {source}")]
    Malformed {
        /// Which file.
        what: &'static str,
        /// Parse error.
        source: serde_json::Error,
    },
    /// No usable runtime directory could be determined.
    #[error("cannot determine runtime dir: {0}")]
    NoRuntimeDir(String),
    /// Another live daemon holds the single-instance lock.
    #[error("another daemon is already running")]
    AlreadyRunning,
}

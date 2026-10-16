use std::io;

#[derive(Debug, thiserror::Error)]
pub enum InferError {
    #[error("invalid settings: {0}")]
    Settings(String),
    #[error("invalid manifest: {0}")]
    Manifest(String),
    #[error("backend binary not found: {0}")]
    BinaryNotFound(String),
    #[error("failed to spawn process: {0}")]
    Spawn(#[source] io::Error),
    #[error("backend not ready: {0}")]
    NotReady(String),
    #[error("memory budget exceeded: {0}")]
    Overcommit(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, InferError>;

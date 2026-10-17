//! Errors raised while confining and starting a sidecar.

use kraken_proto::{ErrorCode, ProtoError};

/// Failure to set up or start a sidecar (as opposed to an error answered by a running one).
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    /// Confinement is required but unavailable on this host.
    #[error("sidecar confinement: {0}")]
    Confinement(String),
    /// The process could not be created.
    #[error("cannot start the sidecar: {0}")]
    Spawn(String),
    /// The sidecar spoke an incompatible or malformed protocol.
    #[error("sidecar protocol: {0}")]
    Protocol(String),
    /// A filesystem or OS call failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}

impl SidecarError {
    /// An [`SidecarError::Io`] with context.
    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        SidecarError::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<SidecarError> for ProtoError {
    fn from(e: SidecarError) -> Self {
        let code = match e {
            SidecarError::Confinement(_) | SidecarError::Protocol(_) => ErrorCode::Unsupported,
            SidecarError::Spawn(_) | SidecarError::Io { .. } => ErrorCode::Internal,
        };
        ProtoError::new(code, e.to_string())
    }
}

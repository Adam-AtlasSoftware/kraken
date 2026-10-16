//! Errors raised while locating, confining and starting the sidecar.

use kraken_proto::{ErrorCode, ProtoError};

/// Failure to set up or start the sidecar (as opposed to an error answered by a running one).
#[derive(Debug, thiserror::Error)]
pub enum GhidraError {
    /// The Ghidra / JDK / extension installation is missing or not a tested version.
    #[error("Ghidra installation: {0}")]
    Install(String),
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

impl GhidraError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        GhidraError::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<GhidraError> for ProtoError {
    fn from(e: GhidraError) -> Self {
        let code = match e {
            GhidraError::Install(_) | GhidraError::Confinement(_) | GhidraError::Protocol(_) => {
                ErrorCode::Unsupported
            }
            GhidraError::Spawn(_) | GhidraError::Io { .. } => ErrorCode::Internal,
        };
        ProtoError::new(code, e.to_string())
    }
}

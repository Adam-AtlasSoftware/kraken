//! Errors raised while locating or starting the sidecar.

use kraken_proto::{ErrorCode, ProtoError};

/// Failure to set up or start the sidecar (as opposed to an error answered by a running one).
#[derive(Debug, thiserror::Error)]
pub enum DotnetError {
    /// The .NET installation or the sidecar build is missing.
    #[error(".NET installation: {0}")]
    Install(String),
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

impl DotnetError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        DotnetError::Io {
            context: context.into(),
            source,
        }
    }
}

impl From<DotnetError> for ProtoError {
    fn from(e: DotnetError) -> Self {
        let code = match e {
            DotnetError::Install(_) | DotnetError::Protocol(_) => ErrorCode::Unsupported,
            DotnetError::Io { .. } => ErrorCode::Internal,
        };
        ProtoError::new(code, e.to_string())
    }
}

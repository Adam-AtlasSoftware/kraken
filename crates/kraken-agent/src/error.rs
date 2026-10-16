//! Agent error type.

/// Errors from providers, configuration and the agent loop.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("missing API key: {0}")]
    MissingKey(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("provider returned HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("malformed provider payload: {0}")]
    Protocol(String),
    #[error("provider reported an error: {0}")]
    Provider(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("no cassette entry for request key {0}")]
    CassetteMiss(String),
    #[error("cassette error: {0}")]
    Cassette(String),
    #[error("cancelled")]
    Cancelled,
}

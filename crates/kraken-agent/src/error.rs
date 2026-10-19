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
    /// A local model is not running and was not started for this request.
    #[error("{message}")]
    ModelNotRunning {
        /// The model's id.
        model: String,
        /// What happened and how to start it, in plain words.
        message: String,
    },
    /// A call was refused because the work reached a limit (calls, estimated cost, daily budget).
    #[error("{0}")]
    Limit(String),
}

impl AgentError {
    /// True when asking again may work: the connection broke or the server was busy or starting.
    pub fn is_retryable(&self) -> bool {
        match self {
            AgentError::Transport(_) => true,
            AgentError::Http { status, .. } => matches!(status, 429 | 502 | 503 | 504),
            _ => false,
        }
    }
}

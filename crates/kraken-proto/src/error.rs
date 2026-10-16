//! Structured protocol errors with stable string codes.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Stable machine-readable error code; the snake_case strings never change once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// The addressed entity does not exist.
    NotFound,
    /// A request argument is malformed or out of range.
    InvalidArgument,
    /// A write was based on a read that is no longer current; re-read and retry.
    ConflictStaleRead,
    /// A concurrent human edit won over an agent edit.
    RejectedHumanPriority,
    /// The engine refused to apply a change.
    EngineRejected,
    /// The operation or variant is not supported by this engine or version.
    Unsupported,
    /// The result depends on analysis that has not finished.
    AnalysisIncomplete,
    /// The deadline passed before the operation finished.
    Timeout,
    /// The operation was cancelled.
    Cancelled,
    /// An unexpected internal failure.
    Internal,
}

impl ErrorCode {
    /// The wire string for this code.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::NotFound => "not_found",
            ErrorCode::InvalidArgument => "invalid_argument",
            ErrorCode::ConflictStaleRead => "conflict_stale_read",
            ErrorCode::RejectedHumanPriority => "rejected_human_priority",
            ErrorCode::EngineRejected => "engine_rejected",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::AnalysisIncomplete => "analysis_incomplete",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A protocol error: a stable code, a human-readable message and optional structured details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("{code}: {message}")]
pub struct ProtoError {
    /// Stable error code.
    pub code: ErrorCode,
    /// Human-readable description; not for programmatic matching.
    pub message: String,
    /// Optional code-specific structured details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl ProtoError {
    /// Creates an error without details.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ProtoError {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Attaches structured details.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_serialize_to_stable_strings() {
        use ErrorCode::*;
        for (code, s) in [
            (NotFound, "not_found"),
            (InvalidArgument, "invalid_argument"),
            (ConflictStaleRead, "conflict_stale_read"),
            (RejectedHumanPriority, "rejected_human_priority"),
            (EngineRejected, "engine_rejected"),
            (Unsupported, "unsupported"),
            (AnalysisIncomplete, "analysis_incomplete"),
            (Timeout, "timeout"),
            (Cancelled, "cancelled"),
            (Internal, "internal"),
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), serde_json::json!(s));
            assert_eq!(code.as_str(), s);
            assert_eq!(code.to_string(), s);
        }
    }

    #[test]
    fn round_trip() {
        let e = ProtoError::new(ErrorCode::ConflictStaleRead, "stale")
            .with_details(serde_json::json!({"expected": 3, "actual": 4}));
        let back: ProtoError = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert_eq!(e.to_string(), "conflict_stale_read: stale");
        let plain = ProtoError::new(ErrorCode::Internal, "x");
        assert!(!serde_json::to_string(&plain).unwrap().contains("details"));
    }
}

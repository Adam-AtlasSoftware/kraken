//! Plain-language error text for the GUI. Errors are shown as they are, never hidden.

use kraken_proto::{ErrorCode, ProtoError};

/// One or two plain sentences describing `e` for a person (not a log line).
pub fn plain_error(e: &ProtoError) -> String {
    let m = e.message.trim();
    match e.code {
        ErrorCode::ConflictStaleRead => format!(
            "This changed since you last looked ({m}). KRAKEN refreshed it; check the new state and try again."
        ),
        ErrorCode::NotFound => format!("Not found: {m}"),
        ErrorCode::InvalidArgument => m.to_string(),
        ErrorCode::RejectedHumanPriority => {
            format!("A person edited this at the same time, so the other change was dropped: {m}")
        }
        ErrorCode::EngineRejected => format!("The analysis engine refused the change: {m}"),
        ErrorCode::Unsupported => format!("Not available here: {m}"),
        ErrorCode::AnalysisIncomplete => {
            format!("Analysis has not finished yet, so this may be incomplete: {m}")
        }
        ErrorCode::Timeout => format!("That took too long and was stopped: {m}"),
        ErrorCode::Cancelled => "Cancelled.".to_string(),
        ErrorCode::Internal => format!("Something went wrong inside KRAKEN: {m}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_text() {
        for code in [
            ErrorCode::NotFound,
            ErrorCode::InvalidArgument,
            ErrorCode::ConflictStaleRead,
            ErrorCode::RejectedHumanPriority,
            ErrorCode::EngineRejected,
            ErrorCode::Unsupported,
            ErrorCode::AnalysisIncomplete,
            ErrorCode::Timeout,
            ErrorCode::Cancelled,
            ErrorCode::Internal,
        ] {
            let t = plain_error(&ProtoError::new(code, "detail"));
            assert!(!t.is_empty());
        }
        assert_eq!(
            plain_error(&ProtoError::new(
                ErrorCode::InvalidArgument,
                "name has spaces"
            )),
            "name has spaces"
        );
    }
}

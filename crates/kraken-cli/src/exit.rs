//! Process exit codes.

use kraken_proto::{ErrorCode, ProtoError};

/// The exit code for a failed command.
///
/// - 2: `invalid_argument`
/// - 3: `not_found`
/// - 4: `conflict_stale_read`, `rejected_human_priority`, `engine_rejected`,
///   `analysis_incomplete`, and a denied approval
/// - 5: `unsupported`, `internal`
/// - 6: `cancelled`, `timeout`
pub fn exit_code(e: &ProtoError) -> i32 {
    match e.code {
        ErrorCode::InvalidArgument => 2,
        ErrorCode::NotFound => 3,
        ErrorCode::ConflictStaleRead
        | ErrorCode::RejectedHumanPriority
        | ErrorCode::EngineRejected
        | ErrorCode::AnalysisIncomplete => 4,
        ErrorCode::Unsupported => {
            let denied = e
                .details
                .as_ref()
                .and_then(|d| d.get("approval"))
                .and_then(|a| a.as_str())
                == Some("denied");
            if denied { 4 } else { 5 }
        }
        ErrorCode::Cancelled | ErrorCode::Timeout => 6,
        ErrorCode::Internal => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codes_map_as_documented() {
        let c = |code| exit_code(&ProtoError::new(code, "x"));
        assert_eq!(c(ErrorCode::InvalidArgument), 2);
        assert_eq!(c(ErrorCode::NotFound), 3);
        assert_eq!(c(ErrorCode::ConflictStaleRead), 4);
        assert_eq!(c(ErrorCode::RejectedHumanPriority), 4);
        assert_eq!(c(ErrorCode::EngineRejected), 4);
        assert_eq!(c(ErrorCode::Unsupported), 5);
        assert_eq!(c(ErrorCode::Internal), 5);
        assert_eq!(c(ErrorCode::Cancelled), 6);
        assert_eq!(c(ErrorCode::Timeout), 6);
        let denied = ProtoError::new(ErrorCode::Unsupported, "no")
            .with_details(json!({"approval": "denied"}));
        assert_eq!(exit_code(&denied), 4);
    }
}

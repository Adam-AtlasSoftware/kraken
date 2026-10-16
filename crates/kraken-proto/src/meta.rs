//! Provenance, completeness, function summaries and the protocol handshake.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::locator::Locator;

/// Where an annotation came from (decision 61).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Entered by a human.
    User,
    /// Produced by an agent from its own reasoning.
    Agent,
    /// Produced by an agent from text found in the binary; always treated as untrusted.
    AgentFromBinaryText,
}

/// Outcome of applying a log entry (decision 27).
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogStatus {
    /// The entry took effect.
    Applied,
    /// The entry was refused.
    Rejected {
        /// Why it was refused.
        reason: String,
    },
    /// The anchor could no longer be resolved.
    Orphaned,
}

/// Whether a log entry has reached the engine (decision 57).
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncState {
    /// Not yet sent to the engine.
    Pending,
    /// Applied by the engine.
    Pushed,
    /// The engine refused the change.
    EngineRejected {
        /// The engine's reason.
        reason: String,
    },
}

/// How much analysis backs a result (decision 36).
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Completeness {
    /// All analysis relevant to this result has finished.
    Complete,
    /// Analysis is still running or was cut short.
    Partial {
        /// What is missing.
        reason: String,
    },
    /// The item has not been analysed at all.
    NotAnalyzed,
}

/// A short description of one function for listings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionSummary {
    /// Entry point.
    pub locator: Locator,
    /// Current function name; binary-derived, so sanitise it at ingestion.
    pub name: String,
    /// Size of the function body in bytes, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Rendered signature, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Content hash of the function's bytes, as used in anchors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fn_hash: Option<String>,
    /// Analysis completeness for this function.
    pub completeness: Completeness,
}

/// Protocol version; a different `major` is incompatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct ProtocolVersion {
    /// Incompatible-change counter.
    pub major: u32,
    /// Compatible-addition counter.
    pub minor: u32,
}

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 1 };

/// One named capability an engine or server offers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Capability {
    /// Capability name such as `"decompiler"`.
    pub name: String,
    /// Capability-specific version.
    pub version: u32,
}

/// Handshake payload: protocol version, build identity and capability list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Handshake {
    /// Protocol version of the sender.
    pub protocol: ProtocolVersion,
    /// Free-form build identifier of the sender.
    pub build: String,
    /// Capabilities the sender offers.
    pub capabilities: Vec<Capability>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt<T: Serialize + for<'a> Deserialize<'a> + PartialEq + std::fmt::Debug>(v: T) {
        let back: T = serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn round_trips() {
        for p in [
            Provenance::User,
            Provenance::Agent,
            Provenance::AgentFromBinaryText,
        ] {
            rt(p);
        }
        assert_eq!(
            serde_json::to_value(Provenance::AgentFromBinaryText).unwrap(),
            "agent_from_binary_text"
        );
        rt(LogStatus::Applied);
        rt(LogStatus::Orphaned);
        rt(LogStatus::Rejected { reason: "r".into() });
        rt(SyncState::Pending);
        rt(SyncState::Pushed);
        rt(SyncState::EngineRejected { reason: "r".into() });
        rt(Completeness::Complete);
        rt(Completeness::NotAnalyzed);
        rt(Completeness::Partial {
            reason: "decompiler switch analysis pending".into(),
        });
        rt(FunctionSummary {
            locator: Locator::ram(0x401000),
            name: "main".into(),
            size: Some(32),
            signature: Some("int main(void)".into()),
            fn_hash: Some("abc".into()),
            completeness: Completeness::Complete,
        });
        rt(FunctionSummary {
            locator: Locator::ram(0x401000),
            name: "f".into(),
            size: None,
            signature: None,
            fn_hash: None,
            completeness: Completeness::NotAnalyzed,
        });
        rt(PROTOCOL_VERSION);
        rt(Capability {
            name: "decompiler".into(),
            version: 1,
        });
        rt(Handshake {
            protocol: PROTOCOL_VERSION,
            build: "test".into(),
            capabilities: vec![Capability {
                name: "loader".into(),
                version: 1,
            }],
        });
    }
}

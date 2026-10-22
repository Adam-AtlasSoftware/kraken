//! Plain data types used by the capability traits.

use kraken_proto::{DisasmScope, ErrorCode, Hex64, ProtoError, TypeDef, XrefDirection, XrefKind};
use serde::{Deserialize, Serialize};

/// Hints for opening a binary; unset fields are auto-detected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoaderSpec {
    /// Architecture/language id override such as `"x86:LE:64:default"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    /// Image base override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<Hex64>,
    /// Container format override such as `"elf"`; an unknown format is `unsupported`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Facts about the loaded program.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramInfo {
    /// Architecture/language id.
    pub arch: String,
    /// Container format such as `"elf"`, `"pe"`, `"macho"`, `"coff"` (an object file) or
    /// `"ar"` (a static or import library).
    pub format: String,
    /// Image base.
    pub base: Hex64,
    /// Lower-case hex SHA-256 of the file.
    pub sha256: String,
    /// File size in bytes.
    pub size: u64,
    /// What the file is, in plain words (`Linux shared library`, `Windows static library with
    /// 2 objects`); absent when the engine does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The members of a static or import library, in file order; empty for other files.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

/// A staged analysis pass (decisions 75, 90).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Loader.
    Load,
    /// All analyzers except the expensive list.
    Core,
    /// Expensive analyzers (decompiler switch analysis, parameter id, ...).
    Expensive,
}

impl Stage {
    /// All stages in execution order.
    pub const ALL: [Stage; 3] = [Stage::Load, Stage::Core, Stage::Expensive];

    /// Wire name: `"load"`, `"core"` or `"expensive"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Load => "load",
            Stage::Core => "core",
            Stage::Expensive => "expensive",
        }
    }
}

/// What the engine is doing inside a stage: the analyzer (or sub-step) and its own count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// Its name, as the engine calls it (engine text).
    pub name: String,
    /// Units done; 0 with `total` 0 when the step gives no count.
    pub done: u64,
    /// Units in all; 0 when unknown.
    pub total: u64,
}

/// One progress event of an analysis job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    /// Stage being run.
    pub stage: Stage,
    /// Work units done within the stage.
    pub done: u64,
    /// Total work units within the stage.
    pub total: u64,
    /// Human-readable status.
    pub message: String,
    /// The step within the stage, when the engine tells.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<Step>,
}

/// Parameters of [`Analyzer::analyze`](crate::Analyzer::analyze).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzeRequest {
    /// Resume: skip every stage before this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<Stage>,
}

/// Result of a finished analysis job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisSummary {
    /// Stages that ran to completion, in order.
    pub stages_completed: Vec<Stage>,
    /// Number of functions known afterwards.
    pub function_count: u64,
}

/// Opaque checkpoint id returned by [`Mutator::save`](crate::Mutator::save); everything applied
/// before the save is durable in the engine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Watermark(pub String);

/// An engine refused a mutation (decision 57).
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{code}: {reason}")]
pub struct EngineRejected {
    /// Error code; `engine_rejected` unless a more specific code applies (`not_found`,
    /// `conflict_stale_read`, `unsupported`, `invalid_argument`, `cancelled`).
    pub code: ErrorCode,
    /// Why the engine refused.
    pub reason: String,
}

impl EngineRejected {
    /// A rejection with a specific code.
    pub fn new(code: ErrorCode, reason: impl Into<String>) -> Self {
        EngineRejected {
            code,
            reason: reason.into(),
        }
    }

    /// A generic `engine_rejected`.
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self::new(ErrorCode::EngineRejected, reason)
    }
}

impl From<EngineRejected> for ProtoError {
    fn from(e: EngineRejected) -> Self {
        ProtoError::new(e.code, e.reason)
    }
}

impl From<ProtoError> for EngineRejected {
    fn from(e: ProtoError) -> Self {
        EngineRejected::new(e.code, e.message)
    }
}

/// Parameters of [`Disassembler::disassemble`](crate::Disassembler::disassemble).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisasmRequest {
    /// Where to start (`ram` space); inside the function for [`DisasmScope::Function`].
    pub start: Hex64,
    /// Whether to stay within one function.
    pub scope: DisasmScope,
}

/// Parameters of [`XrefProvider::xrefs`](crate::XrefProvider::xrefs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefRequest {
    /// The address queried (`ram` space).
    pub address: Hex64,
    /// References to or from the address.
    pub direction: XrefDirection,
    /// Keep only references of this kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<XrefKind>,
    /// With [`XrefDirection::From`]: all references originating anywhere in the function that
    /// contains `address`, not just at the address itself.
    #[serde(default)]
    pub whole_function: bool,
}

/// Parameters of [`StringLister::strings`](crate::StringLister::strings).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringsRequest {
    /// Shortest string to report, in characters.
    pub min_len: u32,
    /// Keep only strings containing this text (case-insensitive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

/// The name of a type definition, if it has one (anonymous function prototypes do not).
pub fn type_def_name(def: &TypeDef) -> Option<&str> {
    match def {
        TypeDef::Struct(c) | TypeDef::Union(c) => Some(&c.name),
        TypeDef::Enum(e) => Some(&e.name),
        TypeDef::Typedef(t) => Some(&t.name),
        TypeDef::Function(f) => f.name.as_deref(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_names_are_stable() {
        for s in Stage::ALL {
            assert_eq!(
                serde_json::to_value(s).unwrap(),
                serde_json::json!(s.as_str())
            );
        }
        assert!(Stage::Load < Stage::Core && Stage::Core < Stage::Expensive);
    }

    #[test]
    fn rejection_maps_to_proto_error() {
        let p: ProtoError = EngineRejected::new(ErrorCode::NotFound, "gone").into();
        assert_eq!(p.code, ErrorCode::NotFound);
        assert_eq!(p.message, "gone");
    }
}

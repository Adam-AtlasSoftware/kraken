//! The versioned edit-log operation enum (decision 70).
//!
//! Serialized with `"op"` as the tag; the surrounding [`VersionedLogOp`] carries
//! `schema_version`. New ops are added as new variants without changing `LOG_SCHEMA_VERSION`;
//! changing the meaning of an existing op bumps it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtoError};
use crate::hex::Hex64;
use crate::locator::{AddressRange, Anchor};
use crate::types::TypeRef;

/// Schema version written with every persisted log operation.
pub const LOG_SCHEMA_VERSION: u32 = 1;

/// Kind of listing comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommentKind {
    /// Comment above a function or label.
    Plate,
    /// Comment on the line before an instruction.
    Pre,
    /// End-of-line comment.
    Eol,
    /// Comment on the line after an instruction.
    Post,
    /// Repeatable comment shown at every reference.
    Repeatable,
}

/// What an address is defined as.
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeData {
    /// Disassembled code.
    Code,
    /// Data of an optional type.
    Data {
        /// Data type, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        data_type: Option<TypeRef>,
    },
    /// Neither code nor data.
    Undefined,
}

/// One edit-log operation; each carries the anchor it applies to and the old value for undo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LogOp {
    /// Rename a symbol.
    Rename {
        /// Target of the rename.
        anchor: Anchor,
        /// Name before the edit, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_name: Option<String>,
        /// Name after the edit.
        new_name: String,
    },
    /// Set the type of an item.
    SetType {
        /// Target item.
        anchor: Anchor,
        /// Type before the edit, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<TypeRef>,
        /// Type after the edit.
        new: TypeRef,
    },
    /// Set or clear a comment.
    SetComment {
        /// Target item.
        anchor: Anchor,
        /// Which comment slot is edited.
        comment_kind: CommentKind,
        /// Text before the edit, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<String>,
        /// Text after the edit; absent clears the comment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        new: Option<String>,
    },
    /// Create a function.
    CreateFunction {
        /// Function entry.
        anchor: Anchor,
        /// Name to give the function, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Explicit body, if the engine should not infer it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        body: Option<AddressRange>,
    },
    /// Delete a function.
    DeleteFunction {
        /// Function entry.
        anchor: Anchor,
        /// Body before the edit, kept for undo.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_body: Option<AddressRange>,
    },
    /// Change a function's address range.
    SetFunctionBounds {
        /// Function entry.
        anchor: Anchor,
        /// Body before the edit, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<AddressRange>,
        /// Body after the edit.
        new: AddressRange,
    },
    /// Mark an address as code, data or undefined.
    SetCodeData {
        /// Target address.
        anchor: Anchor,
        /// Definition before the edit, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<CodeData>,
        /// Definition after the edit.
        new: CodeData,
        /// Length in bytes of the affected region, if not implied by the type.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        length: Option<Hex64>,
    },
    /// Set a function's calling convention.
    SetCallingConvention {
        /// Function entry.
        anchor: Anchor,
        /// Convention before the edit, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old: Option<String>,
        /// Convention after the edit.
        new: String,
    },
}

/// A [`LogOp`] together with the schema version it was written under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VersionedLogOp {
    /// Log schema version; see [`LOG_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The operation.
    pub op: LogOp,
}

impl VersionedLogOp {
    /// Wraps `op` with the current schema version.
    pub fn new(op: LogOp) -> Self {
        VersionedLogOp {
            schema_version: LOG_SCHEMA_VERSION,
            op,
        }
    }

    /// Fails with `unsupported` when the entry was written by a newer schema than this build knows.
    pub fn check_version(&self) -> Result<(), ProtoError> {
        if self.schema_version > LOG_SCHEMA_VERSION {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "log schema version {} is newer than supported {}",
                    self.schema_version, LOG_SCHEMA_VERSION
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Primitive;
    use crate::types::PrimitiveClass;

    fn anchor() -> Anchor {
        Anchor::Native {
            space: "ram".into(),
            offset: Hex64(0x401000),
            fn_entry: Hex64(0x401000),
            fn_hash: "h".into(),
        }
    }

    fn range() -> AddressRange {
        AddressRange {
            space: "ram".into(),
            start: Hex64(0x401000),
            end: Hex64(0x401020),
        }
    }

    fn ty() -> TypeRef {
        TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size: 4,
            signed: true,
        })
    }

    fn all_ops() -> Vec<LogOp> {
        vec![
            LogOp::Rename {
                anchor: anchor(),
                old_name: Some("FUN_00401000".into()),
                new_name: "main".into(),
            },
            LogOp::SetType {
                anchor: anchor(),
                old: None,
                new: ty(),
            },
            LogOp::SetComment {
                anchor: anchor(),
                comment_kind: CommentKind::Eol,
                old: None,
                new: Some("hi".into()),
            },
            LogOp::CreateFunction {
                anchor: anchor(),
                name: Some("f".into()),
                body: Some(range()),
            },
            LogOp::DeleteFunction {
                anchor: anchor(),
                old_body: Some(range()),
            },
            LogOp::SetFunctionBounds {
                anchor: anchor(),
                old: None,
                new: range(),
            },
            LogOp::SetCodeData {
                anchor: anchor(),
                old: Some(CodeData::Undefined),
                new: CodeData::Data {
                    data_type: Some(ty()),
                },
                length: Some(Hex64(4)),
            },
            LogOp::SetCodeData {
                anchor: anchor(),
                old: None,
                new: CodeData::Code,
                length: None,
            },
            LogOp::SetCallingConvention {
                anchor: anchor(),
                old: None,
                new: "__fastcall".into(),
            },
        ]
    }

    #[test]
    fn every_op_round_trips() {
        for op in all_ops() {
            let v = VersionedLogOp::new(op);
            let back: VersionedLogOp =
                serde_json::from_str(&serde_json::to_string(&v).unwrap()).unwrap();
            assert_eq!(back, v);
        }
        for k in [
            CommentKind::Plate,
            CommentKind::Pre,
            CommentKind::Post,
            CommentKind::Repeatable,
        ] {
            let back: CommentKind =
                serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
            assert_eq!(back, k);
        }
        let d = CodeData::Data { data_type: None };
        let back: CodeData = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn wire_shape_and_version_check() {
        let v = VersionedLogOp::new(all_ops().remove(0));
        let json = serde_json::to_value(&v).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["op"]["op"], "rename");
        assert!(v.check_version().is_ok());
        let newer = VersionedLogOp {
            schema_version: LOG_SCHEMA_VERSION + 1,
            ..v
        };
        assert_eq!(
            newer.check_version().unwrap_err().code,
            ErrorCode::Unsupported
        );
    }
}

//! Materialised annotation state and the pure fold that computes it from log ops.

use std::collections::BTreeMap;

use kraken_proto::{AddressRange, CodeData, Hex64, LogOp, TypeDef, TypeRef};
use serde::{Deserialize, Serialize};

use crate::keys::op_key;

/// Current value of one entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateValue {
    /// Symbol name.
    Name {
        /// The name.
        name: String,
    },
    /// Item type.
    Type {
        /// The type.
        ty: TypeRef,
    },
    /// Comment text for the key's comment slot.
    Comment {
        /// The text.
        text: String,
    },
    /// A function exists here.
    Function {
        /// Name given at creation, if any.
        name: Option<String>,
        /// Explicit body, if any.
        body: Option<AddressRange>,
    },
    /// Function body bounds.
    Bounds {
        /// The range.
        range: AddressRange,
    },
    /// Code/data definition.
    CodeData {
        /// The definition.
        def: CodeData,
        /// Affected length, if given.
        length: Option<Hex64>,
    },
    /// Calling convention.
    CallingConvention {
        /// Convention name.
        name: String,
    },
    /// A named type's definition.
    TypeDef {
        /// The definition.
        def: TypeDef,
    },
    /// A byte patch.
    Patch {
        /// The program's bytes, hex.
        original: String,
        /// The replacement bytes, hex.
        replacement: String,
        /// Its note.
        note: String,
        /// Its patch set; empty for none.
        #[serde(default)]
        group: String,
        /// Switched off.
        #[serde(default)]
        disabled: bool,
    },
}

/// Entity key to current value; absent keys have no value.
pub type AnnotationState = BTreeMap<String, StateValue>;

/// Name of the "no type" type; setting it clears the type.
pub const UNDEFINED_TYPE: &str = "undefined";

fn is_undefined_type(t: &TypeRef) -> bool {
    matches!(t, TypeRef::Named { name } if name == UNDEFINED_TYPE)
}

/// Applies one op to `state`. Ops are absolute (they set the new value, never a delta), so a fold
/// over applied entries is order-correct without consulting `old` values.
///
/// Clearing sentinels, needed so undo can invert ops whose `old` was `None`: an empty
/// name/calling convention, the `undefined` named type, `CodeData::Undefined` and an empty range
/// (`start == end`) remove the value. Ops on reserved anchor kinds are ignored.
pub fn apply_op(state: &mut AnnotationState, op: &LogOp) {
    let Ok(key) = op_key(op) else { return };
    let value = match op {
        LogOp::Rename { new_name, .. } => (!new_name.is_empty()).then(|| StateValue::Name {
            name: new_name.clone(),
        }),
        LogOp::SetType { new, .. } => {
            (!is_undefined_type(new)).then(|| StateValue::Type { ty: new.clone() })
        }
        LogOp::SetComment { new, .. } => new.clone().map(|text| StateValue::Comment { text }),
        LogOp::CreateFunction { name, body, .. } => Some(StateValue::Function {
            name: name.clone(),
            body: body.clone(),
        }),
        LogOp::DeleteFunction { .. } => None,
        LogOp::SetFunctionBounds { new, .. } => {
            (new.start != new.end).then(|| StateValue::Bounds { range: new.clone() })
        }
        LogOp::SetCodeData { new, length, .. } => {
            (*new != CodeData::Undefined).then(|| StateValue::CodeData {
                def: new.clone(),
                length: *length,
            })
        }
        LogOp::SetCallingConvention { new, .. } => {
            (!new.is_empty()).then(|| StateValue::CallingConvention { name: new.clone() })
        }
        LogOp::DefineType { new, .. } => new.clone().map(|def| StateValue::TypeDef { def }),
        LogOp::SetPatch { original, new, .. } => new.as_ref().map(|b| StateValue::Patch {
            original: original.clone(),
            replacement: b.replacement.clone(),
            note: b.note.clone(),
            group: b.group.clone(),
            disabled: b.disabled,
        }),
    };
    match value {
        Some(v) => {
            state.insert(key, v);
        }
        None => {
            state.remove(&key);
        }
    }
}

/// The compensating op for `op`: `old` and `new` swapped, `CreateFunction` and `DeleteFunction`
/// exchanged. A function's name is not recorded by `DeleteFunction`, so undoing a delete recreates
/// the function without a name.
pub fn invert_op(op: &LogOp) -> LogOp {
    match op.clone() {
        LogOp::Rename {
            anchor,
            old_name,
            new_name,
        } => LogOp::Rename {
            anchor,
            old_name: Some(new_name),
            new_name: old_name.unwrap_or_default(),
        },
        LogOp::SetType { anchor, old, new } => LogOp::SetType {
            anchor,
            old: Some(new),
            new: old.unwrap_or(TypeRef::Named {
                name: UNDEFINED_TYPE.into(),
            }),
        },
        LogOp::SetComment {
            anchor,
            comment_kind,
            old,
            new,
        } => LogOp::SetComment {
            anchor,
            comment_kind,
            old: new,
            new: old,
        },
        LogOp::CreateFunction { anchor, body, .. } => LogOp::DeleteFunction {
            anchor,
            old_body: body,
        },
        LogOp::DeleteFunction { anchor, old_body } => LogOp::CreateFunction {
            anchor,
            name: None,
            body: old_body,
        },
        LogOp::SetFunctionBounds { anchor, old, new } => {
            let empty = AddressRange {
                space: new.space.clone(),
                start: Hex64(0),
                end: Hex64(0),
            };
            LogOp::SetFunctionBounds {
                anchor,
                old: Some(new),
                new: old.unwrap_or(empty),
            }
        }
        LogOp::SetCodeData {
            anchor,
            old,
            new,
            length,
        } => LogOp::SetCodeData {
            anchor,
            old: Some(new),
            new: old.unwrap_or(CodeData::Undefined),
            length,
        },
        LogOp::SetCallingConvention { anchor, old, new } => LogOp::SetCallingConvention {
            anchor,
            old: Some(new),
            new: old.unwrap_or_default(),
        },
        LogOp::DefineType { name, old, new } => LogOp::DefineType {
            name,
            old: new,
            new: old,
        },
        LogOp::SetPatch {
            anchor,
            original,
            old,
            new,
        } => LogOp::SetPatch {
            anchor,
            original,
            old: new,
            new: old,
        },
    }
}

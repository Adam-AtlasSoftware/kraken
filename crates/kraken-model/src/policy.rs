//! Additive-only policy for agent writes (decision 29).

use kraken_proto::{CodeData, LogOp, TypeRef};

use crate::keys::op_key;
use crate::state::{AnnotationState, StateValue, UNDEFINED_TYPE};

/// Whether an op only fills in missing information or replaces something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classification {
    /// Names on default-named symbols, new comments, types on undefined items.
    Additive,
    /// Anything else, including all structural ops and clearing a value.
    Overwrite,
}

const DEFAULT_PREFIXES: [&str; 8] = [
    "FUN_", "DAT_", "LAB_", "SUB_", "sub_", "UNK_", "PTR_", "loc_",
];

/// True for empty names and engine-generated default names such as `FUN_00401000`.
pub fn is_default_name(name: &str) -> bool {
    name.is_empty()
        || DEFAULT_PREFIXES.iter().any(|p| {
            name.strip_prefix(p)
                .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()))
        })
}

/// Classifies `op` against the current state. The op's own `old` value is consulted only when the
/// log holds no value yet, since the engine may have named or typed the item before any log entry.
pub fn classify(op: &LogOp, state: &AnnotationState) -> Classification {
    let current = op_key(op).ok().and_then(|k| state.get(&k));
    let additive = match op {
        LogOp::Rename { old_name, .. } => match current {
            Some(StateValue::Name { name }) => is_default_name(name),
            Some(_) => false,
            None => old_name.as_deref().is_none_or(is_default_name),
        },
        LogOp::SetType { old, .. } => {
            current.is_none()
                && old
                    .as_ref()
                    .is_none_or(|t| matches!(t, TypeRef::Named { name } if name == UNDEFINED_TYPE))
        }
        LogOp::SetComment { old, new, .. } => {
            new.is_some() && current.is_none() && old.as_deref().is_none_or(str::is_empty)
        }
        LogOp::SetCallingConvention { old, new, .. } => {
            !new.is_empty() && current.is_none() && old.as_deref().is_none_or(str::is_empty)
        }
        LogOp::SetCodeData { old, .. } => {
            current.is_none() && matches!(old, None | Some(CodeData::Undefined))
        }
        // A new patch only adds to the overlay: nothing on disk changes, and exporting a patched
        // binary always asks. Replacing or removing a patch overwrites someone's work, and so
        // does a patch that lands on bytes another patch already covers.
        LogOp::SetPatch { old, new, .. } => {
            new.is_some() && old.is_none() && current.is_none() && !overlaps_a_patch(op, state)
        }
        // Defining a name nothing has defined adds to the program; replacing or deleting a
        // definition changes what other edits and the decompiler already rely on.
        LogOp::DefineType { old, new, .. } => new.is_some() && old.is_none() && current.is_none(),
        // Giving a variable a name or type nothing has given it adds; changing or clearing one
        // overwrites a decision.
        LogOp::SetLocal { old, new, .. } => new.is_some() && old.is_none() && current.is_none(),
        LogOp::CreateFunction { .. }
        | LogOp::DeleteFunction { .. }
        | LogOp::SetFunctionBounds { .. } => false,
    };
    if additive {
        Classification::Additive
    } else {
        Classification::Overwrite
    }
}

/// Whether the patch `op` sets covers bytes that another patch in `state` (at a different
/// address) already covers.
fn overlaps_a_patch(op: &LogOp, state: &AnnotationState) -> bool {
    let LogOp::SetPatch {
        anchor,
        new: Some(new),
        ..
    } = op
    else {
        return false;
    };
    let Ok(own) = crate::keys::anchor_key(anchor) else {
        return false;
    };
    let Some(start) = key_address(&own) else {
        return false;
    };
    let end = start.saturating_add((new.replacement.len() / 2) as u64);
    state.iter().any(|(key, value)| {
        let StateValue::Patch { replacement, .. } = value else {
            return false;
        };
        let Some(base) = key.strip_suffix(":patch") else {
            return false;
        };
        let Some(other) = key_address(base) else {
            return false;
        };
        // an offset into the file and an address are different numberings
        if base.rsplit_once(':').map(|x| x.0) != own.rsplit_once(':').map(|x| x.0) {
            return false;
        }
        let other_end = other.saturating_add((replacement.len() / 2) as u64);
        other != start && other < end && other_end > start
    })
}

/// The address in an anchor key such as `native:ram:0x401000`.
fn key_address(key: &str) -> Option<u64> {
    let hex = key.rsplit(':').next()?.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{Anchor, Hex64, PatchBytes};

    fn set(at: u64, bytes: &str) -> LogOp {
        LogOp::SetPatch {
            anchor: Anchor::Native {
                space: "ram".into(),
                offset: Hex64(at),
                fn_entry: Hex64(at),
                fn_hash: String::new(),
            },
            original: "00".repeat(bytes.len() / 2),
            old: None,
            new: Some(PatchBytes {
                replacement: bytes.into(),
                note: String::new(),
                group: String::new(),
                disabled: false,
            }),
        }
    }

    #[test]
    fn a_patch_over_another_patch_is_not_additive() {
        let mut state = AnnotationState::new();
        assert_eq!(
            classify(&set(0x1000, "9090"), &state),
            Classification::Additive
        );
        state.insert(
            op_key(&set(0x1000, "")).expect("key"),
            StateValue::Patch {
                original: "00000000".into(),
                replacement: "90909090".into(),
                note: String::new(),
                group: String::new(),
                disabled: false,
            },
        );
        assert_eq!(
            classify(&set(0x1002, "9090"), &state),
            Classification::Overwrite
        );
        assert_eq!(
            classify(&set(0x1004, "9090"), &state),
            Classification::Additive
        );
        assert_eq!(
            classify(&set(0xffe, "9090"), &state),
            Classification::Additive
        );
    }

    #[test]
    fn a_new_type_is_additive_and_changing_or_deleting_one_is_not() {
        use kraken_proto::{Composite, TypeDef};
        let def = |size| {
            TypeDef::Struct(Composite {
                name: "packet".into(),
                size,
                align: 1,
                fields: Vec::new(),
            })
        };
        let op = |old: Option<TypeDef>, new: Option<TypeDef>| LogOp::DefineType {
            name: "packet".into(),
            old,
            new,
        };
        let mut state = AnnotationState::new();
        assert_eq!(
            classify(&op(None, Some(def(4))), &state),
            Classification::Additive
        );
        // the engine already had the name (debug info): replacing it is not additive
        assert_eq!(
            classify(&op(Some(def(4)), Some(def(8))), &state),
            Classification::Overwrite
        );
        state.insert(
            op_key(&op(None, Some(def(4)))).expect("key"),
            StateValue::TypeDef { def: def(4) },
        );
        assert_eq!(
            classify(&op(None, Some(def(8))), &state),
            Classification::Overwrite
        );
        assert_eq!(
            classify(&op(Some(def(4)), None), &state),
            Classification::Overwrite
        );
    }
}

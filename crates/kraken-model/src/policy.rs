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
        // binary always asks. Replacing or removing a patch overwrites someone's work.
        LogOp::SetPatch { old, new, .. } => new.is_some() && old.is_none() && current.is_none(),
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

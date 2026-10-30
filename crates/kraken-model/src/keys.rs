//! Entity keys: stable strings naming one versioned aspect of one anchored item.

use kraken_proto::{Anchor, CommentKind, LogOp, ProtoError};

fn comment_suffix(kind: CommentKind) -> &'static str {
    match kind {
        CommentKind::Plate => "plate",
        CommentKind::Pre => "pre",
        CommentKind::Eol => "eol",
        CommentKind::Post => "post",
        CommentKind::Repeatable => "repeatable",
    }
}

/// Key prefix for an anchor, e.g. `native:ram:0x401000` or `managed:<mvid>:0x6000001`. Only the
/// address (or module and token) identifies the entity; the function hash is not part of the key.
pub fn anchor_key(anchor: &Anchor) -> Result<String, ProtoError> {
    if let Anchor::Managed { token } = anchor
        && anchor.managed_parts().is_some()
    {
        return Ok(format!("managed:{token}"));
    }
    let (space, offset, _, _) = anchor.native()?;
    Ok(format!("native:{space}:{:#x}", offset.0))
}

/// Aspect-qualified key such as `native:ram:0x401000:name`.
pub fn entity_key(anchor: &Anchor, aspect: &str) -> Result<String, ProtoError> {
    Ok(format!("{}:{aspect}", anchor_key(anchor)?))
}

/// The aspect string a log op writes: `name`, `type`, `comment:<kind>`, `function`, `bounds`,
/// `codedata`, `cc` or `patch`.
pub fn op_aspect(op: &LogOp) -> String {
    match op {
        LogOp::Rename { .. } => "name".into(),
        LogOp::SetType { .. } => "type".into(),
        LogOp::SetComment { comment_kind, .. } => {
            format!("comment:{}", comment_suffix(*comment_kind))
        }
        LogOp::CreateFunction { .. } | LogOp::DeleteFunction { .. } => "function".into(),
        LogOp::SetFunctionBounds { .. } => "bounds".into(),
        LogOp::SetCodeData { .. } => "codedata".into(),
        LogOp::SetCallingConvention { .. } => "cc".into(),
        LogOp::SetPatch { .. } => "patch".into(),
        LogOp::SetLocal { storage, .. } => format!("local:{storage}"),
        LogOp::DefineType { .. } => "typedef".into(),
    }
}

/// The anchor a log op applies to; type definitions have none.
pub fn op_anchor(op: &LogOp) -> Option<&Anchor> {
    Some(match op {
        LogOp::Rename { anchor, .. }
        | LogOp::SetType { anchor, .. }
        | LogOp::SetComment { anchor, .. }
        | LogOp::CreateFunction { anchor, .. }
        | LogOp::DeleteFunction { anchor, .. }
        | LogOp::SetFunctionBounds { anchor, .. }
        | LogOp::SetCodeData { anchor, .. }
        | LogOp::SetCallingConvention { anchor, .. }
        | LogOp::SetLocal { anchor, .. }
        | LogOp::SetPatch { anchor, .. } => anchor,
        LogOp::DefineType { .. } => return None,
    })
}

/// The single entity key a log op writes.
pub fn op_key(op: &LogOp) -> Result<String, ProtoError> {
    if let LogOp::DefineType { name, .. } = op {
        return Ok(format!("type:{name}"));
    }
    match op_anchor(op) {
        Some(a) => entity_key(a, &op_aspect(op)),
        None => Err(ProtoError::new(
            kraken_proto::ErrorCode::InvalidArgument,
            "op has no anchor",
        )),
    }
}

/// Short name of a log op, such as `rename` or `set_type`.
pub fn op_kind_name(op: &LogOp) -> &'static str {
    match op {
        LogOp::Rename { .. } => "rename",
        LogOp::SetType { .. } => "set_type",
        LogOp::SetComment { .. } => "set_comment",
        LogOp::CreateFunction { .. } => "create_function",
        LogOp::DeleteFunction { .. } => "delete_function",
        LogOp::SetFunctionBounds { .. } => "set_function_bounds",
        LogOp::SetCodeData { .. } => "set_code_data",
        LogOp::SetCallingConvention { .. } => "set_calling_convention",
        LogOp::SetPatch { .. } => "set_patch",
        LogOp::SetLocal { .. } => "set_local",
        LogOp::DefineType { .. } => "define_type",
    }
}

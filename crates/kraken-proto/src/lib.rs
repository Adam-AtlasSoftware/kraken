//! KRAKEN wire and schema types.
//!
//! Engine-neutral types shared by the daemon, engines, clients and the Java extension; no
//! async runtime, GUI or FFI dependencies.
//!
//! Conventions: field names are snake_case; enums are internally tagged (`"kind"`, or `"op"` for
//! [`LogOp`]) with snake_case variant names; every 64-bit address, offset or length that may exceed
//! 2^53 is a [`Hex64`] and serializes as a `"0x..."` string. Sizes, counts and enum values are
//! plain JSON numbers.

pub mod decompile;
pub mod error;
pub mod hex;
pub mod locator;
pub mod logop;
pub mod meta;
pub mod page;
pub mod types;
pub mod untrusted;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use decompile::{DecompileResult, LANGUAGE_C, Token, TokenKind};
pub use error::{ErrorCode, ProtoError};
pub use hex::{Hex64, ParseHexError};
pub use locator::{AddressRange, Anchor, DEFAULT_SPACE, Locator};
pub use logop::{CodeData, CommentKind, LOG_SCHEMA_VERSION, LogOp, VersionedLogOp};
pub use meta::{
    Capability, Completeness, FunctionSummary, Handshake, LogStatus, PROTOCOL_VERSION,
    ProtocolVersion, Provenance, SyncState,
};
pub use page::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT, Page, PageRequest};
pub use types::{
    Bitfield, Composite, EnumDef, EnumVariant, Field, FunctionPrototype, Param, Primitive,
    PrimitiveClass, TypeDef, TypeRef, TypedefDef,
};
pub use untrusted::{Untrusted, sanitize};

/// Root of the generated JSON Schema: one field per top-level protocol type.
///
/// Never sent on the wire; it exists so `cargo xtask schema` can emit a single schema whose
/// `$defs` contain every protocol type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProtoSchema {
    /// See [`Locator`].
    pub locator: Locator,
    /// See [`Anchor`].
    pub anchor: Anchor,
    /// See [`AddressRange`].
    pub address_range: AddressRange,
    /// See [`TypeRef`].
    pub type_ref: TypeRef,
    /// See [`TypeDef`].
    pub type_def: TypeDef,
    /// See [`VersionedLogOp`].
    pub log_op: VersionedLogOp,
    /// See [`Provenance`].
    pub provenance: Provenance,
    /// See [`LogStatus`].
    pub log_status: LogStatus,
    /// See [`SyncState`].
    pub sync_state: SyncState,
    /// See [`FunctionSummary`].
    pub function_summary: FunctionSummary,
    /// See [`DecompileResult`].
    pub decompile_result: DecompileResult,
    /// See [`Completeness`].
    pub completeness: Completeness,
    /// See [`ProtoError`].
    pub error: ProtoError,
    /// See [`Handshake`].
    pub handshake: Handshake,
    /// See [`PageRequest`].
    pub page_request: PageRequest,
    /// A page of function summaries, the canonical [`Page`] instantiation.
    pub function_page: Page<FunctionSummary>,
    /// An untrusted string, the canonical [`Untrusted`] instantiation.
    pub untrusted_string: Untrusted<String>,
}

/// Generates the combined JSON Schema as pretty-printed JSON with a trailing newline.
pub fn schema_json() -> String {
    let schema = schemars::schema_for!(ProtoSchema);
    let mut s = serde_json::to_string_pretty(&schema).expect("schema serializes");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_schema_is_current() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schema/kraken-proto.schema.json");
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == schema_json(),
            "schema/kraken-proto.schema.json is stale: run cargo xtask schema"
        );
    }

    #[test]
    fn schema_covers_hex_and_recursion() {
        let v: serde_json::Value = serde_json::from_str(&schema_json()).unwrap();
        let defs = v["$defs"].as_object().unwrap();
        for name in [
            "Hex64",
            "TypeRef",
            "LogOp",
            "ProtoError",
            "Untrusted_string",
        ] {
            assert!(defs.contains_key(name), "missing {name}");
        }
    }
}

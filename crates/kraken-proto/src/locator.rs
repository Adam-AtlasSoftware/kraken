//! Engine-neutral locations and persisted log anchors.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtoError};
use crate::hex::Hex64;

/// Name of the default address space.
pub const DEFAULT_SPACE: &str = "ram";

fn default_space() -> String {
    DEFAULT_SPACE.to_string()
}

/// Where something lives in a program; protocol-level and extensible with new variants.
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Locator {
    /// An offset in a named address space.
    Native {
        /// Address-space name; defaults to `"ram"`.
        #[serde(default = "default_space")]
        space: String,
        /// Offset within the space, hex-encoded on the wire.
        offset: Hex64,
    },
    /// A member or type of a managed (.NET) module, identified by its metadata token.
    Managed {
        /// Module version id (MVID) as a lowercase hyphenated GUID; it pins the token to one build
        /// of the assembly.
        module: String,
        /// ECMA-335 metadata token (table in the high byte, row in the low 24 bits), e.g.
        /// `0x06000001` for the first method. A plain JSON number.
        token: u32,
    },
}

impl Locator {
    /// A locator in the default `"ram"` space.
    pub fn ram(offset: u64) -> Self {
        Locator::Native {
            space: default_space(),
            offset: Hex64(offset),
        }
    }

    /// A locator for a managed-code member or type.
    pub fn managed(module: impl Into<String>, token: u32) -> Self {
        Locator::Managed {
            module: module.into(),
            token,
        }
    }
}

/// A stable reference persisted in the edit log: function entry plus content hash.
///
/// Serialized with `"kind"` as the tag and always stored together with the log schema version.
/// Only `Native` is implemented; the other variants are reserved and rejected by [`Anchor::native`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Anchor {
    /// An address plus the entry and content hash of the containing function.
    Native {
        /// Address-space name; defaults to `"ram"`.
        #[serde(default = "default_space")]
        space: String,
        /// Offset of the anchored item, hex-encoded.
        offset: Hex64,
        /// Entry offset of the containing function, hex-encoded.
        fn_entry: Hex64,
        /// Hash of the function's original bytes, as an opaque string.
        fn_hash: String,
    },
    /// Reserved: a managed-code member identified by a token.
    Managed {
        /// Engine-specific member token.
        token: String,
    },
    /// Reserved: an address within a bank of a banked address space.
    Banked {
        /// Bank identifier.
        bank: String,
        /// Address-space name.
        space: String,
        /// Offset within the bank, hex-encoded.
        offset: Hex64,
    },
}

impl Anchor {
    /// An anchor for a managed (.NET) entity: the engine-specific token is `<module>:<0xtoken>`,
    /// with the module id (MVID) as in [`Locator::Managed`].
    pub fn managed(module: &str, token: u32) -> Self {
        Anchor::Managed {
            token: format!("{module}:{token:#x}"),
        }
    }

    /// `(module, token)` of a managed anchor made by [`Anchor::managed`]; `None` for other
    /// anchors and for malformed managed tokens.
    pub fn managed_parts(&self) -> Option<(&str, u32)> {
        let Anchor::Managed { token } = self else {
            return None;
        };
        let (module, hex) = token.rsplit_once(':')?;
        let token = u32::from_str_radix(hex.strip_prefix("0x")?, 16).ok()?;
        (!module.is_empty()).then_some((module, token))
    }

    /// Returns `(space, offset, fn_entry, fn_hash)` for a native anchor, or an `unsupported` error
    /// for the reserved variants.
    pub fn native(&self) -> Result<(&str, Hex64, Hex64, &str), ProtoError> {
        match self {
            Anchor::Native {
                space,
                offset,
                fn_entry,
                fn_hash,
            } => Ok((space, *offset, *fn_entry, fn_hash)),
            Anchor::Managed { .. } => Err(ProtoError::new(
                ErrorCode::Unsupported,
                "managed anchors are not supported yet",
            )),
            Anchor::Banked { .. } => Err(ProtoError::new(
                ErrorCode::Unsupported,
                "banked anchors are not supported yet",
            )),
        }
    }
}

/// A half-open address range `[start, end)` in one address space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct AddressRange {
    /// Address-space name; defaults to `"ram"`.
    #[serde(default = "default_space")]
    pub space: String,
    /// First offset in the range, hex-encoded.
    pub start: Hex64,
    /// One past the last offset, hex-encoded.
    pub end: Hex64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_anchor_parts_round_trip() {
        let a = Anchor::managed("61a35c05-1940-4673-81a7-f2157a66b75c", 0x0600_0001);
        assert_eq!(
            a.managed_parts(),
            Some(("61a35c05-1940-4673-81a7-f2157a66b75c", 0x0600_0001))
        );
        assert_eq!(
            Anchor::Managed {
                token: "0x06000001".into()
            }
            .managed_parts(),
            None
        );
        assert_eq!(Anchor::managed("m", 1).managed_parts(), Some(("m", 1)));
    }

    #[test]
    fn locator_round_trip_and_default_space() {
        let l = Locator::ram(0x401000);
        let json = serde_json::to_value(&l).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "native", "space": "ram", "offset": "0x401000"})
        );
        assert_eq!(serde_json::from_value::<Locator>(json).unwrap(), l);
        let no_space: Locator =
            serde_json::from_str(r#"{"kind":"native","offset":"0x10"}"#).unwrap();
        assert_eq!(no_space, Locator::ram(0x10));
    }

    #[test]
    fn managed_locator_round_trip() {
        let l = Locator::managed("6f1b2c3d-0000-4000-8000-0123456789ab", 0x0600_0001);
        let json = serde_json::to_value(&l).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "kind": "managed",
                "module": "6f1b2c3d-0000-4000-8000-0123456789ab",
                "token": 100663297u32,
            })
        );
        assert_eq!(serde_json::from_value::<Locator>(json).unwrap(), l);
        assert!(
            serde_json::from_str::<Locator>(r#"{"kind":"managed","module":"x","token":-1}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Locator>(r#"{"kind":"managed","token":1}"#).is_err());
    }

    #[test]
    fn anchor_round_trip_and_reserved_variants() {
        let native = Anchor::Native {
            space: "ram".into(),
            offset: Hex64(0x401010),
            fn_entry: Hex64(0x401000),
            fn_hash: "abc123".into(),
        };
        let managed = Anchor::Managed {
            token: "0x06000001".into(),
        };
        let banked = Anchor::Banked {
            bank: "2".into(),
            space: "rom".into(),
            offset: Hex64(0x8000),
        };
        for a in [&native, &managed, &banked] {
            let back: Anchor = serde_json::from_str(&serde_json::to_string(a).unwrap()).unwrap();
            assert_eq!(&back, a);
        }
        assert!(native.native().is_ok());
        assert_eq!(managed.native().unwrap_err().code, ErrorCode::Unsupported);
        assert_eq!(banked.native().unwrap_err().code, ErrorCode::Unsupported);
    }

    #[test]
    fn range_round_trip() {
        let r = AddressRange {
            space: "ram".into(),
            start: Hex64(0x1000),
            end: Hex64(0x1040),
        };
        let back: AddressRange = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}

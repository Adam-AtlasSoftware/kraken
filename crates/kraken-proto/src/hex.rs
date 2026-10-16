//! Hex-string encoding of 64-bit values.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

/// A `u64` that serializes as a lowercase hex string such as `"0x401000"`.
///
/// JSON consumers (Java, JavaScript, agents) cannot represent every `u64` as a number without
/// losing precision, so every address and offset on the wire uses this type. On input the `0x` or
/// `0X` prefix is required and 1 to 16 hex digits (either case) are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hex64(pub u64);

/// Error returned when a string is not a valid `0x`-prefixed 64-bit hex value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid hex u64 `{0}`: expected 0x followed by 1 to 16 hex digits")]
pub struct ParseHexError(pub String);

impl Hex64 {
    /// Formats the value as `0x` plus lowercase hex digits without leading zeros.
    pub fn to_hex(self) -> String {
        format!("{:#x}", self.0)
    }
}

impl fmt::Display for Hex64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

impl FromStr for Hex64 {
    type Err = ParseHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseHexError(s.to_string());
        let digits = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .ok_or_else(err)?;
        if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(err());
        }
        u64::from_str_radix(digits, 16)
            .map(Hex64)
            .map_err(|_| err())
    }
}

impl From<u64> for Hex64 {
    fn from(v: u64) -> Self {
        Hex64(v)
    }
}

impl From<Hex64> for u64 {
    fn from(v: Hex64) -> Self {
        v.0
    }
}

impl Serialize for Hex64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hex64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(d)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl JsonSchema for Hex64 {
    fn schema_name() -> Cow<'static, str> {
        "Hex64".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^0[xX][0-9a-fA-F]{1,16}$",
            "description": "Unsigned 64-bit integer as a 0x-prefixed hex string."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_without_padding() {
        assert_eq!(Hex64(0).to_hex(), "0x0");
        assert_eq!(Hex64(0x401000).to_hex(), "0x401000");
        assert_eq!(Hex64(u64::MAX).to_hex(), "0xffffffffffffffff");
    }

    #[test]
    fn parses_valid_values() {
        assert_eq!("0x0".parse(), Ok(Hex64(0)));
        assert_eq!("0X00ff".parse(), Ok(Hex64(255)));
        assert_eq!("0xFFFFFFFFFFFFFFFF".parse(), Ok(Hex64(u64::MAX)));
        assert_eq!("0x0000000000000001".parse(), Ok(Hex64(1)));
    }

    #[test]
    fn rejects_invalid_values() {
        for bad in [
            "",
            "0x",
            "401000",
            "-0x1",
            "+0x1",
            " 0x1",
            "0x1 ",
            "0x1_0",
            "0xg",
            "0x10000000000000000",
            "x10",
            "0x-1",
        ] {
            assert!(bad.parse::<Hex64>().is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn serde_round_trip_edges() {
        for v in [0, 1, 0x7fff_ffff_ffff_ffff, 1 << 63, u64::MAX] {
            let json = serde_json::to_string(&Hex64(v)).unwrap();
            assert_eq!(json, format!("\"{:#x}\"", v));
            assert_eq!(serde_json::from_str::<Hex64>(&json).unwrap(), Hex64(v));
        }
    }

    #[test]
    fn json_numbers_are_rejected() {
        assert!(serde_json::from_str::<Hex64>("4198400").is_err());
    }
}

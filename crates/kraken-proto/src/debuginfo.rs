//! What a binary says about its debug information, without reading any of it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A PDB that a PE image points at (its CodeView record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PdbRef {
    /// The path the linker recorded.
    pub name: crate::Untrusted<String>,
    /// The PDB's GUID, upper-case with dashes (`DEADBEEF-...`).
    pub guid: String,
    /// The PDB's age (how often it was updated).
    pub age: u32,
}

/// A `.gnu_debuglink` section: the name of a separate debug file and the CRC-32 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugLink {
    /// File name of the debug file.
    pub name: crate::Untrusted<String>,
    /// CRC-32 of the debug file's contents.
    pub crc: u32,
}

/// Where DWARF is, when the file has some.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DwarfState {
    /// Plain DWARF sections inside the file.
    Embedded,
    /// DWARF sections inside the file that are compressed (zlib or zstd).
    Compressed,
    /// The file points at DWARF kept in another file (`.gnu_debugaltlink`, `.debug_sup`, `.dwo`).
    Split,
}

/// The debug-information references of a binary. Every field is absent when the file has none.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct DebugRefs {
    /// The PDB a PE image names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdb: Option<PdbRef>,
    /// The GNU build-id, lower-case hex: the key of `/usr/lib/debug/.build-id/..` files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    /// The separate debug file named by `.gnu_debuglink`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debuglink: Option<DebugLink>,
    /// DWARF inside (or beside) the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dwarf: Option<DwarfState>,
}

impl DebugRefs {
    /// True when the debug data itself is inside the file (DWARF sections).
    pub fn embedded(&self) -> bool {
        matches!(
            self.dwarf,
            Some(DwarfState::Embedded | DwarfState::Compressed)
        )
    }

    /// True when the file names debug data that lives elsewhere.
    pub fn external(&self) -> bool {
        self.pdb.is_some() || self.debuglink.is_some() || self.dwarf == Some(DwarfState::Split)
    }
}

//! Program data: memory map, raw bytes, disassembly, cross-references, control-flow graphs,
//! strings and symbols.
//!
//! These are the engine-level shapes. Every text field is binary-derived and raw; the command
//! registry sanitises and marks it [`Untrusted`](crate::Untrusted) at its output boundary.
//! Addresses are `Hex64`; counts and lengths are plain numbers.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::hex::Hex64;
use crate::locator::{AddressRange, DEFAULT_SPACE, Locator};

fn default_space() -> String {
    DEFAULT_SPACE.to_string()
}

fn is_empty<T>(v: &[T]) -> bool {
    v.is_empty()
}

/// How a memory block is backed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// Ordinary block, initialized from the file or zero-filled.
    Default,
    /// Overlay block in its own address space.
    Overlay,
    /// Bytes are mapped from another part of memory.
    ByteMapped,
    /// Bits are mapped from another part of memory.
    BitMapped,
    /// Synthetic block holding external (imported) symbols.
    External,
}

/// One block (segment or section) of the program's memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryBlock {
    /// Block name such as `.text` (binary-derived).
    pub name: String,
    /// Address-space name; defaults to `"ram"`.
    #[serde(default = "default_space")]
    pub space: String,
    /// First address of the block.
    pub start: Hex64,
    /// First address after the block (half-open, like [`AddressRange`]).
    pub end: Hex64,
    /// Permissions as three characters, `r`, `w`, `x` or `-` in that order, such as `r-x`.
    pub perms: String,
    /// Whether the block has file or zero contents; uninitialized blocks (like `.bss`) have none.
    pub initialized: bool,
    /// How the block is backed.
    pub kind: MemoryKind,
}

impl MemoryBlock {
    /// The three-character permission string for the given flags.
    pub fn perms_string(read: bool, write: bool, execute: bool) -> String {
        [
            if read { 'r' } else { '-' },
            if write { 'w' } else { '-' },
            if execute { 'x' } else { '-' },
        ]
        .into_iter()
        .collect()
    }

    /// Size in bytes (`end - start`, saturating).
    pub fn len(&self) -> u64 {
        self.end.0.saturating_sub(self.start.0)
    }

    /// True for a block with no addresses.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

mod base64_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Bytes read from program memory. The read may be shorter than requested when it reaches the
/// end of mapped memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BytesRead {
    /// Address of the first byte.
    pub start: Hex64,
    /// The bytes, base64-encoded on the wire (standard alphabet, padded).
    #[serde(with = "base64_bytes")]
    #[schemars(with = "String")]
    pub bytes: Vec<u8>,
    /// Sub-ranges of the read that lie in uninitialized memory; their bytes are zero.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub uninitialized: Vec<AddressRange>,
}

/// Lower-case contiguous hex of `bytes`.
pub fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// What an operand token is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperandKind {
    /// A register name.
    Register,
    /// A numeric constant that is not an address.
    Immediate,
    /// An address without a symbol.
    Address,
    /// An address that has a symbol; `text` is the symbol name and `target` the address.
    Symbol,
    /// Punctuation, size keywords and anything else.
    Other,
}

/// One piece of an instruction operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OperandToken {
    /// Text of the token; for [`OperandKind::Symbol`] the raw symbol name.
    pub text: String,
    /// Token category.
    pub kind: OperandKind,
    /// The address an address or symbol token refers to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Locator>,
}

/// Control flow out of an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FlowKind {
    /// Execution continues with the next instruction.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Conditional jump (also falls through).
    ConditionalJump,
    /// Call (also falls through).
    Call,
    /// Return from the function.
    Return,
    /// Computed jump or call whose target is not a constant.
    Indirect,
    /// Anything else that ends or redirects flow, such as a halt.
    Other,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DisasmRow {
    /// Address of the instruction.
    pub address: Hex64,
    /// Instruction bytes as contiguous lower-case hex.
    pub bytes: String,
    /// Mnemonic such as `mov`.
    pub mnemonic: String,
    /// Operands flattened to tokens, with separators as `other` tokens.
    pub operands: Vec<OperandToken>,
    /// End-of-line or plate comment at the address, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Labels (symbols) defined at the address.
    #[serde(default, skip_serializing_if = "is_empty")]
    pub labels: Vec<String>,
    /// Control flow out of the instruction.
    pub flow: FlowKind,
}

/// Whether a disassembly stays within one function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DisasmScope {
    /// Instructions in address order from the start address onward.
    Linear,
    /// The body of the function containing the start address, entry first.
    Function,
}

/// Which way cross-references are followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum XrefDirection {
    /// References that point at the address.
    To,
    /// References that originate at the address.
    From,
}

/// What a reference does.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    /// Call.
    Call,
    /// Jump, conditional or not.
    Jump,
    /// Data read.
    Read,
    /// Data write.
    Write,
    /// Other data reference such as a pointer or an address taken.
    Data,
    /// Fall-through flow.
    Fallthrough,
    /// Anything else.
    Other,
}

/// A function named by an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionRef {
    /// Entry address.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: String,
}

/// A cross-reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Xref {
    /// Address the reference originates at.
    pub from: Hex64,
    /// Address the reference points to.
    pub to: Hex64,
    /// What the reference does.
    pub kind: XrefKind,
    /// The function containing `from`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<FunctionRef>,
    /// The function whose entry is `to`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_function: Option<FunctionRef>,
}

/// A basic block of a function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CfgBlock {
    /// Address of the first instruction.
    pub start: Hex64,
    /// Address after the last instruction (half-open).
    pub end: Hex64,
    /// Number of instructions in the block.
    pub instructions: u32,
}

/// Why control moves between blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CfgEdgeKind {
    /// The next block follows without a branch.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Branch taken when the condition holds.
    ConditionalTrue,
    /// Branch not taken (the fall-through of a conditional jump).
    ConditionalFalse,
    /// One case of a computed jump such as a switch table.
    Switch,
}

/// An edge between two blocks, named by their start addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CfgEdge {
    /// Start of the source block.
    pub from: Hex64,
    /// Start of the destination block.
    pub to: Hex64,
    /// Kind of the edge.
    pub kind: CfgEdgeKind,
}

/// The control-flow graph of one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Cfg {
    /// Function entry.
    pub function: Hex64,
    /// Blocks ordered by start address; the one at the entry is first by convention only.
    pub blocks: Vec<CfgBlock>,
    /// Edges between blocks of the function; calls and edges leaving the function are omitted.
    pub edges: Vec<CfgEdge>,
}

/// A computed jump (a `switch`, a dispatch table) and the addresses it can reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JumpTable {
    /// Entry of the function holding the jump.
    pub function: Hex64,
    /// Address of the computed jump instruction.
    pub jump: Hex64,
    /// Addresses the jump can reach, ascending and without repeats.
    pub targets: Vec<Hex64>,
}

/// Character encoding of a string in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// 7-bit ASCII.
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16.
    Utf16,
    /// UTF-32.
    Utf32,
    /// Anything else.
    Other,
}

/// A string found in memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StringEntry {
    /// Address of the first byte.
    pub address: Hex64,
    /// Decoded text (binary-derived).
    pub value: String,
    /// Encoding of the bytes.
    pub encoding: StringEncoding,
    /// Length in bytes in memory, including the terminator when there is one.
    pub length: u32,
}

/// What a symbol names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolKind {
    /// A function.
    Function,
    /// A data item.
    Data,
    /// Anything else.
    Other,
}

/// An imported or exported symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SymbolEntry {
    /// Symbol name (binary-derived).
    pub name: String,
    /// Address: the definition for an export, the stub or thunk (if any) for an import.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// Library an import comes from, when known; for an export of a static library, the archive
    /// member that defines it (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    /// What the symbol names.
    pub kind: SymbolKind,
    /// The mangled name as in the binary when `name` is a demangled one (`_Znwm` for
    /// `operator.new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mangled: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_as_base64() {
        let b = BytesRead {
            start: Hex64(0x401000),
            bytes: vec![0, 1, 2, 0xff, 0x80],
            uninitialized: vec![AddressRange {
                space: "ram".into(),
                start: Hex64(0x401003),
                end: Hex64(0x401005),
            }],
        };
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["bytes"], "AAEC/4A=");
        assert_eq!(serde_json::from_value::<BytesRead>(v).unwrap(), b);
        let none = BytesRead {
            uninitialized: vec![],
            ..b
        };
        assert!(
            serde_json::to_value(&none)
                .unwrap()
                .get("uninitialized")
                .is_none()
        );
    }

    #[test]
    fn bad_base64_is_rejected() {
        let v = serde_json::json!({"start": "0x1", "bytes": "***"});
        assert!(serde_json::from_value::<BytesRead>(v).is_err());
    }

    #[test]
    fn hex_and_perms() {
        assert_eq!(hex_bytes(&[0x48, 0x89, 0x05]), "488905");
        assert_eq!(MemoryBlock::perms_string(true, false, true), "r-x");
    }

    #[test]
    fn optional_fields_default() {
        let row: DisasmRow = serde_json::from_value(serde_json::json!({
            "address": "0x10", "bytes": "90", "mnemonic": "nop", "operands": [], "flow": "fallthrough"
        }))
        .unwrap();
        assert!(row.comment.is_none() && row.labels.is_empty());
        let blk: MemoryBlock = serde_json::from_value(serde_json::json!({
            "name": ".text", "start": "0x10", "end": "0x20", "perms": "r-x",
            "initialized": true, "kind": "default"
        }))
        .unwrap();
        assert_eq!(blk.space, "ram");
        assert_eq!(blk.len(), 16);
    }
}

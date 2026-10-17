//! Typed views of the data commands' JSON outputs (lenient: unknown fields are ignored).

use kraken_proto::{
    CfgBlock, CfgEdge, FlowKind, Hex64, MemoryKind, OperandKind, StringEncoding, SymbolKind,
    TokenKind, Untrusted, XrefKind,
};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MemoryMapWire {
    pub blocks: Vec<MemoryBlockWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MemoryBlockWire {
    pub name: Untrusted<String>,
    #[serde(default)]
    pub space: Option<String>,
    pub start: Hex64,
    pub end: Hex64,
    pub perms: String,
    pub initialized: bool,
    pub kind: MemoryKind,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OperandWire {
    pub kind: OperandKind,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub symbol: Option<Untrusted<String>>,
    #[serde(default)]
    pub target: Option<Hex64>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct InsnWire {
    pub address: Hex64,
    #[serde(default)]
    pub bytes: String,
    pub mnemonic: String,
    #[serde(default)]
    pub operands: Vec<OperandWire>,
    #[serde(default)]
    pub comment: Option<Untrusted<String>>,
    #[serde(default)]
    pub labels: Vec<Untrusted<String>>,
    pub flow: FlowKind,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct FnRefWire {
    pub address: Hex64,
    pub name: Untrusted<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct XrefWire {
    pub from: Hex64,
    pub to: Hex64,
    pub kind: XrefKind,
    #[serde(default)]
    pub from_function: Option<FnRefWire>,
    #[serde(default)]
    pub to_function: Option<FnRefWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct CfgWire {
    pub function: Hex64,
    #[serde(default)]
    pub blocks: Vec<CfgBlock>,
    #[serde(default)]
    pub edges: Vec<CfgEdge>,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StringWire {
    pub address: Hex64,
    pub value: Untrusted<String>,
    #[serde(default)]
    pub truncated: bool,
    pub encoding: StringEncoding,
    #[serde(default)]
    pub length: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SymbolWire {
    pub name: Untrusted<String>,
    #[serde(default)]
    pub address: Option<Hex64>,
    #[serde(default)]
    pub library: Option<Untrusted<String>>,
    pub kind: SymbolKind,
}

/// A decompiler token span as the registry sends it.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct TokenWire {
    pub start: u32,
    pub end: u32,
    pub kind: TokenKind,
    #[serde(default)]
    pub target: Option<Hex64>,
    /// Module id (MVID) of a .NET `target`, whose address is then a metadata token.
    #[serde(default)]
    pub target_module: Option<String>,
    #[serde(default)]
    pub symbol: Option<Untrusted<String>>,
}

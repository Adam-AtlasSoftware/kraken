//! Capability bundle and handshake.

use std::collections::BTreeSet;
use std::sync::Arc;

use kraken_proto::{Capability, Handshake, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

use crate::traits::{
    Analyzer, Assembler, Decompiler, Disassembler, FlowGraph, FunctionLister, Loader, MemoryReader,
    Mutator, StringLister, SymbolLister, TypeStore, XrefProvider,
};

/// A capability an engine may provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cap {
    /// [`Loader`].
    Loader,
    /// [`Analyzer`].
    Analyzer,
    /// [`Decompiler`].
    Decompiler,
    /// [`TypeStore`].
    TypeStore,
    /// [`FunctionLister`].
    FunctionLister,
    /// [`Mutator`].
    Mutator,
    /// [`MemoryReader`].
    Memory,
    /// [`Disassembler`].
    Disassembler,
    /// [`XrefProvider`].
    Xrefs,
    /// [`FlowGraph`].
    Cfg,
    /// [`StringLister`].
    Strings,
    /// [`SymbolLister`].
    Symbols,
    /// [`Assembler`].
    Assembler,
}

impl Cap {
    /// All capabilities.
    pub const ALL: [Cap; 13] = [
        Cap::Loader,
        Cap::Analyzer,
        Cap::Decompiler,
        Cap::TypeStore,
        Cap::FunctionLister,
        Cap::Mutator,
        Cap::Memory,
        Cap::Disassembler,
        Cap::Xrefs,
        Cap::Cfg,
        Cap::Strings,
        Cap::Symbols,
        Cap::Assembler,
    ];

    /// Name used in the handshake: `"loader"`, `"analyzer"`, `"decompiler"`, `"type_store"`,
    /// `"function_lister"`, `"mutator"`, `"memory"`, `"disassembler"`, `"xrefs"`, `"cfg"`,
    /// `"strings"`, `"symbols"`, `"assembler"`.
    pub fn name(self) -> &'static str {
        match self {
            Cap::Loader => "loader",
            Cap::Analyzer => "analyzer",
            Cap::Decompiler => "decompiler",
            Cap::TypeStore => "type_store",
            Cap::FunctionLister => "function_lister",
            Cap::Mutator => "mutator",
            Cap::Memory => "memory",
            Cap::Disassembler => "disassembler",
            Cap::Xrefs => "xrefs",
            Cap::Cfg => "cfg",
            Cap::Strings => "strings",
            Cap::Symbols => "symbols",
            Cap::Assembler => "assembler",
        }
    }
}

/// Which capabilities an engine has, plus its handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCaps {
    /// Protocol handshake; its capability list is derived from `present`.
    pub handshake: Handshake,
    /// Present capabilities in [`Cap::ALL`] order.
    pub present: Vec<Cap>,
}

impl EngineCaps {
    /// Builds caps (and the matching handshake) from a build id and the present capabilities.
    pub fn new(build: impl Into<String>, present: impl IntoIterator<Item = Cap>) -> Self {
        let present: Vec<Cap> = present
            .into_iter()
            .collect::<BTreeSet<Cap>>()
            .into_iter()
            .collect();
        EngineCaps {
            handshake: Handshake {
                protocol: PROTOCOL_VERSION,
                build: build.into(),
                capabilities: present
                    .iter()
                    .map(|c| Capability {
                        name: c.name().to_string(),
                        version: 1,
                    })
                    .collect(),
            },
            present,
        }
    }

    /// Whether `cap` is present.
    pub fn has(&self, cap: Cap) -> bool {
        self.present.contains(&cap)
    }
}

/// A bundle of capabilities. Absent capabilities return `None`, which callers treat as
/// `unsupported`.
pub trait Engine: Send + Sync {
    /// Capabilities and handshake; must agree with the accessors below.
    fn capabilities(&self) -> EngineCaps;
    /// The loader, if supported.
    fn loader(&self) -> Option<&dyn Loader> {
        None
    }
    /// The analyzer, if supported.
    fn analyzer(&self) -> Option<&dyn Analyzer> {
        None
    }
    /// The decompiler, if supported.
    fn decompiler(&self) -> Option<&dyn Decompiler> {
        None
    }
    /// The type store, if supported.
    fn type_store(&self) -> Option<&dyn TypeStore> {
        None
    }
    /// The function lister, if supported.
    fn function_lister(&self) -> Option<&dyn FunctionLister> {
        None
    }
    /// The mutator, if supported.
    fn mutator(&self) -> Option<&dyn Mutator> {
        None
    }
    /// The memory reader, if supported.
    fn memory_reader(&self) -> Option<&dyn MemoryReader> {
        None
    }
    /// The disassembler, if supported.
    fn disassembler(&self) -> Option<&dyn Disassembler> {
        None
    }
    /// The cross-reference provider, if supported.
    fn xref_provider(&self) -> Option<&dyn XrefProvider> {
        None
    }
    /// The control-flow-graph provider, if supported.
    fn flow_graph(&self) -> Option<&dyn FlowGraph> {
        None
    }
    /// The string lister, if supported.
    fn string_lister(&self) -> Option<&dyn StringLister> {
        None
    }
    /// The import/export lister, if supported.
    fn symbol_lister(&self) -> Option<&dyn SymbolLister> {
        None
    }
    /// The assembler, if supported.
    fn assembler(&self) -> Option<&dyn Assembler> {
        None
    }
}

/// How the registry holds engines.
pub type SharedEngine = Arc<dyn Engine>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_follows_present() {
        let c = EngineCaps::new("t", [Cap::Mutator, Cap::Loader, Cap::Loader]);
        assert_eq!(c.present, vec![Cap::Loader, Cap::Mutator]);
        let names: Vec<_> = c
            .handshake
            .capabilities
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["loader", "mutator"]);
        assert!(c.has(Cap::Loader) && !c.has(Cap::Decompiler));
    }
}

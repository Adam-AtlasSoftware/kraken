//! Capability bundle and handshake.

use std::collections::BTreeSet;
use std::sync::Arc;

use kraken_proto::{Capability, Handshake, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

use crate::traits::{Analyzer, Decompiler, FunctionLister, Loader, Mutator, TypeStore};

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
}

impl Cap {
    /// All capabilities.
    pub const ALL: [Cap; 6] = [
        Cap::Loader,
        Cap::Analyzer,
        Cap::Decompiler,
        Cap::TypeStore,
        Cap::FunctionLister,
        Cap::Mutator,
    ];

    /// Name used in the handshake: `"loader"`, `"analyzer"`, `"decompiler"`, `"type_store"`,
    /// `"function_lister"`, `"mutator"`.
    pub fn name(self) -> &'static str {
        match self {
            Cap::Loader => "loader",
            Cap::Analyzer => "analyzer",
            Cap::Decompiler => "decompiler",
            Cap::TypeStore => "type_store",
            Cap::FunctionLister => "function_lister",
            Cap::Mutator => "mutator",
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

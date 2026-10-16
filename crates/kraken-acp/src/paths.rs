//! Where agent support files live.
//!
//! Everything KRAKEN downloads for agents (a private Node.js, the npm adapters, the npm cache)
//! lives under `<data dir>/agents`, where the data dir is `$XDG_DATA_HOME/kraken` or
//! `~/.local/share/kraken`. Nothing is installed globally.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The agent directory layout under KRAKEN's data dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPaths {
    root: PathBuf,
}

impl AgentPaths {
    /// A layout rooted at `data_dir/agents`.
    pub fn in_data_dir(data_dir: impl AsRef<Path>) -> Self {
        AgentPaths {
            root: data_dir.as_ref().join("agents"),
        }
    }

    /// `$XDG_DATA_HOME/kraken/agents`, else `$HOME/.local/share/kraken/agents`.
    pub fn from_env() -> Option<Self> {
        Self::from_env_with(&|k| std::env::var_os(k))
    }

    /// [`from_env`](Self::from_env) with an injectable environment.
    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Self> {
        let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let base = non_empty("XDG_DATA_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| non_empty("HOME").map(|h| h.join(".local/share")))?;
        Some(Self::in_data_dir(base.join("kraken")))
    }

    /// The root (`<data dir>/agents`).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Downloaded archives and partial downloads.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }

    /// Parent of the extracted Node.js directories.
    pub fn node_dir(&self) -> PathBuf {
        self.root.join("node")
    }

    /// Parent of the installed adapters.
    pub fn adapters_dir(&self) -> PathBuf {
        self.root.join("adapters")
    }

    /// The npm cache used when installing adapters.
    pub fn npm_cache_dir(&self) -> PathBuf {
        self.root.join("npm-cache")
    }
}

/// The directory holding `config.toml` (so also the acknowledgement and `agents.toml`).
pub fn config_dir_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let file = kraken_host::KrakenConfig::default_path_with(env)?;
    file.parent().map(Path::to_path_buf)
}

//! The list of agents, what each needs, and the one-time warning.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kraken_acp::{
    AgentPaths, AgentProfile, AgentSetup, AgentStatus, Resolver, config_dir_with, load_catalogue,
};
use kraken_host::provision::Fetcher;

/// Whether an agent can run here, in the words the tab shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Ready to start.
    Ready {
        /// How it was found.
        via: String,
    },
    /// Not installed yet; "Set up" can install it.
    NeedsSetup {
        /// What is missing.
        reason: String,
        /// Setup would also download Node.js.
        downloads_node: bool,
    },
    /// Cannot start and setup cannot fix it; the reason says what to install.
    NotFound {
        /// Why, and what to do.
        reason: String,
    },
    /// This computer cannot run the agent.
    Unsupported {
        /// Why.
        reason: String,
    },
}

impl Availability {
    /// Short label for the row.
    pub fn label(&self) -> &'static str {
        match self {
            Availability::Ready { .. } => "Ready",
            Availability::NeedsSetup { .. } => "Needs setup",
            Availability::NotFound { .. } => "Not found",
            Availability::Unsupported { .. } => "Not supported here",
        }
    }

    /// The reason or detail line.
    pub fn detail(&self) -> &str {
        match self {
            Availability::Ready { via } => via,
            Availability::NeedsSetup { reason, .. }
            | Availability::NotFound { reason }
            | Availability::Unsupported { reason } => reason,
        }
    }
}

/// One agent in the list.
#[derive(Debug, Clone)]
pub struct AgentRow {
    /// Short id (`claude`).
    pub id: String,
    /// Name shown to people.
    pub name: String,
    /// One plain sentence.
    pub summary: String,
    /// Whether it can run here.
    pub availability: Availability,
    /// One of KRAKEN's own entries (not a custom one from `agents.toml`).
    pub builtin: bool,
    pub(crate) profile: AgentProfile,
}

impl AgentRow {
    /// Ready to start.
    pub fn is_ready(&self) -> bool {
        matches!(self.availability, Availability::Ready { .. })
    }
}

/// Where the agent settings find things. The window builds one from its settings; tests build
/// their own.
#[derive(Clone)]
pub struct AgentsConfig {
    /// How agents are found and set up.
    pub resolver: Resolver,
    /// KRAKEN's config directory (`agents.toml`, the saved acknowledgement).
    pub config_dir: Option<PathBuf>,
    /// The `kraken` executable agents run as their MCP server; found next to the window or on
    /// `PATH` when `None`.
    pub kraken_exe: Option<PathBuf>,
    /// Give agents `kraken mcp --daemon` so their edits reach this window live.
    pub use_daemon: bool,
    /// Extra environment for the MCP server (`KRAKEN_RUNTIME_DIR`, `KRAKEN_NO_DAEMON`).
    pub mcp_env: Vec<(String, String)>,
    /// The environment the agent's own is built from (`None`: this process's).
    pub parent_env: Option<Vec<(OsString, OsString)>>,
    /// Agents added on top of the built-in ones and `agents.toml` (tests, screenshots).
    pub extra_profiles: Vec<AgentProfile>,
    /// Where downloads come from (`None`: HTTPS).
    pub fetcher: Option<Arc<dyn Fetcher>>,
    /// How long an agent has to start.
    pub start_timeout: Duration,
}

impl AgentsConfig {
    /// A configuration over `resolver` with the defaults.
    pub fn new(resolver: Resolver, config_dir: Option<PathBuf>) -> Self {
        AgentsConfig {
            resolver,
            config_dir,
            kraken_exe: None,
            use_daemon: false,
            mcp_env: Vec::new(),
            parent_env: None,
            extra_profiles: Vec::new(),
            fetcher: None,
            start_timeout: Duration::from_secs(60),
        }
    }

    /// The real thing: the user's data and config directories. `None` when neither `HOME` nor
    /// `XDG_DATA_HOME` is set.
    pub fn from_env(use_daemon: bool) -> Option<Self> {
        let paths = AgentPaths::from_env()?;
        let mut c = AgentsConfig::new(
            Resolver::from_env(paths),
            config_dir_with(&|k| std::env::var_os(k)),
        );
        c.use_daemon = use_daemon;
        for key in ["KRAKEN_RUNTIME_DIR", "KRAKEN_NO_DAEMON"] {
            if let Ok(v) = std::env::var(key) {
                c.mcp_env.push((key.to_string(), v));
            }
        }
        // The agent does not get `XDG_RUNTIME_DIR`, so its MCP server is told where the daemon is.
        if use_daemon
            && !c.mcp_env.iter().any(|(k, _)| k == "KRAKEN_RUNTIME_DIR")
            && let Some((k, v)) = kraken_host::daemon::mcp_runtime_env()
        {
            c.mcp_env.push((k, v));
        }
        Some(c)
    }
}

pub(super) struct Built {
    pub(super) rows: Vec<AgentRow>,
    pub(super) catalogue_error: Option<String>,
    pub(super) platform_note: Option<String>,
}

/// Every known agent: the built-in ones, those of `agents.toml`, and `cfg.extra_profiles`. The
/// error says why `agents.toml` could not be read (the built-in ones are still listed).
pub(crate) fn profiles(cfg: &AgentsConfig) -> (Vec<AgentProfile>, Option<String>) {
    let (mut profiles, error) = match load_catalogue(cfg.config_dir.as_deref()) {
        Ok(p) => (p, None),
        Err(e) => (kraken_acp::builtin_profiles(), Some(e.to_string())),
    };
    profiles.extend(cfg.extra_profiles.iter().cloned());
    (profiles, error)
}

pub(super) fn build(cfg: &AgentsConfig) -> Built {
    let (profiles, catalogue_error) = profiles(cfg);
    let rows = profiles
        .into_iter()
        .map(|p| {
            let availability = match cfg.resolver.status(&p) {
                AgentStatus::Detected(l) => Availability::Ready { via: l.via },
                AgentStatus::Available {
                    reason,
                    needs_node_download,
                } => Availability::NeedsSetup {
                    reason,
                    downloads_node: needs_node_download,
                },
                AgentStatus::Missing { reason } => Availability::NotFound { reason },
                AgentStatus::Unsupported { reason } => Availability::Unsupported { reason },
            };
            AgentRow {
                id: p.id.clone(),
                name: p.display_name.clone(),
                summary: p.summary.clone(),
                availability,
                builtin: matches!(p.setup, AgentSetup::NodeAdapter(_)),
                profile: p,
            }
        })
        .collect();
    Built {
        rows,
        catalogue_error,
        platform_note: cfg.resolver.platform.supports_agents().err(),
    }
}

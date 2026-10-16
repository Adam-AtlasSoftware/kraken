//! The list of agents, what each needs, and the one-time warning.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kraken_acp::{
    AgentPaths, AgentProfile, AgentSetup, AgentStatus, LaunchSpec, NoticeStore, Resolver,
    config_dir_with, load_catalogue,
};
use kraken_host::provision::Fetcher;

use super::NoticeState;
use crate::vm::ViewModel;

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
    pub(crate) launch: Option<LaunchSpec>,
}

impl AgentRow {
    /// Ready to start.
    pub fn is_ready(&self) -> bool {
        matches!(self.availability, Availability::Ready { .. })
    }
}

/// Where the Agents tab finds things. The window builds one from its settings; tests build their
/// own.
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
        Some(c)
    }
}

struct Built {
    rows: Vec<AgentRow>,
    catalogue_error: Option<String>,
    platform_note: Option<String>,
}

fn build(cfg: &AgentsConfig) -> Built {
    let (mut profiles, catalogue_error) = match load_catalogue(cfg.config_dir.as_deref()) {
        Ok(p) => (p, None),
        Err(e) => (kraken_acp::builtin_profiles(), Some(e.to_string())),
    };
    profiles.extend(cfg.extra_profiles.iter().cloned());
    let rows = profiles
        .into_iter()
        .map(|p| {
            let status = cfg.resolver.status(&p);
            let (availability, launch) = match status {
                AgentStatus::Detected(l) => (Availability::Ready { via: l.via.clone() }, Some(l)),
                AgentStatus::Available {
                    reason,
                    needs_node_download,
                } => (
                    Availability::NeedsSetup {
                        reason,
                        downloads_node: needs_node_download,
                    },
                    None,
                ),
                AgentStatus::Missing { reason } => (Availability::NotFound { reason }, None),
                AgentStatus::Unsupported { reason } => (Availability::Unsupported { reason }, None),
            };
            AgentRow {
                id: p.id.clone(),
                name: p.display_name.clone(),
                summary: p.summary.clone(),
                availability,
                builtin: matches!(p.setup, AgentSetup::NodeAdapter(_)),
                profile: p,
                launch,
            }
        })
        .collect();
    Built {
        rows,
        catalogue_error,
        platform_note: cfg.resolver.platform.supports_agents().err(),
    }
}

impl ViewModel {
    /// Uses `config` for the Agents tab. Call before the tab is first drawn; it rereads the
    /// saved acknowledgement and clears the list.
    pub fn agents_configure(&mut self, config: AgentsConfig) {
        let store = config.config_dir.as_deref().map(NoticeStore::in_config_dir);
        self.agents.notice = NoticeState {
            acknowledged: store.as_ref().is_some_and(NoticeStore::is_acknowledged),
            save_error: None,
        };
        self.agents.store = store;
        self.agents.config = Some(config);
        self.agents.loaded = false;
        self.agents.loading = false;
        self.agents.rows.clear();
        self.agents.refresh_seq += 1;
    }

    /// Whether agents get the daemon-backed MCP server. Call when the project's backend is known.
    pub fn agents_set_daemon(&mut self, use_daemon: bool) {
        if let Some(c) = self.agents.config.as_mut() {
            c.use_daemon = use_daemon;
        } else if let Some(mut c) = AgentsConfig::from_env(use_daemon) {
            c.use_daemon = use_daemon;
            self.agents_configure(c);
        }
    }

    /// The configuration, made from the environment on first use.
    pub(crate) fn agents_config(&mut self) -> Option<AgentsConfig> {
        if self.agents.config.is_none() {
            match AgentsConfig::from_env(false) {
                Some(c) => self.agents_configure(c),
                None => {
                    self.agents.loaded = true;
                    self.agents.error = Some(
                        "KRAKEN cannot tell where to keep agent files: neither XDG_DATA_HOME nor HOME is set."
                            .into(),
                    );
                    return None;
                }
            }
        }
        self.agents.config.clone()
    }

    /// Builds the list the first time the tab is drawn.
    pub fn agents_ensure_loaded(&mut self) {
        if !self.agents.loaded && !self.agents.loading {
            self.agents_refresh();
        }
    }

    /// Looks again at what each agent needs (off the UI thread: it runs `node --version`).
    pub fn agents_refresh(&mut self) {
        let Some(cfg) = self.agents_config() else {
            return;
        };
        self.agents.loading = true;
        self.agents.refresh_seq += 1;
        let seq = self.agents.refresh_seq;
        let post = self.poster();
        let rt = post.runtime().clone();
        rt.spawn_blocking(move || {
            let built = build(&cfg);
            post.post(move |vm| {
                if vm.agents.refresh_seq != seq {
                    return;
                }
                vm.agents.rows = built.rows;
                vm.agents.catalogue_error = built.catalogue_error;
                vm.agents.platform_note = built.platform_note;
                vm.agents.loading = false;
                vm.agents.loaded = true;
            });
        });
    }

    /// The person read the warning. Remembers it in the config directory; if that fails the
    /// warning still counts for this run. Starts the agent that was waiting for it.
    pub fn agents_acknowledge(&mut self) {
        self.agents.notice.acknowledged = true;
        self.agents.notice.save_error = match &self.agents.store {
            Some(s) => s.acknowledge().err().map(|e| {
                format!("KRAKEN could not remember that you read this ({e}); it will ask again next time.")
            }),
            None => Some(
                "KRAKEN has no place to remember this; it will ask again next time.".to_string(),
            ),
        };
        if let Some(id) = self.agents.pending_notice.take() {
            self.agents_start(&id);
        }
    }

    /// Closes the warning without starting the agent.
    pub fn agents_cancel_notice(&mut self) {
        self.agents.pending_notice = None;
    }
}

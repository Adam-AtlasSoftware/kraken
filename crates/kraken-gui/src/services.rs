//! How the GUI reaches the engine: through `krakend` (default) or in its own process.

use std::path::PathBuf;
use std::sync::Arc;

use kraken_host::daemon::StartOptions;
use kraken_host::{HostEngineFactory, KrakenConfig, ManagedFactory};
use kraken_viewmodel::{Connector, default_connector};

/// Where real projects run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// In `krakend`, shared with the CLI and MCP agents (decision 13).
    Daemon,
    /// In this process (`--no-daemon`).
    NoDaemon,
}

/// Everything environment-specific, so tests can run without touching the user's files, the
/// user's daemon or a real engine.
pub struct Services {
    /// Daemon or in-process.
    pub mode: Mode,
    /// The effective configuration (file plus environment), for defaults such as the projects
    /// root.
    pub cfg: KrakenConfig,
    /// The configuration file the settings window edits.
    pub config_path: Option<PathBuf>,
    /// The preferences file (recent projects, theme).
    pub prefs_file: Option<PathBuf>,
    /// How to reach the daemon (`None`: the per-user default, started on demand).
    pub connector: Option<Connector>,
    /// The in-process engine factory of `--no-daemon`. The window runs it behind a private
    /// daemon of its own (see `private`), so a terminal agent shares the open project.
    pub ghidra: Option<Arc<dyn ManagedFactory>>,
    /// Where terminal agents are found (`None`: the user's directories, on first use).
    pub agents: Option<kraken_viewmodel::agents::AgentsConfig>,
    /// Offer the guided tour on the first launch.
    pub first_run_tour: bool,
    /// The daily totals of AI usage (for the daily budget); `None` keeps none.
    pub ai_daily: Option<kraken_model::DailyLedger>,
}

impl Services {
    /// The real thing: the user's configuration and files.
    pub fn from_env(no_daemon: bool) -> Self {
        let cfg = KrakenConfig::load().unwrap_or_else(|e| {
            eprintln!("kraken-gui: {e}; using defaults");
            KrakenConfig::default()
        });
        let ghidra = no_daemon
            .then(|| Arc::new(HostEngineFactory::new(cfg.clone())) as Arc<dyn ManagedFactory>);
        Services {
            mode: if no_daemon {
                Mode::NoDaemon
            } else {
                Mode::Daemon
            },
            cfg,
            config_path: KrakenConfig::default_path(),
            prefs_file: crate::recent::default_file(),
            connector: None,
            ghidra,
            agents: kraken_viewmodel::agents::AgentsConfig::from_env(!no_daemon),
            first_run_tour: true,
            ai_daily: kraken_model::DailyLedger::standard(),
        }
    }

    /// Nothing reachable and nothing persisted; for tests that do not need an engine.
    #[cfg(test)]
    pub fn offline() -> Self {
        Services {
            mode: Mode::Daemon,
            cfg: KrakenConfig::default(),
            config_path: None,
            prefs_file: None,
            connector: Some(Arc::new(|| {
                Box::pin(async { Err("no krakend in this test".to_string()) })
            })),
            ghidra: None,
            agents: Some(offline_agents()),
            first_run_tour: false,
            ai_daily: None,
        }
    }

    /// The connector to use for the daemon.
    pub fn connector(&self) -> Connector {
        self.connector
            .clone()
            .unwrap_or_else(|| default_connector(StartOptions::default()))
    }
}

/// Agent settings that touch nothing of the user's.
#[cfg(test)]
fn offline_agents() -> kraken_viewmodel::agents::AgentsConfig {
    use kraken_acp::{AgentPaths, Platform, Resolver};
    let dir = std::env::temp_dir().join("kraken-gui-test-agents-none");
    kraken_viewmodel::agents::AgentsConfig::new(
        Resolver {
            paths: AgentPaths::in_data_dir(&dir),
            platform: Platform::current(),
            path_env: Some(dir.into_os_string()),
        },
        None,
    )
}

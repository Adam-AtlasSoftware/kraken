//! How the GUI reaches the engine: through `krakend` (default) or in its own process.

use std::path::PathBuf;
use std::sync::Arc;

use kraken_host::daemon::StartOptions;
use kraken_host::{GhidraEngineFactory, KrakenConfig};
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
    /// The in-process engine factory of `--no-daemon`.
    pub ghidra: Option<Arc<GhidraEngineFactory>>,
}

impl Services {
    /// The real thing: the user's configuration and files.
    pub fn from_env(no_daemon: bool) -> Self {
        let cfg = KrakenConfig::load().unwrap_or_else(|e| {
            eprintln!("kraken-gui: {e}; using defaults");
            KrakenConfig::default()
        });
        let ghidra = no_daemon.then(|| Arc::new(GhidraEngineFactory::new(cfg.clone())));
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
        }
    }

    /// The connector to use for the daemon.
    pub fn connector(&self) -> Connector {
        self.connector
            .clone()
            .unwrap_or_else(|| default_connector(StartOptions::default()))
    }
}

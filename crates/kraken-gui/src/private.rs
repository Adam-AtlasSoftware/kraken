//! The private daemon of a `--no-daemon` window.
//!
//! A terminal agent works through its own `kraken mcp` process, and a project can be open in one
//! place only (the project lock), so an agent could never join a project that a window holds in
//! its own process. In `--no-daemon` mode the window therefore runs a `krakend` of its own, in
//! this process, on a runtime directory only it and its agents know, and is a client of that
//! daemon like any other window. The agent's MCP server attaches to the same daemon
//! (`kraken mcp --daemon`, `KRAKEN_RUNTIME_DIR`), so the window and the agent share one session.
//! Nothing outside this process can find it, and it stops with the window.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use kraken_host::{KrakenConfig, ManagedFactory};
use kraken_ipc::{RuntimeDir, SystemClock};
use kraken_viewmodel::{Connector, attach_connector};
use krakend::{Daemon, DaemonOptions};

/// Environment variables that point an MCP server at a daemon (or away from one).
const DAEMON_ENV: [&str; 2] = ["KRAKEN_RUNTIME_DIR", "KRAKEN_NO_DAEMON"];

const BUILD: &str = env!("CARGO_PKG_VERSION");

pub(crate) struct PrivateDaemon {
    daemon: Daemon,
    dir: RuntimeDir,
}

impl PrivateDaemon {
    /// Starts the daemon over `factory`. Needs a Tokio runtime context.
    pub(crate) fn start(
        factory: Arc<dyn ManagedFactory>,
        cfg: &KrakenConfig,
    ) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("kraken-gui-{}-{nanos:08x}", std::process::id()));
        let dir = RuntimeDir::from_dir(path)
            .map_err(|e| format!("Could not set up the private engine daemon: {e}"))?;
        let daemon = krakend::start_with(
            DaemonOptions {
                runtime_dir: dir.clone(),
                factory,
                registry: Arc::new(kraken_registry::Registry::standard()),
                settings: cfg.daemon.clone(),
                session_config: cfg.session_config(),
                clock: Arc::new(SystemClock::new()),
                poll: Duration::from_millis(100),
                build: BUILD.into(),
            },
            Some(kraken_rewrite::RewriteService::standard().into_backend()),
        )
        .map_err(|e| format!("Could not start the private engine daemon: {e}"))?;
        Ok(PrivateDaemon { daemon, dir })
    }

    /// The directory an MCP server connects through.
    pub(crate) fn runtime_dir(&self) -> &Path {
        self.dir.path()
    }

    /// How the window connects.
    pub(crate) fn connector(&self) -> Connector {
        attach_connector(self.dir.clone())
    }

    /// Stops the daemon: it saves and closes the open projects, then removes its runtime files.
    pub(crate) async fn stop(self) {
        self.daemon.shutdown();
        self.daemon.wait().await;
        let _ = std::fs::remove_dir_all(self.dir.path());
    }
}

/// Points the agent's MCP server at the daemon in `runtime_dir`, whatever the environment says.
pub(crate) fn route_agents(cfg: &mut kraken_viewmodel::agents::AgentsConfig, runtime_dir: &Path) {
    cfg.use_daemon = true;
    cfg.mcp_env
        .retain(|(k, _)| !DAEMON_ENV.contains(&k.as_str()));
    cfg.mcp_env.push((
        "KRAKEN_RUNTIME_DIR".into(),
        runtime_dir.to_string_lossy().into_owned(),
    ));
}

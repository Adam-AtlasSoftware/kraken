//! Starting, running and stopping the daemon.
//!
//! [`start`] takes the single-instance lock, binds the socket and spawns the server, the idle
//! monitor, the maintenance tick (job events, session sweep), the event forwarder and the
//! sidecar-event listener. [`Daemon::wait`] returns once shutdown was requested (by the `shutdown`
//! method, idle exit or [`Daemon::shutdown`]) and everything was torn down: sessions closed,
//! sidecars stopped, socket / token / info files removed.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kraken_host::daemon::METHOD_EVENT;
use kraken_host::infer::{InferManager, ghidra_reservations};
use kraken_host::{DaemonSettings, ManagedFactory};
use kraken_ipc::transport::Listener;
use kraken_ipc::{
    Clock, DaemonGuard, IdleMonitor, IpcError, PROTOCOL_VERSION, RuntimeDir, Server, Shutdown,
};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{Registry, SessionConfig};
use tokio::task::JoinHandle;

use crate::approvals::ApprovalBoard;
use crate::events::EventHub;
use crate::handler::{DaemonFacts, DaemonHandler};
use crate::host::{HostConfig, SessionHost};

/// Why the daemon could not start or stopped abnormally.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Another daemon holds the run lock.
    #[error("a krakend is already running for this user")]
    AlreadyRunning,
    /// Runtime directory, token or info file trouble.
    #[error("{0}")]
    Ipc(IpcError),
    /// Socket trouble.
    #[error("cannot listen: {0}")]
    Listen(std::io::Error),
}

impl From<IpcError> for DaemonError {
    fn from(e: IpcError) -> Self {
        match e {
            IpcError::AlreadyRunning => DaemonError::AlreadyRunning,
            other => DaemonError::Ipc(other),
        }
    }
}

/// Adapts a shared clock to the generic parameter of `IdleMonitor`.
pub struct SharedClock(pub Arc<dyn Clock>);

impl Clock for SharedClock {
    fn now(&self) -> Duration {
        self.0.now()
    }
}

/// Everything the daemon needs.
pub struct DaemonOptions {
    /// Where the socket, token and info files live.
    pub runtime_dir: RuntimeDir,
    /// Creates (and stops) engines.
    pub factory: Arc<dyn ManagedFactory>,
    /// The commands served.
    pub registry: Arc<Registry>,
    /// Idle timeouts and the session limit.
    pub settings: DaemonSettings,
    /// Configuration of every session.
    pub session_config: SessionConfig,
    /// Time source for idle decisions; tests inject a manual one.
    pub clock: Arc<dyn Clock>,
    /// How often the idle monitor and the maintenance tick run.
    pub poll: Duration,
    /// Build string announced in the handshake.
    pub build: String,
}

/// A running daemon.
pub struct Daemon {
    shutdown: Shutdown,
    host: SessionHost,
    clients: kraken_ipc::Counter,
    jobs: kraken_ipc::Counter,
    models: kraken_ipc::Counter,
    infer: Arc<InferManager>,
    approvals: ApprovalBoard,
    done: JoinHandle<()>,
}

impl Daemon {
    /// Asks the daemon to stop.
    pub fn shutdown(&self) {
        self.shutdown.trigger();
    }

    /// A handle that stops the daemon when triggered (for signal handlers).
    pub fn stop_handle(&self) -> Shutdown {
        self.shutdown.clone()
    }

    /// The session host (tests inspect it).
    pub fn host(&self) -> &SessionHost {
        &self.host
    }

    /// Connected clients right now.
    pub fn clients(&self) -> usize {
        self.clients.get()
    }

    /// Running jobs right now, as the idle monitor sees them.
    pub fn running_jobs(&self) -> usize {
        self.jobs.get()
    }

    /// Loaded local models right now, as the idle monitor sees them.
    pub fn loaded_models(&self) -> usize {
        self.models.get()
    }

    /// The approvals waiting for a person (tests answer them directly).
    pub fn approvals(&self) -> &ApprovalBoard {
        &self.approvals
    }

    /// The local model manager (tests inspect it).
    pub fn infer(&self) -> &Arc<InferManager> {
        &self.infer
    }

    /// Whether shutdown was requested.
    pub fn is_stopping(&self) -> bool {
        self.shutdown.is_triggered()
    }

    /// Waits until the daemon has fully stopped.
    pub async fn wait(self) {
        let _ = self.done.await;
    }
}

/// Starts the daemon with the standard local-model manager (`llama-server` plus the manifests
/// directory). Fails with [`DaemonError::AlreadyRunning`] if one is already running.
pub fn start(opts: DaemonOptions) -> Result<Daemon, DaemonError> {
    start_full(opts, None, Arc::new(InferManager::from_env()))
}

/// Like [`start`], with the rewrite pipeline attached to every session (`rewrite_*` commands).
pub fn start_with(
    opts: DaemonOptions,
    rewrite: Option<Arc<dyn RewriteBackend>>,
) -> Result<Daemon, DaemonError> {
    start_full(opts, rewrite, Arc::new(InferManager::from_env()))
}

/// [`start`] with a given local-model manager (tests use the fake inference server). The model
/// it runs counts as work for the idle monitor and is stopped when the daemon stops.
pub fn start_with_infer(
    opts: DaemonOptions,
    infer: Arc<InferManager>,
) -> Result<Daemon, DaemonError> {
    start_full(opts, None, infer)
}

/// Starts the daemon with an optional rewrite pipeline and the given local-model manager.
pub fn start_full(
    opts: DaemonOptions,
    rewrite: Option<Arc<dyn RewriteBackend>>,
    infer: Arc<InferManager>,
) -> Result<Daemon, DaemonError> {
    start_with_setup(opts, rewrite, infer, None)
}

/// [`start_full`] with a given setup backend behind `setup_status` and the `setup_*` jobs (tests
/// give one that downloads from a canned source); `None` is this machine's.
pub fn start_with_setup(
    opts: DaemonOptions,
    rewrite: Option<Arc<dyn RewriteBackend>>,
    infer: Arc<InferManager>,
    setup: Option<Arc<dyn kraken_registry::commands::SetupBackend>>,
) -> Result<Daemon, DaemonError> {
    let guard = DaemonGuard::acquire(&opts.runtime_dir, PROTOCOL_VERSION, &opts.build)?;
    let listener = Listener::bind(&opts.runtime_dir).map_err(DaemonError::Listen)?;

    let idle = opts.settings.idle();
    let monitor = Arc::new(IdleMonitor::new(SharedClock(opts.clock.clone()), idle));
    let shutdown = Shutdown::new();
    let hub = EventHub::new();
    let host = SessionHost::new(
        opts.factory.clone(),
        opts.registry.clone(),
        HostConfig {
            session_config: opts.session_config.clone(),
            session_idle: opts.settings.session_idle(),
            max_sessions: opts.settings.max_sessions(),
            rewrite,
            local_models: kraken_host::local_models::LocalModels::system()
                .ok()
                .map(|m| Arc::new(m) as Arc<dyn kraken_registry::commands::LocalModelBackend>),
            integrations: kraken_host::integrations::Integrations::system()
                .ok()
                .map(|i| Arc::new(i) as Arc<dyn kraken_registry::commands::IntegrationsBackend>),
            setup: Some(setup.unwrap_or_else(|| Arc::new(kraken_host::setup::HostSetup::system()))),
        },
        opts.clock.clone(),
        hub.clone(),
    );
    let facts = DaemonFacts {
        pid: guard.info().pid,
        build: opts.build.clone(),
        protocol: PROTOCOL_VERSION,
        runtime_dir: opts.runtime_dir.path().to_path_buf(),
        idle_timeout: idle,
        started: Instant::now(),
    };
    let factory = opts.factory.clone();
    infer.set_clock(opts.clock.clone());
    infer.set_reservations(move || ghidra_reservations(factory.as_ref()));
    let handler = DaemonHandler::new(
        host.clone(),
        opts.registry.clone(),
        facts,
        monitor.clients().clone(),
        monitor.jobs().clone(),
        shutdown.clone(),
    )
    .with_infer(infer.clone());
    let approvals = handler.approvals().clone();
    let server = Server::with_parts(
        handler,
        guard.server_config(),
        monitor.clients().clone(),
        shutdown.clone(),
    );

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    let serve = server.clone();
    tasks.push(tokio::spawn(async move {
        if let Err(e) = serve.serve(listener).await {
            tracing::error!(error = %e, "server stopped with an error");
        }
    }));

    let (m, s, poll) = (monitor.clone(), shutdown.clone(), opts.poll);
    tasks.push(tokio::spawn(async move { m.run(poll, &s).await }));

    // Job events, running-job count and loaded models for the idle monitor, idle session sweep,
    // local models whose grace period is over.
    let (h, m, s, poll) = (host.clone(), monitor.clone(), shutdown.clone(), opts.poll);
    let i = infer.clone();
    tasks.push(tokio::spawn(async move {
        loop {
            let running = h.maintain().await;
            i.tick().await;
            m.jobs().set(running);
            m.models().set(i.loaded_models());
            tokio::select! {
                () = tokio::time::sleep(poll) => {}
                () = s.wait() => return,
            }
        }
    }));

    // Event stream to every connected client.
    let (srv, mut rx, s) = (server.clone(), hub.subscribe(), shutdown.clone());
    tasks.push(tokio::spawn(async move {
        loop {
            tokio::select! {
                ev = rx.recv() => match ev {
                    Ok(ev) => {
                        srv.broadcast(METHOD_EVENT, &ev);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "event stream lagged; clients can catch up with `events`");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                },
                () = s.wait() => return,
            }
        }
    }));

    // Sidecar lifecycle: restart a dead sidecar, replay the log when it is back.
    if let Some(mut rx) = opts.factory.subscribe_events() {
        let (h, s) = (host.clone(), shutdown.clone());
        tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    ev = rx.recv() => match ev {
                        Ok(ev) => {
                            // A restart can take long; do not stall later events behind it.
                            let h = h.clone();
                            tokio::spawn(async move { h.on_engine_event(ev).await });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    },
                    () = s.wait() => return,
                }
            }
        }));
    }

    let (h, s, clients, jobs, models) = (
        host.clone(),
        shutdown.clone(),
        monitor.clients().clone(),
        monitor.jobs().clone(),
        monitor.models().clone(),
    );
    let i = infer.clone();
    let done = tokio::spawn(async move {
        s.wait().await;
        for t in tasks {
            let _ = t.await;
        }
        h.close_all().await;
        i.shutdown().await;
        // Dropping the guard removes the socket, token and info files.
        drop(guard);
        tracing::info!("krakend stopped");
    });

    Ok(Daemon {
        shutdown,
        host,
        clients,
        jobs,
        models,
        infer,
        approvals,
        done,
    })
}

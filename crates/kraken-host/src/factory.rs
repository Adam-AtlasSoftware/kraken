//! `GhidraEngineFactory`: an [`EngineFactory`] over `engine-ghidra`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use engine_ghidra::{EngineConfig, GhidraEngine, GhidraInstall, InstallConfig, SidecarEvent};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::EngineFactory;
use serde_json::Value;
use tokio::sync::broadcast;

use crate::config::KrakenConfig;
use crate::paths::check_ghidra_safe;

/// A lifecycle event of the process behind an engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// A sidecar finished its handshake.
    Started,
    /// The sidecar ended (`None` when killed by a signal).
    Exited {
        /// Exit code.
        code: Option<i32>,
    },
    /// A restart brought a new sidecar up; unsaved engine state is gone, replay the log.
    Restarted,
}

/// An [`EngineEvent`] and the engine directory it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactoryEvent {
    /// Directory the engine was created for (`<project>/ghidra`, ...).
    pub engine_dir: PathBuf,
    /// What happened.
    pub event: EngineEvent,
}

/// Diagnostics of one engine, as JSON (for `krakend` status).
#[derive(Debug, Clone, PartialEq)]
pub struct EngineDiagnostics {
    /// Directory the engine was created for.
    pub engine_dir: PathBuf,
    /// Engine specific diagnostics (state, pid, confinement report, log tail, ...).
    pub value: Value,
}

/// An [`EngineFactory`] that can also stop what it created and report on it. The daemon needs
/// the extra methods; all but `shutdown` have inert defaults.
#[async_trait]
pub trait ManagedFactory: EngineFactory {
    /// Shuts down every engine (and sidecar process) this factory created.
    async fn shutdown(&self);

    /// Shuts down the engines created for directories inside `project_dir` (a closed session).
    async fn shutdown_under(&self, _project_dir: &Path) {}

    /// A stream of engine lifecycle events, or `None` when the engines have no process to lose.
    fn subscribe_events(&self) -> Option<broadcast::Receiver<FactoryEvent>> {
        None
    }

    /// Diagnostics of every live engine.
    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        Vec::new()
    }

    /// Restarts the sidecar of the engine created for `engine_dir` (bounded attempts). An
    /// [`EngineEvent::Restarted`] follows on success.
    async fn restart_engine(&self, _engine_dir: &Path) -> Result<(), ProtoError> {
        Err(ProtoError::new(
            ErrorCode::Unsupported,
            "this engine cannot be restarted",
        ))
    }
}

/// Creates one [`GhidraEngine`] per call (the registry calls it once per session, and again on
/// `rebuild`). The Ghidra install is discovered when an engine is created, so commands that need
/// no engine work without one.
pub struct GhidraEngineFactory {
    cfg: KrakenConfig,
    created: Mutex<Vec<(PathBuf, Arc<GhidraEngine>)>>,
    events: broadcast::Sender<FactoryEvent>,
}

fn map_event(e: SidecarEvent) -> EngineEvent {
    match e {
        SidecarEvent::Started => EngineEvent::Started,
        SidecarEvent::Exited { code } => EngineEvent::Exited { code },
        SidecarEvent::Restarted => EngineEvent::Restarted,
    }
}

impl GhidraEngineFactory {
    /// A factory using `cfg` (locations of Ghidra, the JDK and the extension jar, heap, and
    /// confinement policy).
    pub fn new(cfg: KrakenConfig) -> Self {
        GhidraEngineFactory {
            cfg,
            created: Mutex::new(Vec::new()),
            events: broadcast::channel(256).0,
        }
    }

    /// Where to look for Ghidra, the JDK and the extension jar: explicit configuration and the
    /// environment first, then the copy `kraken setup` provisioned, then engine-ghidra's own
    /// defaults.
    pub fn install_config(&self) -> InstallConfig {
        let mut ic = InstallConfig {
            ghidra_home: self.cfg.ghidra_home.clone(),
            java_home: self.cfg.java_home.clone(),
            ext_jar: self.cfg.ext_jar.clone(),
        };
        if let Some(layout) = crate::provision::Layout::from_env() {
            let p = layout.provisioned();
            ic.ghidra_home = ic.ghidra_home.or(p.ghidra_home);
            ic.java_home = ic.java_home.or(p.java_home);
            ic.ext_jar = ic.ext_jar.or(p.ext_jar);
        }
        ic
    }

    /// The engine config for an engine directory.
    pub fn engine_config(&self, engine_dir: &Path) -> Result<EngineConfig, ProtoError> {
        check_ghidra_safe(engine_dir)?;
        let install = GhidraInstall::discover(&self.install_config()).map_err(|e| {
            let mut e = ProtoError::from(e);
            if self.cfg.ghidra_home.is_none() {
                e.message
                    .push_str("; run `kraken setup` to download Ghidra and a JDK");
            }
            e
        })?;
        let mut ec = EngineConfig::new(install, engine_dir);
        ec.max_heap_mb = self.cfg.max_heap_mb;
        ec.confinement.allow_unconfined = self.cfg.allow_unconfined;
        Ok(ec)
    }
}

#[async_trait]
impl EngineFactory for GhidraEngineFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let engine = Arc::new(GhidraEngine::new(self.engine_config(engine_dir)?));
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((engine_dir.to_path_buf(), engine.clone()));
        let mut rx = engine.subscribe();
        let tx = self.events.clone();
        let dir = engine_dir.to_path_buf();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        let _ = tx.send(FactoryEvent {
                            engine_dir: dir.clone(),
                            event: map_event(ev),
                        });
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        tracing::debug!(dir = %engine_dir.display(), "created Ghidra engine");
        Ok(engine)
    }
}

#[async_trait]
impl ManagedFactory for GhidraEngineFactory {
    async fn shutdown(&self) {
        let engines: Vec<_> =
            std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        for (_, e) in engines {
            e.shutdown().await;
        }
    }

    async fn shutdown_under(&self, project_dir: &Path) {
        let all = std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        let (gone, kept): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|(dir, _)| dir.starts_with(project_dir));
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(kept);
        for (_, e) in gone {
            e.shutdown().await;
        }
    }

    fn subscribe_events(&self) -> Option<broadcast::Receiver<FactoryEvent>> {
        Some(self.events.subscribe())
    }

    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(dir, e)| EngineDiagnostics {
                engine_dir: dir.clone(),
                value: serde_json::to_value(e.diagnostics()).unwrap_or(Value::Null),
            })
            .collect()
    }

    async fn restart_engine(&self, engine_dir: &Path) -> Result<(), ProtoError> {
        let engine = self
            .created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(dir, _)| dir == engine_dir)
            .map(|(_, e)| e.clone())
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::NotFound,
                    format!("no engine for {}", engine_dir.display()),
                )
            })?;
        // A sidecar that is up again (the engine replaced it for another binary, or a racing
        // restart already succeeded) must not be restarted a second time.
        if engine.diagnostics().state == "running" {
            return Ok(());
        }
        engine.restart().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_engine_dirs_are_refused_before_discovery() {
        let f = GhidraEngineFactory::new(KrakenConfig::default());
        let e = f
            .engine_config(Path::new("/home/u/.local/share/kraken/p/ghidra"))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert!(e.message.contains("kraken-projects"));
    }

    #[test]
    fn a_missing_install_is_reported() {
        let f = GhidraEngineFactory::new(KrakenConfig {
            ghidra_home: Some("/nonexistent/ghidra".into()),
            java_home: Some("/nonexistent/jdk".into()),
            ext_jar: Some("/nonexistent/k.jar".into()),
            ..Default::default()
        });
        let e = f
            .engine_config(Path::new("/tmp/kraken-x/ghidra"))
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
    }

    #[tokio::test]
    async fn shutdown_with_no_engines_is_a_no_op() {
        let f = GhidraEngineFactory::new(KrakenConfig::default());
        f.shutdown().await;
        f.shutdown_under(Path::new("/tmp/kraken-none")).await;
        assert!(f.diagnostics().is_empty());
        assert!(f.subscribe_events().is_some());
    }
}

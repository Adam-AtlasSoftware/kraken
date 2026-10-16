//! `GhidraEngineFactory`: an [`EngineFactory`] over `engine-ghidra`.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use engine_ghidra::{EngineConfig, GhidraEngine, GhidraInstall, InstallConfig};
use kraken_engine::SharedEngine;
use kraken_proto::ProtoError;
use kraken_registry::EngineFactory;

use crate::config::KrakenConfig;
use crate::paths::check_ghidra_safe;

/// An [`EngineFactory`] that can also stop what it created.
#[async_trait]
pub trait ManagedFactory: EngineFactory {
    /// Shuts down every engine (and sidecar process) this factory created.
    async fn shutdown(&self);
}

/// Creates one [`GhidraEngine`] per call (the registry calls it once per session, and again on
/// `rebuild`). The Ghidra install is discovered when an engine is created, so commands that need
/// no engine work without one.
pub struct GhidraEngineFactory {
    cfg: KrakenConfig,
    created: Mutex<Vec<Arc<GhidraEngine>>>,
}

impl GhidraEngineFactory {
    /// A factory using `cfg` (locations of Ghidra, the JDK and the extension jar, heap, and
    /// confinement policy).
    pub fn new(cfg: KrakenConfig) -> Self {
        GhidraEngineFactory {
            cfg,
            created: Mutex::new(Vec::new()),
        }
    }

    /// The engine config for an engine directory.
    pub fn engine_config(&self, engine_dir: &Path) -> Result<EngineConfig, ProtoError> {
        check_ghidra_safe(engine_dir)?;
        let install = GhidraInstall::discover(&InstallConfig {
            ghidra_home: self.cfg.ghidra_home.clone(),
            java_home: self.cfg.java_home.clone(),
            ext_jar: self.cfg.ext_jar.clone(),
        })
        .map_err(ProtoError::from)?;
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
            .push(engine.clone());
        tracing::debug!(dir = %engine_dir.display(), "created Ghidra engine");
        Ok(engine)
    }
}

#[async_trait]
impl ManagedFactory for GhidraEngineFactory {
    async fn shutdown(&self) {
        let engines: Vec<_> =
            std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        for e in engines {
            e.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::ErrorCode;

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
        GhidraEngineFactory::new(KrakenConfig::default())
            .shutdown()
            .await;
    }
}

//! Engine factories: [`GhidraEngineFactory`] over `engine-ghidra`, [`DotnetEngineFactory`] over
//! `engine-dotnet` and [`HostEngineFactory`], which picks one per binary.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use engine_dotnet::{
    DotnetEngine, DotnetInstall, EngineConfig as DotnetEngineConfig,
    InstallConfig as DotnetInstallConfig,
};
use engine_ghidra::{EngineConfig, GhidraEngine, GhidraInstall, InstallConfig, SidecarEvent};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{EngineFactory, EngineKind};
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

/// Creates one [`DotnetEngine`] per call. The .NET install is discovered when an engine is
/// created: explicit configuration, then the environment, then the copy `kraken setup --dotnet`
/// provisioned, then `engine-dotnet`'s development defaults.
pub struct DotnetEngineFactory {
    cfg: KrakenConfig,
    created: Mutex<Vec<(PathBuf, Arc<DotnetEngine>)>>,
}

impl DotnetEngineFactory {
    /// A factory using `cfg`.
    pub fn new(cfg: KrakenConfig) -> Self {
        DotnetEngineFactory {
            cfg,
            created: Mutex::new(Vec::new()),
        }
    }

    /// Where to look for the .NET host and the sidecar.
    pub fn install_config(&self) -> DotnetInstallConfig {
        let env = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let provisioned = crate::provision::Layout::from_env()
            .map(|l| l.dotnet_provisioned())
            .unwrap_or_default();
        DotnetInstallConfig {
            dotnet_root: self
                .cfg
                .dotnet_root
                .clone()
                .or_else(|| env(engine_dotnet::ENV_DOTNET_ROOT))
                .or(provisioned.dotnet_root),
            ext_dll: self
                .cfg
                .dotnet_ext
                .clone()
                .or_else(|| env(engine_dotnet::ENV_EXT_DLL))
                .or(provisioned.ext_dll),
        }
    }

    /// The engine config, or `unsupported` with the way to install what is missing.
    pub fn engine_config(&self) -> Result<DotnetEngineConfig, ProtoError> {
        let install = DotnetInstall::discover(&self.install_config()).map_err(|e| {
            let mut e = ProtoError::from(e);
            e.message
                .push_str("; run `kraken setup --dotnet` to install the .NET runtime and sidecar");
            e
        })?;
        let mut ec = DotnetEngineConfig::new(install);
        ec.max_heap_mb = self.cfg.max_heap_mb.unwrap_or(ec.max_heap_mb);
        ec.confinement.allow_unconfined = self.cfg.allow_unconfined;
        Ok(ec)
    }

    fn owns(&self, engine_dir: &Path) -> bool {
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(dir, _)| dir == engine_dir)
    }

    fn shutdown_where(&self, keep: impl Fn(&Path) -> bool) {
        let all = std::mem::take(&mut *self.created.lock().unwrap_or_else(PoisonError::into_inner));
        let (kept, gone): (Vec<_>, Vec<_>) = all.into_iter().partition(|(dir, _)| keep(dir));
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(kept);
        for (_, e) in gone {
            e.shutdown();
        }
    }

    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(dir, e)| {
                let d = e.diagnostics();
                EngineDiagnostics {
                    engine_dir: dir.clone(),
                    value: serde_json::json!({
                        "engine": "dotnet",
                        "state": d.state,
                        "pid": d.pid,
                        "build": d.build,
                        "confinement": d.confinement,
                        "log_tail": d.log_tail,
                    }),
                }
            })
            .collect()
    }
}

#[async_trait]
impl EngineFactory for DotnetEngineFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let engine = Arc::new(DotnetEngine::new(self.engine_config()?));
        self.created
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((engine_dir.to_path_buf(), engine.clone()));
        tracing::debug!(dir = %engine_dir.display(), "created .NET engine");
        Ok(engine)
    }
}

/// The factory every surface uses: Ghidra for native binaries, the .NET engine for managed
/// assemblies. [`detect_kind`](EngineFactory::detect_kind) looks at the file; a project
/// remembers its engine in `meta.json` and reopens with it.
pub struct HostEngineFactory {
    ghidra: GhidraEngineFactory,
    dotnet: DotnetEngineFactory,
}

impl HostEngineFactory {
    /// A factory using `cfg` for both engines.
    pub fn new(cfg: KrakenConfig) -> Self {
        HostEngineFactory {
            ghidra: GhidraEngineFactory::new(cfg.clone()),
            dotnet: DotnetEngineFactory::new(cfg),
        }
    }

    /// The Ghidra half.
    pub fn ghidra(&self) -> &GhidraEngineFactory {
        &self.ghidra
    }

    /// The .NET half.
    pub fn dotnet(&self) -> &DotnetEngineFactory {
        &self.dotnet
    }
}

#[async_trait]
impl EngineFactory for HostEngineFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        self.ghidra.create(engine_dir).await
    }

    fn detect_kind(&self, binary: &Path) -> Result<EngineKind, ProtoError> {
        if !crate::managed::is_managed_assembly(binary) {
            return Ok(EngineKind::Ghidra);
        }
        // Say so now rather than after the project directory is half made.
        self.dotnet.engine_config().map_err(|mut e| {
            e.message = format!(
                "{} is a .NET assembly, which needs the .NET engine: {}",
                binary.display(),
                e.message
            );
            e
        })?;
        Ok(EngineKind::Dotnet)
    }

    async fn create_kind(
        &self,
        kind: EngineKind,
        engine_dir: &Path,
    ) -> Result<SharedEngine, ProtoError> {
        match kind {
            EngineKind::Ghidra => self.ghidra.create(engine_dir).await,
            EngineKind::Dotnet => self.dotnet.create(engine_dir).await,
        }
    }
}

#[async_trait]
impl ManagedFactory for HostEngineFactory {
    async fn shutdown(&self) {
        self.dotnet.shutdown_where(|_| false);
        self.ghidra.shutdown().await;
    }

    async fn shutdown_under(&self, project_dir: &Path) {
        self.dotnet
            .shutdown_where(|dir| !dir.starts_with(project_dir));
        self.ghidra.shutdown_under(project_dir).await;
    }

    fn subscribe_events(&self) -> Option<broadcast::Receiver<FactoryEvent>> {
        self.ghidra.subscribe_events()
    }

    fn diagnostics(&self) -> Vec<EngineDiagnostics> {
        let mut all = self.ghidra.diagnostics();
        all.extend(self.dotnet.diagnostics());
        all
    }

    async fn restart_engine(&self, engine_dir: &Path) -> Result<(), ProtoError> {
        if self.dotnet.owns(engine_dir) {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                "the .NET engine cannot be restarted; reopen the project",
            ));
        }
        self.ghidra.restart_engine(engine_dir).await
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

    fn corpus_dll() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/dotnet/bin/kraken-corpus.dll")
    }

    fn without_dotnet() -> KrakenConfig {
        KrakenConfig {
            dotnet_root: Some("/nonexistent/kraken-dotnet".into()),
            dotnet_ext: Some("/nonexistent/kraken-dotnet.dll".into()),
            ..Default::default()
        }
    }

    #[test]
    fn native_files_go_to_ghidra_and_assemblies_to_dotnet() {
        let dir = tempfile::tempdir().unwrap();
        let elf = dir.path().join("prog");
        std::fs::write(&elf, b"\x7fELF\x02\x01\x01").unwrap();
        let f = HostEngineFactory::new(without_dotnet());
        assert_eq!(f.detect_kind(&elf).unwrap(), EngineKind::Ghidra);
        assert_eq!(
            f.detect_kind(Path::new("/nonexistent/x.bin")).unwrap(),
            EngineKind::Ghidra,
            "the engine reports unreadable files itself"
        );

        // A real install: the pieces only have to exist for the factory to pick the engine.
        let root = dir.path().join("dotnet");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(if cfg!(windows) {
                "dotnet.exe"
            } else {
                "dotnet"
            }),
            b"",
        )
        .unwrap();
        let ext = dir.path().join("kraken-dotnet.dll");
        std::fs::write(&ext, b"").unwrap();
        let f = HostEngineFactory::new(KrakenConfig {
            dotnet_root: Some(root),
            dotnet_ext: Some(ext),
            ..Default::default()
        });
        assert_eq!(f.detect_kind(&corpus_dll()).unwrap(), EngineKind::Dotnet);
        assert_eq!(f.detect_kind(&elf).unwrap(), EngineKind::Ghidra);
    }

    #[test]
    fn an_assembly_without_the_dotnet_engine_says_how_to_get_it() {
        let f = HostEngineFactory::new(without_dotnet());
        let e = f.detect_kind(&corpus_dll()).unwrap_err();
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("is a .NET assembly"), "{}", e.message);
        assert!(e.message.contains("kraken setup --dotnet"), "{}", e.message);
    }

    #[tokio::test]
    async fn creating_a_dotnet_engine_without_an_install_fails_clearly() {
        let f = HostEngineFactory::new(without_dotnet());
        let e = f
            .create_kind(EngineKind::Dotnet, Path::new("/tmp/kraken-x/ghidra"))
            .await
            .err()
            .expect("an error");
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("kraken setup --dotnet"), "{}", e.message);
        assert!(f.diagnostics().is_empty());
        f.shutdown().await;
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

//! Starting a sidecar: the [`Launcher`] seam and the real confined JVM launcher.

use std::path::PathBuf;

use async_trait::async_trait;
use kraken_proto::ProtoError;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::log::LogSink;
use crate::sandbox::{ConfinementReport, ExitInfo};

/// What to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    /// Canonical path of the binary to analyse (readable by the sidecar).
    pub binary: PathBuf,
    /// Its size, used to size the heap.
    pub binary_size: u64,
    /// Ghidra project directory (read-write for the sidecar).
    pub project_dir: PathBuf,
    /// JVM heap in MiB.
    pub heap_mb: u64,
}

/// A started sidecar's lifetime handle.
pub trait Session: Send + Sync {
    /// Kills the sidecar immediately. Dropping the session also kills it.
    fn kill(&self);
}

/// A started sidecar.
pub struct Launched {
    /// Protocol channel, read side.
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    /// Protocol channel, write side.
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    /// Turns `Some` when the process has exited.
    pub exit: watch::Receiver<Option<ExitInfo>>,
    /// Captured stdout/stderr.
    pub log: LogSink,
    /// Applied confinement.
    pub report: ConfinementReport,
    /// Process id, if there is a process.
    pub pid: Option<u32>,
    /// Keeps the process alive; dropping it kills the sidecar and removes its temporary home.
    pub session: Box<dyn Session>,
}

/// Starts sidecars. The real implementation is [`GhidraLauncher`]; tests substitute an
/// in-process fake peer.
#[async_trait]
pub trait Launcher: Send + Sync {
    /// Starts a sidecar for `plan`.
    async fn launch(&self, plan: &LaunchPlan) -> Result<Launched, ProtoError>;
}

pub use real::GhidraLauncher;

#[cfg(any(unix, windows))]
mod real {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use async_trait::async_trait;
    use kraken_proto::{ErrorCode, ProtoError};
    use tempfile::TempDir;

    use super::{LaunchPlan, Launched, Launcher, Session};
    use crate::error::GhidraError;
    use crate::install::GhidraInstall;
    use crate::log::LogSink;
    #[cfg(unix)]
    use crate::sandbox::Sandbox;
    #[cfg(windows)]
    use crate::sandbox::WinSandbox as Sandbox;
    use crate::sandbox::{ConfinementOptions, SpawnSpec};

    /// Launches the Ghidra JVM sidecar under confinement.
    #[derive(Debug, Clone)]
    pub struct GhidraLauncher {
        install: GhidraInstall,
        confinement: ConfinementOptions,
        temp_root: Option<PathBuf>,
    }

    impl GhidraLauncher {
        /// A launcher for `install`.
        pub fn new(
            install: GhidraInstall,
            confinement: ConfinementOptions,
            temp_root: Option<PathBuf>,
        ) -> Self {
            GhidraLauncher {
                install,
                confinement,
                temp_root,
            }
        }

        /// The command line, environment and path sets for `plan`, with `home` as the session's
        /// private home directory.
        pub(crate) fn spawn_spec(
            &self,
            plan: &LaunchPlan,
            home: &Path,
        ) -> Result<SpawnSpec, GhidraError> {
            let i = &self.install;
            let tmp = home.join("tmp");
            #[cfg_attr(target_os = "linux", allow(unused_mut))]
            let mut args: Vec<OsString> = vec![
                format!("-Xmx{}m", plan.heap_mb).into(),
                "-XX:+UseSerialGC".into(),
                "-Djava.awt.headless=true".into(),
                "-Dfile.encoding=UTF-8".into(),
                format!("-Duser.home={}", home.display()).into(),
                format!("-Djava.io.tmpdir={}", tmp.display()).into(),
                format!("-Dghidra.install.dir={}", i.ghidra_home.display()).into(),
                "-cp".into(),
                i.classpath()?.into(),
                "kraken.ghidra.KrakenSidecar".into(),
            ];
            // Linux dies with its parent through PDEATHSIG; elsewhere the JVM watches the pid.
            #[cfg(not(target_os = "linux"))]
            {
                args.push("--watch-parent".into());
                args.push(std::process::id().to_string().into());
            }
            // Windows has no socketpair to hand down as fd 0, so frames use the stdin and stdout
            // pipes instead.
            #[cfg(windows)]
            args.push("--stdio".into());
            let env = sidecar_env(i, home, &tmp);
            Ok(SpawnSpec {
                program: i.java(),
                args,
                env,
                cwd: home.to_path_buf(),
                read_only: vec![
                    i.java_home.clone(),
                    i.ghidra_home.clone(),
                    i.ext_jar.clone(),
                    plan.binary.clone(),
                ],
                read_write: vec![home.to_path_buf(), plan.project_dir.clone()],
                options: self.confinement.clone(),
            })
        }
    }

    #[cfg(unix)]
    fn sidecar_env(i: &GhidraInstall, home: &Path, tmp: &Path) -> Vec<(OsString, OsString)> {
        vec![
            ("PATH".into(), i.java_home.join("bin").into_os_string()),
            ("HOME".into(), home.into()),
            ("TMPDIR".into(), tmp.into()),
            ("JAVA_HOME".into(), i.java_home.clone().into_os_string()),
            ("LANG".into(), "C.UTF-8".into()),
        ]
    }

    /// The JVM and Ghidra's natives need `SystemRoot` and the system directory on `PATH`.
    #[cfg(windows)]
    fn sidecar_env(i: &GhidraInstall, home: &Path, tmp: &Path) -> Vec<(OsString, OsString)> {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let mut path = i.java_home.join("bin").into_os_string();
        path.push(";");
        path.push(Path::new(&system_root).join("System32"));
        vec![
            ("PATH".into(), path),
            ("SystemRoot".into(), system_root),
            ("USERPROFILE".into(), home.into()),
            ("TEMP".into(), tmp.into()),
            ("TMP".into(), tmp.into()),
            ("JAVA_HOME".into(), i.java_home.clone().into_os_string()),
        ]
    }

    struct SidecarSession {
        sandbox: Sandbox,
        // Declared after the sandbox so the process is killed before its home is removed.
        _home: TempDir,
    }

    impl Session for SidecarSession {
        fn kill(&self) {
            self.sandbox.kill();
        }
    }

    /// Creates the per-session private home and the project directory.
    fn prepare_dirs(launcher: &GhidraLauncher, plan: &LaunchPlan) -> Result<TempDir, GhidraError> {
        std::fs::create_dir_all(&plan.project_dir)
            .map_err(|e| GhidraError::io(format!("creating {}", plan.project_dir.display()), e))?;
        let root = launcher
            .temp_root
            .clone()
            .unwrap_or_else(std::env::temp_dir);
        let home = tempfile::Builder::new()
            .prefix("kraken-sidecar-")
            .tempdir_in(&root)
            .map_err(|e| {
                GhidraError::io(format!("creating a temp home in {}", root.display()), e)
            })?;
        std::fs::create_dir_all(home.path().join("tmp"))
            .map_err(|e| GhidraError::io("creating the session tmp dir", e))?;
        Ok(home)
    }

    #[cfg(unix)]
    #[async_trait]
    impl Launcher for GhidraLauncher {
        async fn launch(&self, plan: &LaunchPlan) -> Result<Launched, ProtoError> {
            let this = self.clone();
            let plan = plan.clone();
            let (sandbox, home, log, channel) = tokio::task::spawn_blocking(move || {
                let home = prepare_dirs(&this, &plan)?;
                let spec = this.spawn_spec(&plan, home.path())?;
                let log = LogSink::default();
                let (sandbox, channel) = Sandbox::spawn(spec, &log)?;
                Ok::<_, GhidraError>((sandbox, home, log, channel))
            })
            .await
            .map_err(|e| {
                ProtoError::new(ErrorCode::Internal, format!("launch task failed: {e}"))
            })??;

            channel
                .set_nonblocking(true)
                .map_err(|e| GhidraError::io("configuring the sidecar channel", e))?;
            let stream = tokio::net::UnixStream::from_std(channel)
                .map_err(|e| GhidraError::io("registering the sidecar channel", e))?;
            let (reader, writer) = stream.into_split();
            Ok(Launched {
                reader: Box::new(reader),
                writer: Box::new(writer),
                exit: sandbox.exit_watch(),
                log,
                report: sandbox.report().clone(),
                pid: Some(sandbox.pid()),
                session: Box::new(SidecarSession {
                    sandbox,
                    _home: home,
                }),
            })
        }
    }

    #[cfg(windows)]
    #[async_trait]
    impl Launcher for GhidraLauncher {
        async fn launch(&self, plan: &LaunchPlan) -> Result<Launched, ProtoError> {
            let this = self.clone();
            let plan = plan.clone();
            let (home, spec) = tokio::task::spawn_blocking(move || {
                let home = prepare_dirs(&this, &plan)?;
                let spec = this.spawn_spec(&plan, home.path())?;
                Ok::<_, GhidraError>((home, spec))
            })
            .await
            .map_err(|e| {
                ProtoError::new(ErrorCode::Internal, format!("launch task failed: {e}"))
            })??;
            let log = LogSink::default();
            let (sandbox, stdout, stdin) = Sandbox::spawn(spec, &log)?;
            Ok(Launched {
                reader: Box::new(stdout),
                writer: Box::new(stdin),
                exit: sandbox.exit_watch(),
                log,
                report: sandbox.report().clone(),
                pid: Some(sandbox.pid()),
                session: Box::new(SidecarSession {
                    sandbox,
                    _home: home,
                }),
            })
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod real {
    use async_trait::async_trait;
    use kraken_proto::{ErrorCode, ProtoError};

    use super::{LaunchPlan, Launched, Launcher};
    use crate::install::GhidraInstall;
    use crate::sandbox::ConfinementOptions;

    /// Launches the Ghidra JVM sidecar (unsupported on this platform).
    #[derive(Debug, Clone)]
    pub struct GhidraLauncher;

    impl GhidraLauncher {
        /// A launcher for `install`.
        pub fn new(
            _install: GhidraInstall,
            _confinement: ConfinementOptions,
            _temp_root: Option<std::path::PathBuf>,
        ) -> Self {
            GhidraLauncher
        }
    }

    #[async_trait]
    impl Launcher for GhidraLauncher {
        async fn launch(&self, _plan: &LaunchPlan) -> Result<Launched, ProtoError> {
            Err(ProtoError::new(
                ErrorCode::Unsupported,
                "the Ghidra sidecar needs a Unix socketpair and is not supported on this platform yet",
            ))
        }
    }
}

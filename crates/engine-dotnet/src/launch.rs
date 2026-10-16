//! Starting the confined sidecar. Reuses `engine-ghidra`'s sandbox (Landlock, netns, parent-death
//! handling, job objects) and its log sink; only the command line and the path sets differ.
//! A shared sandbox crate would remove this dependency later (see spikes/dotnet-engine/NOTES.md).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use engine_ghidra::LogSink;
use engine_ghidra::sandbox::{ConfinementOptions, ConfinementReport, ExitInfo, SpawnSpec};
use kraken_proto::{ErrorCode, ProtoError};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;

use crate::error::DotnetError;
use crate::install::DotnetInstall;

#[cfg(unix)]
use engine_ghidra::sandbox::Sandbox;
#[cfg(windows)]
use engine_ghidra::sandbox::WinSandbox as Sandbox;

/// A started sidecar.
pub(crate) struct Launched {
    pub reader: Box<dyn AsyncRead + Send + Unpin>,
    pub writer: Box<dyn AsyncWrite + Send + Unpin>,
    pub exit: watch::Receiver<Option<ExitInfo>>,
    pub log: LogSink,
    pub report: ConfinementReport,
    pub pid: u32,
    pub guard: Guard,
}

/// Keeps the process alive; dropping it kills the sidecar, then removes its private home.
pub(crate) struct Guard {
    sandbox: Sandbox,
    _home: TempDir,
}

impl Guard {
    pub fn kill(&self) {
        self.sandbox.kill();
    }
}

/// Everything the launcher needs to know.
#[derive(Debug, Clone)]
pub(crate) struct LaunchPlan {
    pub install: DotnetInstall,
    pub assembly: PathBuf,
    pub heap_mb: u64,
    pub confinement: ConfinementOptions,
    pub temp_root: Option<PathBuf>,
}

fn spawn_spec(plan: &LaunchPlan, home: &Path) -> SpawnSpec {
    let tmp = home.join("tmp");
    let i = &plan.install;
    #[cfg_attr(target_os = "linux", allow(unused_mut))]
    let mut args: Vec<OsString> = vec![i.ext_dll.clone().into_os_string()];
    // Linux dies with its parent through PDEATHSIG; elsewhere the sidecar watches the pid.
    #[cfg(not(target_os = "linux"))]
    {
        args.push("--watch-parent".into());
        args.push(std::process::id().to_string().into());
    }
    // Windows has no socketpair to hand down as fd 0, so frames use the stdin and stdout pipes.
    #[cfg(windows)]
    args.push("--stdio".into());

    let mut env: Vec<(OsString, OsString)> = vec![
        ("DOTNET_ROOT".into(), i.dotnet_root.clone().into_os_string()),
        ("DOTNET_CLI_TELEMETRY_OPTOUT".into(), "1".into()),
        ("DOTNET_NOLOGO".into(), "1".into()),
        // No diagnostics IPC endpoint in /tmp, no server GC, a hard heap cap, no ICU.
        ("DOTNET_EnableDiagnostics".into(), "0".into()),
        ("DOTNET_gcServer".into(), "0".into()),
        (
            "DOTNET_GCHeapHardLimit".into(),
            format!("{:x}", plan.heap_mb * 1024 * 1024).into(),
        ),
        ("DOTNET_TieredPGO".into(), "0".into()),
        ("DOTNET_SYSTEM_GLOBALIZATION_INVARIANT".into(), "1".into()),
    ];
    #[cfg(unix)]
    env.extend([
        ("PATH".into(), i.dotnet_root.clone().into_os_string()),
        ("HOME".into(), home.into()),
        ("DOTNET_CLI_HOME".into(), home.into()),
        ("TMPDIR".into(), tmp.clone().into_os_string()),
        ("LANG".into(), "C.UTF-8".into()),
    ]);
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        env.extend([
            ("SystemRoot".into(), system_root),
            ("USERPROFILE".into(), home.into()),
            ("DOTNET_CLI_HOME".into(), home.into()),
            ("TEMP".into(), tmp.clone().into_os_string()),
            ("TMP".into(), tmp.clone().into_os_string()),
        ]);
    }

    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut options = plan.confinement.clone();
    // The runtime reads cgroup limits and CPU topology from /proc and /sys.
    #[cfg(target_os = "linux")]
    options
        .extra_read_only
        .extend(["/proc", "/sys"].map(PathBuf::from));

    let ext_dir = i
        .ext_dll
        .parent()
        .map_or_else(|| i.ext_dll.clone(), Path::to_path_buf);
    SpawnSpec {
        program: i.host.clone(),
        args,
        env,
        cwd: home.to_path_buf(),
        // Only the assembly file itself is readable: references next to it are not resolved
        // (spike limitation); framework assemblies come from the runtime directory.
        read_only: vec![i.dotnet_root.clone(), ext_dir, plan.assembly.clone()],
        read_write: vec![home.to_path_buf()],
        options,
    }
}

fn prepare_home(plan: &LaunchPlan) -> Result<TempDir, DotnetError> {
    let root = plan.temp_root.clone().unwrap_or_else(std::env::temp_dir);
    let home = tempfile::Builder::new()
        .prefix("kraken-dotnet-")
        .tempdir_in(&root)
        .map_err(|e| DotnetError::io(format!("creating a temp home in {}", root.display()), e))?;
    std::fs::create_dir_all(home.path().join("tmp"))
        .map_err(|e| DotnetError::io("creating the session tmp dir", e))?;
    Ok(home)
}

fn join_error(e: tokio::task::JoinError) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, format!("launch task failed: {e}"))
}

#[cfg(unix)]
pub(crate) async fn launch(plan: LaunchPlan) -> Result<Launched, ProtoError> {
    let (sandbox, home, log, channel) = tokio::task::spawn_blocking(move || {
        let home = prepare_home(&plan)?;
        let spec = spawn_spec(&plan, home.path());
        let log = LogSink::default();
        let (sandbox, channel) = Sandbox::spawn(spec, &log).map_err(ProtoError::from)?;
        Ok::<_, ProtoError>((sandbox, home, log, channel))
    })
    .await
    .map_err(join_error)??;
    channel
        .set_nonblocking(true)
        .map_err(|e| DotnetError::io("configuring the sidecar channel", e))?;
    let stream = tokio::net::UnixStream::from_std(channel)
        .map_err(|e| DotnetError::io("registering the sidecar channel", e))?;
    let (reader, writer) = stream.into_split();
    Ok(Launched {
        reader: Box::new(reader),
        writer: Box::new(writer),
        exit: sandbox.exit_watch(),
        log,
        report: sandbox.report().clone(),
        pid: sandbox.pid(),
        guard: Guard {
            sandbox,
            _home: home,
        },
    })
}

#[cfg(windows)]
pub(crate) async fn launch(plan: LaunchPlan) -> Result<Launched, ProtoError> {
    let (home, spec) = tokio::task::spawn_blocking(move || {
        let home = prepare_home(&plan)?;
        let spec = spawn_spec(&plan, home.path());
        Ok::<_, ProtoError>((home, spec))
    })
    .await
    .map_err(join_error)??;
    let log = LogSink::default();
    let (sandbox, stdout, stdin) = Sandbox::spawn(spec, &log).map_err(ProtoError::from)?;
    Ok(Launched {
        reader: Box::new(stdout),
        writer: Box::new(stdin),
        exit: sandbox.exit_watch(),
        log,
        report: sandbox.report().clone(),
        pid: sandbox.pid(),
        guard: Guard {
            sandbox,
            _home: home,
        },
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn launch(_plan: LaunchPlan) -> Result<Launched, ProtoError> {
    Err(ProtoError::new(
        ErrorCode::Unsupported,
        "the .NET sidecar is not supported on this platform yet",
    ))
}

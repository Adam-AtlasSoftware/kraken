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

    let options = plan.confinement.clone();
    // The runtime reads cgroup limits, memory and CPU topology from /proc and /sys. Grant only
    // that: the process's own /proc/<pid>, a few global files and the CPU/cgroup views, never
    // other processes' /proc/<pid>/cmdline.
    #[cfg(target_os = "linux")]
    let optional_read_only = proc_sys_paths();
    #[cfg(not(target_os = "linux"))]
    let optional_read_only = Vec::new();

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
        optional_read_only,
        proc_self_read: cfg!(target_os = "linux"),
        read_write: vec![home.to_path_buf()],
        options,
    }
}

/// The `/proc` and `/sys` paths the .NET runtime needs (decision: M8). Missing ones are skipped.
#[cfg(target_os = "linux")]
fn proc_sys_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = [
        "/proc/meminfo",
        "/proc/cpuinfo",
        "/proc/stat",
        "/proc/sys/vm/max_map_count",
        "/proc/sys/vm/overcommit_memory",
        "/sys/devices/system/cpu",
        "/sys/devices/system/node",
        "/sys/kernel/mm/transparent_hugepage",
    ]
    .map(PathBuf::from)
    .into();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    paths.extend(cgroup_paths(&cgroup, Path::new("/sys/fs/cgroup")));
    paths
}

/// The cgroup v2 limit files for the process's own cgroup (`0::/a/b`): the whole directory of
/// the cgroup itself and the limit files of each ancestor (the runtime walks upwards).
#[cfg(target_os = "linux")]
fn cgroup_paths(proc_cgroup: &str, mount: &Path) -> Vec<PathBuf> {
    const LIMIT_FILES: &[&str] = &[
        "memory.max",
        "memory.high",
        "memory.swap.max",
        "cpu.max",
        "cgroup.controllers",
    ];
    let Some(rel) = proc_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().trim_start_matches('/'))
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut dir = mount.to_path_buf();
    let mut dirs = vec![dir.clone()];
    for part in rel.split('/').filter(|p| !p.is_empty() && *p != "..") {
        dir.push(part);
        dirs.push(dir.clone());
    }
    let own = dirs.len() > 1;
    for (i, d) in dirs.iter().enumerate() {
        if own && i == dirs.len() - 1 {
            out.push(d.clone());
        } else {
            out.extend(LIMIT_FILES.iter().map(|f| d.join(f)));
        }
    }
    out
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn proc_and_sys_grants_are_narrow() {
        for p in proc_sys_paths() {
            let p = p.to_string_lossy().into_owned();
            assert!(p != "/proc" && p != "/sys" && p != "/sys/fs/cgroup", "{p}");
            assert!(
                !p.starts_with("/proc/self") && !p.contains("cmdline"),
                "{p}"
            );
        }
    }

    #[test]
    fn cgroup_grants_follow_the_own_cgroup() {
        let m = Path::new("/sys/fs/cgroup");
        let v = cgroup_paths("0::/user.slice/app.slice/x.scope\n", m);
        assert!(v.contains(&m.join("user.slice/app.slice/x.scope")));
        assert!(v.contains(&m.join("user.slice/memory.max")));
        assert!(v.contains(&m.join("memory.max")));
        assert!(
            !v.contains(&m.join("user.slice")),
            "ancestors get files only"
        );
        // In the root cgroup only the root's limit files are granted, never the whole tree.
        assert!(!cgroup_paths("0::/\n", m).contains(&m.to_path_buf()));
        assert!(cgroup_paths("garbage", m).is_empty());
    }
}

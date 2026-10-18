//! Confined child processes (decisions 71, 87, 89).
//!
//! Linux confinement stacks: a scrubbed environment, `PR_SET_PDEATHSIG` (from a spawner thread
//! that lives as long as the child), Landlock filesystem rules, Landlock ABI v4 TCP denial, ABI v6
//! scoping, ABI v9 `ResolveUnix` (no `connect()` to pathname unix sockets), a seccomp filter that
//! refuses `socket(2)` and every `socketpair(2)` but `AF_UNIX` (the child keeps only the inherited
//! protocol socketpair, and no inet, netlink or packet socket can be created, which also covers
//! UDP and ICMP that Landlock does not), and `unshare(CLONE_NEWUSER | CLONE_NEWNET)` when the host
//! allows it. Spawning fails unless Landlock ABI >= [`MIN_LANDLOCK_ABI`] and seccomp are
//! available, or `allow_unconfined` is set.
//!
//! macOS and Windows have no sidecar confinement yet (macOS `sandbox-exec` and a Windows
//! AppContainer are decision 71's later work), so they refuse to spawn unless
//! [`ConfinementOptions::allow_unconfined`] is set. Parent death is still handled there: the JVM
//! watches the parent pid on macOS (decision 68) and a kill-on-close job object ends it on Windows
//! (decision 40).

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

/// Confinement policy knobs.
#[derive(Debug, Clone, Default)]
pub struct ConfinementOptions {
    /// Run the sidecar even when Landlock is not enforced (or unsupported on this platform).
    /// Default `false`: starting then fails with a clear error.
    pub allow_unconfined: bool,
    /// Extra read-only paths on top of the built-in set.
    pub extra_read_only: Vec<PathBuf>,
    /// Extra read-write paths on top of the project dir and the session home.
    pub extra_read_write: Vec<PathBuf>,
    /// Do not try `unshare(CLONE_NEWUSER | CLONE_NEWNET)` even when it works.
    pub skip_network_namespace: bool,
}

/// The lowest Landlock ABI accepted without `allow_unconfined`: v3 adds truncate control and v4
/// TCP bind/connect denial.
pub const MIN_LANDLOCK_ABI: u32 = 4;

/// The refusal shown on platforms without sidecar confinement.
#[cfg(not(target_os = "linux"))]
pub(crate) fn unconfined_refusal() -> String {
    "sidecar confinement is only implemented on Linux (Landlock, decision 71); macOS sandbox-exec \
     and the Windows AppContainer are later work. Set ConfinementOptions::allow_unconfined \
     (`allow_unconfined = true` in the engine config) to run the sidecar unconfined at your own \
     risk"
        .into()
}

/// What confinement was actually applied to a spawned child.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfinementReport {
    /// Landlock filesystem rules are in force.
    pub filesystem: bool,
    /// Landlock ABI version the kernel reports (0 = unavailable).
    pub landlock_abi: u32,
    /// TCP bind/connect are denied by Landlock (ABI >= 4).
    pub tcp_denied: bool,
    /// Abstract unix sockets and signals are scoped (ABI >= 6).
    pub scoped: bool,
    /// `connect()` to pathname unix sockets is denied by Landlock (`ResolveUnix`, ABI >= 9).
    pub unix_connect_denied: bool,
    /// A seccomp filter stops the child from creating any new socket (the inherited protocol
    /// socketpair is the only one it has).
    pub sockets_denied: bool,
    /// The child runs in an empty user + network namespace.
    pub network_namespace: bool,
    /// The child dies with its parent: `PR_SET_PDEATHSIG(SIGKILL)` on Linux, the JVM's parent-pid
    /// watch on macOS, a kill-on-close job object on Windows.
    pub parent_death_signal: bool,
}

impl ConfinementReport {
    /// Nothing applied.
    pub fn none() -> Self {
        ConfinementReport {
            filesystem: false,
            landlock_abi: 0,
            tcp_denied: false,
            scoped: false,
            unix_connect_denied: false,
            sockets_denied: false,
            network_namespace: false,
            parent_death_signal: false,
        }
    }

    /// Whether filesystem confinement is active.
    pub fn is_confined(&self) -> bool {
        self.filesystem
    }

    /// Whether every inet family is blocked: either no socket can be created at all (seccomp), or
    /// the child sits in an empty network namespace on top of Landlock's TCP denial. TCP denial
    /// alone is not enough (UDP and ICMP stay open).
    pub fn network_blocked(&self) -> bool {
        self.sockets_denied || (self.network_namespace && self.tcp_denied)
    }
}

impl fmt::Display for ConfinementReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.filesystem {
            write!(f, "UNCONFINED")?;
        } else {
            write!(f, "landlock abi {} (filesystem", self.landlock_abi)?;
            if self.tcp_denied {
                write!(f, ", tcp denied")?;
            }
            if self.scoped {
                write!(f, ", scoped")?;
            }
            if self.unix_connect_denied {
                write!(f, ", unix connect denied")?;
            }
            if self.sockets_denied {
                write!(f, ", seccomp no sockets")?;
            }
            write!(f, ")")?;
        }
        write!(
            f,
            "; netns={}; pdeathsig={}",
            self.network_namespace, self.parent_death_signal
        )
    }
}

/// How a child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExitInfo {
    /// Exit code; `None` when killed by a signal.
    pub code: Option<i32>,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
}

/// What to run and how to confine it.
#[derive(Debug, Clone)]
pub struct SpawnSpec {
    /// Executable.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<OsString>,
    /// The complete environment (everything else is cleared).
    pub env: Vec<(OsString, OsString)>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Paths readable by the child (must exist). Enforced on Linux only.
    pub read_only: Vec<PathBuf>,
    /// Paths readable by the child when they exist (skipped silently otherwise).
    pub optional_read_only: Vec<PathBuf>,
    /// Grant read access to the child's own `/proc/<pid>` (resolved in the child after fork, so
    /// it is the child's directory and not the parent's).
    pub proc_self_read: bool,
    /// Paths readable and writable by the child (must exist).
    pub read_write: Vec<PathBuf>,
    /// Confinement policy.
    pub options: ConfinementOptions,
}

#[cfg(unix)]
pub use unix::Sandbox;
#[cfg(windows)]
pub use windows::WinSandbox;

#[cfg(unix)]
mod unix {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex, PoisonError, mpsc};
    use std::thread;

    use tokio::sync::watch;

    use super::{ConfinementReport, ExitInfo, SpawnSpec};
    use crate::error::SidecarError;
    use crate::log::LogSink;

    /// A running confined child. Dropping it kills the child.
    #[derive(Debug)]
    pub struct Sandbox {
        pid: u32,
        child: Arc<Mutex<Child>>,
        exit: watch::Receiver<Option<ExitInfo>>,
        report: ConfinementReport,
    }

    impl Sandbox {
        /// Spawns `spec`. The child's stdin (fd 0) is one end of a Unix socketpair that carries
        /// the protocol in both directions (decision 87); the other end is returned. stdout and
        /// stderr go to `log`.
        ///
        /// The child is forked from a dedicated thread that stays alive, waiting on the child,
        /// until it exits: `PR_SET_PDEATHSIG` fires when the *thread* that forked dies.
        pub fn spawn(
            spec: SpawnSpec,
            log: &LogSink,
        ) -> Result<(Sandbox, UnixStream), SidecarError> {
            let plan = confine::prepare(&spec)?;
            let report = plan.report.clone();
            let (parent_end, child_end) = UnixStream::pair()
                .map_err(|e| SidecarError::io("creating the sidecar socketpair", e))?;
            let (started_tx, started_rx) =
                mpsc::channel::<Result<(u32, Arc<Mutex<Child>>), SidecarError>>();
            let (exit_tx, exit_rx) = watch::channel(None);
            let parent_pid = std::process::id();
            let log = log.clone();
            thread::Builder::new()
                .name("kraken-spawner".into())
                .spawn(move || {
                    let child = match start_child(&spec, plan, child_end, parent_pid, current_tid())
                    {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = started_tx.send(Err(e));
                            return;
                        }
                    };
                    let mut child = child;
                    let pid = child.id();
                    for (name, stream) in [
                        ("stdout", child.stdout.take().map(Pump::Out)),
                        ("stderr", child.stderr.take().map(Pump::Err)),
                    ] {
                        if let Some(stream) = stream {
                            let sink = log.clone();
                            let _ = thread::Builder::new()
                                .name(format!("kraken-sidecar-{name}"))
                                .spawn(move || match stream {
                                    Pump::Out(s) => sink.pump(s),
                                    Pump::Err(s) => sink.pump(s),
                                });
                        }
                    }
                    let child = Arc::new(Mutex::new(child));
                    if started_tx.send(Ok((pid, child.clone()))).is_err() {
                        kill_child(&child);
                    }
                    wait_without_reaping(pid);
                    let status = child.lock().unwrap_or_else(PoisonError::into_inner).wait();
                    let info = match status {
                        Ok(s) => ExitInfo {
                            code: s.code(),
                            signal: s.signal(),
                        },
                        Err(_) => ExitInfo {
                            code: None,
                            signal: None,
                        },
                    };
                    let _ = exit_tx.send(Some(info));
                })
                .map_err(|e| SidecarError::io("starting the spawner thread", e))?;
            let (pid, child) = started_rx
                .recv()
                .map_err(|_| SidecarError::Spawn("the spawner thread died".into()))??;
            Ok((
                Sandbox {
                    pid,
                    child,
                    exit: exit_rx,
                    report,
                },
                parent_end,
            ))
        }

        /// The child's process id.
        pub fn pid(&self) -> u32 {
            self.pid
        }

        /// What confinement was applied.
        pub fn report(&self) -> &ConfinementReport {
            &self.report
        }

        /// A receiver that turns `Some` when the child has exited.
        pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
            self.exit.clone()
        }

        /// Sends SIGKILL to the child (a no-op once it has been reaped).
        pub fn kill(&self) {
            kill_child(&self.child);
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            self.kill();
        }
    }

    enum Pump {
        Out(std::process::ChildStdout),
        Err(std::process::ChildStderr),
    }

    fn kill_child(child: &Mutex<Child>) {
        let _ = child.lock().unwrap_or_else(PoisonError::into_inner).kill();
    }

    /// Blocks until `pid` has exited without reaping it, so that `kill` can never hit a reused pid.
    fn wait_without_reaping(pid: u32) {
        loop {
            // SAFETY: waitid only writes into the zeroed siginfo we pass; `pid` is our own child.
            let rc = unsafe {
                let mut info: libc::siginfo_t = std::mem::zeroed();
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            };
            if rc == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return;
            }
        }
    }

    /// The kernel thread id of the calling thread (the one `PR_SET_PDEATHSIG` is tied to).
    fn current_tid() -> u32 {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: gettid takes no arguments and cannot fail.
            u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    }

    fn start_child(
        spec: &SpawnSpec,
        plan: confine::Plan,
        child_end: UnixStream,
        parent_pid: u32,
        spawner_tid: u32,
    ) -> Result<Child, SidecarError> {
        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args)
            .env_clear()
            .current_dir(&spec.cwd)
            .stdin(Stdio::from(OwnedFd::from(child_end)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        confine::install(plan, &mut cmd, parent_pid, spawner_tid);
        cmd.spawn()
            .map_err(|e| SidecarError::Spawn(format!("{}: {e}", spec.program.display())))
    }

    #[cfg(target_os = "linux")]
    mod confine {
        use std::io;
        use std::os::unix::process::CommandExt;
        use std::path::PathBuf;
        use std::process::Command;
        use std::sync::OnceLock;

        use landlock::{
            ABI, Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
            RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
        };

        use super::{ConfinementReport, SidecarError, SpawnSpec};

        const ABI_TARGET: ABI = ABI::V9;
        /// Present on most hosts; skipped silently when missing.
        const OPTIONAL_READ_ONLY: &[&str] = &[
            "/usr/lib",
            "/lib",
            "/lib64",
            // Without these the JVM's SecureRandom seeding takes ~8 s longer (spike S2).
            "/dev/random",
            "/dev/urandom",
        ];

        pub(super) struct Plan {
            pub report: ConfinementReport,
            ruleset: Option<RulesetCreated>,
            unshare: bool,
            proc_self: bool,
            filter: Option<Vec<libc::sock_filter>>,
        }

        /// Classic BPF opcodes and seccomp return values (`linux/filter.h`, `linux/seccomp.h`).
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JEQ_K: u16 = 0x15;
        #[cfg(target_arch = "x86_64")]
        const BPF_JSET_K: u16 = 0x45;
        const BPF_RET_K: u16 = 0x06;
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
        /// `offsetof(struct seccomp_data, {nr, arch, args[0]})`.
        const OFF_NR: u32 = 0;
        const OFF_ARCH: u32 = 4;
        const OFF_ARG0: u32 = 16;
        #[cfg(target_arch = "x86_64")]
        const AUDIT_ARCH: Option<u32> = Some(0xC000_003E);
        #[cfg(target_arch = "aarch64")]
        const AUDIT_ARCH: Option<u32> = Some(0xC000_00B7);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        const AUDIT_ARCH: Option<u32> = None;

        fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
            libc::sock_filter { code, jt, jf, k }
        }

        /// The socket filter: `socket(2)` fails with EACCES, `socketpair(2)` only for `AF_UNIX`,
        /// every syscall of another ABI (x32, compat) kills the process, all else is allowed.
        pub fn socket_filter() -> Option<Vec<libc::sock_filter>> {
            let arch = AUDIT_ARCH?;
            let deny = SECCOMP_RET_ERRNO | libc::EACCES as u32;
            #[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
            let mut p = vec![
                insn(BPF_LD_W_ABS, 0, 0, OFF_ARCH),
                insn(BPF_JEQ_K, 1, 0, arch),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
                insn(BPF_LD_W_ABS, 0, 0, OFF_NR),
            ];
            // The x32 ABI shares the arch value but sets bit 30 of the syscall number.
            #[cfg(target_arch = "x86_64")]
            p.extend([
                insn(BPF_JSET_K, 0, 1, 0x4000_0000),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
            ]);
            p.extend([
                insn(BPF_JEQ_K, 3, 0, libc::SYS_socket as u32),
                insn(BPF_JEQ_K, 0, 3, libc::SYS_socketpair as u32),
                insn(BPF_LD_W_ABS, 0, 0, OFF_ARG0),
                insn(BPF_JEQ_K, 1, 0, libc::AF_UNIX as u32),
                insn(BPF_RET_K, 0, 0, deny),
                insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW),
            ]);
            Some(p)
        }

        /// Whether the kernel has seccomp filter support.
        fn seccomp_available() -> bool {
            // SAFETY: PR_GET_SECCOMP only reads the calling thread's mode.
            unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
        }

        /// The Landlock ABI version of the running kernel; 0 when unavailable or disabled.
        pub fn landlock_abi() -> u32 {
            const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
            // SAFETY: with a null attribute pointer and the VERSION flag the syscall only returns
            // the supported ABI number (or -1); it touches no memory.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    std::ptr::null::<libc::c_void>(),
                    0 as libc::size_t,
                    LANDLOCK_CREATE_RULESET_VERSION,
                )
            };
            u32::try_from(rc).unwrap_or(0)
        }

        /// Whether `unshare(CLONE_NEWUSER | CLONE_NEWNET)` works for an unprivileged forked
        /// child. Probed once per process.
        pub fn userns_netns_works() -> bool {
            static WORKS: OnceLock<bool> = OnceLock::new();
            *WORKS.get_or_init(|| {
                // SAFETY: the forked child only calls async-signal-safe functions (unshare, _exit)
                // and the parent waits for exactly that pid.
                unsafe {
                    let pid = libc::fork();
                    if pid < 0 {
                        return false;
                    }
                    if pid == 0 {
                        let rc = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
                        libc::_exit(if rc == 0 { 0 } else { 1 });
                    }
                    let mut status = 0;
                    loop {
                        let r = libc::waitpid(pid, &mut status, 0);
                        if r == pid {
                            break;
                        }
                        if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                        {
                            return false;
                        }
                    }
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
                }
            })
        }

        pub(super) fn prepare(spec: &SpawnSpec) -> Result<Plan, SidecarError> {
            let opts = &spec.options;
            let abi = landlock_abi();
            let filesystem = abi >= 1;
            if !filesystem && !opts.allow_unconfined {
                return Err(SidecarError::Confinement(
                    "Landlock is not enforced on this host (kernel too old or the LSM is \
                     disabled); refusing to run the sidecar unconfined. Enable Landlock, \
                     or set ConfinementOptions::allow_unconfined to accept the risk"
                        .into(),
                ));
            }
            if abi < crate::sandbox::MIN_LANDLOCK_ABI && !opts.allow_unconfined {
                return Err(SidecarError::Confinement(format!(
                    "Landlock ABI {abi} is too old (need >= {}: truncate control and TCP denial); \
                     refusing to run the sidecar with weak confinement. Upgrade the kernel, or \
                     set ConfinementOptions::allow_unconfined to accept the risk",
                    crate::sandbox::MIN_LANDLOCK_ABI
                )));
            }
            let filter = socket_filter().filter(|_| seccomp_available());
            if filter.is_none() && !opts.allow_unconfined {
                return Err(SidecarError::Confinement(
                    "seccomp filtering is unavailable on this host or architecture; refusing to \
                     run the sidecar with sockets enabled. Set \
                     ConfinementOptions::allow_unconfined to accept the risk"
                        .into(),
                ));
            }
            let ruleset = if filesystem {
                Some(build_ruleset(spec)?)
            } else {
                None
            };
            let netns = !opts.skip_network_namespace && userns_netns_works();
            Ok(Plan {
                report: ConfinementReport {
                    filesystem,
                    landlock_abi: abi,
                    tcp_denied: filesystem && abi >= 4,
                    scoped: filesystem && abi >= 6,
                    unix_connect_denied: filesystem && abi >= 9,
                    sockets_denied: filter.is_some(),
                    network_namespace: netns,
                    parent_death_signal: true,
                },
                ruleset,
                unshare: netns,
                proc_self: spec.proc_self_read,
                filter,
            })
        }

        fn build_ruleset(spec: &SpawnSpec) -> Result<RulesetCreated, SidecarError> {
            let err = |what: &str, e: &dyn std::fmt::Display| {
                SidecarError::Confinement(format!("{what}: {e}"))
            };
            let mut rs = Ruleset::default()
                .handle_access(AccessFs::from_all(ABI_TARGET))
                .map_err(|e| err("landlock filesystem access", &e))?;
            // Handling TCP bind/connect without allow rules denies all TCP (ABI >= 4); the
            // scopes need ABI 6. Older kernels silently drop what they do not know.
            rs = rs
                .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
                .map_err(|e| err("landlock network access", &e))?;
            rs = rs
                .scope(Scope::AbstractUnixSocket)
                .map_err(|e| err("landlock scope", &e))?;
            rs = rs
                .scope(Scope::Signal)
                .map_err(|e| err("landlock scope", &e))?;
            let mut created = rs.create().map_err(|e| err("landlock ruleset", &e))?;

            let read_only = spec
                .read_only
                .iter()
                .chain(&spec.options.extra_read_only)
                .map(|p| (p.clone(), true));
            let optional = OPTIONAL_READ_ONLY
                .iter()
                .map(PathBuf::from)
                .chain(spec.optional_read_only.iter().cloned())
                .map(|p| (p, false));
            for (path, required) in read_only.chain(optional) {
                match PathFd::new(&path) {
                    Ok(fd) => {
                        created = created
                            .add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))
                            .map_err(|e| err(&format!("read rule for {}", path.display()), &e))?;
                    }
                    Err(e) if required => {
                        return Err(err(&format!("read-only path {}", path.display()), &e));
                    }
                    Err(_) => {}
                }
            }
            for path in spec.read_write.iter().chain(&spec.options.extra_read_write) {
                let fd = PathFd::new(path)
                    .map_err(|e| err(&format!("read-write path {}", path.display()), &e))?;
                created = created
                    // No ResolveUnix: nothing may connect to a socket in a writable directory.
                    .add_rule(PathBeneath::new(fd, write_access()))
                    .map_err(|e| err(&format!("write rule for {}", path.display()), &e))?;
            }
            Ok(created)
        }

        fn write_access() -> BitFlags<AccessFs> {
            AccessFs::from_all(ABI_TARGET) & !AccessFs::ResolveUnix
        }

        pub(super) fn install(plan: Plan, cmd: &mut Command, parent_pid: u32, tid: u32) {
            let Plan {
                ruleset,
                unshare,
                proc_self,
                filter,
                ..
            } = plan;
            let mut slot = ruleset;
            // SAFETY: runs in the forked child before exec; it performs plain syscalls plus the
            // landlock crate's restrict_self (which may allocate; the child is single-threaded).
            unsafe {
                cmd.pre_exec(move || {
                    child_setup(
                        parent_pid,
                        tid,
                        unshare,
                        proc_self,
                        filter.as_deref(),
                        &mut slot,
                    )
                });
            }
        }

        fn install_seccomp(filter: &[libc::sock_filter]) -> io::Result<()> {
            let prog = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_ptr().cast_mut(),
            };
            // SAFETY: plain prctl calls; `prog` points at a live, correctly sized filter.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &prog as *const libc::sock_fprog,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }

        fn child_setup(
            parent_pid: u32,
            spawner_tid: u32,
            unshare: bool,
            proc_self: bool,
            filter: Option<&[libc::sock_filter]>,
            ruleset: &mut Option<RulesetCreated>,
        ) -> io::Result<()> {
            // SAFETY: plain syscalls in the post-fork, pre-exec child.
            unsafe {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                // The parent (spawner thread) may have died between fork and prctl.
                if libc::getppid() as u32 != parent_pid {
                    libc::_exit(1);
                }
                // PDEATHSIG follows the forking *thread*, and getppid() only names the process:
                // also require the spawner thread itself to be alive (tgkill signal 0).
                if spawner_tid != 0
                    && libc::syscall(
                        libc::SYS_tgkill,
                        parent_pid as libc::c_long,
                        spawner_tid as libc::c_long,
                        0,
                    ) != 0
                {
                    libc::_exit(1);
                }
                // No core dump of a process that parses hostile input: its memory may hold the
                // user's data, and a crash is reported by the supervisor. 1, not 0: with a piped
                // core_pattern (systemd-coredump) the kernel skips the dump only at exactly 1.
                let core = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                    let none = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    libc::setrlimit(libc::RLIMIT_CORE, &none);
                }
                // Belt and braces: no inherited descriptor survives exec (std already sets
                // CLOEXEC on its own). Failure (old kernel) is harmless.
                libc::syscall(
                    libc::SYS_close_range,
                    3 as libc::c_uint,
                    libc::c_uint::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                );
                if unshare && libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if let Some(mut rs) = ruleset.take() {
                if proc_self {
                    // Resolved here, after fork, so it is the child's own /proc/<pid>.
                    let fd = PathFd::new("/proc/self").map_err(io::Error::other)?;
                    rs = rs
                        .add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))
                        .map_err(io::Error::other)?;
                }
                let status = rs.restrict_self().map_err(io::Error::other)?;
                // PartiallyEnforced is expected: file rules drop directory-only access bits.
                if status.ruleset == RulesetStatus::NotEnforced {
                    return Err(io::Error::other("landlock not enforced"));
                }
            }
            // Last, so the setup above (and the exec) are not subject to the filter.
            if let Some(filter) = filter {
                install_seccomp(filter)?;
            }
            Ok(())
        }
    }

    #[cfg(not(target_os = "linux"))]
    mod confine {
        use std::process::Command;

        use super::{ConfinementReport, SidecarError, SpawnSpec};

        pub(super) struct Plan {
            pub report: ConfinementReport,
        }

        pub(super) fn prepare(spec: &SpawnSpec) -> Result<Plan, SidecarError> {
            if spec.options.allow_unconfined {
                Ok(Plan {
                    report: ConfinementReport {
                        // The JVM watches the parent pid itself (`--watch-parent`).
                        parent_death_signal: true,
                        ..ConfinementReport::none()
                    },
                })
            } else {
                Err(SidecarError::Confinement(
                    crate::sandbox::unconfined_refusal(),
                ))
            }
        }

        pub(super) fn install(_plan: Plan, _cmd: &mut Command, _parent_pid: u32, _tid: u32) {}
    }

    #[cfg(all(test, target_os = "linux"))]
    pub use confine::socket_filter;
    #[cfg(target_os = "linux")]
    pub use confine::{landlock_abi, userns_netns_works};
}

#[cfg(windows)]
mod windows {
    use std::process::Stdio;
    use std::sync::Arc;

    use kraken_procguard::ProcessGuard;
    use tokio::process::{ChildStdin, ChildStdout, Command};
    use tokio::sync::watch;
    use tokio_util::io::SyncIoBridge;

    use super::{ConfinementReport, ExitInfo, SpawnSpec};
    use crate::error::SidecarError;
    use crate::log::LogSink;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// A running sidecar on Windows: stdin/stdout pipes carry the protocol, stderr goes to the
    /// log, and a kill-on-close job object ties the JVM's life to this process.
    #[derive(Debug)]
    pub struct WinSandbox {
        pid: u32,
        guard: Arc<ProcessGuard>,
        exit: watch::Receiver<Option<ExitInfo>>,
        report: ConfinementReport,
    }

    impl WinSandbox {
        /// Spawns `spec`; must run inside a Tokio runtime. Refuses unless
        /// `allow_unconfined` is set, because no Windows confinement exists yet.
        pub fn spawn(
            spec: SpawnSpec,
            log: &LogSink,
        ) -> Result<(WinSandbox, ChildStdout, ChildStdin), SidecarError> {
            if !spec.options.allow_unconfined {
                return Err(SidecarError::Confinement(super::unconfined_refusal()));
            }
            let guard = ProcessGuard::new()
                .map_err(|e| SidecarError::io("creating the sidecar job object", e))?;
            let mut child = Command::new(&spec.program)
                .args(&spec.args)
                .env_clear()
                .envs(spec.env.iter().map(|(k, v)| (k, v)))
                .current_dir(&spec.cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .creation_flags(CREATE_NO_WINDOW)
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| SidecarError::Spawn(format!("{}: {e}", spec.program.display())))?;
            let pid = child
                .id()
                .ok_or_else(|| SidecarError::Spawn("the sidecar exited immediately".into()))?;
            guard
                .assign_pid(pid)
                .map_err(|e| SidecarError::io("adding the sidecar to its job object", e))?;
            let (Some(stdin), Some(stdout), Some(stderr)) =
                (child.stdin.take(), child.stdout.take(), child.stderr.take())
            else {
                return Err(SidecarError::Spawn("the sidecar pipes are missing".into()));
            };
            let sink = log.clone();
            drop(tokio::task::spawn_blocking(move || {
                sink.pump(SyncIoBridge::new(stderr));
            }));
            let (exit_tx, exit_rx) = watch::channel(None);
            drop(tokio::spawn(async move {
                let info = match child.wait().await {
                    Ok(st) => ExitInfo {
                        code: st.code(),
                        signal: None,
                    },
                    Err(_) => ExitInfo {
                        code: None,
                        signal: None,
                    },
                };
                let _ = exit_tx.send(Some(info));
            }));
            let report = ConfinementReport {
                parent_death_signal: true,
                ..ConfinementReport::none()
            };
            Ok((
                WinSandbox {
                    pid,
                    guard: Arc::new(guard),
                    exit: exit_rx,
                    report,
                },
                stdout,
                stdin,
            ))
        }

        /// The child's process id.
        pub fn pid(&self) -> u32 {
            self.pid
        }

        /// What confinement was applied (none, plus the job object).
        pub fn report(&self) -> &ConfinementReport {
            &self.report
        }

        /// A receiver that turns `Some` when the child has exited.
        pub fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
            self.exit.clone()
        }

        /// Terminates the whole job.
        pub fn kill(&self) {
            self.guard.terminate();
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
use unix::socket_filter as confine_socket_filter;
#[cfg(all(unix, target_os = "linux"))]
pub use unix::{landlock_abi, userns_netns_works};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::io::Read;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::log::LogSink;

    const TEST_NAME: &str = "sandbox::tests::network_is_denied_inside_the_sandbox";
    const SOCKET_TEST_NAME: &str = "sandbox::tests::new_sockets_are_denied_inside_the_sandbox";

    fn probe_child() {
        let addr = std::env::var("KRAKEN_PROBE_ADDR").unwrap_or_default();
        let describe = |r: std::io::Result<()>| {
            r.map(|()| "OK".to_string())
                .unwrap_or_else(|e| format!("denied({})", e.kind()))
        };
        println!(
            "PROBE connect={} bind={}",
            describe(std::net::TcpStream::connect(&addr).map(drop)),
            describe(std::net::TcpListener::bind("127.0.0.1:0").map(drop)),
        );
    }

    /// `socket(domain, SOCK_STREAM|SOCK_DGRAM, 0)` result as text; closes a successful fd.
    fn raw_socket(domain: libc::c_int, ty: libc::c_int) -> String {
        // SAFETY: plain syscalls on descriptors this function creates and closes.
        unsafe {
            let fd = libc::socket(domain, ty, 0);
            if fd >= 0 {
                libc::close(fd);
                "OK".into()
            } else {
                format!(
                    "denied({})",
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                )
            }
        }
    }

    fn socket_probe_child() {
        let path = std::env::var("KRAKEN_PROBE_SOCK").unwrap_or_default();
        let describe = |r: std::io::Result<()>| {
            r.map(|()| "OK".to_string())
                .unwrap_or_else(|e| format!("denied({})", e.raw_os_error().unwrap_or(0)))
        };
        let mut pair = [0 as libc::c_int; 2];
        // SAFETY: socketpair writes two descriptors into `pair`.
        let sp =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
        // The inherited protocol socket (fd 0) still works for I/O.
        // SAFETY: fd 0 is the inherited socketpair end; one byte is read-only written.
        let inherited = unsafe { libc::write(0, [0u8].as_ptr().cast(), 0) };
        println!(
            "SOCKPROBE unix_connect={} udp={} tcp={} raw={} netlink={} packet={} unix_socket={} \
             inet6={} socketpair={} inherited={}",
            describe(std::os::unix::net::UnixStream::connect(&path).map(drop)),
            raw_socket(libc::AF_INET, libc::SOCK_DGRAM),
            raw_socket(libc::AF_INET, libc::SOCK_STREAM),
            raw_socket(libc::AF_INET, libc::SOCK_RAW),
            raw_socket(libc::AF_NETLINK, libc::SOCK_RAW),
            raw_socket(libc::AF_PACKET, libc::SOCK_RAW),
            raw_socket(libc::AF_UNIX, libc::SOCK_STREAM),
            raw_socket(libc::AF_INET6, libc::SOCK_DGRAM),
            if sp == 0 { "OK" } else { "denied" },
            if inherited >= 0 { "OK" } else { "broken" },
        );
    }

    fn run_probe(skip_netns: bool, addr: std::net::SocketAddr) -> (ConfinementReport, String) {
        run_probe_test(
            TEST_NAME,
            "PROBE connect=",
            skip_netns,
            &[("KRAKEN_PROBE_ADDR", addr.to_string())],
        )
    }

    fn run_probe_test(
        test: &str,
        marker: &str,
        skip_netns: bool,
        env: &[(&str, String)],
    ) -> (ConfinementReport, String) {
        let exe = std::env::current_exe().unwrap();
        let log = LogSink::default();
        let mut spec_env: Vec<(std::ffi::OsString, std::ffi::OsString)> =
            vec![("KRAKEN_PROBE_CHILD".into(), "1".into())];
        spec_env.extend(env.iter().map(|(k, v)| ((*k).into(), v.into())));
        let spec = SpawnSpec {
            program: exe.clone(),
            args: [
                "--exact",
                test,
                "--include-ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .map(Into::into)
            .to_vec(),
            env: spec_env,
            cwd: "/".into(),
            read_only: vec![exe, "/usr".into(), "/etc".into()],
            optional_read_only: vec![],
            proc_self_read: false,
            read_write: vec![],
            options: ConfinementOptions {
                skip_network_namespace: skip_netns,
                ..ConfinementOptions::default()
            },
        };
        let (sb, mut channel) = Sandbox::spawn(spec, &log).unwrap();
        let exit = sb.exit_watch();
        let deadline = Instant::now() + Duration::from_secs(60);
        while exit.borrow().is_none() {
            assert!(Instant::now() < deadline, "probe child did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
        // Give the log pump threads a moment to drain the pipes.
        std::thread::sleep(Duration::from_millis(200));
        let mut sink = Vec::new();
        let _ = channel.read_to_end(&mut sink);
        let line = log
            .lines()
            .into_iter()
            .find_map(|l| l.find(marker).map(|i| l[i..].to_string()))
            .unwrap_or_else(|| panic!("no probe output; log: {:?}", log.lines()));
        (sb.report().clone(), line)
    }

    /// Re-executes this test binary under the sandbox and checks that TCP is refused, once with
    /// Landlock alone and once with the network namespace as well.
    #[test]
    #[ignore = "needs Landlock (kernel 6.7+ for TCP rules); run with --ignored"]
    fn network_is_denied_inside_the_sandbox() {
        if std::env::var_os("KRAKEN_PROBE_CHILD").is_some() {
            probe_child();
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        if landlock_abi() >= 4 {
            let (report, line) = run_probe(true, addr);
            assert!(report.tcp_denied && !report.network_namespace, "{report}");
            assert!(
                line.contains("connect=denied") && line.contains("bind=denied"),
                "landlock alone: {line}"
            );
        } else {
            eprintln!(
                "skipping the landlock-only probe: kernel ABI is {}",
                landlock_abi()
            );
        }
        if userns_netns_works() {
            let (report, line) = run_probe(false, addr);
            assert!(report.network_namespace, "{report}");
            assert!(line.contains("connect=denied"), "netns: {line}");
        } else {
            eprintln!("skipping the netns probe: unprivileged user namespaces are unavailable");
        }
    }

    /// The confined child cannot create any new socket (inet, UDP, raw, netlink, packet, even a
    /// fresh AF_UNIX one) and cannot connect to a pathname unix socket that the parent listens
    /// on, while `socketpair(AF_UNIX)` and the inherited protocol socket keep working. Runs with
    /// and without the network namespace so the seccomp filter is shown to work on its own.
    #[test]
    fn new_sockets_are_denied_inside_the_sandbox() {
        if std::env::var_os("KRAKEN_PROBE_CHILD").is_some() {
            socket_probe_child();
            return;
        }
        if landlock_abi() < crate::sandbox::MIN_LANDLOCK_ABI {
            eprintln!(
                "skipping: Landlock ABI {} is below the floor",
                landlock_abi()
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("victim.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let sock_env = [("KRAKEN_PROBE_SOCK", sock.display().to_string())];
        for skip_netns in [true, false] {
            let (report, line) =
                run_probe_test(SOCKET_TEST_NAME, "SOCKPROBE ", skip_netns, &sock_env);
            assert!(
                report.sockets_denied && report.network_blocked(),
                "{report}"
            );
            assert_eq!(report.unix_connect_denied, landlock_abi() >= 9, "{report}");
            for denied in [
                "unix_connect=denied",
                "udp=denied",
                "tcp=denied",
                "raw=denied",
                "netlink=denied",
                "packet=denied",
                "unix_socket=denied",
                "inet6=denied",
            ] {
                assert!(line.contains(denied), "netns skipped={skip_netns}: {line}");
            }
            assert!(
                line.contains("socketpair=OK") && line.contains("inherited=OK"),
                "{line}"
            );
        }
        // Nothing ever reached the listener.
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err());
    }

    #[test]
    fn socket_filter_is_well_formed() {
        let Some(f) = confine_socket_filter() else {
            return;
        };
        // Every forward jump lands inside the program, and it ends in a return.
        for (i, ins) in f.iter().enumerate() {
            if ins.code == 0x15 || ins.code == 0x45 {
                assert!(i + 1 + (ins.jt.max(ins.jf) as usize) < f.len(), "insn {i}");
            }
        }
        assert_eq!(f.last().unwrap().code, 0x06);
    }

    #[test]
    fn the_abi_floor_and_network_blocked_are_strict() {
        let mut r = ConfinementReport::none();
        r.tcp_denied = true;
        assert!(!r.network_blocked(), "TCP denial alone leaves UDP open");
        r.network_namespace = true;
        assert!(r.network_blocked());
        let mut r = ConfinementReport::none();
        r.network_namespace = true;
        assert!(
            !r.network_blocked(),
            "a netns without TCP denial is not enough"
        );
        r.sockets_denied = true;
        assert!(r.network_blocked());
        // Without allow_unconfined a host below the floor refuses to spawn.
        if landlock_abi() < crate::sandbox::MIN_LANDLOCK_ABI {
            let spec = SpawnSpec {
                program: "/bin/true".into(),
                args: vec![],
                env: vec![],
                cwd: "/".into(),
                read_only: vec![],
                optional_read_only: vec![],
                proc_self_read: false,
                read_write: vec![],
                options: ConfinementOptions::default(),
            };
            assert!(Sandbox::spawn(spec, &LogSink::default()).is_err());
        }
    }

    #[test]
    fn report_display_is_readable() {
        let r = ConfinementReport::none();
        assert!(r.to_string().starts_with("UNCONFINED"));
        assert!(!r.is_confined() && !r.network_blocked());
    }
}

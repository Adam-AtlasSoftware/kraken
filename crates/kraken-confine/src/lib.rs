//! Confinement for child processes that run untrusted code: model-written Rust (the rewrite
//! pipeline), and whatever the assistant is allowed to run (a shell, the analysed program).
//! Decision 71 spirit: what a model wrote, or what a sample does, is untrusted code.
//!
//! Linux: a scrubbed environment, `PR_SET_PDEATHSIG`, a process group of its own (so a timeout
//! can kill every descendant), resource limits, a Landlock ruleset, and network isolation:
//!
//! * Landlock: read-only system paths (plus the toolchain sysroot for the compile step) and one
//!   read-write run directory; TCP denied; abstract unix sockets and signals scoped. The compile
//!   step does **not** get the whole file system: `include_str!` and friends must not be able to
//!   read `~/.ssh` or the daemon token.
//! * Landlock ABI 4 or newer is required (it is the first ABI that can deny TCP). Landlock never
//!   covers UDP at any ABI, so network isolation is separate and also required: a user plus
//!   network namespace when the host allows one, otherwise a seccomp filter that refuses
//!   `socket()` for every domain but `AF_UNIX` (and everything for a runner). The filter is
//!   installed in both cases as a second layer; it also removes `io_uring` (which could open
//!   sockets without `socket()`), and for a runner `fork`/`clone`.
//!
//! A host that cannot do all of this refuses to run unless [`Confinement::allow_unconfined`] is
//! set; then the child runs without any of the Landlock/namespace/seccomp layers. Other platforms
//! refuse the same way.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Why a child could not be confined or a scratch directory could not be made.
#[derive(Debug, thiserror::Error)]
pub enum ConfineError {
    /// The host cannot confine (Landlock too old, no network isolation, not Linux), or the
    /// ruleset could not be built.
    #[error("{0}")]
    Refused(String),
    /// A scratch directory could not be made or is not private.
    #[error("{0}")]
    Scratch(String),
}

/// The lowest Landlock ABI accepted (the first one that can deny TCP bind/connect).
pub const LANDLOCK_ABI_FLOOR: u32 = 4;

/// What a confined child may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadScope {
    /// A build tool or shell: system library directories and `/proc/self`, `PATH` kept in the
    /// environment, `socket(AF_UNIX)` and `fork` allowed; plus [`Confinement::exec_read_paths`]
    /// (the compiler adds its sysroot there).
    Toolchain,
    /// A compiled runner: system libraries and `/proc/self` only; no sockets, no new processes.
    SystemLibraries,
}

/// Resource limits applied in the child before exec (`setrlimit`, soft = hard).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// `RLIMIT_AS`, bytes.
    pub address_space: u64,
    /// `RLIMIT_CPU`, seconds.
    pub cpu_seconds: u64,
    /// `RLIMIT_FSIZE`, bytes: the largest file the child may write.
    pub file_size: u64,
    /// `RLIMIT_NPROC`. Counted against the whole user, not the child: a value at or below the
    /// number of processes the user already runs makes every `fork` fail.
    pub processes: u64,
}

/// Confinement settings.
#[derive(Debug, Clone, Default)]
pub struct Confinement {
    /// Run unconfined when the host cannot confine. Off by default.
    pub allow_unconfined: bool,
    /// Skip the network namespace and use only the seccomp filter (for tests of that path).
    #[doc(hidden)]
    pub seccomp_only: bool,
    /// Further paths the child may read (never write), for example the analysed binary.
    pub extra_read_paths: Vec<PathBuf>,
    /// Paths the child may read and execute (the compiler's sysroot, with
    /// [`ReadScope::Toolchain`]); they are not affected by `deny_exec_in_dir`.
    pub exec_read_paths: Vec<PathBuf>,
    /// Withhold the execute right from the writable directory and `extra_read_paths`, so nothing
    /// written there (or placed there) can be run. System directories stay executable.
    pub deny_exec_in_dir: bool,
    /// Resource limits replacing the scope's defaults (`None`: the defaults).
    pub limits: Option<Limits>,
}

/// How a child was kept off the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkIsolation {
    /// Not isolated.
    None,
    /// A user plus network namespace.
    Namespace,
    /// A seccomp filter refusing non-`AF_UNIX` sockets.
    Seccomp,
}

/// How a child was confined, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementReport {
    /// Landlock ABI version enforced (0 when none).
    pub landlock_abi: u32,
    /// How the network was cut off.
    pub network: NetworkIsolation,
}

impl ConfinementReport {
    /// Short label stored in unit records.
    pub fn label(&self) -> String {
        if self.landlock_abi == 0 {
            return "none".to_string();
        }
        let net = match self.network {
            NetworkIsolation::None => "",
            NetworkIsolation::Namespace => "+netns",
            NetworkIsolation::Seccomp => "+seccomp",
        };
        format!("landlock-v{}{net}", self.landlock_abi)
    }
}

/// Installs the confinement on `cmd`: environment scrubbed to the minimum, working directory
/// `dir`, the filesystem limited as `scope` says with `dir` writable, no network, its own process
/// group.
pub fn confine(
    cmd: &mut Command,
    dir: &Path,
    scope: ReadScope,
    opts: &Confinement,
) -> Result<ConfinementReport, ConfineError> {
    imp::confine(cmd, dir, scope, opts)
}

/// True when this host can confine the processes that build and run generated code: Landlock ABI
/// 4 or newer plus network isolation (Linux). The `rewrite_*` commands that run generated code
/// refuse to start when it is false.
pub fn enforced() -> bool {
    imp::enforced()
}

/// The Landlock ABI version the host enforces (0 when none or not Linux).
pub fn landlock_abi_version() -> u32 {
    imp::abi()
}

/// Paths every confined child may read on Linux (a toolchain adds its sysroot through [`Confinement::exec_read_paths`]).
#[cfg(target_os = "linux")]
pub fn system_read_paths() -> Vec<PathBuf> {
    // `/proc` is deliberately absent: only `/proc/self` is granted, in the child, so another
    // process's `cmdline` stays unreadable.
    [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/dev/null",
        "/dev/urandom",
    ]
    .iter()
    .map(PathBuf::from)
    .collect()
}

// ----- private scratch directories -----

/// A fresh scratch directory under a private (`0700`, owned by the current user) root, never
/// directly under a shared `/tmp`: another local user could otherwise plant
/// `/tmp/.cargo/config.toml` (a `rustc-wrapper` or `linker` that the build would run) or
/// pre-create the path. The root is `$XDG_RUNTIME_DIR/kraken-confine`, else
/// `<temp dir>/kraken-confine-<uid>`; no ancestor may hold a cargo config.
pub fn scratch_dir(prefix: &str) -> Result<tempfile::TempDir, ConfineError> {
    let root = scratch_root()?;
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&root)
        .map_err(|e| {
            ConfineError::Scratch(format!("scratch directory in {}: {e}", root.display()))
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ConfineError::Scratch(format!("scratch directory mode: {e}")))?;
    }
    Ok(dir)
}

fn scratch_root() -> Result<PathBuf, ConfineError> {
    let err = |m: String| ConfineError::Scratch(format!("scratch directory: {m}"));
    #[cfg(unix)]
    // SAFETY: geteuid takes no arguments and cannot fail.
    let uid = unsafe { libc::geteuid() };
    #[cfg(unix)]
    let name = format!("kraken-confine-{uid}");
    #[cfg(not(unix))]
    let name = "kraken-confine".to_string();
    let root = match std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
    {
        Some(x) => x.join("kraken-confine"),
        None => std::env::temp_dir().join(name),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(err(format!("{}: {e}", root.display()))),
        }
        let md = std::fs::symlink_metadata(&root).map_err(|e| err(format!("{e}")))?;
        if !md.is_dir() || md.uid() != uid || md.mode() & 0o077 != 0 {
            return Err(err(format!(
                "{} is not a private directory owned by the current user (mode {:o}, uid {})",
                root.display(),
                md.mode() & 0o7777,
                md.uid()
            )));
        }
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&root).map_err(|e| err(format!("{}: {e}", root.display())))?;
    let canon = root
        .canonicalize()
        .map_err(|e| err(format!("{}: {e}", root.display())))?;
    check_no_cargo_config(&canon).map_err(err)?;
    Ok(canon)
}

/// Cargo reads `.cargo/config.toml` from every ancestor of its working directory; none may exist
/// above the scratch root.
fn check_no_cargo_config(root: &Path) -> Result<(), String> {
    for anc in root.ancestors() {
        for f in [".cargo/config.toml", ".cargo/config"] {
            let p = anc.join(f);
            if p.symlink_metadata().is_ok() {
                return Err(format!(
                    "{} exists above the scratch directory; cargo would apply it to the build",
                    p.display()
                ));
            }
        }
    }
    Ok(())
}

// ----- running a confined child with a deadline -----

/// What a confined child produced.
#[derive(Debug)]
pub struct Captured {
    /// Exit status; `None` when the deadline killed it.
    pub status: Option<ExitStatus>,
    /// Captured stdout (capped).
    pub stdout: Vec<u8>,
    /// Captured stderr (capped).
    pub stderr: Vec<u8>,
}

fn read_capped(mut r: impl Read, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = r.by_ref().take(cap as u64).read_to_end(&mut out);
    // Drain the rest so the child never blocks on a full pipe.
    let _ = std::io::copy(&mut r, &mut std::io::sink());
    out
}

fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        // The child leads its own process group (see `confine`), so this reaches descendants too.
        // SAFETY: plain kill(2) on a negative pid (a process group).
        unsafe {
            libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

/// Spawns `cmd` (already confined) with piped output, waits at most `timeout`, and returns what it
/// printed (each stream capped at `cap` bytes). On a timeout, and also after a normal exit, the
/// child's whole process group is killed, so no descendant outlives the call; reader threads are
/// waited for only briefly, so a descendant that escaped the group cannot hang the caller.
pub fn run_captured(
    cmd: &mut Command,
    timeout: Duration,
    cap: usize,
    poll: Duration,
) -> std::io::Result<Captured> {
    run_captured_with_input(cmd, None, timeout, cap, poll)
}

/// [`run_captured`] with `input` written to the child's standard input (then closed); `None`
/// gives the child an empty, closed stdin. A child that stops reading early is not an error.
pub fn run_captured_with_input(
    cmd: &mut Command,
    input: Option<Vec<u8>>,
    timeout: Duration,
    cap: usize,
    poll: Duration,
) -> std::io::Result<Captured> {
    cmd.stdin(if input.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    if let (Some(data), Some(mut stdin)) = (input, child.stdin.take()) {
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(&data);
        });
    }
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>)>();
    let mut readers = 0;
    if let Some(s) = child.stdout.take() {
        let tx = tx.clone();
        readers += 1;
        std::thread::spawn(move || {
            let _ = tx.send((true, read_capped(s, cap)));
        });
    }
    if let Some(s) = child.stderr.take() {
        let tx = tx.clone();
        readers += 1;
        std::thread::spawn(move || {
            let _ = tx.send((false, read_capped(s, cap)));
        });
    }
    drop(tx);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => {
                kill_tree(&mut child);
                break Some(s);
            }
            Ok(None) if started.elapsed() > timeout => {
                kill_tree(&mut child);
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(poll),
            Err(e) => {
                kill_tree(&mut child);
                return Err(e);
            }
        }
    };
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..readers {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((true, b)) => stdout = b,
            Ok((false, b)) => stderr = b,
            Err(_) => break,
        }
    }
    Ok(Captured {
        status,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::sync::OnceLock;

    use landlock::{
        ABI, Access, AccessFs, AccessNet, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope,
    };

    use super::*;

    const ABI_TARGET: ABI = ABI::V6;
    // A runner is single-purpose: bounded memory, CPU and output files; no cores.
    const RUNNER_MEMORY: u64 = 2 << 30;
    const RUNNER_CPU_SECONDS: u64 = 30;
    const RUNNER_FILE_SIZE: u64 = 64 << 20;
    const RUNNER_OPEN_FILES: u64 = 64;
    // The compile step: generous (LLVM, linkers), but bounded.
    const COMPILE_MEMORY: u64 = 16 << 30;
    const COMPILE_CPU_SECONDS: u64 = 900;
    const COMPILE_FILE_SIZE: u64 = 4 << 30;
    const COMPILE_OPEN_FILES: u64 = 4096;

    pub fn abi() -> u32 {
        landlock_abi()
    }

    pub fn enforced() -> bool {
        landlock_abi() >= LANDLOCK_ABI_FLOOR
            && network_isolation(&Confinement::default()) != NetworkIsolation::None
    }

    fn landlock_abi() -> u32 {
        const LANDLOCK_CREATE_RULESET_VERSION: libc::c_ulong = 1;
        // SAFETY: with a null attribute pointer and the VERSION flag the syscall only returns the
        // supported ABI number (or -1); it touches no memory.
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

    /// True when a child can `unshare(CLONE_NEWUSER | CLONE_NEWNET)` (probed once, in a forked
    /// child that only calls `unshare` and `_exit`).
    fn netns_available() -> bool {
        static CELL: OnceLock<bool> = OnceLock::new();
        *CELL.get_or_init(|| {
            // SAFETY: the child calls only async-signal-safe functions (`unshare`, `_exit`).
            unsafe {
                let pid = libc::fork();
                if pid == 0 {
                    let rc = libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET);
                    libc::_exit(if rc == 0 { 0 } else { 1 });
                }
                if pid < 0 {
                    return false;
                }
                let mut st = 0;
                libc::waitpid(pid, &mut st, 0) == pid
                    && libc::WIFEXITED(st)
                    && libc::WEXITSTATUS(st) == 0
            }
        })
    }

    fn network_isolation(opts: &Confinement) -> NetworkIsolation {
        if !opts.seccomp_only && netns_available() {
            NetworkIsolation::Namespace
        } else if seccomp::SUPPORTED {
            NetworkIsolation::Seccomp
        } else {
            NetworkIsolation::None
        }
    }

    // ----- seccomp -----

    mod seccomp {
        use super::*;

        #[cfg(target_arch = "x86_64")]
        const AUDIT_ARCH: u32 = 0xC000_003E;
        #[cfg(target_arch = "aarch64")]
        const AUDIT_ARCH: u32 = 0xC000_00B7;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        const AUDIT_ARCH: u32 = 0;

        pub const SUPPORTED: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JEQ_K: u16 = 0x15;
        const BPF_JSET_K: u16 = 0x45;
        const BPF_RET_K: u16 = 0x06;
        const RET_ALLOW: u32 = 0x7fff_0000;
        const RET_KILL_PROCESS: u32 = 0x8000_0000;
        const RET_ERRNO: u32 = 0x0005_0000;
        const AF_UNIX: u32 = 1;
        const CLONE_THREAD: u32 = 0x0001_0000;
        // seccomp_data: nr at 0, arch at 4, args from 16 (little-endian: low word first).
        const OFF_NR: u32 = 0;
        const OFF_ARCH: u32 = 4;
        const OFF_ARG0: u32 = 16;

        fn ins(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
            libc::sock_filter { code, jt, jf, k }
        }

        fn deny(p: &mut Vec<libc::sock_filter>, nr: libc::c_long, errno: libc::c_int) {
            p.push(ins(BPF_JEQ_K, 0, 1, nr as u32));
            p.push(ins(BPF_RET_K, 0, 0, RET_ERRNO | errno as u32));
        }

        /// The filter for `scope`: `socket`/`socketpair` refused (all domains but `AF_UNIX` for the
        /// compiler, all for a runner), `io_uring_setup` refused, and for a runner `fork`,
        /// `vfork`, `clone3` and any `clone` that is not a thread.
        pub fn program(scope: ReadScope) -> Vec<libc::sock_filter> {
            let runner = scope == ReadScope::SystemLibraries;
            let eperm = RET_ERRNO | libc::EPERM as u32;
            let mut p = vec![
                ins(BPF_LD_W_ABS, 0, 0, OFF_ARCH),
                ins(BPF_JEQ_K, 1, 0, AUDIT_ARCH),
                ins(BPF_RET_K, 0, 0, RET_KILL_PROCESS),
                ins(BPF_LD_W_ABS, 0, 0, OFF_NR),
            ];
            for nr in [libc::SYS_socket, libc::SYS_socketpair] {
                p.push(ins(BPF_JEQ_K, 0, if runner { 2 } else { 4 }, nr as u32));
                p.push(ins(BPF_LD_W_ABS, 0, 0, OFF_ARG0));
                if !runner {
                    p.push(ins(BPF_JEQ_K, 0, 1, AF_UNIX));
                    p.push(ins(BPF_RET_K, 0, 0, RET_ALLOW));
                }
                p.push(ins(BPF_RET_K, 0, 0, eperm));
            }
            deny(&mut p, libc::SYS_io_uring_setup, libc::EPERM);
            if runner {
                #[cfg(target_arch = "x86_64")]
                {
                    deny(&mut p, libc::SYS_fork, libc::EPERM);
                    deny(&mut p, libc::SYS_vfork, libc::EPERM);
                }
                // glibc falls back to `clone` when `clone3` reports ENOSYS.
                deny(&mut p, libc::SYS_clone3, libc::ENOSYS);
                p.push(ins(BPF_JEQ_K, 0, 4, libc::SYS_clone as u32));
                p.push(ins(BPF_LD_W_ABS, 0, 0, OFF_ARG0));
                p.push(ins(BPF_JSET_K, 0, 1, CLONE_THREAD));
                p.push(ins(BPF_RET_K, 0, 0, RET_ALLOW));
                p.push(ins(BPF_RET_K, 0, 0, eperm));
            }
            p.push(ins(BPF_RET_K, 0, 0, RET_ALLOW));
            p
        }

        /// Installs `prog` on the calling thread (and everything it forks).
        pub fn install(prog: &mut [libc::sock_filter]) -> io::Result<()> {
            let fprog = libc::sock_fprog {
                len: prog.len() as u16,
                filter: prog.as_mut_ptr(),
            };
            // SAFETY: documented prctl/seccomp calls; `fprog` points at `prog`, which outlives them.
            unsafe {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
                if libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    0 as libc::c_ulong,
                    &fprog as *const libc::sock_fprog,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }
    }

    // ----- Landlock -----

    fn build(
        dir: &Path,
        scope: ReadScope,
        opts: &Confinement,
    ) -> Result<RulesetCreated, ConfineError> {
        let err = |what: &str, e: &dyn std::fmt::Display| {
            ConfineError::Refused(format!("confinement: {what}: {e}"))
        };
        let mut rs = Ruleset::default()
            .handle_access(AccessFs::from_all(ABI_TARGET))
            .map_err(|e| err("filesystem access", &e))?
            .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
            .map_err(|e| err("network access", &e))?;
        rs = rs
            .scope(Scope::AbstractUnixSocket)
            .map_err(|e| err("scope", &e))?
            .scope(Scope::Signal)
            .map_err(|e| err("scope", &e))?;
        let mut created = rs.create().map_err(|e| err("ruleset", &e))?;
        let mut read = system_read_paths();
        if scope == ReadScope::Toolchain {
            read.extend(opts.exec_read_paths.iter().cloned());
            read.push(PathBuf::from("/nix/store"));
            read.push(PathBuf::from("/sys/devices/system/cpu"));
        }
        for path in read {
            if let Ok(fd) = PathFd::new(&path) {
                created = created
                    .add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))
                    .map_err(|e| err("read rule", &e))?;
            }
        }
        let no_exec = |a: BitFlags<AccessFs>| {
            if opts.deny_exec_in_dir {
                a & !BitFlags::from_flag(AccessFs::Execute)
            } else {
                a
            }
        };
        for path in &opts.extra_read_paths {
            let fd = PathFd::new(path).map_err(|e| err("extra read path", &e))?;
            created = created
                .add_rule(PathBeneath::new(
                    fd,
                    no_exec(AccessFs::from_read(ABI_TARGET)),
                ))
                .map_err(|e| err("extra read rule", &e))?;
        }
        if let Ok(fd) = PathFd::new("/dev/null") {
            created = created
                .add_rule(PathBeneath::new(
                    fd,
                    AccessFs::ReadFile | AccessFs::WriteFile,
                ))
                .map_err(|e| err("null device", &e))?;
        }
        let fd = PathFd::new(dir).map_err(|e| err("writable directory", &e))?;
        created = created
            .add_rule(PathBeneath::new(
                fd,
                no_exec(AccessFs::from_all(ABI_TARGET)),
            ))
            .map_err(|e| err("write rule", &e))?;
        Ok(created)
    }

    fn refusal(abi: u32, net: NetworkIsolation) -> ConfineError {
        let mut why = Vec::new();
        if abi < LANDLOCK_ABI_FLOOR {
            why.push(format!(
                "Landlock ABI {abi} is below the required {LANDLOCK_ABI_FLOOR} (Linux 6.7)"
            ));
        }
        if net == NetworkIsolation::None {
            why.push("no network isolation is available (user+net namespace or seccomp)".into());
        }
        ConfineError::Refused(format!(
            "this host cannot confine model-written code: {}; refusing to run it unconfined \
             (set Confinement::allow_unconfined to accept the risk)",
            why.join("; ")
        ))
    }

    #[cfg(test)]
    pub fn refusal_for_test(abi: u32, net: NetworkIsolation) -> ConfineError {
        refusal(abi, net)
    }

    #[cfg(test)]
    pub fn seccomp_program_for_test(scope: ReadScope) -> Vec<libc::sock_filter> {
        seccomp::program(scope)
    }

    pub fn confine(
        cmd: &mut Command,
        dir: &Path,
        scope: ReadScope,
        opts: &Confinement,
    ) -> Result<ConfinementReport, ConfineError> {
        let abi = landlock_abi();
        let net = network_isolation(opts);
        let enforceable = abi >= LANDLOCK_ABI_FLOOR && net != NetworkIsolation::None;
        if !enforceable && !opts.allow_unconfined {
            return Err(refusal(abi, net));
        }
        cmd.env_clear().current_dir(dir).env("TMPDIR", dir);
        // The compiler needs PATH to find `cc`; nothing else of the caller's environment (no
        // HOME, CARGO_HOME or RUSTUP_HOME: the real toolchain binaries are run directly).
        if scope == ReadScope::Toolchain
            && let Some(p) = std::env::var_os("PATH")
        {
            cmd.env("PATH", p);
        }
        let mut ruleset = if enforceable {
            Some(build(dir, scope, opts)?)
        } else {
            None
        };
        let mut filter = enforceable.then(|| seccomp::program(scope));
        let use_netns = enforceable && net == NetworkIsolation::Namespace;
        // SAFETY: geteuid/getegid take no arguments and cannot fail.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let uid_map = format!("{uid} {uid} 1\n");
        let gid_map = format!("{gid} {gid} 1\n");
        let parent = std::process::id();
        let limits = opts.limits;
        // Own process group, so a timeout can kill every descendant.
        cmd.process_group(0);
        // SAFETY: runs in the forked child before exec: plain syscalls plus the landlock crate's
        // restrict_self; the child is single threaded until exec.
        unsafe {
            cmd.pre_exec(move || {
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
                if libc::getppid() as u32 != parent {
                    libc::_exit(1);
                }
                let limit = |res, v: u64| {
                    let l = libc::rlimit {
                        rlim_cur: v,
                        rlim_max: v,
                    };
                    libc::setrlimit(res, &l)
                };
                // 1, not 0: with a piped core_pattern (systemd-coredump) the kernel still
                // dumps at 0 and skips the dump only at exactly 1, so a crashing translation
                // does not reach the host's crash handlers
                if limit(libc::RLIMIT_CORE, 1) != 0 {
                    // the hard limit is already 0 and cannot be raised
                    limit(libc::RLIMIT_CORE, 0);
                }
                if let Some(l) = limits {
                    limit(libc::RLIMIT_AS, l.address_space);
                    limit(libc::RLIMIT_CPU, l.cpu_seconds);
                    limit(libc::RLIMIT_FSIZE, l.file_size);
                    limit(libc::RLIMIT_NPROC, l.processes);
                    limit(libc::RLIMIT_NOFILE, RUNNER_OPEN_FILES);
                } else if scope == ReadScope::SystemLibraries {
                    limit(libc::RLIMIT_AS, RUNNER_MEMORY);
                    limit(libc::RLIMIT_CPU, RUNNER_CPU_SECONDS);
                    limit(libc::RLIMIT_FSIZE, RUNNER_FILE_SIZE);
                    limit(libc::RLIMIT_NOFILE, RUNNER_OPEN_FILES);
                } else {
                    limit(libc::RLIMIT_AS, COMPILE_MEMORY);
                    limit(libc::RLIMIT_CPU, COMPILE_CPU_SECONDS);
                    limit(libc::RLIMIT_FSIZE, COMPILE_FILE_SIZE);
                    limit(libc::RLIMIT_NOFILE, COMPILE_OPEN_FILES);
                }
                if use_netns {
                    if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // Map our own ids so the child still looks like the same user (best effort).
                    write_file(c"/proc/self/setgroups", b"deny\n");
                    write_file(c"/proc/self/uid_map", uid_map.as_bytes());
                    write_file(c"/proc/self/gid_map", gid_map.as_bytes());
                }
                if let Some(rs) = ruleset.take() {
                    // `/proc/self` has to be opened here: it is this process's own directory.
                    let fd = libc::open(
                        c"/proc/self".as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    );
                    let rs = if fd >= 0 {
                        let fd = OwnedFd::from_raw_fd(fd);
                        rs.add_rule(PathBeneath::new(fd, AccessFs::from_read(ABI_TARGET)))
                            .map_err(io::Error::other)?
                    } else {
                        rs
                    };
                    let status = rs.restrict_self().map_err(io::Error::other)?;
                    if status.ruleset == RulesetStatus::NotEnforced {
                        return Err(io::Error::other("landlock not enforced"));
                    }
                }
                if let Some(f) = filter.as_mut() {
                    seccomp::install(f)?;
                }
                Ok(())
            });
        }
        Ok(ConfinementReport {
            landlock_abi: if enforceable { abi } else { 0 },
            network: if enforceable {
                net
            } else {
                NetworkIsolation::None
            },
        })
    }

    /// Writes `data` to `path` (used for `/proc/self/*_map`); errors ignored.
    fn write_file(path: &std::ffi::CStr, data: &[u8]) {
        // SAFETY: `path` is NUL-terminated; `data` is a valid slice.
        unsafe {
            let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                libc::write(fd, data.as_ptr().cast(), data.len());
                libc::close(fd);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn abi() -> u32 {
        0
    }

    pub fn enforced() -> bool {
        false
    }

    pub fn confine(
        cmd: &mut Command,
        dir: &Path,
        _scope: ReadScope,
        opts: &Confinement,
    ) -> Result<ConfinementReport, ConfineError> {
        if !opts.allow_unconfined {
            return Err(ConfineError::Refused(
                "confinement of model-written code is only implemented on Linux (Landlock)".into(),
            ));
        }
        cmd.env_clear().current_dir(dir).env("TMPDIR", dir);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        Ok(ConfinementReport {
            landlock_abi: 0,
            network: NetworkIsolation::None,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "tests.rs"]
mod tests;

//! Confining terminal agents so they cannot read KRAKEN's user credential (security finding H4).
//!
//! The daemon issues two credentials: the *user* token (`daemon.token`, GUI and CLI) and the
//! *agent* token (`agent.token`, the MCP server). A terminal agent runs as the same OS user as
//! KRAKEN, so without more it could simply read `daemon.token` and speak as the person. On Linux
//! the agent is therefore started in an unprivileged sandbox of namespaces:
//!
//! - a **user namespace** (identity-mapped: same uid and gid, no capabilities after `exec`),
//! - a **mount namespace** in which an empty `tmpfs` hides KRAKEN's runtime directory, with only
//!   the daemon socket, `daemon.json` and the *agent* token bind-mounted back in, so the MCP
//!   server the agent starts (it inherits the sandbox) still reaches the daemon with the agent
//!   credential and nothing else in that directory exists for the agent,
//! - a **PID namespace** with a fresh `/proc`, so the agent cannot walk to the daemon's mount
//!   namespace through `/proc/<pid>/root` and read the original directory,
//! - `no_new_privs`, an emptied capability set and bounding set.
//!
//! The rest of the machine (home directory, tools, network) is unchanged, so the agent keeps its
//! normal working environment. Nothing needs root or an external helper program.
//!
//! When the kernel or the distribution refuses unprivileged namespaces (`probe` fails), the
//! caller must not hand the agent any runtime-directory information and should tell the person;
//! see [`crate::host`]. On macOS and Windows there is no such confinement yet: [`probe`] reports
//! it as unavailable.

use std::ffi::OsString;
use std::path::PathBuf;

/// One runtime directory to hide and the entries of it that stay visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HiddenDir {
    /// The directory (absolute).
    pub dir: PathBuf,
    /// File names inside `dir` that are bind-mounted back (when they exist).
    pub keep: Vec<OsString>,
}

/// What to hide from an agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confinement {
    /// Directories replaced by an empty `tmpfs`.
    pub hide: Vec<HiddenDir>,
}

/// File names of the runtime directory that an agent's MCP server needs: the socket, the info
/// file and the agent-class credential. The user token is deliberately not among them.
pub const AGENT_VISIBLE: &[&str] = &["daemon.sock", "daemon.json", "agent.token"];

/// Whether this platform can confine agents, and if not, why. The answer is computed once by
/// actually starting a throwaway process in the sandbox.
pub fn probe() -> Result<(), String> {
    imp::probe()
}

pub(crate) use imp::install;

#[cfg(target_os = "linux")]
mod imp {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicI32, Ordering};

    use super::Confinement;

    const MAX_KEEPS: usize = 32;

    struct Prepared {
        uid_map: Vec<u8>,
        gid_map: Vec<u8>,
        dirs: Vec<PreparedDir>,
    }

    struct PreparedDir {
        dir: CString,
        keeps: Vec<(CString, CString)>,
    }

    fn cstr(b: &[u8]) -> std::io::Result<CString> {
        CString::new(b).map_err(|_| std::io::Error::other("a path contains a NUL byte"))
    }

    fn prepare(c: &Confinement) -> std::io::Result<Prepared> {
        // SAFETY: getuid/getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        if uid == 0 {
            return Err(std::io::Error::other(
                "running as root: namespaces would not take away any privilege",
            ));
        }
        let mut dirs = Vec::new();
        let mut total = 0;
        for h in &c.hide {
            let mut keeps = Vec::new();
            for name in &h.keep {
                let src = cstr(h.dir.join(name).as_os_str().as_bytes())?;
                // Only plain names: never a path that could point out of the directory.
                if name.as_bytes().contains(&b'/') || name.is_empty() {
                    return Err(std::io::Error::other("bad name in the keep list"));
                }
                keeps.push((src.clone(), src));
                total += 1;
            }
            dirs.push(PreparedDir {
                dir: cstr(h.dir.as_os_str().as_bytes())?,
                keeps,
            });
        }
        if total > MAX_KEEPS {
            return Err(std::io::Error::other("too many entries to keep"));
        }
        Ok(Prepared {
            uid_map: format!("{uid} {uid} 1\n").into_bytes(),
            gid_map: format!("{gid} {gid} 1\n").into_bytes(),
            dirs,
        })
    }

    /// Makes `command` start inside the sandbox. Fails (before any process exists) when the
    /// confinement description is unusable; kernel refusals show up when the command is spawned.
    pub(crate) fn install(command: &mut Command, c: &Confinement) -> std::io::Result<()> {
        let prepared = prepare(c)?;
        // SAFETY: `enter` only uses async-signal-safe calls (no allocation, no locks) and runs
        // between fork and exec.
        unsafe {
            command.pre_exec(move || enter(&prepared));
        }
        Ok(())
    }

    pub(super) fn probe() -> Result<(), String> {
        static CELL: OnceLock<Result<(), String>> = OnceLock::new();
        CELL.get_or_init(|| {
            let tmp = std::env::temp_dir();
            let c = Confinement {
                hide: vec![super::HiddenDir {
                    dir: tmp.clone(),
                    keep: vec![],
                }],
            };
            // Hiding the real temp dir in a throwaway process is harmless, but a missing or
            // relative one would be a mistake: probe a directory that exists.
            if !tmp.is_absolute() || !tmp.is_dir() {
                return Err("no usable temporary directory to probe with".into());
            }
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c")
                .arg("exit 0")
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            install(&mut cmd, &c).map_err(|e| e.to_string())?;
            match cmd.status() {
                Ok(st) if st.success() => Ok(()),
                Ok(_) => Err("the sandbox could not be set up (user, mount or PID namespaces, or a fresh /proc, are refused here)".into()),
                Err(e) => Err(format!("namespaces are unavailable: {e}")),
            }
        })
        .clone()
    }

    // ---- code that runs after fork: raw syscalls only ---------------------------------------

    static INIT_PID: AtomicI32 = AtomicI32::new(0);
    static AGENT_PID: AtomicI32 = AtomicI32::new(0);

    extern "C" fn forward_to_init(sig: libc::c_int) {
        let p = INIT_PID.load(Ordering::Relaxed);
        if p > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe { libc::kill(p, sig) };
        }
    }

    extern "C" fn forward_to_agent(sig: libc::c_int) {
        let p = AGENT_PID.load(Ordering::Relaxed);
        if p > 0 {
            // SAFETY: kill is async-signal-safe.
            unsafe { libc::kill(p, sig) };
        }
    }

    const FORWARDED: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

    fn errno_err() -> std::io::Error {
        std::io::Error::last_os_error()
    }

    unsafe fn write_all(path: &[u8], data: &[u8]) -> std::io::Result<()> {
        // `path` is NUL-terminated by the caller.
        let fd = unsafe { libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(errno_err());
        }
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        let e = errno_err();
        unsafe { libc::close(fd) };
        if n < 0 || n as usize != data.len() {
            return Err(e);
        }
        Ok(())
    }

    fn status_code(st: libc::c_int) -> libc::c_int {
        if libc::WIFEXITED(st) {
            libc::WEXITSTATUS(st)
        } else if libc::WIFSIGNALED(st) {
            128 + libc::WTERMSIG(st)
        } else {
            1
        }
    }

    unsafe fn die(msg: &[u8]) -> ! {
        unsafe {
            libc::write(2, msg.as_ptr().cast(), msg.len());
            libc::_exit(125)
        }
    }

    unsafe fn close_from_3() {
        let r = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
        if r != 0 {
            for fd in 3..1024 {
                unsafe { libc::close(fd) };
            }
        }
    }

    /// Runs in the child between fork and exec. Returns `Ok(())` only in the process that is to
    /// exec the agent (the third process of the chain).
    fn enter(p: &Prepared) -> std::io::Result<()> {
        // SAFETY: only raw syscalls on data prepared before the fork.
        unsafe {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) != 0 {
                return Err(errno_err());
            }
            write_all(b"/proc/self/setgroups\0", b"deny")?;
            write_all(b"/proc/self/uid_map\0", &p.uid_map)?;
            write_all(b"/proc/self/gid_map\0", &p.gid_map)?;

            let init = libc::fork();
            if init < 0 {
                return Err(errno_err());
            }
            if init > 0 {
                middle(init);
            }
            // Process 1 of the new PID namespace.
            init_process(p)
        }
    }

    /// The process the spawner sees. It stays outside the PID namespace, relays signals and the
    /// exit status, and drops every inherited descriptor so that `spawn` returns as soon as the
    /// agent has exec'd.
    unsafe fn middle(init: libc::pid_t) -> ! {
        unsafe {
            INIT_PID.store(init, Ordering::Relaxed);
            for s in FORWARDED {
                libc::signal(s, forward_to_init as *const () as usize);
            }
            close_from_3();
            let mut st: libc::c_int = 0;
            loop {
                let r = libc::waitpid(init, &mut st, 0);
                if r == init {
                    libc::_exit(status_code(st));
                }
                if r < 0 && *libc::__errno_location() != libc::EINTR {
                    libc::_exit(1);
                }
            }
        }
    }

    /// Sets up the mounts, then forks the agent process and reaps until it ends.
    unsafe fn init_process(p: &Prepared) -> std::io::Result<()> {
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                die(b"kraken: cannot make the mounts private\n");
            }
            if libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            ) != 0
            {
                die(b"kraken: cannot mount a private /proc\n");
            }

            // Hold the entries to keep open before their directory disappears.
            let mut fds = [-1i32; MAX_KEEPS];
            let mut n = 0usize;
            for d in &p.dirs {
                for (src, _) in &d.keeps {
                    let fd = libc::open(src.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                    fds[n] = fd; // -1 when the entry does not exist
                    n += 1;
                }
            }
            let mut i = 0usize;
            for d in &p.dirs {
                if libc::mount(
                    c"tmpfs".as_ptr(),
                    d.dir.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    c"mode=0700,size=1m".as_ptr().cast(),
                ) != 0
                {
                    die(b"kraken: cannot hide the runtime directory\n");
                }
                for (_, dst) in &d.keeps {
                    let fd = fds[i];
                    i += 1;
                    if fd < 0 {
                        continue;
                    }
                    let t = libc::open(
                        dst.as_ptr(),
                        libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                        0o600 as libc::c_uint,
                    );
                    if t < 0 {
                        die(b"kraken: cannot prepare a bind target\n");
                    }
                    libc::close(t);
                    let mut buf = [0u8; 40];
                    let src = fd_path(fd, &mut buf);
                    if libc::mount(
                        src.as_ptr().cast(),
                        dst.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    ) != 0
                    {
                        die(b"kraken: cannot bind an entry into the hidden directory\n");
                    }
                }
            }

            let agent = libc::fork();
            if agent < 0 {
                die(b"kraken: cannot fork the agent\n");
            }
            if agent == 0 {
                // The agent: no descriptors of ours, no privileges, then exec (by the caller).
                for fd in fds.iter().take(n) {
                    if *fd >= 0 {
                        libc::close(*fd);
                    }
                }
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong);
                for s in FORWARDED {
                    libc::signal(s, libc::SIG_DFL);
                }
                drop_privileges()?;
                return Ok(());
            }
            AGENT_PID.store(agent, Ordering::Relaxed);
            for s in FORWARDED {
                libc::signal(s, forward_to_agent as *const () as usize);
            }
            // Only the agent keeps the spawner's error pipe.
            close_from_3();
            let mut st: libc::c_int = 0;
            loop {
                let r = libc::waitpid(-1, &mut st, 0);
                if r == agent {
                    libc::_exit(status_code(st));
                }
                if r < 0 && *libc::__errno_location() != libc::EINTR {
                    libc::_exit(1);
                }
            }
        }
    }

    /// Writes `/proc/self/fd/<fd>\0` into `buf` and returns the used part.
    fn fd_path(fd: i32, buf: &mut [u8; 40]) -> &[u8] {
        let prefix = b"/proc/self/fd/";
        buf[..prefix.len()].copy_from_slice(prefix);
        let mut digits = [0u8; 10];
        let mut v = fd as u32;
        let mut k = 0;
        loop {
            digits[k] = b'0' + (v % 10) as u8;
            k += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut at = prefix.len();
        while k > 0 {
            k -= 1;
            buf[at] = digits[k];
            at += 1;
        }
        buf[at] = 0;
        &buf[..=at]
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const CAP_V3: u32 = 0x2008_0522;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    unsafe fn drop_privileges() -> std::io::Result<()> {
        unsafe {
            libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
            for cap in 0..64 {
                // EINVAL past the last capability the kernel knows.
                libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
            }
            let hdr = CapHeader {
                version: CAP_V3,
                pid: 0,
            };
            let data = [CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            }; 2];
            if libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) != 0 {
                return Err(errno_err());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(errno_err());
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::process::Command;

    use super::Confinement;

    pub(crate) fn install(_: &mut Command, _: &Confinement) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "agent confinement is only implemented on Linux",
        ))
    }

    pub(super) fn probe() -> Result<(), String> {
        Err("agent confinement is only implemented on Linux for now".into())
    }
}

/// The directories a runtime-directory setting could mean, for the host to hide: the directory
/// the MCP server is told about, the one named by the parent environment, and the per-user
/// default under `XDG_RUNTIME_DIR`. Only absolute paths; duplicates removed.
pub fn runtime_dirs(mcp_dir: Option<&str>, parent_env: &[(OsString, OsString)]) -> Vec<PathBuf> {
    let get = |k: &str| {
        parent_env
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| PathBuf::from(v))
    };
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |p: PathBuf| {
        if p.is_absolute() && !p.as_os_str().is_empty() && !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(d) = mcp_dir {
        add(PathBuf::from(d));
    }
    if let Some(d) = get("KRAKEN_RUNTIME_DIR") {
        add(d);
    }
    if let Some(x) = get("XDG_RUNTIME_DIR") {
        add(x.join("kraken"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dirs_are_collected_once_and_absolute() {
        let env = vec![
            (OsString::from("KRAKEN_RUNTIME_DIR"), OsString::from("/r")),
            (OsString::from("XDG_RUNTIME_DIR"), OsString::from("/run/u")),
        ];
        let dirs = runtime_dirs(Some("/r"), &env);
        assert_eq!(
            dirs,
            vec![PathBuf::from("/r"), PathBuf::from("/run/u/kraken")]
        );
        assert!(runtime_dirs(Some("rel"), &[]).is_empty());
    }
}

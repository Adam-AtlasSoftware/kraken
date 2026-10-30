//! Descriptor and directory system calls of the Linux layer beyond plain files: `dup`, `dup2`,
//! `dup3`, `fcntl`, `pipe`, `pipe2` (in-process buffers), `getdents64`, `mkdir`, `rename` (only
//! inside `/work`), `nanosleep` and `clock_nanosleep` (virtual time), `poll`, `ppoll` and
//! `sched_yield`.
//!
//! All state lives in the [`Kernel`](super::Kernel) next to the descriptor table, never in the
//! CPU snapshot, so taking or restoring a CPU snapshot cannot corrupt it. The emulated process is
//! the only one there is, so a call that would block for ever (a read from an empty pipe whose
//! writer is open, `poll` without a timeout and nothing ready) ends the run as unsupported
//! instead of hanging.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::fs::{Node, PROG_NAME};
use super::{
    EBADF, EEXIST, EFAULT, EINVAL, EMFILE, ENOENT, ENOSPC, ENOTDIR, EPIPE, EROFS, Exit, Fd, FdMeta,
    LinuxProcess, MAX_FDS, SysResult, io_errno,
};

/// The bytes in flight in a pipe.
pub(super) type PipeBuf = Arc<Mutex<VecDeque<u8>>>;

/// The capacity of a pipe, as on Linux.
const PIPE_CAP: usize = 65536;
const O_APPEND: u64 = 0o2000;
const O_NONBLOCK: u64 = 0o4000;
const O_CLOEXEC: u64 = 0o2000000;
const FD_CLOEXEC: u64 = 1;
const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 16;
const POLLNVAL: i16 = 32;
const TIMER_ABSTIME: u64 = 1;
/// Most directories the guest may create.
const MAX_DIRS: u32 = 1024;
/// Most entries one directory listing reports.
const MAX_ENTRIES: usize = 4096;
/// Most entries a `poll` call takes.
const MAX_POLL: u64 = 1024;

impl Fd {
    /// A second descriptor for the same open file description.
    fn dup(&self) -> Result<Fd, u64> {
        Ok(match self {
            Fd::Stdin => Fd::Stdin,
            Fd::Stdout => Fd::Stdout,
            Fd::Stderr => Fd::Stderr,
            Fd::Null => Fd::Null,
            Fd::Zero => Fd::Zero,
            Fd::Random => Fd::Random,
            Fd::File {
                file,
                writable,
                readable,
                append,
                work,
            } => Fd::File {
                file: file.try_clone().map_err(io_errno)?,
                writable: *writable,
                readable: *readable,
                append: *append,
                work: *work,
            },
            Fd::Dir { path, pos } => Fd::Dir {
                path: path.clone(),
                pos: *pos,
            },
            Fd::PipeRead {
                buf,
                readers,
                writers,
            } => Fd::PipeRead {
                buf: buf.clone(),
                readers: readers.clone(),
                writers: writers.clone(),
            },
            Fd::PipeWrite {
                buf,
                writers,
                readers,
            } => Fd::PipeWrite {
                buf: buf.clone(),
                writers: writers.clone(),
                readers: readers.clone(),
            },
        })
    }
}

fn dirent_len(name: &str) -> usize {
    (19 + name.len() + 1).next_multiple_of(8)
}

impl LinuxProcess {
    /// The guest clock in nanoseconds since the start: instructions executed plus time slept.
    pub(super) fn now_ns(&self) -> u64 {
        self.m.icount().saturating_add(self.k.skew_ns)
    }

    /// `int` arguments arrive in registers whose upper half the ABI leaves undefined.
    fn int_arg(&mut self, i: usize) -> i32 {
        self.arg(i) as u32 as i32
    }

    fn fd_index(&self, fd: i32) -> Result<usize, u64> {
        let i = usize::try_from(fd).map_err(|_| EBADF)?;
        match self.k.fds.get(i) {
            Some(Some(_)) => Ok(i),
            _ => Err(EBADF),
        }
    }

    fn install(&mut self, i: usize, fd: Fd, meta: FdMeta) {
        if self.k.fds.len() <= i {
            self.k.fds.resize_with(i + 1, || None);
        }
        if self.k.meta.len() <= i {
            self.k.meta.resize_with(i + 1, FdMeta::default);
        }
        self.k.fds[i] = Some(fd);
        self.k.meta[i] = meta;
    }

    /// Puts `fd` in the lowest free slot at or above `min`.
    pub(super) fn alloc_fd_from(&mut self, min: usize, fd: Fd, meta: FdMeta) -> SysResult {
        let free = (min..self.k.fds.len()).find(|&i| self.k.fds[i].is_none());
        let i = free.unwrap_or_else(|| self.k.fds.len().max(min));
        if i >= MAX_FDS {
            return Err(EMFILE);
        }
        self.install(i, fd, meta);
        Ok(i as u64)
    }

    fn free_fd(&mut self, i: usize) {
        self.k.fds[i] = None;
        self.k.meta[i] = FdMeta::default();
    }

    /// Applies `O_CLOEXEC` and `O_NONBLOCK` of an `open` to the new descriptor.
    pub(super) fn apply_open_flags(&mut self, fd: u64, flags: u64) {
        if let Some(m) = self.k.meta.get_mut(fd as usize) {
            m.cloexec = flags & O_CLOEXEC != 0;
            m.status
                .store((flags & O_NONBLOCK) as u32, Ordering::Relaxed);
        }
    }

    fn nonblocking(&self, fd: u64) -> bool {
        self.k
            .meta
            .get(fd as usize)
            .is_some_and(|m| u64::from(m.status.load(Ordering::Relaxed)) & O_NONBLOCK != 0)
    }

    /// The run cannot go on: the call would wait for something only another process could do.
    fn would_block_forever(&mut self, what: &str) {
        self.k.exit = Some(Exit::Unsupported {
            detail: format!("{what} would block for ever: no other process or thread exists"),
        });
    }

    pub(super) fn dispatch_fd(&mut self, name: &str, at_fdcwd: u64) -> SysResult {
        match name {
            "dup" => {
                let old = self.int_arg(0);
                self.dup_to(old, None, false)
            }
            "dup2" => {
                let (old, new) = (self.int_arg(0), self.int_arg(1));
                if old == new {
                    self.fd_index(old)?;
                    return Ok(new as u64);
                }
                self.dup_to(old, Some(new), false)
            }
            "dup3" => {
                let (old, new, flags) = (self.int_arg(0), self.int_arg(1), self.arg(2));
                if flags & !O_CLOEXEC != 0 || old == new {
                    return Err(EINVAL);
                }
                self.dup_to(old, Some(new), flags & O_CLOEXEC != 0)
            }
            "fcntl" | "fcntl64" => {
                let (fd, cmd, arg) = (self.int_arg(0), self.int_arg(1), self.arg(2));
                self.sys_fcntl(fd, cmd, arg)
            }
            "pipe" => {
                let addr = self.arg(0);
                self.sys_pipe(addr, 0)
            }
            "pipe2" => {
                let (addr, flags) = (self.arg(0), self.arg(1));
                self.sys_pipe(addr, flags)
            }
            "getdents64" => {
                let (fd, buf, n) = (self.int_arg(0), self.arg(1), self.arg(2));
                self.sys_getdents64(fd, buf, n)
            }
            "mkdir" => {
                let path = self.arg(0);
                self.sys_mkdir(path)
            }
            "mkdirat" => {
                let (dirfd, path) = (self.arg(0), self.arg(1));
                self.check_dirfd(dirfd, at_fdcwd, path)?;
                self.sys_mkdir(path)
            }
            "rename" => {
                let (old, new) = (self.arg(0), self.arg(1));
                self.sys_rename(old, new)
            }
            "renameat" | "renameat2" => {
                let (od, old, nd, new) = (self.arg(0), self.arg(1), self.arg(2), self.arg(3));
                if name == "renameat2" && self.arg(4) != 0 {
                    return Err(EINVAL);
                }
                self.check_dirfd(od, at_fdcwd, old)?;
                self.check_dirfd(nd, at_fdcwd, new)?;
                self.sys_rename(old, new)
            }
            "nanosleep" => {
                let req = self.arg(0);
                let ns = self.read_sleep(req, false)?;
                self.sleep(ns);
                Ok(0)
            }
            "clock_nanosleep" | "clock_nanosleep_time64" => {
                let (clock, flags, req) = (self.int_arg(0), self.arg(1), self.arg(2));
                // Realtime, monotonic, process CPU time, boot time and TAI.
                if !matches!(clock, 0 | 1 | 2 | 7 | 11) || flags & !TIMER_ABSTIME != 0 {
                    return Err(EINVAL);
                }
                let ns = self.read_sleep(req, name.ends_with("time64"))?;
                if flags & TIMER_ABSTIME != 0 {
                    self.sleep_until(ns);
                } else {
                    self.sleep(ns);
                }
                Ok(0)
            }
            "poll" => {
                let (fds, n, ms) = (self.arg(0), self.arg(1), self.int_arg(2));
                let timeout = (ms >= 0).then(|| ms as u64 * 1_000_000);
                self.sys_poll(fds, n, timeout)
            }
            "ppoll" | "ppoll_time64" => {
                let (fds, n, ts) = (self.arg(0), self.arg(1), self.arg(2));
                let timeout = if ts == 0 {
                    None
                } else {
                    Some(self.read_sleep(ts, name.ends_with("time64"))?)
                };
                self.sys_poll(fds, n, timeout)
            }
            "sched_yield" => Ok(0),
            _ => Err(super::ENOSYS),
        }
    }

    fn dup_to(&mut self, old: i32, new: Option<i32>, cloexec: bool) -> SysResult {
        let oi = self.fd_index(old)?;
        let fd = self.k.fds[oi].as_ref().ok_or(EBADF)?.dup()?;
        let meta = FdMeta {
            cloexec,
            status: self.k.meta[oi].status.clone(),
        };
        match new {
            None => self.alloc_fd_from(0, fd, meta),
            Some(n) => {
                let n = usize::try_from(n).map_err(|_| EBADF)?;
                if n >= MAX_FDS {
                    return Err(EBADF);
                }
                self.install(n, fd, meta);
                Ok(n as u64)
            }
        }
    }

    fn sys_fcntl(&mut self, fd: i32, cmd: i32, arg: u64) -> SysResult {
        const F_DUPFD: i32 = 0;
        const F_GETFD: i32 = 1;
        const F_SETFD: i32 = 2;
        const F_GETFL: i32 = 3;
        const F_SETFL: i32 = 4;
        const F_DUPFD_CLOEXEC: i32 = 1030;
        let i = self.fd_index(fd)?;
        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                let min = arg as u32 as i32;
                let min = usize::try_from(min).map_err(|_| EINVAL)?;
                if min >= MAX_FDS {
                    return Err(EINVAL);
                }
                let dup = self.k.fds[i].as_ref().ok_or(EBADF)?.dup()?;
                let meta = FdMeta {
                    cloexec: cmd == F_DUPFD_CLOEXEC,
                    status: self.k.meta[i].status.clone(),
                };
                self.alloc_fd_from(min, dup, meta)
            }
            F_GETFD => Ok(if self.k.meta[i].cloexec {
                FD_CLOEXEC
            } else {
                0
            }),
            F_SETFD => {
                self.k.meta[i].cloexec = arg & FD_CLOEXEC != 0;
                Ok(0)
            }
            F_GETFL => {
                let (acc, append) = match &self.k.fds[i] {
                    Some(Fd::Stdin | Fd::PipeRead { .. } | Fd::Dir { .. }) => (0, false),
                    Some(Fd::Stdout | Fd::Stderr | Fd::PipeWrite { .. }) => (1, false),
                    Some(Fd::Null | Fd::Zero | Fd::Random) => (2, false),
                    Some(Fd::File {
                        readable,
                        writable,
                        append,
                        ..
                    }) => (
                        match (readable, writable) {
                            (true, true) => 2,
                            (false, true) => 1,
                            _ => 0,
                        },
                        *append,
                    ),
                    None => return Err(EBADF),
                };
                let status = u64::from(self.k.meta[i].status.load(Ordering::Relaxed));
                Ok(acc | (status & O_NONBLOCK) | if append { O_APPEND } else { 0 })
            }
            F_SETFL => {
                self.k.meta[i]
                    .status
                    .store((arg & O_NONBLOCK) as u32, Ordering::Relaxed);
                if let Some(Fd::File { append, .. }) = &mut self.k.fds[i] {
                    *append = arg & O_APPEND != 0;
                }
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    }

    fn sys_pipe(&mut self, addr: u64, flags: u64) -> SysResult {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(EINVAL);
        }
        let buf: PipeBuf = Arc::default();
        let (rtok, wtok) = (Arc::new(()), Arc::new(()));
        let read = Fd::PipeRead {
            buf: buf.clone(),
            readers: rtok.clone(),
            writers: Arc::downgrade(&wtok),
        };
        let write = Fd::PipeWrite {
            buf,
            writers: wtok.clone(),
            readers: Arc::downgrade(&rtok),
        };
        let meta = || {
            let m = FdMeta {
                cloexec: flags & O_CLOEXEC != 0,
                ..FdMeta::default()
            };
            m.status
                .store((flags & O_NONBLOCK) as u32, Ordering::Relaxed);
            m
        };
        let r = self.alloc_fd_from(0, read, meta())?;
        let w = match self.alloc_fd_from(0, write, meta()) {
            Ok(w) => w,
            Err(e) => {
                self.free_fd(r as usize);
                return Err(e);
            }
        };
        let mut b = (r as u32).to_le_bytes().to_vec();
        b.extend_from_slice(&(w as u32).to_le_bytes());
        if !self.m.guest_write(addr, &b) {
            self.free_fd(r as usize);
            self.free_fd(w as usize);
            return Err(EFAULT);
        }
        Ok(0)
    }

    pub(super) fn pipe_read(&mut self, fd: u64, buf: u64, n: usize) -> SysResult {
        let nonblock = self.nonblocking(fd);
        let Some(Some(Fd::PipeRead {
            buf: pipe, writers, ..
        })) = self.k.fds.get(fd as usize)
        else {
            return Err(EBADF);
        };
        let eof = writers.strong_count() == 0;
        let data: Vec<u8> = {
            let mut q = pipe.lock().map_err(|_| EINVAL)?;
            let take = q.len().min(n);
            q.drain(..take).collect()
        };
        if data.is_empty() && n > 0 {
            if eof {
                return Ok(0);
            }
            if nonblock {
                return Err(super::EAGAIN);
            }
            self.would_block_forever("a read from an empty pipe");
            return Ok(0);
        }
        if !data.is_empty() && !self.m.guest_write(buf, &data) {
            return Err(EFAULT);
        }
        Ok(data.len() as u64)
    }

    pub(super) fn pipe_write(&mut self, fd: u64, data: &[u8]) -> SysResult {
        let nonblock = self.nonblocking(fd);
        let Some(Some(Fd::PipeWrite {
            buf: pipe, readers, ..
        })) = self.k.fds.get(fd as usize)
        else {
            return Err(EBADF);
        };
        // The kernel would raise SIGPIPE too; the layer reports the error only.
        if readers.strong_count() == 0 {
            return Err(EPIPE);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let took = {
            let mut q = pipe.lock().map_err(|_| EINVAL)?;
            let take = PIPE_CAP.saturating_sub(q.len()).min(data.len());
            q.extend(&data[..take]);
            take
        };
        if took == 0 {
            if nonblock {
                return Err(super::EAGAIN);
            }
            self.would_block_forever("a write to a full pipe");
        }
        Ok(took as u64)
    }

    fn list_dir(&self, path: &std::path::Path) -> Result<Vec<(String, u8)>, u64> {
        let is_work = path == self.k.vfs.workdir();
        let mut entries: Vec<(String, u8)> = Vec::new();
        for e in std::fs::read_dir(path).map_err(io_errno)?.take(MAX_ENTRIES) {
            let e = e.map_err(io_errno)?;
            let name = e.file_name().to_string_lossy().into_owned();
            if is_work && name == PROG_NAME {
                continue;
            }
            let ty = match e.file_type() {
                Ok(t) if t.is_dir() => 4,
                Ok(t) if t.is_symlink() => 10,
                Ok(t) if t.is_file() => 8,
                _ => 0,
            };
            entries.push((name, ty));
        }
        if is_work {
            entries.push((PROG_NAME.to_string(), 8));
        }
        entries.sort();
        let mut all = vec![(".".to_string(), 4), ("..".to_string(), 4)];
        all.extend(entries);
        Ok(all)
    }

    fn sys_getdents64(&mut self, fd: i32, buf: u64, count: u64) -> SysResult {
        let i = self.fd_index(fd)?;
        let (path, pos) = match &self.k.fds[i] {
            Some(Fd::Dir { path, pos }) => (path.clone(), *pos),
            _ => return Err(ENOTDIR),
        };
        let all = self.list_dir(&path)?;
        let count = count.min(1 << 20) as usize;
        let mut out: Vec<u8> = Vec::new();
        let mut next = pos;
        for (idx, (name, ty)) in all.iter().enumerate().skip(pos) {
            let len = dirent_len(name);
            if out.len() + len > count {
                if out.is_empty() {
                    return Err(EINVAL);
                }
                break;
            }
            let start = out.len();
            out.extend_from_slice(&(0x1000 + idx as u64 + 1).to_le_bytes());
            out.extend_from_slice(&(idx as i64 + 1).to_le_bytes());
            out.extend_from_slice(&(len as u16).to_le_bytes());
            out.push(*ty);
            out.extend_from_slice(name.as_bytes());
            out.resize(start + len, 0);
            next = idx + 1;
        }
        if !out.is_empty() && !self.m.guest_write(buf, &out) {
            return Err(EFAULT);
        }
        if let Some(Fd::Dir { pos, .. }) = &mut self.k.fds[i] {
            *pos = next;
        }
        Ok(out.len() as u64)
    }

    fn sys_mkdir(&mut self, path: u64) -> SysResult {
        let p = self.read_path(path)?;
        if p.is_empty() {
            return Err(ENOENT);
        }
        match self.k.vfs.resolve(&p) {
            Node::Work(h) => {
                if self.k.dirs_made >= MAX_DIRS {
                    return Err(ENOSPC);
                }
                std::fs::create_dir(&h).map_err(io_errno)?;
                self.k.dirs_made += 1;
                Ok(0)
            }
            Node::Missing => Err(EROFS),
            _ => Err(EEXIST),
        }
    }

    fn sys_rename(&mut self, old: u64, new: u64) -> SysResult {
        let o = self.read_path(old)?;
        let n = self.read_path(new)?;
        if o.is_empty() || n.is_empty() {
            return Err(ENOENT);
        }
        match (self.k.vfs.resolve(&o), self.k.vfs.resolve(&n)) {
            (Node::Work(a), Node::Work(b)) => std::fs::rename(a, b).map(|_| 0).map_err(io_errno),
            (Node::Missing, _) => Err(ENOENT),
            _ => Err(EROFS),
        }
    }

    /// Reads a `timespec` (two 32-bit fields on a 32-bit architecture unless it is the time64
    /// form) and returns it in nanoseconds.
    fn read_sleep(&mut self, addr: u64, time64: bool) -> Result<u64, u64> {
        let wide = time64 || self.k.arch.bits() == 64;
        let (sec, nsec) = if wide {
            (
                self.m.read_uint(addr, 8).map_err(|_| EFAULT)? as i64,
                self.m.read_uint(addr + 8, 8).map_err(|_| EFAULT)? as i64,
            )
        } else {
            (
                self.m.read_uint(addr, 4).map_err(|_| EFAULT)? as u32 as i32 as i64,
                self.m.read_uint(addr + 4, 4).map_err(|_| EFAULT)? as u32 as i32 as i64,
            )
        };
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(EINVAL);
        }
        Ok((sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec as u64))
    }

    /// Sleeps `ns` of virtual time. The remainder is left alone: a sleep here always finishes.
    fn sleep(&mut self, ns: u64) {
        self.k.skew_ns = self.k.skew_ns.saturating_add(ns);
    }

    /// Sleeps until the guest clock reads `target` nanoseconds (as `clock_gettime` returns it).
    fn sleep_until(&mut self, target: u64) {
        let epoch = super::EPOCH.saturating_mul(1_000_000_000);
        let now = epoch.saturating_add(self.now_ns());
        if target > now {
            self.k.skew_ns = self.k.skew_ns.saturating_add(target - now);
        }
    }

    fn readiness(&self, fd: &Fd) -> i16 {
        let pipe_has = |b: &PipeBuf| b.lock().is_ok_and(|q| !q.is_empty());
        match fd {
            // Standard input behaves as a pipe whose writer has gone away.
            Fd::Stdin => {
                (if self.k.stdin_pos < self.k.stdin.len() {
                    POLLIN
                } else {
                    0
                }) | POLLHUP
            }
            Fd::Stdout | Fd::Stderr => POLLOUT,
            Fd::Null | Fd::Zero | Fd::Random | Fd::File { .. } | Fd::Dir { .. } => POLLIN | POLLOUT,
            Fd::PipeRead { buf, writers, .. } => {
                (if pipe_has(buf) { POLLIN } else { 0 })
                    | (if writers.strong_count() == 0 {
                        POLLHUP
                    } else {
                        0
                    })
            }
            Fd::PipeWrite { buf, readers, .. } => {
                let room = buf.lock().is_ok_and(|q| q.len() < PIPE_CAP);
                (if room { POLLOUT } else { 0 })
                    | (if readers.strong_count() == 0 {
                        POLLERR
                    } else {
                        0
                    })
            }
        }
    }

    fn sys_poll(&mut self, fds: u64, nfds: u64, timeout_ns: Option<u64>) -> SysResult {
        if nfds > MAX_POLL {
            return Err(EINVAL);
        }
        let mut ready = 0u64;
        for i in 0..nfds {
            let a = fds + 8 * i;
            let fd = self.m.read_uint(a, 4).map_err(|_| EFAULT)? as u32 as i32;
            let events = self.m.read_uint(a + 4, 2).map_err(|_| EFAULT)? as u16 as i16;
            let revents = match usize::try_from(fd) {
                Err(_) => 0,
                Ok(idx) => match self.k.fds.get(idx) {
                    Some(Some(f)) => self.readiness(f) & (events | POLLERR | POLLHUP),
                    _ => POLLNVAL,
                },
            };
            self.m
                .write_uint(a + 6, 2, u64::from(revents as u16))
                .map_err(|_| EFAULT)?;
            if revents != 0 {
                ready += 1;
            }
        }
        if ready == 0 {
            match timeout_ns {
                Some(t) => self.k.skew_ns = self.k.skew_ns.saturating_add(t),
                None => self.would_block_forever("a poll without a timeout and nothing ready"),
            }
        }
        Ok(ready)
    }
}

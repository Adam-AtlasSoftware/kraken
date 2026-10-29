//! System call numbers: the generic table (AArch64, RISC-V 64 and 32), ARM EABI, x86-64 and
//! i386. Only the calls the layer knows by name are listed; every other number is reported as
//! unknown and answered with `ENOSYS`.

use crate::arch::Arch;

/// The name of system call `nr` on `arch`, as the layer dispatches it.
pub fn name(arch: Arch, nr: u64) -> Option<&'static str> {
    tables(arch)
        .iter()
        .flat_map(|t| t.iter())
        .find(|(n, _)| *n == nr)
        .map(|(_, s)| *s)
}

/// A readable name for system call `nr`: the layer's own name, else the kernel's name for a call
/// it does not implement, else `syscall <nr>`. Used in reports so a user sees `socket` and not 41.
pub fn describe(arch: Arch, nr: u64) -> String {
    if let Some(n) = name(arch, nr) {
        return n.to_string();
    }
    let extra: &[(u64, &str)] = match arch {
        Arch::X86_64 => X86_64_EXTRA,
        Arch::Aarch64 | Arch::Riscv64 | Arch::Riscv32 => GENERIC_EXTRA,
        Arch::Arm => ARM_EXTRA,
        Arch::X86 => I386_EXTRA,
    };
    match extra.iter().find(|(n, _)| *n == nr) {
        Some((_, s)) => (*s).to_string(),
        None => format!("syscall {nr}"),
    }
}

/// Linux x86-64 calls the layer does not implement (named for reports only).
const X86_64_EXTRA: &[(u64, &str)] = &[
    (7, "poll"),
    (22, "pipe"),
    (23, "select"),
    (24, "sched_yield"),
    (25, "mremap"),
    (32, "dup"),
    (33, "dup2"),
    (35, "nanosleep"),
    (38, "setitimer"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (44, "sendto"),
    (45, "recvfrom"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (48, "shutdown"),
    (49, "bind"),
    (50, "listen"),
    (51, "getsockname"),
    (52, "getpeername"),
    (54, "setsockopt"),
    (55, "getsockopt"),
    (56, "clone"),
    (57, "fork"),
    (58, "vfork"),
    (59, "execve"),
    (61, "wait4"),
    (72, "fcntl"),
    (74, "fsync"),
    (78, "getdents"),
    (80, "chdir"),
    (82, "rename"),
    (83, "mkdir"),
    (84, "rmdir"),
    (90, "chmod"),
    (95, "umask"),
    (98, "getrusage"),
    (99, "sysinfo"),
    (100, "times"),
    (203, "sched_setaffinity"),
    (204, "sched_getaffinity"),
    (217, "getdents64"),
    (230, "clock_nanosleep"),
    (270, "pselect6"),
    (271, "ppoll"),
    (281, "epoll_pwait"),
    (288, "accept4"),
    (290, "eventfd2"),
    (291, "epoll_create1"),
    (292, "dup3"),
    (293, "pipe2"),
    (319, "memfd_create"),
    (435, "clone3"),
];

/// Calls of the generic table (AArch64, RISC-V) the layer does not implement.
const GENERIC_EXTRA: &[(u64, &str)] = &[
    (19, "eventfd2"),
    (20, "epoll_create1"),
    (21, "epoll_ctl"),
    (22, "epoll_pwait"),
    (23, "dup"),
    (24, "dup3"),
    (25, "fcntl"),
    (34, "mkdirat"),
    (38, "renameat"),
    (59, "pipe2"),
    (61, "getdents64"),
    (73, "ppoll"),
    (82, "fsync"),
    (101, "nanosleep"),
    (115, "clock_nanosleep"),
    (122, "sched_setaffinity"),
    (123, "sched_getaffinity"),
    (124, "sched_yield"),
    (153, "times"),
    (165, "getrusage"),
    (166, "umask"),
    (179, "sysinfo"),
    (198, "socket"),
    (200, "bind"),
    (201, "listen"),
    (202, "accept"),
    (203, "connect"),
    (204, "getsockname"),
    (205, "getpeername"),
    (206, "sendto"),
    (207, "recvfrom"),
    (208, "setsockopt"),
    (209, "getsockopt"),
    (210, "shutdown"),
    (211, "sendmsg"),
    (212, "recvmsg"),
    (216, "mremap"),
    (220, "clone"),
    (221, "execve"),
    (242, "accept4"),
    (260, "wait4"),
    (435, "clone3"),
];

/// ARM EABI calls the layer does not implement.
const ARM_EXTRA: &[(u64, &str)] = &[
    (2, "fork"),
    (11, "execve"),
    (114, "wait4"),
    (120, "clone"),
    (162, "nanosleep"),
    (281, "socket"),
    (283, "connect"),
];

/// i386 calls the layer does not implement.
const I386_EXTRA: &[(u64, &str)] = &[
    (2, "fork"),
    (11, "execve"),
    (102, "socketcall"),
    (114, "wait4"),
    (120, "clone"),
    (158, "sched_yield"),
    (162, "nanosleep"),
];

fn tables(arch: Arch) -> &'static [&'static [(u64, &'static str)]] {
    match arch {
        Arch::Aarch64 | Arch::Riscv64 => &[GENERIC, GENERIC64],
        Arch::Riscv32 => &[GENERIC, GENERIC32],
        Arch::Arm => &[ARM_EABI],
        Arch::X86_64 => &[X86_64],
        Arch::X86 => &[I386],
    }
}

/// Calls common to every generic-table architecture.
const GENERIC: &[(u64, &str)] = &[
    (17, "getcwd"),
    (29, "ioctl"),
    (35, "unlinkat"),
    (46, "ftruncate"),
    (48, "faccessat"),
    (56, "openat"),
    (57, "close"),
    (63, "read"),
    (64, "write"),
    (65, "readv"),
    (66, "writev"),
    (67, "pread64"),
    (78, "readlinkat"),
    (93, "exit"),
    (94, "exit_group"),
    (96, "set_tid_address"),
    (98, "futex"),
    (99, "set_robust_list"),
    (129, "kill"),
    (130, "tkill"),
    (131, "tgkill"),
    (132, "sigaltstack"),
    (134, "rt_sigaction"),
    (135, "rt_sigprocmask"),
    (160, "uname"),
    (163, "getrlimit"),
    (172, "getpid"),
    (173, "getppid"),
    (174, "getuid"),
    (175, "geteuid"),
    (176, "getgid"),
    (177, "getegid"),
    (178, "gettid"),
    (214, "brk"),
    (215, "munmap"),
    (226, "mprotect"),
    (233, "madvise"),
    (258, "riscv_hwprobe"),
    (261, "prlimit64"),
    (278, "getrandom"),
    (291, "statx"),
    (293, "rseq"),
    (403, "clock_gettime64"),
    (439, "faccessat2"),
];

const GENERIC64: &[(u64, &str)] = &[
    (62, "lseek"),
    (79, "newfstatat"),
    (80, "fstat"),
    (113, "clock_gettime"),
    (169, "gettimeofday"),
    (222, "mmap"),
];

/// The 32-bit generic table: `_llseek` under the lseek number, `mmap2` under mmap's, and only the
/// 64-bit time calls (RV32 is time64 only).
const GENERIC32: &[(u64, &str)] = &[(62, "_llseek"), (222, "mmap2")];

const ARM_EABI: &[(u64, &str)] = &[
    (1, "exit"),
    (3, "read"),
    (4, "write"),
    (5, "open"),
    (6, "close"),
    (10, "unlink"),
    (19, "lseek"),
    (20, "getpid"),
    (33, "access"),
    (37, "kill"),
    (45, "brk"),
    (54, "ioctl"),
    (64, "getppid"),
    (85, "readlink"),
    (91, "munmap"),
    (93, "ftruncate"),
    (122, "uname"),
    (125, "mprotect"),
    (140, "_llseek"),
    (145, "readv"),
    (146, "writev"),
    (174, "rt_sigaction"),
    (175, "rt_sigprocmask"),
    (180, "pread64"),
    (183, "getcwd"),
    (186, "sigaltstack"),
    (191, "ugetrlimit"),
    (192, "mmap2"),
    (195, "stat64"),
    (196, "lstat64"),
    (197, "fstat64"),
    (199, "getuid"),
    (200, "getgid"),
    (201, "geteuid"),
    (202, "getegid"),
    (220, "madvise"),
    (224, "gettid"),
    (238, "tkill"),
    (240, "futex"),
    (248, "exit_group"),
    (256, "set_tid_address"),
    (263, "clock_gettime"),
    (268, "tgkill"),
    (322, "openat"),
    (327, "fstatat64"),
    (328, "unlinkat"),
    (332, "readlinkat"),
    (334, "faccessat"),
    (338, "set_robust_list"),
    (369, "prlimit64"),
    (384, "getrandom"),
    (397, "statx"),
    (398, "rseq"),
    (403, "clock_gettime64"),
    (439, "faccessat2"),
    (0xf0005, "set_tls"),
];

const X86_64: &[(u64, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (16, "ioctl"),
    (17, "pread64"),
    (19, "readv"),
    (20, "writev"),
    (21, "access"),
    (28, "madvise"),
    (39, "getpid"),
    (60, "exit"),
    (62, "kill"),
    (63, "uname"),
    (77, "ftruncate"),
    (79, "getcwd"),
    (87, "unlink"),
    (89, "readlink"),
    (96, "gettimeofday"),
    (97, "getrlimit"),
    (102, "getuid"),
    (104, "getgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (110, "getppid"),
    (131, "sigaltstack"),
    (158, "arch_prctl"),
    (186, "gettid"),
    (200, "tkill"),
    (202, "futex"),
    (218, "set_tid_address"),
    (228, "clock_gettime"),
    (231, "exit_group"),
    (234, "tgkill"),
    (257, "openat"),
    (262, "newfstatat"),
    (263, "unlinkat"),
    (267, "readlinkat"),
    (269, "faccessat"),
    (273, "set_robust_list"),
    (302, "prlimit64"),
    (318, "getrandom"),
    (332, "statx"),
    (334, "rseq"),
    (439, "faccessat2"),
];

const I386: &[(u64, &str)] = &[
    (1, "exit"),
    (3, "read"),
    (4, "write"),
    (5, "open"),
    (6, "close"),
    (10, "unlink"),
    (19, "lseek"),
    (20, "getpid"),
    (33, "access"),
    (37, "kill"),
    (45, "brk"),
    (54, "ioctl"),
    (64, "getppid"),
    (85, "readlink"),
    (91, "munmap"),
    (93, "ftruncate"),
    (122, "uname"),
    (125, "mprotect"),
    (140, "_llseek"),
    (145, "readv"),
    (146, "writev"),
    (174, "rt_sigaction"),
    (175, "rt_sigprocmask"),
    (180, "pread64"),
    (183, "getcwd"),
    (186, "sigaltstack"),
    (191, "ugetrlimit"),
    (192, "mmap2"),
    (195, "stat64"),
    (196, "lstat64"),
    (197, "fstat64"),
    (199, "getuid"),
    (200, "getgid"),
    (201, "geteuid"),
    (202, "getegid"),
    (219, "madvise"),
    (224, "gettid"),
    (238, "tkill"),
    (240, "futex"),
    (243, "set_thread_area"),
    (252, "exit_group"),
    (258, "set_tid_address"),
    (265, "clock_gettime"),
    (270, "tgkill"),
    (295, "openat"),
    (300, "fstatat64"),
    (301, "unlinkat"),
    (305, "readlinkat"),
    (307, "faccessat"),
    (311, "set_robust_list"),
    (340, "prlimit64"),
    (355, "getrandom"),
    (383, "statx"),
    (386, "rseq"),
    (403, "clock_gettime64"),
    (439, "faccessat2"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_name_the_calls_the_corpus_makes() {
        assert_eq!(name(Arch::Riscv32, 64), Some("write"));
        assert_eq!(name(Arch::Riscv32, 94), Some("exit_group"));
        assert_eq!(name(Arch::Riscv32, 222), Some("mmap2"));
        assert_eq!(name(Arch::Riscv64, 222), Some("mmap"));
        assert_eq!(name(Arch::Aarch64, 80), Some("fstat"));
        assert_eq!(name(Arch::Arm, 0xf0005), Some("set_tls"));
        assert_eq!(name(Arch::Arm, 248), Some("exit_group"));
        assert_eq!(name(Arch::X86_64, 158), Some("arch_prctl"));
        assert_eq!(name(Arch::X86, 252), Some("exit_group"));
        assert_eq!(name(Arch::X86_64, 9999), None);
        assert_eq!(describe(Arch::X86_64, 41), "socket");
        assert_eq!(describe(Arch::Aarch64, 220), "clone");
        assert_eq!(describe(Arch::X86_64, 9999), "syscall 9999");
        assert_eq!(describe(Arch::X86_64, 1), "write");
    }

    #[test]
    fn no_table_repeats_a_number() {
        for arch in Arch::ALL {
            let mut nums: Vec<u64> = tables(arch)
                .iter()
                .flat_map(|t| t.iter())
                .map(|(n, _)| *n)
                .collect();
            nums.sort_unstable();
            let before = nums.len();
            nums.dedup();
            assert_eq!(before, nums.len(), "{arch}");
        }
    }
}

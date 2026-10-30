//! Whole-program Linux user-mode emulation: an ELF (static, or dynamic with its loader and
//! libraries from a sysroot) started the way the kernel starts it (segments, initial stack with
//! argv, envp and the auxiliary vector), its system calls answered by this layer.
//!
//! The layer is KRAKEN's own for every architecture (not icicle's Linux layer): one
//! implementation, one confinement story, and no code path that parses a guest's debug
//! information (the guard test next to the crate and the RUSTSEC-2026-0344 note in
//! `deny.toml`). No system call is
//! passed through to the host. File access reaches only the private working directory
//! (read-write) and the optional sysroot (read-only), see [`fs`]. Time and randomness are
//! deterministic, so two runs of the same program on the same input agree byte for byte.

mod fdops;
pub mod fs;
mod isa_marker;
pub mod sysno;

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::error::EmuError;
use crate::loader::{self, PAGE, align_up};
use crate::machine::{ARM_KUSER_PAGE, ARM_TLS_CELL, Machine, Perm, Stop};
use crate::specs::SpecRoots;
use fs::{GUEST_CWD, Node, PROG_NAME, Vfs};

/// Default instruction budget of a run.
pub const DEFAULT_MAX_INSTRUCTIONS: u64 = 2_000_000_000;
/// Default wall-clock limit of a run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Default cap on the output kept per stream.
pub const DEFAULT_OUTPUT_CAP: usize = 1 << 20;
/// Most bytes the guest may write to files of its working directory.
const MAX_FILE_BYTES: u64 = 64 << 20;
/// Most open descriptors.
const MAX_FDS: usize = 256;
/// Largest program file read.
const MAX_PROGRAM_BYTES: u64 = 512 << 20;
/// Most of one written file kept in the outcome.
const FILE_KEEP: usize = 1 << 20;
/// Most files reported.
const MAX_FILES: usize = 64;
/// The process and thread id the guest sees.
const PID: u64 = 1000;
/// The epoch the guest's clock starts at (the corpus's `SOURCE_DATE_EPOCH`).
const EPOCH: u64 = 1_704_067_200;

/// How to run a program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSpec {
    /// The program (ELF).
    pub program: PathBuf,
    /// `argv[0]` (default `prog`, as the native runner names it).
    #[serde(default)]
    pub argv0: Option<String>,
    /// Arguments after `argv[0]`.
    #[serde(default)]
    pub args: Vec<String>,
    /// The complete environment (nothing of the host's is passed).
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Standard input.
    #[serde(default)]
    pub stdin: Vec<u8>,
    /// The private working directory (`/work` in the guest). `None`: a fresh temporary one,
    /// removed afterwards.
    #[serde(default)]
    pub workdir: Option<PathBuf>,
    /// A sysroot with the loader and libraries of a dynamically linked program (read-only).
    #[serde(default)]
    pub sysroot: Option<PathBuf>,
    /// Instruction budget.
    pub max_instructions: u64,
    /// Wall-clock limit in milliseconds.
    pub timeout_ms: u64,
    /// Cap on the output kept per stream.
    pub output_cap: usize,
    /// Spec roots tried before the discovered ones.
    #[serde(default)]
    pub spec_roots: Vec<PathBuf>,
}

impl RunSpec {
    /// A run of `program` with no arguments, empty input and the default limits.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        RunSpec {
            program: program.into(),
            argv0: None,
            args: Vec::new(),
            env: Vec::new(),
            stdin: Vec::new(),
            workdir: None,
            sysroot: None,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            timeout_ms: DEFAULT_TIMEOUT.as_millis() as u64,
            output_cap: DEFAULT_OUTPUT_CAP,
            spec_roots: Vec::new(),
        }
    }
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Exit {
    /// `exit_group(code)` (the low 8 bits, as a parent would see them).
    Code { code: i32 },
    /// A signal ended it: a fault (SIGSEGV, SIGILL, SIGFPE, SIGBUS) or one it sent itself
    /// (`abort` raises SIGABRT).
    Signal { signal: i32, detail: String },
    /// The instruction budget ran out.
    Budget,
    /// The wall-clock limit ran out.
    Timeout,
    /// The guest needed something the emulator does not implement (an instruction's p-code
    /// operation).
    Unsupported { detail: String },
}

impl Exit {
    /// The text in reports.
    pub fn describe(&self) -> String {
        match self {
            Exit::Code { code } => format!("exit {code}"),
            Exit::Signal { signal, detail } => format!("signal {signal} ({detail})"),
            Exit::Budget => "instruction budget exhausted".into(),
            Exit::Timeout => "timeout".into(),
            Exit::Unsupported { detail } => format!("unsupported: {detail}"),
        }
    }
}

/// A file the run left in its working directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenFile {
    /// Path relative to the working directory.
    pub name: String,
    /// Length in bytes.
    pub size: u64,
    /// The contents (at most 1 MiB).
    pub data: Vec<u8>,
}

/// What one run produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramOutcome {
    /// The architecture emulated.
    pub arch: Arch,
    /// How it ended.
    pub exit: Exit,
    /// Standard output (capped).
    pub stdout: Vec<u8>,
    /// Standard error (capped).
    pub stderr: Vec<u8>,
    /// Instructions executed.
    pub instructions: u64,
    /// Wall-clock time of the emulation (not of building the CPU).
    pub elapsed_ms: u64,
    /// Time spent building the CPU (compiling the SLEIGH spec) and loading.
    pub setup_ms: u64,
    /// Files left in the working directory.
    pub files: Vec<WrittenFile>,
    /// System calls made, by name.
    pub syscalls: BTreeMap<String, u64>,
    /// Numbers of system calls the layer does not know (answered `ENOSYS`).
    pub unknown_syscalls: Vec<u64>,
    /// What the emulator changed or assumed to run the program (shown to the user).
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ProgramOutcome {
    /// Instructions per second of the emulation.
    pub fn ips(&self) -> f64 {
        if self.elapsed_ms == 0 {
            return self.instructions as f64 * 1000.0;
        }
        self.instructions as f64 * 1000.0 / self.elapsed_ms as f64
    }
}

/// Where things go in a process's address space.
#[derive(Debug, Clone, Copy)]
struct Layout {
    pie_base: u64,
    interp_base: u64,
    mmap_base: u64,
    mmap_end: u64,
    stack_top: u64,
    stack_size: u64,
}

fn layout(arch: Arch) -> Layout {
    match arch {
        Arch::X86_64 | Arch::Aarch64 => Layout {
            pie_base: 0x5555_5555_0000,
            interp_base: 0x7fff_f7f0_0000,
            mmap_base: 0x7fff_e000_0000,
            mmap_end: 0x7fff_f000_0000,
            stack_top: 0x7fff_ff00_0000,
            stack_size: 8 << 20,
        },
        // Sv39: user addresses below 0x40_0000_0000.
        Arch::Riscv64 => Layout {
            pie_base: 0x2a_aaaa_0000,
            interp_base: 0x3f_f7f0_0000,
            mmap_base: 0x3f_e000_0000,
            mmap_end: 0x3f_f000_0000,
            stack_top: 0x3f_ff00_0000,
            stack_size: 8 << 20,
        },
        Arch::X86 | Arch::Arm | Arch::Riscv32 => Layout {
            pie_base: 0x0040_0000,
            interp_base: 0xb7f0_0000,
            mmap_base: 0x4000_0000,
            mmap_end: 0xb000_0000,
            stack_top: 0xbf00_0000,
            stack_size: 8 << 20,
        },
    }
}

/// An open file description.
#[derive(Debug)]
enum Fd {
    Stdin,
    Stdout,
    Stderr,
    Null,
    Zero,
    Random,
    File {
        file: std::fs::File,
        writable: bool,
        readable: bool,
        append: bool,
        /// Counted against the guest's file quota.
        work: bool,
    },
    Dir {
        path: PathBuf,
        /// The next entry `getdents64` returns (an index into the sorted listing).
        pos: usize,
    },
    /// The read end of an in-process pipe.
    PipeRead {
        buf: fdops::PipeBuf,
        readers: std::sync::Arc<()>,
        writers: std::sync::Weak<()>,
    },
    /// The write end of an in-process pipe.
    PipeWrite {
        buf: fdops::PipeBuf,
        writers: std::sync::Arc<()>,
        readers: std::sync::Weak<()>,
    },
}

/// What belongs to a descriptor rather than to the open file description it names.
#[derive(Debug, Clone, Default)]
struct FdMeta {
    cloexec: bool,
    /// Status flags (`O_NONBLOCK`), shared by the descriptors `dup` made from one another.
    status: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

/// Stat facts, independent of the struct layout.
#[derive(Debug, Clone, Copy, Default)]
struct StatInfo {
    dev: u64,
    ino: u64,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    size: u64,
    blksize: u32,
    blocks: u64,
    mtime: i64,
}

const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

// errno values (the same on every emulated architecture).
const EPERM: u64 = 1;
const ENOENT: u64 = 2;
const EBADF: u64 = 9;
const EAGAIN: u64 = 11;
const ENOMEM: u64 = 12;
const EACCES: u64 = 13;
const EFAULT: u64 = 14;
const EISDIR: u64 = 21;
const EINVAL: u64 = 22;
const EMFILE: u64 = 24;
const ENOTTY: u64 = 25;
const EFBIG: u64 = 27;
const ESPIPE: u64 = 29;
const EROFS: u64 = 30;
const ERANGE: u64 = 34;
const ENOSYS: u64 = 38;
const EEXIST: u64 = 17;
const ENOTDIR: u64 = 20;
const EPIPE: u64 = 32;
const ENOSPC: u64 = 28;

type SysResult = Result<u64, u64>;

/// The system call registers of one architecture.
struct SysRegs {
    nr: &'static str,
    args: [&'static str; 6],
    ret: &'static str,
}

fn sys_regs(arch: Arch) -> SysRegs {
    match arch {
        Arch::X86_64 => SysRegs {
            nr: "RAX",
            args: ["RDI", "RSI", "RDX", "R10", "R8", "R9"],
            ret: "RAX",
        },
        Arch::X86 => SysRegs {
            nr: "EAX",
            args: ["EBX", "ECX", "EDX", "ESI", "EDI", "EBP"],
            ret: "EAX",
        },
        Arch::Arm => SysRegs {
            nr: "r7",
            args: ["r0", "r1", "r2", "r3", "r4", "r5"],
            ret: "r0",
        },
        Arch::Aarch64 => SysRegs {
            nr: "x8",
            args: ["x0", "x1", "x2", "x3", "x4", "x5"],
            ret: "x0",
        },
        Arch::Riscv32 | Arch::Riscv64 => SysRegs {
            nr: "a7",
            args: ["a0", "a1", "a2", "a3", "a4", "a5"],
            ret: "a0",
        },
    }
}

/// The kernel side of one emulated process.
struct Kernel {
    arch: Arch,
    vfs: Vfs,
    fds: Vec<Option<Fd>>,
    /// Parallel to `fds`.
    meta: Vec<FdMeta>,
    /// Virtual time slept away (`nanosleep`, poll timeouts), added to the instruction clock.
    skew_ns: u64,
    dirs_made: u32,
    brk_start: u64,
    brk_cur: u64,
    brk_max: u64,
    mmap_next: u64,
    mmap_end: u64,
    stdin: Vec<u8>,
    stdin_pos: usize,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_cap: usize,
    file_bytes: u64,
    rng: u64,
    syscalls: BTreeMap<String, u64>,
    unknown: Vec<u64>,
    exit: Option<Exit>,
}

/// A started Linux process under emulation: the CPU plus the kernel side. The stepping API
/// drives one of these too.
pub struct LinuxProcess {
    m: Machine,
    k: Kernel,
    regs: SysRegs,
    entry: u64,
    main_bias: u64,
    setup_ms: u64,
    notes: Vec<String>,
    _tmp: Option<tempfile::TempDir>,
}

impl std::fmt::Debug for LinuxProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinuxProcess")
            .field("arch", &self.k.arch)
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

fn read_program(path: &Path) -> Result<Vec<u8>, EmuError> {
    let meta =
        std::fs::metadata(path).map_err(|e| EmuError::Image(format!("{}: {e}", path.display())))?;
    if meta.len() > MAX_PROGRAM_BYTES {
        return Err(EmuError::Image(format!("{} is too large", path.display())));
    }
    std::fs::read(path).map_err(|e| EmuError::Image(format!("{}: {e}", path.display())))
}

/// The `AT_HWCAP` a program sees: what the emulated CPU does (no NEON or SVE: icicle implements
/// few vector helpers, and glibc would pick vector string routines).
fn hwcap(arch: Arch) -> u64 {
    match arch {
        Arch::X86 | Arch::X86_64 => 0x178b_fbff,
        // SWP HALF THUMB FAST_MULT VFP EDSP TLS VFPv3 IDIVA IDIVT VFPD32 LPAE
        Arch::Arm => {
            1 | 2
                | 4
                | 16
                | 64
                | 128
                | (1 << 13)
                | (1 << 15)
                | (1 << 17)
                | (1 << 18)
                | (1 << 19)
                | (1 << 20)
        }
        // FP ASIMD
        Arch::Aarch64 => 0x3,
        // The single-letter extensions I M A F D C.
        Arch::Riscv64 => {
            let l = |c: u8| 1u64 << (c - b'a');
            l(b'i') | l(b'm') | l(b'a') | l(b'f') | l(b'd') | l(b'c')
        }
        Arch::Riscv32 => {
            let l = |c: u8| 1u64 << (c - b'a');
            l(b'i') | l(b'm') | l(b'a') | l(b'c')
        }
    }
}

fn platform(arch: Arch) -> &'static str {
    match arch {
        Arch::X86 => "i686",
        Arch::X86_64 => "x86_64",
        Arch::Arm => "v7l",
        Arch::Aarch64 => "aarch64",
        Arch::Riscv32 => "riscv32",
        Arch::Riscv64 => "riscv64",
    }
}

fn uname_machine(arch: Arch) -> &'static str {
    match arch {
        Arch::X86 => "i686",
        Arch::X86_64 => "x86_64",
        Arch::Arm => "armv7l",
        Arch::Aarch64 => "aarch64",
        Arch::Riscv32 => "riscv32",
        Arch::Riscv64 => "riscv64",
    }
}

impl LinuxProcess {
    /// Loads `spec.program` (and its interpreter from the sysroot), builds the initial stack and
    /// stops before the first instruction.
    pub fn spawn(spec: &RunSpec) -> Result<LinuxProcess, EmuError> {
        let t0 = Instant::now();
        let mut data = read_program(&spec.program)?;
        let notes: Vec<String> = isa_marker::clear_isa_needed(&mut data)
            .into_iter()
            .collect();
        let info = loader::parse_elf(&data)?;
        let arch = info.arch;
        let (workdir, tmp) = match &spec.workdir {
            Some(d) => (d.clone(), None),
            None => {
                let t = tempfile::Builder::new()
                    .prefix("kraken-emu-")
                    .tempdir()
                    .map_err(|e| EmuError::Io(format!("private directory: {e}")))?;
                (t.path().to_path_buf(), Some(t))
            }
        };
        let vfs = Vfs::new(workdir, spec.sysroot.clone(), spec.program.clone());
        let binary = spec
            .program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let interp = match &info.interp {
            None => None,
            Some(path) => {
                let host = match vfs.resolve(path.as_bytes()) {
                    Node::Sys(p) if spec.sysroot.is_some() => p,
                    _ => {
                        return Err(EmuError::NeedsSysroot {
                            binary,
                            interp: path.clone(),
                            arch,
                        });
                    }
                };
                let bytes = read_program(&host)?;
                let i = loader::parse_elf(&bytes)?;
                if i.arch != arch {
                    return Err(EmuError::Image(format!(
                        "the interpreter {path} is for {}, not {arch}",
                        i.arch
                    )));
                }
                Some((bytes, i))
            }
        };

        let specs = SpecRoots::discover_with(spec.spec_roots.iter().cloned());
        let mut m = Machine::new(arch, &specs)?;
        let lay = layout(arch);
        let bias = if info.is_dyn { lay.pie_base } else { 0 };
        let main = loader::map_segments(&mut m, &data, &info, bias)?;
        let mut entry = main.entry;
        let mut interp_base = 0;
        if let Some((bytes, i)) = &interp {
            let lo = i.span().0;
            let ib = lay.interp_base.wrapping_sub(lo);
            let mapped = loader::map_segments(&mut m, bytes, i, ib)?;
            interp_base = mapped.start;
            entry = mapped.entry;
        }
        if arch == Arch::Arm {
            m.map(ARM_KUSER_PAGE, PAGE, Perm::RX)?;
        }
        let brk_start = main.end;
        let k = Kernel {
            arch,
            vfs,
            fds: vec![Some(Fd::Stdin), Some(Fd::Stdout), Some(Fd::Stderr)],
            meta: vec![FdMeta::default(); 3],
            skew_ns: 0,
            dirs_made: 0,
            brk_start,
            brk_cur: brk_start,
            brk_max: brk_start + (256 << 20),
            mmap_next: lay.mmap_base,
            mmap_end: lay.mmap_end,
            stdin: spec.stdin.clone(),
            stdin_pos: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_cap: spec.output_cap,
            file_bytes: 0,
            rng: 0x9e37_79b9_7f4a_7c15,
            syscalls: BTreeMap::new(),
            unknown: Vec::new(),
            exit: None,
        };
        let mut p = LinuxProcess {
            m,
            k,
            regs: sys_regs(arch),
            entry,
            main_bias: bias,
            setup_ms: 0,
            notes,
            _tmp: tmp,
        };
        let argv0 = spec.argv0.clone().unwrap_or_else(|| PROG_NAME.to_string());
        let mut argv = vec![argv0.into_bytes()];
        argv.extend(spec.args.iter().map(|a| a.clone().into_bytes()));
        let mut envp: Vec<Vec<u8>> = spec
            .env
            .iter()
            .map(|(k, v)| format!("{k}={v}").into_bytes())
            .collect();
        // x86-64 glibc's lazy-binding trampoline saves the vector state with FXSAVE, which the
        // CPU model does not implement; binding at start never enters it.
        if arch == Arch::X86_64
            && interp.is_some()
            && !spec.env.iter().any(|(k, _)| k == "LD_BIND_NOW")
        {
            envp.push(b"LD_BIND_NOW=1".to_vec());
            p.notes.push(
                "Set LD_BIND_NOW=1 for the guest: lazy symbol binding uses FXSAVE, which the \
                 emulated CPU cannot execute."
                    .to_string(),
            );
        }
        let auxv_phdr = main.phdr;
        p.build_stack(
            &lay,
            &argv,
            &envp,
            &info,
            auxv_phdr,
            main.entry,
            interp_base,
        )?;
        p.m.set_pc(entry);
        p.setup_ms = t0.elapsed().as_millis() as u64;
        Ok(p)
    }

    /// The CPU.
    pub fn machine(&mut self) -> &mut Machine {
        &mut self.m
    }

    /// The architecture.
    pub fn arch(&self) -> Arch {
        self.k.arch
    }

    /// The load bias of the main program (0 for a fixed-address executable).
    pub fn main_bias(&self) -> u64 {
        self.main_bias
    }

    /// How the process ended, once it has.
    pub fn exit(&self) -> Option<&Exit> {
        self.k.exit.as_ref()
    }

    /// Standard output so far.
    pub fn stdout(&self) -> &[u8] {
        &self.k.stdout
    }

    /// Standard error so far.
    pub fn stderr(&self) -> &[u8] {
        &self.k.stderr
    }

    /// Drops output beyond these lengths (a restored snapshot).
    pub fn truncate_output(&mut self, stdout: usize, stderr: usize) {
        self.k.stdout.truncate(stdout);
        self.k.stderr.truncate(stderr);
        self.k.exit = None;
    }

    #[allow(clippy::too_many_arguments)]
    fn build_stack(
        &mut self,
        lay: &Layout,
        argv: &[Vec<u8>],
        envp: &[Vec<u8>],
        info: &loader::ElfInfo,
        phdr: u64,
        prog_entry: u64,
        interp_base: u64,
    ) -> Result<(), EmuError> {
        let arch = self.k.arch;
        let ps = arch.ptr_size() as u64;
        let bottom = lay.stack_top - lay.stack_size;
        self.m.map(bottom, lay.stack_size, Perm::RW)?;
        let mut sp = lay.stack_top - 16;
        let push_bytes = |m: &mut Machine, sp: &mut u64, b: &[u8]| -> Result<u64, EmuError> {
            *sp -= b.len() as u64 + 1;
            m.write_mem(*sp, b)?;
            m.write_mem(*sp + b.len() as u64, &[0])?;
            Ok(*sp)
        };
        let execfn = push_bytes(
            &mut self.m,
            &mut sp,
            format!("{GUEST_CWD}/{PROG_NAME}").as_bytes(),
        )?;
        let mut env_ptrs = Vec::new();
        for e in envp.iter().rev() {
            env_ptrs.push(push_bytes(&mut self.m, &mut sp, e)?);
        }
        env_ptrs.reverse();
        let mut arg_ptrs = Vec::new();
        for a in argv.iter().rev() {
            arg_ptrs.push(push_bytes(&mut self.m, &mut sp, a)?);
        }
        arg_ptrs.reverse();
        let plat = push_bytes(&mut self.m, &mut sp, platform(arch).as_bytes())?;
        sp &= !15;
        sp -= 16;
        let random = sp;
        let rand: Vec<u8> = (0..16).map(|_| self.k.next_random()).collect();
        self.m.write_mem(random, &rand)?;
        let auxv: Vec<(u64, u64)> = vec![
            (3, phdr),
            (4, info.phentsize),
            (5, info.phnum),
            (6, PAGE),
            (7, interp_base),
            (8, 0),
            (9, prog_entry),
            (11, PID),
            (12, PID),
            (13, PID),
            (14, PID),
            (16, hwcap(arch)),
            (17, 100),
            (15, plat),
            (23, 0),
            (25, random),
            (26, 0),
            (31, execfn),
            (0, 0),
        ];
        let words = 1 + arg_ptrs.len() + 1 + env_ptrs.len() + 1 + auxv.len() * 2;
        sp -= words as u64 * ps;
        sp &= !15;
        let mut at = sp;
        let mut put = |m: &mut Machine, v: u64| -> Result<(), EmuError> {
            m.write_uint(at, ps as usize, v)?;
            at += ps;
            Ok(())
        };
        put(&mut self.m, argv.len() as u64)?;
        for a in &arg_ptrs {
            put(&mut self.m, *a)?;
        }
        put(&mut self.m, 0)?;
        for e in &env_ptrs {
            put(&mut self.m, *e)?;
        }
        put(&mut self.m, 0)?;
        for (k, v) in auxv {
            put(&mut self.m, k)?;
            put(&mut self.m, v)?;
        }
        self.m.set_sp(sp);
        Ok(())
    }

    fn arg(&mut self, i: usize) -> u64 {
        let mask = self.k.arch.ptr_mask();
        self.m.read_reg(self.regs.args[i]).unwrap_or(0) & mask
    }

    /// A 64-bit argument that 32-bit ABIs pass in two registers starting at `lo` (`lo`, `lo+1`);
    /// 64-bit ABIs pass it in `lo64`.
    fn arg64(&mut self, lo64: usize, lo32: usize) -> u64 {
        if self.k.arch.bits() == 64 {
            self.arg(lo64)
        } else {
            self.arg(lo32) | (self.arg(lo32 + 1) << 32)
        }
    }

    /// Answers the system call the CPU stopped at and moves past it. Returns how the process
    /// ended when the call ended it.
    pub fn handle_syscall(&mut self) -> Option<Exit> {
        let nr = self.m.read_reg(self.regs.nr).unwrap_or(u64::MAX);
        let arch = self.k.arch;
        let name = sysno::name(arch, nr);
        *self
            .k
            .syscalls
            .entry(name.map_or_else(|| format!("#{nr}"), str::to_string))
            .or_insert(0) += 1;
        let result = match name {
            Some(n) => self.dispatch(n),
            None => {
                if !self.k.unknown.contains(&nr) && self.k.unknown.len() < 64 {
                    self.k.unknown.push(nr);
                }
                Err(ENOSYS)
            }
        };
        if let Some(e) = &self.k.exit {
            return Some(e.clone());
        }
        let v = match result {
            Ok(v) => v,
            Err(errno) => errno.wrapping_neg(),
        };
        let mask = arch.ptr_mask();
        let _ = self.m.write_reg(self.regs.ret, v & mask);
        self.m.resume_after_syscall();
        None
    }

    fn dispatch(&mut self, name: &str) -> SysResult {
        const AT_FDCWD: u64 = (-100i64) as u64;
        let arch = self.k.arch;
        let mask = arch.ptr_mask();
        let at_fdcwd = AT_FDCWD & mask;
        match name {
            "exit" | "exit_group" => {
                let code = (self.arg(0) & 0xff) as i32;
                self.k.exit = Some(Exit::Code { code });
                Ok(0)
            }
            "read" => {
                let (fd, buf, n) = (self.arg(0), self.arg(1), self.arg(2));
                self.sys_read(fd, buf, n, None)
            }
            "pread64" => {
                let (fd, buf, n) = (self.arg(0), self.arg(1), self.arg(2));
                let off = match arch {
                    Arch::Arm => self.arg64(3, 4),
                    _ => self.arg64(3, 3),
                };
                self.sys_read(fd, buf, n, Some(off))
            }
            "write" => {
                let (fd, buf, n) = (self.arg(0), self.arg(1), self.arg(2));
                self.sys_write(fd, buf, n)
            }
            "readv" | "writev" => {
                let (fd, iov, cnt) = (self.arg(0), self.arg(1), self.arg(2));
                if cnt > 1024 {
                    return Err(EINVAL);
                }
                let ps = arch.ptr_size() as u64;
                let mut total = 0u64;
                for i in 0..cnt {
                    let base = self.m.read_ptr(iov + i * 2 * ps).map_err(|_| EFAULT)?;
                    let len = self.m.read_ptr(iov + i * 2 * ps + ps).map_err(|_| EFAULT)?;
                    let r = if name == "readv" {
                        self.sys_read(fd, base, len, None)
                    } else {
                        self.sys_write(fd, base, len)
                    };
                    match r {
                        Ok(n) => {
                            total += n;
                            if n < len {
                                break;
                            }
                        }
                        Err(e) if total == 0 => return Err(e),
                        Err(_) => break,
                    }
                }
                Ok(total)
            }
            "open" => {
                let (path, flags) = (self.arg(0), self.arg(1));
                let fd = self.sys_open(path, flags)?;
                self.apply_open_flags(fd, flags);
                Ok(fd)
            }
            "openat" => {
                let (dirfd, path, flags) = (self.arg(0), self.arg(1), self.arg(2));
                self.check_dirfd(dirfd, at_fdcwd, path)?;
                let fd = self.sys_open(path, flags)?;
                self.apply_open_flags(fd, flags);
                Ok(fd)
            }
            "close" => {
                let fd = self.arg(0) as usize;
                match self.k.fds.get_mut(fd) {
                    Some(slot @ Some(_)) => {
                        *slot = None;
                        self.k.meta[fd] = FdMeta::default();
                        Ok(0)
                    }
                    _ => Err(EBADF),
                }
            }
            "lseek" => {
                let (fd, off, whence) = (self.arg(0), self.arg(1), self.arg(2));
                let off = if arch.bits() == 32 {
                    off as u32 as i32 as i64
                } else {
                    off as i64
                };
                self.sys_lseek(fd, off, whence)
            }
            "_llseek" => {
                let (fd, hi, lo, res, whence) = (
                    self.arg(0),
                    self.arg(1),
                    self.arg(2),
                    self.arg(3),
                    self.arg(4),
                );
                let off = ((hi << 32) | (lo & 0xffff_ffff)) as i64;
                let pos = self.sys_lseek(fd, off, whence)?;
                self.m.write_uint(res, 8, pos).map_err(|_| EFAULT)?;
                Ok(0)
            }
            "fstat" | "fstat64" => {
                let (fd, buf) = (self.arg(0), self.arg(1));
                let st = self.stat_fd(fd)?;
                self.write_stat(buf, &st, name)
            }
            "stat" | "lstat" | "stat64" | "lstat64" => {
                let (path, buf) = (self.arg(0), self.arg(1));
                let st = self.stat_path(path)?;
                self.write_stat(buf, &st, name)
            }
            "newfstatat" | "fstatat64" => {
                let (dirfd, path, buf, flags) =
                    (self.arg(0), self.arg(1), self.arg(2), self.arg(3));
                let st = self.stat_at(dirfd, path, flags, at_fdcwd)?;
                self.write_stat(buf, &st, name)
            }
            "statx" => {
                let (dirfd, path, flags, _mask, buf) = (
                    self.arg(0),
                    self.arg(1),
                    self.arg(2),
                    self.arg(3),
                    self.arg(4),
                );
                let st = self.stat_at(dirfd, path, flags, at_fdcwd)?;
                self.write_stat(buf, &st, "statx")
            }
            "access" => {
                let path = self.arg(0);
                self.sys_access(path)
            }
            "faccessat" | "faccessat2" => {
                let (dirfd, path) = (self.arg(0), self.arg(1));
                self.check_dirfd(dirfd, at_fdcwd, path)?;
                self.sys_access(path)
            }
            "readlink" => {
                let (path, buf, n) = (self.arg(0), self.arg(1), self.arg(2));
                self.sys_readlink(path, buf, n)
            }
            "readlinkat" => {
                let (_dirfd, path, buf, n) = (self.arg(0), self.arg(1), self.arg(2), self.arg(3));
                self.sys_readlink(path, buf, n)
            }
            "unlink" => {
                let path = self.arg(0);
                self.sys_unlink(path)
            }
            "unlinkat" => {
                let (dirfd, path) = (self.arg(0), self.arg(1));
                self.check_dirfd(dirfd, at_fdcwd, path)?;
                self.sys_unlink(path)
            }
            "ftruncate" => {
                let fd = self.arg(0) as usize;
                let len = self.arg64(1, if arch == Arch::Arm { 2 } else { 1 });
                match self.k.fds.get_mut(fd) {
                    Some(Some(Fd::File {
                        file,
                        writable: true,
                        ..
                    })) => {
                        if len > MAX_FILE_BYTES {
                            return Err(EFBIG);
                        }
                        file.set_len(len).map_err(|_| EINVAL)?;
                        Ok(0)
                    }
                    Some(Some(_)) => Err(EINVAL),
                    _ => Err(EBADF),
                }
            }
            "getcwd" => {
                let (buf, n) = (self.arg(0), self.arg(1));
                let mut s = GUEST_CWD.as_bytes().to_vec();
                s.push(0);
                if (n as usize) < s.len() {
                    return Err(ERANGE);
                }
                if !self.m.guest_write(buf, &s) {
                    return Err(EFAULT);
                }
                Ok(s.len() as u64)
            }
            "ioctl" => {
                let fd = self.arg(0) as usize;
                match self.k.fds.get(fd) {
                    Some(Some(_)) => Err(ENOTTY),
                    _ => Err(EBADF),
                }
            }
            "brk" => {
                let want = self.arg(0);
                Ok(self.sys_brk(want))
            }
            "mmap" => {
                let a: [u64; 6] = std::array::from_fn(|i| self.arg(i));
                self.sys_mmap(a[0], a[1], a[2], a[3], a[4], a[5])
            }
            "mmap2" => {
                let a: [u64; 6] = std::array::from_fn(|i| self.arg(i));
                self.sys_mmap(a[0], a[1], a[2], a[3], a[4], a[5] * PAGE)
            }
            "munmap" => {
                let (addr, len) = (self.arg(0), self.arg(1));
                if !addr.is_multiple_of(PAGE) {
                    return Err(EINVAL);
                }
                let len = align_up(len).ok_or(EINVAL)?;
                self.m.unmap(addr, len);
                Ok(0)
            }
            "mprotect" => {
                let (addr, len, prot) = (self.arg(0), self.arg(1), self.arg(2));
                if !addr.is_multiple_of(PAGE) {
                    return Err(EINVAL);
                }
                let len = align_up(len).ok_or(EINVAL)?;
                self.m
                    .protect(addr, len, Perm::from_prot(prot))
                    .map(|_| 0)
                    .map_err(|_| ENOMEM)
            }
            "madvise" => Ok(0),
            "set_tid_address" => Ok(PID),
            "set_robust_list" => Ok(0),
            "rseq" | "riscv_hwprobe" => Err(ENOSYS),
            "futex" => {
                let op = self.arg(1) & 0x7f;
                match op {
                    // FUTEX_WAKE
                    1 => Ok(0),
                    // FUTEX_WAIT with one thread would block forever.
                    _ => Err(EAGAIN),
                }
            }
            "rt_sigaction" => {
                let old = self.arg(2);
                if old != 0 {
                    let size = if arch.bits() == 64 { 32 } else { 20 };
                    if !self.m.guest_write(old, &vec![0u8; size]) {
                        return Err(EFAULT);
                    }
                }
                Ok(0)
            }
            "rt_sigprocmask" => {
                let old = self.arg(2);
                if old != 0 && !self.m.guest_write(old, &[0u8; 8]) {
                    return Err(EFAULT);
                }
                Ok(0)
            }
            "sigaltstack" => Ok(0),
            "getpid" | "gettid" => Ok(PID),
            "getppid" => Ok(1),
            "getuid" | "geteuid" | "getgid" | "getegid" => Ok(PID),
            "kill" | "tkill" | "tgkill" => {
                let sig = match name {
                    "tgkill" => self.arg(2),
                    _ => self.arg(1),
                };
                if sig == 0 {
                    return Ok(0);
                }
                self.k.exit = Some(Exit::Signal {
                    signal: sig as i32,
                    detail: format!("raised by the program ({name})"),
                });
                Ok(0)
            }
            "uname" => {
                let buf = self.arg(0);
                let mut u = vec![0u8; 65 * 6];
                for (i, f) in [
                    "Linux",
                    "kraken",
                    "6.12.0",
                    "#1 SMP KRAKEN emulation",
                    uname_machine(arch),
                    "(none)",
                ]
                .iter()
                .enumerate()
                {
                    u[i * 65..i * 65 + f.len()].copy_from_slice(f.as_bytes());
                }
                if !self.m.guest_write(buf, &u) {
                    return Err(EFAULT);
                }
                Ok(0)
            }
            "prlimit64" => {
                let (resource, old) = (self.arg(1), self.arg(3));
                if old != 0 {
                    let (cur, max) = rlimit(resource);
                    let mut b = cur.to_le_bytes().to_vec();
                    b.extend_from_slice(&max.to_le_bytes());
                    if !self.m.guest_write(old, &b) {
                        return Err(EFAULT);
                    }
                }
                Ok(0)
            }
            "getrlimit" | "ugetrlimit" => {
                let (resource, old) = (self.arg(0), self.arg(1));
                let (cur, max) = rlimit(resource);
                let ps = arch.ptr_size();
                let mut b = (cur & mask).to_le_bytes()[..ps].to_vec();
                b.extend_from_slice(&(max & mask).to_le_bytes()[..ps]);
                if !self.m.guest_write(old, &b) {
                    return Err(EFAULT);
                }
                Ok(0)
            }
            "getrandom" => {
                let (buf, n) = (self.arg(0), self.arg(1));
                let n = n.min(1 << 20);
                let bytes: Vec<u8> = (0..n).map(|_| self.k.next_random()).collect();
                if !self.m.guest_write(buf, &bytes) {
                    return Err(EFAULT);
                }
                Ok(n)
            }
            "clock_gettime" | "clock_gettime64" | "gettimeofday" => {
                let ts = if name == "gettimeofday" {
                    self.arg(0)
                } else {
                    self.arg(1)
                };
                if ts == 0 {
                    return Ok(0);
                }
                let ns = self.now_ns();
                let (sec, sub) = (EPOCH + ns / 1_000_000_000, ns % 1_000_000_000);
                let sub = if name == "gettimeofday" {
                    sub / 1000
                } else {
                    sub
                };
                let b = if name == "clock_gettime64" || arch.bits() == 64 {
                    [sec.to_le_bytes(), sub.to_le_bytes()].concat()
                } else {
                    [(sec as u32).to_le_bytes(), (sub as u32).to_le_bytes()].concat()
                };
                if !self.m.guest_write(ts, &b) {
                    return Err(EFAULT);
                }
                Ok(0)
            }
            "arch_prctl" => {
                const ARCH_SET_FS: u64 = 0x1002;
                const ARCH_GET_FS: u64 = 0x1003;
                let (code, addr) = (self.arg(0), self.arg(1));
                match code {
                    ARCH_SET_FS => {
                        self.m.write_reg("FS_OFFSET", addr).map_err(|_| EINVAL)?;
                        Ok(0)
                    }
                    ARCH_GET_FS => {
                        let fs = self.m.read_reg("FS_OFFSET").map_err(|_| EINVAL)?;
                        self.m.write_uint(addr, 8, fs).map_err(|_| EFAULT)?;
                        Ok(0)
                    }
                    _ => Err(EINVAL),
                }
            }
            "set_thread_area" => {
                // i386: user_desc { entry_number, base_addr, limit, flags }.
                let desc = self.arg(0);
                let entry = self.m.read_uint(desc, 4).map_err(|_| EFAULT)?;
                let base = self.m.read_uint(desc + 4, 4).map_err(|_| EFAULT)?;
                if entry == 0xffff_ffff {
                    self.m.write_uint(desc, 4, 12).map_err(|_| EFAULT)?;
                }
                self.m.write_reg("GS_OFFSET", base).map_err(|_| EINVAL)?;
                Ok(0)
            }
            "set_tls" => {
                let v = self.arg(0);
                self.m.write_uint(ARM_TLS_CELL, 4, v).map_err(|_| EFAULT)?;
                Ok(0)
            }
            "dup"
            | "dup2"
            | "dup3"
            | "fcntl"
            | "fcntl64"
            | "pipe"
            | "pipe2"
            | "getdents64"
            | "mkdir"
            | "mkdirat"
            | "rename"
            | "renameat"
            | "renameat2"
            | "nanosleep"
            | "clock_nanosleep"
            | "clock_nanosleep_time64"
            | "poll"
            | "ppoll"
            | "ppoll_time64"
            | "sched_yield" => self.dispatch_fd(name, at_fdcwd),
            _ => Err(ENOSYS),
        }
    }

    fn check_dirfd(&mut self, dirfd: u64, at_fdcwd: u64, path: u64) -> Result<(), u64> {
        if dirfd == at_fdcwd {
            return Ok(());
        }
        // A relative path against another directory descriptor is not modelled; absolute paths
        // ignore the descriptor.
        let p = self.read_path(path)?;
        if p.first() == Some(&b'/') {
            Ok(())
        } else {
            Err(EBADF)
        }
    }

    fn read_path(&mut self, addr: u64) -> Result<Vec<u8>, u64> {
        self.m.read_cstr(addr, 4096).ok_or(EFAULT)
    }

    fn alloc_fd(&mut self, fd: Fd) -> SysResult {
        self.alloc_fd_from(0, fd, FdMeta::default())
    }

    fn sys_open(&mut self, path: u64, flags: u64) -> SysResult {
        const O_ACCMODE: u64 = 3;
        const O_CREAT: u64 = 0o100;
        const O_EXCL: u64 = 0o200;
        const O_TRUNC: u64 = 0o1000;
        const O_APPEND: u64 = 0o2000;
        let p = self.read_path(path)?;
        let acc = flags & O_ACCMODE;
        let (readable, writable) = (acc != 1, acc != 0);
        let wants_write = writable || flags & (O_CREAT | O_TRUNC) != 0;
        match self.k.vfs.resolve(&p) {
            Node::Null => self.alloc_fd(Fd::Null),
            Node::Zero => self.alloc_fd(Fd::Zero),
            Node::Random => self.alloc_fd(Fd::Random),
            Node::Missing => Err(if wants_write { EROFS } else { ENOENT }),
            Node::Dir(d) => {
                if writable {
                    Err(EISDIR)
                } else {
                    self.alloc_fd(Fd::Dir { path: d, pos: 0 })
                }
            }
            Node::Prog | Node::Sys(_) if wants_write => Err(EROFS),
            Node::Prog => {
                let file = std::fs::File::open(self.k.vfs.program()).map_err(|_| EACCES)?;
                self.alloc_fd(Fd::File {
                    file,
                    writable: false,
                    readable: true,
                    append: false,
                    work: false,
                })
            }
            Node::Sys(host) => {
                let file = open_nofollow(&host, false, false, false, false).map_err(io_errno)?;
                self.alloc_fd(Fd::File {
                    file,
                    writable: false,
                    readable: true,
                    append: false,
                    work: false,
                })
            }
            Node::Work(host) => {
                let file = open_nofollow(
                    &host,
                    writable,
                    flags & O_CREAT != 0,
                    flags & O_EXCL != 0,
                    flags & O_TRUNC != 0,
                )
                .map_err(io_errno)?;
                if file.metadata().map(|m| m.is_dir()).unwrap_or(false) {
                    return if writable {
                        Err(EISDIR)
                    } else {
                        self.alloc_fd(Fd::Dir { path: host, pos: 0 })
                    };
                }
                self.alloc_fd(Fd::File {
                    file,
                    writable,
                    readable,
                    append: flags & O_APPEND != 0,
                    work: true,
                })
            }
        }
    }

    fn sys_read(&mut self, fd: u64, buf: u64, n: u64, at: Option<u64>) -> SysResult {
        let n = n.min(1 << 24) as usize;
        let data: Vec<u8> = match self.k.fds.get_mut(fd as usize) {
            Some(Some(Fd::Stdin)) => {
                if at.is_some() {
                    return Err(ESPIPE);
                }
                let rest = &self.k.stdin[self.k.stdin_pos..];
                let take = rest.len().min(n);
                let d = rest[..take].to_vec();
                self.k.stdin_pos += take;
                d
            }
            Some(Some(Fd::Null)) => Vec::new(),
            Some(Some(Fd::Zero)) => vec![0u8; n],
            Some(Some(Fd::Random)) => {
                let mut d = vec![0u8; n];
                for b in &mut d {
                    *b = self.k.next_random();
                }
                d
            }
            Some(Some(Fd::File {
                file,
                readable: true,
                ..
            })) => {
                let mut d = vec![0u8; n];
                let got = match at {
                    Some(off) => read_at(file, &mut d, off).map_err(io_errno)?,
                    None => file.read(&mut d).map_err(io_errno)?,
                };
                d.truncate(got);
                d
            }
            Some(Some(Fd::Dir { .. })) => return Err(EISDIR),
            Some(Some(Fd::PipeRead { .. })) => return self.pipe_read(fd, buf, n),
            Some(Some(_)) => return Err(EBADF),
            _ => return Err(EBADF),
        };
        if !data.is_empty() && !self.m.guest_write(buf, &data) {
            return Err(EFAULT);
        }
        Ok(data.len() as u64)
    }

    fn sys_write(&mut self, fd: u64, buf: u64, n: u64) -> SysResult {
        let n = n.min(1 << 24) as usize;
        let mut data = vec![0u8; n];
        if n > 0 && !self.m.guest_read(buf, &mut data) {
            return Err(EFAULT);
        }
        let cap = self.k.output_cap;
        match self.k.fds.get_mut(fd as usize) {
            Some(Some(Fd::Stdout)) => {
                let room = cap.saturating_sub(self.k.stdout.len());
                self.k.stdout.extend_from_slice(&data[..room.min(n)]);
                Ok(n as u64)
            }
            Some(Some(Fd::Stderr)) => {
                let room = cap.saturating_sub(self.k.stderr.len());
                self.k.stderr.extend_from_slice(&data[..room.min(n)]);
                Ok(n as u64)
            }
            Some(Some(Fd::Null | Fd::Zero | Fd::Random)) => Ok(n as u64),
            Some(Some(Fd::File {
                file,
                writable: true,
                append,
                work,
                ..
            })) => {
                if *work {
                    if self.k.file_bytes + n as u64 > MAX_FILE_BYTES {
                        return Err(EFBIG);
                    }
                    self.k.file_bytes += n as u64;
                }
                if *append {
                    file.seek(SeekFrom::End(0)).map_err(io_errno)?;
                }
                file.write_all(&data).map_err(io_errno)?;
                Ok(n as u64)
            }
            Some(Some(Fd::PipeWrite { .. })) => self.pipe_write(fd, &data),
            Some(Some(_)) => Err(EBADF),
            _ => Err(EBADF),
        }
    }

    fn sys_lseek(&mut self, fd: u64, off: i64, whence: u64) -> SysResult {
        match self.k.fds.get_mut(fd as usize) {
            Some(Some(Fd::File { file, .. })) => {
                let pos = match whence {
                    0 => SeekFrom::Start(u64::try_from(off).map_err(|_| EINVAL)?),
                    1 => SeekFrom::Current(off),
                    2 => SeekFrom::End(off),
                    _ => return Err(EINVAL),
                };
                file.seek(pos).map_err(|_| EINVAL)
            }
            Some(Some(Fd::Null | Fd::Zero | Fd::Random)) => Ok(0),
            Some(Some(Fd::Dir { pos, .. })) => match (whence, usize::try_from(off)) {
                (0, Ok(o)) => {
                    *pos = o;
                    Ok(o as u64)
                }
                _ => Err(EINVAL),
            },
            Some(Some(_)) => Err(ESPIPE),
            _ => Err(EBADF),
        }
    }

    fn sys_access(&mut self, path: u64) -> SysResult {
        let p = self.read_path(path)?;
        match self.k.vfs.resolve(&p) {
            Node::Missing => Err(ENOENT),
            Node::Work(h) => {
                if h.exists() {
                    Ok(0)
                } else {
                    Err(ENOENT)
                }
            }
            _ => Ok(0),
        }
    }

    fn sys_readlink(&mut self, path: u64, buf: u64, n: u64) -> SysResult {
        let p = self.read_path(path)?;
        if p == b"/proc/self/exe" {
            let target = format!("{GUEST_CWD}/{PROG_NAME}").into_bytes();
            let take = target.len().min(n as usize);
            if !self.m.guest_write(buf, &target[..take]) {
                return Err(EFAULT);
            }
            return Ok(take as u64);
        }
        match self.k.vfs.resolve(&p) {
            Node::Missing => Err(ENOENT),
            _ => Err(EINVAL),
        }
    }

    fn sys_unlink(&mut self, path: u64) -> SysResult {
        let p = self.read_path(path)?;
        match self.k.vfs.resolve(&p) {
            Node::Work(h) => match std::fs::symlink_metadata(&h) {
                Ok(m) if m.is_file() => std::fs::remove_file(&h).map(|_| 0).map_err(io_errno),
                Ok(_) => Err(EISDIR),
                Err(_) => Err(ENOENT),
            },
            Node::Missing => Err(ENOENT),
            _ => Err(EROFS),
        }
    }

    fn sys_brk(&mut self, want: u64) -> u64 {
        let k = &mut self.k;
        if want < k.brk_start || want > k.brk_max {
            return k.brk_cur;
        }
        let (old_end, new_end) = (
            align_up(k.brk_cur).unwrap_or(k.brk_cur),
            align_up(want).unwrap_or(want),
        );
        if new_end > old_end {
            if self.m.map(old_end, new_end - old_end, Perm::RW).is_err() {
                return k.brk_cur;
            }
        } else if new_end < old_end {
            self.m.unmap(new_end, old_end - new_end);
        }
        k.brk_cur = want;
        want
    }

    fn sys_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        off: u64,
    ) -> SysResult {
        const MAP_FIXED: u64 = 0x10;
        const MAP_ANONYMOUS: u64 = 0x20;
        const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
        if len == 0 {
            return Err(EINVAL);
        }
        let len = align_up(len).ok_or(ENOMEM)?;
        if len > 1 << 30 {
            return Err(ENOMEM);
        }
        let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
        let at = if fixed {
            if !addr.is_multiple_of(PAGE) {
                return Err(EINVAL);
            }
            self.m.unmap(addr, len);
            addr
        } else {
            let a = self.k.mmap_next;
            if a + len > self.k.mmap_end {
                return Err(ENOMEM);
            }
            // A guard page between mappings.
            self.k.mmap_next = a + len + PAGE;
            a
        };
        let perm = Perm::from_prot(prot);
        self.m.map(at, len, perm).map_err(|_| ENOMEM)?;
        if flags & MAP_ANONYMOUS == 0 {
            let fd = fd & self.k.arch.ptr_mask();
            let data = match self.k.fds.get_mut(fd as usize) {
                Some(Some(Fd::File { file, .. })) => {
                    let mut d = vec![0u8; len as usize];
                    let mut got = 0;
                    while got < d.len() {
                        match read_at(file, &mut d[got..], off + got as u64) {
                            Ok(0) => break,
                            Ok(k) => got += k,
                            Err(_) => break,
                        }
                    }
                    d.truncate(got);
                    d
                }
                Some(Some(Fd::Zero | Fd::Null)) => Vec::new(),
                _ => {
                    self.m.unmap(at, len);
                    return Err(EBADF);
                }
            };
            self.m.write_mem(at, &data).map_err(|_| EFAULT)?;
        }
        Ok(at)
    }

    fn stat_fd(&mut self, fd: u64) -> Result<StatInfo, u64> {
        let fifo = StatInfo {
            mode: S_IFIFO | 0o600,
            nlink: 1,
            uid: PID as u32,
            gid: PID as u32,
            blksize: 4096,
            mtime: EPOCH as i64,
            dev: 0xc,
            ino: 100 + fd,
            ..StatInfo::default()
        };
        match self.k.fds.get(fd as usize) {
            Some(Some(
                Fd::Stdin | Fd::Stdout | Fd::Stderr | Fd::PipeRead { .. } | Fd::PipeWrite { .. },
            )) => Ok(fifo),
            Some(Some(Fd::Null | Fd::Zero | Fd::Random)) => Ok(StatInfo {
                mode: S_IFCHR | 0o666,
                rdev: 0x103,
                dev: 5,
                ..fifo
            }),
            Some(Some(Fd::File { file, .. })) => {
                let m = file.metadata().map_err(io_errno)?;
                Ok(host_stat(&m))
            }
            Some(Some(Fd::Dir { path: p, .. })) => {
                let m = std::fs::metadata(p).map_err(io_errno)?;
                Ok(host_stat(&m))
            }
            _ => Err(EBADF),
        }
    }

    fn stat_path(&mut self, path: u64) -> Result<StatInfo, u64> {
        let p = self.read_path(path)?;
        let host = match self.k.vfs.resolve(&p) {
            Node::Missing => return Err(ENOENT),
            Node::Null | Node::Zero | Node::Random => {
                return Ok(StatInfo {
                    mode: S_IFCHR | 0o666,
                    rdev: 0x103,
                    dev: 5,
                    nlink: 1,
                    blksize: 4096,
                    ..StatInfo::default()
                });
            }
            Node::Prog => self.k.vfs.program().to_path_buf(),
            Node::Work(h) | Node::Sys(h) | Node::Dir(h) => h,
        };
        let m = std::fs::metadata(&host).map_err(io_errno)?;
        Ok(host_stat(&m))
    }

    fn stat_at(
        &mut self,
        dirfd: u64,
        path: u64,
        flags: u64,
        at_fdcwd: u64,
    ) -> Result<StatInfo, u64> {
        const AT_EMPTY_PATH: u64 = 0x1000;
        if flags & AT_EMPTY_PATH != 0 {
            let p = self.read_path(path).unwrap_or_default();
            if p.is_empty() {
                return self.stat_fd(dirfd);
            }
        }
        self.check_dirfd(dirfd, at_fdcwd, path)?;
        self.stat_path(path)
    }

    fn write_stat(&mut self, buf: u64, st: &StatInfo, call: &str) -> SysResult {
        let b = stat_bytes(self.k.arch, st, call);
        if !self.m.guest_write(buf, &b) {
            return Err(EFAULT);
        }
        Ok(0)
    }

    /// Runs until the process ends, the budget or the deadline is reached. Breakpoints stop the
    /// run with `Ok(None)` and the stop.
    pub fn run_to_end(&mut self, max_instructions: u64, timeout: Duration) -> Exit {
        let deadline = Instant::now() + timeout;
        let start = self.m.icount();
        loop {
            if let Some(e) = &self.k.exit {
                return e.clone();
            }
            let used = self.m.icount() - start;
            if used >= max_instructions {
                return Exit::Budget;
            }
            if Instant::now() >= deadline {
                return Exit::Timeout;
            }
            let chunk = (max_instructions - used).min(4_000_000);
            match self.m.run(chunk) {
                Stop::Syscall => {
                    if let Some(e) = self.handle_syscall() {
                        return e;
                    }
                }
                Stop::Budget | Stop::Breakpoint { .. } | Stop::Interrupted => {}
                Stop::Halt => {
                    return Exit::Signal {
                        signal: 11,
                        detail: format!("halt instruction at {:#x}", self.m.pc()),
                    };
                }
                Stop::Fault { detail, pc } => return fault_exit(&detail, pc),
            }
        }
    }

    /// The outcome so far (stdout, stderr, files, counters) with `exit`.
    pub fn outcome(&self, exit: Exit, elapsed: Duration, instructions: u64) -> ProgramOutcome {
        ProgramOutcome {
            arch: self.k.arch,
            exit,
            stdout: self.k.stdout.clone(),
            stderr: self.k.stderr.clone(),
            instructions,
            elapsed_ms: elapsed.as_millis() as u64,
            setup_ms: self.setup_ms,
            files: written_files(self.k.vfs.workdir()),
            syscalls: self.k.syscalls.clone(),
            unknown_syscalls: self.k.unknown.clone(),
            notes: self.notes.clone(),
        }
    }
}

/// The signal a CPU fault becomes.
pub(crate) fn fault_exit(detail: &str, pc: u64) -> Exit {
    let signal = if detail.starts_with("UnimplementedOp") {
        return Exit::Unsupported {
            detail: format!("{detail} at pc {pc:#x}"),
        };
    } else if detail.starts_with("InvalidInstruction") {
        4
    } else if detail.starts_with("DivisionException") {
        8
    } else if detail.contains("Unaligned") {
        7
    } else {
        11
    };
    Exit::Signal {
        signal,
        detail: format!("{detail} at pc {pc:#x}"),
    }
}

fn rlimit(resource: u64) -> (u64, u64) {
    const INF: u64 = u64::MAX;
    match resource {
        // RLIMIT_STACK
        3 => (8 << 20, INF),
        // RLIMIT_NOFILE
        7 => (MAX_FDS as u64, MAX_FDS as u64),
        _ => (INF, INF),
    }
}

impl Kernel {
    fn next_random(&mut self) -> u8 {
        // xorshift64*: deterministic, so runs repeat exactly.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
    }
}

/// A positional read that leaves the file position alone (`pread`).
#[cfg(unix)]
fn read_at(file: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buf, off)
}

#[cfg(not(unix))]
fn read_at(file: &std::fs::File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buf, off)
}

fn io_errno(e: std::io::Error) -> u64 {
    e.raw_os_error().map_or(EPERM, |c| c as u64)
}

#[cfg(unix)]
fn open_nofollow(
    path: &Path,
    write: bool,
    create: bool,
    excl: bool,
    trunc: bool,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut o = std::fs::OpenOptions::new();
    o.read(true).custom_flags(libc::O_NOFOLLOW);
    if write {
        o.write(true);
        if create && excl {
            o.create_new(true);
        } else if create {
            o.create(true);
        }
        if trunc {
            o.truncate(true);
        }
    }
    o.mode(0o644);
    o.open(path)
}

#[cfg(not(unix))]
fn open_nofollow(
    path: &Path,
    write: bool,
    create: bool,
    excl: bool,
    trunc: bool,
) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    if write {
        o.write(true);
        if create && excl {
            o.create_new(true);
        } else if create {
            o.create(true);
        }
        if trunc {
            o.truncate(true);
        }
    }
    o.open(path)
}

#[cfg(unix)]
fn host_stat(m: &std::fs::Metadata) -> StatInfo {
    use std::os::unix::fs::MetadataExt;
    let kind = if m.is_dir() { S_IFDIR } else { S_IFREG };
    StatInfo {
        dev: 0x803,
        ino: m.ino(),
        mode: kind | (m.mode() & 0o777),
        nlink: m.nlink() as u32,
        uid: PID as u32,
        gid: PID as u32,
        rdev: 0,
        size: m.len(),
        blksize: 4096,
        blocks: m.len().div_ceil(512),
        mtime: EPOCH as i64,
    }
}

#[cfg(not(unix))]
fn host_stat(m: &std::fs::Metadata) -> StatInfo {
    let kind = if m.is_dir() { S_IFDIR } else { S_IFREG };
    StatInfo {
        dev: 0x803,
        ino: 1,
        mode: kind | 0o644,
        nlink: 1,
        uid: PID as u32,
        gid: PID as u32,
        rdev: 0,
        size: m.len(),
        blksize: 4096,
        blocks: m.len().div_ceil(512),
        mtime: EPOCH as i64,
    }
}

/// The kernel struct a stat-family call fills, in the guest's layout.
fn stat_bytes(arch: Arch, s: &StatInfo, call: &str) -> Vec<u8> {
    let mut b: Vec<u8>;
    let put = |b: &mut Vec<u8>, off: usize, v: &[u8]| b[off..off + v.len()].copy_from_slice(v);
    if call == "statx" {
        b = vec![0u8; 256];
        put(&mut b, 0, &0x7ffu32.to_le_bytes()); // STATX_BASIC_STATS
        put(&mut b, 4, &s.blksize.to_le_bytes());
        put(&mut b, 16, &s.nlink.to_le_bytes());
        put(&mut b, 20, &s.uid.to_le_bytes());
        put(&mut b, 24, &s.gid.to_le_bytes());
        put(&mut b, 28, &(s.mode as u16).to_le_bytes());
        put(&mut b, 32, &s.ino.to_le_bytes());
        put(&mut b, 40, &s.size.to_le_bytes());
        put(&mut b, 48, &s.blocks.to_le_bytes());
        for off in [64, 96, 112] {
            put(&mut b, off, &s.mtime.to_le_bytes());
        }
        put(&mut b, 128, &((s.rdev >> 8) as u32).to_le_bytes());
        put(&mut b, 132, &((s.rdev & 0xff) as u32).to_le_bytes());
        put(&mut b, 136, &((s.dev >> 8) as u32).to_le_bytes());
        put(&mut b, 140, &((s.dev & 0xff) as u32).to_le_bytes());
        return b;
    }
    match arch {
        Arch::X86_64 => {
            b = vec![0u8; 144];
            put(&mut b, 0, &s.dev.to_le_bytes());
            put(&mut b, 8, &s.ino.to_le_bytes());
            put(&mut b, 16, &u64::from(s.nlink).to_le_bytes());
            put(&mut b, 24, &s.mode.to_le_bytes());
            put(&mut b, 28, &s.uid.to_le_bytes());
            put(&mut b, 32, &s.gid.to_le_bytes());
            put(&mut b, 40, &s.rdev.to_le_bytes());
            put(&mut b, 48, &s.size.to_le_bytes());
            put(&mut b, 56, &u64::from(s.blksize).to_le_bytes());
            put(&mut b, 64, &s.blocks.to_le_bytes());
            for off in [72, 88, 104] {
                put(&mut b, off, &s.mtime.to_le_bytes());
            }
        }
        Arch::Aarch64 | Arch::Riscv64 | Arch::Riscv32 => {
            b = vec![0u8; 128];
            put(&mut b, 0, &s.dev.to_le_bytes());
            put(&mut b, 8, &s.ino.to_le_bytes());
            put(&mut b, 16, &s.mode.to_le_bytes());
            put(&mut b, 20, &s.nlink.to_le_bytes());
            put(&mut b, 24, &s.uid.to_le_bytes());
            put(&mut b, 28, &s.gid.to_le_bytes());
            put(&mut b, 32, &s.rdev.to_le_bytes());
            put(&mut b, 48, &s.size.to_le_bytes());
            put(&mut b, 56, &s.blksize.to_le_bytes());
            put(&mut b, 64, &s.blocks.to_le_bytes());
            for off in [72, 88, 104] {
                put(&mut b, off, &s.mtime.to_le_bytes());
            }
        }
        Arch::Arm => {
            b = vec![0u8; 104];
            put(&mut b, 0, &s.dev.to_le_bytes());
            put(&mut b, 12, &(s.ino as u32).to_le_bytes());
            put(&mut b, 16, &s.mode.to_le_bytes());
            put(&mut b, 20, &s.nlink.to_le_bytes());
            put(&mut b, 24, &s.uid.to_le_bytes());
            put(&mut b, 28, &s.gid.to_le_bytes());
            put(&mut b, 32, &s.rdev.to_le_bytes());
            put(&mut b, 48, &s.size.to_le_bytes());
            put(&mut b, 56, &s.blksize.to_le_bytes());
            put(&mut b, 64, &s.blocks.to_le_bytes());
            for off in [72, 80, 88] {
                put(&mut b, off, &(s.mtime as u32).to_le_bytes());
            }
            put(&mut b, 96, &s.ino.to_le_bytes());
        }
        Arch::X86 => {
            b = vec![0u8; 96];
            put(&mut b, 0, &s.dev.to_le_bytes());
            put(&mut b, 12, &(s.ino as u32).to_le_bytes());
            put(&mut b, 16, &s.mode.to_le_bytes());
            put(&mut b, 20, &s.nlink.to_le_bytes());
            put(&mut b, 24, &s.uid.to_le_bytes());
            put(&mut b, 28, &s.gid.to_le_bytes());
            put(&mut b, 32, &s.rdev.to_le_bytes());
            put(&mut b, 44, &s.size.to_le_bytes());
            put(&mut b, 52, &s.blksize.to_le_bytes());
            put(&mut b, 56, &s.blocks.to_le_bytes());
            for off in [64, 72, 80] {
                put(&mut b, off, &(s.mtime as u32).to_le_bytes());
            }
            put(&mut b, 88, &s.ino.to_le_bytes());
        }
    }
    b
}

/// The regular files under `dir`, sorted by name.
fn written_files(dir: &Path) -> Vec<WrittenFile> {
    let mut out = Vec::new();
    let mut todo = vec![(dir.to_path_buf(), String::new())];
    while let Some((d, prefix)) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            let Ok(ty) = e.file_type() else { continue };
            if ty.is_dir() && prefix.matches('/').count() < 4 {
                todo.push((e.path(), format!("{name}/")));
            } else if ty.is_file() && out.len() < MAX_FILES {
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                let mut data = Vec::new();
                if let Ok(f) = std::fs::File::open(e.path()) {
                    let _ = f.take(FILE_KEEP as u64).read_to_end(&mut data);
                }
                out.push(WrittenFile { name, size, data });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Runs a program to its end under emulation, in this process. The guest cannot reach the host:
/// every instruction is interpreted and every system call is answered by this layer (file access
/// only inside the private directory and the read-only sysroot). [`crate::confined`] runs the
/// same inside the sandbox child as a second layer.
pub fn run_program(spec: &RunSpec) -> Result<ProgramOutcome, EmuError> {
    let mut p = LinuxProcess::spawn(spec)?;
    let t = Instant::now();
    let start = p.m.icount();
    let exit = p.run_to_end(
        spec.max_instructions,
        Duration::from_millis(spec.timeout_ms),
    );
    let instructions = p.m.icount() - start;
    Ok(p.outcome(exit, t.elapsed(), instructions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_layouts_have_the_kernel_sizes() {
        let s = StatInfo {
            size: 0x1234,
            mode: S_IFREG | 0o644,
            ..StatInfo::default()
        };
        assert_eq!(stat_bytes(Arch::X86_64, &s, "fstat").len(), 144);
        assert_eq!(stat_bytes(Arch::Aarch64, &s, "fstat").len(), 128);
        assert_eq!(stat_bytes(Arch::Arm, &s, "fstat64").len(), 104);
        assert_eq!(stat_bytes(Arch::X86, &s, "fstat64").len(), 96);
        let x = stat_bytes(Arch::Arm, &s, "statx");
        assert_eq!(x.len(), 256);
        assert_eq!(u64::from_le_bytes(x[40..48].try_into().expect("8")), 0x1234);
        let g = stat_bytes(Arch::Riscv64, &s, "fstat");
        assert_eq!(
            u32::from_le_bytes(g[16..20].try_into().expect("4")),
            S_IFREG | 0o644
        );
    }

    #[test]
    fn faults_map_to_signals() {
        assert!(matches!(
            fault_exit("ReadUnmapped (0x0)", 0x10),
            Exit::Signal { signal: 11, .. }
        ));
        assert!(matches!(
            fault_exit("InvalidInstruction (0x0)", 0x10),
            Exit::Signal { signal: 4, .. }
        ));
        assert!(matches!(
            fault_exit("UnimplementedOp (0x0)", 0x10),
            Exit::Unsupported { .. }
        ));
    }
}

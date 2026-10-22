//! The function oracle: runs one function of an ELF program under emulation and reports what it
//! did.
//!
//! The emulator is kraken-emu (icicle-emu's SLEIGH p-code interpreter underneath), driven as a
//! bare CPU of the program's architecture: x86-64, x86, ARM/Thumb, AArch64, RISC-V 64 or 32. The
//! ELF's `PT_LOAD` segments are mapped by kraken-emu's loader, its dynamic relocations applied,
//! every import slot pointed at a stub address, and a call is set up per the architecture's C
//! calling convention (`kraken_emu::call`: SysV, cdecl, AAPCS-VFP, AAPCS64, RISC-V lp64d/ilp32)
//! with a sentinel return address. Stubs are handled by the host when the program counter
//! reaches them (a breakpoint), never emulated.
//!
//! What it passes: integers and pointers, `double`s and `float`s where the convention puts them,
//! pointer graphs placed where the native runner places them (on 64-bit targets; 32-bit targets
//! get the same layout below 4 GiB), and two host callbacks for function-pointer parameters (see
//! `abi`). What it deliberately does not do: run `main`, the dynamic loader or libc; vector
//! arguments; more parameters than the x86-64 registers hold (the native runner's limit); threads;
//! syscalls (a system call ends the case as a fault); floating-point `printf`.

use std::path::{Path, PathBuf};

use kraken_emu::call::{
    RetKind, Value, incoming_float_arg, incoming_int_arg, read_return, return_to_caller,
    set_float_return, set_int_return, setup_call,
};
use kraken_emu::loader::{Image, SlotKind};
use kraken_emu::{Arch, EmuError, Machine, Perm, SpecRoots, Stop};

use crate::abi::{
    Arg, Callback, GlobalWrite, Observation, Param, Ret, Signature, Termination, callback_tag,
    check_graph, mask, place_object_for,
};
use crate::clib::{ctype_b_table, format_printf};
use crate::error::RewriteError;

const PAGE: u64 = 0x1000;
const MAX_BUFFER: usize = 0x10_0000;
const STACK_CANARY: u64 = 0x2f8b_1c3a_5d6e_7f00;

/// Imports the oracle models (everything else a function calls ends the case as unsupported).
/// The planner flags functions that call anything outside this list.
pub const STUBBED_IMPORTS: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "__stack_chk_fail",
    "printf",
    "fprintf",
    "puts",
    "putchar",
    "strlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strcat",
    "memcpy",
    "memmove",
    "memset",
    "__ctype_b_loc",
    "fputc",
    "putc",
    "fputs",
    "fwrite",
    "strspn",
    "strcspn",
    "malloc",
    "calloc",
    "free",
    "_Znwm",
    "_Znam",
    "_ZdlPv",
    "_ZdlPvm",
    "_ZdaPv",
    "_ZdaPvm",
    "operator.new",
    "operator.delete",
    "operator.new[]",
    "operator.delete[]",
    "_ZSt20__throw_length_errorPKc",
    "__throw_length_error",
    "sqrt",
    "sqrtf",
    "sin",
    "sinf",
    "cos",
    "cosf",
    "pow",
    "powf",
    "exp",
    "expf",
    "log",
    "logf",
    "log2",
    "log2f",
    "log10",
    "log10f",
    "floor",
    "floorf",
    "ceil",
    "ceilf",
    "round",
    "roundf",
    "fabs",
    "fabsf",
    "lround",
    "lroundf",
    "fmod",
    "fmodf",
    "atan2",
    "atan2f",
];

/// Where the oracle puts its own memory. 64-bit targets keep the addresses the x86-64 oracle has
/// always used; 32-bit targets get the same shape below 4 GiB.
#[derive(Debug, Clone, Copy)]
struct Layout {
    stack_base: u64,
    stack_size: u64,
    stub_base: u64,
    heap_base: u64,
    heap_size: u64,
}

impl Layout {
    fn for_arch(arch: Arch) -> Layout {
        if arch.bits() == 64 {
            Layout {
                stack_base: 0x7ffd_0000_0000,
                stack_size: 0x1_0000,
                stub_base: 0x7ffe_0000_0000,
                heap_base: 0x7ffc_0000_0000,
                heap_size: 0x100_0000,
            }
        } else {
            Layout {
                stack_base: 0xbe00_0000,
                stack_size: 0x1_0000,
                stub_base: 0xbf00_0000,
                heap_base: 0x7000_0000,
                heap_size: 0x100_0000,
            }
        }
    }
    fn return_addr(&self) -> u64 {
        self.stub_base + 0xff0
    }
    /// The host callbacks a function pointer parameter can be given (`Callback::index` apart).
    fn callback_base(&self) -> u64 {
        self.stub_base + 0xfd0
    }
    fn stub_data(&self) -> u64 {
        self.stub_base + 0x1_0000
    }
    fn ctype_ptr_cell(&self) -> u64 {
        self.stub_data()
    }
    fn stdout_cell(&self) -> u64 {
        self.stub_data() + 0x10
    }
    fn stderr_cell(&self) -> u64 {
        self.stub_data() + 0x18
    }
    /// The `FILE *` values `stdout` and `stderr` hold inside the oracle.
    fn stdout_file(&self) -> u64 {
        self.stub_data() + 0x20
    }
    fn stderr_file(&self) -> u64 {
        self.stub_data() + 0x30
    }
    /// `__stack_chk_guard` for the architectures that read the canary from a global.
    fn canary_cell(&self) -> u64 {
        self.stub_data() + 0x40
    }
    fn ctype_table(&self) -> u64 {
        self.stub_data() + 0x100
    }
    /// The thread block `fs:` (x86-64) or `gs:` (x86) points at; the canary lives at `fs:0x28` /
    /// `gs:0x14`.
    fn tls_base(&self) -> u64 {
        self.stub_base + 0x4_0000
    }
}

/// Oracle settings.
#[derive(Debug, Clone)]
pub struct OracleConfig {
    /// A Ghidra install (the oracle compiles the SLEIGH spec of the program's architecture from
    /// its processor sources). Default: `KRAKEN_GHIDRA_HOME`, else the runtime `kraken setup`
    /// provisioned, else the spec roots kraken-emu discovers.
    pub ghidra_home: Option<PathBuf>,
    /// Instruction budget per call.
    pub max_instructions: u64,
    /// Where a position-independent executable is loaded (64-bit targets; 32-bit ones use
    /// [`PIE_BASE_32`]).
    pub load_base: u64,
}

/// Load address of a 32-bit position-independent executable.
pub const PIE_BASE_32: u64 = 0x0040_0000;

impl Default for OracleConfig {
    fn default() -> Self {
        OracleConfig {
            ghidra_home: None,
            max_instructions: 5_000_000,
            load_base: 0x5555_5555_4000,
        }
    }
}

/// The spec roots the oracle builds its CPU from: the configured Ghidra install,
/// `KRAKEN_GHIDRA_HOME`, the provisioned runtime, then kraken-emu's discovery.
pub fn spec_roots(cfg: &OracleConfig) -> SpecRoots {
    let mut first: Vec<PathBuf> = Vec::new();
    if let Some(h) = &cfg.ghidra_home {
        first.push(h.clone());
    }
    if let Some(h) = std::env::var_os("KRAKEN_GHIDRA_HOME").filter(|v| !v.is_empty()) {
        first.push(PathBuf::from(h));
    }
    if let Some(layout) = kraken_host::provision::Layout::from_env()
        && let Some(h) = layout.provisioned().ghidra_home
    {
        first.push(h);
    }
    SpecRoots::discover_with(first)
}

/// `Ghidra/Processors` of the configured spec roots for x86-64 (kept for callers that only
/// check that the oracle can be built).
pub fn find_processors(cfg: &OracleConfig) -> Result<PathBuf, RewriteError> {
    spec_roots(cfg)
        .processors_for(Arch::X86_64)
        .map_err(|_| RewriteError::NoProcessors)
}

/// Where a call's arguments went.
#[derive(Default)]
struct Laid {
    /// Argument values in parameter order.
    values: Vec<Value>,
    /// Every object: address and length.
    buffers: Vec<(u64, usize)>,
}

/// A loaded program image plus the emulator that runs functions of it.
pub struct FunctionOracle {
    m: Machine,
    image: Image,
    layout: Layout,
    /// Stub index to the import it stands for.
    stub_names: Vec<String>,
    max_instructions: u64,
    stdout: Vec<u8>,
    /// The objects of the call in progress (base address and length), for callback tags.
    objects: Vec<(u64, usize)>,
    /// Callback calls of the call in progress.
    callbacks: Vec<String>,
    stderr: Vec<u8>,
    /// Next free byte of the emulated heap.
    heap_next: u64,
    /// The heap blocks of the call in progress, with the size asked for.
    blocks: Vec<(u64, usize)>,
}

impl std::fmt::Debug for FunctionOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionOracle")
            .field("arch", &self.image.arch)
            .field("bias", &self.image.bias)
            .field("imports", &self.stub_names)
            .finish_non_exhaustive()
    }
}

fn emu(e: impl std::fmt::Display) -> RewriteError {
    RewriteError::Emulator(e.to_string())
}

fn from_emu(e: EmuError) -> RewriteError {
    match e {
        EmuError::Image(m) => RewriteError::Image(m),
        EmuError::Unsupported(m) => RewriteError::Image(m),
        EmuError::NoSpecs { .. } => RewriteError::NoProcessors,
        other => RewriteError::Emulator(other.to_string()),
    }
}

impl FunctionOracle {
    /// Loads the ELF at `path` and builds the emulator.
    pub fn load(path: &Path, cfg: &OracleConfig) -> Result<Self, RewriteError> {
        let data = std::fs::read(path)
            .map_err(|e| RewriteError::Image(format!("{}: {e}", path.display())))?;
        Self::from_bytes(&data, cfg)
    }

    /// Loads an ELF from memory.
    pub fn from_bytes(data: &[u8], cfg: &OracleConfig) -> Result<Self, RewriteError> {
        let arch = Arch::from_elf(data).map_err(from_emu)?;
        let layout = Layout::for_arch(arch);
        let pie_base = if arch.bits() == 64 {
            cfg.load_base
        } else {
            PIE_BASE_32
        };
        // Every import slot gets a stub address, except the C library's data the oracle models.
        let mut stub_names: Vec<String> = Vec::new();
        let image = Image::load(data, pie_base, |name, kind, _slot| match (kind, name) {
            (SlotKind::GlobDat, "stdout") => Some(layout.stdout_cell()),
            (SlotKind::GlobDat, "stderr") => Some(layout.stderr_cell()),
            (SlotKind::GlobDat | SlotKind::Absolute, "__stack_chk_guard") => {
                Some(layout.canary_cell())
            }
            (SlotKind::Copy, "stdout") => Some(layout.stdout_file()),
            (SlotKind::Copy, "stderr") => Some(layout.stderr_file()),
            (SlotKind::Copy, "__stack_chk_guard") => Some(STACK_CANARY),
            (SlotKind::Copy, _) => None,
            _ => {
                stub_names.push(name.to_string());
                Some(layout.stub_base + 0x10 * stub_names.len() as u64)
            }
        })
        .map_err(from_emu)?;
        if stub_names.len() * 0x10 >= 0xfc0 {
            return Err(RewriteError::Image(
                "too many imports for the stub page".into(),
            ));
        }

        let specs = spec_roots(cfg);
        let mut m = Machine::new(arch, &specs).map_err(from_emu)?;
        image.map_into(&mut m).map_err(from_emu)?;
        let map =
            |m: &mut Machine, addr: u64, len: u64, p: Perm| m.map(addr, len, p).map_err(from_emu);
        map(&mut m, layout.stack_base, layout.stack_size, Perm::RW)?;
        map(&mut m, layout.stub_base, PAGE, Perm::RX)?;
        map(&mut m, layout.stub_data(), 0x2000, Perm::RW)?;
        map(&mut m, layout.heap_base, layout.heap_size, Perm::RW)?;
        map(&mut m, layout.tls_base(), PAGE, Perm::RW)?;

        // Stub code page: an instruction that decodes (the CPU stops on the stubs' breakpoints
        // first; on x86 it is `ret`, so a stray fall-through returns).
        m.write_mem(layout.stub_base, &kraken_emu::call::stub_fill(arch))
            .map_err(from_emu)?;
        let ps = arch.ptr_size();
        let w = |m: &mut Machine, addr: u64, v: u64| m.write_uint(addr, ps, v).map_err(from_emu);
        m.write_mem(layout.ctype_table(), &ctype_b_table())
            .map_err(from_emu)?;
        w(
            &mut m,
            layout.ctype_ptr_cell(),
            layout.ctype_table() + 128 * 2,
        )?;
        w(&mut m, layout.stdout_cell(), layout.stdout_file())?;
        w(&mut m, layout.stderr_cell(), layout.stderr_file())?;
        w(&mut m, layout.canary_cell(), STACK_CANARY)?;
        let canary_at = if arch == Arch::X86 { 0x14 } else { 0x28 };
        w(&mut m, layout.tls_base() + canary_at, STACK_CANARY)?;
        m.add_breakpoint(layout.return_addr());
        for cb in Callback::ALL {
            m.add_breakpoint(layout.callback_base() + 0x10 * cb.index());
        }
        for i in 0..stub_names.len() {
            m.add_breakpoint(layout.stub_base + 0x10 * (i as u64 + 1));
        }

        Ok(FunctionOracle {
            m,
            image,
            layout,
            stub_names,
            max_instructions: cfg.max_instructions,
            objects: Vec::new(),
            callbacks: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            heap_next: layout.heap_base,
            blocks: Vec::new(),
        })
    }

    /// The program's architecture.
    pub fn arch(&self) -> Arch {
        self.image.arch
    }

    /// The ELF virtual address of the function KRAKEN reports at `address` for a program loaded
    /// at `image_base`: a position-independent executable's addresses include the image base
    /// Ghidra chose, a fixed-address executable's are the ELF addresses themselves.
    pub fn elf_vaddr(&self, address: u64, image_base: u64) -> u64 {
        if self.image.is_pie {
            address.wrapping_sub(image_base)
        } else {
            address
        }
    }

    /// The ELF virtual address of a symbol (not including the load bias; Thumb functions keep
    /// bit 0, so the value is a code address).
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.image.symbols.get(name).copied()
    }

    /// Imports the program has (every one gets a stub address; unmodelled ones end a call that
    /// reaches them with [`Termination::Unsupported`]).
    pub fn imports(&self) -> &[String] {
        &self.stub_names
    }

    /// Calls the function at ELF virtual address `entry` with `args` and reports what happened.
    /// The program image, stack and stub state are reset first, so calls are independent.
    pub fn call(
        &mut self,
        entry: u64,
        sig: &Signature,
        args: &[Arg],
    ) -> Result<Observation, RewriteError> {
        let doubles = sig.params.iter().filter(|p| p.is_sse()).count();
        if sig.params.len() - doubles > 6 || doubles > 8 {
            return Err(RewriteError::Unsupported(
                "more than six integer or eight floating-point parameters (stack arguments are \
                 not modelled)"
                    .into(),
            ));
        }
        if sig.params.len() != args.len() {
            return Err(RewriteError::Unsupported(format!(
                "{} arguments for {} parameters",
                args.len(),
                sig.params.len()
            )));
        }
        self.reset_memory()?;
        self.stdout.clear();
        self.stderr.clear();
        self.callbacks.clear();
        // What the last call allocated is cleared, so no case sees another's heap.
        let used = self.heap_next - self.layout.heap_base;
        if used > 0 {
            self.m
                .write_mem(self.layout.heap_base, &vec![0u8; used as usize])
                .map_err(from_emu)?;
        }
        self.heap_next = self.layout.heap_base;
        self.blocks.clear();
        self.objects.clear();

        let mut mapped: Vec<(u64, u64)> = Vec::new();
        // A bug in the emulator (an arithmetic overflow on a wild address) must not take the
        // whole run down: the case is one the oracle could not evaluate.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.lay_out(args, sig, &mut mapped)
                .and_then(|laid| self.run_call(entry, sig, &laid.values, &laid.buffers))
        }))
        .unwrap_or_else(|_| {
            Ok(Observation::failed(Termination::Unsupported {
                detail: "the emulator failed on this case".into(),
            }))
        });
        self.objects.clear();
        for (addr, len) in mapped {
            self.m.unmap(addr, len);
        }
        result
    }

    /// Maps one object into its own region, page padded with unmapped space around it, the data
    /// flush against the end (rounded down to 8 bytes) so a read past it faults. Returns where
    /// the data starts.
    fn map_object(
        &mut self,
        data: &[u8],
        mapped: &mut Vec<(u64, u64)>,
        n: usize,
    ) -> Result<u64, RewriteError> {
        if data.len() > MAX_BUFFER {
            return Err(RewriteError::Unsupported("buffer over 1 MiB".into()));
        }
        let (addr, len, at) = place_object_for(self.image.arch.bits(), n, data.len());
        self.m
            .map(addr, len, Perm::RW)
            .map_err(|_| emu("cannot map buffer"))?;
        mapped.push((addr, len));
        self.m.write_mem(at, data).map_err(from_emu)?;
        Ok(at)
    }

    fn lay_out(
        &mut self,
        args: &[Arg],
        sig: &Signature,
        mapped: &mut Vec<(u64, u64)>,
    ) -> Result<Laid, RewriteError> {
        let arch = self.image.arch;
        let ptr = |v: u64| Value::ptr(arch, v);
        let mut laid = Laid::default();
        for (i, (p, a)) in sig.params.iter().zip(args).enumerate() {
            match (p, a) {
                (Param::Int { bits, signed }, Arg::Int { value }) => {
                    laid.values.push(Value::Int {
                        bits: *bits,
                        signed: *signed,
                        value: value & mask(*bits),
                    });
                }
                (Param::Double, Arg::Double { bits }) => {
                    laid.values.push(Value::F64 { bits: *bits })
                }
                (Param::Float, Arg::Float { bits }) => laid.values.push(Value::F32 { bits: *bits }),
                (Param::FnPtr, Arg::FnPtr { callback }) => {
                    laid.values
                        .push(ptr(self.layout.callback_base() + 0x10 * callback.index()));
                }
                (Param::Buf, Arg::Buf { data }) => {
                    let at = self.map_object(data, mapped, laid.buffers.len())?;
                    laid.buffers.push((at, data.len()));
                    laid.values.push(ptr(at));
                }
                (Param::Buf, Arg::Graph { objects, links }) => {
                    check_graph(objects, links).map_err(RewriteError::Unsupported)?;
                    let first = laid.buffers.len();
                    for o in objects {
                        let at = self.map_object(o, mapped, laid.buffers.len())?;
                        laid.buffers.push((at, o.len()));
                    }
                    for l in links {
                        let target = laid.buffers[first + l.to].0 + l.to_offset as u64;
                        let at = laid.buffers[first + l.from].0 + l.offset as u64;
                        self.m.write_ptr(at, target).map_err(from_emu)?;
                    }
                    laid.values.push(ptr(laid.buffers[first].0));
                }
                _ => {
                    return Err(RewriteError::Unsupported(format!(
                        "argument {i} does not match its parameter kind"
                    )));
                }
            }
        }
        self.objects = laid.buffers.clone();
        Ok(laid)
    }

    fn reset_memory(&mut self) -> Result<(), RewriteError> {
        self.image.reset(&mut self.m).map_err(from_emu)?;
        self.m
            .write_mem(
                self.layout.stack_base,
                &vec![0u8; self.layout.stack_size as usize],
            )
            .map_err(from_emu)?;
        Ok(())
    }

    /// Clears the registers a call reads, so no value from an earlier case leaks into this one.
    fn clear_registers(&mut self) -> Result<(), RewriteError> {
        let arch = self.image.arch;
        let mut regs: Vec<&str> = arch.int_arg_regs().to_vec();
        regs.extend(arch.int_ret_regs());
        let fp: &[&str] = match arch {
            Arch::X86_64 => &[
                "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
            ],
            Arch::Arm => &["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"],
            Arch::Aarch64 => &["q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7"],
            Arch::Riscv64 => &["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"],
            Arch::X86 | Arch::Riscv32 => &[],
        };
        regs.extend(fp);
        for r in regs {
            if self.m.has_reg(r) {
                self.m.write_reg(r, 0).map_err(from_emu)?;
            }
        }
        match arch {
            Arch::X86_64 => self
                .m
                .write_reg("FS_OFFSET", self.layout.tls_base())
                .map_err(from_emu)?,
            Arch::X86 => self
                .m
                .write_reg("GS_OFFSET", self.layout.tls_base())
                .map_err(from_emu)?,
            _ => {}
        }
        Ok(())
    }

    fn run_call(
        &mut self,
        entry: u64,
        sig: &Signature,
        values: &[Value],
        buffers: &[(u64, usize)],
    ) -> Result<Observation, RewriteError> {
        self.clear_registers()?;
        // The call-site stack pointer is 16-byte aligned (8 on ARM); x86 then pushes the return
        // address.
        let top = self.layout.stack_base + self.layout.stack_size - 0x100 + 0x40;
        setup_call(
            &mut self.m,
            self.image.bias + entry,
            values,
            top,
            self.layout.return_addr(),
        )
        .map_err(from_emu)?;

        let start = self.m.icount();
        let termination = loop {
            let used = self.m.icount() - start;
            if used >= self.max_instructions {
                break Termination::Timeout;
            }
            match self.m.run(self.max_instructions - used) {
                Stop::Breakpoint { pc } => {
                    if pc == self.layout.return_addr() {
                        break Termination::Returned;
                    }
                    if let Some(cb) = pc
                        .checked_sub(self.layout.callback_base())
                        .filter(|d| d % 0x10 == 0 && d / 0x10 < Callback::ALL.len() as u64)
                        .map(|d| Callback::ALL[(d / 0x10) as usize])
                    {
                        if let Some(end) = self.run_callback(cb) {
                            break end;
                        }
                        continue;
                    }
                    let idx = pc
                        .checked_sub(self.layout.stub_base + 0x10)
                        .filter(|d| d % 0x10 == 0)
                        .map(|d| (d / 0x10) as usize)
                        .filter(|i| *i < self.stub_names.len());
                    let Some(idx) = idx else {
                        break Termination::Fault {
                            detail: format!("stopped at unexpected breakpoint {pc:#x}"),
                        };
                    };
                    let name = self.stub_names[idx].clone();
                    if let Some(end) = self.run_stub(&name) {
                        break end;
                    }
                }
                Stop::Budget => continue,
                Stop::Fault { detail, pc } => {
                    break Termination::Fault {
                        detail: format!("{detail} at pc {:#x}", pc.wrapping_sub(self.image.bias)),
                    };
                }
                Stop::Syscall => {
                    break Termination::Fault {
                        detail: format!(
                            "system call at pc {:#x}",
                            self.m.pc().wrapping_sub(self.image.bias)
                        ),
                    };
                }
                other => {
                    break Termination::Fault {
                        detail: format!("emulator stopped: {other:?}"),
                    };
                }
            }
        };
        let instructions = self.m.icount().saturating_sub(start);
        let mut obs = Observation::failed(termination.clone());
        obs.instructions = instructions;
        obs.stdout = self.stdout.clone();
        obs.stderr = self.stderr.clone();
        obs.global_writes = self.global_writes()?;
        obs.callbacks = self.callbacks.clone();
        if termination == Termination::Returned {
            let kind = match sig.ret {
                Ret::Int { bits, .. } => Some(RetKind::Int { bits }),
                Ret::Double => Some(RetKind::F64),
                Ret::Float => Some(RetKind::F32),
                Ret::Void | Ret::Ptr => None,
            };
            if let Some(k) = kind {
                obs.ret = read_return(&mut self.m, k).map_err(from_emu)?;
            }
            if sig.ret == Ret::Ptr {
                let bits = if self.m.arch().bits() == 32 { 32 } else { 64 };
                let p = read_return(&mut self.m, RetKind::Int { bits })
                    .map_err(from_emu)?
                    .unwrap_or(0);
                let blocks = self.blocks.clone();
                let m = &mut self.m;
                obs.ret_object = Some(crate::ptrdesc::describe_pointer(p, &blocks, &mut |a, n| {
                    m.read_vec(a, n).unwrap_or_default()
                }));
            }
            for &(addr, len) in buffers {
                obs.buffers
                    .push(self.m.read_vec(addr, len).map_err(from_emu)?);
            }
        }
        Ok(obs)
    }

    /// A call of the function under test to one of the host callbacks: records it, answers it as
    /// [`Callback::result`] says and returns to the caller. `None` means the call goes on.
    fn run_callback(&mut self, cb: Callback) -> Option<Termination> {
        let (a, b) = (self.stub_arg(0), self.stub_arg(1));
        let objects = self.objects.clone();
        let m = &mut self.m;
        let mut read32 = |addr: u64| m.read_uint(addr, 4).ok().map(|v| v as u32 as i32);
        let (ta, tb) = (
            callback_tag(a, &objects, &mut read32),
            callback_tag(b, &objects, &mut read32),
        );
        let both = [a, b].iter().all(|v| {
            objects
                .iter()
                .any(|&(base, len)| *v >= base && *v < base + len as u64)
        });
        let ret = match (both, read32(a), read32(b)) {
            (true, Some(x), Some(y)) => cb.result(x, y),
            _ => 0,
        };
        self.callbacks
            .push(format!("cb{}({ta},{tb})={:x}", cb.index(), ret as u64));
        self.return_from_stub(ret as u64)
    }

    fn global_writes(&mut self) -> Result<Vec<GlobalWrite>, RewriteError> {
        let mut out: Vec<GlobalWrite> = Vec::new();
        let bias = self.image.bias;
        for r in self.image.regions.iter().filter(|r| r.writable) {
            let now = self.m.read_vec(r.addr, r.bytes.len()).map_err(from_emu)?;
            let mut i = 0;
            while i < now.len() {
                if now[i] == r.bytes[i] {
                    i += 1;
                    continue;
                }
                let s = i;
                while i < now.len() && now[i] != r.bytes[i] {
                    i += 1;
                }
                out.push(GlobalWrite {
                    vaddr: r.addr - bias + s as u64,
                    before: r.bytes[s..i].to_vec(),
                    after: now[s..i].to_vec(),
                });
                if out.len() >= 64 {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    }

    /// The `n`th integer argument of the stubbed call at the current stop.
    fn stub_arg(&mut self, n: usize) -> u64 {
        incoming_int_arg(&mut self.m, n)
    }

    fn byte_at(&mut self, addr: u64) -> Option<u8> {
        let mut b = [0u8; 1];
        self.m.read_mem(addr, &mut b).ok().map(|()| b[0])
    }

    fn read_cstr(&mut self, addr: u64) -> Option<Vec<u8>> {
        self.m.read_cstr(addr, 0xffff)
    }

    fn format(&mut self, fmt_addr: u64, first_arg: usize) -> Result<Vec<u8>, String> {
        let fmt = self
            .read_cstr(fmt_addr)
            .ok_or_else(|| format!("unreadable format string at {fmt_addr:#x}"))?;
        let mut n = first_arg;
        // The formatter asks for as many arguments as the format needs.
        let this = std::cell::RefCell::new(&mut *self);
        let mut next = || {
            let v = this.borrow_mut().stub_arg(n);
            n += 1;
            v
        };
        // Variadic doubles of the System V x86-64 ABI arrive in xmm0..xmm7 in order.
        let mut d = 0usize;
        let mut next_double = || {
            let mut t = this.borrow_mut();
            if t.m.arch() != kraken_emu::Arch::X86_64 || d >= 8 {
                return None;
            }
            let v = t.m.read_reg(&format!("XMM{d}")).ok()?;
            d += 1;
            Some(f64::from_bits(v))
        };
        let mut cstr = |a: u64| this.borrow_mut().read_cstr(a);
        format_printf(&fmt, &mut next, &mut next_double, &mut cstr)
    }

    /// Runs the stub for import `name`. `None` means the call continues (returned to the caller).
    fn run_stub(&mut self, name: &str) -> Option<Termination> {
        let unsupported = |detail: String| Some(Termination::Unsupported { detail });
        let (stdout_file, stderr_file) = (self.layout.stdout_file(), self.layout.stderr_file());
        let ret: u64 = match name {
            "exit" | "_exit" | "_Exit" => {
                let status = self.stub_arg(0) as i32;
                return Some(Termination::Exited { status });
            }
            "abort" => {
                return Some(Termination::Fault {
                    detail: "abort() called".into(),
                });
            }
            "__stack_chk_fail" => {
                return Some(Termination::Fault {
                    detail: "stack smashing detected".into(),
                });
            }
            "printf" => {
                let f = self.stub_arg(0);
                match self.format(f, 1) {
                    Ok(b) => {
                        self.stdout.extend_from_slice(&b);
                        b.len() as u64
                    }
                    Err(e) => return unsupported(format!("printf: {e}")),
                }
            }
            "fprintf" => {
                let stream = self.stub_arg(0);
                let f = self.stub_arg(1);
                match self.format(f, 2) {
                    Ok(b) => {
                        let n = b.len() as u64;
                        if stream == stdout_file {
                            self.stdout.extend_from_slice(&b);
                        } else if stream == stderr_file {
                            self.stderr.extend_from_slice(&b);
                        } else {
                            return unsupported(format!("fprintf to FILE* {stream:#x}"));
                        }
                        n
                    }
                    Err(e) => return unsupported(format!("fprintf: {e}")),
                }
            }
            "puts" => {
                let a = self.stub_arg(0);
                match self.read_cstr(a) {
                    Some(mut s) => {
                        s.push(b'\n');
                        self.stdout.extend_from_slice(&s);
                        1
                    }
                    None => return unsupported("puts of unreadable pointer".into()),
                }
            }
            "putchar" => {
                let c = self.stub_arg(0);
                self.stdout.push(c as u8);
                c & 0xff
            }
            "strlen" => {
                let a = self.stub_arg(0);
                match self.read_cstr(a) {
                    Some(s) => s.len() as u64,
                    None => return unsupported("strlen of unreadable pointer".into()),
                }
            }
            "strcmp" => {
                let (a, b) = (self.stub_arg(0), self.stub_arg(1));
                match (self.read_cstr(a), self.read_cstr(b)) {
                    // The difference of the first differing bytes, as glibc's x86-64 strcmp
                    // returns it (and `rt::strcmp` does), not just its sign.
                    (Some(x), Some(y)) => {
                        let mut d = 0i64;
                        for i in 0..=x.len().max(y.len()) {
                            let (p, q) = (
                                x.get(i).copied().unwrap_or(0),
                                y.get(i).copied().unwrap_or(0),
                            );
                            if p != q {
                                d = i64::from(p) - i64::from(q);
                                break;
                            }
                        }
                        d as u64
                    }
                    _ => return unsupported("strcmp of unreadable pointer".into()),
                }
            }
            "strncmp" => {
                let (a, b, n) = (self.stub_arg(0), self.stub_arg(1), self.stub_arg(2));
                let mut d = 0i64;
                for i in 0..n.min(MAX_BUFFER as u64) {
                    let (Some(x), Some(y)) = (self.byte_at(a + i), self.byte_at(b + i)) else {
                        return Some(Termination::Fault {
                            detail: "strncmp of an unreadable pointer".into(),
                        });
                    };
                    if x != y || x == 0 {
                        d = i64::from(x) - i64::from(y);
                        break;
                    }
                }
                d as u64
            }
            "strcpy" | "strcat" | "strncpy" => {
                let (dst, src) = (self.stub_arg(0), self.stub_arg(1));
                let limit = if name == "strncpy" {
                    self.stub_arg(2)
                } else {
                    MAX_BUFFER as u64
                };
                if limit > MAX_BUFFER as u64 {
                    return unsupported(format!("{name} of {limit} bytes"));
                }
                let start = if name == "strcat" {
                    match self.read_cstr(dst) {
                        Some(s) => dst + s.len() as u64,
                        None => return unsupported("strcat to an unreadable string".into()),
                    }
                } else {
                    dst
                };
                // As C: copy up to the NUL (strcpy and strcat copy it too); strncpy pads with
                // NULs to `n` and leaves a truncated copy unterminated.
                let mut out = Vec::new();
                let mut i = 0u64;
                while i < limit {
                    let Some(c) = self.byte_at(src + i) else {
                        return Some(Termination::Fault {
                            detail: format!("{name} source {src:#x} unreadable"),
                        });
                    };
                    out.push(c);
                    i += 1;
                    if c == 0 {
                        break;
                    }
                }
                if name == "strncpy" {
                    out.resize(limit as usize, 0);
                } else if out.last() != Some(&0) {
                    return unsupported(format!("{name} of an unterminated string"));
                }
                if self.m.write_mem(start, &out).is_err() {
                    return Some(Termination::Fault {
                        detail: format!("{name} destination {start:#x} unwritable"),
                    });
                }
                dst
            }
            "memcpy" | "memmove" | "memset" => {
                let (dst, a1, n) = (self.stub_arg(0), self.stub_arg(1), self.stub_arg(2));
                if n > MAX_BUFFER as u64 {
                    return unsupported(format!("{name} of {n} bytes"));
                }
                let mut bytes = vec![0u8; n as usize];
                if name == "memset" {
                    bytes.fill(a1 as u8);
                } else if self.m.read_mem(a1, &mut bytes).is_err() {
                    return Some(Termination::Fault {
                        detail: format!("{name} source {a1:#x} unreadable"),
                    });
                }
                if self.m.write_mem(dst, &bytes).is_err() {
                    return Some(Termination::Fault {
                        detail: format!("{name} destination {dst:#x} unwritable"),
                    });
                }
                dst
            }
            "__ctype_b_loc" => self.layout.ctype_ptr_cell(),
            "fputc" | "putc" => {
                let (c, stream) = (self.stub_arg(0), self.stub_arg(1));
                if let Some(end) = self.write_stream(stream, &[c as u8], name) {
                    return end;
                }
                c & 0xff
            }
            "fputs" => {
                let (s, stream) = (self.stub_arg(0), self.stub_arg(1));
                let Some(text) = self.read_cstr(s) else {
                    return unsupported("fputs of an unreadable pointer".into());
                };
                if let Some(end) = self.write_stream(stream, &text, name) {
                    return end;
                }
                1
            }
            "fwrite" => {
                let (p, size, n, stream) = (
                    self.stub_arg(0),
                    self.stub_arg(1),
                    self.stub_arg(2),
                    self.stub_arg(3),
                );
                let total = size.saturating_mul(n);
                if total > MAX_BUFFER as u64 {
                    return unsupported(format!("fwrite of {total} bytes"));
                }
                let mut bytes = vec![0u8; total as usize];
                if self.m.read_mem(p, &mut bytes).is_err() {
                    return Some(Termination::Fault {
                        detail: format!("fwrite source {p:#x} unreadable"),
                    });
                }
                if let Some(end) = self.write_stream(stream, &bytes, name) {
                    return end;
                }
                if size == 0 { 0 } else { n }
            }
            "strspn" | "strcspn" => {
                let (a, b) = (self.stub_arg(0), self.stub_arg(1));
                match (self.read_cstr(a), self.read_cstr(b)) {
                    (Some(s), Some(set)) => s
                        .iter()
                        .take_while(|c| set.contains(c) == (name == "strspn"))
                        .count() as u64,
                    _ => return unsupported(format!("{name} of an unreadable pointer")),
                }
            }
            "malloc" | "_Znwm" | "_Znam" | "operator.new" | "operator.new[]" => {
                let n = self.stub_arg(0);
                let p = self.allocate(n);
                if p != 0 {
                    self.blocks.push((p, n as usize));
                }
                if p == 0 && name != "malloc" {
                    // `operator new` never returns null: libstdc++ throws, nobody catches.
                    self.stderr.extend_from_slice(
                        b"terminate called after throwing an instance of 'std::bad_alloc'\n  \
                          what():  std::bad_alloc\n",
                    );
                    return Some(Termination::Fault {
                        detail: "abort() called (uncaught std::bad_alloc)".into(),
                    });
                }
                p
            }
            "calloc" => {
                let n = self.stub_arg(0).saturating_mul(self.stub_arg(1));
                let p = self.allocate(n);
                if p != 0 {
                    // The bump heap is reused from call to call: zero the block as C does.
                    if self.m.write_mem(p, &vec![0u8; n as usize]).is_err() {
                        return Some(Termination::Fault {
                            detail: format!("calloc block {p:#x} unwritable"),
                        });
                    }
                    self.blocks.push((p, n as usize));
                }
                p
            }
            "free" | "_ZdlPv" | "_ZdlPvm" | "_ZdaPv" | "_ZdaPvm" | "operator.delete"
            | "operator.delete[]" => {
                // Memory the function allocated itself is let go; freeing an object the test
                // passed in cannot be reproduced by the native side (its allocator never saw it).
                let p = self.stub_arg(0);
                let heap = self.layout.heap_base..self.layout.heap_base + self.layout.heap_size;
                if p != 0 && !heap.contains(&p) {
                    return unsupported(format!("{name} of memory the function did not allocate"));
                }
                0
            }
            "_ZSt20__throw_length_errorPKc" | "__throw_length_error" => {
                let what = self.stub_arg(0);
                let text = self.read_cstr(what).unwrap_or_default();
                self.stderr.extend_from_slice(
                    b"terminate called after throwing an instance of 'std::length_error'\n  what():  ",
                );
                self.stderr.extend_from_slice(&text);
                self.stderr.push(b'\n');
                return Some(Termination::Fault {
                    detail: "abort() called (uncaught std::length_error)".into(),
                });
            }
            other => match self.math(other) {
                Some(Ok(())) => return None,
                Some(Err(end)) => return Some(end),
                None => return unsupported(format!("call to import `{other}`")),
            },
        };
        self.return_from_stub(ret)
    }

    /// Bump allocation from the emulated heap; null when it is used up.
    fn allocate(&mut self, n: u64) -> u64 {
        let size = n.max(1).div_ceil(16) * 16;
        if self.heap_next + size > self.layout.heap_base + self.layout.heap_size {
            return 0;
        }
        let p = self.heap_next;
        self.heap_next += size;
        p
    }

    /// Output to the oracle's `stdout` or `stderr`; any other stream ends the case as unsupported.
    fn write_stream(
        &mut self,
        stream: u64,
        bytes: &[u8],
        name: &str,
    ) -> Option<Option<Termination>> {
        if stream == self.layout.stdout_file() {
            self.stdout.extend_from_slice(bytes);
        } else if stream == self.layout.stderr_file() {
            self.stderr.extend_from_slice(bytes);
        } else {
            return Some(Some(Termination::Unsupported {
                detail: format!("{name} to FILE* {stream:#x}"),
            }));
        }
        None
    }

    /// The C library's math functions, computed by the host's (the same library the original
    /// links). `None` when `name` is not one of them; `Some(Ok(()))` when the call returned.
    fn math(&mut self, name: &str) -> Option<Result<(), Termination>> {
        let d = |v: u64| f64::from_bits(v);
        let f = |v: u64| f32::from_bits(v as u32);
        if !STUBBED_IMPORTS.contains(&name) {
            return None;
        }
        // The `float` variants end in `f`; every double one does not.
        let double = !name.ends_with('f');
        let a = incoming_float_arg(&mut self.m, 0, double);
        let b = incoming_float_arg(&mut self.m, 1, double);
        enum R {
            D(f64),
            F(f32),
            I(i64),
        }
        let r = match name {
            "sqrt" => R::D(d(a).sqrt()),
            "sqrtf" => R::F(f(a).sqrt()),
            "sin" => R::D(d(a).sin()),
            "sinf" => R::F(f(a).sin()),
            "cos" => R::D(d(a).cos()),
            "cosf" => R::F(f(a).cos()),
            "pow" => R::D(d(a).powf(d(b))),
            "powf" => R::F(f(a).powf(f(b))),
            "exp" => R::D(d(a).exp()),
            "expf" => R::F(f(a).exp()),
            "log" => R::D(d(a).ln()),
            "logf" => R::F(f(a).ln()),
            "log2" => R::D(d(a).log2()),
            "log2f" => R::F(f(a).log2()),
            "log10" => R::D(d(a).log10()),
            "log10f" => R::F(f(a).log10()),
            "floor" => R::D(d(a).floor()),
            "floorf" => R::F(f(a).floor()),
            "ceil" => R::D(d(a).ceil()),
            "ceilf" => R::F(f(a).ceil()),
            "round" => R::D(d(a).round()),
            "roundf" => R::F(f(a).round()),
            "fabs" => R::D(d(a).abs()),
            "fabsf" => R::F(f(a).abs()),
            "fmod" => R::D(d(a) % d(b)),
            "fmodf" => R::F(f(a) % f(b)),
            "atan2" => R::D(d(a).atan2(d(b))),
            "atan2f" => R::F(f(a).atan2(f(b))),
            "lround" | "lroundf" => {
                let r = if name == "lround" {
                    d(a).round()
                } else {
                    f64::from(f(a).round())
                };
                R::I(
                    if r.is_nan() || r >= i64::MAX as f64 || r < i64::MIN as f64 {
                        i64::MIN
                    } else {
                        r as i64
                    },
                )
            }
            _ => return None,
        };
        let ret = match r {
            R::D(v) => {
                if set_float_return(&mut self.m, v.to_bits(), true).is_err() {
                    return Some(Err(Termination::Fault {
                        detail: format!("{name}: cannot set the result"),
                    }));
                }
                None
            }
            R::F(v) => {
                if set_float_return(&mut self.m, u64::from(v.to_bits()), false).is_err() {
                    return Some(Err(Termination::Fault {
                        detail: format!("{name}: cannot set the result"),
                    }));
                }
                None
            }
            R::I(v) => Some(v as u64),
        };
        // A floating-point result leaves the integer result register zero (as the x86-64 oracle
        // always did), except on soft-float RISC-V 32, where they are the same registers.
        let end = match ret {
            Some(v) => self.return_from_stub(v),
            None if self.image.arch != Arch::Riscv32 => self.return_from_stub(0),
            None => self.return_only(),
        };
        Some(match end {
            None => Ok(()),
            Some(end) => Err(end),
        })
    }

    /// Returns to the caller of a stub with `ret` as its integer result.
    fn return_from_stub(&mut self, ret: u64) -> Option<Termination> {
        if set_int_return(&mut self.m, ret).is_err() {
            return Some(Termination::Fault {
                detail: "cannot set the stub's result".into(),
            });
        }
        self.return_only()
    }

    /// Returns to the caller of a stub, leaving the result registers as they are.
    fn return_only(&mut self) -> Option<Termination> {
        if return_to_caller(&mut self.m) {
            None
        } else {
            Some(Termination::Fault {
                detail: "stub return address unreadable".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal x86-64 ELF with one PT_LOAD program header.
    fn elf_with_load(vaddr: u64, off: u64, filesz: u64, memsz: u64) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 56 + 16];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // 64-bit
        b[5] = 1; // little endian
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let ph = 64;
        b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
        b[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
        b[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
        b[ph + 24..ph + 32].copy_from_slice(&vaddr.to_le_bytes());
        b[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
        b[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    /// Loading must fail cleanly (no panic, no abort, no huge allocation) before the emulator or
    /// its SLEIGH specs are needed.
    fn refused(vaddr: u64, off: u64, filesz: u64, memsz: u64) -> String {
        let cfg = OracleConfig {
            ghidra_home: Some(PathBuf::from("/nonexistent")),
            ..OracleConfig::default()
        };
        match FunctionOracle::from_bytes(&elf_with_load(vaddr, off, filesz, memsz), &cfg) {
            Err(RewriteError::Image(m)) => m,
            Err(other) => panic!("unexpected error kind: {other}"),
            Ok(_) => panic!("hostile ELF was accepted"),
        }
    }

    #[test]
    fn a_huge_memsz_is_refused_not_allocated() {
        let m = refused(0x1000, 0, 16, 1 << 46);
        assert!(m.contains("256 MiB") || m.contains("address space"), "{m}");
        let m = refused(0x1000, 0, 16, 300 << 20);
        assert!(m.contains("256 MiB"), "{m}");
    }

    #[test]
    fn address_arithmetic_overflow_is_refused() {
        let m = refused(u64::MAX - 8, 0, 0, 0x2000);
        assert!(m.contains("overflow") || m.contains("address space"), "{m}");
        let m = refused(0x1000, 0, 0, u64::MAX);
        assert!(m.contains("overflow") || m.contains("address space"), "{m}");
        let m = refused(0x1000, u64::MAX - 4, 16, 16);
        assert!(m.contains("beyond end of file"), "{m}");
    }

    #[test]
    fn filesz_beyond_memsz_is_refused_instead_of_panicking() {
        let m = refused(0x1000, 0, 64, 16);
        assert!(m.contains("exceeds"), "{m}");
    }

    #[test]
    fn a_segment_reaching_past_the_file_is_refused() {
        let m = refused(0x1000, 100, 1 << 20, 1 << 20);
        assert!(m.contains("beyond end of file"), "{m}");
    }
}

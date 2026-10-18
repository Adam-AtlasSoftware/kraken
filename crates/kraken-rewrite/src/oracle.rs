//! The function oracle: runs one function of an x86-64 System V ELF under emulation and reports
//! what it did.
//!
//! The emulator is icicle-emu (SLEIGH p-code interpreter, `MIT OR Apache-2.0`), driven as a bare
//! CPU: the ELF's `PT_LOAD` segments are mapped by hand, relocations are applied, every import
//! slot is pointed at a stub address, and a call is set up per the System V AMD64 convention
//! (integer arguments in registers, a sentinel return address). Stubs are handled by the host
//! when the program counter reaches them (a breakpoint), never emulated.
//!
//! What it passes: integers and pointers in the integer registers, `double`s in `xmm0` to `xmm7`,
//! pointer graphs placed where the native runner places them, and two host callbacks for
//! function-pointer parameters (see `abi`). What it deliberately does not do: run `main`, the
//! dynamic loader or libc; single-precision floats and vector arguments; stack-passed arguments;
//! threads; syscalls (a `syscall` instruction faults); floating-point `printf`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use icicle_cpu::mem::{Mapping, perm};
use icicle_cpu::{Config, VmExit};
use icicle_vm::Vm;
use object::elf;
use object::read::elf::{ElfFile64, ProgramHeader};
use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget};

use crate::abi::{
    Arg, Callback, GlobalWrite, Observation, Param, Ret, Signature, Termination, callback_tag,
    check_graph, mask, place_object,
};
use crate::clib::{ctype_b_table, format_printf};
use crate::error::RewriteError;

const PAGE: u64 = 0x1000;
const STACK_BASE: u64 = 0x7ffd_0000_0000;
const STACK_SIZE: u64 = 0x1_0000;
const STUB_BASE: u64 = 0x7ffe_0000_0000;
const RETURN_ADDR: u64 = STUB_BASE + 0xff0;
/// The host callbacks a function pointer parameter can be given (`Callback::index` apart).
const CALLBACK_BASE: u64 = STUB_BASE + 0xfd0;
const STUB_DATA: u64 = STUB_BASE + 0x1_0000;
const CTYPE_PTR_CELL: u64 = STUB_DATA;
const STDOUT_CELL: u64 = STUB_DATA + 0x10;
const STDERR_CELL: u64 = STUB_DATA + 0x18;
const CTYPE_TABLE: u64 = STUB_DATA + 0x100;
/// The `FILE *` values `stdout` and `stderr` hold inside the oracle.
const STDOUT_FILE: u64 = STUB_DATA + 0x20;
const STDERR_FILE: u64 = STUB_DATA + 0x30;
const MAX_BUFFER: usize = 0x10_0000;

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

/// Where the emulator's `malloc` hands out memory (a bump allocator; `free` does nothing).
const HEAP_BASE: u64 = 0x7ffc_0000_0000;
const HEAP_SIZE: u64 = 0x100_0000;
/// The thread block `fs:` points at; `fs:0x28` holds the stack protector's canary.
const TLS_BASE: u64 = STUB_BASE + 0x4_0000;
const STACK_CANARY: u64 = 0x2f8b_1c3a_5d6e_7f00;

/// Oracle settings.
#[derive(Debug, Clone)]
pub struct OracleConfig {
    /// A Ghidra install (the oracle compiles its x86 SLEIGH spec). Default: `KRAKEN_GHIDRA_HOME`,
    /// else the runtime `kraken setup` provisioned.
    pub ghidra_home: Option<PathBuf>,
    /// Instruction budget per call.
    pub max_instructions: u64,
    /// Where a position-independent executable is loaded.
    pub load_base: u64,
}

impl Default for OracleConfig {
    fn default() -> Self {
        OracleConfig {
            ghidra_home: None,
            max_instructions: 5_000_000,
            load_base: 0x5555_5555_4000,
        }
    }
}

/// `Ghidra/Processors` of the configured install.
pub fn find_processors(cfg: &OracleConfig) -> Result<PathBuf, RewriteError> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(h) = &cfg.ghidra_home {
        candidates.push(h.clone());
    }
    if let Some(h) = std::env::var_os("KRAKEN_GHIDRA_HOME").filter(|v| !v.is_empty()) {
        candidates.push(PathBuf::from(h));
    }
    if let Some(layout) = kraken_host::provision::Layout::from_env()
        && let Some(h) = layout.provisioned().ghidra_home
    {
        candidates.push(h);
    }
    candidates
        .into_iter()
        .map(|h| h.join("Ghidra/Processors"))
        .find(|p| p.join("x86/data/languages/x86.ldefs").is_file())
        .ok_or(RewriteError::NoProcessors)
}

/// Where a call's arguments went.
#[derive(Default)]
struct Laid {
    /// Integer register arguments in order.
    ints: Vec<u64>,
    /// `double` arguments as bit patterns, in order.
    doubles: Vec<u64>,
    /// Every object: address and length.
    buffers: Vec<(u64, usize)>,
}

struct Region {
    /// Runtime address of the first byte.
    addr: u64,
    /// Initial contents.
    bytes: Vec<u8>,
    writable: bool,
}

struct Regs {
    xmm: [pcode::VarNode; 8],
    rax: pcode::VarNode,
    rsp: pcode::VarNode,
    /// The base of `fs:`, where the thread block and its stack canary live.
    fs: pcode::VarNode,
    args: [pcode::VarNode; 6],
}

/// A loaded program image plus the emulator that runs functions of it.
pub struct FunctionOracle {
    vm: Vm,
    regs: Regs,
    bias: u64,
    is_pie: bool,
    symbols: BTreeMap<String, u64>,
    /// Stub index to the import it stands for.
    stub_names: Vec<String>,
    regions: Vec<Region>,
    max_instructions: u64,
    stdout: Vec<u8>,
    /// The objects of the call in progress (base address and length), for callback tags.
    objects: Vec<(u64, usize)>,
    /// Callback calls of the call in progress.
    callbacks: Vec<String>,
    stderr: Vec<u8>,
    /// Next free byte of the emulated heap.
    heap_next: u64,
}

impl std::fmt::Debug for FunctionOracle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionOracle")
            .field("bias", &self.bias)
            .field("imports", &self.stub_names)
            .finish_non_exhaustive()
    }
}

fn emu(e: impl std::fmt::Display) -> RewriteError {
    RewriteError::Emulator(e.to_string())
}

fn align_down(v: u64) -> u64 {
    v & !(PAGE - 1)
}

fn checked_align_up(v: u64) -> Option<u64> {
    Some(v.checked_add(PAGE - 1)? & !(PAGE - 1))
}

/// Highest address a segment may end at (the x86-64 user half).
const MAX_ADDRESS: u64 = 1 << 47;
/// Most memory the emulated image may take.
const MAX_IMAGE_BYTES: u64 = 256 << 20;
/// Most dynamic relocations processed.
const MAX_RELOCATIONS: usize = 1 << 20;

impl FunctionOracle {
    /// Loads the ELF at `path` and builds the emulator.
    pub fn load(path: &Path, cfg: &OracleConfig) -> Result<Self, RewriteError> {
        let data = std::fs::read(path)
            .map_err(|e| RewriteError::Image(format!("{}: {e}", path.display())))?;
        Self::from_bytes(&data, cfg)
    }

    /// Loads an ELF from memory.
    pub fn from_bytes(data: &[u8], cfg: &OracleConfig) -> Result<Self, RewriteError> {
        let file = ElfFile64::<object::Endianness>::parse(data)
            .map_err(|e| RewriteError::Image(e.to_string()))?;
        let endian = file.endian();
        if file.elf_header().e_machine.get(endian) != elf::EM_X86_64 {
            return Err(RewriteError::Image("not an x86-64 ELF".into()));
        }
        let is_pie = file.elf_header().e_type.get(endian) == elf::ET_DYN;
        let bias = if is_pie { cfg.load_base } else { 0 };

        // Segments, merged into page regions.
        let mut loads: Vec<(u64, u64, u64, u64, bool)> = Vec::new(); // vaddr, off, filesz, memsz, w
        for ph in file.elf_program_headers() {
            if ph.p_type(endian) == elf::PT_LOAD {
                loads.push((
                    ph.p_vaddr(endian),
                    ph.p_offset(endian),
                    ph.p_filesz(endian),
                    ph.p_memsz(endian),
                    ph.p_flags(endian) & elf::PF_W != 0,
                ));
            }
        }
        if loads.is_empty() {
            return Err(RewriteError::Image("no PT_LOAD segments".into()));
        }
        loads.sort_by_key(|l| l.0);
        let bad = |m: &str| RewriteError::Image(m.to_string());
        let mut ranges: Vec<(u64, u64, bool)> = Vec::new();
        for &(vaddr, off, filesz, memsz, w) in &loads {
            if filesz > memsz {
                return Err(bad("segment file size exceeds its memory size"));
            }
            if off
                .checked_add(filesz)
                .is_none_or(|e| e > data.len() as u64)
            {
                return Err(bad("segment beyond end of file"));
            }
            let end = vaddr
                .checked_add(memsz)
                .and_then(checked_align_up)
                .ok_or_else(|| bad("segment address range overflows"))?;
            if end > MAX_ADDRESS || bias.checked_add(end).is_none() {
                return Err(bad("segment lies beyond the 47-bit address space"));
            }
            let (s, e) = (align_down(vaddr), end);
            match ranges.last_mut() {
                Some(last) if s <= last.1 => {
                    last.1 = last.1.max(e);
                    last.2 |= w;
                }
                _ => ranges.push((s, e, w)),
            }
        }
        // The emulated image is bounded: a hostile program header must not make the daemon
        // allocate gigabytes (or abort on a failed allocation).
        let total = ranges
            .iter()
            .try_fold(0u64, |acc, r| acc.checked_add(r.1 - r.0));
        if total.is_none_or(|t| t > MAX_IMAGE_BYTES) {
            return Err(bad("the loadable segments need more than 256 MiB"));
        }
        let mut regions: Vec<Region> = Vec::with_capacity(ranges.len());
        for &(s, e, _) in &ranges {
            let len = usize::try_from(e - s).map_err(|_| bad("segment too large"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| bad("cannot allocate the segment"))?;
            bytes.resize(len, 0);
            regions.push(Region {
                addr: bias + s,
                bytes,
                writable: false,
            });
        }
        for &(vaddr, off, filesz, _, w) in &loads {
            let idx = ranges
                .iter()
                .position(|r| r.0 <= vaddr && vaddr < r.1)
                .ok_or_else(|| bad("segment outside its range"))?;
            let start = usize::try_from(vaddr - ranges[idx].0).map_err(emu)?;
            let (lo, hi) = (
                usize::try_from(off).map_err(emu)?,
                usize::try_from(off + filesz).map_err(emu)?,
            );
            let src = data
                .get(lo..hi)
                .ok_or_else(|| bad("segment beyond end of file"))?;
            let dst = start
                .checked_add(src.len())
                .and_then(|e| regions[idx].bytes.get_mut(start..e))
                .ok_or_else(|| bad("segment data does not fit its range"))?;
            dst.copy_from_slice(src);
            regions[idx].writable |= w;
        }

        // Symbols.
        let mut symbols = BTreeMap::new();
        for s in file.symbols() {
            if let Ok(name) = s.name()
                && !name.is_empty()
                && s.address() != 0
            {
                symbols.entry(name.to_string()).or_insert(s.address());
            }
        }

        // Relocations: every import slot gets a stub address.
        let mut stub_names: Vec<String> = Vec::new();
        let mut patches: Vec<(u64, u64)> = Vec::new(); // runtime address, value
        // Symbol names by index, built once (a lookup per relocation would be quadratic).
        let dyn_names: std::collections::HashMap<_, String> = file
            .dynamic_symbols()
            .filter_map(|s| s.name().ok().map(|n| (s.index(), n.to_string())))
            .collect();
        if let Some(relocs) = file.dynamic_relocations() {
            for (offset, rel) in relocs {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    continue;
                };
                let name = match rel.target() {
                    RelocationTarget::Symbol(idx) => {
                        dyn_names.get(&idx).cloned().unwrap_or_default()
                    }
                    _ => String::new(),
                };
                if patches.len() >= MAX_RELOCATIONS {
                    return Err(bad("too many relocations"));
                }
                let slot = bias.wrapping_add(offset);
                match r_type {
                    elf::R_X86_64_RELATIVE => {
                        patches.push((slot, bias.wrapping_add(rel.addend() as u64)));
                    }
                    elf::R_X86_64_JUMP_SLOT | elf::R_X86_64_64 | elf::R_X86_64_GLOB_DAT
                        if !name.is_empty() =>
                    {
                        let value = match name.as_str() {
                            "stdout" if r_type == elf::R_X86_64_GLOB_DAT => STDOUT_CELL,
                            "stderr" if r_type == elf::R_X86_64_GLOB_DAT => STDERR_CELL,
                            _ => {
                                stub_names.push(name);
                                STUB_BASE + 0x10 * stub_names.len() as u64
                            }
                        };
                        patches.push((slot, value));
                    }
                    elf::R_X86_64_COPY => match name.as_str() {
                        "stdout" => patches.push((slot, STDOUT_FILE)),
                        "stderr" => patches.push((slot, STDERR_FILE)),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
        for (addr, value) in patches {
            let region = regions
                .iter_mut()
                .find(|r| {
                    addr.checked_add(8).is_some_and(|end| {
                        r.addr <= addr && end <= r.addr.saturating_add(r.bytes.len() as u64)
                    })
                })
                .ok_or_else(|| RewriteError::Image(format!("relocation at {addr:#x} unmapped")))?;
            let off = usize::try_from(addr - region.addr).map_err(emu)?;
            region
                .bytes
                .get_mut(off..off + 8)
                .ok_or_else(|| bad("relocation outside its segment"))?
                .copy_from_slice(&value.to_le_bytes());
        }

        // The emulator.
        let processors = find_processors(cfg)?;
        let mut config = Config::from_target_triple("x86_64-none");
        config.enable_jit = false;
        config.enable_shadow_stack = false;
        let mut vm = icicle_vm::build_with_path(&config, &processors)
            .map_err(|e| RewriteError::Emulator(format!("{e:?}")))?;
        let var = |vm: &Vm, n: &str| {
            vm.cpu
                .arch
                .sleigh
                .get_varnode(n)
                .ok_or_else(|| RewriteError::Emulator(format!("no register {n}")))
        };
        let regs = Regs {
            xmm: [
                var(&vm, "XMM0")?,
                var(&vm, "XMM1")?,
                var(&vm, "XMM2")?,
                var(&vm, "XMM3")?,
                var(&vm, "XMM4")?,
                var(&vm, "XMM5")?,
                var(&vm, "XMM6")?,
                var(&vm, "XMM7")?,
            ],
            rax: var(&vm, "RAX")?,
            rsp: var(&vm, "RSP")?,
            fs: var(&vm, "FS_OFFSET")?,
            args: [
                var(&vm, "RDI")?,
                var(&vm, "RSI")?,
                var(&vm, "RDX")?,
                var(&vm, "RCX")?,
                var(&vm, "R8")?,
                var(&vm, "R9")?,
            ],
        };
        let rwx = perm::READ | perm::WRITE | perm::EXEC;
        let mut map = |addr: u64, len: u64| {
            if vm.cpu.mem.map_memory_len(
                addr,
                len,
                Mapping {
                    perm: rwx,
                    value: 0,
                },
            ) {
                Ok(())
            } else {
                Err(RewriteError::Emulator(format!(
                    "cannot map {len:#x} bytes at {addr:#x}"
                )))
            }
        };
        for r in &regions {
            map(r.addr, r.bytes.len() as u64)?;
        }
        map(STACK_BASE, STACK_SIZE)?;
        map(STUB_BASE, PAGE)?;
        map(STUB_DATA, 0x2000)?;
        map(HEAP_BASE, HEAP_SIZE)?;
        map(TLS_BASE, PAGE)?;

        // Stub code page: `ret`, so a stray fall-through returns; the data page.
        let ret_page = vec![0xc3u8; PAGE as usize];
        vm.cpu
            .mem
            .write_bytes(STUB_BASE, &ret_page, perm::NONE)
            .map_err(|e| emu(format!("{e:?}")))?;
        let table = ctype_b_table();
        let w = |vm: &mut Vm, addr: u64, b: &[u8]| {
            vm.cpu
                .mem
                .write_bytes(addr, b, perm::NONE)
                .map_err(|e| emu(format!("{e:?}")))
        };
        w(&mut vm, CTYPE_TABLE, &table)?;
        w(
            &mut vm,
            CTYPE_PTR_CELL,
            &(CTYPE_TABLE + 128 * 2).to_le_bytes(),
        )?;
        w(&mut vm, STDOUT_CELL, &STDOUT_FILE.to_le_bytes())?;
        w(&mut vm, STDERR_CELL, &STDERR_FILE.to_le_bytes())?;
        w(&mut vm, TLS_BASE + 0x28, &STACK_CANARY.to_le_bytes())?;
        vm.add_breakpoint(RETURN_ADDR);
        for cb in Callback::ALL {
            vm.add_breakpoint(CALLBACK_BASE + 0x10 * cb.index());
        }
        for i in 0..stub_names.len() {
            vm.add_breakpoint(STUB_BASE + 0x10 * (i as u64 + 1));
        }

        Ok(FunctionOracle {
            vm,
            regs,
            bias,
            is_pie,
            symbols,
            stub_names,
            regions,
            max_instructions: cfg.max_instructions,
            objects: Vec::new(),
            callbacks: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            heap_next: HEAP_BASE,
        })
    }

    /// The ELF virtual address of the function KRAKEN reports at `address` for a program loaded
    /// at `image_base`: a position-independent executable's addresses include the image base
    /// Ghidra chose, a fixed-address executable's are the ELF addresses themselves.
    pub fn elf_vaddr(&self, address: u64, image_base: u64) -> u64 {
        if self.is_pie {
            address.wrapping_sub(image_base)
        } else {
            address
        }
    }

    /// The ELF virtual address of a symbol (not including the load bias).
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
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
        self.heap_next = HEAP_BASE;
        self.objects.clear();

        let mut mapped: Vec<(u64, u64)> = Vec::new();
        // A bug in the emulator (an arithmetic overflow on a wild address) must not take the
        // whole run down: the case is one the oracle could not evaluate.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.lay_out(args, sig, &mut mapped).and_then(|laid| {
                self.run_call(entry, sig, &laid.ints, &laid.doubles, &laid.buffers)
            })
        }))
        .unwrap_or_else(|_| {
            Ok(Observation::failed(Termination::Unsupported {
                detail: "the emulator failed on this case".into(),
            }))
        });
        self.objects.clear();
        for (addr, len) in mapped {
            self.vm.cpu.mem.unmap_memory_len(addr, len);
        }
        result
    }

    /// Maps one object into its own region, page padded with unmapped space around it, the data
    /// flush against the end (rounded down to 8 bytes) so a read past it faults. Returns where the data starts.
    fn map_object(
        &mut self,
        data: &[u8],
        mapped: &mut Vec<(u64, u64)>,
        n: usize,
    ) -> Result<u64, RewriteError> {
        if data.len() > MAX_BUFFER {
            return Err(RewriteError::Unsupported("buffer over 1 MiB".into()));
        }
        let (addr, len, at) = place_object(n, data.len());
        let rw = perm::READ | perm::WRITE;
        if !self
            .vm
            .cpu
            .mem
            .map_memory_len(addr, len, Mapping { perm: rw, value: 0 })
        {
            return Err(emu("cannot map buffer"));
        }
        mapped.push((addr, len));
        self.vm
            .cpu
            .mem
            .write_bytes(at, data, perm::NONE)
            .map_err(|e| emu(format!("{e:?}")))?;
        Ok(at)
    }

    fn lay_out(
        &mut self,
        args: &[Arg],
        sig: &Signature,
        mapped: &mut Vec<(u64, u64)>,
    ) -> Result<Laid, RewriteError> {
        let mut laid = Laid::default();
        for (i, (p, a)) in sig.params.iter().zip(args).enumerate() {
            match (p, a) {
                (Param::Int { bits, .. }, Arg::Int { value }) => {
                    laid.ints.push(value & mask(*bits));
                }
                (Param::Double, Arg::Double { bits }) => laid.doubles.push(*bits),
                (Param::Float, Arg::Float { bits }) => laid.doubles.push(u64::from(*bits)),
                (Param::FnPtr, Arg::FnPtr { callback }) => {
                    laid.ints.push(CALLBACK_BASE + 0x10 * callback.index());
                }
                (Param::Buf, Arg::Buf { data }) => {
                    let at = self.map_object(data, mapped, laid.buffers.len())?;
                    laid.buffers.push((at, data.len()));
                    laid.ints.push(at);
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
                        self.vm
                            .cpu
                            .mem
                            .write_bytes(at, &target.to_le_bytes(), perm::NONE)
                            .map_err(|e| emu(format!("{e:?}")))?;
                    }
                    laid.ints.push(laid.buffers[first].0);
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
        for r in &self.regions {
            self.vm
                .cpu
                .mem
                .write_bytes(r.addr, &r.bytes, perm::NONE)
                .map_err(|e| emu(format!("{e:?}")))?;
        }
        self.vm
            .cpu
            .mem
            .fill_mem(STACK_BASE, STACK_SIZE, 0)
            .map_err(|e| emu(format!("{e:?}")))?;
        Ok(())
    }

    fn run_call(
        &mut self,
        entry: u64,
        sig: &Signature,
        values: &[u64],
        doubles: &[u64],
        buffers: &[(u64, usize)],
    ) -> Result<Observation, RewriteError> {
        let cpu = &mut self.vm.cpu;
        for reg in [self.regs.rax].iter().chain(&self.regs.args) {
            cpu.write_reg(*reg, 0);
        }
        for reg in &self.regs.xmm {
            cpu.write_reg(*reg, 0);
        }
        for (reg, v) in self.regs.args.iter().zip(values) {
            cpu.write_reg(*reg, *v);
        }
        for (reg, v) in self.regs.xmm.iter().zip(doubles) {
            cpu.write_reg(*reg, *v);
        }
        // Entry stack alignment: (rsp + 8) % 16 == 0 after the return address is pushed.
        let sp = STACK_BASE + STACK_SIZE - 0x100 - 8;
        cpu.mem
            .write_bytes(sp, &RETURN_ADDR.to_le_bytes(), perm::NONE)
            .map_err(|e| emu(format!("{e:?}")))?;
        cpu.write_reg(self.regs.rsp, sp);
        cpu.write_reg(self.regs.fs, TLS_BASE);
        cpu.write_pc(self.bias + entry);

        let start = self.vm.cpu.icount;
        self.vm.icount_limit = start.saturating_add(self.max_instructions);
        let termination = loop {
            match self.vm.run() {
                VmExit::Breakpoint => {
                    let pc = self.vm.cpu.read_pc();
                    if pc == RETURN_ADDR {
                        break Termination::Returned;
                    }
                    if let Some(cb) = pc
                        .checked_sub(CALLBACK_BASE)
                        .filter(|d| d % 0x10 == 0 && d / 0x10 < Callback::ALL.len() as u64)
                        .map(|d| Callback::ALL[(d / 0x10) as usize])
                    {
                        if let Some(end) = self.run_callback(cb) {
                            break end;
                        }
                        continue;
                    }
                    let idx = pc
                        .checked_sub(STUB_BASE + 0x10)
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
                VmExit::InstructionLimit => break Termination::Timeout,
                VmExit::UnhandledException((code, value)) => {
                    break Termination::Fault {
                        detail: format!(
                            "{code:?} ({value:#x}) at pc {:#x}",
                            self.vm.cpu.read_pc().wrapping_sub(self.bias)
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
        let instructions = self.vm.cpu.icount.saturating_sub(start);
        let mut obs = Observation::failed(termination.clone());
        obs.instructions = instructions;
        obs.stdout = self.stdout.clone();
        obs.stderr = self.stderr.clone();
        obs.global_writes = self.global_writes()?;
        obs.callbacks = self.callbacks.clone();
        if termination == Termination::Returned {
            match sig.ret {
                Ret::Int { bits, .. } => {
                    obs.ret = Some(self.vm.cpu.read_reg(self.regs.rax) & mask(bits));
                }
                Ret::Double => obs.ret = Some(self.vm.cpu.read_reg(self.regs.xmm[0])),
                Ret::Float => {
                    obs.ret = Some(self.vm.cpu.read_reg(self.regs.xmm[0]) & 0xffff_ffff);
                }
                Ret::Void | Ret::Ptr => {}
            }
            for &(addr, len) in buffers {
                let mut b = vec![0u8; len];
                self.vm
                    .cpu
                    .mem
                    .read_bytes(addr, &mut b, perm::NONE)
                    .map_err(|e| emu(format!("{e:?}")))?;
                obs.buffers.push(b);
            }
        }
        Ok(obs)
    }

    /// A call of the function under test to one of the host callbacks: records it, answers it as
    /// [`Callback::result`] says and returns to the caller. `None` means the call goes on.
    fn run_callback(&mut self, cb: Callback) -> Option<Termination> {
        let (a, b) = (self.stub_arg(0), self.stub_arg(1));
        let objects = self.objects.clone();
        let cpu = &mut self.vm.cpu;
        let mut read32 = |addr: u64| {
            let mut w = [0u8; 4];
            cpu.mem
                .read_bytes(addr, &mut w, perm::NONE)
                .ok()
                .map(|_| i32::from_le_bytes(w))
        };
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
        for r in self.regions.iter().filter(|r| r.writable) {
            let mut now = vec![0u8; r.bytes.len()];
            self.vm
                .cpu
                .mem
                .read_bytes(r.addr, &mut now, perm::NONE)
                .map_err(|e| emu(format!("{e:?}")))?;
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
                    vaddr: r.addr - self.bias + s as u64,
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
        if let Some(reg) = self.regs.args.get(n) {
            return self.vm.cpu.read_reg(*reg);
        }
        let sp = self.vm.cpu.read_reg(self.regs.rsp);
        let mut b = [0u8; 8];
        let at = sp.wrapping_add(8 + 8 * (n as u64 - 6));
        if self.vm.cpu.mem.read_bytes(at, &mut b, perm::NONE).is_err() {
            return 0;
        }
        u64::from_le_bytes(b)
    }

    fn read_cstr(&mut self, addr: u64) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        for i in 0..0x1_0000u64 {
            let mut b = [0u8; 1];
            self.vm
                .cpu
                .mem
                .read_bytes(addr.wrapping_add(i), &mut b, perm::NONE)
                .ok()?;
            if b[0] == 0 {
                return Some(out);
            }
            out.push(b[0]);
        }
        None
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
        let mut cstr = |a: u64| this.borrow_mut().read_cstr(a);
        format_printf(&fmt, &mut next, &mut cstr)
    }

    /// Runs the stub for import `name`. `None` means the call continues (returned to the caller).
    fn run_stub(&mut self, name: &str) -> Option<Termination> {
        let unsupported = |detail: String| Some(Termination::Unsupported { detail });
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
                        match stream {
                            STDOUT_FILE => self.stdout.extend_from_slice(&b),
                            STDERR_FILE => self.stderr.extend_from_slice(&b),
                            other => {
                                return unsupported(format!("fprintf to FILE* {other:#x}"));
                            }
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
            "memcpy" | "memmove" | "memset" => {
                let (dst, a1, n) = (self.stub_arg(0), self.stub_arg(1), self.stub_arg(2));
                if n > MAX_BUFFER as u64 {
                    return unsupported(format!("{name} of {n} bytes"));
                }
                let mut bytes = vec![0u8; n as usize];
                if name == "memset" {
                    bytes.fill(a1 as u8);
                } else if self
                    .vm
                    .cpu
                    .mem
                    .read_bytes(a1, &mut bytes, perm::NONE)
                    .is_err()
                {
                    return Some(Termination::Fault {
                        detail: format!("{name} source {a1:#x} unreadable"),
                    });
                }
                if self
                    .vm
                    .cpu
                    .mem
                    .write_bytes(dst, &bytes, perm::NONE)
                    .is_err()
                {
                    return Some(Termination::Fault {
                        detail: format!("{name} destination {dst:#x} unwritable"),
                    });
                }
                dst
            }
            "__ctype_b_loc" => CTYPE_PTR_CELL,
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
                if self
                    .vm
                    .cpu
                    .mem
                    .read_bytes(p, &mut bytes, perm::NONE)
                    .is_err()
                {
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
                self.allocate(n)
            }
            "free" | "_ZdlPv" | "_ZdlPvm" | "_ZdaPv" | "_ZdaPvm" | "operator.delete"
            | "operator.delete[]" => {
                // Memory the function allocated itself is let go; freeing an object the test
                // passed in cannot be reproduced by the native side (its allocator never saw it).
                let p = self.stub_arg(0);
                if p != 0 && !(HEAP_BASE..HEAP_BASE + HEAP_SIZE).contains(&p) {
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
        if self.heap_next + size > HEAP_BASE + HEAP_SIZE {
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
        match stream {
            STDOUT_FILE => self.stdout.extend_from_slice(bytes),
            STDERR_FILE => self.stderr.extend_from_slice(bytes),
            other => {
                return Some(Some(Termination::Unsupported {
                    detail: format!("{name} to FILE* {other:#x}"),
                }));
            }
        }
        None
    }

    fn xmm(&mut self, n: usize) -> u64 {
        self.vm.cpu.read_reg(self.regs.xmm[n])
    }

    /// The C library's math functions, computed by the host's (the same library the original
    /// links). `None` when `name` is not one of them; `Some(Ok(()))` when the call returned.
    fn math(&mut self, name: &str) -> Option<Result<(), Termination>> {
        let d = |v: u64| f64::from_bits(v);
        let f = |v: u64| f32::from_bits(v as u32);
        let (a, b) = (self.xmm(0), self.xmm(1));
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
                self.vm.cpu.write_reg(self.regs.xmm[0], v.to_bits());
                0
            }
            R::F(v) => {
                self.vm
                    .cpu
                    .write_reg(self.regs.xmm[0], u64::from(v.to_bits()));
                0
            }
            R::I(v) => v as u64,
        };
        Some(match self.return_from_stub(ret) {
            None => Ok(()),
            Some(end) => Err(end),
        })
    }

    /// Returns to the caller of a stub with `ret` in RAX: pops the return address.
    fn return_from_stub(&mut self, ret: u64) -> Option<Termination> {
        let sp = self.vm.cpu.read_reg(self.regs.rsp);
        let mut b = [0u8; 8];
        if self.vm.cpu.mem.read_bytes(sp, &mut b, perm::NONE).is_err() {
            return Some(Termination::Fault {
                detail: "stub return address unreadable".into(),
            });
        }
        self.vm.cpu.write_reg(self.regs.rax, ret);
        self.vm.cpu.write_reg(self.regs.rsp, sp.wrapping_add(8));
        self.vm.cpu.write_pc(u64::from_le_bytes(b));
        None
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
        assert!(m.contains("256 MiB") || m.contains("47-bit"), "{m}");
        let m = refused(0x1000, 0, 16, 300 << 20);
        assert!(m.contains("256 MiB"), "{m}");
    }

    #[test]
    fn address_arithmetic_overflow_is_refused() {
        let m = refused(u64::MAX - 8, 0, 0, 0x2000);
        assert!(m.contains("overflow") || m.contains("47-bit"), "{m}");
        let m = refused(0x1000, 0, 0, u64::MAX);
        assert!(m.contains("overflow") || m.contains("47-bit"), "{m}");
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

//! The function oracle: runs one function of an x86-64 System V ELF under emulation and reports
//! what it did.
//!
//! The emulator is icicle-emu (SLEIGH p-code interpreter, `MIT OR Apache-2.0`), driven as a bare
//! CPU: the ELF's `PT_LOAD` segments are mapped by hand, relocations are applied, every import
//! slot is pointed at a stub address, and a call is set up per the System V AMD64 convention
//! (integer arguments in registers, a sentinel return address). Stubs are handled by the host
//! when the program counter reaches them (a breakpoint), never emulated.
//!
//! What it deliberately does not do: run `main`, the dynamic loader or libc; floating point and
//! SSE arguments; stack-passed arguments; threads; syscalls (a `syscall` instruction faults).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use icicle_cpu::mem::{Mapping, perm};
use icicle_cpu::{Config, VmExit};
use icicle_vm::Vm;
use object::elf;
use object::read::elf::{ElfFile64, ProgramHeader};
use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget};

use crate::abi::{Arg, GlobalWrite, Observation, Param, Ret, Signature, Termination, mask};
use crate::clib::{ctype_b_table, format_printf};
use crate::error::RewriteError;

const PAGE: u64 = 0x1000;
const STACK_BASE: u64 = 0x7ffd_0000_0000;
const STACK_SIZE: u64 = 0x1_0000;
const STUB_BASE: u64 = 0x7ffe_0000_0000;
const RETURN_ADDR: u64 = STUB_BASE + 0xff0;
const STUB_DATA: u64 = STUB_BASE + 0x1_0000;
const CTYPE_PTR_CELL: u64 = STUB_DATA;
const STDOUT_CELL: u64 = STUB_DATA + 0x10;
const STDERR_CELL: u64 = STUB_DATA + 0x18;
const CTYPE_TABLE: u64 = STUB_DATA + 0x100;
/// The `FILE *` values `stdout` and `stderr` hold inside the oracle.
const STDOUT_FILE: u64 = STUB_DATA + 0x20;
const STDERR_FILE: u64 = STUB_DATA + 0x30;
const BUFFER_BASE: u64 = 0x6000_0000_0000;
const BUFFER_STRIDE: u64 = 0x100_0000;
const MAX_BUFFER: usize = 0x10_0000;

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

struct Region {
    /// Runtime address of the first byte.
    addr: u64,
    /// Initial contents.
    bytes: Vec<u8>,
    writable: bool,
}

struct Regs {
    rax: pcode::VarNode,
    rsp: pcode::VarNode,
    args: [pcode::VarNode; 6],
}

/// A loaded program image plus the emulator that runs functions of it.
pub struct FunctionOracle {
    vm: Vm,
    regs: Regs,
    bias: u64,
    symbols: BTreeMap<String, u64>,
    /// Stub index to the import it stands for.
    stub_names: Vec<String>,
    regions: Vec<Region>,
    max_instructions: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
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

fn align_up(v: u64) -> u64 {
    (v + PAGE - 1) & !(PAGE - 1)
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
        let processors = find_processors(cfg)?;
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
        let mut ranges: Vec<(u64, u64, bool)> = Vec::new();
        for &(vaddr, _, _, memsz, w) in &loads {
            let (s, e) = (align_down(vaddr), align_up(vaddr + memsz));
            match ranges.last_mut() {
                Some(last) if s <= last.1 => {
                    last.1 = last.1.max(e);
                    last.2 |= w;
                }
                _ => ranges.push((s, e, w)),
            }
        }
        let mut regions: Vec<Region> = ranges
            .iter()
            .map(|&(s, e, _)| Region {
                addr: bias + s,
                bytes: vec![0; usize::try_from(e - s).unwrap_or(0)],
                writable: false,
            })
            .collect();
        for &(vaddr, off, filesz, _, w) in &loads {
            let idx = ranges
                .iter()
                .position(|r| r.0 <= vaddr && vaddr < r.1)
                .ok_or_else(|| RewriteError::Image("segment outside its range".into()))?;
            let start = usize::try_from(vaddr - ranges[idx].0).map_err(emu)?;
            let src = data
                .get(
                    usize::try_from(off).map_err(emu)?
                        ..usize::try_from(off + filesz).map_err(emu)?,
                )
                .ok_or_else(|| RewriteError::Image("segment beyond end of file".into()))?;
            regions[idx].bytes[start..start + src.len()].copy_from_slice(src);
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
        let dynsyms = file.dynamic_symbol_table();
        if let Some(relocs) = file.dynamic_relocations() {
            for (offset, rel) in relocs {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    continue;
                };
                let name = match rel.target() {
                    RelocationTarget::Symbol(idx) => dynsyms
                        .as_ref()
                        .and_then(|_| file.dynamic_symbols().find(|s| s.index() == idx))
                        .and_then(|s| s.name().ok())
                        .unwrap_or("")
                        .to_string(),
                    _ => String::new(),
                };
                let slot = bias + offset;
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
                .find(|r| r.addr <= addr && addr + 8 <= r.addr + r.bytes.len() as u64)
                .ok_or_else(|| RewriteError::Image(format!("relocation at {addr:#x} unmapped")))?;
            let off = usize::try_from(addr - region.addr).map_err(emu)?;
            region.bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }

        // The emulator.
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
            rax: var(&vm, "RAX")?,
            rsp: var(&vm, "RSP")?,
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
        vm.add_breakpoint(RETURN_ADDR);
        for i in 0..stub_names.len() {
            vm.add_breakpoint(STUB_BASE + 0x10 * (i as u64 + 1));
        }

        Ok(FunctionOracle {
            vm,
            regs,
            bias,
            symbols,
            stub_names,
            regions,
            max_instructions: cfg.max_instructions,
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
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
        if sig.params.len() > 6 {
            return Err(RewriteError::Unsupported(
                "more than six parameters (stack arguments are not modelled)".into(),
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

        // Buffers get their own regions, page padded, with unmapped space around them.
        let mut mapped: Vec<(u64, u64)> = Vec::new();
        let mut values: Vec<u64> = Vec::new();
        let mut buffers: Vec<(u64, usize)> = Vec::new();
        for (i, (p, a)) in sig.params.iter().zip(args).enumerate() {
            match (p, a) {
                (Param::Int { bits, .. }, Arg::Int { value }) => values.push(value & mask(*bits)),
                (Param::Buf, Arg::Buf { data }) => {
                    if data.len() > MAX_BUFFER {
                        return Err(RewriteError::Unsupported("buffer over 1 MiB".into()));
                    }
                    let addr = BUFFER_BASE + BUFFER_STRIDE * buffers.len() as u64;
                    let len = align_up(data.len().max(1) as u64);
                    // Flush the data against the end of the mapping so reads past it fault.
                    let at = addr + len - data.len() as u64;
                    let rwx = perm::READ | perm::WRITE;
                    if !self.vm.cpu.mem.map_memory_len(
                        addr,
                        len,
                        Mapping {
                            perm: rwx,
                            value: 0,
                        },
                    ) {
                        return Err(emu("cannot map buffer"));
                    }
                    mapped.push((addr, len));
                    self.vm
                        .cpu
                        .mem
                        .write_bytes(at, data, perm::NONE)
                        .map_err(|e| emu(format!("{e:?}")))?;
                    buffers.push((at, data.len()));
                    values.push(at);
                }
                _ => {
                    return Err(RewriteError::Unsupported(format!(
                        "argument {i} does not match its parameter kind"
                    )));
                }
            }
        }
        let obs = self.run_call(entry, sig, &values, &buffers);
        for (addr, len) in mapped {
            self.vm.cpu.mem.unmap_memory_len(addr, len);
        }
        obs
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
        buffers: &[(u64, usize)],
    ) -> Result<Observation, RewriteError> {
        let cpu = &mut self.vm.cpu;
        for reg in [self.regs.rax].iter().chain(&self.regs.args) {
            cpu.write_reg(*reg, 0);
        }
        for (reg, v) in self.regs.args.iter().zip(values) {
            cpu.write_reg(*reg, *v);
        }
        // Entry stack alignment: (rsp + 8) % 16 == 0 after the return address is pushed.
        let sp = STACK_BASE + STACK_SIZE - 0x100 - 8;
        cpu.mem
            .write_bytes(sp, &RETURN_ADDR.to_le_bytes(), perm::NONE)
            .map_err(|e| emu(format!("{e:?}")))?;
        cpu.write_reg(self.regs.rsp, sp);
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
        if termination == Termination::Returned {
            if let Ret::Int { bits, .. } = sig.ret {
                obs.ret = Some(self.vm.cpu.read_reg(self.regs.rax) & mask(bits));
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
                    (Some(x), Some(y)) => match x.cmp(&y) {
                        std::cmp::Ordering::Less => -1i64 as u64,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    },
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
            other => return unsupported(format!("call to import `{other}`")),
        };
        // Return to the caller: pop the return address.
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

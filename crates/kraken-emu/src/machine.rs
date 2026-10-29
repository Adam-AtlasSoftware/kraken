//! One emulated CPU with its memory: icicle's SLEIGH p-code interpreter built for an [`Arch`],
//! with register access by SLEIGH name, the program counter with ARM/Thumb interworking, memory
//! mapping, disassembly and the run loop's stop reasons.

use std::collections::HashMap;

use icicle_cpu::mem::{Mapping, perm};
use icicle_cpu::{Config, Cpu, ExceptionCode, ValueSource, VmExit};
use icicle_vm::Vm;
use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::error::{EmuError, emu};
use crate::specs::SpecRoots;

/// Where Linux keeps the ARM thread pointer for user space (the kuser helper page at
/// `0xffff0000`; `__kuser_get_tls` reads this word). The coprocessor read of `TPIDRURO` returns it.
pub const ARM_TLS_CELL: u64 = 0xffff_0ff0;
/// The ARM vector/kuser page.
pub const ARM_KUSER_PAGE: u64 = 0xffff_0000;

/// Memory permissions of a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Perm {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub exec: bool,
}

impl Perm {
    /// Read, write and execute.
    pub const RWX: Perm = Perm {
        read: true,
        write: true,
        exec: true,
    };
    /// Read and write.
    pub const RW: Perm = Perm {
        read: true,
        write: true,
        exec: false,
    };
    /// Read only.
    pub const R: Perm = Perm {
        read: true,
        write: false,
        exec: false,
    };
    /// Read and execute.
    pub const RX: Perm = Perm {
        read: true,
        write: false,
        exec: true,
    };
    /// Nothing.
    pub const NONE: Perm = Perm {
        read: false,
        write: false,
        exec: false,
    };

    /// From a Linux `PROT_*` mask.
    pub fn from_prot(prot: u64) -> Perm {
        Perm {
            read: prot & 1 != 0,
            write: prot & 2 != 0,
            exec: prot & 4 != 0,
        }
    }

    /// From ELF `PF_*` flags.
    pub fn from_elf_flags(flags: u32) -> Perm {
        Perm {
            read: flags & 4 != 0,
            write: flags & 2 != 0,
            exec: flags & 1 != 0,
        }
    }

    pub(crate) fn bits(self) -> u8 {
        let mut p = perm::MAP | perm::INIT;
        if self.read {
            p |= perm::READ;
        }
        if self.write {
            // icicle checks READ for read-modify-write sequences; a writable page is readable.
            p |= perm::WRITE | perm::READ;
        }
        if self.exec {
            p |= perm::EXEC | perm::READ;
        }
        p
    }
}

/// Why the CPU stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Stop {
    /// The program counter reached a breakpoint address.
    Breakpoint { pc: u64 },
    /// The guest made a system call (the PC is already past the instruction).
    Syscall,
    /// The instruction budget of this run is used up.
    Budget,
    /// The guest faulted: unmapped or forbidden access, invalid instruction, an operation the
    /// emulator does not implement.
    Fault { detail: String, pc: u64 },
    /// The run was interrupted from outside (wall-clock limit).
    Interrupted,
    /// The guest halted the CPU.
    Halt,
}

/// An emulated CPU.
pub struct Machine {
    pub(crate) vm: Vm,
    arch: Arch,
    regs: HashMap<String, pcode::VarNode>,
    pc: pcode::VarNode,
    sp: pcode::VarNode,
}

/// The watched addresses that ran since the last [`take`](BlockLog::take)
/// ([`Machine::track_addresses`]).
#[derive(Debug, Clone, Default)]
pub struct BlockLog(std::rc::Rc<std::cell::RefCell<std::collections::BTreeSet<u64>>>);

impl BlockLog {
    /// The recorded addresses, and forgets them.
    pub fn take(&self) -> std::collections::BTreeSet<u64> {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

impl std::fmt::Debug for Machine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Machine")
            .field("arch", &self.arch)
            .field("pc", &self.vm.cpu.read_pc())
            .finish_non_exhaustive()
    }
}

/// Reads the ARM user read-only thread register (`mrc p15, 0, Rd, c13, c0, 3`).
fn arm_read_tls(cpu: &mut Cpu, dst: pcode::VarNode, _: [pcode::Value; 2]) {
    let mut b = [0u8; 4];
    let v = match cpu.mem.read_bytes(ARM_TLS_CELL, &mut b, perm::NONE) {
        Ok(()) => u32::from_le_bytes(b),
        Err(_) => 0,
    };
    cpu.write_var(dst, v);
}

/// The generic coprocessor read (`coprocessor_movefromRt(cpn, op1, [op2, CRn, CRm])` from Thumb
/// and `(cpn, op, [CRm])` from `mrrc`): `TPIDRURO` and the virtual counter; anything else is an
/// unimplemented operation, as in icicle's own helper.
fn arm_coprocessor_read(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let cpn = cpu.read::<u32>(args[0]);
    let op1 = cpu.read::<u32>(args[1]);
    let (a0, a1, a2) = (cpu.args[0], cpu.args[1], cpu.args[2]);
    if cpn == 15 && op1 == 0 && a0 == 3 && a1 == 13 && a2 == 0 {
        arm_read_tls(cpu, dst, args);
    } else if cpn == 15 && op1 == 1 && a0 == 14 {
        let v = cpu.icount() as u32;
        cpu.write_var(dst, v);
    } else {
        cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
    }
}

/// `CPUID` (the patched spec's `cpuid(EAX, ECX)`, see `specs::X86_CPUID`): a baseline x86-64 CPU
/// (FPU, TSC, CX8, CMOV, MMX, FXSR, SSE, SSE2; SYSCALL, NX, LM, LAHF), so the C library picks its
/// plain SSE2 routines. Every other leaf reads as zero. Output order: EAX, EBX, EDX, ECX.
fn x86_cpuid(cpu: &mut Cpu, dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let leaf = cpu.read::<u32>(args[0]);
    let regs: [u32; 4] = match leaf {
        0 => [
            0xd,
            u32::from_le_bytes(*b"Genu"),
            u32::from_le_bytes(*b"ineI"),
            u32::from_le_bytes(*b"ntel"),
        ],
        1 => {
            let edx =
                1 | (1 << 4) | (1 << 8) | (1 << 15) | (1 << 23) | (1 << 24) | (1 << 25) | (1 << 26);
            [0x0009_06e0, 0x0000_0800, edx, 0]
        }
        0x8000_0000 => [0x8000_0001, 0, 0, 0],
        0x8000_0001 => [0, 0, (1 << 11) | (1 << 20) | (1 << 29), 1],
        _ => [0; 4],
    };
    if dst.size >= 16 {
        for (i, r) in regs.iter().enumerate() {
            cpu.write_var(dst.slice(4 * i as u8, 4), *r);
        }
    } else {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
    }
}

/// Works around icicle lifting a new block with the decoder context of the block the CPU came
/// from: after an interworking branch (`bx`, `blx`, `pop {pc}`) into code not lifted yet, that
/// context still says A32 (or Thumb), and icicle only switches it when the instruction set differs
/// from the one it lifted last, which is stale once cached blocks of the other set ran. Forgetting
/// the previous block before the lift makes icicle take the context of its last lift, or the
/// instruction set's own context when that differs. No other context needs to cross a block
/// boundary on ARM (an IT block never spans one: a branch must be its last instruction).
struct ArmEnv;

impl icicle_cpu::Environment for ArmEnv {
    fn load(&mut self, _: &mut Cpu, _: &[u8]) -> Result<(), String> {
        Err("loading is done by kraken-emu".into())
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        if cpu.exception.code == ExceptionCode::CodeNotTranslated as u32 {
            cpu.block_id = u64::MAX;
        }
        None
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

impl Machine {
    /// Builds a CPU for `arch` from the first spec root that has its SLEIGH sources.
    pub fn new(arch: Arch, specs: &SpecRoots) -> Result<Machine, EmuError> {
        let processors = specs.processors_for(arch)?;
        let mut config = Config::from_target_triple(arch.icicle_triple());
        config.enable_jit = false;
        config.enable_shadow_stack = false;
        config.enable_recompilation = false;
        let mut vm = icicle_vm::build_with_path(&config, &processors)
            .map_err(|e| EmuError::Emulator(format!("building the {arch} CPU: {e}")))?;
        if arch == Arch::Arm {
            vm.set_env(ArmEnv);
            let helpers: [(&str, icicle_cpu::exec::helpers::PcodeOpHelper); 2] = [
                ("coproc_movefrom_User_R_Thread_and_Process_ID", arm_read_tls),
                ("coprocessor_movefromRt", arm_coprocessor_read),
            ];
            for (name, f) in helpers
                .into_iter()
                .chain(crate::vfp::HELPERS.iter().copied())
            {
                if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
                    vm.cpu.set_helper(id, f);
                }
            }
        }
        if matches!(arch, Arch::X86 | Arch::X86_64)
            && let Some(id) = vm.cpu.arch.sleigh.get_userop("cpuid")
        {
            vm.cpu.set_helper(id, x86_cpuid);
        }
        if arch == Arch::Aarch64 {
            for (name, f) in crate::neon::HELPERS {
                if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
                    vm.cpu.set_helper(id, *f);
                }
            }
        }
        let pc = vm.cpu.arch.reg_pc;
        let sp = vm.cpu.arch.reg_sp;
        let mut m = Machine {
            vm,
            arch,
            regs: HashMap::new(),
            pc,
            sp,
        };
        if arch == Arch::Arm {
            // The Thumb `mrc` passes its CRn/CRm operands as the coprocessor registers
            // `cr0`-`cr15`, so the helper sees their values: give each its own number.
            for n in 0..16u64 {
                let name = format!("cr{n}");
                if m.has_reg(&name) {
                    m.write_reg(&name, n)?;
                }
            }
        }
        if matches!(arch, Arch::Riscv32 | Arch::Riscv64) {
            // The CSRs of the patched spec (see specs::riscv_overlay); all zero.
            m.map(
                crate::specs::RISCV_CSR_BASE,
                crate::specs::RISCV_CSR_SIZE,
                Perm::RW,
            )?;
        }
        Ok(m)
    }

    /// The architecture.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The varnode of a SLEIGH register.
    pub fn reg(&mut self, name: &str) -> Result<pcode::VarNode, EmuError> {
        if let Some(v) = self.regs.get(name) {
            return Ok(*v);
        }
        let v =
            self.vm.cpu.arch.sleigh.get_varnode(name).ok_or_else(|| {
                EmuError::Emulator(format!("{} has no register `{name}`", self.arch))
            })?;
        self.regs.insert(name.to_string(), v);
        Ok(v)
    }

    /// Whether the SLEIGH spec has register `name`.
    pub fn has_reg(&mut self, name: &str) -> bool {
        self.reg(name).is_ok()
    }

    /// A register's value (zero-extended; the low 64 bits of a wider one).
    pub fn read_reg(&mut self, name: &str) -> Result<u64, EmuError> {
        let v = self.reg(name)?;
        Ok(self.vm.cpu.read_reg(v))
    }

    /// A register's raw bytes (little-endian, its full width).
    pub fn read_reg_bytes(&mut self, name: &str) -> Result<Vec<u8>, EmuError> {
        let v = self.reg(name)?;
        self.vm
            .cpu
            .regs
            .get(v)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| EmuError::Emulator(format!("register `{name}` unreadable")))
    }

    /// Sets a register (truncated to its width; the rest of a wider register is cleared). Writing
    /// the program counter goes through [`Machine::set_pc`].
    pub fn write_reg(&mut self, name: &str, value: u64) -> Result<(), EmuError> {
        let v = self.reg(name)?;
        if v == self.pc {
            self.set_pc(value);
            return Ok(());
        }
        if let Some(bytes) = self.vm.cpu.regs.get_mut(v) {
            bytes.fill(0);
        }
        self.vm.cpu.write_reg(v, value);
        Ok(())
    }

    /// Writes raw little-endian bytes to a register (at most its width).
    pub fn write_reg_bytes(&mut self, name: &str, value: &[u8]) -> Result<(), EmuError> {
        let v = self.reg(name)?;
        let bytes = self
            .vm
            .cpu
            .regs
            .get_mut(v)
            .ok_or_else(|| EmuError::Emulator(format!("register `{name}` unwritable")))?;
        bytes.fill(0);
        let n = bytes.len().min(value.len());
        bytes[..n].copy_from_slice(&value[..n]);
        Ok(())
    }

    /// The program counter (the instruction address; no Thumb bit).
    pub fn pc(&self) -> u64 {
        self.vm.cpu.read_pc()
    }

    /// Whether the CPU executes Thumb code (ARM only).
    pub fn thumb(&self) -> bool {
        self.arch.has_thumb() && self.vm.cpu.isa_mode() == 1
    }

    /// The program counter as a code address: with bit 0 set in Thumb mode, as `bx` would take it.
    pub fn code_pc(&self) -> u64 {
        self.pc() | u64::from(self.thumb())
    }

    /// Moves execution to `addr`. On ARM bit 0 selects Thumb (set) or A32 (clear), as `bx` does.
    pub fn set_pc(&mut self, addr: u64) {
        let mut addr = addr & self.arch.ptr_mask();
        if self.arch.has_thumb() {
            self.vm.cpu.set_isa_mode((addr & 1) as u8);
            addr &= !1;
        }
        self.vm.cpu.write_pc(addr);
    }

    /// Resumes after a system call: at the instruction that follows it.
    pub(crate) fn resume_after_syscall(&mut self) {
        let next = self.vm.cpu.read_var::<u64>(self.vm.cpu.arch.reg_next_pc);
        self.vm.cpu.write_pc(next);
    }

    /// The stack pointer.
    pub fn sp(&mut self) -> u64 {
        self.vm.cpu.read_reg(self.sp)
    }

    /// Sets the stack pointer.
    pub fn set_sp(&mut self, v: u64) {
        let sp = self.sp;
        self.vm.cpu.write_reg(sp, v);
    }

    /// Instructions executed so far.
    pub fn icount(&self) -> u64 {
        self.vm.cpu.icount
    }

    /// Maps `len` bytes at `addr` (page aligned by the caller), zero filled.
    pub fn map(&mut self, addr: u64, len: u64, p: Perm) -> Result<(), EmuError> {
        if len == 0 {
            return Ok(());
        }
        if self.vm.cpu.mem.map_memory_len(
            addr,
            len,
            Mapping {
                perm: p.bits(),
                value: 0,
            },
        ) {
            Ok(())
        } else {
            Err(EmuError::Emulator(format!(
                "cannot map {len:#x} bytes at {addr:#x}"
            )))
        }
    }

    /// Unmaps a range (a no-op where nothing is mapped).
    pub fn unmap(&mut self, addr: u64, len: u64) {
        if len > 0 {
            self.vm.cpu.mem.unmap_memory_len(addr, len);
        }
    }

    /// Changes the permissions of a mapped range.
    pub fn protect(&mut self, addr: u64, len: u64, p: Perm) -> Result<(), EmuError> {
        if len == 0 {
            return Ok(());
        }
        self.vm
            .cpu
            .mem
            .update_perm(addr, len, p.bits())
            .map_err(emu)
    }

    /// Whether `addr` is mapped.
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.vm.cpu.mem.get_perm(addr) & perm::MAP != 0
    }

    /// Reads guest memory, ignoring permissions (a debugger read). Fails on unmapped memory.
    pub fn read_mem(&mut self, addr: u64, buf: &mut [u8]) -> Result<(), EmuError> {
        self.vm
            .cpu
            .mem
            .read_bytes_large(addr, buf, perm::NONE)
            .map_err(|e| {
                EmuError::Emulator(format!("read of {} bytes at {addr:#x}: {e:?}", buf.len()))
            })
    }

    /// Reads `len` bytes of guest memory.
    pub fn read_vec(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, EmuError> {
        let mut b = vec![0u8; len];
        self.read_mem(addr, &mut b)?;
        Ok(b)
    }

    /// Writes guest memory, ignoring permissions (a loader or debugger write).
    pub fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<(), EmuError> {
        self.vm
            .cpu
            .mem
            .write_bytes_large(addr, data, perm::NONE)
            .map_err(|e| {
                EmuError::Emulator(format!("write of {} bytes at {addr:#x}: {e:?}", data.len()))
            })
    }

    /// Reads guest memory the way the guest would (`perm` checked); used by the syscall layer so
    /// a system call cannot read what the program could not.
    pub(crate) fn guest_read(&mut self, addr: u64, buf: &mut [u8]) -> bool {
        self.vm
            .cpu
            .mem
            .read_bytes_large(addr, buf, perm::READ)
            .is_ok()
    }

    /// Writes guest memory the way the guest would.
    pub(crate) fn guest_write(&mut self, addr: u64, data: &[u8]) -> bool {
        self.vm
            .cpu
            .mem
            .write_bytes_large(addr, data, perm::WRITE)
            .is_ok()
    }

    /// Reads an unsigned little-endian integer of `size` bytes (1, 2, 4 or 8).
    pub fn read_uint(&mut self, addr: u64, size: usize) -> Result<u64, EmuError> {
        let mut b = [0u8; 8];
        self.read_mem(addr, &mut b[..size.min(8)])?;
        Ok(u64::from_le_bytes(b))
    }

    /// Writes an unsigned little-endian integer of `size` bytes.
    pub fn write_uint(&mut self, addr: u64, size: usize, v: u64) -> Result<(), EmuError> {
        let b = v.to_le_bytes();
        self.write_mem(addr, &b[..size.min(8)])
    }

    /// Reads a pointer-sized word.
    pub fn read_ptr(&mut self, addr: u64) -> Result<u64, EmuError> {
        self.read_uint(addr, self.arch.ptr_size())
    }

    /// Writes a pointer-sized word.
    pub fn write_ptr(&mut self, addr: u64, v: u64) -> Result<(), EmuError> {
        self.write_uint(addr, self.arch.ptr_size(), v)
    }

    /// Reads a NUL-terminated string of at most `max` bytes (without the NUL); `None` when it is
    /// unreadable or longer.
    pub fn read_cstr(&mut self, addr: u64, max: usize) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = [0u8; 64];
        let mut at = addr;
        while out.len() <= max {
            // Read up to the end of the page so a string that ends just before unmapped memory
            // still reads.
            let room = (0x1000 - (at & 0xfff)) as usize;
            let n = room.min(chunk.len());
            self.vm
                .cpu
                .mem
                .read_bytes(at, &mut chunk[..n], perm::NONE)
                .ok()?;
            if let Some(z) = chunk[..n].iter().position(|b| *b == 0) {
                out.extend_from_slice(&chunk[..z]);
                return (out.len() <= max).then_some(out);
            }
            out.extend_from_slice(&chunk[..n]);
            at = at.wrapping_add(n as u64);
        }
        None
    }

    /// Disassembles the instruction at `addr` (in the current instruction set, or Thumb when
    /// `thumb` says so): its text and length. `None` when the bytes are unreadable or invalid.
    pub fn disasm_at(&mut self, addr: u64, thumb: Option<bool>) -> Option<(String, u64)> {
        let mode = match thumb {
            Some(t) if self.arch.has_thumb() => usize::from(t),
            _ => self.vm.cpu.isa_mode() as usize,
        };
        let ctx = *self
            .vm
            .cpu
            .arch
            .isa_mode_context
            .get(mode)
            .or_else(|| self.vm.cpu.arch.isa_mode_context.first())?;
        let mut bytes = [0u8; 16];
        // Fewer bytes near the end of a mapping.
        let mut n = bytes.len();
        while n > 0
            && self
                .vm
                .cpu
                .mem
                .read_bytes(addr, &mut bytes[..n], perm::NONE)
                .is_err()
        {
            n /= 2;
        }
        if n == 0 {
            return None;
        }
        let mut rt = sleigh_runtime::Runtime::new(ctx);
        let sleigh = &self.vm.cpu.arch.sleigh;
        let len = {
            let inst = rt.decode(sleigh, addr, &bytes[..n])?;
            inst.num_bytes()
        };
        let text = rt.disasm(sleigh)?.to_string();
        Some((text, len))
    }

    /// Starts recording which of the instruction addresses `addrs` run. Code the emulator lifted
    /// before this call is not watched, so call it right after building the machine.
    pub fn track_addresses(&mut self, addrs: &[u64]) -> BlockLog {
        let log = BlockLog::default();
        let sink = log.0.clone();
        self.vm
            .hook_many_addresses(addrs, move |_: &mut Cpu, addr: u64| {
                sink.borrow_mut().insert(addr);
            });
        log
    }

    /// Adds a breakpoint (an instruction address, no Thumb bit).
    pub fn add_breakpoint(&mut self, addr: u64) -> bool {
        self.vm.add_breakpoint(addr)
    }

    /// Removes a breakpoint.
    pub fn remove_breakpoint(&mut self, addr: u64) -> bool {
        self.vm.remove_breakpoint(addr)
    }

    /// The breakpoints.
    pub fn breakpoints(&self) -> Vec<u64> {
        let mut b = self.vm.breakpoints();
        b.sort_unstable();
        b
    }

    /// The flag that interrupts a run from another thread.
    pub fn interrupt_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.vm.interrupt_flag.clone()
    }

    /// Runs at most `budget` instructions.
    pub fn run(&mut self, budget: u64) -> Stop {
        let start = self.vm.cpu.icount;
        self.vm.icount_limit = start.saturating_add(budget);
        let exit = self.vm.run();
        self.classify(exit)
    }

    fn classify(&mut self, exit: VmExit) -> Stop {
        let pc = self.vm.cpu.read_pc();
        match exit {
            VmExit::Breakpoint => Stop::Breakpoint { pc },
            VmExit::InstructionLimit => Stop::Budget,
            VmExit::Interrupted => {
                self.vm
                    .interrupt_flag
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                Stop::Interrupted
            }
            VmExit::Halt => Stop::Halt,
            VmExit::UnhandledException((ExceptionCode::Syscall, _)) => Stop::Syscall,
            VmExit::UnhandledException((code, value)) => {
                let insn = match self.disasm_at(pc, None) {
                    Some((text, _)) if !text.is_empty() => format!(" `{text}`"),
                    _ => String::new(),
                };
                Stop::Fault {
                    detail: format!("{code:?} ({value:#x}){insn}"),
                    pc,
                }
            }
            other => Stop::Fault {
                detail: format!("emulator stopped: {other:?}"),
                pc,
            },
        }
    }

    /// A snapshot of registers and memory (icicle's copy-on-write snapshot).
    pub fn snapshot(&mut self) -> icicle_vm::Snapshot {
        self.vm.snapshot()
    }

    /// Restores a snapshot taken from this machine.
    pub fn restore(&mut self, s: &icicle_vm::Snapshot) {
        self.vm.restore(s);
    }
}

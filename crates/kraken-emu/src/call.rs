//! Function-level calls with each architecture's C calling convention.
//!
//! | arch | integers | `float`/`double` | stack slots | result |
//! |---|---|---|---|---|
//! | x86-64 (SysV) | RDI RSI RDX RCX R8 R9 | XMM0-7 | 8 bytes, after the return address | RAX, XMM0 |
//! | x86 (cdecl) | stack | stack | 4 bytes (8 for 64-bit values), after the return address | EAX(:EDX), ST0 |
//! | ARM (AAPCS-VFP) | r0-r3 (64-bit in an even pair) | s0-s15 / d0-d7 with back-filling | 4 bytes, 8-byte values 8-aligned | r0(:r1), s0/d0 |
//! | AArch64 (AAPCS64) | x0-x7 | v0-v7 | 8 bytes | x0, s0/d0 |
//! | RISC-V lp64d | a0-a7 (32-bit values sign-extended) | fa0-fa7 (NaN-boxed `float`), then a-registers | 8 bytes | a0, fa0 |
//! | RISC-V ilp32 | a0-a7 (64-bit values in two, split onto the stack) | as integers (soft-float) | 4 bytes, 8-byte values 8-aligned | a0(:a1) |
//!
//! The return trap: x86 pushes the trap address as the return address, the others put it in the
//! link register (`lr`, `x30`, `ra`); a breakpoint on it ends the call. The same rules read the
//! arguments of an incoming call (a stub the host answers, see kraken-rewrite's oracle) and
//! return from it.

use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::error::EmuError;
use crate::linux::{Exit, LinuxProcess, RunSpec};
use crate::loader::{Image, PAGE, SlotKind};
use crate::machine::{Machine, Perm, Stop};
use crate::specs::SpecRoots;

/// An argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    /// An integer or pointer of `bits` (8, 16, 32 or 64; pointers use the pointer width), the raw
    /// pattern in `value`.
    Int { bits: u8, signed: bool, value: u64 },
    /// A `float` (IEEE-754 bits).
    F32 { bits: u32 },
    /// A `double` (IEEE-754 bits).
    F64 { bits: u64 },
}

impl Value {
    /// A pointer-sized unsigned integer.
    pub fn ptr(arch: Arch, v: u64) -> Value {
        Value::Int {
            bits: arch.bits() as u8,
            signed: false,
            value: v,
        }
    }

    /// A signed 32-bit `int`.
    pub fn i32(v: i32) -> Value {
        Value::Int {
            bits: 32,
            signed: true,
            value: v as i64 as u64,
        }
    }

    /// A `double`.
    pub fn f64(v: f64) -> Value {
        Value::F64 { bits: v.to_bits() }
    }

    /// A `float`.
    pub fn f32(v: f32) -> Value {
        Value::F32 { bits: v.to_bits() }
    }

    fn is_float(&self) -> bool {
        matches!(self, Value::F32 { .. } | Value::F64 { .. })
    }

    /// Width in bytes.
    fn size(&self) -> usize {
        match *self {
            Value::Int { bits, .. } => (usize::from(bits).max(8)).div_ceil(8),
            Value::F32 { .. } => 4,
            Value::F64 { .. } => 8,
        }
    }

    /// The bit pattern, extended to 64 bits the way a register holds it on `arch`.
    fn reg_bits(&self, arch: Arch) -> u64 {
        match *self {
            Value::Int {
                bits,
                signed,
                value,
            } => {
                let b = u32::from(bits.clamp(1, 64));
                let masked = if b >= 64 {
                    value
                } else {
                    value & ((1u64 << b) - 1)
                };
                // RV64 keeps 32-bit values sign-extended whatever their type; narrower ones
                // follow their signedness everywhere.
                let sext = signed || (b == 32 && arch == Arch::Riscv64);
                if sext && b < 64 && masked >> (b - 1) & 1 == 1 {
                    masked | !((1u64 << b) - 1)
                } else {
                    masked
                }
            }
            Value::F32 { bits } => u64::from(bits),
            Value::F64 { bits } => bits,
        }
    }
}

/// The result type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RetKind {
    /// Nothing.
    Void,
    /// An integer or pointer of `bits`.
    Int { bits: u8 },
    /// A `float`.
    F32,
    /// A `double`.
    F64,
}

/// Where one argument goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    /// A register (SLEIGH name) with the value's register bits.
    Reg(&'static str),
    /// Two registers: low half, high half (32-bit ABIs).
    Pair(&'static str, &'static str),
    /// Low half in a register, high half at a stack offset (RISC-V ilp32 when one register is
    /// left).
    Split(&'static str, usize),
    /// The stack argument area at this byte offset.
    Stack(usize),
}

/// Where every argument of a call goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// One location per argument.
    pub locs: Vec<Loc>,
    /// Bytes of the stack argument area.
    pub stack_size: usize,
}

const XMM: [&str; 8] = [
    "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
];
const ARM_S: [&str; 16] = [
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14",
    "s15",
];
const ARM_D: [&str; 8] = ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"];
const A64_D: [&str; 8] = ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"];
const A64_S: [&str; 8] = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"];
const RV_FA: [&str; 8] = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"];

fn align(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

/// Lays out `args` per `arch`'s C calling convention.
pub fn place(arch: Arch, args: &[Value]) -> Placement {
    let ints = arch.int_arg_regs();
    let mut next_int = 0usize;
    let mut stack = 0usize;
    let mut locs = Vec::with_capacity(args.len());
    match arch {
        Arch::X86_64 | Arch::Aarch64 => {
            let mut next_fp = 0usize;
            for a in args {
                if a.is_float() {
                    if next_fp < 8 {
                        locs.push(Loc::Reg(match (arch, a) {
                            (Arch::X86_64, _) => XMM[next_fp],
                            (_, Value::F32 { .. }) => A64_S[next_fp],
                            _ => A64_D[next_fp],
                        }));
                        next_fp += 1;
                        continue;
                    }
                } else if next_int < ints.len() {
                    locs.push(Loc::Reg(ints[next_int]));
                    next_int += 1;
                    continue;
                }
                locs.push(Loc::Stack(stack));
                stack += 8;
            }
        }
        Arch::X86 => {
            for a in args {
                locs.push(Loc::Stack(stack));
                stack += align(a.size(), 4);
            }
        }
        Arch::Arm => {
            // Single-precision slots s0-s15; a double takes an aligned pair.
            let mut used = [false; 16];
            let mut vfp_on_stack = false;
            for a in args {
                match a {
                    Value::F32 { .. } if !vfp_on_stack => {
                        if let Some(i) = used.iter().position(|u| !u) {
                            used[i] = true;
                            locs.push(Loc::Reg(ARM_S[i]));
                            continue;
                        }
                        vfp_on_stack = true;
                    }
                    Value::F64 { .. } if !vfp_on_stack => {
                        if let Some(d) = (0..8).find(|d| !used[2 * d] && !used[2 * d + 1]) {
                            used[2 * d] = true;
                            used[2 * d + 1] = true;
                            locs.push(Loc::Reg(ARM_D[d]));
                            continue;
                        }
                        vfp_on_stack = true;
                    }
                    Value::Int { bits: 64, .. } => {
                        next_int = align(next_int, 2);
                        if next_int + 1 < ints.len() {
                            locs.push(Loc::Pair(ints[next_int], ints[next_int + 1]));
                            next_int += 2;
                            continue;
                        }
                        next_int = ints.len();
                    }
                    Value::Int { .. } if next_int < ints.len() => {
                        locs.push(Loc::Reg(ints[next_int]));
                        next_int += 1;
                        continue;
                    }
                    _ => {}
                }
                let sz = a.size().max(4);
                stack = align(stack, sz.min(8));
                locs.push(Loc::Stack(stack));
                stack += sz;
            }
        }
        Arch::Riscv64 => {
            let mut next_fp = 0usize;
            for a in args {
                if a.is_float() && next_fp < 8 {
                    locs.push(Loc::Reg(RV_FA[next_fp]));
                    next_fp += 1;
                } else if next_int < ints.len() {
                    locs.push(Loc::Reg(ints[next_int]));
                    next_int += 1;
                } else {
                    locs.push(Loc::Stack(stack));
                    stack += 8;
                }
            }
        }
        Arch::Riscv32 => {
            for a in args {
                if a.size() == 8 {
                    if next_int + 1 < ints.len() {
                        locs.push(Loc::Pair(ints[next_int], ints[next_int + 1]));
                        next_int += 2;
                    } else if next_int < ints.len() {
                        locs.push(Loc::Split(ints[next_int], stack));
                        next_int += 1;
                        stack += 4;
                    } else {
                        stack = align(stack, 8);
                        locs.push(Loc::Stack(stack));
                        stack += 8;
                    }
                } else if next_int < ints.len() {
                    locs.push(Loc::Reg(ints[next_int]));
                    next_int += 1;
                } else {
                    locs.push(Loc::Stack(stack));
                    stack += 4;
                }
            }
        }
    }
    Placement {
        locs,
        stack_size: align(stack, 16),
    }
}

/// The stack alignment at a call site (before the return address is pushed on x86).
fn call_align(arch: Arch) -> u64 {
    match arch {
        Arch::Arm => 8,
        _ => 16,
    }
}

/// Sets up a call of `entry` (a code address: bit 0 selects Thumb on ARM) with `args`: argument
/// registers, the stack argument area below `stack_top`, the return trap, the program counter.
/// Other registers are left as they are.
pub fn setup_call(
    m: &mut Machine,
    entry: u64,
    args: &[Value],
    stack_top: u64,
    trap: u64,
) -> Result<(), EmuError> {
    let arch = m.arch();
    let p = place(arch, args);
    let ps = arch.ptr_size() as u64;
    // The stack argument area starts at the aligned call-site stack pointer.
    let area = (stack_top - p.stack_size as u64 - 0x40) & !(call_align(arch) - 1);
    for (a, loc) in args.iter().zip(&p.locs) {
        let bits = a.reg_bits(arch);
        match *loc {
            Loc::Reg(r) => {
                // A NaN-boxed float in a 64-bit FP register (RISC-V); other float registers take
                // the plain pattern.
                let v = match (arch, a) {
                    (Arch::Riscv64, Value::F32 { bits }) if r.starts_with('f') => {
                        0xffff_ffff_0000_0000 | u64::from(*bits)
                    }
                    _ => bits,
                };
                m.write_reg(r, v)?;
            }
            Loc::Pair(lo, hi) => {
                m.write_reg(lo, bits & 0xffff_ffff)?;
                m.write_reg(hi, bits >> 32)?;
            }
            Loc::Split(lo, off) => {
                m.write_reg(lo, bits & 0xffff_ffff)?;
                m.write_uint(area + off as u64, 4, bits >> 32)?;
            }
            Loc::Stack(off) => {
                let size = match (arch, a) {
                    (Arch::X86_64 | Arch::Aarch64 | Arch::Riscv64, _) => 8,
                    (_, v) => v.size().max(4),
                };
                m.write_uint(area + off as u64, size, bits)?;
            }
        }
    }
    let sp = match arch {
        Arch::X86 | Arch::X86_64 => {
            let sp = area - ps;
            m.write_uint(sp, ps as usize, trap)?;
            sp
        }
        _ => {
            if let Some(lr) = arch.link_reg() {
                m.write_reg(lr, trap)?;
            }
            area
        }
    };
    m.set_sp(sp);
    m.set_pc(entry);
    Ok(())
}

/// The `double` an x87 register holds. icicle keeps 80-bit values as the `double` bit pattern in
/// their low eight bytes (its p-code float operations work in `f64`), so that is what is read.
fn st0_to_f64(b: &[u8]) -> u64 {
    let mut w = [0u8; 8];
    let n = b.len().min(8);
    w[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(w)
}

/// The x87 register contents for a `double`, in icicle's representation (see [`st0_to_f64`]).
fn f64_to_st0(v: u64) -> [u8; 10] {
    let mut out = [0u8; 10];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

/// Reads the result of a call that returned.
pub fn read_return(m: &mut Machine, ret: RetKind) -> Result<Option<u64>, EmuError> {
    let arch = m.arch();
    let regs = arch.int_ret_regs();
    Ok(match ret {
        RetKind::Void => None,
        RetKind::Int { bits } => {
            let lo = m.read_reg(regs[0])?;
            let v = if bits > 32 && arch.bits() == 32 {
                (lo & 0xffff_ffff) | (m.read_reg(regs[1])? << 32)
            } else {
                lo
            };
            Some(if bits >= 64 {
                v
            } else {
                v & ((1u64 << bits) - 1)
            })
        }
        RetKind::F32 | RetKind::F64 => {
            let double = ret == RetKind::F64;
            let v = match arch {
                Arch::X86_64 => m.read_reg("XMM0")?,
                Arch::X86 => {
                    let d = st0_to_f64(&m.read_reg_bytes("ST0")?);
                    if double {
                        d
                    } else {
                        u64::from((f64::from_bits(d) as f32).to_bits())
                    }
                }
                Arch::Arm | Arch::Aarch64 => m.read_reg(if double { "d0" } else { "s0" })?,
                Arch::Riscv64 => m.read_reg("fa0")?,
                Arch::Riscv32 => {
                    let lo = m.read_reg("a0")? & 0xffff_ffff;
                    if double {
                        lo | (m.read_reg("a1")? << 32)
                    } else {
                        lo
                    }
                }
            };
            Some(if double { v } else { v & 0xffff_ffff })
        }
    })
}

/// The `n`th integer or pointer argument of the call the CPU just entered (registers, then the
/// stack slots of the convention; 32-bit values on 32-bit architectures). For a stub the host
/// answers.
pub fn incoming_int_arg(m: &mut Machine, n: usize) -> u64 {
    let arch = m.arch();
    let ints = arch.int_arg_regs();
    if let Some(r) = ints.get(n) {
        return m.read_reg(r).unwrap_or(0) & arch.ptr_mask();
    }
    let ps = arch.ptr_size() as u64;
    let sp = m.sp();
    let at = match arch {
        Arch::X86 | Arch::X86_64 => sp + ps + (n - ints.len()) as u64 * ps,
        _ => sp + (n - ints.len()) as u64 * ps,
    };
    m.read_uint(at, ps as usize).unwrap_or(0)
}

/// The `n`th floating-point argument of a call whose arguments are all `float` or all `double`
/// (the C math functions).
pub fn incoming_float_arg(m: &mut Machine, n: usize, double: bool) -> u64 {
    let arch = m.arch();
    let v = match arch {
        Arch::X86_64 => m.read_reg(XMM[n.min(7)]).unwrap_or(0),
        Arch::Aarch64 => m
            .read_reg(if double {
                A64_D[n.min(7)]
            } else {
                A64_S[n.min(7)]
            })
            .unwrap_or(0),
        Arch::Riscv64 => m.read_reg(RV_FA[n.min(7)]).unwrap_or(0),
        Arch::Arm => {
            if double {
                m.read_reg(ARM_D[n.min(7)]).unwrap_or(0)
            } else {
                m.read_reg(ARM_S[n.min(15)]).unwrap_or(0)
            }
        }
        Arch::X86 => {
            let sp = m.sp();
            let size = if double { 8 } else { 4 };
            m.read_uint(sp + 4 + (n * size) as u64, size).unwrap_or(0)
        }
        Arch::Riscv32 => {
            if double {
                incoming_int_arg(m, 2 * n) | (incoming_int_arg(m, 2 * n + 1) << 32)
            } else {
                incoming_int_arg(m, n)
            }
        }
    };
    if double { v } else { v & 0xffff_ffff }
}

/// Sets an integer result (both halves for 64-bit values on 32-bit architectures).
pub fn set_int_return(m: &mut Machine, v: u64) -> Result<(), EmuError> {
    let arch = m.arch();
    let regs = arch.int_ret_regs();
    if arch.bits() == 32 {
        m.write_reg(regs[0], v & 0xffff_ffff)?;
        m.write_reg(regs[1], v >> 32)?;
    } else {
        m.write_reg(regs[0], v)?;
    }
    Ok(())
}

/// Sets a floating-point result.
pub fn set_float_return(m: &mut Machine, bits: u64, double: bool) -> Result<(), EmuError> {
    match m.arch() {
        Arch::X86_64 => m.write_reg("XMM0", bits),
        Arch::X86 => {
            let d = if double {
                bits
            } else {
                f64::from(f32::from_bits(bits as u32)).to_bits()
            };
            m.write_reg_bytes("ST0", &f64_to_st0(d))
        }
        Arch::Arm | Arch::Aarch64 => m.write_reg(if double { "d0" } else { "s0" }, bits),
        Arch::Riscv64 => m.write_reg(
            "fa0",
            if double {
                bits
            } else {
                0xffff_ffff_0000_0000 | (bits & 0xffff_ffff)
            },
        ),
        Arch::Riscv32 => set_int_return(m, if double { bits } else { bits & 0xffff_ffff }),
    }
}

/// Returns from the call the CPU just entered to its caller (pops the return address on x86,
/// jumps to the link register elsewhere). `false` when the return address is unreadable.
pub fn return_to_caller(m: &mut Machine) -> bool {
    let arch = m.arch();
    match arch.link_reg() {
        None => {
            let ps = arch.ptr_size();
            let sp = m.sp();
            let Ok(ret) = m.read_uint(sp, ps) else {
                return false;
            };
            m.set_sp(sp + ps as u64);
            m.set_pc(ret);
            true
        }
        Some(lr) => {
            let ret = m.read_reg(lr).unwrap_or(0);
            m.set_pc(ret);
            true
        }
    }
}

/// How a function call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallTermination {
    /// It returned to the trap.
    Returned,
    /// It reached an import slot's stub (`name`): the caller decides what that import does.
    Import { name: String },
    /// It faulted.
    Fault { detail: String, pc: u64 },
    /// It made a system call (an image caller has no kernel).
    Syscall,
    /// The process ended during the call (process callers: `exit`, a signal).
    Exited { exit: Exit },
    /// The instruction budget ran out.
    Budget,
}

/// What a call did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallOutcome {
    /// How it ended.
    pub termination: CallTermination,
    /// The result (masked to its width) when it returned.
    pub ret: Option<u64>,
    /// Instructions executed.
    pub instructions: u64,
}

/// Where a started process is stopped for function calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StartAt {
    /// A function symbol of the program (normally `main`).
    Symbol { name: String },
    /// A link-time address (the load bias is added).
    Vaddr { value: u64 },
}

/// What a call targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callee {
    /// A runtime code address (bit 0 selects Thumb on ARM).
    Address(u64),
    /// A symbol of the image (its ELF value plus the load bias; Thumb symbols keep bit 0).
    Symbol(String),
}

/// One call.
#[derive(Debug, Clone, PartialEq)]
pub struct CallSpec {
    /// What to call.
    pub callee: Callee,
    /// Arguments.
    pub args: Vec<Value>,
    /// Result type.
    pub ret: RetKind,
    /// Instruction budget.
    pub max_instructions: u64,
}

/// Address-space layout of the function caller.
#[derive(Debug, Clone, Copy)]
pub struct CallLayout {
    /// Stack mapping.
    pub stack_base: u64,
    /// Stack size.
    pub stack_size: u64,
    /// The page of stub addresses (the return trap and one per import).
    pub stub_base: u64,
    /// Scratch memory for buffers the caller places ([`FunctionCaller::alloc`]).
    pub scratch_base: u64,
    /// Scratch size.
    pub scratch_size: u64,
}

impl CallLayout {
    /// The default layout for `arch` (low addresses on 32-bit architectures).
    pub fn for_arch(arch: Arch) -> CallLayout {
        if arch.bits() == 64 {
            CallLayout {
                stack_base: 0x7ffd_0000_0000,
                stack_size: 0x10_0000,
                stub_base: 0x7ffe_0000_0000,
                scratch_base: 0x6000_0000_0000,
                scratch_size: 0x100_0000,
            }
        } else {
            CallLayout {
                stack_base: 0xbe00_0000,
                stack_size: 0x10_0000,
                stub_base: 0xbf00_0000,
                scratch_base: 0x6000_0000,
                scratch_size: 0x100_0000,
            }
        }
    }

    /// The layout inside a started process ([`FunctionCaller::after_startup`]): clear of the
    /// Linux layer's own address-space layout.
    pub fn for_process(arch: Arch) -> CallLayout {
        if arch.bits() == 64 {
            CallLayout::for_arch(arch)
        } else {
            CallLayout {
                stack_base: 0,
                stack_size: 0,
                stub_base: 0xbf10_0000,
                scratch_base: 0xb100_0000,
                scratch_size: 0x100_0000,
            }
        }
    }

    /// The return trap.
    pub fn trap(&self) -> u64 {
        self.stub_base + 0xff0
    }
}

/// What a [`FunctionCaller`] runs on.
enum Backend {
    /// A bare CPU with the program image (imports stubbed).
    Image {
        m: Box<Machine>,
        image: Option<Image>,
    },
    /// A started Linux process stopped at a point of its own (its C library initialised); every
    /// call starts from the snapshot taken there, and system calls are answered.
    Process {
        p: Box<LinuxProcess>,
        snapshot: Box<icicle_vm::Snapshot>,
        out_mark: (usize, usize),
        symbols: std::collections::BTreeMap<String, u64>,
        stack_top: u64,
        main_bias: u64,
    },
}

/// Calls functions of a program on a CPU of its architecture.
///
/// Two ways to get there:
/// * [`FunctionCaller::load_elf`]: the program image alone, relocated, with every import slot
///   pointing at a stub address; reaching one ends the call with [`CallTermination::Import`]
///   (the caller can answer it with [`incoming_int_arg`], [`set_int_return`] and
///   [`return_to_caller`] and resume with [`FunctionCaller::resume`]). No libc runs.
/// * [`FunctionCaller::after_startup`]: the whole program started under the Linux layer and run
///   to a symbol (normally `main`), so the C library is initialised (TLS, `IRELATIVE`
///   relocations, stdio); calls then run in that process and may use libc and system calls.
pub struct FunctionCaller {
    backend: Backend,
    layout: CallLayout,
    imports: Vec<String>,
    scratch_next: u64,
}

impl std::fmt::Debug for FunctionCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionCaller")
            .field("imports", &self.imports)
            .finish_non_exhaustive()
    }
}

/// Load address of a 32-bit position-independent image.
pub const PIE_BASE_32: u64 = 0x0040_0000;

impl FunctionCaller {
    /// Loads an ELF program image for function calls; a position-independent one goes at
    /// `pie_bias` (64-bit) or [`PIE_BASE_32`] (32-bit).
    pub fn load_elf(data: &[u8], pie_bias: u64, specs: &SpecRoots) -> Result<Self, EmuError> {
        let arch = Arch::from_elf(data)?;
        let layout = CallLayout::for_arch(arch);
        let bias = if arch.bits() == 64 {
            pie_bias
        } else {
            PIE_BASE_32
        };
        let mut imports: Vec<String> = Vec::new();
        let image = Image::load(data, bias, |name, kind, _| match kind {
            SlotKind::Copy => None,
            _ => {
                let idx = imports.iter().position(|n| n == name).unwrap_or_else(|| {
                    imports.push(name.to_string());
                    imports.len() - 1
                });
                Some(layout.stub_base + 0x10 * (idx as u64 + 1))
            }
        })?;
        if imports.len() > 250 {
            return Err(EmuError::Unsupported("more than 250 imports".into()));
        }
        let mut m = Machine::new(arch, specs)?;
        image.map_into(&mut m)?;
        let mut fc = FunctionCaller {
            backend: Backend::Image {
                m: Box::new(m),
                image: Some(image),
            },
            layout,
            imports,
            scratch_next: layout.scratch_base,
        };
        fc.map_runtime(true)?;
        Ok(fc)
    }

    /// A caller over raw code bytes at `base` (tests, snippets).
    pub fn with_code(
        arch: Arch,
        base: u64,
        code: &[u8],
        specs: &SpecRoots,
    ) -> Result<Self, EmuError> {
        let mut m = Machine::new(arch, specs)?;
        let len = crate::loader::align_up(code.len() as u64 + 1).unwrap_or(PAGE);
        m.map(base & !(PAGE - 1), len + PAGE, Perm::RWX)?;
        m.write_mem(base, code)?;
        let layout = CallLayout::for_arch(arch);
        let mut fc = FunctionCaller {
            backend: Backend::Image {
                m: Box::new(m),
                image: None,
            },
            layout,
            imports: Vec::new(),
            scratch_next: layout.scratch_base,
        };
        fc.map_runtime(true)?;
        Ok(fc)
    }

    /// Starts `spec`'s program under the Linux layer, runs it to `symbol` (a function of the
    /// main program, e.g. `main`) within `budget` instructions and keeps that state: every call
    /// starts from it. Fails when the program ends or faults first.
    pub fn after_startup(spec: &RunSpec, symbol: &str, budget: u64) -> Result<Self, EmuError> {
        Self::after_startup_at(
            spec,
            &StartAt::Symbol {
                name: symbol.to_string(),
            },
            budget,
        )
    }

    /// Like [`FunctionCaller::after_startup`], stopping at `at` (a symbol, or a link-time
    /// address, which is what a stripped program needs).
    pub fn after_startup_at(spec: &RunSpec, at: &StartAt, budget: u64) -> Result<Self, EmuError> {
        let mut p = LinuxProcess::spawn(spec)?;
        let arch = p.arch();
        let data = std::fs::read(&spec.program)
            .map_err(|e| EmuError::Image(format!("{}: {e}", spec.program.display())))?;
        let main_bias = p.main_bias();
        let symbols = crate::session::function_symbols(&data, main_bias);
        let (at, symbol) = match at {
            StartAt::Symbol { name } => (
                *symbols
                    .get(name)
                    .ok_or_else(|| EmuError::Image(format!("no function symbol `{name}`")))?,
                name.clone(),
            ),
            StartAt::Vaddr { value } => (value.wrapping_add(main_bias), format!("{value:#x}")),
        };
        let symbol = symbol.as_str();
        let m = p.machine();
        m.add_breakpoint(at & !1);
        let start = m.icount();
        loop {
            let used = p.machine().icount() - start;
            if used >= budget {
                return Err(EmuError::Unsupported(format!(
                    "`{symbol}` not reached within {budget} instructions"
                )));
            }
            match p.machine().run(budget - used) {
                Stop::Breakpoint { pc } if pc == at & !1 => break,
                Stop::Breakpoint { .. } | Stop::Budget => {}
                Stop::Syscall => {
                    if let Some(e) = p.handle_syscall() {
                        return Err(EmuError::Unsupported(format!(
                            "the program ended before `{symbol}`: {}",
                            e.describe()
                        )));
                    }
                }
                Stop::Fault { detail, pc } => {
                    return Err(EmuError::Emulator(format!(
                        "fault before `{symbol}`: {detail} at {pc:#x}"
                    )));
                }
                other => {
                    return Err(EmuError::Emulator(format!(
                        "stopped before `{symbol}`: {other:?}"
                    )));
                }
            }
        }
        p.machine().remove_breakpoint(at & !1);
        // Calls use the stack below the frame `symbol` was entered with.
        let stack_top = (p.machine().sp() - 0x1000) & !0xf;
        let layout = CallLayout::for_process(arch);
        map_runtime(p.machine(), &layout, 0, false)?;
        let snapshot = Box::new(p.machine().snapshot());
        let out_mark = (p.stdout().len(), p.stderr().len());
        Ok(FunctionCaller {
            backend: Backend::Process {
                p: Box::new(p),
                snapshot,
                out_mark,
                symbols,
                stack_top,
                main_bias,
            },
            layout,
            imports: Vec::new(),
            scratch_next: layout.scratch_base,
        })
    }

    fn map_runtime(&mut self, stack: bool) -> Result<(), EmuError> {
        let l = self.layout;
        let n = self.imports.len();
        map_runtime(self.machine(), &l, n, stack)
    }

    /// The CPU.
    pub fn machine(&mut self) -> &mut Machine {
        match &mut self.backend {
            Backend::Image { m, .. } => m,
            Backend::Process { p, .. } => p.machine(),
        }
    }

    /// The image, when one was loaded with [`FunctionCaller::load_elf`].
    pub fn image(&self) -> Option<&Image> {
        match &self.backend {
            Backend::Image { image, .. } => image.as_ref(),
            Backend::Process { .. } => None,
        }
    }

    /// The load bias of the main program (0 unless it is position independent).
    pub fn bias(&self) -> u64 {
        match &self.backend {
            Backend::Image { image, .. } => image.as_ref().map_or(0, |i| i.bias),
            Backend::Process { main_bias, .. } => *main_bias,
        }
    }

    /// The imports (each has a stub address).
    pub fn imports(&self) -> &[String] {
        &self.imports
    }

    /// The layout.
    pub fn layout(&self) -> CallLayout {
        self.layout
    }

    /// Standard output and error of calls since the last reset (process callers).
    pub fn output(&self) -> (Vec<u8>, Vec<u8>) {
        match &self.backend {
            Backend::Process { p, out_mark, .. } => (
                p.stdout()[out_mark.0.min(p.stdout().len())..].to_vec(),
                p.stderr()[out_mark.1.min(p.stderr().len())..].to_vec(),
            ),
            Backend::Image { .. } => (Vec::new(), Vec::new()),
        }
    }

    /// Copies `data` into scratch memory (16-byte aligned) and returns its address.
    pub fn alloc(&mut self, data: &[u8]) -> Result<u64, EmuError> {
        let at = self.scratch_next;
        let end = at + data.len() as u64;
        if end > self.layout.scratch_base + self.layout.scratch_size {
            return Err(EmuError::Unsupported("scratch memory used up".into()));
        }
        self.machine().write_mem(at, data)?;
        self.scratch_next = (end + 15) & !15;
        Ok(at)
    }

    /// Resets the program to its initial state (the image, or the process at its start symbol),
    /// the stack and scratch memory.
    pub fn reset(&mut self) -> Result<(), EmuError> {
        let l = self.layout;
        match &mut self.backend {
            Backend::Image { m, image } => {
                if let Some(img) = image {
                    img.reset(m)?;
                }
                m.write_mem(l.stack_base, &vec![0u8; l.stack_size as usize])?;
            }
            Backend::Process {
                p,
                snapshot,
                out_mark,
                ..
            } => {
                p.machine().restore(snapshot);
                p.truncate_output(out_mark.0, out_mark.1);
            }
        }
        let m = self.machine();
        m.write_mem(l.scratch_base, &vec![0u8; 0x1_0000])?;
        self.scratch_next = l.scratch_base;
        Ok(())
    }

    /// Calls a function. The program and scratch memory are not reset (call [`Self::reset`]).
    pub fn call(&mut self, spec: &CallSpec) -> Result<CallOutcome, EmuError> {
        let entry = match &spec.callee {
            Callee::Address(a) => *a,
            Callee::Symbol(s) => {
                let found = match &self.backend {
                    Backend::Image { image, .. } => image.as_ref().and_then(|i| i.symbol_addr(s)),
                    Backend::Process { symbols, .. } => symbols.get(s).copied(),
                };
                found.ok_or_else(|| EmuError::Image(format!("no symbol `{s}`")))?
            }
        };
        let top = match &self.backend {
            Backend::Process { stack_top, .. } => *stack_top,
            Backend::Image { .. } => self.layout.stack_base + self.layout.stack_size - 0x100,
        };
        let trap = self.layout.trap();
        setup_call(self.machine(), entry, &spec.args, top, trap)?;
        self.resume(spec.ret, spec.max_instructions)
    }

    /// Continues a call (after the caller answered an import) until it ends.
    pub fn resume(&mut self, ret: RetKind, budget: u64) -> Result<CallOutcome, EmuError> {
        let start = self.machine().icount();
        let termination = loop {
            let used = self.machine().icount() - start;
            if used >= budget {
                break CallTermination::Budget;
            }
            match self.machine().run(budget - used) {
                Stop::Breakpoint { pc } if pc == self.layout.trap() => {
                    break CallTermination::Returned;
                }
                Stop::Breakpoint { pc } => {
                    let idx = pc
                        .checked_sub(self.layout.stub_base + 0x10)
                        .filter(|d| d % 0x10 == 0)
                        .map(|d| (d / 0x10) as usize);
                    match idx.and_then(|i| self.imports.get(i)) {
                        Some(name) => {
                            break CallTermination::Import { name: name.clone() };
                        }
                        // A breakpoint the caller set itself: keep going.
                        None => continue,
                    }
                }
                Stop::Budget => continue,
                Stop::Syscall => match &mut self.backend {
                    Backend::Process { p, .. } => {
                        if let Some(e) = p.handle_syscall() {
                            break CallTermination::Exited { exit: e };
                        }
                    }
                    Backend::Image { .. } => break CallTermination::Syscall,
                },
                Stop::Fault { detail, pc } => break CallTermination::Fault { detail, pc },
                Stop::Interrupted | Stop::Halt => {
                    break CallTermination::Fault {
                        detail: "stopped".into(),
                        pc: self.machine().pc(),
                    };
                }
            }
        };
        let ret = if termination == CallTermination::Returned {
            read_return(self.machine(), ret)?
        } else {
            None
        };
        Ok(CallOutcome {
            termination,
            ret,
            instructions: self.machine().icount() - start,
        })
    }
}

/// A page of a harmless instruction for stub and trap addresses: the CPU stops on their
/// breakpoints, but icicle decodes the instruction at an address before it checks for a
/// breakpoint there, so it must decode (`ret` on x86, `nop` elsewhere; A32 on ARM, where a
/// return to an even address lands).
pub fn stub_fill(arch: Arch) -> Vec<u8> {
    let word: &[u8] = match arch {
        Arch::X86 | Arch::X86_64 => &[0xc3],
        Arch::Arm => &[0x00, 0xf0, 0x20, 0xe3],
        Arch::Aarch64 => &[0x1f, 0x20, 0x03, 0xd5],
        Arch::Riscv32 | Arch::Riscv64 => &[0x13, 0x00, 0x00, 0x00],
    };
    word.iter().copied().cycle().take(PAGE as usize).collect()
}

/// Maps the caller's stack (optionally), stub page and scratch memory and sets the trap and stub
/// breakpoints.
fn map_runtime(
    m: &mut Machine,
    l: &CallLayout,
    imports: usize,
    stack: bool,
) -> Result<(), EmuError> {
    if stack {
        m.map(l.stack_base, l.stack_size, Perm::RW)?;
    }
    m.map(l.stub_base, PAGE, Perm::RX)?;
    let fill = stub_fill(m.arch());
    m.write_mem(l.stub_base, &fill)?;
    m.map(l.scratch_base, l.scratch_size, Perm::RW)?;
    m.add_breakpoint(l.trap());
    for i in 0..imports {
        m.add_breakpoint(l.stub_base + 0x10 * (i as u64 + 1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> Value {
        Value::f64(1.0)
    }
    fn f() -> Value {
        Value::f32(1.0)
    }
    fn i() -> Value {
        Value::i32(1)
    }
    fn l() -> Value {
        Value::Int {
            bits: 64,
            signed: false,
            value: 1,
        }
    }

    #[test]
    fn sysv_counts_integer_and_sse_registers_separately() {
        let p = place(Arch::X86_64, &[i(), d(), i(), f(), i(), i(), i(), i(), i()]);
        assert_eq!(p.locs[0], Loc::Reg("RDI"));
        assert_eq!(p.locs[1], Loc::Reg("XMM0"));
        assert_eq!(p.locs[2], Loc::Reg("RSI"));
        assert_eq!(p.locs[3], Loc::Reg("XMM1"));
        assert_eq!(p.locs[7], Loc::Reg("R9"));
        assert_eq!(p.locs[8], Loc::Stack(0));
    }

    #[test]
    fn cdecl_puts_everything_on_the_stack() {
        let p = place(Arch::X86, &[i(), d(), l(), f()]);
        assert_eq!(
            p.locs,
            vec![Loc::Stack(0), Loc::Stack(4), Loc::Stack(12), Loc::Stack(20)]
        );
    }

    #[test]
    fn aapcs_vfp_back_fills_single_slots() {
        // f -> s0, d -> d1 (s2,s3), f -> s1 (back-filled).
        let p = place(Arch::Arm, &[f(), d(), f()]);
        assert_eq!(p.locs, vec![Loc::Reg("s0"), Loc::Reg("d1"), Loc::Reg("s1")]);
        // A 64-bit integer skips r1 to start at an even register.
        let p = place(Arch::Arm, &[i(), l(), i()]);
        assert_eq!(
            p.locs,
            vec![Loc::Reg("r0"), Loc::Pair("r2", "r3"), Loc::Stack(0)]
        );
        // ... and goes to an 8-aligned stack slot when no pair is left.
        let p = place(Arch::Arm, &[i(), i(), i(), l()]);
        assert_eq!(p.locs[3], Loc::Stack(0));
    }

    #[test]
    fn riscv_floats_overflow_into_integer_registers_and_ilp32_splits() {
        let nine_d = vec![d(); 9];
        let p = place(Arch::Riscv64, &nine_d);
        assert_eq!(p.locs[7], Loc::Reg("fa7"));
        assert_eq!(p.locs[8], Loc::Reg("a0"));
        let mut args = vec![i(); 7];
        args.push(d());
        let p = place(Arch::Riscv32, &args);
        assert_eq!(p.locs[7], Loc::Split("a7", 0));
        let p = place(Arch::Riscv32, &[d(), l()]);
        assert_eq!(p.locs, vec![Loc::Pair("a0", "a1"), Loc::Pair("a2", "a3")]);
    }

    #[test]
    fn aapcs64_uses_v_registers_by_width() {
        let p = place(Arch::Aarch64, &[f(), d(), i()]);
        assert_eq!(p.locs, vec![Loc::Reg("s0"), Loc::Reg("d1"), Loc::Reg("x0")]);
    }

    #[test]
    fn rv64_sign_extends_32_bit_values_of_any_signedness() {
        let v = Value::Int {
            bits: 32,
            signed: false,
            value: 0x8000_0000,
        };
        assert_eq!(v.reg_bits(Arch::Riscv64), 0xffff_ffff_8000_0000);
        assert_eq!(v.reg_bits(Arch::Aarch64), 0x8000_0000);
    }

    #[test]
    fn x87_values_use_icicles_double_representation() {
        for v in [0.0, -2.5, 1e300, f64::INFINITY] {
            assert_eq!(f64::from_bits(st0_to_f64(&f64_to_st0(v.to_bits()))), v);
        }
    }
}

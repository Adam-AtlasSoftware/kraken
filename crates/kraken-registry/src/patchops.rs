//! Patch intents computed per architecture without an assembler: NOPs, branch edits, constant
//! returns, immediates. Every function is pure: it takes the bytes of the instruction (or just a
//! length) and returns the replacement bytes, or says plainly why the intent does not apply.
//! The commands in `commands/patch_intent.rs` feed these with bytes read through the engine.

use std::fmt;

/// An instruction set the intents know how to encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    /// 32-bit x86.
    X86,
    /// x86-64.
    X86_64,
    /// 32-bit ARM, A32 instructions.
    Arm,
    /// 32-bit ARM, Thumb instructions.
    Thumb,
    /// AArch64.
    Aarch64,
    /// RV32.
    Riscv32,
    /// RV64.
    Riscv64,
}

impl Isa {
    /// The instruction set for a processor language id such as `x86:LE:64:default` or
    /// `AARCH64:LE:64:v8A`. `thumb` selects Thumb for ARM. Big-endian and other processors are
    /// `None`.
    pub fn from_language(language: &str, thumb: bool) -> Option<Isa> {
        let lower = language.to_ascii_lowercase();
        let mut parts = lower.split(':');
        let family = parts.next()?;
        if parts.next()? != "le" {
            return None;
        }
        let bits = parts.next()?;
        match (family, bits) {
            ("x86", "64") => Some(Isa::X86_64),
            ("x86", "32") => Some(Isa::X86),
            ("aarch64", _) => Some(Isa::Aarch64),
            ("arm", "32") => Some(if thumb { Isa::Thumb } else { Isa::Arm }),
            ("riscv", "64") => Some(Isa::Riscv64),
            ("riscv", "32") => Some(Isa::Riscv32),
            _ => None,
        }
    }

    /// Whether the family is ARM (A32 or Thumb).
    pub fn is_arm32(self) -> bool {
        matches!(self, Isa::Arm | Isa::Thumb)
    }
}

/// Why an intent does not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentError(pub String);

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for IntentError {}

type R<T> = Result<T, IntentError>;

fn err<T>(msg: impl Into<String>) -> R<T> {
    Err(IntentError(msg.into()))
}

/// What to do to a conditional branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchMode {
    /// Take it when it was not taken and the other way round.
    Invert,
    /// Always take it (an unconditional jump to the same target).
    Always,
    /// Never take it (NOPs).
    Never,
}

// ---- NOP --------------------------------------------------------------------------------

/// Intel's recommended multi-byte NOPs, 1 to 9 bytes.
const X86_NOPS: [&[u8]; 9] = [
    &[0x90],
    &[0x66, 0x90],
    &[0x0f, 0x1f, 0x00],
    &[0x0f, 0x1f, 0x40, 0x00],
    &[0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00],
    &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00],
    &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
    &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],
];

/// `len` bytes of NOPs in the instruction set's own encoding.
pub fn nop(isa: Isa, len: usize) -> R<Vec<u8>> {
    if len == 0 {
        return err("nothing to fill: the length is 0");
    }
    let mut out = Vec::with_capacity(len);
    match isa {
        Isa::X86 | Isa::X86_64 => {
            let mut left = len;
            while left > 0 {
                let n = left.min(9);
                out.extend_from_slice(X86_NOPS[n - 1]);
                left -= n;
            }
        }
        Isa::Arm => {
            if !len.is_multiple_of(4) {
                return err("ARM instructions are 4 bytes: the range must be a multiple of 4");
            }
            (0..len / 4).for_each(|_| out.extend_from_slice(&0xe320_f000u32.to_le_bytes()));
        }
        Isa::Thumb => {
            if !len.is_multiple_of(2) {
                return err("Thumb instructions are 2 bytes: the range must be a multiple of 2");
            }
            (0..len / 2).for_each(|_| out.extend_from_slice(&0xbf00u16.to_le_bytes()));
        }
        Isa::Aarch64 => {
            if !len.is_multiple_of(4) {
                return err("AArch64 instructions are 4 bytes: the range must be a multiple of 4");
            }
            (0..len / 4).for_each(|_| out.extend_from_slice(&0xd503_201fu32.to_le_bytes()));
        }
        Isa::Riscv32 | Isa::Riscv64 => {
            if !len.is_multiple_of(2) {
                return err("RISC-V instructions are 2 or 4 bytes: the range must be even");
            }
            (0..len / 4).for_each(|_| out.extend_from_slice(&0x0000_0013u32.to_le_bytes()));
            if len % 4 == 2 {
                out.extend_from_slice(&0x0001u16.to_le_bytes());
            }
        }
    }
    Ok(out)
}

// ---- conditional branches ---------------------------------------------------------------

fn le32(b: &[u8]) -> R<u32> {
    match <[u8; 4]>::try_from(b) {
        Ok(a) => Ok(u32::from_le_bytes(a)),
        Err(_) => err(format!(
            "expected a 4-byte instruction, found {} bytes",
            b.len()
        )),
    }
}

fn le16(b: &[u8]) -> R<u16> {
    match <[u8; 2]>::try_from(b) {
        Ok(a) => Ok(u16::from_le_bytes(a)),
        Err(_) => err(format!(
            "expected a 2-byte instruction, found {} bytes",
            b.len()
        )),
    }
}

fn sext(v: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((v << shift) as i32) >> shift
}

const NOT_COND: &str = "this is not a conditional branch";

/// The bytes that replace the conditional branch `insn` (same length as `insn`).
pub fn branch(isa: Isa, insn: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    let new = match isa {
        Isa::X86 | Isa::X86_64 => branch_x86(insn, mode)?,
        Isa::Aarch64 => branch_a64(insn, mode)?,
        Isa::Arm => branch_a32(insn, mode)?,
        Isa::Thumb => branch_thumb(insn, mode)?,
        Isa::Riscv32 | Isa::Riscv64 => branch_riscv(insn, mode)?,
    };
    if mode == BranchMode::Never {
        return nop(isa, insn.len());
    }
    Ok(new)
}

fn branch_x86(b: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    match b {
        [op @ 0x70..=0x7f, rel] => Ok(match mode {
            BranchMode::Invert => vec![op ^ 1, *rel],
            BranchMode::Always => vec![0xeb, *rel],
            BranchMode::Never => vec![],
        }),
        [0x0f, op @ 0x80..=0x8f, r0, r1, r2, r3] => {
            let rel = i32::from_le_bytes([*r0, *r1, *r2, *r3]);
            Ok(match mode {
                BranchMode::Invert => {
                    let mut v = b.to_vec();
                    v[1] = op ^ 1;
                    v
                }
                BranchMode::Always => {
                    // jmp rel32 is one byte shorter, so its end is one byte earlier.
                    let Some(rel) = rel.checked_add(1) else {
                        return err("the branch target is out of range for a jump");
                    };
                    let mut v = vec![0xe9];
                    v.extend_from_slice(&rel.to_le_bytes());
                    v.push(0x90);
                    v
                }
                BranchMode::Never => vec![],
            })
        }
        _ => err(format!(
            "{NOT_COND}: expected a short (70-7f) or near (0f 80-8f) jcc, found {}",
            kraken_proto::hex_bytes(b)
        )),
    }
}

fn branch_a64(b: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    let w = le32(b)?;
    let (imm, cond) = if w & 0xff00_0010 == 0x5400_0000 {
        (sext((w >> 5) & 0x7_ffff, 19), Some(w & 0xf))
    } else if (w >> 25) & 0x3f == 0b01_1010 {
        (sext((w >> 5) & 0x7_ffff, 19), None)
    } else if (w >> 25) & 0x3f == 0b01_1011 {
        (sext((w >> 5) & 0x3fff, 14), None)
    } else {
        return err(format!(
            "{NOT_COND}: expected b.cond, cbz, cbnz, tbz or tbnz, found {w:#010x}"
        ));
    };
    Ok(match mode {
        BranchMode::Invert => match cond {
            Some(c) if c >= 0xe => return err("`b.al` is not conditional"),
            Some(_) => (w ^ 1).to_le_bytes().to_vec(),
            None => (w ^ (1 << 24)).to_le_bytes().to_vec(),
        },
        BranchMode::Always => (0x1400_0000 | (imm as u32 & 0x03ff_ffff))
            .to_le_bytes()
            .to_vec(),
        BranchMode::Never => vec![],
    })
}

fn branch_a32(b: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    let w = le32(b)?;
    if (w >> 25) & 7 != 0b101 {
        return err(format!("{NOT_COND}: expected b or bl, found {w:#010x}"));
    }
    match w >> 28 {
        0xe => return err("this branch is already unconditional"),
        0xf => return err("`blx` to an immediate cannot be inverted or made conditional"),
        _ => {}
    }
    Ok(match mode {
        BranchMode::Invert => (w ^ 0x1000_0000).to_le_bytes().to_vec(),
        BranchMode::Always => ((w & 0x0fff_ffff) | 0xe000_0000).to_le_bytes().to_vec(),
        BranchMode::Never => vec![],
    })
}

fn branch_thumb(b: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    if b.len() == 4 {
        return err("32-bit Thumb branches (b.w) are not handled yet; use patch_set");
    }
    let hw = le16(b)?;
    let (flip, half_offset) = if hw >> 12 == 0xd && (hw >> 8) & 0xf < 0xe {
        (0x0100u16, sext(u32::from(hw & 0xff), 8))
    } else if hw & 0xf500 == 0xb100 {
        let off = ((u32::from(hw) >> 9) & 1) << 5 | ((u32::from(hw) >> 3) & 0x1f);
        (0x0800u16, off as i32)
    } else {
        return err(format!(
            "{NOT_COND}: expected a Thumb b<cond>, cbz or cbnz, found {hw:#06x}"
        ));
    };
    Ok(match mode {
        BranchMode::Invert => (hw ^ flip).to_le_bytes().to_vec(),
        BranchMode::Always => (0xe000 | (half_offset as u16 & 0x7ff))
            .to_le_bytes()
            .to_vec(),
        BranchMode::Never => vec![],
    })
}

fn branch_riscv(b: &[u8], mode: BranchMode) -> R<Vec<u8>> {
    if b.len() == 2 {
        let hw = u32::from(le16(b)?);
        let op = (hw & 3, hw >> 13);
        if op != (1, 0b110) && op != (1, 0b111) {
            return err(format!(
                "{NOT_COND}: expected c.beqz or c.bnez, found {hw:#06x}"
            ));
        }
        let off = ((hw >> 12) & 1) << 8
            | ((hw >> 10) & 3) << 3
            | ((hw >> 5) & 3) << 6
            | ((hw >> 3) & 3) << 1
            | ((hw >> 2) & 1) << 5;
        let off = sext(off, 9) as u32;
        return Ok(match mode {
            BranchMode::Invert => ((hw ^ (1 << 13)) as u16).to_le_bytes().to_vec(),
            BranchMode::Always => {
                let bit = |from: u32, to: u32| ((off >> from) & 1) << to;
                let cj = 0xa001
                    | bit(11, 12)
                    | bit(4, 11)
                    | ((off >> 8) & 3) << 9
                    | bit(10, 8)
                    | bit(6, 7)
                    | bit(7, 6)
                    | ((off >> 1) & 7) << 3
                    | bit(5, 2);
                (cj as u16).to_le_bytes().to_vec()
            }
            BranchMode::Never => vec![],
        });
    }
    let w = le32(b)?;
    let f3 = (w >> 12) & 7;
    if w & 0x7f != 0x63 || matches!(f3, 2 | 3) {
        return err(format!(
            "{NOT_COND}: expected beq, bne, blt, bge, bltu or bgeu, found {w:#010x}"
        ));
    }
    Ok(match mode {
        BranchMode::Invert => (w ^ (1 << 12)).to_le_bytes().to_vec(),
        BranchMode::Always => {
            let imm = ((w >> 31) & 1) << 12
                | ((w >> 7) & 1) << 11
                | ((w >> 25) & 0x3f) << 5
                | ((w >> 8) & 0xf) << 1;
            let imm = sext(imm, 13) as u32;
            let jal = ((imm >> 20) & 1) << 31
                | ((imm >> 1) & 0x3ff) << 21
                | ((imm >> 11) & 1) << 20
                | ((imm >> 12) & 0xff) << 12
                | 0x6f;
            jal.to_le_bytes().to_vec()
        }
        BranchMode::Never => vec![],
    })
}

// ---- return a constant ------------------------------------------------------------------

/// Code that returns `value` to the caller, in the calling convention the platform's C compiler
/// uses. The caller pads the rest of the function's first instructions with NOPs.
pub fn return_value(isa: Isa, value: i64) -> R<Vec<u8>> {
    let mut out = Vec::new();
    let fits_i32 = i32::try_from(value).is_ok();
    let fits_u32 = u32::try_from(value).is_ok();
    match isa {
        Isa::X86 | Isa::X86_64 => {
            if value == 0 {
                out.extend_from_slice(&[0x31, 0xc0]);
            } else if fits_u32 || (isa == Isa::X86 && fits_i32) {
                out.push(0xb8);
                out.extend_from_slice(&(value as u32).to_le_bytes());
            } else if fits_i32 {
                out.extend_from_slice(&[0x48, 0xc7, 0xc0]);
                out.extend_from_slice(&(value as i32).to_le_bytes());
            } else if isa == Isa::X86_64 {
                out.extend_from_slice(&[0x48, 0xb8]);
                out.extend_from_slice(&value.to_le_bytes());
            } else {
                return err("a 32-bit x86 function returns at most 32 bits here");
            }
            out.push(0xc3);
        }
        Isa::Aarch64 => {
            let words = a64_load_x0(value);
            for w in words {
                out.extend_from_slice(&w.to_le_bytes());
            }
            out.extend_from_slice(&0xd65f_03c0u32.to_le_bytes());
        }
        Isa::Arm => {
            let v = match u32::try_from(value)
                .ok()
                .or_else(|| i32::try_from(value).ok().map(|v| v as u32))
            {
                Some(v) => v,
                None => return err("a 32-bit ARM function returns at most 32 bits here"),
            };
            if v <= 0xff {
                out.extend_from_slice(&(0xe3a0_0000 | v).to_le_bytes());
            } else {
                out.extend_from_slice(&a32_movw(v & 0xffff).to_le_bytes());
                if v >> 16 != 0 {
                    out.extend_from_slice(&(a32_movw(v >> 16) | 0x0040_0000).to_le_bytes());
                }
            }
            out.extend_from_slice(&0xe12f_ff1eu32.to_le_bytes());
        }
        Isa::Thumb => {
            if !(0..=255).contains(&value) {
                return err("in Thumb code a function can return 0 to 255 here");
            }
            out.extend_from_slice(&(0x2000u16 | value as u16).to_le_bytes());
            out.extend_from_slice(&0x4770u16.to_le_bytes());
        }
        Isa::Riscv32 | Isa::Riscv64 => {
            if !fits_i32 {
                return err("a RISC-V function returns a 32-bit value here");
            }
            let a0 = 10u32 << 7;
            if (-2048..2048).contains(&value) {
                out.extend_from_slice(&(((value as u32 & 0xfff) << 20) | a0 | 0x13).to_le_bytes());
            } else {
                let v = value as u32;
                let hi = v.wrapping_add(0x800) >> 12;
                let lo = v & 0xfff;
                out.extend_from_slice(&((hi << 12) | a0 | 0x37).to_le_bytes());
                let addi = if isa == Isa::Riscv64 { 0x1b } else { 0x13 };
                out.extend_from_slice(&((lo << 20) | (10 << 15) | a0 | addi).to_le_bytes());
            }
            out.extend_from_slice(&0x0000_8067u32.to_le_bytes());
        }
    }
    Ok(out)
}

fn a32_movw(v: u32) -> u32 {
    0xe300_0000 | ((v >> 12) << 16) | (v & 0xfff)
}

/// `movn`/`movz`/`movk` words that load `value` into x0.
fn a64_load_x0(value: i64) -> Vec<u32> {
    if (-65536..0).contains(&value) {
        return vec![0x9280_0000 | (((!value) as u32 & 0xffff) << 5)];
    }
    let v = value as u64;
    let mut words = Vec::new();
    for hw in 0..4u32 {
        let part = ((v >> (16 * hw)) & 0xffff) as u32;
        if part == 0 {
            continue;
        }
        let op = if words.is_empty() {
            0xd280_0000
        } else {
            0xf280_0000
        };
        words.push(op | (hw << 21) | (part << 5));
    }
    if words.is_empty() {
        words.push(0xd280_0000);
    }
    words
}

// ---- immediates -------------------------------------------------------------------------

/// A constant edit: the old value and the new instruction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstantEdit {
    /// The immediate before, as the instruction reads it.
    pub old: i64,
    /// The instruction with the new immediate (same length).
    pub bytes: Vec<u8>,
}

/// Rewrites the immediate operand of `insn` to `value` where the encoding allows it.
pub fn set_constant(isa: Isa, insn: &[u8], value: i64) -> R<ConstantEdit> {
    match isa {
        Isa::X86 | Isa::X86_64 => constant_x86(isa == Isa::X86_64, insn, value),
        Isa::Aarch64 => constant_a64(insn, value),
        Isa::Arm => constant_a32(insn, value),
        Isa::Thumb => constant_thumb(insn, value),
        Isa::Riscv32 | Isa::Riscv64 => constant_riscv(insn, value),
    }
}

fn range_err<T>(value: i64, what: &str) -> R<T> {
    err(format!(
        "{value} does not fit {what}; the instruction would need a longer encoding (use patch_set or a patch with assembly)"
    ))
}

fn constant_x86(is64: bool, b: &[u8], value: i64) -> R<ConstantEdit> {
    let mut i = 0;
    let (mut op16, mut rexw) = (false, false);
    while i < b.len()
        && matches!(
            b[i],
            0x66 | 0xf2 | 0xf3 | 0x2e | 0x3e | 0x26 | 0x36 | 0x64 | 0x65 | 0x67
        )
    {
        op16 |= b[i] == 0x66;
        i += 1;
    }
    if is64 && i < b.len() && (0x40..=0x4f).contains(&b[i]) {
        rexw = b[i] & 8 != 0;
        i += 1;
    }
    let Some(&op) = b.get(i) else {
        return err("empty instruction");
    };
    let z = if op16 { 2 } else { 4 };
    let reg = b.get(i + 1).map(|m| (m >> 3) & 7);
    // (immediate size, sign-extended immediate)
    let (size, sx) = match op {
        0xb0..=0xb7 => (1, false),
        0xb8..=0xbf => (if rexw { 8 } else { z }, false),
        0xc6 if reg == Some(0) => (1, false),
        0xc7 if reg == Some(0) => (z, rexw),
        0x80 | 0x82 => (1, false),
        0x83 => (1, true),
        0x81 => (z, rexw),
        0x04 | 0x0c | 0x14 | 0x1c | 0x24 | 0x2c | 0x34 | 0x3c | 0xa8 => (1, false),
        0x05 | 0x0d | 0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0xa9 => (z, rexw),
        0x68 => (z, is64),
        0x6a => (1, true),
        0x69 => (z, rexw),
        0x6b => (1, true),
        0xf6 if matches!(reg, Some(0 | 1)) => (1, false),
        0xf7 if matches!(reg, Some(0 | 1)) => (z, rexw),
        _ => {
            return err(format!(
                "no immediate operand this tool can change in {}",
                kraken_proto::hex_bytes(b)
            ));
        }
    };
    if b.len() < size + i + 1 {
        return err("the instruction is shorter than its immediate");
    }
    let at = b.len() - size;
    let raw = &b[at..];
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(raw);
    let unsigned = u64::from_le_bytes(buf);
    let signed_old = {
        let shift = 64 - 8 * size as u32;
        ((unsigned << shift) as i64) >> shift
    };
    let old = if sx || size == 8 {
        signed_old
    } else {
        unsigned as i64
    };
    let bits = 8 * size as u32;
    let ok = match size {
        8 => true,
        _ if sx => {
            let lim = 1i64 << (bits - 1);
            (-lim..lim).contains(&value)
        }
        _ => {
            let lim = 1i64 << (bits - 1);
            (-lim..(2 * lim)).contains(&value)
        }
    };
    if !ok {
        return range_err(value, &format!("the {size}-byte immediate"));
    }
    let mut out = b.to_vec();
    out[at..].copy_from_slice(&value.to_le_bytes()[..size]);
    Ok(ConstantEdit { old, bytes: out })
}

fn imm16_fit(v: u64, bits: u32) -> Option<(u32, u32)> {
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    let v = v & mask;
    (0..bits / 16).find_map(|hw| {
        let shifted = v >> (16 * hw);
        (shifted <= 0xffff && (shifted << (16 * hw)) == v).then_some((shifted as u32, hw))
    })
}

fn constant_a64(b: &[u8], value: i64) -> R<ConstantEdit> {
    let w = le32(b)?;
    let sf = w >> 31 == 1;
    let bits = if sf { 64 } else { 32 };
    if !sf && !(-(1i64 << 31)..(1i64 << 32)).contains(&value) {
        return range_err(value, "a 32-bit register");
    }
    if (w >> 23) & 0x3f == 0b10_0101 {
        let opc = (w >> 29) & 3;
        let hw = (w >> 21) & 3;
        let imm = u64::from((w >> 5) & 0xffff);
        let mask = if sf { u64::MAX } else { 0xffff_ffff };
        match opc {
            3 => {
                if !(0..=0xffff).contains(&value) {
                    return range_err(value, "a movk's 16 bits");
                }
                let nw = (w & !(0xffff << 5)) | ((value as u32) << 5);
                return Ok(ConstantEdit {
                    old: imm as i64,
                    bytes: nw.to_le_bytes().to_vec(),
                });
            }
            0 | 2 => {
                let full = imm << (16 * hw);
                let shown = if opc == 2 { full } else { !full & mask };
                let old = if sf {
                    shown as i64
                } else {
                    i64::from(shown as u32 as i32)
                };
                let v = value as u64 & mask;
                let base = w & 0x8000_0000 | (hw << 21);
                if let Some((i, h)) = imm16_fit(v, bits) {
                    let nw = base & !(3 << 21) | 0x5280_0000 | (h << 21) | (i << 5);
                    return Ok(ConstantEdit {
                        old,
                        bytes: nw.to_le_bytes().to_vec(),
                    });
                }
                if let Some((i, h)) = imm16_fit(!v & mask, bits) {
                    let nw = base & !(3 << 21) | 0x1280_0000 | (h << 21) | (i << 5);
                    return Ok(ConstantEdit {
                        old,
                        bytes: nw.to_le_bytes().to_vec(),
                    });
                }
                return range_err(value, "a single mov immediate (one 16-bit field)");
            }
            _ => {}
        }
    }
    if (w >> 23) & 0x3f == 0b10_0010 {
        let sh = (w >> 22) & 1;
        let old = i64::from((w >> 10) & 0xfff) << (12 * sh);
        let ok_value = |sh: u32| {
            let unit = 1i64 << (12 * sh);
            (0..4096 * unit).contains(&value) && value % unit == 0
        };
        if !ok_value(sh) {
            return range_err(
                value,
                if sh == 1 {
                    "imm12 shifted by 12"
                } else {
                    "imm12 (0 to 4095)"
                },
            );
        }
        let imm = (value >> (12 * sh)) as u32;
        let nw = (w & !(0xfff << 10)) | (imm << 10);
        return Ok(ConstantEdit {
            old,
            bytes: nw.to_le_bytes().to_vec(),
        });
    }
    err(format!(
        "no immediate this tool can change in {w:#010x} (handles mov, movk, add/sub/cmp immediates)"
    ))
}

fn constant_a32(b: &[u8], value: i64) -> R<ConstantEdit> {
    let w = le32(b)?;
    if !(-(1i64 << 31)..(1i64 << 32)).contains(&value) {
        return range_err(value, "32 bits");
    }
    let v = value as u32;
    if w & 0x0fb0_0000 == 0x0300_0000 {
        let old = i64::from(((w >> 4) & 0xf000) | (w & 0xfff));
        if v > 0xffff {
            return range_err(value, "movw/movt's 16 bits");
        }
        let nw = (w & 0xfff0_f000) | ((v >> 12) << 16) | (v & 0xfff);
        return Ok(ConstantEdit {
            old,
            bytes: nw.to_le_bytes().to_vec(),
        });
    }
    let opcode = (w >> 21) & 0xf;
    let s = (w >> 20) & 1;
    if (w >> 25) & 7 == 0b001 && !((8..=11).contains(&opcode) && s == 0) {
        let old = i64::from((w & 0xff).rotate_right(2 * ((w >> 8) & 0xf)));
        for rot in 0..16 {
            let imm8 = v.rotate_left(2 * rot);
            if imm8 <= 0xff {
                let nw = (w & 0xffff_f000) | (rot << 8) | imm8;
                return Ok(ConstantEdit {
                    old,
                    bytes: nw.to_le_bytes().to_vec(),
                });
            }
        }
        return range_err(
            value,
            "an ARM immediate (an 8-bit value rotated by an even amount)",
        );
    }
    err(format!(
        "no immediate this tool can change in {w:#010x} (handles data-processing immediates, movw, movt)"
    ))
}

fn constant_thumb(b: &[u8], value: i64) -> R<ConstantEdit> {
    let hw = le16(b)?;
    if hw >> 13 != 0b001 {
        return err(format!(
            "no immediate this tool can change in {hw:#06x} (handles movs, cmp, adds, subs with an 8-bit immediate)"
        ));
    }
    if !(0..=255).contains(&value) {
        return range_err(value, "an 8-bit immediate");
    }
    let nw = (hw & 0xff00) | value as u16;
    Ok(ConstantEdit {
        old: i64::from(hw & 0xff),
        bytes: nw.to_le_bytes().to_vec(),
    })
}

fn constant_riscv(b: &[u8], value: i64) -> R<ConstantEdit> {
    if b.len() == 2 {
        let hw = u32::from(le16(b)?);
        let kind = (hw & 3, hw >> 13);
        if kind != (1, 0b010) && kind != (1, 0b000) {
            return err(format!(
                "no immediate this tool can change in {hw:#06x} (handles c.li, c.addi)"
            ));
        }
        if !(-32..32).contains(&value) {
            return range_err(value, "a 6-bit immediate");
        }
        let old = sext(((hw >> 12) & 1) << 5 | ((hw >> 2) & 0x1f), 6);
        let imm = value as u32 & 0x3f;
        let nw = (hw & !(1 << 12) & !(0x1f << 2)) | ((imm >> 5) << 12) | ((imm & 0x1f) << 2);
        return Ok(ConstantEdit {
            old: i64::from(old),
            bytes: (nw as u16).to_le_bytes().to_vec(),
        });
    }
    let w = le32(b)?;
    let f3 = (w >> 12) & 7;
    let opcode = w & 0x7f;
    if opcode == 0x37 {
        let ok = value % 4096 == 0 && (-(1i64 << 31)..(1i64 << 31)).contains(&value);
        if !ok {
            return range_err(value, "lui (a multiple of 4096 within 32 bits)");
        }
        let nw = (w & 0xfff) | ((value as u32) & 0xffff_f000);
        return Ok(ConstantEdit {
            old: i64::from((w & 0xffff_f000) as i32),
            bytes: nw.to_le_bytes().to_vec(),
        });
    }
    let op_imm = opcode == 0x13 && !matches!(f3, 1 | 5);
    let op_imm32 = opcode == 0x1b && f3 == 0;
    if op_imm || op_imm32 || (opcode == 0x67 && f3 == 0) {
        if !(-2048..2048).contains(&value) {
            return range_err(value, "a 12-bit immediate");
        }
        let nw = (w & 0x000f_ffff) | ((value as u32 & 0xfff) << 20);
        return Ok(ConstantEdit {
            old: i64::from(sext(w >> 20, 12)),
            bytes: nw.to_le_bytes().to_vec(),
        });
    }
    err(format!(
        "no immediate this tool can change in {w:#010x} (handles addi, ori, andi, xori, slti, lui, c.li, c.addi)"
    ))
}

// ---- helpers for the commands -----------------------------------------------------------

/// The instruction bytes reach `needed` bytes (at least) when whole instructions of lengths
/// `lens` are taken from the start; `None` if they never do.
pub fn cover(lens: &[usize], needed: usize) -> Option<usize> {
    let mut total = 0;
    for l in lens {
        total += l;
        if total >= needed {
            return Some(total);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: &[u8]) -> String {
        kraken_proto::hex_bytes(b)
    }

    #[test]
    fn x86_nops_are_the_recommended_forms() {
        assert_eq!(h(&nop(Isa::X86_64, 1).unwrap()), "90");
        assert_eq!(h(&nop(Isa::X86_64, 3).unwrap()), "0f1f00");
        assert_eq!(h(&nop(Isa::X86_64, 5).unwrap()), "0f1f440000");
        assert_eq!(nop(Isa::X86_64, 12).unwrap().len(), 12);
        assert_eq!(h(&nop(Isa::X86_64, 10).unwrap()), "660f1f84000000000090");
    }

    #[test]
    fn other_nops() {
        assert_eq!(h(&nop(Isa::Aarch64, 8).unwrap()), "1f2003d51f2003d5");
        assert!(nop(Isa::Aarch64, 6).is_err());
        assert_eq!(h(&nop(Isa::Arm, 4).unwrap()), "00f020e3");
        assert_eq!(h(&nop(Isa::Thumb, 4).unwrap()), "00bf00bf");
        assert_eq!(h(&nop(Isa::Riscv64, 6).unwrap()), "130000000100");
    }

    #[test]
    fn x86_branches() {
        let jne = [0x75, 0x10];
        assert_eq!(
            h(&branch(Isa::X86_64, &jne, BranchMode::Invert).unwrap()),
            "7410"
        );
        assert_eq!(
            h(&branch(Isa::X86_64, &jne, BranchMode::Always).unwrap()),
            "eb10"
        );
        assert_eq!(
            h(&branch(Isa::X86_64, &jne, BranchMode::Never).unwrap()),
            "6690"
        );
        let near = [0x0f, 0x84, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(
            h(&branch(Isa::X86_64, &near, BranchMode::Invert).unwrap()),
            "0f8510000000"
        );
        // The jump is one byte shorter, so the displacement grows by one to hit the same target.
        assert_eq!(
            h(&branch(Isa::X86_64, &near, BranchMode::Always).unwrap()),
            "e91100000090"
        );
        assert!(branch(Isa::X86_64, &[0xc3], BranchMode::Invert).is_err());
        assert!(branch(Isa::X86_64, &[0xeb, 0x10], BranchMode::Invert).is_err());
    }

    #[test]
    fn aarch64_branches() {
        // b.eq +8
        let beq = 0x5400_0040u32.to_le_bytes();
        let inv = branch(Isa::Aarch64, &beq, BranchMode::Invert).unwrap();
        assert_eq!(u32::from_le_bytes(inv.try_into().unwrap()), 0x5400_0041);
        let always = branch(Isa::Aarch64, &beq, BranchMode::Always).unwrap();
        assert_eq!(u32::from_le_bytes(always.try_into().unwrap()), 0x1400_0002);
        // cbz w0, +8 -> cbnz
        let cbz = 0x3400_0040u32.to_le_bytes();
        let inv = branch(Isa::Aarch64, &cbz, BranchMode::Invert).unwrap();
        assert_eq!(u32::from_le_bytes(inv.try_into().unwrap()), 0x3500_0040);
        // a backward b.cond keeps its sign
        let back = (0x5400_0000u32 | (0x7_fffe << 5)).to_le_bytes();
        let always = branch(Isa::Aarch64, &back, BranchMode::Always).unwrap();
        assert_eq!(u32::from_le_bytes(always.try_into().unwrap()), 0x17ff_fffe);
        assert!(
            branch(
                Isa::Aarch64,
                &0xd65f_03c0u32.to_le_bytes(),
                BranchMode::Invert
            )
            .is_err()
        );
    }

    #[test]
    fn arm_branches() {
        let beq = 0x0a00_0004u32.to_le_bytes();
        let inv = branch(Isa::Arm, &beq, BranchMode::Invert).unwrap();
        assert_eq!(u32::from_le_bytes(inv.try_into().unwrap()), 0x1a00_0004);
        let always = branch(Isa::Arm, &beq, BranchMode::Always).unwrap();
        assert_eq!(u32::from_le_bytes(always.try_into().unwrap()), 0xea00_0004);
        assert!(branch(Isa::Arm, &0xea00_0004u32.to_le_bytes(), BranchMode::Invert).is_err());
        // thumb beq -> bne, and b
        let t = 0xd005u16.to_le_bytes();
        assert_eq!(
            h(&branch(Isa::Thumb, &t, BranchMode::Invert).unwrap()),
            "05d1"
        );
        assert_eq!(
            h(&branch(Isa::Thumb, &t, BranchMode::Always).unwrap()),
            "05e0"
        );
    }

    #[test]
    fn riscv_branches() {
        // beq a0,a1,+8
        let beq = 0x00b5_0463u32.to_le_bytes();
        let inv = branch(Isa::Riscv64, &beq, BranchMode::Invert).unwrap();
        assert_eq!(u32::from_le_bytes(inv.try_into().unwrap()), 0x00b5_1463);
        let j = branch(Isa::Riscv64, &beq, BranchMode::Always).unwrap();
        assert_eq!(u32::from_le_bytes(j.try_into().unwrap()), 0x0080_006f);
        // c.beqz a0,+4 -> c.bnez / c.j +4
        let c = 0xc111u16.to_le_bytes();
        assert_eq!(
            h(&branch(Isa::Riscv64, &c, BranchMode::Invert).unwrap()),
            "11e1"
        );
        assert_eq!(
            h(&branch(Isa::Riscv64, &c, BranchMode::Always).unwrap()),
            "11a0"
        );
    }

    #[test]
    fn returns() {
        assert_eq!(h(&return_value(Isa::X86_64, 0).unwrap()), "31c0c3");
        assert_eq!(h(&return_value(Isa::X86_64, 1).unwrap()), "b801000000c3");
        assert_eq!(
            h(&return_value(Isa::X86_64, -1).unwrap()),
            "48c7c0ffffffffc3"
        );
        assert_eq!(
            h(&return_value(Isa::Aarch64, 1).unwrap()),
            "200080d2c0035fd6"
        );
        assert_eq!(
            h(&return_value(Isa::Aarch64, -1).unwrap()),
            "00008092c0035fd6"
        );
        assert_eq!(h(&return_value(Isa::Arm, 7).unwrap()), "0700a0e31eff2fe1");
        assert_eq!(
            h(&return_value(Isa::Riscv64, 5).unwrap()),
            "1305500067800000"
        );
        assert!(return_value(Isa::Riscv64, 1 << 40).is_err());
    }

    #[test]
    fn x86_constants() {
        // cmp eax, 5 (83 f8 05) -> 9
        let e = set_constant(Isa::X86_64, &[0x83, 0xf8, 0x05], 9).unwrap();
        assert_eq!((e.old, h(&e.bytes).as_str()), (5, "83f809"));
        assert!(set_constant(Isa::X86_64, &[0x83, 0xf8, 0x05], 300).is_err());
        // mov eax, 1
        let e = set_constant(Isa::X86_64, &[0xb8, 1, 0, 0, 0], 0x1234).unwrap();
        assert_eq!(h(&e.bytes), "b834120000");
        // mov dword [rbp-4], 3 (c7 45 fc 03 00 00 00)
        let e = set_constant(Isa::X86_64, &[0xc7, 0x45, 0xfc, 3, 0, 0, 0], -2).unwrap();
        assert_eq!(h(&e.bytes), "c745fcfeffffff");
        assert!(set_constant(Isa::X86_64, &[0x90], 1).is_err());
    }

    #[test]
    fn other_constants() {
        // mov w0,#1 -> #7
        let e = set_constant(Isa::Aarch64, &0x5280_0020u32.to_le_bytes(), 7).unwrap();
        assert_eq!(e.old, 1);
        assert_eq!(u32::from_le_bytes(e.bytes.try_into().unwrap()), 0x5280_00e0);
        // mov w0,#1 -> -1 becomes movn
        let e = set_constant(Isa::Aarch64, &0x5280_0020u32.to_le_bytes(), -1).unwrap();
        assert_eq!(u32::from_le_bytes(e.bytes.try_into().unwrap()), 0x1280_0000);
        // cmp w0,#5 (subs wzr,w0,#5) -> #9
        let e = set_constant(Isa::Aarch64, &0x7100_141fu32.to_le_bytes(), 9).unwrap();
        assert_eq!(u32::from_le_bytes(e.bytes.try_into().unwrap()), 0x7100_241f);
        // arm mov r0,#1 -> #0x100
        let e = set_constant(Isa::Arm, &0xe3a0_0001u32.to_le_bytes(), 0x100).unwrap();
        assert_eq!(u32::from_le_bytes(e.bytes.try_into().unwrap()), 0xe3a0_0c01);
        assert!(set_constant(Isa::Arm, &0xe3a0_0001u32.to_le_bytes(), 0x101).is_err());
        // riscv addi a0,zero,1 -> 100
        let e = set_constant(Isa::Riscv64, &0x0010_0513u32.to_le_bytes(), 100).unwrap();
        assert_eq!(u32::from_le_bytes(e.bytes.try_into().unwrap()), 0x0640_0513);
        assert!(set_constant(Isa::Riscv64, &0x0010_0513u32.to_le_bytes(), 5000).is_err());
    }

    #[test]
    fn language_ids() {
        assert_eq!(
            Isa::from_language("x86:LE:64:default", false),
            Some(Isa::X86_64)
        );
        assert_eq!(
            Isa::from_language("AARCH64:LE:64:v8A", false),
            Some(Isa::Aarch64)
        );
        assert_eq!(Isa::from_language("ARM:LE:32:v8", true), Some(Isa::Thumb));
        assert_eq!(Isa::from_language("ARM:BE:32:v8", false), None);
        assert_eq!(Isa::from_language("MIPS:LE:32:default", false), None);
    }
}

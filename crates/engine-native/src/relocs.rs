//! The relocations of ARM (A32 and Thumb), AArch64 and RISC-V object files, applied the way a
//! linker without relaxation applies them: data words, branch and call offsets in their
//! instruction fields (a call between A32 and Thumb becomes `blx`), page and low-12-bit
//! address pairs (AArch64 `adrp`, RISC-V `auipc` with the `%pcrel_lo` that refers back to it),
//! GOT slots, and RISC-V's in-place arithmetic for the DWARF and unwind tables (`ADD`/`SUB`,
//! `SET`, ULEB128).

use std::collections::BTreeMap;

use object::Architecture;
use object::elf::*;

// the ARM ELF ABI's names for the types `object` names after their older spellings
const R_ARM_GOTOFF32: RelocationType = R_ARM_GOTOFF;
const R_ARM_BASE_PREL: RelocationType = R_ARM_GOTPC;
const R_ARM_GOT_BREL: RelocationType = R_ARM_GOT32;
const R_ARM_THM_CALL: RelocationType = R_ARM_THM_PC22;

/// Where a relocation points.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Target {
    /// The symbol's address (with the Thumb bit for a Thumb function).
    pub s: u64,
    /// The address of its GOT slot, if it has one.
    pub slot: u64,
    /// The GOT's address (`_GLOBAL_OFFSET_TABLE_`).
    pub got: u64,
    /// The addend of a RELA relocation; `None` for REL (ARM), whose addend is in the field.
    pub addend: Option<i64>,
}

/// What applying one relocation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Applied {
    /// Patched; the value is an absolute pointer when `Some`.
    Done(Option<u64>),
    /// A type this module does not handle (or one that needs nothing, such as `R_RISCV_RELAX`).
    Skipped,
}

/// Whether relocation type `r_type` of `arch` needs a GOT slot for its symbol, and whether it
/// needs the GOT's address.
pub(crate) fn got_use(arch: Architecture, r_type: RelocationType) -> (bool, bool) {
    match arch {
        Architecture::Arm => match r_type {
            R_ARM_GOT_BREL | R_ARM_GOT_PREL => (true, true),
            R_ARM_BASE_PREL | R_ARM_GOTOFF32 => (false, true),
            _ => (false, false),
        },
        Architecture::Aarch64 => match r_type {
            R_AARCH64_ADR_GOT_PAGE | R_AARCH64_LD64_GOT_LO12_NC | R_AARCH64_LD64_GOTPAGE_LO15 => {
                (true, true)
            }
            _ => (false, false),
        },
        Architecture::Riscv32 | Architecture::Riscv64 => match r_type {
            R_RISCV_GOT_HI20 => (true, true),
            _ => (false, false),
        },
        _ => (false, false),
    }
}

fn sext(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn get(bytes: &[u8], off: usize, n: usize) -> Option<u64> {
    let b = bytes.get(off..off.checked_add(n)?)?;
    let mut w = [0u8; 8];
    w[..n].copy_from_slice(b);
    Some(u64::from_le_bytes(w))
}

fn put(bytes: &mut [u8], off: usize, n: usize, v: u64) -> Option<()> {
    let b = bytes.get_mut(off..off.checked_add(n)?)?;
    b.copy_from_slice(&v.to_le_bytes()[..n]);
    Some(())
}

fn get32(bytes: &[u8], off: usize) -> Option<u32> {
    get(bytes, off, 4).map(|v| v as u32)
}

fn put32(bytes: &mut [u8], off: usize, v: u32) -> Option<()> {
    put(bytes, off, 4, u64::from(v))
}

/// The page (4 KiB) of an address, for AArch64 `adrp`.
fn page(a: u64) -> u64 {
    a & !0xfff
}

/// RISC-V: the 20 bits `auipc`/`lui` adds, rounded so the low 12 bits (sign-extended) make up
/// the rest.
fn hi20(v: i64) -> u32 {
    ((v.wrapping_add(0x800) >> 12) as u32) & 0xf_ffff
}

fn set_i_imm(w: u32, lo: i64) -> u32 {
    (w & 0x000f_ffff) | (((lo as u32) & 0xfff) << 20)
}

fn set_s_imm(w: u32, lo: i64) -> u32 {
    let lo = lo as u32;
    (w & 0x01ff_f07f) | ((lo & 0xfe0) << 20) | ((lo & 0x1f) << 7)
}

fn set_b_imm(w: u32, off: i64) -> u32 {
    let o = off as u32;
    (w & 0x01ff_f07f)
        | ((o >> 12) & 1) << 31
        | ((o >> 5) & 0x3f) << 25
        | ((o >> 1) & 0xf) << 8
        | ((o >> 11) & 1) << 7
}

fn set_j_imm(w: u32, off: i64) -> u32 {
    let o = off as u32;
    (w & 0xfff)
        | ((o >> 20) & 1) << 31
        | ((o >> 1) & 0x3ff) << 21
        | ((o >> 11) & 1) << 20
        | ((o >> 12) & 0xff) << 12
}

fn set_cb_imm(h: u16, off: i64) -> u16 {
    let o = off as u16;
    (h & 0xe383)
        | ((o >> 8) & 1) << 12
        | ((o >> 3) & 3) << 10
        | ((o >> 6) & 3) << 5
        | ((o >> 1) & 3) << 3
        | ((o >> 5) & 1) << 2
}

fn set_cj_imm(h: u16, off: i64) -> u16 {
    let o = off as u16;
    (h & 0xe003)
        | ((o >> 11) & 1) << 12
        | ((o >> 4) & 1) << 11
        | ((o >> 8) & 3) << 9
        | ((o >> 10) & 1) << 8
        | ((o >> 6) & 1) << 7
        | ((o >> 7) & 1) << 6
        | ((o >> 1) & 7) << 3
        | ((o >> 5) & 1) << 2
}

/// A ULEB128 at `off`: its value and length.
fn uleb(bytes: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for i in 0..10 {
        let b = *bytes.get(off + i)?;
        v |= u64::from(b & 0x7f) << (7 * i);
        if b & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Rewrites the ULEB128 at `off` with `v` in the same number of bytes.
fn put_uleb(bytes: &mut [u8], off: usize, len: usize, mut v: u64) -> Option<()> {
    for i in 0..len {
        let more = if i + 1 < len { 0x80 } else { 0 };
        *bytes.get_mut(off + i)? = (v & 0x7f) as u8 | more;
        v >>= 7;
    }
    Some(())
}

/// The value of the Thumb `bl`/`blx`/`b.w` offset in `(hw1, hw2)`.
fn thumb_branch(hw1: u16, hw2: u16) -> i64 {
    let (h1, h2) = (u64::from(hw1), u64::from(hw2));
    let s = (h1 >> 10) & 1;
    let i1 = 1 ^ ((h2 >> 13) & 1) ^ s;
    let i2 = 1 ^ ((h2 >> 11) & 1) ^ s;
    sext(
        s << 24 | i1 << 23 | i2 << 22 | (h1 & 0x3ff) << 12 | (h2 & 0x7ff) << 1,
        25,
    )
}

fn set_thumb_branch(hw1: u16, hw2: u16, v: i64) -> (u16, u16) {
    let v = v as u64;
    let s = (v >> 24) & 1;
    let j1 = (1 ^ ((v >> 23) & 1)) ^ s;
    let j2 = (1 ^ ((v >> 22) & 1)) ^ s;
    let h1 = (u64::from(hw1) & 0xf800) | s << 10 | ((v >> 12) & 0x3ff);
    let h2 = (u64::from(hw2) & 0xd000) | j1 << 13 | j2 << 11 | ((v >> 1) & 0x7ff);
    (h1 as u16, h2 as u16)
}

/// The 16-bit immediate of an A32 `movw`/`movt`.
fn arm_imm16(w: u32) -> u32 {
    ((w >> 4) & 0xf000) | (w & 0xfff)
}

fn set_arm_imm16(w: u32, v: u32) -> u32 {
    (w & 0xfff0_f000) | ((v & 0xf000) << 4) | (v & 0xfff)
}

/// The 16-bit immediate of a Thumb `movw`/`movt` (`imm4:i:imm3:imm8`).
fn thumb_imm16(hw1: u16, hw2: u16) -> u32 {
    let (h1, h2) = (u32::from(hw1), u32::from(hw2));
    (h1 & 0xf) << 12 | ((h1 >> 10) & 1) << 11 | ((h2 >> 12) & 7) << 8 | (h2 & 0xff)
}

fn set_thumb_imm16(hw1: u16, hw2: u16, v: u32) -> (u16, u16) {
    let h1 = (u32::from(hw1) & 0xfbf0) | ((v >> 12) & 0xf) | ((v >> 11) & 1) << 10;
    let h2 = (u32::from(hw2) & 0x8f00) | ((v >> 8) & 7) << 12 | (v & 0xff);
    (h1 as u16, h2 as u16)
}

/// Computes the `%pcrel_hi` offsets of the RISC-V `auipc` instructions of a section (by the
/// address of the `auipc`), which the `%pcrel_lo` relocations name by their label.
pub(crate) fn riscv_hi(r_type: RelocationType, p: u64, t: &Target) -> Option<i64> {
    let a = t.addend.unwrap_or(0);
    match r_type {
        R_RISCV_PCREL_HI20 => Some((t.s as i64).wrapping_add(a).wrapping_sub(p as i64)),
        R_RISCV_GOT_HI20 => Some((t.slot as i64).wrapping_add(a).wrapping_sub(p as i64)),
        _ => None,
    }
}

/// Applies relocation `r_type` at `off` of `bytes` (address `p`). `hi` holds the RISC-V
/// `%pcrel_hi` offsets by `auipc` address (see [`riscv_hi`]).
pub(crate) fn apply(
    arch: Architecture,
    r_type: RelocationType,
    bytes: &mut [u8],
    off: usize,
    p: u64,
    t: &Target,
    hi: &BTreeMap<u64, i64>,
) -> Applied {
    let done = match arch {
        Architecture::Arm => arm(r_type, bytes, off, p, t),
        Architecture::Aarch64 => aarch64(r_type, bytes, off, p, t),
        Architecture::Riscv32 | Architecture::Riscv64 => {
            riscv(arch == Architecture::Riscv64, r_type, bytes, off, p, t, hi)
        }
        _ => None,
    };
    done.map_or(Applied::Skipped, Applied::Done)
}

fn arm(
    r_type: RelocationType,
    bytes: &mut [u8],
    off: usize,
    p: u64,
    t: &Target,
) -> Option<Option<u64>> {
    let (s, p, got, slot) = (t.s as i64, p as i64, t.got as i64, t.slot as i64);
    let word = |b: &[u8]| get32(b, off);
    let a32 = |b: &[u8]| -> Option<i64> { Some(t.addend.unwrap_or(i64::from(word(b)? as i32))) };
    let mask = |v: i64| (v as u64) & 0xffff_ffff;
    match r_type {
        R_ARM_ABS32 | R_ARM_TARGET1 => {
            let v = mask(s + a32(bytes)?);
            put32(bytes, off, v as u32)?;
            Some(Some(v))
        }
        R_ARM_REL32 => put32(bytes, off, mask(s + a32(bytes)? - p) as u32).map(|_| None),
        R_ARM_PREL31 => {
            let w = word(bytes)?;
            let a = t.addend.unwrap_or(sext(u64::from(w & 0x7fff_ffff), 31));
            let v = (mask(s + a - p) as u32 & 0x7fff_ffff) | (w & 0x8000_0000);
            put32(bytes, off, v).map(|_| None)
        }
        R_ARM_BASE_PREL => put32(bytes, off, mask(got + a32(bytes)? - p) as u32).map(|_| None),
        R_ARM_GOT_BREL => put32(bytes, off, mask(slot + a32(bytes)? - got) as u32).map(|_| None),
        R_ARM_GOT_PREL => put32(bytes, off, mask(slot + a32(bytes)? - p) as u32).map(|_| None),
        R_ARM_GOTOFF32 => put32(bytes, off, mask(s + a32(bytes)? - got) as u32).map(|_| None),
        R_ARM_CALL | R_ARM_JUMP24 | R_ARM_PC24 => {
            let w = word(bytes)?;
            let a = t
                .addend
                .unwrap_or(sext(u64::from(w & 0x00ff_ffff), 24) << 2);
            let thumb = s & 1 == 1;
            let v = (s & !1) + a - p;
            let new = if thumb && r_type == R_ARM_CALL {
                // a call into Thumb code is a `blx`, with bit 1 of the offset in H
                0xfa00_0000 | (((v >> 1) & 1) as u32) << 24 | ((v >> 2) as u32 & 0x00ff_ffff)
            } else {
                (w & 0xff00_0000) | ((v >> 2) as u32 & 0x00ff_ffff)
            };
            put32(bytes, off, new).map(|_| None)
        }
        R_ARM_MOVW_ABS_NC | R_ARM_MOVT_ABS | R_ARM_MOVW_PREL_NC | R_ARM_MOVT_PREL => {
            let w = word(bytes)?;
            let a = t.addend.unwrap_or(sext(u64::from(arm_imm16(w)), 16));
            let rel = matches!(r_type, R_ARM_MOVW_PREL_NC | R_ARM_MOVT_PREL);
            let v = mask(s + a - if rel { p } else { 0 });
            let half = if matches!(r_type, R_ARM_MOVT_ABS | R_ARM_MOVT_PREL) {
                v >> 16
            } else {
                v
            };
            put32(bytes, off, set_arm_imm16(w, half as u32 & 0xffff)).map(|_| None)
        }
        R_ARM_THM_CALL | R_ARM_THM_JUMP24 => {
            let hw1 = get(bytes, off, 2)? as u16;
            let mut hw2 = get(bytes, off + 2, 2)? as u16;
            let a = t.addend.unwrap_or(thumb_branch(hw1, hw2));
            let thumb = s & 1 == 1;
            let v = if r_type == R_ARM_THM_CALL && !thumb {
                // a call into A32 code is a `blx`, from the word-aligned pc
                hw2 &= !0x1000;
                ((s & !1) + a - (p & !3)) & !3
            } else {
                if r_type == R_ARM_THM_CALL {
                    hw2 |= 0x1000;
                }
                (s & !1) + a - p
            };
            let (h1, h2) = set_thumb_branch(hw1, hw2, v);
            put(bytes, off, 2, u64::from(h1))?;
            put(bytes, off + 2, 2, u64::from(h2)).map(|_| None)
        }
        R_ARM_THM_JUMP19 => {
            let hw1 = u64::from(get(bytes, off, 2)? as u16);
            let hw2 = u64::from(get(bytes, off + 2, 2)? as u16);
            let a = t.addend.unwrap_or_else(|| {
                let sgn = (hw1 >> 10) & 1;
                let (j1, j2) = ((hw2 >> 13) & 1, (hw2 >> 11) & 1);
                sext(
                    sgn << 20 | j2 << 19 | j1 << 18 | (hw1 & 0x3f) << 12 | (hw2 & 0x7ff) << 1,
                    21,
                )
            });
            let v = ((s & !1) + a - p) as u64;
            let h1 = (hw1 & 0xfbc0) | ((v >> 20) & 1) << 10 | ((v >> 12) & 0x3f);
            let h2 =
                (hw2 & 0xd000) | ((v >> 18) & 1) << 13 | ((v >> 19) & 1) << 11 | ((v >> 1) & 0x7ff);
            put(bytes, off, 2, h1)?;
            put(bytes, off + 2, 2, h2).map(|_| None)
        }
        R_ARM_THM_MOVW_ABS_NC
        | R_ARM_THM_MOVT_ABS
        | R_ARM_THM_MOVW_PREL_NC
        | R_ARM_THM_MOVT_PREL => {
            let hw1 = get(bytes, off, 2)? as u16;
            let hw2 = get(bytes, off + 2, 2)? as u16;
            let a = t
                .addend
                .unwrap_or(sext(u64::from(thumb_imm16(hw1, hw2)), 16));
            let rel = matches!(r_type, R_ARM_THM_MOVW_PREL_NC | R_ARM_THM_MOVT_PREL);
            let v = mask(s + a - if rel { p } else { 0 });
            let half = if matches!(r_type, R_ARM_THM_MOVT_ABS | R_ARM_THM_MOVT_PREL) {
                v >> 16
            } else {
                v
            };
            let (h1, h2) = set_thumb_imm16(hw1, hw2, half as u32 & 0xffff);
            put(bytes, off, 2, u64::from(h1))?;
            put(bytes, off + 2, 2, u64::from(h2)).map(|_| None)
        }
        // interworking marks and markers for the linker
        R_ARM_NONE | R_ARM_V4BX => Some(None),
        _ => None,
    }
}

fn aarch64(
    r_type: RelocationType,
    bytes: &mut [u8],
    off: usize,
    p: u64,
    t: &Target,
) -> Option<Option<u64>> {
    let a = t.addend.unwrap_or(0);
    let (s, pi) = (t.s as i64, p as i64);
    let target = s.wrapping_add(a);
    let w = || get32(bytes, off);
    match r_type {
        R_AARCH64_ABS64 => {
            let v = target as u64;
            put(bytes, off, 8, v)?;
            Some(Some(v))
        }
        R_AARCH64_ABS32 => put32(bytes, off, target as u32).map(|_| None),
        R_AARCH64_ABS16 => put(bytes, off, 2, target as u64 & 0xffff).map(|_| None),
        R_AARCH64_PREL64 => put(bytes, off, 8, (target - pi) as u64).map(|_| None),
        R_AARCH64_PREL32 => put32(bytes, off, (target - pi) as u32).map(|_| None),
        R_AARCH64_PREL16 => put(bytes, off, 2, (target - pi) as u64 & 0xffff).map(|_| None),
        R_AARCH64_CALL26 | R_AARCH64_JUMP26 => {
            let v = ((target - pi) >> 2) as u32 & 0x03ff_ffff;
            put32(bytes, off, (w()? & 0xfc00_0000) | v).map(|_| None)
        }
        R_AARCH64_CONDBR19 | R_AARCH64_LD_PREL_LO19 => {
            let v = ((target - pi) >> 2) as u32 & 0x7ffff;
            put32(bytes, off, (w()? & 0xff00_001f) | v << 5).map(|_| None)
        }
        R_AARCH64_TSTBR14 => {
            let v = ((target - pi) >> 2) as u32 & 0x3fff;
            put32(bytes, off, (w()? & 0xfff8_001f) | v << 5).map(|_| None)
        }
        R_AARCH64_ADR_PREL_PG_HI21
        | R_AARCH64_ADR_PREL_PG_HI21_NC
        | R_AARCH64_ADR_GOT_PAGE
        | R_AARCH64_ADR_PREL_LO21 => {
            let imm = match r_type {
                R_AARCH64_ADR_PREL_LO21 => target - pi,
                R_AARCH64_ADR_GOT_PAGE => {
                    (page((t.slot as i64 + a) as u64) as i64 - page(p) as i64) >> 12
                }
                _ => (page(target as u64) as i64 - page(p) as i64) >> 12,
            } as u32;
            let new = (w()? & 0x9f00_001f) | (imm & 3) << 29 | ((imm >> 2) & 0x7ffff) << 5;
            put32(bytes, off, new).map(|_| None)
        }
        R_AARCH64_ADD_ABS_LO12_NC
        | R_AARCH64_LDST8_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC
        | R_AARCH64_LDST128_ABS_LO12_NC
        | R_AARCH64_LD64_GOT_LO12_NC => {
            let scale = match r_type {
                R_AARCH64_LDST16_ABS_LO12_NC => 1,
                R_AARCH64_LDST32_ABS_LO12_NC => 2,
                R_AARCH64_LDST64_ABS_LO12_NC | R_AARCH64_LD64_GOT_LO12_NC => 3,
                R_AARCH64_LDST128_ABS_LO12_NC => 4,
                _ => 0,
            };
            let v = if r_type == R_AARCH64_LD64_GOT_LO12_NC {
                (t.slot as i64).wrapping_add(a)
            } else {
                target
            };
            let imm = ((v as u32) & 0xfff) >> scale;
            put32(bytes, off, (w()? & !(0xfff << 10)) | imm << 10).map(|_| None)
        }
        R_AARCH64_NONE => Some(None),
        _ => None,
    }
}

fn riscv(
    rv64: bool,
    r_type: RelocationType,
    bytes: &mut [u8],
    off: usize,
    p: u64,
    t: &Target,
    hi: &BTreeMap<u64, i64>,
) -> Option<Option<u64>> {
    let a = t.addend.unwrap_or(0);
    let (s, pi) = (t.s as i64, p as i64);
    let v = s.wrapping_add(a);
    let w = || get32(bytes, off);
    let h = || get(bytes, off, 2).map(|x| x as u16);
    match r_type {
        R_RISCV_64 => {
            put(bytes, off, 8, v as u64)?;
            Some(rv64.then_some(v as u64))
        }
        R_RISCV_32 => {
            put32(bytes, off, v as u32)?;
            Some((!rv64).then_some(v as u64 & 0xffff_ffff))
        }
        R_RISCV_32_PCREL => put32(bytes, off, (v - pi) as u32).map(|_| None),
        R_RISCV_BRANCH => put32(bytes, off, set_b_imm(w()?, v - pi)).map(|_| None),
        R_RISCV_JAL => put32(bytes, off, set_j_imm(w()?, v - pi)).map(|_| None),
        R_RISCV_CALL | R_RISCV_CALL_PLT => {
            let o = v - pi;
            let auipc = (w()? & 0xfff) | hi20(o) << 12;
            let jalr = set_i_imm(get32(bytes, off + 4)?, o);
            put32(bytes, off, auipc)?;
            put32(bytes, off + 4, jalr).map(|_| None)
        }
        R_RISCV_PCREL_HI20 | R_RISCV_GOT_HI20 => {
            let o = riscv_hi(r_type, p, t)?;
            put32(bytes, off, (w()? & 0xfff) | hi20(o) << 12).map(|_| None)
        }
        R_RISCV_PCREL_LO12_I | R_RISCV_PCREL_LO12_S => {
            // the symbol is the label of the `auipc` whose offset this completes
            let o = *hi.get(&t.s)?;
            let new = if r_type == R_RISCV_PCREL_LO12_I {
                set_i_imm(w()?, o)
            } else {
                set_s_imm(w()?, o)
            };
            put32(bytes, off, new).map(|_| None)
        }
        R_RISCV_HI20 => put32(bytes, off, (w()? & 0xfff) | hi20(v) << 12).map(|_| None),
        R_RISCV_LO12_I => put32(bytes, off, set_i_imm(w()?, v)).map(|_| None),
        R_RISCV_LO12_S => put32(bytes, off, set_s_imm(w()?, v)).map(|_| None),
        R_RISCV_RVC_BRANCH => put(bytes, off, 2, u64::from(set_cb_imm(h()?, v - pi))).map(|_| None),
        R_RISCV_RVC_JUMP => put(bytes, off, 2, u64::from(set_cj_imm(h()?, v - pi))).map(|_| None),
        R_RISCV_ADD8 | R_RISCV_ADD16 | R_RISCV_ADD32 | R_RISCV_ADD64 | R_RISCV_SUB8
        | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64 => {
            let n = match r_type {
                R_RISCV_ADD8 | R_RISCV_SUB8 => 1,
                R_RISCV_ADD16 | R_RISCV_SUB16 => 2,
                R_RISCV_ADD32 | R_RISCV_SUB32 => 4,
                _ => 8,
            };
            let old = get(bytes, off, n)?;
            let sub = matches!(
                r_type,
                R_RISCV_SUB8 | R_RISCV_SUB16 | R_RISCV_SUB32 | R_RISCV_SUB64
            );
            let new = if sub {
                old.wrapping_sub(v as u64)
            } else {
                old.wrapping_add(v as u64)
            };
            put(bytes, off, n, new).map(|_| None)
        }
        R_RISCV_SET6 | R_RISCV_SUB6 => {
            let old = get(bytes, off, 1)?;
            let low = if r_type == R_RISCV_SET6 {
                v as u64
            } else {
                old.wrapping_sub(v as u64)
            };
            put(bytes, off, 1, (old & 0xc0) | (low & 0x3f)).map(|_| None)
        }
        R_RISCV_SET8 => put(bytes, off, 1, v as u64).map(|_| None),
        R_RISCV_SET16 => put(bytes, off, 2, v as u64).map(|_| None),
        R_RISCV_SET32 => put32(bytes, off, v as u32).map(|_| None),
        R_RISCV_SET_ULEB128 | R_RISCV_SUB_ULEB128 => {
            let (old, len) = uleb(bytes, off)?;
            let new = if r_type == R_RISCV_SET_ULEB128 {
                v as u64
            } else {
                old.wrapping_sub(v as u64)
            };
            put_uleb(bytes, off, len, new).map(|_| None)
        }
        // relaxation hints: nothing is relaxed
        R_RISCV_RELAX | R_RISCV_ALIGN | R_RISCV_NONE => Some(None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(s: u64, addend: Option<i64>) -> Target {
        Target {
            s,
            addend,
            ..Target::default()
        }
    }

    #[test]
    fn arm_calls_switch_modes() {
        // A32 `bl` (addend -8 in the field) to a Thumb function becomes `blx`
        let mut b = 0xebff_fffeu32.to_le_bytes().to_vec();
        let r = apply(
            Architecture::Arm,
            R_ARM_CALL,
            &mut b,
            0,
            0x1000,
            &target(0x1101, None),
            &BTreeMap::new(),
        );
        assert_eq!(r, Applied::Done(None));
        assert_eq!(u32::from_le_bytes([b[0], b[1], b[2], b[3]]), 0xfa00_003e);
        // Thumb `bl` (addend -4) to a Thumb function at 0x2000 from 0x1000
        let mut b = vec![0xff, 0xf7, 0xfe, 0xff];
        apply(
            Architecture::Arm,
            R_ARM_THM_CALL,
            &mut b,
            0,
            0x1000,
            &target(0x2001, None),
            &BTreeMap::new(),
        );
        let (h1, h2) = (
            u16::from_le_bytes([b[0], b[1]]),
            u16::from_le_bytes([b[2], b[3]]),
        );
        assert_eq!(thumb_branch(h1, h2), 0xffc);
        assert_eq!(h2 & 0x1000, 0x1000, "stays bl");
        // and to an A32 function: blx, aligned
        let mut b = vec![0xff, 0xf7, 0xfe, 0xff];
        apply(
            Architecture::Arm,
            R_ARM_THM_CALL,
            &mut b,
            0,
            0x1002,
            &target(0x2000, None),
            &BTreeMap::new(),
        );
        let h2 = u16::from_le_bytes([b[2], b[3]]);
        assert_eq!(h2 & 0x1000, 0, "becomes blx");
    }

    #[test]
    fn aarch64_page_pairs() {
        let mut b = 0x9000_0000u32.to_le_bytes().to_vec(); // adrp x0, 0
        apply(
            Architecture::Aarch64,
            R_AARCH64_ADR_PREL_PG_HI21,
            &mut b,
            0,
            0x10_0ffc,
            &target(0x12_3456, Some(0)),
            &BTreeMap::new(),
        );
        let w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let imm = ((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3;
        assert_eq!(imm, 0x23);
        let mut b = 0x9100_0000u32.to_le_bytes().to_vec(); // add x0, x0, #0
        apply(
            Architecture::Aarch64,
            R_AARCH64_ADD_ABS_LO12_NC,
            &mut b,
            0,
            0,
            &target(0x12_3456, Some(0)),
            &BTreeMap::new(),
        );
        assert_eq!(
            (u32::from_le_bytes([b[0], b[1], b[2], b[3]]) >> 10) & 0xfff,
            0x456
        );
    }

    #[test]
    fn riscv_pcrel_pairs_and_uleb() {
        let p = 0x1_0000u64;
        let t = target(0x1_2ffc, Some(0));
        let o = riscv_hi(R_RISCV_PCREL_HI20, p, &t).unwrap_or_default();
        assert_eq!(o, 0x2ffc);
        assert_eq!(hi20(o), 3, "rounded up: the low part is negative");
        let mut hi = BTreeMap::new();
        hi.insert(p, o);
        let mut b = 0x0000_0513u32.to_le_bytes().to_vec(); // addi a0, a0, 0
        apply(
            Architecture::Riscv64,
            R_RISCV_PCREL_LO12_I,
            &mut b,
            0,
            p + 4,
            &target(p, Some(0)),
            &hi,
        );
        let w = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        assert_eq!(sext(u64::from(w >> 20), 12), -4);
        let mut u = vec![0x80, 0x00];
        apply(
            Architecture::Riscv64,
            R_RISCV_SET_ULEB128,
            &mut u,
            0,
            0,
            &target(300, Some(0)),
            &hi,
        );
        apply(
            Architecture::Riscv64,
            R_RISCV_SUB_ULEB128,
            &mut u,
            0,
            0,
            &target(100, Some(0)),
            &hi,
        );
        assert_eq!(uleb(&u, 0), Some((200, 2)));
    }
}

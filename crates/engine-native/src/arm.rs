//! ARM specifics of loading: which code is A32 and which is Thumb (T32), told to Sleigh through
//! the `TMode` context variable, and the PLT entries of ARM, AArch64 and RISC-V images.
//!
//! Code addresses with the low bit set (symbol values, the entry point, function pointers in
//! data) are Thumb code at the even address. Mapping symbols (`$a`, `$t`, `$d`), when the symbol
//! table is still there, say exactly where each kind of code starts. A stripped image keeps only
//! the low bits of its code pointers, so the mode of the rest is followed through the flow: a
//! light recursive descent (a decoder of branch instructions only, no Sleigh) walks from every
//! code pointer of known mode, and a `blx` switches mode at its target. The result is painted
//! as ranges of `TMode`, one per run of code in the same mode, so that a `globalset` the
//! decompiler meets on the way repaints at most to the end of its run.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{ContextRange, Image};

/// The ARM context variable that selects Thumb decoding.
pub const TMODE: &str = "TMode";

/// What a mapping symbol says about the bytes from its address on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// `$a`: A32 code.
    Arm,
    /// `$t`: Thumb code.
    Thumb,
    /// `$d`: data (literal pools, tables).
    Data,
}

/// The kind of an ARM mapping symbol name (`$a`, `$t.42`, `$d`), if it is one.
pub fn mapping_kind(name: &str) -> Option<Mapping> {
    let kind = match name.as_bytes() {
        [b'$', k] | [b'$', k, b'.', ..] => *k,
        _ => return None,
    };
    match kind {
        b'a' => Some(Mapping::Arm),
        b't' => Some(Mapping::Thumb),
        b'd' => Some(Mapping::Data),
        _ => None,
    }
}

/// A code address whose mode is known, and how much to trust it (lower is stronger: a symbol
/// beats a pointer found in data).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Seed {
    /// Trust, lower first.
    pub rank: u8,
    /// The even address.
    pub addr: u64,
    /// Whether the code there is Thumb.
    pub thumb: bool,
}

/// Seed ranks.
pub mod rank {
    /// Function symbols and the entry point.
    pub const SYMBOL: u8 = 0;
    /// PLT entries (A32), init and fini functions.
    pub const KNOWN: u8 = 1;
    /// Odd code pointers in data (Thumb functions).
    pub const POINTER: u8 = 2;
    /// Even code pointers in data, which may be A32 functions or something else.
    pub const WEAK: u8 = 4;
}

/// How an instruction affects flow, as far as the mode walk needs to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Goes on to the next instruction.
    Next,
    /// Always continues at the target.
    Jump(u64),
    /// Continues at the target or the next instruction.
    Branch(u64),
    /// Calls the target (in the other mode when `switch`) and goes on.
    Call(u64, bool),
    /// Leaves the function (return, computed or indirect jump).
    End,
    /// Does not decode (or is permanently undefined).
    Stop,
}

fn sext(v: u32, bits: u32) -> i64 {
    let shift = 32 - bits;
    i64::from(((v << shift) as i32) >> shift)
}

/// The A32 modified immediate (`imm8` rotated right by twice `rot`).
fn arm_imm(field: u32) -> u32 {
    (field & 0xff).rotate_right(2 * ((field >> 8) & 0xf))
}

/// One A32 instruction at `pc`.
fn arm_step(w: u32, pc: u64) -> Step {
    // zero padding (`andeq r0, r0, r0`), which no compiler emits as code
    if w == 0 {
        return Step::Stop;
    }
    let cond = w >> 28;
    let always = cond == 0xe;
    if (w >> 25) & 7 == 0b101 {
        let off = sext(w & 0x00ff_ffff, 24) << 2;
        let base = pc.wrapping_add(8);
        if cond == 0xf {
            // blx imm: to Thumb, with the H bit as bit 1
            let h = u64::from((w >> 24) & 1) << 1;
            return Step::Call(base.wrapping_add_signed(off) + h, true);
        }
        let t = base.wrapping_add_signed(off) & 0xffff_ffff;
        if (w >> 24) & 1 == 1 {
            return Step::Call(t, false);
        }
        return if always {
            Step::Jump(t)
        } else {
            Step::Branch(t)
        };
    }
    if cond == 0xf {
        return Step::Next;
    }
    let end = if always { Step::End } else { Step::Next };
    // bx rm, blx rm
    if w & 0x0fff_fff0 == 0x012f_ff10 {
        return end;
    }
    if w & 0x0fff_fff0 == 0x012f_ff30 {
        return Step::Next;
    }
    // ldm with pc in the list
    if w & 0x0e10_8000 == 0x0810_8000 {
        return end;
    }
    // ldr pc, [...]
    if w & 0x0c10_f000 == 0x0410_f000 {
        return end;
    }
    // data processing into pc (mov pc, lr; add pc, pc, r3, lsl #2)
    if w & 0x0c00_f000 == 0x0000_f000 && (w >> 23) & 3 != 0b10 {
        return end;
    }
    // udf
    if w & 0x0ff0_00f0 == 0x07f0_00f0 {
        return Step::Stop;
    }
    Step::Next
}

/// One Thumb instruction at `pc`: its length and step. `hw2` is the following halfword.
fn thumb_step(hw: u16, hw2: Option<u16>, pc: u64) -> (u64, Step) {
    let base = pc.wrapping_add(4);
    let wide = matches!(hw >> 11, 0b11101..=0b11111);
    if !wide {
        let h = u32::from(hw);
        // zero padding (`movs r0, r0`), which no compiler emits as code
        let step = if h == 0 {
            Step::Stop
        } else if h & 0xf000 == 0xd000 {
            match (h >> 8) & 0xf {
                0xe => Step::Stop,
                0xf => Step::Next,
                _ => Step::Branch(base.wrapping_add_signed(sext(h & 0xff, 8) << 1)),
            }
        } else if h & 0xf800 == 0xe000 {
            Step::Jump(base.wrapping_add_signed(sext(h & 0x7ff, 11) << 1))
        } else if h & 0xf500 == 0xb100 {
            let off = ((h >> 9) & 1) << 6 | ((h >> 3) & 0x1f) << 1;
            Step::Branch(base + u64::from(off))
        } else if h & 0xff87 == 0x4700 || h & 0xff00 == 0xbd00 {
            // bx rm; pop {.., pc}
            Step::End
        } else if h & 0xff87 == 0x4687 || h & 0xff87 == 0x4487 {
            // mov pc, rm; add pc, rm
            Step::End
        } else if h & 0xff00 == 0xde00 {
            Step::Stop
        } else {
            Step::Next
        };
        return (2, step);
    }
    let Some(lo) = hw2 else {
        return (4, Step::Stop);
    };
    let (h1, h2) = (u32::from(hw), u32::from(lo));
    let step = if h1 & 0xf800 == 0xf000 && h2 & 0x8000 == 0x8000 {
        let s = (h1 >> 10) & 1;
        let (j1, j2) = ((h2 >> 13) & 1, (h2 >> 11) & 1);
        let imm11 = h2 & 0x7ff;
        match h2 & 0xd000 {
            0xd000 | 0xc000 | 0x9000 => {
                let (i1, i2) = (1 ^ (j1 ^ s), 1 ^ (j2 ^ s));
                let v = s << 24 | i1 << 23 | i2 << 22 | (h1 & 0x3ff) << 12 | imm11 << 1;
                let off = sext(v, 25);
                match h2 & 0xd000 {
                    0xd000 => Step::Call(base.wrapping_add_signed(off) & 0xffff_ffff, false),
                    // blx: to A32, from the word-aligned pc
                    0xc000 => Step::Call((base & !3).wrapping_add_signed(off) & 0xffff_ffff, true),
                    _ => Step::Jump(base.wrapping_add_signed(off) & 0xffff_ffff),
                }
            }
            _ => {
                let cond = (h1 >> 6) & 0xf;
                if cond >= 0xe {
                    // misc control (msr, mrs, hints, subs pc, lr)
                    if h1 == 0xf3de && h2 & 0xff00 == 0x8f00 {
                        Step::End
                    } else {
                        Step::Next
                    }
                } else {
                    let v = s << 20 | j2 << 19 | j1 << 18 | (h1 & 0x3f) << 12 | imm11 << 1;
                    Step::Branch(base.wrapping_add_signed(sext(v, 21)) & 0xffff_ffff)
                }
            }
        }
    } else if h1 & 0xfff0 == 0xe8d0 && h2 & 0xffe0 == 0xf000 {
        // tbb, tbh
        Step::End
    } else if (h1 & 0xffd0 == 0xe890 || h1 & 0xffd0 == 0xe910) && h2 & 0x8000 != 0 {
        // ldm.w / pop.w with pc in the list
        Step::End
    } else if h1 & 0xfff0 == 0xf8d0 && h2 & 0xf000 == 0xf000 {
        // ldr.w pc, [rn, #imm12]
        Step::End
    } else if h1 & 0xfff0 == 0xf850 && h2 & 0xf000 == 0xf000 {
        // ldr pc, [rn, ...] (pop.w {pc} is ldr pc, [sp], #4)
        Step::End
    } else if h1 & 0xfff0 == 0xf7f0 && h2 & 0xf000 == 0xa000 {
        // udf.w
        Step::Stop
    } else {
        Step::Next
    };
    (4, step)
}

/// The A32 and Thumb code of an image and the walk that tells them apart.
pub struct Modes<'a> {
    image: &'a Image,
    /// Executable ranges, ascending and disjoint.
    exec: Vec<(u64, u64)>,
    /// Instruction ranges walked: start to (end, thumb).
    walked: BTreeMap<u64, (u64, bool)>,
    /// Starts of instructions walked, for a quick "seen" check.
    seen: BTreeSet<u64>,
    /// Functions that never return (by name): the walk stops after a call to one.
    noreturn: BTreeSet<u64>,
    /// Literal-pool words the walked code loads: data, where a walk stops.
    pools: BTreeSet<u64>,
}

/// Upper bound on instructions the mode walk decodes.
const MAX_WALK: usize = 4_000_000;

impl<'a> Modes<'a> {
    /// A walker over the executable ranges `exec` of `image`; calls to `noreturn` end a path.
    pub fn new(image: &'a Image, mut exec: Vec<(u64, u64)>, noreturn: BTreeSet<u64>) -> Modes<'a> {
        exec.sort_unstable();
        Modes {
            image,
            exec,
            walked: BTreeMap::new(),
            seen: BTreeSet::new(),
            noreturn,
            pools: BTreeSet::new(),
        }
    }

    /// Whether the `len` bytes at `a` overlap a literal-pool word.
    fn in_pool(&self, a: u64, len: u64) -> bool {
        self.pools
            .range(a.saturating_sub(3)..a + len)
            .next()
            .is_some()
    }

    fn is_exec(&self, a: u64) -> bool {
        let i = self.exec.partition_point(|(s, _)| *s <= a);
        i > 0 && a < self.exec[i - 1].1
    }

    fn word(&self, a: u64) -> Option<u32> {
        let mut b = [0u8; 4];
        (self.is_exec(a) && self.is_exec(a + 3) && self.image.read(a, &mut b))
            .then(|| u32::from_le_bytes(b))
    }

    fn half(&self, a: u64) -> Option<u16> {
        let mut b = [0u8; 2];
        (self.is_exec(a) && self.is_exec(a + 1) && self.image.read(a, &mut b))
            .then(|| u16::from_le_bytes(b))
    }

    /// Whether `a` lies inside an instruction already walked (in either mode).
    fn covered(&self, a: u64) -> bool {
        self.walked
            .range(..=a)
            .next_back()
            .is_some_and(|(_, (end, _))| a < *end)
    }

    /// Walks the seeds, strongest first, and the call targets they lead to. Returns the
    /// instruction ranges found, by start: (end, thumb).
    pub fn walk(mut self, mut seeds: Vec<Seed>) -> BTreeMap<u64, (u64, bool)> {
        seeds.sort_unstable();
        seeds.dedup_by_key(|s| s.addr);
        let mut budget = MAX_WALK;
        let mut i = 0;
        while i < seeds.len() {
            let s = seeds[i];
            i += 1;
            if s.addr & 1 != 0 || self.covered(s.addr) || !self.is_exec(s.addr) {
                continue;
            }
            let mut calls = Vec::new();
            let mut pointers = Vec::new();
            let mut added = Vec::new();
            let clean = self.function(s, &mut calls, &mut pointers, &mut added, &mut budget);
            if budget == 0 {
                break;
            }
            // an even pointer that does not walk like code was data after all
            if !clean && s.rank >= rank::WEAK {
                for a in added {
                    self.seen.remove(&a);
                    self.walked.remove(&a);
                }
                continue;
            }
            // call targets go right after the seed that found them, before weaker seeds; code
            // pointers from literal pools go last
            calls.retain(|c: &Seed| !self.covered(c.addr));
            let rest = seeds.split_off(i);
            seeds.extend(calls);
            seeds.extend(rest);
            seeds.extend(pointers);
        }
        self.walked
    }

    /// The value a literal-pool load at `pc` puts in its register, `ldr rN, [pc, #n]` (A32,
    /// T16 and T32 forms), plus the `pc` the next instruction adds when it is `add rN, pc, rN`
    /// / `add rN, pc` (position-independent code); the pool word is remembered as data.
    fn pool_pointer(&mut self, pc: u64, thumb: bool) -> Option<u64> {
        let (pool, reg, next) = if thumb {
            let hw = self.half(pc)?;
            if hw & 0xf800 == 0x4800 {
                let pool = ((pc + 4) & !3) + u64::from(hw & 0xff) * 4;
                (pool, u32::from((hw >> 8) & 7), pc + 2)
            } else if hw & 0xff7f == 0xf85f {
                let lo = self.half(pc + 2)?;
                let imm = u64::from(lo & 0xfff);
                let base = (pc + 4) & !3;
                let pool = if hw & 0x80 != 0 {
                    base + imm
                } else {
                    base.wrapping_sub(imm)
                };
                (pool, u32::from(lo >> 12), pc + 4)
            } else {
                return None;
            }
        } else {
            let w = self.word(pc)?;
            if w & 0x0f7f_0000 != 0x051f_0000 {
                return None;
            }
            let imm = u64::from(w & 0xfff);
            let pool = if w & (1 << 23) != 0 {
                pc + 8 + imm
            } else {
                (pc + 8).wrapping_sub(imm)
            };
            (pool, (w >> 12) & 0xf, pc + 4)
        };
        let mut b = [0u8; 4];
        if !self.image.read(pool, &mut b) {
            return None;
        }
        self.pools.insert(pool);
        let value = u64::from(u32::from_le_bytes(b));
        let pic = if thumb {
            self.half(next).and_then(|h| {
                let rdn = u32::from(h & 7) | u32::from((h >> 4) & 8);
                (h & 0xff78 == 0x4478 && rdn == reg).then_some(next + 4)
            })
        } else {
            self.word(next).and_then(|w| {
                let same = (w >> 12) & 0xf == reg && w & 0xf == reg;
                (w & 0x0fff_0ff0 == 0x008f_0000 && same).then_some(next + 8)
            })
        };
        Some(match pic {
            Some(p) => value.wrapping_add(p) & 0xffff_ffff,
            None => value,
        })
    }

    /// Walks the function at `seed` in its mode, adding the instructions to `added`. False when
    /// the walk met something code would not do: undefined instructions, bytes outside the
    /// code, a literal-pool word or code already walked in the other mode.
    fn function(
        &mut self,
        seed: Seed,
        calls: &mut Vec<Seed>,
        pointers: &mut Vec<Seed>,
        added: &mut Vec<u64>,
        budget: &mut usize,
    ) -> bool {
        let thumb = seed.thumb;
        let mut clean = true;
        let mut work = vec![seed.addr];
        while let Some(start) = work.pop() {
            let mut pc = start;
            // instructions left in the current IT block
            let mut it_left = 0u32;
            loop {
                if *budget == 0 || self.seen.contains(&pc) {
                    break;
                }
                if self.covered(pc) {
                    let same = self
                        .walked
                        .range(..=pc)
                        .next_back()
                        .is_some_and(|(_, (_, t))| *t == thumb);
                    clean &= same;
                    break;
                }
                if self.in_pool(pc, if thumb { 2 } else { 4 }) {
                    clean = false;
                    break;
                }
                let (len, mut step) = if thumb {
                    let Some(hw) = self.half(pc) else {
                        clean = false;
                        break;
                    };
                    let (len, step) = thumb_step(hw, self.half(pc + 2), pc);
                    // it: the next 1 to 4 instructions are conditional
                    if hw & 0xff00 == 0xbf00 && hw & 0xf != 0 {
                        it_left = 4 - (hw & 0xf).trailing_zeros();
                        (len, Step::Next)
                    } else {
                        (len, step)
                    }
                } else {
                    let Some(w) = self.word(pc) else {
                        clean = false;
                        break;
                    };
                    (4, arm_step(w, pc))
                };
                if step == Step::Stop {
                    clean = false;
                    break;
                }
                let in_it =
                    it_left > 0 && !(thumb && self.half(pc).is_some_and(|h| h & 0xff00 == 0xbf00));
                if in_it {
                    it_left -= 1;
                    step = match step {
                        Step::End => Step::Next,
                        Step::Jump(t) => Step::Branch(t),
                        other => other,
                    };
                }
                *budget -= 1;
                self.seen.insert(pc);
                self.walked.insert(pc, (pc + len, thumb));
                added.push(pc);
                // a Thumb pointer (odd) is surely code; an even one may be A32 code or a table,
                // which its walk tells
                if let Some(v) = self.pool_pointer(pc, thumb)
                    && self.is_exec(v & !1)
                {
                    let odd = v & 1 == 1;
                    pointers.push(Seed {
                        rank: if odd { rank::POINTER } else { rank::WEAK },
                        addr: v & !1,
                        thumb: odd,
                    });
                }
                match step {
                    Step::Next | Step::Stop => {}
                    Step::Jump(t) => {
                        if self.is_exec(t) {
                            work.push(t);
                        }
                        break;
                    }
                    Step::Branch(t) => {
                        if self.is_exec(t) {
                            work.push(t);
                        }
                    }
                    Step::Call(t, switch) => {
                        if self.is_exec(t) {
                            calls.push(Seed {
                                rank: rank::KNOWN,
                                addr: t,
                                thumb: thumb ^ switch,
                            });
                        }
                        if self.noreturn.contains(&t) {
                            break;
                        }
                    }
                    Step::End => break,
                }
                pc += len;
            }
        }
        clean
    }
}

/// The `TMode` ranges for the walked instructions `walked` (start to (end, thumb)): one range
/// per run of instructions in the same mode, each stretched over the gap to the next run (literal
/// pools, padding, code no walk reached), within the executable ranges `exec`. Runs of A32 code
/// are painted too, so a `blx` into Thumb code repaints only its own run.
pub fn paint(walked: &BTreeMap<u64, (u64, bool)>, exec: &[(u64, u64)]) -> Vec<ContextRange> {
    let mut out: Vec<ContextRange> = Vec::new();
    for &(lo, hi) in exec {
        let mut runs: Vec<(u64, u64, bool)> = Vec::new();
        for (s, (e, t)) in walked.range(lo..hi) {
            match runs.last_mut() {
                Some((_, re, rt)) if *rt == *t => *re = (*e).max(*re),
                _ => runs.push((*s, *e, *t)),
            }
        }
        if runs.is_empty() {
            continue;
        }
        let n = runs.len();
        for k in 0..n {
            let (s, _, t) = runs[k];
            let start = if k == 0 { lo } else { s };
            let end = if k + 1 < n { runs[k + 1].0 } else { hi };
            out.push(ContextRange {
                name: TMODE.into(),
                start,
                end,
                value: u32::from(t),
            });
        }
    }
    out
}

/// The `TMode` ranges from mapping symbols (address, kind), within the executable ranges
/// `exec`: each `$t` starts Thumb code and each `$a` A32 code up to the next `$a` or `$t`;
/// `$d` (data inside code) keeps the mode around it.
pub fn paint_mapping(symbols: &[(u64, Mapping)], exec: &[(u64, u64)]) -> Vec<ContextRange> {
    let mut code: Vec<(u64, bool)> = symbols
        .iter()
        .filter_map(|(a, m)| match m {
            Mapping::Arm => Some((*a, false)),
            Mapping::Thumb => Some((*a, true)),
            Mapping::Data => None,
        })
        .collect();
    code.sort_unstable();
    code.dedup_by_key(|(a, _)| *a);
    let mut out = Vec::new();
    for &(lo, hi) in exec {
        let inside: Vec<(u64, bool)> = code
            .iter()
            .copied()
            .filter(|(a, _)| lo <= *a && *a < hi)
            .collect();
        for (k, (a, t)) in inside.iter().enumerate() {
            let start = if k == 0 { lo } else { *a };
            let end = inside.get(k + 1).map_or(hi, |(n, _)| *n);
            out.push(ContextRange {
                name: TMODE.into(),
                start,
                end,
                value: u32::from(*t),
            });
        }
    }
    out
}

/// Whether `addr` is Thumb code according to `context` (the painted `TMode` ranges).
pub fn is_thumb(context: &[ContextRange], addr: u64) -> bool {
    context
        .iter()
        .rev()
        .find(|c| c.name == TMODE && c.start <= addr && addr < c.end)
        .is_some_and(|c| c.value == 1)
}

/// The GOT slot an ARM PLT entry at `at` (`add ip, pc, #..; add ip, ip, #..; ldr pc, [ip,
/// #..]!`, also the long form with a third `add`) jumps through, and the entry's length.
pub fn arm_plt_slot(read: &dyn Fn(u64) -> Option<u32>, at: u64) -> Option<(u64, u64)> {
    let first = read(at)?;
    if first & 0xffff_f000 != 0xe28f_c000 {
        return None;
    }
    let mut ip = (at + 8).wrapping_add(u64::from(arm_imm(first & 0xfff)));
    let mut pc = at + 4;
    for _ in 0..3 {
        let w = read(pc)?;
        if w & 0xffff_f000 == 0xe28c_c000 {
            ip = ip.wrapping_add(u64::from(arm_imm(w & 0xfff)));
            pc += 4;
            continue;
        }
        if w & 0xffff_f000 == 0xe5bc_f000 {
            return Some(((ip + u64::from(w & 0xfff)) & 0xffff_ffff, pc + 4 - at));
        }
        return None;
    }
    None
}

/// The GOT slot an AArch64 PLT entry at `at` (`adrp x16, page; ldr x17, [x16, #off]; add x16,
/// x16, #off; br x17`) jumps through.
pub fn aarch64_plt_slot(read: &dyn Fn(u64) -> Option<u32>, at: u64) -> Option<u64> {
    let adrp = read(at)?;
    let ldr = read(at + 4)?;
    if adrp & 0x9f00_001f != 0x9000_0010 || ldr & 0xffc0_03ff != 0xf940_0211 {
        return None;
    }
    let imm = ((adrp >> 5) & 0x7ffff) << 2 | (adrp >> 29) & 3;
    let page = (at & !0xfff).wrapping_add_signed(sext(imm, 21) << 12);
    Some(page + u64::from((ldr >> 10) & 0xfff) * 8)
}

/// The GOT slot a RISC-V PLT entry at `at` (`auipc t3, hi; l[wd] t3, lo(t3); jalr t1, t3`)
/// jumps through.
pub fn riscv_plt_slot(read: &dyn Fn(u64) -> Option<u32>, at: u64, ptr: usize) -> Option<u64> {
    let auipc = read(at)?;
    let load = read(at + 4)?;
    let jalr = read(at + 8)?;
    let funct3 = if ptr == 8 { 0x3000 } else { 0x2000 };
    if auipc & 0xfff != 0xe17 || load & 0xf_ffff != 0xe_0e03 | funct3 || jalr != 0x000e_0367 {
        return None;
    }
    let hi = sext(auipc & 0xffff_f000, 32);
    let lo = sext(load >> 20, 12);
    let mask = if ptr == 4 { 0xffff_ffff } else { u64::MAX };
    Some(at.wrapping_add_signed(hi + lo) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_symbol_names() {
        assert_eq!(mapping_kind("$a"), Some(Mapping::Arm));
        assert_eq!(mapping_kind("$t.12"), Some(Mapping::Thumb));
        assert_eq!(mapping_kind("$d"), Some(Mapping::Data));
        assert_eq!(mapping_kind("$x"), None);
        assert_eq!(mapping_kind("main"), None);
    }

    #[test]
    fn branches_decode_in_both_modes() {
        // A32: bl 0x10b74 at 0x10bb0 (from switch_vm-arm32-O0) and blx to Thumb
        assert_eq!(arm_step(0xebff_fff0, 0x10bb0), Step::Call(0x10b78, false));
        assert_eq!(arm_step(0xfa00_0000, 0x1000), Step::Call(0x1008, true));
        assert_eq!(arm_step(0xe12f_ff1e, 0), Step::End, "bx lr");
        assert_eq!(arm_step(0x012f_ff1e, 0), Step::Next, "bxeq lr");
        assert_eq!(arm_step(0xe8bd_8800, 0), Step::End, "pop {{fp, pc}}");
        // Thumb: bl, blx (to A32), b.n, cbz, pop {pc}, bx lr
        assert_eq!(
            thumb_step(0xf000, Some(0xf802), 0x100),
            (4, Step::Call(0x108, false))
        );
        assert_eq!(
            thumb_step(0xf000, Some(0xe802), 0x102),
            (4, Step::Call(0x108, true))
        );
        assert_eq!(thumb_step(0xe7fe, None, 0x100), (2, Step::Jump(0x100)));
        assert_eq!(thumb_step(0xb108, None, 0x100), (2, Step::Branch(0x106)));
        assert_eq!(thumb_step(0xbd10, None, 0), (2, Step::End));
        assert_eq!(thumb_step(0x4770, None, 0), (2, Step::End));
        assert_eq!(
            thumb_step(0xe8bd, Some(0x8010), 0),
            (4, Step::End),
            "pop.w {{r4, pc}}"
        );
    }

    #[test]
    fn plt_entries_name_their_slots() {
        // switch_vm-arm32-thumb-O2: __libc_start_main@plt at 0x404, slot 0x2000c
        let arm = [0xe28f_c600u32, 0xe28c_ca1f, 0xe5bc_fc00];
        let read = |a: u64| arm.get(((a - 0x404) / 4) as usize).copied();
        assert_eq!(arm_plt_slot(&read, 0x404), Some((0x2_000c, 12)));
        // switch_vm-aarch64-O0: __libc_start_main@plt at 0x670, slot 0x20008
        let a64 = [0x9000_0110u32, 0xf940_0611];
        let read = |a: u64| a64.get(((a - 0x670) / 4) as usize).copied();
        assert_eq!(aarch64_plt_slot(&read, 0x670), Some(0x2_0008));
        // switch_vm-riscv64-O0: __libc_start_main@plt at 0x640, slot 0x3008
        let rv = [0x0000_3e17u32, 0x9c8e_3e03, 0x000e_0367];
        let read = |a: u64| rv.get(((a - 0x640) / 4) as usize).copied();
        assert_eq!(riscv_plt_slot(&read, 0x640, 8), Some(0x3008));
    }

    #[test]
    fn runs_of_one_mode_become_ranges() {
        let walked: BTreeMap<u64, (u64, bool)> = [
            (0x100, (0x104, false)),
            (0x104, (0x108, false)),
            (0x120, (0x122, true)),
            (0x122, (0x126, true)),
        ]
        .into_iter()
        .collect();
        let r = paint(&walked, &[(0x100, 0x200)]);
        let spans: Vec<(u64, u64, u32)> = r.iter().map(|c| (c.start, c.end, c.value)).collect();
        assert_eq!(spans, vec![(0x100, 0x120, 0), (0x120, 0x200, 1)]);
        assert!(is_thumb(&r, 0x150) && !is_thumb(&r, 0x110));
    }
}

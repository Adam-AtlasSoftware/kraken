//! Cross-references from the decoded flow: calls and jumps from branch targets and recovered
//! jump tables, reads, writes and taken addresses from the instructions' memory operands and
//! constants, and pointers stored in data (relocated slots).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction, RefKind};
use kraken_proto::XrefKind;

use crate::discover::{ComputedRefs, Func};
use crate::elf::Loaded;

/// The displacement of a memory operand based on `reg` alone in x86 operand text, as Sleigh
/// prints it: `[EBX]`, `[EBX + 0x14]`, `[EBX + 0xffffe07c]` (32-bit wrap) or `[EBX + -0x8]`.
fn base_disp(body: &str, reg: &str) -> Option<i64> {
    let inner = &body[body.find('[')? + 1..body.find(']')?];
    let mut parts = inner.split(" + ");
    if parts.next()?.trim() != reg {
        return None;
    }
    let disp = match parts.next() {
        None => 0,
        Some(d) => {
            let d = d.trim();
            let (neg, hex) = match d.strip_prefix('-') {
                Some(h) => (true, h),
                None => (false, d),
            };
            let v = i64::from_str_radix(hex.strip_prefix("0x")?, 16).ok()?;
            if neg { -v } else { v }
        }
    };
    parts.next().is_none().then_some(disp)
}

/// What an instruction does with its memory operand: the address for `LEA`, a write when it is
/// the destination, else a read.
fn memory_kind(mnemonic: &str, body: &str) -> XrefKind {
    let m = mnemonic.to_ascii_uppercase();
    if m == "LEA" {
        return XrefKind::Data;
    }
    let bracket = body.find('[').unwrap_or(0);
    let comma = body.find(',');
    let first = comma.is_none_or(|c| bracket < c);
    let two = comma.is_some();
    let writes_single = ["FST", "SET", "POP", "INC", "DEC", "NOT", "NEG", "FIST"]
        .iter()
        .any(|p| m.starts_with(p));
    if (two && first && !matches!(m.as_str(), "CMP" | "TEST")) || (!two && writes_single) {
        XrefKind::Write
    } else {
        XrefKind::Read
    }
}

/// The register a 32-bit `get_pc_thunk` sets, by its Ghidra name (`__x86.get_pc_thunk.bx`).
fn pc_thunk_register(name: &str) -> Option<&'static str> {
    let reg = name
        .strip_prefix("__x86.get_pc_thunk.")
        .or_else(|| name.strip_prefix("__i686.get_pc_thunk."))?;
    Some(match reg {
        "ax" => "EAX",
        "bx" => "EBX",
        "cx" => "ECX",
        "dx" => "EDX",
        "si" => "ESI",
        "di" => "EDI",
        "bp" => "EBP",
        _ => return None,
    })
}

/// Whether two register ranges (offset, size) overlap.
fn overlaps(a: (u64, u32), b: (u64, u32)) -> bool {
    a.0 < b.0 + u64::from(b.1) && b.0 < a.0 + u64::from(a.1)
}

/// One reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ref {
    /// Where it originates (an instruction, or a pointer slot in data).
    pub from: u64,
    /// What it points at.
    pub to: u64,
    /// What it does.
    pub kind: XrefKind,
}

struct Builder<'a> {
    loaded: &'a Loaded,
    lowest: u64,
    set: BTreeSet<Ref>,
    /// References found by constant propagation, which replace the operand references of RISC
    /// code (whose operands hold literal-pool and page addresses, not what the code refers to).
    computed: Option<&'a ComputedRefs>,
}

impl Builder<'_> {
    fn mapped(&self, a: u64) -> bool {
        let blocks = &self.loaded.blocks;
        let i = blocks.partition_point(|b| b.start.0 <= a);
        blocks[..i].iter().rev().any(|b| a < b.end.0)
    }

    fn add(&mut self, from: u64, to: u64, kind: XrefKind) {
        self.set.insert(Ref { from, to, kind });
    }

    /// The references of one instruction. `is_tail(t)` says whether a jump to `t` leaves for
    /// another function (and so counts as a call).
    fn instruction(&mut self, i: &Instruction, is_tail: &dyn Fn(u64) -> bool) {
        let a = i.addr;
        let next = a + u64::from(i.length);
        let flow_kind = match i.flow {
            Flow::Call => Some(XrefKind::Call),
            Flow::Jump | Flow::ConditionalJump => Some(XrefKind::Jump),
            _ => None,
        };
        if let Some(kind) = flow_kind {
            for t in &i.targets {
                if !self.mapped(*t) || *t == a {
                    continue;
                }
                let kind = if i.flow == Flow::Jump && is_tail(*t) {
                    XrefKind::Call
                } else {
                    kind
                };
                self.add(a, *t, kind);
            }
        }
        if let Some(computed) = self.computed {
            // a PLT entry reads its slot; its address arithmetic is not a reference
            let plt = self.loaded.in_plt(a);
            for (to, kind) in computed.get(&a).into_iter().flatten() {
                if plt && *kind != XrefKind::Read {
                    continue;
                }
                if self.mapped(*to) && !i.targets.contains(to) {
                    self.add(a, *to, *kind);
                }
            }
            return;
        }
        let is_call = matches!(i.flow, Flow::Call | Flow::IndirectCall);
        for r in &i.refs {
            if !self.mapped(r.addr) || i.targets.contains(&r.addr) {
                continue;
            }
            // the return address a call pushes is not a reference, and neither is the x87
            // instruction pointer an FPU instruction records (its own address)
            if (is_call && r.addr == next) || r.addr == a {
                continue;
            }
            let kind = match r.kind {
                // the slot a stub jumps through is an indirection, as Ghidra types it
                RefKind::Read if i.flow == Flow::IndirectJump && i.via_pointer => XrefKind::Other,
                RefKind::Read => XrefKind::Read,
                RefKind::Write => XrefKind::Write,
                RefKind::Data => XrefKind::Data,
                // a narrow constant counts only when it lands in a fixed-address image proper
                RefKind::Immediate if r.addr >= self.lowest && self.lowest >= 0x1_0000 => {
                    XrefKind::Data
                }
                RefKind::Immediate => continue,
            };
            self.add(a, r.addr, kind);
        }
    }
}

/// All references of the program, indexed both ways.
#[derive(Debug, Default)]
pub struct RefIndex {
    /// Ordered by (from, to, kind).
    by_from: Vec<Ref>,
    /// Positions in `by_from`, by target.
    by_to: BTreeMap<u64, Vec<u32>>,
}

impl RefIndex {
    /// Builds the index over every instruction of every function body, the code reached only
    /// through data (`orphans`, such as the lazy PLT entries), and the image's relocated
    /// pointers. Only targets inside a memory block count. For RISC code the references of the
    /// operands are those constant propagation found (`computed`, see [`crate::constprop`]).
    pub fn build(
        loaded: &Loaded,
        functions: &BTreeMap<u64, Func>,
        insns: &BTreeMap<u64, Instruction>,
        orphans: &[Instruction],
        computed: &ComputedRefs,
    ) -> RefIndex {
        let mut b = Builder {
            loaded,
            lowest: loaded.blocks.first().map_or(0, |b| b.start.0),
            set: BTreeSet::new(),
            computed: crate::constprop::wanted(loaded).then_some(computed),
        };
        let mut done: BTreeSet<u64> = BTreeSet::new();
        let pic32 = loaded.pointer_size() == 4 && loaded.pic_base.is_some();
        let mask = if loaded.pointer_size() == 4 {
            0xffff_ffff
        } else {
            u64::MAX
        };
        // the pointer a relocated slot in a read-only block holds
        let readonly_pointer = |slot: u64| -> Option<u64> {
            let k = loaded.pointer_slots.partition_point(|(s, _)| *s < slot);
            let (s, t) = *loaded.pointer_slots.get(k)?;
            let ro = loaded
                .blocks
                .iter()
                .any(|bl| bl.start.0 <= s && s < bl.end.0 && !bl.perms.contains('w'));
            (s == slot && ro).then_some(t)
        };
        for f in functions.values() {
            for (op, targets) in &f.switches {
                for t in targets {
                    b.add(*op, *t, XrefKind::Jump);
                }
            }
            let tails: BTreeSet<(u64, u64)> = f.tail_calls.iter().copied().collect();
            if b.computed.is_some() {
                // propagation already followed the registers
                for a in f.insns.iter() {
                    if let Some(i) = insns.get(a)
                        && done.insert(*a)
                    {
                        b.instruction(i, &|t| tails.contains(&(*a, t)));
                    }
                }
                continue;
            }
            let mut leaders: BTreeSet<u64> = f.switches.values().flatten().copied().collect();
            for a in f.insns.iter() {
                if let Some(i) = insns.get(a)
                    && matches!(i.flow, Flow::Jump | Flow::ConditionalJump)
                {
                    leaders.extend(i.targets.iter().copied());
                }
            }
            // registers holding a taken address within the current block: (offset, size, address)
            let mut held: Vec<(u64, u32, u64)> = Vec::new();
            let mut prev_end = None;
            // registers known to hold an address, for the memory accesses made through them:
            // the 32-bit PIC base (`call get_pc_thunk.bx; add ebx, n`, kept across blocks until
            // overwritten, and in PLT entries as their callers set it), an address taken with
            // `lea`, or a pointer
            // loaded from a read-only relocated slot (mingw-w64's `.refptr` indirections), the
            // last two within a block. (register, address, kept across blocks)
            let mut bases: Vec<(String, u64, bool)> = Vec::new();
            if pic32 && loaded.in_plt(f.entry) {
                bases.extend(loaded.pic_base.map(|g| ("EBX".to_string(), g, true)));
            }
            let mut thunk_reg: Option<&'static str> = None;
            for a in f.insns.iter() {
                let Some(i) = insns.get(a) else { continue };
                if prev_end != Some(*a) || leaders.contains(a) {
                    held.clear();
                    bases.retain(|(_, _, keep)| *keep);
                }
                let dest = i.body.split(',').next().unwrap_or("").trim().to_string();
                let pic_setup = thunk_reg.take().and_then(|reg| {
                    let imm = i
                        .body
                        .strip_prefix(&format!("{reg},"))
                        .and_then(|v| u64::from_str_radix(v.trim().strip_prefix("0x")?, 16).ok())?;
                    i.mnemonic
                        .eq_ignore_ascii_case("ADD")
                        .then(|| (reg, (a + imm) & 0xffff_ffff))
                });
                if let Some((reg, base)) = pic_setup {
                    bases.retain(|(r, _, _)| r != reg);
                    bases.push((reg.to_string(), base, true));
                } else {
                    for (reg, base, _) in bases.clone() {
                        let Some(d) = base_disp(&i.body, &reg) else {
                            continue;
                        };
                        let to = base.wrapping_add_signed(d) & mask;
                        if b.mapped(to) && !done.contains(a) {
                            let kind = memory_kind(&i.mnemonic, &i.body);
                            b.add(*a, to, kind);
                            if kind == XrefKind::Data {
                                held.extend(i.reg_writes.iter().map(|(o, s)| (*o, *s, to)));
                            }
                        }
                    }
                    // a write to a base register ends it (`ebx` excepted: restoring it before a
                    // return does not change what other blocks see)
                    bases.retain(|(r, _, _)| r == "EBX" || dest != *r);
                    let mnemonic = i.mnemonic.to_ascii_uppercase();
                    let taken = i
                        .refs
                        .iter()
                        .find(|r| r.kind == RefKind::Data && r.addr != *a && b.mapped(r.addr));
                    if mnemonic == "LEA"
                        && let Some(r) = taken
                    {
                        bases.push((dest.clone(), r.addr, false));
                    }
                    if mnemonic == "MOV"
                        && let Some(r) = i.refs.iter().find(|r| r.kind == RefKind::Read)
                        && let Some(target) = readonly_pointer(r.addr)
                    {
                        bases.push((dest.clone(), target, false));
                    }
                }
                if matches!(i.flow, Flow::Call | Flow::IndirectCall) {
                    // calls clobber the scratch registers; a PIC base in a callee-saved one stays
                    bases.retain(|(r, _, keep)| {
                        *keep && !matches!(r.as_str(), "EAX" | "ECX" | "EDX")
                    });
                } else if !matches!(i.flow, Flow::Fallthrough | Flow::ConditionalJump) {
                    // the fall-through of a conditional jump still sees the registers
                    bases.retain(|(_, _, keep)| *keep);
                }
                if pic32 && i.flow == Flow::Call {
                    thunk_reg = i.targets.iter().find_map(|t| {
                        functions
                            .get(t)
                            .and_then(|g| pc_thunk_register(&g.name))
                            .or_else(|| {
                                crate::discover::pc_thunk_name(loaded, *t)
                                    .and_then(pc_thunk_register)
                            })
                    });
                }
                prev_end = Some(a + u64::from(i.length));
                let first = done.insert(*a);
                // Ghidra also refers to the address from the instruction that next copies the
                // register it was loaded into, or addresses memory through it
                // (`lea rax,[s]; mov rsi,rax`); arithmetic and compares do not count
                let starts = |prefix: &str| {
                    i.mnemonic
                        .as_bytes()
                        .get(..prefix.len())
                        .is_some_and(|m| m.eq_ignore_ascii_case(prefix.as_bytes()))
                };
                let copies =
                    starts("MOV") || starts("LEA") || i.mnemonic.eq_ignore_ascii_case("PUSH");
                for (off, size, to) in &held {
                    if first && copies && i.reg_reads.iter().any(|r| overlaps(*r, (*off, *size))) {
                        b.add(*a, *to, XrefKind::Data);
                    }
                }
                held.retain(|(off, size, _)| {
                    !i.reg_writes.iter().any(|w| overlaps(*w, (*off, *size)))
                });
                if i.flow == Flow::Fallthrough
                    && let Some(d) = i
                        .refs
                        .iter()
                        .find(|r| r.kind == RefKind::Data && r.addr != *a && b.mapped(r.addr))
                {
                    held.extend(i.reg_writes.iter().map(|(o, s)| (*o, *s, d.addr)));
                }
                if i.flow != Flow::Fallthrough {
                    held.clear();
                }
                if first {
                    b.instruction(i, &|t| tails.contains(&(*a, t)));
                }
            }
        }
        for i in orphans {
            if done.insert(i.addr) {
                b.instruction(i, &|t| functions.contains_key(&t));
            }
        }
        for (slot, target) in &loaded.pointer_slots {
            if b.mapped(*target) {
                b.add(*slot, *target, XrefKind::Data);
            }
        }
        let by_from: Vec<Ref> = b.set.into_iter().collect();
        let mut by_to: BTreeMap<u64, Vec<u32>> = BTreeMap::new();
        for (i, r) in by_from.iter().enumerate() {
            by_to.entry(r.to).or_default().push(i as u32);
        }
        RefIndex { by_from, by_to }
    }

    /// References originating at `from`, ordered.
    pub fn from(&self, from: u64) -> &[Ref] {
        let lo = self.by_from.partition_point(|r| r.from < from);
        let hi = self.by_from.partition_point(|r| r.from <= from);
        &self.by_from[lo..hi]
    }

    /// Targets of data references made by instructions (taken addresses and reads), ascending.
    pub fn data_targets(&self) -> Vec<u64> {
        self.by_to
            .iter()
            .filter(|(_, refs)| {
                refs.iter().any(|i| {
                    matches!(
                        self.by_from[*i as usize].kind,
                        XrefKind::Data | XrefKind::Read
                    )
                })
            })
            .map(|(to, _)| *to)
            .collect()
    }

    /// Targets of every reference that touches data (taken addresses, reads, writes), ascending.
    pub fn touched_targets(&self) -> Vec<u64> {
        self.by_to
            .iter()
            .filter(|(_, refs)| {
                refs.iter().any(|i| {
                    matches!(
                        self.by_from[*i as usize].kind,
                        XrefKind::Data | XrefKind::Read | XrefKind::Write
                    )
                })
            })
            .map(|(to, _)| *to)
            .collect()
    }

    /// References pointing at `to`, ordered by (from, to, kind).
    pub fn to(&self, to: u64) -> Vec<Ref> {
        self.by_to
            .get(&to)
            .map(|v| v.iter().map(|i| self.by_from[*i as usize]).collect())
            .unwrap_or_default()
    }

    /// Number of references.
    pub fn len(&self) -> usize {
        self.by_from.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.by_from.is_empty()
    }
}

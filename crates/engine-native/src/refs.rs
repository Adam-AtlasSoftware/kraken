//! Cross-references from the decoded flow: calls and jumps from branch targets and recovered
//! jump tables, reads, writes and taken addresses from the instructions' memory operands and
//! constants, and pointers stored in data (relocated slots).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction, RefKind};
use kraken_proto::XrefKind;

use crate::discover::Func;
use crate::elf::Loaded;

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
        let is_call = matches!(i.flow, Flow::Call | Flow::IndirectCall);
        for r in &i.refs {
            if !self.mapped(r.addr) || i.targets.contains(&r.addr) {
                continue;
            }
            // the return address a call pushes is not a reference
            if is_call && r.addr == next {
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
    /// pointers. Only targets inside a memory block count.
    pub fn build(
        loaded: &Loaded,
        functions: &BTreeMap<u64, Func>,
        insns: &BTreeMap<u64, Instruction>,
        orphans: &[Instruction],
    ) -> RefIndex {
        let mut b = Builder {
            loaded,
            lowest: loaded.blocks.first().map_or(0, |b| b.start.0),
            set: BTreeSet::new(),
        };
        let mut done: BTreeSet<u64> = BTreeSet::new();
        for f in functions.values() {
            for (op, targets) in &f.switches {
                for t in targets {
                    b.add(*op, *t, XrefKind::Jump);
                }
            }
            let tails: BTreeSet<(u64, u64)> = f.tail_calls.iter().copied().collect();
            let mut leaders: BTreeSet<u64> = f.switches.values().flatten().copied().collect();
            for a in &f.insns {
                if let Some(i) = insns.get(a)
                    && matches!(i.flow, Flow::Jump | Flow::ConditionalJump)
                {
                    leaders.extend(i.targets.iter().copied());
                }
            }
            // registers holding a taken address within the current block: (offset, size, address)
            let mut held: Vec<(u64, u32, u64)> = Vec::new();
            let mut prev_end = None;
            for a in &f.insns {
                let Some(i) = insns.get(a) else { continue };
                if prev_end != Some(*a) || leaders.contains(a) {
                    held.clear();
                }
                prev_end = Some(a + u64::from(i.length));
                let first = done.insert(*a);
                // Ghidra also refers to the address from the instruction that next copies the
                // register it was loaded into, or addresses memory through it
                // (`lea rax,[s]; mov rsi,rax`); arithmetic and compares do not count
                let mnemonic = i.mnemonic.to_ascii_uppercase();
                let copies = mnemonic.starts_with("MOV")
                    || mnemonic.starts_with("LEA")
                    || mnemonic == "PUSH";
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
                        .find(|r| r.kind == RefKind::Data && b.mapped(r.addr))
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

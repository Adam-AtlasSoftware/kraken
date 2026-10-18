//! Addresses that RISC code builds in registers, found by following constants through the raw
//! p-code of each basic block: AArch64 `adrp` + `add`/`ldr`, RISC-V `auipc` + `addi`/`ld`, ARM
//! literal-pool loads and `add rN, pc, rN`, and loads through GOT slots. x86 code names its
//! addresses in the operands (absolute or `rip`-relative), so it does not need this.
//!
//! Like Ghidra's constant propagation, it makes a read (or write) reference where a load (or
//! store) goes to a known address, and a data reference where arithmetic yields an address in
//! the image; loading a relocated slot (a GOT entry) yields the address the loader puts there,
//! and loading read-only memory (a literal pool) yields the word stored there.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction, NativeResult, PcodeOp, Session, Varnode};
use kraken_proto::XrefKind;

use crate::elf::Loaded;

/// A reference found by propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Computed {
    /// The instruction.
    pub from: u64,
    /// The address it reaches.
    pub to: u64,
    /// Read, write or data (an address computed).
    pub kind: XrefKind,
}

/// Whether the program's code needs propagation to find its addresses (everything but x86).
pub fn wanted(loaded: &Loaded) -> bool {
    !loaded.language.id.starts_with("x86")
}

fn mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (8 * size)) - 1
    }
}

fn sext(v: u64, size: u32) -> u64 {
    if size >= 8 {
        return v;
    }
    let shift = 64 - 8 * size;
    (((v << shift) as i64) >> shift) as u64
}

/// Known values of registers and temporaries: (space, offset) to (size, value, the instruction
/// whose arithmetic made the value, if any).
#[derive(Default)]
struct State {
    known: BTreeMap<(bool, u64), (u32, u64, Option<u64>)>,
}

impl State {
    fn key(v: &Varnode) -> Option<(bool, u64)> {
        match v.space.as_str() {
            "register" => Some((false, v.offset)),
            "unique" => Some((true, v.offset)),
            _ => None,
        }
    }

    fn get(&self, v: &Varnode) -> Option<u64> {
        if v.space == "const" {
            return Some(v.offset & mask(v.size));
        }
        let (u, off) = Self::key(v)?;
        // the value of a register written wider (little-endian: the low part shares the offset)
        let (size, value, _) = self.known.get(&(u, off))?;
        (*size >= v.size).then(|| value & mask(v.size))
    }

    /// The instruction whose arithmetic made the value of `v`.
    fn origin(&self, v: &Varnode) -> Option<u64> {
        self.known.get(&Self::key(v)?).and_then(|(_, _, o)| *o)
    }

    fn clobber(&mut self, v: &Varnode) {
        let Some((u, off)) = Self::key(v) else {
            return;
        };
        let end = off + u64::from(v.size);
        self.known
            .retain(|(ku, ko), (ks, _, _)| *ku != u || *ko + u64::from(*ks) <= off || *ko >= end);
    }

    fn set(&mut self, v: &Varnode, value: Option<u64>, origin: Option<u64>) {
        self.clobber(v);
        if let (Some((u, off)), Some(x)) = (Self::key(v), value) {
            self.known
                .insert((u, off), (v.size, x & mask(v.size), origin));
        }
    }

    /// Forgets every register a call may change: all but the callee-saved ones (`keep`).
    fn clear_registers(&mut self, keep: &dyn Fn(u64) -> bool) {
        self.known.retain(|(u, off), _| *u || keep(*off));
    }
}

/// Whether the register at `offset` (in the language's register space) survives a call: ARM's
/// r4-r11, AArch64's x19-x28, RISC-V's s0-s11 and gp. The offsets are those of Ghidra's
/// specifications (`r0` at 0x20, `x0` at 0x4000, RISC-V `zero` at 0x2000).
fn callee_saved(loaded: &Loaded, offset: u64) -> bool {
    let id = loaded.language.id;
    if id.starts_with("ARM:") {
        (0x30..0x50).contains(&offset)
    } else if id.starts_with("AARCH64:") {
        (0x4098..0x40e8).contains(&offset)
    } else if id.starts_with("RISCV:") {
        let w = loaded.pointer_size() as u64;
        let n = offset.wrapping_sub(0x2000) / w;
        offset >= 0x2000 && matches!(n, 3 | 8 | 9 | 18..=27)
    } else {
        false
    }
}

/// Registers whose value is known everywhere: RISC-V's `gp`, which the start-up code points at
/// `__global_pointer$` for the linker's gp-relative addressing.
fn fixed_registers(loaded: &Loaded, state: &mut State) {
    if let Some(gp) = loaded.global_pointer {
        let w = loaded.pointer_size() as u32;
        let reg = Varnode {
            space: "register".into(),
            offset: 0x2000 + 3 * u64::from(w),
            size: w,
        };
        state.set(&reg, Some(gp), None);
    }
}

/// What the propagation over one function found.
#[derive(Debug, Default)]
pub struct Found {
    /// References made by the instructions.
    pub refs: Vec<Computed>,
    /// Code addresses built or loaded (function pointer candidates), Thumb bit cleared.
    pub code: Vec<u64>,
}

/// The flow of a function body that the propagation follows: where control comes from at each
/// jump target, and what each instruction writes.
struct Body<'a> {
    insns: BTreeMap<u64, &'a Instruction>,
    /// Jump and switch targets, with the instructions that go there.
    preds: BTreeMap<u64, Vec<u64>>,
}

impl Body<'_> {
    /// Whether control falls from the instruction before `addr` into it.
    fn falls_into(&self, addr: u64) -> bool {
        self.insns.range(..addr).next_back().is_some_and(|(a, i)| {
            a + u64::from(i.length) == addr && i.fallthrough && i.flow != Flow::Jump
        })
    }
}

/// Follows constants through the body `insns` (ascending) with its recovered `switches`. At a
/// jump target, the registers keep the values the paths from before it agree on (the
/// fall-through and forward jumps, as they left); loops back to it are followed in their first
/// round only.
pub fn function(
    loaded: &Loaded,
    session: &mut Session,
    insns: &[&Instruction],
    switches: &BTreeMap<u64, Vec<u64>>,
) -> NativeResult<Found> {
    let mut found = Found::default();
    let mut body = Body {
        insns: insns.iter().map(|i| (i.addr, *i)).collect(),
        preds: BTreeMap::new(),
    };
    for i in insns {
        if matches!(i.flow, Flow::Jump | Flow::ConditionalJump) {
            for t in &i.targets {
                body.preds.entry(*t).or_default().push(i.addr);
            }
        }
    }
    for (op, targets) in switches {
        for t in targets {
            body.preds.entry(*t).or_default().push(*op);
        }
    }
    let mut ops = Vec::new();
    let mut i = 0;
    while i < insns.len() {
        // a contiguous run of the body, lifted at once
        let start = insns[i].addr;
        let mut end = start + u64::from(insns[i].length);
        let mut j = i + 1;
        while j < insns.len() && insns[j].addr == end {
            end += u64::from(insns[j].length);
            j += 1;
        }
        ops.extend(session.lift(start, end)?);
        i = j;
    }
    run(loaded, &ops, &body, &mut found);
    found.refs.sort_unstable();
    found.refs.dedup();
    // one reference per (instruction, address), as Ghidra keeps them: a read or write wins
    // over a data reference to the same place
    let accesses: BTreeSet<(u64, u64)> = found
        .refs
        .iter()
        .filter(|r| r.kind != XrefKind::Data)
        .map(|r| (r.from, r.to))
        .collect();
    found
        .refs
        .retain(|r| r.kind != XrefKind::Data || !accesses.contains(&(r.from, r.to)));
    found.code.sort_unstable();
    found.code.dedup();
    Ok(found)
}

/// The word of `size` bytes at `addr` if the loader fixes it (a relocated slot) or it lies in
/// read-only initialized memory.
fn memory_value(loaded: &Loaded, addr: u64, size: u32) -> Option<u64> {
    let ptr = loaded.pointer_size() as u32;
    if size == ptr {
        let k = loaded.pointer_slots.partition_point(|(s, _)| *s < addr);
        if let Some((s, t)) = loaded.pointer_slots.get(k)
            && *s == addr
        {
            return Some(*t);
        }
    }
    let block = loaded
        .blocks
        .iter()
        .find(|b| b.start.0 <= addr && addr + u64::from(size) <= b.end.0)?;
    // the GOT of an image without a dynamic loader holds its final values
    let fixed =
        block.name.starts_with(".got") && !loaded.blocks.iter().any(|b| b.name == ".dynamic");
    if (block.perms.contains('w') && !fixed) || !block.initialized || size > 8 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    loaded
        .image
        .read(addr, &mut buf)
        .then(|| crate::elf::le_word(&buf))
}

fn mapped(loaded: &Loaded, addr: u64) -> bool {
    loaded
        .blocks
        .iter()
        .any(|b| b.start.0 <= addr && addr < b.end.0)
}

/// The value of a register-to-register operation whose inputs have the values `ins`.
fn eval(opcode: &str, op: &PcodeOp, ins: &[Option<u64>]) -> Option<u64> {
    let input = |k: usize| ins.get(k).copied().flatten();
    match opcode {
        "COPY" | "INT_ZEXT" => input(0),
        "INT_ADD" => Some(input(0)?.wrapping_add(input(1)?)),
        "INT_SUB" => Some(input(0)?.wrapping_sub(input(1)?)),
        "INT_AND" => Some(input(0)? & input(1)?),
        "INT_OR" => Some(input(0)? | input(1)?),
        "INT_XOR" => Some(input(0)? ^ input(1)?),
        "INT_MULT" => Some(input(0)?.wrapping_mul(input(1)?)),
        "INT_LEFT" => {
            let s = input(1)?;
            if s < 64 { Some(input(0)? << s) } else { None }
        }
        "INT_RIGHT" => {
            let s = input(1)?;
            if s < 64 { Some(input(0)? >> s) } else { None }
        }
        "INT_NEGATE" => Some(!input(0)?),
        "INT_2COMP" => Some(input(0)?.wrapping_neg()),
        "INT_SEXT" => {
            let size = op.inputs.first().map_or(8, |v| v.size);
            Some(sext(input(0)?, size))
        }
        "SUBPIECE" => {
            let s = input(1)?;
            if s < 8 {
                Some(input(0)? >> (8 * s))
            } else {
                None
            }
        }
        "PIECE" => {
            let lo = op.inputs.get(1).map_or(0, |v| v.size);
            if lo < 8 {
                Some((input(0)? << (8 * lo)) | input(1)?)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The pointer a relocated slot at `addr` holds (a GOT entry, a pointer in data).
fn slot_target(loaded: &Loaded, addr: u64) -> Option<u64> {
    let k = loaded.pointer_slots.partition_point(|(s, _)| *s < addr);
    loaded
        .pointer_slots
        .get(k)
        .filter(|(s, _)| *s == addr)
        .map(|(_, t)| *t)
}

/// Computed addresses waiting for a use, by register: (the address, the instruction that last
/// wrote it). Like Ghidra, an address built in a register is a data reference of the
/// instruction that put it there once it is used: handed to a call (or a jump through a
/// register) as an argument, or used as the base of a load or store. A copy (`mov r0, r3`, `mv
/// a0, a5`) hands the address on, and the copy is then the instruction that wrote it; an
/// address only compared, or overwritten, is no reference.
type Pending = BTreeMap<(bool, u64), (u64, u64)>;

/// Ends the waiting references: as references of the instructions that computed them
/// (`keep`), or not at all.
fn flush(pending: &mut Pending, found: &mut Found, keep: bool) {
    for (_, (to, from)) in std::mem::take(pending) {
        if keep {
            found.refs.push(Computed {
                from,
                to,
                kind: XrefKind::Data,
            });
        }
    }
}

/// The registers on which all of `states` agree.
fn meet(states: &[State]) -> State {
    let Some((first, rest)) = states.split_first() else {
        return State::default();
    };
    let mut out = State::default();
    for (k, (size, value, _)) in &first.known {
        if !k.0
            && rest.iter().all(|s| {
                s.known
                    .get(k)
                    .is_some_and(|(z, v, _)| z == size && v == value)
            })
        {
            out.known.insert(*k, (*size, *value, None));
        }
    }
    out
}

fn run(loaded: &Loaded, ops: &[PcodeOp], body: &Body, found: &mut Found) {
    let mut state = State::default();
    fixed_registers(loaded, &mut state);
    let keep = |off: u64| callee_saved(loaded, off);
    let mut pending: Pending = BTreeMap::new();
    let mut current: Option<u64> = None;
    // the state each jump left with, for its forward targets
    let mut left: BTreeMap<u64, State> = BTreeMap::new();
    // whether the current instruction loads or stores
    let mut memory = false;
    // waiting addresses the current instruction's access uses
    let mut used: Vec<(u64, u64)> = Vec::new();
    for (n, op) in ops.iter().enumerate() {
        if current != Some(op.addr) {
            if let Some(prev) = current
                && body.insns.get(&prev).is_some_and(|i| {
                    matches!(
                        i.flow,
                        Flow::Jump | Flow::ConditionalJump | Flow::IndirectJump
                    )
                })
            {
                let registers = state
                    .known
                    .iter()
                    .filter(|(k, _)| !k.0)
                    .map(|(k, v)| (*k, *v))
                    .collect();
                left.insert(prev, State { known: registers });
            }
            let contiguous = current.is_some_and(|p| {
                body.insns
                    .get(&p)
                    .is_some_and(|i| p + u64::from(i.length) == op.addr)
            });
            current = Some(op.addr);
            memory = ops[n..]
                .iter()
                .take_while(|o| o.addr == op.addr)
                .any(|o| matches!(o.opcode.as_str(), "LOAD" | "STORE"));
            // temporaries live within one instruction
            state.known.retain(|(u, _), _| !*u);
            if let Some(preds) = body.preds.get(&op.addr) {
                // a join: the values every way in agrees on
                let mut ways: Vec<State> = Vec::new();
                if contiguous && body.falls_into(op.addr) {
                    ways.push(std::mem::take(&mut state));
                }
                for p in preds.iter().filter(|p| **p < op.addr) {
                    ways.push(left.get(p).map_or_else(State::default, |s| State {
                        known: s.known.clone(),
                    }));
                }
                // a loop back here is followed in its first round, as Ghidra's propagation
                // does: the values it brings are not merged in
                state = meet(&ways);
                fixed_registers(loaded, &mut state);
                flush(&mut pending, found, false);
            } else if !contiguous {
                state = State::default();
                fixed_registers(loaded, &mut state);
                flush(&mut pending, found, false);
            }
        }
        let at = op.addr;
        let flow = matches!(
            op.opcode.as_str(),
            "BRANCH" | "CBRANCH" | "CALL" | "BRANCHIND" | "CALLIND" | "RETURN"
        );
        // a memory operand at a fixed address (a literal-pool load is `COPY rN, *[ram]addr`)
        let ins: Vec<Option<u64>> = op
            .inputs
            .iter()
            .map(|v| {
                if v.space == "ram" && !flow {
                    if mapped(loaded, v.offset) {
                        found.refs.push(Computed {
                            from: at,
                            to: v.offset,
                            kind: XrefKind::Read,
                        });
                    }
                    if let Some(t) = slot_target(loaded, v.offset)
                        && mapped(loaded, t)
                    {
                        found.refs.push(Computed {
                            from: at,
                            to: t,
                            kind: XrefKind::Data,
                        });
                    }
                    memory_value(loaded, v.offset, v.size)
                } else {
                    state.get(v)
                }
            })
            .collect();
        // an address register a load or store uses: a reference of its writer when the access
        // goes to a known address, else of the access (an indexed table)
        if memory && op.opcode != "COPY" {
            for k in op.inputs.iter().filter_map(State::key).filter(|k| !k.0) {
                if let Some(p) = pending.remove(&k) {
                    used.push(p);
                }
            }
        }
        if matches!(op.opcode.as_str(), "LOAD" | "STORE") {
            let known = op.inputs.get(1).is_some_and(|v| state.get(v).is_some());
            for (to, from) in used.drain(..) {
                found.refs.push(Computed {
                    from: if known { from } else { at },
                    to,
                    kind: XrefKind::Data,
                });
            }
        }
        // what a copy hands on
        let handed = (op.opcode == "COPY")
            .then(|| op.inputs.first().and_then(State::key))
            .flatten()
            .and_then(|src| pending.get(&src).map(|(to, _)| *to));
        if let Some(out) = &op.output
            && out.space == "ram"
            && mapped(loaded, out.offset)
        {
            found.refs.push(Computed {
                from: at,
                to: out.offset,
                kind: XrefKind::Write,
            });
        }
        let input = |k: usize| ins.get(k).copied().flatten();
        let out_size = op.output.as_ref().map_or(0, |v| v.size);
        let value: Option<u64> = match op.opcode.as_str() {
            "LOAD" => match input(1) {
                Some(addr) => {
                    let addr = addr & mask(loaded.pointer_size() as u32);
                    if mapped(loaded, addr) && addr != at {
                        found.refs.push(Computed {
                            from: at,
                            to: addr,
                            kind: XrefKind::Read,
                        });
                    }
                    // the pointer loaded from a relocated slot is referred to as well
                    if let Some(t) = slot_target(loaded, addr)
                        && mapped(loaded, t)
                    {
                        found.refs.push(Computed {
                            from: at,
                            to: t,
                            kind: XrefKind::Data,
                        });
                    }
                    memory_value(loaded, addr, out_size)
                }
                None => None,
            },
            "STORE" => {
                if let Some(addr) = input(1) {
                    let addr = addr & mask(loaded.pointer_size() as u32);
                    if mapped(loaded, addr) {
                        found.refs.push(Computed {
                            from: at,
                            to: addr,
                            kind: XrefKind::Write,
                        });
                    }
                }
                // a code address stored away is a function pointer
                if let Some(v) = input(2) {
                    escape(loaded, at, v, found);
                }
                None
            }
            "CALL" | "CALLIND" | "BRANCHIND" => {
                // addresses in the argument registers are the call's references
                flush(&mut pending, found, true);
                // code addresses handed to a callee (in the argument registers) or jumped to
                // are function pointers
                if op.opcode != "CALL"
                    && let Some(v) = input(0)
                {
                    escape(loaded, at, v, found);
                }
                if op.opcode != "BRANCHIND" {
                    let ptr = loaded.pointer_size() as u32;
                    // (the return address a call leaves in the link register is not one)
                    for (k, (size, v, _)) in &state.known {
                        if !k.0 && *size == ptr {
                            escape(loaded, at, *v, found);
                        }
                    }
                    // the callee may change the registers it need not save
                    state.clear_registers(&keep);
                }
                None
            }
            "RETURN" => {
                // an address left in the return register
                flush(&mut pending, found, true);
                None
            }
            other => eval(other, op, &ins),
        };
        let Some(out) = &op.output else {
            continue;
        };
        // a register written drops its waiting reference, unless it is a copy of one
        if let Some(k) = State::key(out) {
            pending.remove(&k);
            if let Some(to) = handed
                && !k.0
            {
                pending.insert(k, (to, at));
            }
        }
        // where the value was computed: here for arithmetic, else where its input was (a copy
        // of a temporary carries the arithmetic of its instruction into a register)
        let origin = match op.opcode.as_str() {
            "LOAD" => None,
            "COPY" | "INT_ZEXT" | "INT_SEXT" | "SUBPIECE" => {
                op.inputs.first().and_then(|v| state.origin(v))
            }
            // arithmetic on constants alone (`lui`, in temporaries) builds a constant: an
            // address is computed from a register
            _ if !op.inputs.iter().any(|v| {
                v.space == "register" || (v.space == "unique" && state.origin(v).is_some())
            }) =>
            {
                None
            }
            _ => Some(at),
        };
        if let Some(v) = value
            && origin == Some(at)
            && out.space == "register"
            && out.size == loaded.pointer_size() as u32
        {
            let v = v & mask(out.size);
            // (a return address the call leaves in the link register is not a reference)
            if mapped(loaded, v)
                && v != at
                && !(at < v && v <= at + 5)
                && let Some(k) = State::key(out)
            {
                pending.insert(k, (v, at));
            }
            // an odd address in Thumb code can only be a function pointer
            if loaded.is_arm() && v & 1 == 1 {
                escape(loaded, at, v, found);
            }
        }
        state.set(out, value, origin);
    }
    flush(&mut pending, found, false);
}

/// Notes `v` as a function pointer when it is a code address, other than the return address
/// of a call at `at` (which ARM keeps in the link register, with the Thumb bit).
fn escape(loaded: &Loaded, at: u64, v: u64, found: &mut Found) {
    let c = loaded.code_address(v);
    if loaded.is_code(c) && !(at < c && c <= at + 4) {
        found.code.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vn(space: &str, offset: u64, size: u32) -> Varnode {
        Varnode {
            space: space.into(),
            offset,
            size,
        }
    }

    #[test]
    fn registers_track_values_and_sub_registers() {
        let mut s = State::default();
        s.set(
            &vn("register", 0x4000, 8),
            Some(0x1234_5678_9abc),
            Some(0x10),
        );
        assert_eq!(s.get(&vn("register", 0x4000, 4)), Some(0x5678_9abc));
        assert_eq!(s.origin(&vn("register", 0x4000, 8)), Some(0x10));
        assert_eq!(s.get(&vn("const", 0x10, 1)), Some(0x10));
        // writing the low half forgets the wide value
        s.set(&vn("register", 0x4000, 4), None, None);
        assert_eq!(s.get(&vn("register", 0x4000, 8)), None);
        assert_eq!(sext(0xfff, 2), 0xfff);
        assert_eq!(sext(0x8000, 2), 0xffff_ffff_ffff_8000);
    }
}

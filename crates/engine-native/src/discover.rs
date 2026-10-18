//! Function discovery: symbols, the entry point, PLT stubs and PE import thunks, init/fini
//! pointers and TLS callbacks, `.eh_frame` FDE starts and PE `.pdata` entries seed a recursive
//! descent over Sleigh flow information; call targets become
//! functions, exception landing pads join the body of the function whose FDE lists them, and
//! address-sized constants that point at code no function covers yet (function pointers, the
//! `main` handed to `__libc_start_main`) are tried last.
//!
//! Functions that never return are known by name at first (`exit`, `abort`, ...). After each
//! round, a function whose every path ends in a call (or tail call) to a function that never
//! returns is marked the same way, and discovery runs again until the set stops growing, so the
//! code after such calls is not taken for part of the caller.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction, JumpEdge, NativeResult, RefKind, Session};
use tokio_util::sync::CancellationToken;

use crate::elf::Loaded;

/// Calls to these never return, so descent stops after them.
pub const NORETURN: &[&str] = &[
    "exit",
    "_exit",
    "_Exit",
    "quick_exit",
    "abort",
    "__assert_fail",
    "__stack_chk_fail",
    "__fortify_fail",
    "__chk_fail",
    "err",
    "errx",
    "verr",
    "verrx",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "pthread_exit",
    "__libc_start_main",
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "_Unwind_Resume",
    "_ZSt9terminatev",
    "_ZSt17__throw_bad_allocv",
    "_ZSt20__throw_length_errorPKc",
    "_ZSt19__throw_logic_errorPKc",
    "_ZSt20__throw_out_of_rangePKc",
    "_ZSt24__throw_out_of_range_fmtPKcz",
    "_ZSt28__throw_bad_array_new_lengthv",
];

/// Whether a function of this name never returns (the list above, the C library's, and for PE
/// images the Win32 and C runtime ones).
pub fn is_noreturn_name(loaded: &Loaded, name: &str) -> bool {
    NORETURN.contains(&name)
        || (loaded.is_pe() && crate::win32::noreturn_names().any(|n| n == name))
}

/// Ghidra's name for a 32-bit x86 `get_pc_thunk` (`mov <reg>,[esp]; ret`) at `addr`, which
/// position-independent code calls to find itself. Named, it gets the compiler spec's call fixup
/// in the decompiler, which stripped PIC code needs for its switch tables and constants.
pub fn pc_thunk_name(loaded: &Loaded, addr: u64) -> Option<&'static str> {
    if loaded.pointer_size() != 4 {
        return None;
    }
    let mut b = [0u8; 4];
    if !loaded.image.read(addr, &mut b) || b[0] != 0x8b || b[2] != 0x24 || b[3] != 0xc3 {
        return None;
    }
    Some(match b[1] {
        0x04 => "__i686.get_pc_thunk.ax",
        0x0c => "__i686.get_pc_thunk.cx",
        0x14 => "__i686.get_pc_thunk.dx",
        0x1c => "__i686.get_pc_thunk.bx",
        0x2c => "__i686.get_pc_thunk.bp",
        0x34 => "__i686.get_pc_thunk.si",
        0x3c => "__i686.get_pc_thunk.di",
        _ => return None,
    })
}

/// Upper bound on instructions in one function body.
const MAX_BODY: usize = 50_000;
/// Instructions decoded per FFI call during a linear run.
const CHUNK: u32 = 64;
/// Upper bound on discovery rounds (each round can only add noreturn functions).
const MAX_ROUNDS: usize = 6;

/// A discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Func {
    /// Entry point.
    pub entry: u64,
    /// Current name.
    pub name: String,
    /// Addresses of the body's instructions, ascending.
    pub insns: Vec<u64>,
    /// Body as merged half-open address ranges, ascending.
    pub ranges: Vec<(u64, u64)>,
    /// Recovered jump tables: computed jump address to its targets, ascending.
    pub switches: BTreeMap<u64, Vec<u64>>,
    /// Jumps to another function's entry: (jump address, target).
    pub tail_calls: Vec<(u64, u64)>,
    /// Whether the function never returns (by name or by propagation).
    pub noreturn: bool,
    /// Whether a path of the body returns (or leaves through a stub or an unresolved computed
    /// jump), as the walk found it.
    pub returns: bool,
}

impl Func {
    /// Number of addresses in the body.
    pub fn size(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }

    /// Whether `addr` lies in the body.
    pub fn contains(&self, addr: u64) -> bool {
        let i = self.ranges.partition_point(|(s, _)| *s <= addr);
        i > 0 && addr < self.ranges[i - 1].1
    }
}

/// The result of discovery.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Functions by entry.
    pub functions: BTreeMap<u64, Func>,
    /// Every instruction decoded on the way, by address.
    pub insns: BTreeMap<u64, Instruction>,
    /// Number of rounds run (more than one when noreturn propagation found new functions).
    pub rounds: usize,
}

/// The default name of a function without a symbol (`FUN_` and the entry), as Ghidra names it.
pub fn default_name(entry: u64) -> String {
    format!("FUN_{entry:08x}")
}

struct Walk {
    func: Func,
    calls: Vec<u64>,
    consts: Vec<u64>,
    returns: bool,
}

struct Walker<'a> {
    loaded: &'a Loaded,
    session: &'a mut Session,
    names: BTreeMap<u64, String>,
    noreturn: BTreeSet<u64>,
    insns: BTreeMap<u64, Instruction>,
    tables: BTreeMap<u64, Vec<JumpEdge>>,
    /// Direct calls of the current round to callees not known to never return:
    /// (callee, address after the call).
    sites: Vec<(u64, u64)>,
}

impl Walker<'_> {
    /// `addr` past alignment padding (`NOP`, `INT3`), if it decodes.
    fn skip_padding(&mut self, mut addr: u64) -> NativeResult<u64> {
        for _ in 0..16 {
            match self.instruction(addr)? {
                Some(i) if matches!(i.mnemonic.as_str(), "NOP" | "INT3" | "nop") => {
                    addr += u64::from(i.length);
                }
                _ => break,
            }
        }
        Ok(addr)
    }

    /// Callees that cannot return: a call to them is followed (after padding) by the entry of
    /// another function, so returning would run into that function. This is the evidence
    /// Ghidra's discovered-noreturn analysis uses, and it needs no names.
    fn evidence(&mut self, functions: &BTreeMap<u64, Func>) -> NativeResult<BTreeSet<u64>> {
        let mut out = BTreeSet::new();
        for (target, next) in std::mem::take(&mut self.sites) {
            if out.contains(&target) || self.noreturn.contains(&target) {
                continue;
            }
            let after = self.skip_padding(next)?;
            if after != target && functions.contains_key(&after) {
                out.insert(target);
            }
        }
        Ok(out)
    }

    fn instruction(&mut self, addr: u64) -> NativeResult<Option<Instruction>> {
        if let Some(i) = self.insns.get(&addr) {
            return Ok(Some(i.clone()));
        }
        let run = self.session.decode(addr, CHUNK)?;
        // decoding depends only on the address, so instructions past a branch are kept too
        for i in run {
            self.insns.entry(i.addr).or_insert(i);
        }
        Ok(self.insns.get(&addr).cloned())
    }

    fn tables(&mut self, entry: u64) -> NativeResult<Vec<JumpEdge>> {
        if let Some(t) = self.tables.get(&entry) {
            return Ok(t.clone());
        }
        let t = self.session.jump_tables(entry)?;
        self.tables.insert(entry, t.clone());
        Ok(t)
    }

    /// Recursive descent over one function.
    fn walk(&mut self, entry: u64) -> NativeResult<Walk> {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut work = vec![entry];
        if let Some(pads) = self.loaded.landing_pads.get(&entry) {
            work.extend(pads.iter().copied());
        }
        let mut calls = Vec::new();
        let mut consts = Vec::new();
        let mut tail_calls = Vec::new();
        let mut switches: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        let mut computed = Vec::new();
        let mut switches_done = false;
        let mut returns = false;
        loop {
            let Some(start) = work.pop() else {
                // computed jumps: ask the decompiler's switch analysis for the table targets
                if !computed.is_empty() && !switches_done {
                    switches_done = true;
                    for e in self.tables(entry)? {
                        if self.loaded.is_code(e.target) && computed.contains(&e.op) {
                            switches.entry(e.op).or_default().push(e.target);
                            work.push(e.target);
                        }
                    }
                    continue;
                }
                break;
            };
            let mut pc = start;
            loop {
                if seen.contains(&pc) || seen.len() >= MAX_BODY || !self.loaded.is_code(pc) {
                    break;
                }
                let Some(insn) = self.instruction(pc)? else {
                    break;
                };
                seen.insert(pc);
                for r in &insn.refs {
                    if r.kind != RefKind::Immediate && self.loaded.is_code(r.addr) {
                        consts.push(r.addr);
                    }
                }
                let next = pc + u64::from(insn.length);
                match insn.flow {
                    Flow::Return => {
                        returns = true;
                        break;
                    }
                    Flow::IndirectJump => {
                        if insn.via_pointer {
                            // a stub: control goes to whatever the slot holds, which may return
                            returns = true;
                        } else {
                            computed.push(pc);
                        }
                        break;
                    }
                    Flow::Jump => {
                        if let Some(&t) = insn.targets.first() {
                            // a jump to another function's entry is a tail call
                            if t != entry && self.names.contains_key(&t) {
                                calls.push(t);
                                tail_calls.push((pc, t));
                            } else {
                                work.push(t);
                            }
                        }
                        break;
                    }
                    Flow::ConditionalJump => work.extend(insn.targets.iter().copied()),
                    Flow::Call => {
                        for t in &insn.targets {
                            // unnamed, or holding an FDE start's placeholder name
                            let unnamed = self.names.get(t).is_none_or(|n| *n == default_name(*t));
                            if unnamed && let Some(n) = pc_thunk_name(self.loaded, *t) {
                                self.names.insert(*t, n.to_string());
                                self.session.add_function(*t, n)?;
                            }
                        }
                        calls.extend(insn.targets.iter().copied());
                        if insn.targets.iter().any(|t| self.noreturn.contains(t)) {
                            break;
                        }
                        self.sites.extend(insn.targets.iter().map(|t| (*t, next)));
                    }
                    Flow::IndirectCall => {
                        // `call [IAT slot]` of an import that never returns
                        let ends = insn.refs.iter().any(|r| {
                            self.loaded
                                .import_slots
                                .get(&r.addr)
                                .is_some_and(|n| is_noreturn_name(self.loaded, n))
                        });
                        if ends {
                            break;
                        }
                    }
                    Flow::Fallthrough => {}
                }
                if !insn.fallthrough {
                    break;
                }
                pc = next;
            }
        }
        // an unresolved computed jump may leave the function
        if computed.iter().any(|c| !switches.contains_key(c)) {
            returns = true;
        }
        let insns: Vec<u64> = seen.into_iter().collect();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for a in &insns {
            let len = self.insns.get(a).map_or(1, |i| u64::from(i.length));
            match ranges.last_mut() {
                Some((_, e)) if *e >= *a => *e = (*e).max(a + len),
                _ => ranges.push((*a, a + len)),
            }
        }
        for t in switches.values_mut() {
            t.sort_unstable();
            t.dedup();
        }
        let name = self
            .names
            .get(&entry)
            .cloned()
            .unwrap_or_else(|| default_name(entry));
        Ok(Walk {
            func: Func {
                entry,
                name,
                insns,
                ranges,
                switches,
                tail_calls,
                noreturn: self.noreturn.contains(&entry),
                returns,
            },
            calls,
            consts,
            returns,
        })
    }

    /// One full round of discovery with the current noreturn set. Returns the functions and,
    /// for each, whether a path returns, or `None` when cancelled.
    #[allow(clippy::type_complexity)]
    fn round(
        &mut self,
        seeds: &[u64],
        cancel: &CancellationToken,
    ) -> NativeResult<Option<(BTreeMap<u64, Func>, BTreeMap<u64, (bool, Vec<u64>)>)>> {
        let loaded = self.loaded;
        let mut functions: BTreeMap<u64, Func> = BTreeMap::new();
        let mut flow: BTreeMap<u64, (bool, Vec<u64>)> = BTreeMap::new();
        self.sites.clear();
        let mut queue: Vec<u64> = seeds.to_vec();
        let mut pending: BTreeSet<u64> = loaded
            .data_pointers
            .iter()
            .copied()
            .filter(|a| loaded.is_code(*a))
            .collect();
        loop {
            while let Some(f) = queue.pop() {
                if cancel.is_cancelled() {
                    return Ok(None);
                }
                if functions.contains_key(&f) || !loaded.is_code(f) {
                    continue;
                }
                let w = self.walk(f)?;
                queue.extend(w.calls.iter().copied().filter(|c| loaded.is_code(*c)));
                pending.extend(w.consts);
                flow.insert(f, (w.returns, w.calls));
                functions.insert(f, w.func);
            }
            // constants pointing at code outside every known body are function-pointer candidates
            let candidates: Vec<u64> = std::mem::take(&mut pending)
                .into_iter()
                .filter(|a| {
                    !functions.contains_key(a)
                        && !loaded.in_plt(*a)
                        && !functions.values().any(|f| f.contains(*a))
                })
                .collect();
            if candidates.is_empty() {
                break;
            }
            queue.extend(candidates);
        }
        Ok(Some((functions, flow)))
    }
}

/// Functions that never return given the current set: no path returns, and at least one call
/// or tail call reaches a function that never returns (so a body cut short by undecodable bytes
/// is not taken for one).
fn propagate(
    functions: &BTreeMap<u64, Func>,
    flow: &BTreeMap<u64, (bool, Vec<u64>)>,
    noreturn: &BTreeSet<u64>,
) -> Vec<u64> {
    let mut known = noreturn.clone();
    let mut added = Vec::new();
    loop {
        let mut grew = false;
        for (entry, (returns, calls)) in flow {
            if known.contains(entry) || *returns {
                continue;
            }
            let f = &functions[entry];
            let tails_return = f.tail_calls.iter().any(|(_, t)| !known.contains(t));
            if tails_return {
                continue;
            }
            if calls.iter().any(|c| known.contains(c)) {
                known.insert(*entry);
                added.push(*entry);
                grew = true;
            }
        }
        if !grew {
            return added;
        }
    }
}

/// The body of one function at `entry` by the same recursive descent discovery uses (switch
/// tables included), for a function created after discovery. `names` are the known function
/// entries (a jump to one is a tail call) and `noreturn` the functions that never return;
/// `insns` is the shared instruction cache, which keeps what the walk decodes.
pub fn walk_function(
    loaded: &Loaded,
    session: &mut Session,
    names: BTreeMap<u64, String>,
    noreturn: BTreeSet<u64>,
    insns: &mut BTreeMap<u64, Instruction>,
    entry: u64,
) -> NativeResult<Func> {
    let mut w = Walker {
        loaded,
        session,
        names,
        noreturn,
        insns: std::mem::take(insns),
        tables: BTreeMap::new(),
        sites: Vec::new(),
    };
    let r = w.walk(entry);
    *insns = std::mem::take(&mut w.insns);
    r.map(|walk| walk.func)
}

/// Discovers the functions of `loaded`. With `use_symbols` false the symbol table is ignored
/// (except PLT names), which approximates a stripped binary. `None` when cancelled.
pub fn discover(
    loaded: &Loaded,
    session: &mut Session,
    use_symbols: bool,
    cancel: &CancellationToken,
) -> NativeResult<Option<Discovery>> {
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    if use_symbols {
        for (a, n) in &loaded.functions {
            if loaded.is_code(*a) {
                names.insert(*a, n.clone());
            }
        }
    }
    for (a, n) in &loaded.plt {
        names.entry(*a).or_insert_with(|| n.clone());
    }
    let mut noreturn: BTreeSet<u64> = names
        .iter()
        .filter(|(_, n)| is_noreturn_name(loaded, n))
        .map(|(a, _)| *a)
        .collect();

    let mut seeds: Vec<u64> = names.keys().copied().collect();
    if let Some(e) = loaded.entry.filter(|e| loaded.is_code(*e)) {
        names.entry(e).or_insert_with(|| "entry".to_string());
        seeds.push(e);
    }
    for (a, n) in &loaded.default_names {
        if loaded.is_code(*a) {
            names.entry(*a).or_insert_with(|| n.clone());
        }
    }
    seeds.extend(
        loaded
            .init_pointers
            .iter()
            .copied()
            .filter(|a| loaded.is_code(*a)),
    );
    // the switch analysis creates decompiler functions on the way, so they get their names now;
    // the placeholder names of FDE starts below stay out of the decompiler until discovery is
    // done, because they made its switch analysis about three times slower on static binaries
    for (a, n) in &names {
        session.add_function(*a, n)?;
    }
    // every FDE starts a function (or a separated part of one, such as `main.cold`), and so
    // does every unchained `.pdata` entry of a PE image
    for a in loaded
        .fde_starts
        .iter()
        .chain(&loaded.pdata_starts)
        .filter(|a| loaded.is_code(**a))
    {
        names.entry(*a).or_insert_with(|| default_name(*a));
        seeds.push(*a);
    }
    seeds.sort_unstable();
    seeds.dedup();
    // seeds are popped from the back: walk in address order
    seeds.reverse();

    for a in &noreturn {
        session.set_noreturn(*a, true)?;
    }
    let mut w = Walker {
        loaded,
        session,
        names,
        noreturn: noreturn.clone(),
        insns: BTreeMap::new(),
        tables: BTreeMap::new(),
        sites: Vec::new(),
    };
    let mut rounds = 0;
    loop {
        rounds += 1;
        let Some((functions, flow)) = w.round(&seeds, cancel)? else {
            return Ok(None);
        };
        let seen = w.evidence(&functions)?;
        let mut known = noreturn.clone();
        known.extend(seen.iter().copied());
        let mut added: Vec<u64> = seen.into_iter().collect();
        added.extend(propagate(&functions, &flow, &known));
        if added.is_empty() || rounds >= MAX_ROUNDS {
            let mut functions = functions;
            for f in functions.values_mut() {
                f.noreturn = noreturn.contains(&f.entry);
            }
            return Ok(Some(Discovery {
                functions,
                insns: std::mem::take(&mut w.insns),
                rounds,
            }));
        }
        // the decompiler followed flow past calls it now knows never return, so the jump tables
        // of their callers are recovered again
        for (entry, (_, calls)) in &flow {
            if calls.iter().any(|c| added.contains(c)) {
                w.tables.remove(entry);
            }
        }
        for a in added {
            noreturn.insert(a);
            w.noreturn.insert(a);
            w.session.set_noreturn(a, true)?;
            // functions found by this round keep their names in the next one
            w.names.entry(a).or_insert_with(|| default_name(a));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn func(entry: u64, tail_calls: Vec<(u64, u64)>) -> Func {
        Func {
            entry,
            name: default_name(entry),
            insns: vec![entry],
            ranges: vec![(entry, entry + 1)],
            switches: BTreeMap::new(),
            tail_calls,
            noreturn: false,
            returns: true,
        }
    }

    #[test]
    fn noreturn_spreads_through_callers_and_tail_calls() {
        // 0x10 = exit; 0x20 calls exit and never returns; 0x30 tail-calls 0x20; 0x40 calls
        // 0x20 but also returns; 0x50 does not return but calls nothing that never returns
        let functions: BTreeMap<u64, Func> = [
            (0x20, func(0x20, vec![])),
            (0x30, func(0x30, vec![(0x31, 0x20)])),
            (0x40, func(0x40, vec![])),
            (0x50, func(0x50, vec![])),
        ]
        .into_iter()
        .collect();
        let flow: BTreeMap<u64, (bool, Vec<u64>)> = [
            (0x20, (false, vec![0x10])),
            (0x30, (false, vec![0x20])),
            (0x40, (true, vec![0x20])),
            (0x50, (false, vec![0x40])),
        ]
        .into_iter()
        .collect();
        let added = propagate(&functions, &flow, &[0x10].into_iter().collect());
        assert_eq!(added, vec![0x20, 0x30]);
    }

    #[test]
    fn contains_uses_the_ranges() {
        let mut f = func(0x100, vec![]);
        f.ranges = vec![(0x100, 0x110), (0x200, 0x204)];
        assert!(f.contains(0x100) && f.contains(0x10f) && f.contains(0x203));
        assert!(!f.contains(0x110) && !f.contains(0xff) && !f.contains(0x204));
    }
}

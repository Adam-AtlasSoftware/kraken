//! Function discovery: symbols, the entry point, PLT stubs and init/fini pointers seed a
//! recursive descent over Sleigh flow information; call targets become functions, and
//! address-sized constants that point at code no function covers yet (function pointers, the
//! `main` handed to `__libc_start_main`) are tried last.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{Flow, Instruction, NativeResult, Session};
use tokio_util::sync::CancellationToken;

use crate::elf::Loaded;

/// Calls to these never return, so descent stops after them.
const NORETURN: &[&str] = &[
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
];

/// Upper bound on instructions in one function body.
const MAX_BODY: usize = 50_000;
/// Instructions decoded per FFI call during a linear run.
const CHUNK: u32 = 64;

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
}

impl Func {
    /// Number of addresses in the body.
    pub fn size(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s).sum()
    }

    /// Whether `addr` lies in the body.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|(s, e)| *s <= addr && addr < *e)
    }
}

/// The result of discovery.
#[derive(Debug, Default)]
pub struct Discovery {
    /// Functions by entry.
    pub functions: BTreeMap<u64, Func>,
    /// Every instruction decoded on the way, by address.
    pub insns: BTreeMap<u64, Instruction>,
}

/// Where a function's name comes from.
fn default_name(entry: u64) -> String {
    format!("FUN_{entry:08x}")
}

struct Walker<'a> {
    loaded: &'a Loaded,
    session: &'a mut Session,
    names: BTreeMap<u64, String>,
    noreturn: BTreeSet<u64>,
    out: Discovery,
}

impl Walker<'_> {
    fn instruction(&mut self, addr: u64) -> NativeResult<Option<Instruction>> {
        if let Some(i) = self.out.insns.get(&addr) {
            return Ok(Some(i.clone()));
        }
        let run = self.session.decode(addr, CHUNK)?;
        // decoding depends only on the address, so instructions past a branch are kept too
        for i in run {
            self.out.insns.entry(i.addr).or_insert(i);
        }
        Ok(self.out.insns.get(&addr).cloned())
    }

    /// Recursive descent over one function; returns the call targets and code constants found.
    fn walk(&mut self, entry: u64) -> NativeResult<(Func, Vec<u64>, Vec<u64>)> {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut work = vec![entry];
        let mut calls = Vec::new();
        let mut consts = Vec::new();
        let mut indirect = false;
        let mut switches_done = false;
        loop {
            let Some(start) = work.pop() else {
                // computed jumps: ask the decompiler's switch analysis for the table targets
                if indirect && !switches_done {
                    switches_done = true;
                    let targets = self.session.jump_targets(entry)?;
                    work.extend(targets.into_iter().filter(|t| self.loaded.is_code(*t)));
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
                    if self.loaded.is_code(*r) {
                        consts.push(*r);
                    }
                }
                let next = pc + u64::from(insn.length);
                match insn.flow {
                    Flow::Return => break,
                    Flow::IndirectJump => {
                        indirect |= !insn.via_pointer;
                        break;
                    }
                    Flow::Jump => {
                        if let Some(&t) = insn.targets.first() {
                            // a jump to another function's entry is a tail call
                            if t != entry && self.names.contains_key(&t) {
                                calls.push(t);
                            } else {
                                work.push(t);
                            }
                        }
                        break;
                    }
                    Flow::ConditionalJump => work.extend(insn.targets.iter().copied()),
                    Flow::Call => {
                        calls.extend(insn.targets.iter().copied());
                        if insn.targets.iter().any(|t| self.noreturn.contains(t)) {
                            break;
                        }
                    }
                    Flow::IndirectCall | Flow::Fallthrough => {}
                }
                if !insn.fallthrough {
                    break;
                }
                pc = next;
            }
        }
        let insns: Vec<u64> = seen.into_iter().collect();
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for a in &insns {
            let len = self.out.insns.get(a).map_or(1, |i| u64::from(i.length));
            match ranges.last_mut() {
                Some((_, e)) if *e >= *a => *e = (*e).max(a + len),
                _ => ranges.push((*a, a + len)),
            }
        }
        let name = self
            .names
            .get(&entry)
            .cloned()
            .unwrap_or_else(|| default_name(entry));
        Ok((
            Func {
                entry,
                name,
                insns,
                ranges,
            },
            calls,
            consts,
        ))
    }
}

/// Discovers the functions of `loaded`. With `use_symbols` false the symbol table is ignored
/// (except PLT names), which approximates a stripped binary.
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
    let noreturn: BTreeSet<u64> = names
        .iter()
        .filter(|(_, n)| NORETURN.contains(&n.as_str()))
        .map(|(a, _)| *a)
        .collect();

    let mut seeds: Vec<u64> = names.keys().copied().collect();
    if let Some(e) = loaded.entry.filter(|e| loaded.is_code(*e)) {
        names.entry(e).or_insert_with(|| "entry".to_string());
        seeds.push(e);
    }
    seeds.extend(
        loaded
            .init_pointers
            .iter()
            .copied()
            .filter(|a| loaded.is_code(*a)),
    );

    // the switch analysis creates decompiler functions on the way, so they get their names now
    for (a, n) in &names {
        session.add_function(*a, n)?;
    }
    let mut w = Walker {
        loaded,
        session,
        names,
        noreturn,
        out: Discovery::default(),
    };
    let mut queue: Vec<u64> = seeds;
    let mut pending_consts: BTreeSet<u64> = loaded
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
            if w.out.functions.contains_key(&f) || !loaded.is_code(f) {
                continue;
            }
            let (func, calls, consts) = w.walk(f)?;
            w.out.functions.insert(f, func);
            queue.extend(calls.into_iter().filter(|c| loaded.is_code(*c)));
            pending_consts.extend(consts);
        }
        // constants pointing at code outside every known body are function-pointer candidates
        let candidates: Vec<u64> = std::mem::take(&mut pending_consts)
            .into_iter()
            .filter(|a| {
                !w.out.functions.contains_key(a)
                    && !loaded.in_plt(*a)
                    && !w.out.functions.values().any(|f| f.contains(*a))
            })
            .collect();
        if candidates.is_empty() {
            break;
        }
        queue.extend(candidates);
    }
    // functions first found inside another body stay separate; nothing to merge in phase 1
    Ok(Some(w.out))
}

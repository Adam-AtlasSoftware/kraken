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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use engine_native_sys::{Flow, Instruction, JumpEdge, NativeError, NativeResult, RefKind, Session};
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
/// Stack of a discovery thread: the decompiler recurses deeply on big functions.
const WALK_STACK: usize = 64 * 1024 * 1024;

/// A discovered function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Func {
    /// Entry point.
    pub entry: u64,
    /// Current name.
    pub name: String,
    /// Addresses of the body's instructions, ascending. Shared, so that a copy of the function
    /// table (an edit makes one) does not copy every body.
    pub insns: Arc<[u64]>,
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
    /// The instructions of the function bodies, by address.
    pub insns: BTreeMap<u64, Instruction>,
    /// Number of rounds run (more than one when noreturn propagation found new functions).
    pub rounds: usize,
    /// The jump tables this run used, to be saved for the next one.
    pub jumps: JumpCache,
    /// How many jump-table recoveries ran (the rest came from the cache).
    pub recovered: usize,
}

/// The default name of a function without a symbol (`FUN_` and the entry), as Ghidra names it.
pub fn default_name(entry: u64) -> String {
    format!("FUN_{entry:08x}")
}

/// Jump-table recoveries of an earlier discovery of the same binary. The recovery is by far the
/// slowest step of opening a program (a decompiler pass per switch), and it is a pure function of
/// the entry and of the set of functions known not to return, so a run that makes the same
/// calls in the same order can take the answers from here. The `n`-th recovery of an entry (a
/// caller of a function found not to return is recovered again in a later round) is the `n`-th
/// element.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JumpCache {
    /// Recoveries by function entry, in the order they were made.
    pub runs: BTreeMap<u64, Vec<Vec<JumpEdge>>>,
}

impl JumpCache {
    /// Number of recoveries held.
    pub fn len(&self) -> usize {
        self.runs.values().map(Vec::len).sum()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }
}

struct Walk {
    func: Func,
    calls: Vec<u64>,
    consts: Vec<u64>,
    returns: bool,
}

/// What a walk reads from the discovery in progress; shared by the threads of a wave.
struct Env<'a> {
    loaded: &'a Loaded,
    names: &'a BTreeMap<u64, String>,
    noreturn: &'a BTreeSet<u64>,
}

/// One decoder: a session and the instructions it has decoded so far (decoding depends only on
/// the address, so the lanes' caches agree wherever they overlap).
struct Lane<'a> {
    session: &'a mut Session,
    insns: BTreeMap<u64, Instruction>,
    /// Functions this walk side added to the session since it was set up.
    named: BTreeSet<u64>,
}

impl Lane<'_> {
    fn instruction(&mut self, addr: u64) -> NativeResult<Option<&Instruction>> {
        if !self.insns.contains_key(&addr) {
            let run = self.session.decode(addr, CHUNK)?;
            // instructions past a branch are kept too
            for i in run {
                self.insns.entry(i.addr).or_insert(i);
            }
        }
        Ok(self.insns.get(&addr))
    }

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
}

/// A finished walk, with the facts the walker has to hand back to the discovery.
struct Walked {
    walk: Walk,
    /// Direct calls to callees not known to never return: (callee, address after the call).
    sites: Vec<(u64, u64)>,
    /// The jump tables the walk used and whether it recovered them (rather than taking them
    /// from the table it was given).
    tables: Option<(Vec<JumpEdge>, bool)>,
    /// Unnamed callees that are 32-bit `get_pc_thunk`s, with their names.
    thunks: Vec<(u64, &'static str)>,
}

/// Recursive descent over one function. `cached` are the jump tables of an earlier recovery of
/// this entry, taken instead of asking the decompiler.
fn walk(
    env: &Env,
    lane: &mut Lane,
    entry: u64,
    mut cached: Option<Vec<JumpEdge>>,
) -> NativeResult<Walked> {
    let loaded = env.loaded;
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut work = vec![entry];
    if let Some(pads) = loaded.landing_pads.get(&entry) {
        work.extend(pads.iter().copied());
    }
    let mut calls = Vec::new();
    let mut consts = Vec::new();
    let mut tail_calls = Vec::new();
    let mut sites = Vec::new();
    let mut switches: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut computed = Vec::new();
    let mut switches_done = false;
    let mut returns = false;
    let mut tables = None;
    let mut thunks: Vec<(u64, &'static str)> = Vec::new();
    loop {
        let Some(start) = work.pop() else {
            // computed jumps: ask the decompiler's switch analysis for the table targets
            if !computed.is_empty() && !switches_done {
                switches_done = true;
                // the decompiler applies a thunk's call fixup by its name
                for (a, n) in &thunks {
                    if lane.named.insert(*a) {
                        lane.session.add_function(*a, n)?;
                    }
                }
                let (found, fresh) = match cached.take() {
                    Some(t) => (t, false),
                    // a function the decompiler cannot follow (it reads bytes outside the image)
                    // has no recovered tables, like a computed jump it cannot resolve
                    None => match lane.session.jump_tables(entry) {
                        Ok(t) => (t, true),
                        Err(NativeError::Native(_)) => (Vec::new(), true),
                        Err(e) => return Err(e),
                    },
                };
                for e in &found {
                    if loaded.is_code(e.target) && computed.contains(&e.op) {
                        switches.entry(e.op).or_default().push(e.target);
                        work.push(e.target);
                    }
                }
                tables = Some((found, fresh));
                continue;
            }
            break;
        };
        let mut pc = start;
        loop {
            if seen.contains(&pc) || seen.len() >= MAX_BODY || !loaded.is_code(pc) {
                break;
            }
            let Some(insn) = lane.instruction(pc)? else {
                break;
            };
            seen.insert(pc);
            for r in &insn.refs {
                if r.kind != RefKind::Immediate && loaded.is_code(r.addr) {
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
                        if t != entry && env.names.contains_key(&t) {
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
                        let unnamed = env.names.get(t).is_none_or(|n| *n == default_name(*t));
                        if unnamed
                            && !thunks.iter().any(|(a, _)| a == t)
                            && let Some(n) = pc_thunk_name(loaded, *t)
                        {
                            thunks.push((*t, n));
                        }
                    }
                    calls.extend(insn.targets.iter().copied());
                    if insn.targets.iter().any(|t| env.noreturn.contains(t)) {
                        break;
                    }
                    sites.extend(insn.targets.iter().map(|t| (*t, next)));
                }
                Flow::IndirectCall => {
                    // `call [IAT slot]` of an import that never returns
                    let ends = insn.refs.iter().any(|r| {
                        loaded
                            .import_slots
                            .get(&r.addr)
                            .is_some_and(|n| is_noreturn_name(loaded, n))
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
        let len = lane.insns.get(a).map_or(1, |i| u64::from(i.length));
        match ranges.last_mut() {
            Some((_, e)) if *e >= *a => *e = (*e).max(a + len),
            _ => ranges.push((*a, a + len)),
        }
    }
    for t in switches.values_mut() {
        t.sort_unstable();
        t.dedup();
    }
    let name = env
        .names
        .get(&entry)
        .cloned()
        .unwrap_or_else(|| default_name(entry));
    Ok(Walked {
        walk: Walk {
            func: Func {
                entry,
                name,
                insns: insns.into(),
                ranges,
                switches,
                tail_calls,
                noreturn: env.noreturn.contains(&entry),
                returns,
            },
            calls,
            consts,
            returns,
        },
        sites,
        tables,
        thunks,
    })
}

/// Memory (bytes) that should stay free while several sessions work.
const MIN_FREE_MEMORY: u64 = 3 << 30;

/// Memory (bytes) the system has available (Linux; `None` when unknown).
fn available_memory() -> Option<u64> {
    let info = std::fs::read_to_string("/proc/meminfo").ok()?;
    info.lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

/// Whether the system has less than [`MIN_FREE_MEMORY`] available (false when unknown).
fn low_on_memory() -> bool {
    available_memory().is_some_and(|b| b < MIN_FREE_MEMORY)
}

/// The address ranges of all bodies, merged into ascending disjoint ranges.
fn coverage(functions: &BTreeMap<u64, Func>) -> Vec<(u64, u64)> {
    let all: Vec<(u64, u64)> = functions
        .values()
        .flat_map(|f| f.ranges.iter().copied())
        .collect();
    merge_ranges(all)
}

/// Half-open ranges, sorted and merged where they overlap or touch.
pub(crate) fn merge_ranges(mut all: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    all.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(all.len());
    for (s, e) in all {
        match merged.last_mut() {
            Some((_, me)) if s <= *me => *me = (*me).max(e),
            _ => merged.push((s, e)),
        }
    }
    merged
}

/// Whether `addr` lies in one of the ascending disjoint half-open `ranges`.
pub(crate) fn in_ranges(ranges: &[(u64, u64)], addr: u64) -> bool {
    let i = ranges.partition_point(|(s, _)| *s <= addr);
    i > 0 && addr < ranges[i - 1].1
}

/// The functions found by one round and, for each, whether a path returns and its calls.
type Round = (BTreeMap<u64, Func>, BTreeMap<u64, (bool, Vec<u64>)>);

/// A walk and where its jump tables came from.
type Done = (Walked, Option<Source>);

/// Jump tables handed to a walk instead of recovering them, and where they came from.
type Cached = (Vec<JumpEdge>, Source);

/// Where a jump table handed to a walk came from.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Recovered in an earlier round of this discovery.
    Round,
    /// The cache of an earlier discovery.
    Cache,
}

struct Walker<'a> {
    loaded: &'a Loaded,
    lanes: Vec<Lane<'a>>,
    names: BTreeMap<u64, String>,
    noreturn: BTreeSet<u64>,
    /// Jump tables recovered or taken from the cache, until a callee turns out not to return.
    tables: BTreeMap<u64, Vec<JumpEdge>>,
    /// The cache of the earlier discovery and how many of its answers per entry were taken.
    cache: JumpCache,
    taken: BTreeMap<u64, usize>,
    /// What this discovery used, in order: the cache of the next one.
    log: JumpCache,
    recovered: usize,
    /// Direct calls of the current round to callees not known to never return:
    /// (callee, address after the call).
    sites: Vec<(u64, u64)>,
    progress: Option<&'a (dyn Fn(usize, usize) + Sync)>,
}

impl Walker<'_> {
    /// Callees that cannot return: a call to them is followed (after padding) by the entry of
    /// another function, so returning would run into that function. This is the evidence
    /// Ghidra's discovered-noreturn analysis uses, and it needs no names.
    fn evidence(&mut self, functions: &BTreeMap<u64, Func>) -> NativeResult<BTreeSet<u64>> {
        let mut out = BTreeSet::new();
        for (target, next) in std::mem::take(&mut self.sites) {
            if out.contains(&target) || self.noreturn.contains(&target) {
                continue;
            }
            let after = self.lanes[0].skip_padding(next)?;
            if after != target && functions.contains_key(&after) {
                out.insert(target);
            }
        }
        Ok(out)
    }

    /// Walks `wave` (distinct entries) on all lanes at once; the walks are independent, so the
    /// result does not depend on the number of lanes. `None` when cancelled.
    fn walk_wave(
        &mut self,
        wave: &[u64],
        found: usize,
        cancel: &CancellationToken,
    ) -> NativeResult<Option<Vec<Done>>> {
        let progress = self.progress;
        let env = Env {
            loaded: self.loaded,
            names: &self.names,
            noreturn: &self.noreturn,
        };
        let tasks: Vec<(u64, Option<Cached>)> = wave
            .iter()
            .map(|&e| {
                let hit = if let Some(t) = self.tables.get(&e) {
                    Some((t.clone(), Source::Round))
                } else {
                    let n = self.taken.get(&e).copied().unwrap_or(0);
                    self.cache
                        .runs
                        .get(&e)
                        .and_then(|r| r.get(n))
                        .map(|t| (t.clone(), Source::Cache))
                };
                (e, hit)
            })
            .collect();
        let out: Mutex<Vec<Option<NativeResult<Done>>>> =
            Mutex::new((0..tasks.len()).map(|_| None).collect());
        let next = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let finished = AtomicUsize::new(0);
        let last_report = Mutex::new(std::time::Instant::now());
        let run = |lane: &mut Lane| {
            loop {
                // one switch analysis can take gigabytes: with little memory left a lane waits for
                // the others (one always goes on)
                while active.load(Ordering::SeqCst) > 0 && low_on_memory() {
                    if cancel.is_cancelled() {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((entry, hit)) = tasks.get(i) else {
                    return;
                };
                if cancel.is_cancelled() {
                    return;
                }
                let source = hit.as_ref().map(|(_, s)| *s);
                active.fetch_add(1, Ordering::SeqCst);
                let r = walk(&env, lane, *entry, hit.as_ref().map(|(t, _)| t.clone()))
                    .map(|w| (w, source));
                active.fetch_sub(1, Ordering::SeqCst);
                let failed = r.is_err();
                out.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(r);
                // a wave can be the whole binary: say now and then that the walks go on
                let done = finished.fetch_add(1, Ordering::Relaxed) + 1;
                if let Some(report) = progress {
                    let mut last = last_report.lock().unwrap_or_else(|p| p.into_inner());
                    if last.elapsed() >= std::time::Duration::from_millis(250) {
                        *last = std::time::Instant::now();
                        report(found + done, tasks.len() - done);
                    }
                }
                if failed {
                    next.store(tasks.len(), Ordering::Relaxed);
                    return;
                }
            }
        };
        let n = self.lanes.len().min(tasks.len());
        if n <= 1 {
            run(&mut self.lanes[0]);
        } else {
            let mut started = 0;
            std::thread::scope(|s| {
                for lane in self.lanes.iter_mut().take(n) {
                    let run = &run;
                    let spawned = std::thread::Builder::new()
                        .name("kraken-discover".into())
                        .stack_size(WALK_STACK)
                        .spawn_scoped(s, move || run(lane));
                    if spawned.is_err() {
                        // the lanes that did start take over the rest of the wave
                        break;
                    }
                    started += 1;
                }
            });
            if started == 0 {
                run(&mut self.lanes[0]);
            }
        }
        let mut done = Vec::with_capacity(tasks.len());
        for slot in out.into_inner().unwrap_or_else(|p| p.into_inner()) {
            match slot {
                Some(r) => done.push(r?),
                // unreached: cancelled
                None => return Ok(None),
            }
        }
        Ok(Some(done))
    }

    /// One full round of discovery with the current noreturn set. Returns the functions and,
    /// for each, whether a path returns, or `None` when cancelled.
    fn round(&mut self, seeds: &[u64], cancel: &CancellationToken) -> NativeResult<Option<Round>> {
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
            // the queue is walked in waves: every function found by one wave is walked by the
            // next, so the walks of a wave can run side by side
            while !queue.is_empty() {
                if cancel.is_cancelled() {
                    return Ok(None);
                }
                let mut wave: Vec<u64> = std::mem::take(&mut queue)
                    .into_iter()
                    .filter(|f| !functions.contains_key(f) && loaded.is_code(*f))
                    .collect();
                wave.sort_unstable();
                wave.dedup();
                let Some(done) = self.walk_wave(&wave, functions.len(), cancel)? else {
                    return Ok(None);
                };
                let mut thunks = Vec::new();
                for (f, (w, source)) in wave.into_iter().zip(done) {
                    let Walked {
                        walk: w,
                        sites,
                        tables,
                        thunks: t,
                    } = w;
                    thunks.extend(t);
                    if let Some((edges, fresh)) = tables {
                        if fresh || source == Some(Source::Cache) {
                            if fresh {
                                self.recovered += 1;
                            }
                            *self.taken.entry(f).or_default() += 1;
                            self.log.runs.entry(f).or_default().push(edges.clone());
                        }
                        self.tables.insert(f, edges);
                    }
                    self.sites.extend(sites);
                    queue.extend(w.calls.iter().copied().filter(|c| loaded.is_code(*c)));
                    pending.extend(w.consts);
                    flow.insert(f, (w.returns, w.calls));
                    functions.insert(f, w.func);
                }
                // thunks found by the wave are named for every later walk, on every session
                for (a, n) in thunks {
                    if self.names.get(&a).is_none_or(|x| *x == default_name(a)) {
                        self.names.insert(a, n.to_string());
                        if let Some(func) = functions.get_mut(&a) {
                            func.name = n.to_string();
                        }
                    }
                    for lane in &mut self.lanes {
                        if lane.named.insert(a) {
                            lane.session.add_function(a, n)?;
                        }
                    }
                }
                if let Some(report) = self.progress {
                    report(functions.len(), queue.len());
                }
            }
            // constants pointing at code outside every known body are function-pointer candidates
            let covered = coverage(&functions);
            let candidates: Vec<u64> = std::mem::take(&mut pending)
                .into_iter()
                .filter(|a| {
                    !functions.contains_key(a) && !loaded.in_plt(*a) && !in_ranges(&covered, *a)
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
    let env = Env {
        loaded,
        names: &names,
        noreturn: &noreturn,
    };
    let mut lane = Lane {
        session,
        insns: std::mem::take(insns),
        named: BTreeSet::new(),
    };
    let r = walk(&env, &mut lane, entry, None);
    *insns = std::mem::take(&mut lane.insns);
    r.map(|w| w.walk.func)
}

/// Code smaller than this is discovered on one session: starting another costs more than it saves.
pub const PARALLEL_MIN_CODE: u64 = 256 * 1024;

/// How many sessions discovery uses: `KRAKEN_NATIVE_THREADS` if set (1 to 16), else the number of
/// CPUs, at most 6 and at most one per 3 GB of available memory (each session holds its own copy
/// of the Sleigh specification, and the switch analysis of a big function can take gigabytes).
pub fn default_threads() -> usize {
    match std::env::var("KRAKEN_NATIVE_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
    {
        Some(n) => n.clamp(1, 16),
        None => {
            let cpus = std::thread::available_parallelism().map_or(1, usize::from);
            let by_memory = available_memory().map_or(usize::MAX, |b| (b >> 30) as usize / 3);
            cpus.min(6).min(by_memory).max(1)
        }
    }
}

/// How a discovery runs.
pub struct Options<'a> {
    /// Seed discovery with the symbol table. Off approximates a stripped binary: the symbol
    /// table is ignored (except PLT names).
    pub use_symbols: bool,
    /// The jump tables of an earlier discovery of the same binary.
    pub cache: JumpCache,
    /// The number of sessions to use: the one passed in and `threads - 1` more.
    pub threads: usize,
    /// The code size (bytes) from which more than one session is used.
    pub parallel_min_code: u64,
    /// Called after each batch of functions with the number found and the number still queued.
    pub progress: Option<&'a (dyn Fn(usize, usize) + Sync)>,
}

impl Options<'_> {
    /// One-session-per-CPU defaults (see [`default_threads`]), no cache and no progress report.
    pub fn new(use_symbols: bool) -> Self {
        Options {
            use_symbols,
            cache: JumpCache::default(),
            threads: default_threads(),
            parallel_min_code: PARALLEL_MIN_CODE,
            progress: None,
        }
    }
}

/// Discovers the functions of `loaded`. `None` when cancelled.
pub fn discover(
    loaded: &Loaded,
    session: &mut Session,
    cancel: &CancellationToken,
    options: Options,
) -> NativeResult<Option<Discovery>> {
    let Options {
        use_symbols,
        cache,
        threads,
        parallel_min_code,
        progress,
    } = options;
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
    // more sessions for the parallel walks, set up like the first
    let code: u64 = loaded
        .blocks
        .iter()
        .filter(|b| b.initialized && b.perms.ends_with('x'))
        .map(|b| b.end.0 - b.start.0)
        .sum();
    // a session holds its own copy of the specification (some 200 MB with the function names), so
    // they are only worth having when the decompiler is going to be asked; with the answers of an
    // earlier run in the cache they are not (setting them up costs as much as the decoding they
    // would share)
    let extra = if code >= parallel_min_code && cache.is_empty() {
        threads.saturating_sub(1)
    } else {
        0
    };
    let mut others: Vec<Session> = Vec::new();
    for _ in 0..extra {
        let mut s = match Session::new(
            loaded.language.id,
            loaded.language.compiler,
            loaded.image.clone(),
        ) {
            Ok(s) => s,
            // fewer sessions are slower, not wrong
            Err(_) => break,
        };
        for (a, n) in &names {
            s.add_function(*a, n)?;
        }
        others.push(s);
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
        for s in &mut others {
            s.set_noreturn(*a, true)?;
        }
    }
    let mut lanes = vec![Lane {
        session,
        insns: BTreeMap::new(),
        named: BTreeSet::new(),
    }];
    lanes.extend(others.iter_mut().map(|session| Lane {
        session,
        insns: BTreeMap::new(),
        named: BTreeSet::new(),
    }));
    let mut w = Walker {
        loaded,
        lanes,
        names,
        noreturn: noreturn.clone(),
        tables: BTreeMap::new(),
        cache,
        taken: BTreeMap::new(),
        log: JumpCache::default(),
        recovered: 0,
        sites: Vec::new(),
        progress,
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
            // keep what the bodies use; the rest was decoded speculatively past branches
            let mut insns: BTreeMap<u64, Instruction> = BTreeMap::new();
            for lane in std::mem::take(&mut w.lanes) {
                for (a, i) in lane.insns {
                    insns.entry(a).or_insert(i);
                }
            }
            let body: BTreeSet<u64> = functions
                .values()
                .flat_map(|f| f.insns.iter().copied())
                .collect();
            insns.retain(|a, _| body.contains(a));
            return Ok(Some(Discovery {
                functions,
                insns,
                rounds,
                jumps: std::mem::take(&mut w.log),
                recovered: w.recovered,
            }));
        }
        // the decompiler followed flow past calls it now knows never return, so the jump tables
        // of their callers are recovered again
        let added_set: BTreeSet<u64> = added.iter().copied().collect();
        for (entry, (_, calls)) in &flow {
            if calls.iter().any(|c| added_set.contains(c)) {
                w.tables.remove(entry);
            }
        }
        for a in added {
            noreturn.insert(a);
            w.noreturn.insert(a);
            for lane in &mut w.lanes {
                lane.session.set_noreturn(a, true)?;
            }
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
            insns: vec![entry].into(),
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

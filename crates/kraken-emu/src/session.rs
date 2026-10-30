//! The stepping API a debugger drives: a session over a whole program (stopped before its first
//! instruction) or one function call, with stepping, stepping over calls, running to a
//! breakpoint, an address, the return or the exit, registers, memory, disassembly and snapshots.
//!
//! icicle's CPU is not `Send`, so a [`Session`] owns a thread that owns the emulator; every method
//! sends it a request and waits for the answer. The API is synchronous and the handle is `Send`,
//! so it can live in a worker thread, a daemon task or a confined process.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use object::{Object, ObjectSymbol};
use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::call::{
    Callee, FunctionCaller, RetKind, Value, read_return, return_to_caller, set_int_return,
    setup_call,
};
use crate::error::EmuError;
use crate::linux::{Exit, KernelScalars, LinuxProcess, RunSpec, fault_exit};
use crate::machine::{AccessHooks, Machine, Stop};
use crate::specs::SpecRoots;

/// What a session runs.
#[derive(Debug, Clone)]
pub enum Target {
    /// A whole program under the Linux layer, stopped at its first instruction (the loader's
    /// entry for a dynamic program).
    Program(RunSpec),
    /// One function of a program image, called with `args` (no loader, no libc: imports stop the
    /// session with [`SessionStop::Import`]).
    Function {
        /// The ELF file.
        program: PathBuf,
        /// What to call.
        callee: Callee,
        /// Arguments.
        args: Vec<Value>,
        /// Result type.
        ret: RetKind,
        /// Load bias of a position-independent image.
        pie_bias: u64,
        /// Spec roots tried first.
        spec_roots: Vec<PathBuf>,
    },
}

/// Why a session stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionStop {
    /// The requested number of instructions ran.
    Stepped,
    /// A user breakpoint.
    Breakpoint { pc: u64 },
    /// The address of a run-to request.
    Reached { pc: u64 },
    /// The function under test returned (function sessions) or the function being finished
    /// returned to its caller.
    Returned { ret: Option<u64> },
    /// The program ended.
    Exited { exit: Exit },
    /// The call reached an import the host must answer ([`Session::answer_import`]).
    Import { name: String },
    /// The budget ran out first.
    Budget,
    /// [`Interrupter::interrupt`] stopped the run (the session stays usable).
    Interrupted,
    /// The guest faulted (it stays stopped at the faulting instruction).
    Fault { detail: String, pc: u64 },
    /// A watchpoint fired. Forward, the session stands after the accessing instruction (`pc` is
    /// the next one); in reverse it stands before it (`pc` is the accessing instruction).
    Watch {
        /// The program counter.
        pc: u64,
        /// First byte of the watched range.
        addr: u64,
        /// Length of the watched range.
        len: u64,
        /// What happened: [`WatchKind::Read`] or [`WatchKind::Write`].
        access: WatchKind,
        /// The range before a write (the current contents for a read).
        old: Vec<u8>,
        /// The range after the write (the same for a read).
        new: Vec<u8>,
    },
    /// Reverse execution reached the start of the recorded history.
    HistoryStart,
}

/// What a watchpoint reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    /// Loads.
    Read,
    /// Stores.
    Write,
    /// Loads and stores.
    Access,
}

impl WatchKind {
    /// The lowercase name (`read`, `write`, `access`).
    pub fn name(self) -> &'static str {
        match self {
            WatchKind::Read => "read",
            WatchKind::Write => "write",
            WatchKind::Access => "access",
        }
    }

    /// Parses [`name`](WatchKind::name).
    pub fn parse(s: &str) -> Option<WatchKind> {
        match s {
            "read" => Some(WatchKind::Read),
            "write" => Some(WatchKind::Write),
            "access" => Some(WatchKind::Access),
            _ => None,
        }
    }
}

/// A watched memory range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WatchSpec {
    /// First byte.
    pub addr: u64,
    /// Length in bytes.
    pub len: u64,
    /// What it reacts to.
    pub kind: WatchKind,
}

/// Most bytes one watchpoint covers.
pub const MAX_WATCH_LEN: u64 = 4096;
/// Most watchpoints at once.
pub const MAX_WATCHES: usize = 16;
/// Instructions between history snapshots at first (doubles when the history is thinned).
const HISTORY_EVERY: u64 = 20_000;
/// History snapshots kept before every other one is dropped.
const HISTORY_MAX: usize = 512;

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Insn {
    /// Address.
    pub addr: u64,
    /// Length in bytes.
    pub len: u64,
    /// The raw bytes.
    pub bytes: Vec<u8>,
    /// SLEIGH disassembly.
    pub text: String,
}

/// A snapshot handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(pub usize);

enum Kind {
    Process(Box<LinuxProcess>),
    Function {
        fc: Box<FunctionCaller>,
        ret: RetKind,
    },
}

struct KernelMark {
    stdout: usize,
    stderr: usize,
    scalars: Option<KernelScalars>,
}

struct Watch {
    spec: WatchSpec,
    shadow: Vec<u8>,
    hooks: AccessHooks,
}

struct Inner {
    kind: Kind,
    symbols: BTreeMap<String, u64>,
    snapshots: Vec<(icicle_vm::Snapshot, KernelMark)>,
    done: Option<SessionStop>,
    watches: Vec<Watch>,
    /// Snapshots by instruction count, ascending, for reverse execution.
    history: Vec<(u64, icicle_vm::Snapshot, KernelMark)>,
    history_every: u64,
    /// Replaying recorded history: breakpoints and watchpoints are ignored.
    replaying: bool,
}

type Job = Box<dyn FnOnce(&mut Inner) + Send>;

/// A stepping session. Dropping it stops the emulator thread.
pub struct Session {
    tx: Option<mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
    arch: Arch,
    interrupt: Arc<AtomicBool>,
}

/// Stops a run in progress from another thread (a wall-clock limit, a Pause button). Cheap to
/// clone; the run ends with [`SessionStop::Interrupted`] and the session can go on.
#[derive(Debug, Clone)]
pub struct Interrupter(Arc<AtomicBool>);

impl Interrupter {
    /// Asks the running session to stop at the next instruction boundary.
    pub fn interrupt(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("arch", &self.arch).finish()
    }
}

fn symbols_of(path: &std::path::Path, bias: u64) -> BTreeMap<String, u64> {
    match std::fs::read(path) {
        Ok(data) => function_symbols(&data, bias),
        Err(_) => BTreeMap::new(),
    }
}

/// The function symbols of an ELF file at their runtime addresses (`bias` added; Thumb
/// functions keep bit 0).
pub(crate) fn function_symbols(data: &[u8], bias: u64) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let Ok(file) = object::File::parse(data) else {
        return out;
    };
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(n) = s.name()
            && !n.is_empty()
            && s.address() != 0
            && !n.starts_with('$')
            && s.kind() == object::SymbolKind::Text
        {
            out.entry(n.to_string())
                .or_insert(s.address().wrapping_add(bias));
        }
    }
    out
}

impl Inner {
    fn build(target: Target) -> Result<(Inner, Arch), EmuError> {
        match target {
            Target::Program(spec) => {
                let p = LinuxProcess::spawn(&spec)?;
                let arch = p.arch();
                let symbols = symbols_of(&spec.program, p.main_bias());
                Ok((
                    Inner {
                        kind: Kind::Process(Box::new(p)),
                        symbols,
                        snapshots: Vec::new(),
                        done: None,
                        watches: Vec::new(),
                        history: Vec::new(),
                        history_every: HISTORY_EVERY,
                        replaying: false,
                    },
                    arch,
                ))
            }
            Target::Function {
                program,
                callee,
                args,
                ret,
                pie_bias,
                spec_roots,
            } => {
                let data = std::fs::read(&program)
                    .map_err(|e| EmuError::Image(format!("{}: {e}", program.display())))?;
                let specs = SpecRoots::discover_with(spec_roots);
                let mut fc = FunctionCaller::load_elf(&data, pie_bias, &specs)?;
                let arch = fc.machine().arch();
                let bias = fc.image().map_or(0, |i| i.bias);
                let symbols = symbols_of(&program, bias);
                let entry = match callee {
                    Callee::Address(a) => a,
                    Callee::Symbol(s) => *symbols
                        .get(&s)
                        .ok_or_else(|| EmuError::Image(format!("no symbol `{s}`")))?,
                };
                let l = fc.layout();
                let top = l.stack_base + l.stack_size - 0x100;
                setup_call(fc.machine(), entry, &args, top, l.trap())?;
                Ok((
                    Inner {
                        kind: Kind::Function {
                            fc: Box::new(fc),
                            ret,
                        },
                        symbols,
                        snapshots: Vec::new(),
                        done: None,
                        watches: Vec::new(),
                        history: Vec::new(),
                        history_every: HISTORY_EVERY,
                        replaying: false,
                    },
                    arch,
                ))
            }
        }
    }

    fn m(&mut self) -> &mut Machine {
        match &mut self.kind {
            Kind::Process(p) => p.machine(),
            Kind::Function { fc, .. } => fc.machine(),
        }
    }

    /// Runs at most `budget` instructions, handling system calls (process) and classifying
    /// stops. `stop_at` adds a temporary stop address.
    fn run(&mut self, budget: u64, stop_at: Option<u64>) -> SessionStop {
        if let Some(d) = &self.done {
            return d.clone();
        }
        let start = self.m().icount();
        // Leave a breakpoint we are sitting on by one step without it.
        let pc0 = self.m().pc();
        let user_bps = self.m().breakpoints();
        let mut first = user_bps.contains(&pc0);
        let temp = stop_at.filter(|a| !user_bps.contains(a)).is_some_and(|a| {
            self.m().add_breakpoint(a);
            true
        });
        let watching = !self.watches.is_empty() && !self.replaying;
        let result = loop {
            self.record_history();
            let used = self.m().icount() - start;
            if used >= budget {
                break SessionStop::Stepped;
            }
            let chunk = if first || watching { 1 } else { budget - used };
            let chunk = chunk.min(self.history_gap());
            if watching {
                self.m().take_accesses();
            }
            if first {
                self.m().remove_breakpoint(pc0);
            }
            let stop = self.m().run(chunk);
            if first {
                self.m().add_breakpoint(pc0);
                first = false;
            }
            match stop {
                Stop::Budget => {
                    if watching && let Some(hit) = self.watch_hit() {
                        break hit;
                    }
                    if self.m().icount() - start >= budget {
                        break SessionStop::Stepped;
                    }
                }
                Stop::Syscall => {
                    let ended = match &mut self.kind {
                        Kind::Process(p) => p.handle_syscall(),
                        Kind::Function { .. } => Some(Exit::Unsupported {
                            detail: "a system call in a function session".into(),
                        }),
                    };
                    if let Some(e) = ended {
                        break SessionStop::Exited { exit: e };
                    }
                    if watching && let Some(hit) = self.watch_hit() {
                        break hit;
                    }
                    if self.m().icount() - start >= budget {
                        break SessionStop::Stepped;
                    }
                }
                Stop::Breakpoint { pc } => {
                    if let Kind::Function { fc, ret } = &mut self.kind {
                        let l = fc.layout();
                        if pc == l.trap() {
                            let r = *ret;
                            let v = read_return(fc.machine(), r).ok().flatten();
                            break SessionStop::Returned { ret: v };
                        }
                        let idx = pc
                            .checked_sub(l.stub_base + 0x10)
                            .filter(|d| d % 0x10 == 0)
                            .map(|d| (d / 0x10) as usize);
                        if let Some(name) = idx.and_then(|i| fc.imports().get(i)) {
                            break SessionStop::Import { name: name.clone() };
                        }
                    }
                    if Some(pc) == stop_at {
                        break SessionStop::Reached { pc };
                    }
                    break SessionStop::Breakpoint { pc };
                }
                Stop::Fault { detail, pc } => {
                    break match fault_exit(&detail, pc) {
                        Exit::Unsupported { detail } => SessionStop::Fault { detail, pc },
                        _ => SessionStop::Fault { detail, pc },
                    };
                }
                Stop::Interrupted => break SessionStop::Interrupted,
                Stop::Halt => {
                    break SessionStop::Fault {
                        detail: "stopped".into(),
                        pc: self.m().pc(),
                    };
                }
            }
        };
        if temp && let Some(a) = stop_at {
            self.m().remove_breakpoint(a);
        }
        if matches!(
            result,
            SessionStop::Exited { .. } | SessionStop::Returned { .. }
        ) {
            self.done = Some(result.clone());
        }
        result
    }

    fn mark(&self) -> KernelMark {
        match &self.kind {
            Kind::Process(p) => KernelMark {
                stdout: p.stdout().len(),
                stderr: p.stderr().len(),
                scalars: Some(p.kernel_scalars()),
            },
            Kind::Function { .. } => KernelMark {
                stdout: 0,
                stderr: 0,
                scalars: None,
            },
        }
    }

    fn records_history(&self) -> bool {
        matches!(self.kind, Kind::Process(_))
    }

    /// Instructions until the next history snapshot is due.
    fn history_gap(&mut self) -> u64 {
        if !self.records_history() {
            return u64::MAX;
        }
        let every = self.history_every;
        every - self.m().icount() % every
    }

    /// Keeps a snapshot at every multiple of `history_every` instructions (and at the start).
    fn record_history(&mut self) {
        if !self.records_history() {
            return;
        }
        let at = self.m().icount();
        if !at.is_multiple_of(self.history_every) {
            return;
        }
        if let Err(pos) = self.history.binary_search_by_key(&at, |h| h.0) {
            let (snap, mark) = (self.m().snapshot(), self.mark());
            self.history.insert(pos, (at, snap, mark));
        }
        if self.history.len() > HISTORY_MAX {
            let mut i = 0;
            self.history.retain(|_| {
                i += 1;
                i % 2 == 1
            });
            self.history_every *= 2;
        }
    }

    /// After a change the recorded history cannot reproduce (a register or memory write): the
    /// entries from here on are void and a fresh snapshot starts the new line.
    fn history_break(&mut self) {
        if !self.records_history() {
            return;
        }
        let at = self.m().icount();
        self.history.retain(|h| h.0 < at);
        let (snap, mark) = (self.m().snapshot(), self.mark());
        self.history.push((at, snap, mark));
    }

    fn read_watch(&mut self, spec: &WatchSpec) -> Vec<u8> {
        self.m()
            .read_vec(spec.addr, spec.len as usize)
            .unwrap_or_else(|_| vec![0; spec.len as usize])
    }

    fn refresh_shadows(&mut self) {
        for i in 0..self.watches.len() {
            let spec = self.watches[i].spec;
            self.watches[i].shadow = self.read_watch(&spec);
        }
    }

    /// The first watchpoint the accesses of the instruction just run trigger.
    fn watch_hit(&mut self) -> Option<SessionStop> {
        let accesses = self.m().take_accesses();
        if accesses.is_empty() {
            return None;
        }
        let pc = self.m().pc();
        let mut hit = None;
        for i in 0..self.watches.len() {
            let spec = self.watches[i].spec;
            let new = self.read_watch(&spec);
            let old = std::mem::replace(&mut self.watches[i].shadow, new.clone());
            if hit.is_some() {
                continue;
            }
            for a in &accesses {
                let overlaps = a.addr < spec.addr + spec.len && spec.addr < a.addr + a.len;
                let wanted = match spec.kind {
                    WatchKind::Read => !a.write,
                    WatchKind::Write => a.write,
                    WatchKind::Access => true,
                };
                if overlaps && wanted {
                    hit = Some(SessionStop::Watch {
                        pc,
                        addr: spec.addr,
                        len: spec.len,
                        access: if a.write {
                            WatchKind::Write
                        } else {
                            WatchKind::Read
                        },
                        old: if a.write { old.clone() } else { new.clone() },
                        new: new.clone(),
                    });
                    break;
                }
            }
        }
        hit
    }

    /// Restores history entry `i` (registers, memory, output length).
    fn restore_history(&mut self, i: usize) {
        let hist = std::mem::take(&mut self.history);
        self.m().restore(&hist[i].1);
        let (out, err, scalars) = (hist[i].2.stdout, hist[i].2.stderr, hist[i].2.scalars);
        self.history = hist;
        if let Kind::Process(p) = &mut self.kind {
            p.truncate_output(out, err);
            if let Some(v) = &scalars {
                p.set_kernel_scalars(v);
            }
        }
        self.done = None;
    }

    /// Runs forward `n` instructions through recorded history: no breakpoints, no watchpoints.
    fn replay(&mut self, n: u64) -> SessionStop {
        let bps = self.m().breakpoints();
        for b in &bps {
            self.m().remove_breakpoint(*b);
        }
        self.replaying = true;
        let r = self.run(n, None);
        self.replaying = false;
        for b in bps {
            self.m().add_breakpoint(b);
        }
        r
    }

    /// Moves to instruction count `target` (at or before the current one) from the nearest
    /// snapshot.
    fn go_to(&mut self, target: u64) -> SessionStop {
        let Some(i) = self.history.iter().rposition(|h| h.0 <= target) else {
            return SessionStop::HistoryStart;
        };
        let from = self.history[i].0;
        self.restore_history(i);
        let r = self.replay(target - from);
        self.refresh_shadows();
        r
    }

    fn reverse_unsupported(&self) -> Option<EmuError> {
        (!self.records_history()).then(|| {
            EmuError::Unsupported("reverse execution works on program sessions only".into())
        })
    }

    fn reverse_step(&mut self, n: u64) -> Result<SessionStop, EmuError> {
        if let Some(e) = self.reverse_unsupported() {
            return Err(e);
        }
        let cur = self.m().icount();
        if n == 0 {
            return Ok(SessionStop::Stepped);
        }
        if cur == 0 {
            return Ok(SessionStop::HistoryStart);
        }
        let r = self.go_to(cur.saturating_sub(n));
        Ok(match r {
            SessionStop::Stepped if n > cur => SessionStop::HistoryStart,
            other => other,
        })
    }

    /// Back to the latest breakpoint or watchpoint event before the current instruction
    /// (`budget` bounds the instructions replayed to find it).
    fn reverse_continue(&mut self, budget: u64) -> Result<SessionStop, EmuError> {
        if let Some(e) = self.reverse_unsupported() {
            return Err(e);
        }
        let cur = self.m().icount();
        let bps = self.m().breakpoints();
        let mut spent = 0u64;
        for i in (0..self.history.len()).rev() {
            let s = self.history[i].0;
            if s >= cur {
                continue;
            }
            let end = self.history.get(i + 1).map_or(cur, |h| h.0).min(cur);
            spent += end - s;
            if spent > budget {
                return Ok(SessionStop::Budget);
            }
            self.restore_history(i);
            self.refresh_shadows();
            let mut last: Option<(u64, SessionStop)> = None;
            let pc = self.m().pc();
            if bps.contains(&pc) {
                last = Some((s, SessionStop::Breakpoint { pc }));
            }
            while self.m().icount() < end {
                let left = end - self.m().icount();
                match self.run(left, None) {
                    SessionStop::Breakpoint { pc } => {
                        last = Some((self.m().icount(), SessionStop::Breakpoint { pc }));
                    }
                    w @ SessionStop::Watch { .. } => {
                        let at = self.m().icount() - 1;
                        last = Some((at, w));
                    }
                    SessionStop::Stepped => break,
                    other => return Ok(other),
                }
            }
            if let Some((at, mut stop)) = last {
                self.restore_history(i);
                let r = self.replay(at - s);
                self.refresh_shadows();
                if r != SessionStop::Stepped {
                    return Ok(r);
                }
                if let SessionStop::Watch { pc, .. } = &mut stop {
                    *pc = self.m().pc();
                }
                return Ok(stop);
            }
        }
        let r = self.go_to(0);
        Ok(if r == SessionStop::Stepped {
            SessionStop::HistoryStart
        } else {
            r
        })
    }

    fn add_watch(&mut self, spec: WatchSpec) -> Result<bool, EmuError> {
        if spec.len == 0 || spec.len > MAX_WATCH_LEN {
            return Err(EmuError::Unsupported(format!(
                "a watchpoint covers 1 to {MAX_WATCH_LEN} bytes"
            )));
        }
        if self.watches.iter().any(|w| w.spec == spec) {
            return Ok(false);
        }
        if self.watches.len() >= MAX_WATCHES {
            return Err(EmuError::Unsupported(format!(
                "at most {MAX_WATCHES} watchpoints"
            )));
        }
        let shadow = self.read_watch(&spec);
        let (read, write) = match spec.kind {
            WatchKind::Read => (true, false),
            WatchKind::Write => (false, true),
            WatchKind::Access => (true, true),
        };
        let hooks = self.m().add_access_hooks(spec.addr, spec.len, read, write);
        self.watches.push(Watch {
            spec,
            shadow,
            hooks,
        });
        Ok(true)
    }

    fn remove_watch(&mut self, spec: WatchSpec) -> bool {
        let Some(i) = self.watches.iter().position(|w| w.spec == spec) else {
            return false;
        };
        let w = self.watches.remove(i);
        self.m().remove_access_hooks(&w.hooks);
        true
    }

    /// The return address of a call that was just entered, and the stack pointer the caller
    /// will have after it returns.
    fn return_site(&mut self) -> (u64, u64) {
        let m = self.m();
        let arch = m.arch();
        let sp = m.sp();
        match arch.link_reg() {
            None => {
                let ps = arch.ptr_size();
                (m.read_uint(sp, ps).unwrap_or(0), sp + ps as u64)
            }
            Some(lr) => (m.read_reg(lr).unwrap_or(0) & !1, sp),
        }
    }

    fn step_over(&mut self, budget: u64) -> SessionStop {
        let arch = self.m().arch();
        let pc = self.m().pc();
        let thumb = self.m().thumb();
        let len = self.m().disasm_at(pc, Some(thumb)).map_or(0, |(_, l)| l);
        let sp_before = self.m().sp();
        let stop = self.run(1, None);
        if stop != SessionStop::Stepped {
            return stop;
        }
        let next = pc + len;
        let now = self.m().pc();
        if len == 0 || now == next {
            return stop;
        }
        // A call leaves the next instruction as its return address.
        let (ret, _) = self.return_site();
        let is_call = ret == next
            && match arch.link_reg() {
                None => self.m().sp() + arch.ptr_size() as u64 == sp_before,
                Some(_) => true,
            };
        if !is_call {
            return stop;
        }
        self.run_until_return_to(next, sp_before, budget)
    }

    /// Runs until the program counter is `addr` with the stack pointer back at `sp` or above
    /// (so a recursive call's return does not count).
    fn run_until_return_to(&mut self, addr: u64, sp: u64, budget: u64) -> SessionStop {
        let start = self.m().icount();
        loop {
            let used = self.m().icount() - start;
            if used >= budget {
                return SessionStop::Budget;
            }
            match self.run(budget - used, Some(addr)) {
                SessionStop::Reached { pc } if self.m().sp() >= sp => {
                    let _ = pc;
                    return SessionStop::Stepped;
                }
                SessionStop::Reached { .. } => continue,
                SessionStop::Stepped => return SessionStop::Budget,
                other => return other,
            }
        }
    }
}

const STOP: &str = "the emulator thread stopped";

impl Session {
    /// Starts a session on its own thread.
    pub fn new(target: Target) -> Result<Session, EmuError> {
        let (tx, rx) = mpsc::channel::<Job>();
        let (ready_tx, ready_rx) =
            mpsc::sync_channel::<Result<(Arch, Arc<AtomicBool>), EmuError>>(1);
        let thread = std::thread::Builder::new()
            .name("kraken-emu-session".into())
            .stack_size(16 << 20)
            .spawn(move || {
                let mut inner = match Inner::build(target) {
                    Ok((mut inner, arch)) => {
                        inner.record_history();
                        let _ = ready_tx.send(Ok((arch, inner.m().interrupt_handle())));
                        inner
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                while let Ok(job) = rx.recv() {
                    job(&mut inner);
                }
            })
            .map_err(|e| EmuError::Io(format!("starting the session thread: {e}")))?;
        let (arch, interrupt) = ready_rx
            .recv()
            .map_err(|_| EmuError::Emulator(STOP.into()))??;
        Ok(Session {
            tx: Some(tx),
            thread: Some(thread),
            arch,
            interrupt,
        })
    }

    fn call<R: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Inner) -> R + Send + 'static,
    ) -> Result<R, EmuError> {
        let (rtx, rrx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .ok_or_else(|| EmuError::Emulator(STOP.into()))?
            .send(Box::new(move |i: &mut Inner| {
                let _ = rtx.send(f(i));
            }))
            .map_err(|_| EmuError::Emulator(STOP.into()))?;
        rrx.recv().map_err(|_| EmuError::Emulator(STOP.into()))
    }

    /// A handle that stops a run in progress from another thread.
    pub fn interrupter(&self) -> Interrupter {
        Interrupter(self.interrupt.clone())
    }

    /// The architecture.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The program counter (no Thumb bit).
    pub fn pc(&self) -> Result<u64, EmuError> {
        self.call(|i| i.m().pc())
    }

    /// Whether the CPU executes Thumb code.
    pub fn thumb(&self) -> Result<bool, EmuError> {
        self.call(|i| i.m().thumb())
    }

    /// Instructions executed so far.
    pub fn icount(&self) -> Result<u64, EmuError> {
        self.call(|i| i.m().icount())
    }

    /// Executes `n` instructions (a system call counts as its instruction).
    pub fn step(&self, n: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| i.run(n, None))
    }

    /// Executes one instruction; a call is run to its return.
    pub fn step_over(&self, budget: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| i.step_over(budget))
    }

    /// Runs until a breakpoint, the end or the budget.
    pub fn run(&self, budget: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| i.run(budget, None))
    }

    /// Runs until the program counter reaches `addr` (an instruction address), a breakpoint, the
    /// end or the budget.
    pub fn run_to(&self, addr: u64, budget: u64) -> Result<SessionStop, EmuError> {
        let arch = self.arch;
        self.call(move |i| i.run(budget, Some(arch.insn_addr(addr))))
    }

    /// Run to the return of the function just entered (call it at the function's first
    /// instruction, where the return address is still in the link register or on top of the
    /// stack).
    pub fn finish(&self, budget: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| {
            let (ret, sp) = i.return_site();
            match i.run_until_return_to(ret, sp, budget) {
                SessionStop::Stepped => SessionStop::Returned { ret: None },
                other => other,
            }
        })
    }

    /// Answers the import the session stopped at with `value` and returns to its caller.
    pub fn answer_import(&self, value: u64) -> Result<(), EmuError> {
        self.call(move |i| {
            set_int_return(i.m(), value)?;
            if return_to_caller(i.m()) {
                Ok(())
            } else {
                Err(EmuError::Emulator("return address unreadable".into()))
            }
        })?
    }

    /// Adds a breakpoint at an instruction address.
    pub fn add_breakpoint(&self, addr: u64) -> Result<bool, EmuError> {
        let arch = self.arch;
        self.call(move |i| i.m().add_breakpoint(arch.insn_addr(addr)))
    }

    /// Removes a breakpoint.
    pub fn remove_breakpoint(&self, addr: u64) -> Result<bool, EmuError> {
        let arch = self.arch;
        self.call(move |i| i.m().remove_breakpoint(arch.insn_addr(addr)))
    }

    /// The user breakpoints (stub and trap addresses of function sessions included).
    pub fn breakpoints(&self) -> Result<Vec<u64>, EmuError> {
        self.call(|i| i.m().breakpoints())
    }

    /// Adds a watchpoint: the run stops with [`SessionStop::Watch`] after an instruction that
    /// reads or writes the range. Returns false if it already exists. Runs with watchpoints
    /// execute one instruction at a time, so they are slower.
    pub fn add_watchpoint(&self, addr: u64, len: u64, kind: WatchKind) -> Result<bool, EmuError> {
        self.call(move |i| i.add_watch(WatchSpec { addr, len, kind }))?
    }

    /// Removes a watchpoint added with the same range and kind.
    pub fn remove_watchpoint(
        &self,
        addr: u64,
        len: u64,
        kind: WatchKind,
    ) -> Result<bool, EmuError> {
        self.call(move |i| i.remove_watch(WatchSpec { addr, len, kind }))
    }

    /// The watchpoints.
    pub fn watchpoints(&self) -> Result<Vec<WatchSpec>, EmuError> {
        self.call(|i| i.watches.iter().map(|w| w.spec).collect())
    }

    /// Goes back `n` instructions (program sessions): restores the nearest recorded snapshot
    /// and replays forward. File descriptors and the input position are not part of a snapshot,
    /// so a window that read input or changed files may not replay identically. Returns
    /// [`SessionStop::HistoryStart`] when fewer than `n` instructions are recorded.
    pub fn reverse_step(&self, n: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| i.reverse_step(n))?
    }

    /// Goes back to the latest earlier breakpoint or watchpoint event, standing before the
    /// instruction (before the accessing instruction for a watchpoint), or to the start of the
    /// history. `budget` bounds the instructions replayed to find it.
    pub fn reverse_continue(&self, budget: u64) -> Result<SessionStop, EmuError> {
        self.call(move |i| i.reverse_continue(budget))?
    }

    /// The general purpose registers in display order with their values.
    pub fn registers(&self) -> Result<Vec<(String, u64)>, EmuError> {
        self.call(|i| {
            let names = i.m().arch().display_regs();
            names
                .iter()
                .filter_map(|n| i.m().read_reg(n).ok().map(|v| (n.to_string(), v)))
                .collect()
        })
    }

    /// One register by SLEIGH name.
    pub fn read_reg(&self, name: &str) -> Result<u64, EmuError> {
        let n = name.to_string();
        self.call(move |i| i.m().read_reg(&n))?
    }

    /// Sets a register.
    pub fn write_reg(&self, name: &str, v: u64) -> Result<(), EmuError> {
        let n = name.to_string();
        self.call(move |i| {
            let r = i.m().write_reg(&n, v);
            i.history_break();
            r
        })?
    }

    /// Reads memory.
    pub fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmuError> {
        if len > 1 << 24 {
            return Err(EmuError::Unsupported("reads are capped at 16 MiB".into()));
        }
        self.call(move |i| i.m().read_vec(addr, len))?
    }

    /// Writes memory.
    pub fn write_memory(&self, addr: u64, data: Vec<u8>) -> Result<(), EmuError> {
        self.call(move |i| {
            let r = i.m().write_mem(addr, &data);
            i.refresh_shadows();
            i.history_break();
            r
        })?
    }

    /// Disassembles `count` instructions from `addr` (`None`: the program counter) in the current
    /// instruction set.
    pub fn disasm(&self, addr: Option<u64>, count: usize) -> Result<Vec<Insn>, EmuError> {
        self.call(move |i| {
            let m = i.m();
            let thumb = m.thumb();
            let mut at = addr.map_or(m.pc(), |a| m.arch().insn_addr(a));
            let mode = match addr {
                Some(a) if m.arch().has_thumb() => Some(a & 1 == 1 || thumb),
                _ => Some(thumb),
            };
            let mut out = Vec::new();
            for _ in 0..count.min(256) {
                let Some((text, len)) = m.disasm_at(at, mode) else {
                    break;
                };
                let bytes = m.read_vec(at, len as usize).unwrap_or_default();
                out.push(Insn {
                    addr: at,
                    len,
                    bytes,
                    text,
                });
                at += len.max(1);
            }
            out
        })
    }

    /// The load bias of the main program image (0 for a fixed-address executable).
    pub fn main_bias(&self) -> Result<u64, EmuError> {
        self.call(|i| match &i.kind {
            Kind::Process(p) => p.main_bias(),
            Kind::Function { fc, .. } => fc.image().map_or(0, |im| im.bias),
        })
    }

    /// The runtime address of a function symbol of the program.
    pub fn symbol(&self, name: &str) -> Result<Option<u64>, EmuError> {
        let n = name.to_string();
        self.call(move |i| i.symbols.get(&n).copied())
    }

    /// Standard output and error so far (program sessions; empty for functions).
    pub fn output(&self) -> Result<(Vec<u8>, Vec<u8>), EmuError> {
        self.call(|i| match &i.kind {
            Kind::Process(p) => (p.stdout().to_vec(), p.stderr().to_vec()),
            Kind::Function { .. } => (Vec::new(), Vec::new()),
        })
    }

    /// Takes a snapshot of registers and memory. File descriptors, files of the working
    /// directory and the input position are not part of it; output written after the snapshot is
    /// dropped on restore.
    pub fn snapshot(&self) -> Result<SnapshotId, EmuError> {
        self.call(|i| {
            let mark = i.mark();
            let s = i.m().snapshot();
            i.snapshots.push((s, mark));
            SnapshotId(i.snapshots.len() - 1)
        })
    }

    /// Restores a snapshot.
    pub fn restore(&self, id: SnapshotId) -> Result<(), EmuError> {
        self.call(move |i| {
            let Some((out, err, scalars)) = i
                .snapshots
                .get(id.0)
                .map(|(_, m)| (m.stdout, m.stderr, m.scalars))
            else {
                return Err(EmuError::Unsupported(format!("no snapshot {}", id.0)));
            };
            // Restoring needs the machine and the snapshot at once.
            let snaps = std::mem::take(&mut i.snapshots);
            i.m().restore(&snaps[id.0].0);
            i.snapshots = snaps;
            if let Kind::Process(p) = &mut i.kind {
                p.truncate_output(out, err);
                if let Some(v) = &scalars {
                    p.set_kernel_scalars(v);
                }
            }
            i.done = None;
            i.refresh_shadows();
            Ok(())
        })?
    }

    /// Runs to the end with a wall-clock limit (program sessions).
    pub fn run_to_end(&self, budget: u64, timeout: Duration) -> Result<SessionStop, EmuError> {
        self.call(move |i| match &mut i.kind {
            Kind::Process(p) => {
                let e = p.run_to_end(budget, timeout);
                let stop = SessionStop::Exited { exit: e };
                i.done = Some(stop.clone());
                stop
            }
            Kind::Function { .. } => i.run(budget, None),
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.tx.take();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_handle_is_send() {
        fn send<T: Send>() {}
        send::<Session>();
    }
}

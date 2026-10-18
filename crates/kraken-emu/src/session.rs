//! The stepping API a debugger drives: a session over a whole program (stopped before its first
//! instruction) or one function call, with stepping, stepping over calls, running to a
//! breakpoint, an address, the return or the exit, registers, memory, disassembly and snapshots.
//!
//! icicle's CPU is not `Send`, so a [`Session`] owns a thread that owns the emulator; every method
//! sends it a request and waits for the answer. The API is synchronous and the handle is `Send`,
//! so it can live in a worker thread, a daemon task or a confined process.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use object::{Object, ObjectSymbol};
use serde::{Deserialize, Serialize};

use crate::arch::Arch;
use crate::call::{
    Callee, FunctionCaller, RetKind, Value, read_return, return_to_caller, set_int_return,
    setup_call,
};
use crate::error::EmuError;
use crate::linux::{Exit, LinuxProcess, RunSpec, fault_exit};
use crate::machine::{Machine, Stop};
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
    /// The guest faulted (it stays stopped at the faulting instruction).
    Fault { detail: String, pc: u64 },
}

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
}

struct Inner {
    kind: Kind,
    symbols: BTreeMap<String, u64>,
    snapshots: Vec<(icicle_vm::Snapshot, KernelMark)>,
    done: Option<SessionStop>,
}

type Job = Box<dyn FnOnce(&mut Inner) + Send>;

/// A stepping session. Dropping it stops the emulator thread.
pub struct Session {
    tx: Option<mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
    arch: Arch,
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
        let result = loop {
            let used = self.m().icount() - start;
            if used >= budget {
                break SessionStop::Stepped;
            }
            let chunk = if first { 1 } else { budget - used };
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
                Stop::Halt | Stop::Interrupted => {
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
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<Arch, EmuError>>(1);
        let thread = std::thread::Builder::new()
            .name("kraken-emu-session".into())
            .stack_size(16 << 20)
            .spawn(move || {
                let mut inner = match Inner::build(target) {
                    Ok((inner, arch)) => {
                        let _ = ready_tx.send(Ok(arch));
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
        let arch = ready_rx
            .recv()
            .map_err(|_| EmuError::Emulator(STOP.into()))??;
        Ok(Session {
            tx: Some(tx),
            thread: Some(thread),
            arch,
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
        self.call(move |i| i.run(budget, Some(addr & !1)))
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
        self.call(move |i| i.m().add_breakpoint(addr & !1))
    }

    /// Removes a breakpoint.
    pub fn remove_breakpoint(&self, addr: u64) -> Result<bool, EmuError> {
        self.call(move |i| i.m().remove_breakpoint(addr & !1))
    }

    /// The user breakpoints (stub and trap addresses of function sessions included).
    pub fn breakpoints(&self) -> Result<Vec<u64>, EmuError> {
        self.call(|i| i.m().breakpoints())
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
        self.call(move |i| i.m().write_reg(&n, v))?
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
        self.call(move |i| i.m().write_mem(addr, &data))?
    }

    /// Disassembles `count` instructions from `addr` (`None`: the program counter) in the current
    /// instruction set.
    pub fn disasm(&self, addr: Option<u64>, count: usize) -> Result<Vec<Insn>, EmuError> {
        self.call(move |i| {
            let m = i.m();
            let thumb = m.thumb();
            let mut at = addr.map_or(m.pc(), |a| a & !1);
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
            let mark = match &i.kind {
                Kind::Process(p) => KernelMark {
                    stdout: p.stdout().len(),
                    stderr: p.stderr().len(),
                },
                Kind::Function { .. } => KernelMark {
                    stdout: 0,
                    stderr: 0,
                },
            };
            let s = i.m().snapshot();
            i.snapshots.push((s, mark));
            SnapshotId(i.snapshots.len() - 1)
        })
    }

    /// Restores a snapshot.
    pub fn restore(&self, id: SnapshotId) -> Result<(), EmuError> {
        self.call(move |i| {
            let Some((out, err)) = i.snapshots.get(id.0).map(|(_, m)| (m.stdout, m.stderr)) else {
                return Err(EmuError::Unsupported(format!("no snapshot {}", id.0)));
            };
            // Restoring needs the machine and the snapshot at once.
            let snaps = std::mem::take(&mut i.snapshots);
            i.m().restore(&snaps[id.0].0);
            i.snapshots = snaps;
            if let Kind::Process(p) = &mut i.kind {
                p.truncate_output(out, err);
            }
            i.done = None;
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

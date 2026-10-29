//! Whole-program emulation inside the sandbox child, for the daemon.
//!
//! Emulation is already a confinement of its own: the guest's instructions are interpreted and
//! every system call is answered by [`crate::linux`], which reaches only the private working
//! directory and the read-only sysroot. Running it in `kraken-emu-run` under kraken-sidecar's
//! spawner adds the usual second layer (Landlock: the program, the sysroot and the SLEIGH specs
//! read-only, the working directory read-write; seccomp without sockets; a network namespace
//! when the host allows one; a scrubbed environment; parent-death signal), so a bug in the
//! emulator or the syscall layer still cannot reach the rest of the host.
//!
//! Protocol over the child's socketpair: one request and one reply, each an 8-byte
//! little-endian length followed by JSON ([`RunSpec`] in, `Result<ProgramOutcome, String>` out).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kraken_sidecar::{ConfinementOptions, ConfinementReport, LogSink, SpawnSpec};

use crate::arch::Arch;
use crate::call::{CallOutcome, CallSpec, Callee, FunctionCaller, RetKind, StartAt, Value};
use crate::error::EmuError;
use crate::linux::{ProgramOutcome, RunSpec};
use crate::session::{Insn, Session, SessionStop, Target};
use crate::specs::SpecRoots;
use serde::{Deserialize, Serialize};

/// The runner's file name.
pub const RUNNER: &str = "kraken-emu-run";
/// Largest message accepted.
const MAX_MESSAGE: u64 = 256 << 20;

/// Writes one framed message.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u64).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Reads one framed message.
pub fn read_message(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 8];
    r.read_exact(&mut len)?;
    let n = u64::from_le_bytes(len);
    if n > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; n as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Finds `kraken-emu-run`: `KRAKEN_EMU_RUN`, next to the current executable, or one directory up
/// (test binaries live in `target/<profile>/deps`).
pub fn find_runner() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [dir.join(RUNNER), dir.parent()?.join(RUNNER)]
        .into_iter()
        .find(|p| p.is_file())
}

/// What the parent works out before starting a runner: the spec the child gets (spec root
/// resolved) and the spawn description.
fn prepare(
    spec: &RunSpec,
    runner: &Path,
    options: ConfinementOptions,
    check_sysroot: bool,
) -> Result<(RunSpec, SpawnSpec), EmuError> {
    let workdir = spec
        .workdir
        .clone()
        .ok_or_else(|| EmuError::Io("a confined run needs RunSpec::workdir".into()))?;
    let head = {
        let mut f = std::fs::File::open(&spec.program)
            .map_err(|e| EmuError::Image(format!("{}: {e}", spec.program.display())))?;
        let mut b = vec![0u8; 64];
        let n = f.read(&mut b).map_err(|e| EmuError::Image(e.to_string()))?;
        b.truncate(n);
        b
    };
    let arch = Arch::from_elf(&head)?;
    if check_sysroot && spec.sysroot.is_none() {
        // The child's errors cross as text; this one the caller acts on (it supplies a sysroot).
        let data = std::fs::read(&spec.program)
            .map_err(|e| EmuError::Image(format!("{}: {e}", spec.program.display())))?;
        if let Some(interp) = crate::loader::parse_elf(&data).ok().and_then(|i| i.interp) {
            return Err(EmuError::NeedsSysroot {
                binary: spec
                    .program
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                interp,
                arch,
            });
        }
    }
    let processors =
        SpecRoots::discover_with(spec.spec_roots.iter().cloned()).processors_for(arch)?;
    let root = processors
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| EmuError::Io("spec root has no parent".into()))?
        .to_path_buf();
    let mut child_spec = spec.clone();
    child_spec.spec_roots = vec![root];

    let mut read_only = vec![
        runner.to_path_buf(),
        spec.program.clone(),
        processors.clone(),
    ];
    if let Some(s) = &spec.sysroot {
        read_only.push(s.clone());
    }
    let sp = SpawnSpec {
        program: runner.to_path_buf(),
        args: Vec::new(),
        env: Vec::new(),
        cwd: workdir.clone(),
        read_only,
        optional_read_only: Vec::new(),
        proc_self_read: false,
        read_write: vec![workdir],
        options,
    };
    Ok((child_spec, sp))
}

/// Runs `spec` in the confined runner. `spec.workdir` must be set (it becomes the child's only
/// writable directory); the SLEIGH spec root is resolved here and passed on, since the child
/// sees no environment.
pub fn run_program_confined(
    spec: &RunSpec,
    runner: &Path,
    options: ConfinementOptions,
) -> Result<(ProgramOutcome, ConfinementReport), EmuError> {
    let (child_spec, sp) = prepare(spec, runner, options, true)?;
    let log = LogSink::with_capacity(200);
    let (sandbox, mut sock) = kraken_sidecar::sandbox::Sandbox::spawn(sp, &log)
        .map_err(|e| EmuError::Io(format!("starting {RUNNER}: {e}")))?;
    let report = sandbox.report().clone();
    let body = serde_json::to_vec(&child_spec).map_err(|e| EmuError::Io(e.to_string()))?;
    write_message(&mut sock, &body).map_err(|e| EmuError::Io(format!("to {RUNNER}: {e}")))?;
    // The child enforces the run's own limits; this only catches a runner that hangs.
    let deadline =
        Instant::now() + Duration::from_millis(spec.timeout_ms) + Duration::from_secs(60);
    sock.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|e| EmuError::Io(e.to_string()))?;
    let reply = read_message(&mut sock);
    drop(sandbox);
    let reply = reply.map_err(|e| {
        EmuError::Io(format!(
            "no answer from {RUNNER} ({e}); its log: {}",
            log.tail(20).join(" | ")
        ))
    })?;
    let result: Result<ProgramOutcome, String> =
        serde_json::from_slice(&reply).map_err(|e| EmuError::Io(format!("{RUNNER} reply: {e}")))?;
    result.map(|o| (o, report)).map_err(EmuError::Emulator)
}

/// One argument of a function call made in the runner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallArg {
    /// A number passed in a register or on the stack.
    Value { value: Value },
    /// A buffer placed in the emulator's memory; the function gets its address and the bytes
    /// are returned after the call (`nul` appends a terminating zero byte first).
    Buffer { data: Vec<u8>, nul: bool },
}

/// Where the function is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallTarget {
    /// A function symbol.
    Symbol { name: String },
    /// A link-time address (the load bias is added).
    Vaddr { value: u64 },
}

/// A function call for [`call_function_confined`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRequest {
    /// The function.
    pub target: CallTarget,
    /// Arguments in order.
    pub args: Vec<CallArg>,
    /// Result type.
    pub ret: RetKind,
    /// Instruction budget of the call.
    pub max_instructions: u64,
    /// Run the program to this point first, so its C library is initialised and the function
    /// may use libc and system calls; absent: only the program image is loaded and an import
    /// ends the call.
    pub start_at: Option<StartAt>,
    /// Instruction budget of that startup.
    pub startup_budget: u64,
}

/// A buffer after the call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallBuffer {
    /// Index of its argument.
    pub arg: usize,
    /// Where it was placed (runtime address).
    pub address: u64,
    /// Its bytes after the call.
    pub data: Vec<u8>,
}

/// What a confined function call did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallReply {
    /// How the call ended.
    pub outcome: CallOutcome,
    /// The buffers after the call.
    pub buffers: Vec<CallBuffer>,
    /// Standard output of the call (process mode).
    pub stdout: Vec<u8>,
    /// Standard error of the call (process mode).
    pub stderr: Vec<u8>,
    /// The architecture.
    pub arch: String,
    /// The load bias of the program.
    pub bias: u64,
}

#[derive(Serialize, Deserialize)]
struct CallHello {
    mode: String,
    spec: RunSpec,
    call: CallRequest,
}

/// Calls one function of `spec.program` in the confined runner (`spec.workdir` set). A sysroot
/// is only needed when `call.start_at` is set.
pub fn call_function_confined(
    spec: &RunSpec,
    call: &CallRequest,
    runner: &Path,
    options: ConfinementOptions,
) -> Result<(CallReply, ConfinementReport), EmuError> {
    let (child_spec, sp) = prepare(spec, runner, options, call.start_at.is_some())?;
    let log = LogSink::with_capacity(200);
    let (sandbox, mut sock) = kraken_sidecar::sandbox::Sandbox::spawn(sp, &log)
        .map_err(|e| EmuError::Io(format!("starting {RUNNER}: {e}")))?;
    let report = sandbox.report().clone();
    let hello = CallHello {
        mode: "call".into(),
        spec: child_spec,
        call: call.clone(),
    };
    let body = serde_json::to_vec(&hello).map_err(|e| EmuError::Io(e.to_string()))?;
    write_message(&mut sock, &body).map_err(|e| EmuError::Io(format!("to {RUNNER}: {e}")))?;
    let deadline =
        Instant::now() + Duration::from_millis(spec.timeout_ms) + Duration::from_secs(60);
    sock.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|e| EmuError::Io(e.to_string()))?;
    let reply = read_message(&mut sock);
    drop(sandbox);
    let reply = reply.map_err(|e| {
        EmuError::Io(format!(
            "no answer from {RUNNER} ({e}); its log: {}",
            log.tail(20).join(" | ")
        ))
    })?;
    let result: Result<CallReply, String> =
        serde_json::from_slice(&reply).map_err(|e| EmuError::Io(format!("{RUNNER} reply: {e}")))?;
    result.map(|o| (o, report)).map_err(EmuError::Emulator)
}

fn serve_call(sock: &mut UnixStream, spec: RunSpec, call: CallRequest) -> Result<(), String> {
    let result = do_call(&spec, &call).map_err(|e| e.to_string());
    let body = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    write_message(sock, &body).map_err(|e| format!("reply: {e}"))
}

fn do_call(spec: &RunSpec, req: &CallRequest) -> Result<CallReply, EmuError> {
    let mut fc = match &req.start_at {
        Some(at) => FunctionCaller::after_startup_at(spec, at, req.startup_budget)?,
        None => {
            let data = std::fs::read(&spec.program)
                .map_err(|e| EmuError::Image(format!("{}: {e}", spec.program.display())))?;
            let roots = SpecRoots::discover_with(spec.spec_roots.iter().cloned());
            FunctionCaller::load_elf(&data, 0x5555_5555_0000, &roots)?
        }
    };
    let arch = fc.machine().arch();
    let mut args = Vec::new();
    let mut placed: Vec<(usize, u64, usize)> = Vec::new();
    for (i, a) in req.args.iter().enumerate() {
        match a {
            CallArg::Value { value } => args.push(*value),
            CallArg::Buffer { data, nul } => {
                let mut bytes = data.clone();
                if *nul {
                    bytes.push(0);
                }
                let at = fc.alloc(&bytes)?;
                placed.push((i, at, bytes.len()));
                args.push(Value::ptr(arch, at));
            }
        }
    }
    let callee = match &req.target {
        CallTarget::Symbol { name } => Callee::Symbol(name.clone()),
        CallTarget::Vaddr { value } => Callee::Address(value.wrapping_add(fc.bias())),
    };
    let outcome = fc.call(&CallSpec {
        callee,
        args,
        ret: req.ret,
        max_instructions: req.max_instructions,
    })?;
    let mut buffers = Vec::new();
    for (arg, address, len) in placed {
        let mut data = vec![0u8; len];
        fc.machine().read_mem(address, &mut data)?;
        buffers.push(CallBuffer { arg, address, data });
    }
    let (stdout, stderr) = fc.output();
    Ok(CallReply {
        outcome,
        buffers,
        stdout,
        stderr,
        arch: arch.name().to_string(),
        bias: fc.bias(),
    })
}

/// A request to a debugging runner ([`DebugChild`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DebugRequest {
    /// Execute `n` instructions.
    Step { n: u64, wall_ms: u64 },
    /// One instruction, a call run to its return.
    StepOver { budget: u64, wall_ms: u64 },
    /// Run to a breakpoint, the end or the budget.
    Run { budget: u64, wall_ms: u64 },
    /// Run to an address.
    RunTo {
        addr: u64,
        budget: u64,
        wall_ms: u64,
    },
    /// Run until the current function returns.
    Finish { budget: u64, wall_ms: u64 },
    /// Add a breakpoint.
    AddBreakpoint { addr: u64 },
    /// Remove a breakpoint.
    RemoveBreakpoint { addr: u64 },
    /// Registers, in display order.
    Registers,
    /// Write a register.
    WriteReg { name: String, value: u64 },
    /// Read the named registers (the ones that exist; the rest are left out of the answer).
    ReadRegs { names: Vec<String> },
    /// Write guest memory.
    WriteMemory { addr: u64, data: Vec<u8> },
    /// Read guest memory.
    ReadMemory { addr: u64, len: usize },
    /// Disassemble `count` instructions from `addr` (default: the program counter).
    Disasm { addr: Option<u64>, count: usize },
    /// Pc, instruction count, output sizes.
    State,
    /// Standard output and error so far, from the given offsets.
    Output { out_from: usize, err_from: usize },
    /// A function symbol's address.
    Symbol { name: String },
}

/// The state of a debugging runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugState {
    /// Program counter.
    pub pc: u64,
    /// Instructions executed.
    pub icount: u64,
    /// The main image's load bias.
    pub main_bias: u64,
    /// Architecture name.
    pub arch: String,
    /// Breakpoints.
    pub breakpoints: Vec<u64>,
    /// Bytes of standard output so far.
    pub stdout_len: usize,
    /// Bytes of standard error so far.
    pub stderr_len: usize,
}

/// The answer to a [`DebugRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DebugReply {
    /// A run ended.
    Stop {
        /// Why.
        stop: SessionStop,
        /// The state after it.
        state: DebugState,
    },
    /// Done, nothing to return.
    Done,
    /// Whether a breakpoint changed.
    Changed { changed: bool },
    /// Registers.
    Registers { regs: Vec<(String, u64)> },
    /// Memory bytes.
    Bytes { bytes: Vec<u8> },
    /// Instructions.
    Insns { insns: Vec<Insn> },
    /// State.
    State { state: DebugState },
    /// Output from the offsets.
    Output { stdout: Vec<u8>, stderr: Vec<u8> },
    /// A symbol.
    Symbol { addr: Option<u64> },
}

/// Longest wall-clock limit of one run request the child honours.
const MAX_WALL_MS: u64 = 600_000;

fn debug_state(s: &Session) -> Result<DebugState, EmuError> {
    let (out, err) = s.output()?;
    Ok(DebugState {
        pc: s.pc()?,
        icount: s.icount()?,
        main_bias: s.main_bias()?,
        arch: s.arch().name().to_string(),
        breakpoints: s.breakpoints()?,
        stdout_len: out.len(),
        stderr_len: err.len(),
    })
}

/// Runs `f` with a watchdog that interrupts the session after `wall_ms`.
fn with_deadline(
    s: &Session,
    wall_ms: u64,
    f: impl FnOnce() -> Result<SessionStop, EmuError>,
) -> Result<DebugReply, EmuError> {
    let int = s.interrupter();
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let wall = Duration::from_millis(wall_ms.clamp(1, MAX_WALL_MS));
    let dog = std::thread::spawn(move || {
        if done_rx.recv_timeout(wall) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            int.interrupt();
        }
    });
    let stop = f();
    drop(done_tx);
    let _ = dog.join();
    let stop = stop?;
    Ok(DebugReply::Stop {
        stop,
        state: debug_state(s)?,
    })
}

fn handle(s: &Session, req: DebugRequest) -> Result<DebugReply, EmuError> {
    Ok(match req {
        DebugRequest::Step { n, wall_ms } => with_deadline(s, wall_ms, || s.step(n))?,
        DebugRequest::StepOver { budget, wall_ms } => {
            with_deadline(s, wall_ms, || s.step_over(budget))?
        }
        DebugRequest::Run { budget, wall_ms } => with_deadline(s, wall_ms, || s.run(budget))?,
        DebugRequest::RunTo {
            addr,
            budget,
            wall_ms,
        } => with_deadline(s, wall_ms, || s.run_to(addr, budget))?,
        DebugRequest::Finish { budget, wall_ms } => with_deadline(s, wall_ms, || s.finish(budget))?,
        DebugRequest::AddBreakpoint { addr } => DebugReply::Changed {
            changed: s.add_breakpoint(addr)?,
        },
        DebugRequest::RemoveBreakpoint { addr } => DebugReply::Changed {
            changed: s.remove_breakpoint(addr)?,
        },
        DebugRequest::Registers => DebugReply::Registers {
            regs: s.registers()?,
        },
        DebugRequest::WriteReg { name, value } => {
            s.write_reg(&name, value)?;
            DebugReply::Done
        }
        DebugRequest::ReadRegs { names } => DebugReply::Registers {
            regs: names
                .into_iter()
                .filter_map(|n| s.read_reg(&n).ok().map(|v| (n, v)))
                .collect(),
        },
        DebugRequest::WriteMemory { addr, data } => {
            s.write_memory(addr, data)?;
            DebugReply::Done
        }
        DebugRequest::ReadMemory { addr, len } => DebugReply::Bytes {
            bytes: s.read_memory(addr, len)?,
        },
        DebugRequest::Disasm { addr, count } => DebugReply::Insns {
            insns: s.disasm(addr, count)?,
        },
        DebugRequest::State => DebugReply::State {
            state: debug_state(s)?,
        },
        DebugRequest::Output { out_from, err_from } => {
            let (o, e) = s.output()?;
            DebugReply::Output {
                stdout: o.get(out_from..).unwrap_or_default().to_vec(),
                stderr: e.get(err_from..).unwrap_or_default().to_vec(),
            }
        }
        DebugRequest::Symbol { name } => DebugReply::Symbol {
            addr: s.symbol(&name)?,
        },
    })
}

/// The first message that puts the runner into session mode.
#[derive(Serialize, Deserialize)]
struct DebugHello {
    mode: String,
    spec: RunSpec,
}

/// A debugging session in a confined `kraken-emu-run`: the program is loaded and stopped before
/// its first instruction, and every request is answered over the child's socket. Dropping it
/// ends the child.
pub struct DebugChild {
    sandbox: Option<kraken_sidecar::sandbox::Sandbox>,
    sock: UnixStream,
    log: LogSink,
    report: ConfinementReport,
    /// The state right after loading.
    pub initial: DebugState,
}

impl std::fmt::Debug for DebugChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugChild").finish_non_exhaustive()
    }
}

impl DebugChild {
    /// Starts the runner on `spec` (`workdir` set, a sysroot when the program is dynamic;
    /// `EmuError::NeedsSysroot` says so otherwise).
    pub fn start(
        spec: &RunSpec,
        runner: &Path,
        options: ConfinementOptions,
    ) -> Result<DebugChild, EmuError> {
        let (child_spec, sp) = prepare(spec, runner, options, true)?;
        let log = LogSink::with_capacity(200);
        let (sandbox, mut sock) = kraken_sidecar::sandbox::Sandbox::spawn(sp, &log)
            .map_err(|e| EmuError::Io(format!("starting {RUNNER}: {e}")))?;
        let report = sandbox.report().clone();
        let hello = DebugHello {
            mode: "debug".into(),
            spec: child_spec,
        };
        let body = serde_json::to_vec(&hello).map_err(|e| EmuError::Io(e.to_string()))?;
        write_message(&mut sock, &body).map_err(|e| EmuError::Io(format!("to {RUNNER}: {e}")))?;
        sock.set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| EmuError::Io(e.to_string()))?;
        let mut child = DebugChild {
            sandbox: Some(sandbox),
            sock,
            log,
            report,
            initial: DebugState {
                pc: 0,
                icount: 0,
                main_bias: 0,
                arch: String::new(),
                breakpoints: Vec::new(),
                stdout_len: 0,
                stderr_len: 0,
            },
        };
        match child.read_reply()? {
            DebugReply::State { state } => child.initial = state,
            _ => return Err(EmuError::Io(format!("{RUNNER}: unexpected first reply"))),
        }
        Ok(child)
    }

    /// How the child is confined.
    pub fn report(&self) -> &ConfinementReport {
        &self.report
    }

    fn read_reply(&mut self) -> Result<DebugReply, EmuError> {
        let bytes = read_message(&mut self.sock).map_err(|e| {
            EmuError::Io(format!(
                "no answer from {RUNNER} ({e}); its log: {}",
                self.log.tail(20).join(" | ")
            ))
        })?;
        let r: Result<DebugReply, String> = serde_json::from_slice(&bytes)
            .map_err(|e| EmuError::Io(format!("{RUNNER} reply: {e}")))?;
        r.map_err(EmuError::Emulator)
    }

    /// One request and its answer. A child that does not answer within the request's wall-clock
    /// limit plus a grace period is killed (the session is then over).
    pub fn request(&mut self, req: &DebugRequest) -> Result<DebugReply, EmuError> {
        let wall = match req {
            DebugRequest::Step { wall_ms, .. }
            | DebugRequest::StepOver { wall_ms, .. }
            | DebugRequest::Run { wall_ms, .. }
            | DebugRequest::RunTo { wall_ms, .. }
            | DebugRequest::Finish { wall_ms, .. } => *wall_ms,
            _ => 0,
        };
        if self.sandbox.is_none() {
            return Err(EmuError::Io("the emulator child has ended".into()));
        }
        let body = serde_json::to_vec(req).map_err(|e| EmuError::Io(e.to_string()))?;
        write_message(&mut self.sock, &body)
            .map_err(|e| EmuError::Io(format!("to {RUNNER}: {e}")))?;
        let limit = Duration::from_millis(wall.min(MAX_WALL_MS)) + Duration::from_secs(20);
        self.sock
            .set_read_timeout(Some(limit))
            .map_err(|e| EmuError::Io(e.to_string()))?;
        let r = self.read_reply();
        if matches!(r, Err(EmuError::Io(_))) {
            self.sandbox.take();
        }
        r
    }
}

/// The runner's side: read the request from the socket on fd 0, run, answer.
pub fn serve(sock: &mut UnixStream) -> Result<(), String> {
    let req = read_message(sock).map_err(|e| format!("request: {e}"))?;
    if let Ok(hello) = serde_json::from_slice::<CallHello>(&req)
        && hello.mode == "call"
    {
        return serve_call(sock, hello.spec, hello.call);
    }
    if let Ok(hello) = serde_json::from_slice::<DebugHello>(&req)
        && hello.mode == "debug"
    {
        return serve_debug(sock, hello.spec);
    }
    let spec: RunSpec = serde_json::from_slice(&req).map_err(|e| format!("request: {e}"))?;
    let result: Result<ProgramOutcome, String> =
        crate::linux::run_program(&spec).map_err(|e| e.to_string());
    let body = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    write_message(sock, &body).map_err(|e| format!("reply: {e}"))
}

fn reply(sock: &mut UnixStream, r: Result<DebugReply, String>) -> Result<(), String> {
    let body = serde_json::to_vec(&r).map_err(|e| e.to_string())?;
    write_message(sock, &body).map_err(|e| format!("reply: {e}"))
}

fn serve_debug(sock: &mut UnixStream, spec: RunSpec) -> Result<(), String> {
    let session = match Session::new(Target::Program(spec)) {
        Ok(s) => s,
        Err(e) => return reply(sock, Err(e.to_string())),
    };
    let first = debug_state(&session).map(|state| DebugReply::State { state });
    reply(sock, first.map_err(|e| e.to_string()))?;
    loop {
        let Ok(req) = read_message(sock) else {
            return Ok(());
        };
        let r = serde_json::from_slice::<DebugRequest>(&req)
            .map_err(|e| format!("request: {e}"))
            .and_then(|req| handle(&session, req).map_err(|e| e.to_string()));
        reply(sock, r)?;
    }
}

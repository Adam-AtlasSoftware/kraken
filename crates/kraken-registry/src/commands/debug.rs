//! `debug_*`: a debugger on KRAKEN's own emulator.
//!
//! `debug_start` loads the project's executable (the original or a copy with the byte patches
//! applied) into a confined `kraken-emu-run` child, stopped before its first instruction; the
//! other commands step it, run it to a breakpoint, read its registers and memory and disassemble
//! around the program counter. The guest never runs natively and the project does not change.
//!
//! Sessions are owned by the registry [`Session`] (the daemon holds it): at most
//! [`MAX_SESSIONS`] at a time (a slot is reserved before the child starts), closed after
//! [`IDLE_LIMIT`] without a command (a background thread checks every [`REAP_EVERY`] while
//! sessions exist), when the project is closed or replaced, and when the daemon ends (the child
//! dies with its parent).
//!
//! Addresses in arguments and results are listing addresses (what the Listing tab shows); for a
//! position-independent program they differ from the emulator's by `address_delta`. Register
//! values are the emulator's own.

mod gdb;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_emu::confined::{
    DebugChild, DebugReply, DebugRequest, DebugState as EmuState, RUNNER, find_runner,
};
use kraken_emu::{EmuError, Exit, RunSpec, SessionStop};
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted, hex_bytes, sanitize};
use kraken_sidecar::ConfinementOptions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::emulate::{
    EmulateExit, EmulateExitKind, Patched, build_patched_copy, invalid, problem, with_sysroot,
};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{Session, blocking};

/// How often the background thread looks for idle sessions.
pub const REAP_EVERY: Duration = Duration::from_secs(60);

/// Most debug sessions open at once.
pub const MAX_SESSIONS: usize = 4;
/// A session with no command for this long is closed.
pub const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
/// Most instructions one `debug_step` executes.
pub const MAX_STEP_COUNT: u64 = 1_000_000;
/// Default instruction budget of a run command.
pub const DEFAULT_BUDGET: u64 = 100_000_000;
/// Largest instruction budget of a run command.
pub const MAX_BUDGET: u64 = 1_000_000_000;
/// Default wall-clock limit of one run command, in seconds.
pub const DEFAULT_WALL_SECONDS: u64 = 10;
/// Largest wall-clock limit of one run command, in seconds.
pub const MAX_WALL_SECONDS: u64 = 120;
/// Largest `debug_mem_read`, in bytes.
pub const MAX_READ: usize = 4096;
/// Most instructions `debug_disasm` returns.
pub const MAX_DISASM: usize = 200;
/// Characters of program output returned per stream.
const OUTPUT_CHARS: usize = 4000;
/// Most breakpoints per session.
const MAX_BREAKPOINTS: usize = 256;

struct Live {
    child: DebugChild,
    _work: tempfile::TempDir,
    _libs: Option<tempfile::TempDir>,
    /// Emulator address minus listing address.
    delta: u64,
    arch: String,
    program: String,
    patched: bool,
    out_seen: usize,
    err_seen: usize,
    last_used: Instant,
    last_stop: Option<DebugStop>,
    gdb: Option<gdb::GdbServer>,
}

impl Live {
    fn to_listing(&self, emu: u64) -> u64 {
        emu.wrapping_sub(self.delta)
    }
    fn to_emu(&self, listing: u64) -> u64 {
        listing.wrapping_add(self.delta)
    }
}

#[derive(Default)]
struct Table {
    next: u64,
    reserved: usize,
    reaper: bool,
    sessions: HashMap<u64, Arc<Mutex<Live>>>,
}

/// The debug sessions of one registry session.
#[derive(Clone, Default)]
pub struct DebugTable {
    inner: Arc<Mutex<Table>>,
}

impl std::fmt::Debug for DebugTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DebugTable").finish_non_exhaustive()
    }
}

impl DebugTable {
    /// Ends every session (the project was closed or replaced).
    pub fn clear(&self) {
        let drained: Vec<_> = {
            let mut t = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            t.sessions.drain().map(|(_, v)| v).collect()
        };
        drop(drained);
    }

    fn reap(t: &mut Table) -> Vec<Arc<Mutex<Live>>> {
        let mut gone = Vec::new();
        t.sessions.retain(|_, v| {
            let keep = match v.try_lock() {
                Ok(l) => l.last_used.elapsed() < IDLE_LIMIT,
                Err(_) => true,
            };
            if !keep {
                gone.push(v.clone());
            }
            keep
        });
        gone
    }

    /// Takes a slot before the child is started; dropped unused, it gives the slot back.
    fn reserve(&self) -> Result<Slot, ProtoError> {
        let (gone, result) = {
            let mut t = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let gone = Self::reap(&mut t);
            if t.sessions.len() + t.reserved >= MAX_SESSIONS {
                (
                    gone,
                    Err(problem(
                        ErrorCode::InvalidArgument,
                        format!(
                            "{MAX_SESSIONS} debug sessions are open; end one with debug_stop first"
                        ),
                    )),
                )
            } else {
                t.reserved += 1;
                (gone, Ok(()))
            }
        };
        drop(gone);
        result.map(|()| Slot {
            table: self.clone(),
            used: false,
        })
    }

    fn insert(&self, mut slot: Slot, live: Live) -> u64 {
        slot.used = true;
        let mut t = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        t.reserved = t.reserved.saturating_sub(1);
        t.next += 1;
        let id = t.next;
        t.sessions.insert(id, Arc::new(Mutex::new(live)));
        if !t.reaper {
            t.reaper = true;
            let weak = Arc::downgrade(&self.inner);
            std::thread::spawn(move || Self::reap_loop(&weak, REAP_EVERY));
        }
        id
    }

    fn reap_loop(weak: &std::sync::Weak<Mutex<Table>>, every: Duration) {
        loop {
            std::thread::sleep(every);
            let Some(inner) = weak.upgrade() else { return };
            let (gone, stop) = {
                let mut t = inner.lock().unwrap_or_else(PoisonError::into_inner);
                let gone = Self::reap(&mut t);
                let stop = t.sessions.is_empty();
                if stop {
                    t.reaper = false;
                }
                (gone, stop)
            };
            drop(gone);
            if stop {
                return;
            }
        }
    }

    fn get(&self, id: u64) -> Result<Arc<Mutex<Live>>, ProtoError> {
        let (gone, found) = {
            let mut t = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let gone = Self::reap(&mut t);
            (gone, t.sessions.get(&id).cloned())
        };
        drop(gone);
        found.ok_or_else(|| {
            problem(
                ErrorCode::NotFound,
                format!("no debug session {id}; it ended or was never started (debug_start)"),
            )
        })
    }

    fn remove(&self, id: u64) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sessions
            .remove(&id)
            .is_some()
    }

    fn ids(&self) -> Vec<(u64, Arc<Mutex<Live>>)> {
        let (gone, mut v) = {
            let mut t = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let gone = Self::reap(&mut t);
            let v: Vec<_> = t.sessions.iter().map(|(k, v)| (*k, v.clone())).collect();
            (gone, v)
        };
        drop(gone);
        v.sort_by_key(|(k, _)| *k);
        v
    }
}

/// A reserved session slot.
struct Slot {
    table: DebugTable,
    used: bool,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if !self.used {
            let mut t = self
                .table
                .inner
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            t.reserved = t.reserved.saturating_sub(1);
        }
    }
}

/// Why the program stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugStop {
    /// `stepped`, `breakpoint`, `reached`, `returned`, `exited`, `budget`, `interrupted` (the
    /// wall-clock limit), `fault` or `import`.
    pub kind: String,
    /// Program counter (listing address) where it stopped.
    pub pc: Hex64,
    /// Fault text or the name of the import.
    pub detail: Option<String>,
    /// How the program ended, when `kind` is `exited`.
    pub exit: Option<EmulateExit>,
}

fn present_stop(stop: &SessionStop, state: &EmuState, live: &Live) -> DebugStop {
    let pc = Hex64(live.to_listing(state.pc));
    let (kind, detail, exit) = match stop {
        SessionStop::Stepped => ("stepped", None, None),
        SessionStop::Breakpoint { .. } => ("breakpoint", None, None),
        SessionStop::Reached { .. } => ("reached", None, None),
        SessionStop::Returned { .. } => ("returned", None, None),
        SessionStop::Budget => ("budget", None, None),
        SessionStop::Interrupted => (
            "interrupted",
            Some("the wall-clock limit of this command ran out".into()),
            None,
        ),
        SessionStop::Import { name } => ("import", Some(sanitize(name)), None),
        SessionStop::Fault { detail, .. } => ("fault", Some(sanitize(detail)), None),
        SessionStop::Exited { exit } => {
            let (k, v, d) = match exit {
                Exit::Code { code } => (EmulateExitKind::Code, Some(i64::from(*code)), None),
                Exit::Signal { signal, detail } => (
                    EmulateExitKind::Signal,
                    Some(i64::from(*signal)),
                    Some(sanitize(detail)),
                ),
                Exit::Budget => (EmulateExitKind::StepLimit, None, None),
                Exit::Timeout => (EmulateExitKind::Timeout, None, None),
                Exit::Unsupported { detail } => {
                    (EmulateExitKind::Unsupported, None, Some(sanitize(detail)))
                }
            };
            ("exited", d, Some(EmulateExit { kind: k, value: v }))
        }
    };
    DebugStop {
        kind: kind.into(),
        pc,
        detail,
        exit,
    }
}

fn cut(bytes: &[u8], tail: bool) -> Untrusted<String> {
    let all = String::from_utf8_lossy(bytes);
    let n = all.chars().count();
    let kept: String = if tail {
        all.chars().skip(n.saturating_sub(OUTPUT_CHARS)).collect()
    } else {
        all.chars().take(OUTPUT_CHARS).collect()
    };
    Untrusted(sanitize(&kept))
}

fn emu_problem(e: EmuError) -> ProtoError {
    match e {
        EmuError::Emulator(m) | EmuError::Io(m) => problem(
            ErrorCode::Internal,
            format!("the emulator failed: {m} (the session may have ended; check debug_state)"),
        ),
        other => problem(ErrorCode::InvalidArgument, other.to_string()),
    }
}

fn ask(live: &mut Live, req: &DebugRequest) -> Result<DebugReply, ProtoError> {
    live.last_used = Instant::now();
    live.child.request(req).map_err(emu_problem)
}

fn unexpected() -> ProtoError {
    problem(
        ErrorCode::Internal,
        "the emulator child sent an unexpected reply",
    )
}

fn lock(live: &Arc<Mutex<Live>>) -> std::sync::MutexGuard<'_, Live> {
    live.lock().unwrap_or_else(PoisonError::into_inner)
}

fn session_arg(id: u64) -> Result<u64, ProtoError> {
    if id == 0 {
        return Err(invalid("session must be the id debug_start returned"));
    }
    Ok(id)
}

/// A function symbol of the program or an address.
fn resolve(
    live: &mut Live,
    address: Option<Hex64>,
    symbol: Option<&str>,
) -> Result<u64, ProtoError> {
    match (address, symbol) {
        (Some(a), None) => Ok(live.to_emu(a.0)),
        (None, Some(name)) => match ask(
            live,
            &DebugRequest::Symbol {
                name: name.to_string(),
            },
        )? {
            DebugReply::Symbol { addr: Some(a) } => Ok(a),
            DebugReply::Symbol { addr: None } => Err(problem(
                ErrorCode::NotFound,
                format!("the program has no function symbol `{name}` (stripped? give an address)"),
            )),
            _ => Err(unexpected()),
        },
        _ => Err(invalid("give exactly one of address and symbol")),
    }
}

// ---------------------------------------------------------------------------------------------
// debug_start

/// Arguments of `debug_start`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugStartArgs {
    /// Debug a copy with the project's byte patches applied, instead of the original (default
    /// false).
    #[serde(default)]
    pub patched: bool,
    /// Command-line arguments after `argv[0]` (at most 64, each at most 4096 bytes).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Text for the program's standard input (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
}

/// Result of `debug_start`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugStartOut {
    /// The id every other `debug_*` command takes.
    pub session: u64,
    /// The architecture.
    pub arch: String,
    /// The first instruction (listing address).
    pub pc: Hex64,
    /// Emulator address minus listing address (0 unless the program is position independent).
    pub address_delta: Hex64,
    /// Facts about the session.
    pub notes: Vec<String>,
}

/// Starts a debug session.
pub struct DebugStart;

#[async_trait]
impl Command for DebugStart {
    type Args = DebugStartArgs;
    type Output = DebugStartOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_start",
            "Start a debugger session on the program in the emulator, stopped before its first instruction",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Loads the project's executable (or, with `patched`, a copy with its byte patches \
             applied) into the emulator and stops before the first instruction. Returns the \
             `session` id the other `debug_*` commands take. Linux ELF programs only (x86, \
             x86-64, ARM, AArch64, RISC-V). At most 4 sessions; idle ones close after 30 \
             minutes.\n\
             Example: debug_start {\"argv\": [\"-v\"], \"stdin\": \"hello\\n\"}",
        )
        .details(
            "The guest is interpreted in a sandboxed child process (`kraken-emu-run`) that can \
             read the program and the SLEIGH specs and write one private directory; time and \
             randomness are fixed, there is no network, and nothing in the project changes. A \
             dynamically linked program needs a sysroot or this computer's libraries, as for \
             `emulate_run`. Next: `debug_break_set`, `debug_run_to` (for example \
             `{\"symbol\": \"main\"}`), `debug_step`, `debug_regs`, `debug_mem_read`. End it \
             with `debug_stop`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: DebugStartArgs,
    ) -> Result<DebugStartOut, ProtoError> {
        if args.stdin.len() > super::emulate::MAX_STDIN_BYTES {
            return Err(invalid("stdin is longer than 1 MiB"));
        }
        if args.argv.len() > super::emulate::MAX_ARGS {
            return Err(invalid("argv has more than 64 entries"));
        }
        if args
            .argv
            .iter()
            .any(|a| a.len() > super::emulate::MAX_ARG_BYTES || a.contains('\0'))
        {
            return Err(invalid("an argv entry is too long or contains a NUL byte"));
        }
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let patches = if args.patched {
            project.with_store(|st| st.active_patches(None)).await?
        } else {
            Vec::new()
        };
        let patched = Patched {
            patches,
            engine_base: project.program().base.0,
        };
        let table = s.debug().clone();
        blocking(move || start(&table, &binary, args, patched)).await
    }
}

fn start(
    table: &DebugTable,
    binary: &std::path::Path,
    args: DebugStartArgs,
    patched: Patched,
) -> Result<DebugStartOut, ProtoError> {
    let slot = table.reserve()?;
    let runner = find_runner().filter(|p| p.is_file()).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            format!(
                "the emulator's child program `{RUNNER}` was not found next to this executable: \
                 build it (`cargo build -p kraken-emu --bin {RUNNER}`) or set KRAKEN_EMU_RUN to \
                 its path"
            ),
        )
    })?;
    if !binary.is_file() {
        return Err(problem(
            ErrorCode::NotFound,
            format!(
                "the project's binary {} is not there any more",
                binary.display()
            ),
        ));
    }
    let work = tempfile::Builder::new()
        .prefix("kraken-debug-")
        .tempdir()
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    let mut notes = Vec::new();
    let use_patched = args.patched && !patched.patches.is_empty();
    let program = if use_patched {
        notes.push(format!(
            "debugging a patched copy with {} byte patch{} applied",
            patched.patches.len(),
            if patched.patches.len() == 1 { "" } else { "es" }
        ));
        build_patched_copy(binary, &patched.patches, work.path(), patched.engine_base)?
    } else {
        if args.patched {
            notes.push("the project has no byte patches; debugging the original".into());
        }
        binary.to_path_buf()
    };
    let pie = is_pie(&program);
    let mut spec = RunSpec::new(&program);
    spec.args = args.argv;
    spec.stdin = args.stdin.into_bytes();
    spec.output_cap = 64 * 1024;
    spec.workdir = Some(work.path().to_path_buf());
    let start = |spec: &RunSpec| DebugChild::start(spec, &runner, ConfinementOptions::default());
    let (child, libs) = with_sysroot(&mut spec, &program, binary, &mut notes, start)?;
    if !child.report().is_confined() {
        notes.push(format!(
            "the emulator child ran with limited confinement: {}",
            child.report()
        ));
    }
    let initial = child.initial.clone();
    let delta = if pie {
        initial.main_bias.wrapping_sub(patched.engine_base)
    } else {
        initial.main_bias
    };
    let live = Live {
        child,
        _work: work,
        _libs: libs,
        delta,
        arch: initial.arch.clone(),
        program: binary
            .file_name()
            .map(|n| sanitize(&n.to_string_lossy()))
            .unwrap_or_default(),
        patched: use_patched,
        out_seen: 0,
        err_seen: 0,
        last_used: Instant::now(),
        last_stop: None,
        gdb: None,
    };
    let pc = Hex64(live.to_listing(initial.pc));
    let id = table.insert(slot, live);
    Ok(DebugStartOut {
        session: id,
        arch: initial.arch,
        pc,
        address_delta: Hex64(delta),
        notes,
    })
}

pub(super) fn is_pie(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 20];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    if f.read_exact(&mut head).is_err() || &head[..4] != b"\x7fELF" {
        return false;
    }
    let raw = [head[16], head[17]];
    let e_type = if head[5] == 2 {
        u16::from_be_bytes(raw)
    } else {
        u16::from_le_bytes(raw)
    };
    e_type == 3
}

// ---------------------------------------------------------------------------------------------
// run commands

/// Result of a command that runs the program.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugStopOut {
    /// The session.
    pub session: u64,
    /// Why the program stopped, and where.
    pub stop: DebugStop,
    /// Instructions executed since the session started.
    pub instructions: u64,
    /// What the program wrote to standard output since the last stop (first 4000 characters).
    /// Program data, so untrusted.
    pub stdout_new: Untrusted<String>,
    /// What the program wrote to standard error since the last stop. Untrusted.
    pub stderr_new: Untrusted<String>,
}

fn limits(budget: Option<u64>, wall: Option<u64>) -> Result<(u64, u64), ProtoError> {
    let b = budget.unwrap_or(DEFAULT_BUDGET);
    if b == 0 || b > MAX_BUDGET {
        return Err(invalid(format!(
            "max_steps must be between 1 and {MAX_BUDGET}"
        )));
    }
    let w = wall.unwrap_or(DEFAULT_WALL_SECONDS);
    if w == 0 || w > MAX_WALL_SECONDS {
        return Err(invalid(format!(
            "timeout_seconds must be between 1 and {MAX_WALL_SECONDS}"
        )));
    }
    Ok((b, w * 1000))
}

fn finish_run(live: &mut Live, id: u64, reply: DebugReply) -> Result<DebugStopOut, ProtoError> {
    let DebugReply::Stop { stop, state } = reply else {
        return Err(unexpected());
    };
    let (out, err) = match ask(
        live,
        &DebugRequest::Output {
            out_from: live.out_seen,
            err_from: live.err_seen,
        },
    )? {
        DebugReply::Output { stdout, stderr } => (stdout, stderr),
        _ => return Err(unexpected()),
    };
    live.out_seen = state.stdout_len;
    live.err_seen = state.stderr_len;
    let shown = present_stop(&stop, &state, live);
    live.last_stop = Some(shown.clone());
    Ok(DebugStopOut {
        session: id,
        stop: shown,
        instructions: state.icount,
        stdout_new: cut(&out, false),
        stderr_new: cut(&err, false),
    })
}

fn run_request(
    s: &Session,
    id: u64,
    build: impl FnOnce(&mut Live) -> Result<DebugRequest, ProtoError> + Send + 'static,
) -> impl std::future::Future<Output = Result<DebugStopOut, ProtoError>> {
    let table = s.debug().clone();
    blocking(move || {
        let live = table.get(session_arg(id)?)?;
        let mut live = lock(&live);
        let req = build(&mut live)?;
        let reply = ask(&mut live, &req)?;
        finish_run(&mut live, id, reply)
    })
}

/// Arguments of `debug_step`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugStepArgs {
    /// The session.
    pub session: u64,
    /// Instructions to execute (default 1, at most 1000000).
    #[serde(default)]
    pub count: Option<u64>,
}

/// Executes instructions.
pub struct DebugStep;

#[async_trait]
impl Command for DebugStep {
    type Args = DebugStepArgs;
    type Output = DebugStopOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_step",
            "Execute one instruction (or `count`) of the debugged program, entering calls",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Executes `count` instructions (default 1) and reports where the program stopped. \
             A call is entered. Stops early at a breakpoint, a fault or the program's end.\n\
             Example: debug_step {\"session\": 1, \"count\": 5}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugStepArgs,
    ) -> Result<DebugStopOut, ProtoError> {
        let n = a.count.unwrap_or(1);
        if n == 0 || n > MAX_STEP_COUNT {
            return Err(invalid(format!(
                "count must be between 1 and {MAX_STEP_COUNT}"
            )));
        }
        run_request(s, a.session, move |_| {
            Ok(DebugRequest::Step {
                n,
                wall_ms: DEFAULT_WALL_SECONDS * 1000,
            })
        })
        .await
    }
}

/// Arguments of the commands that take a session and limits.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugRunArgs {
    /// The session.
    pub session: u64,
    /// Instruction budget (default 100000000, at most 1000000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit in seconds (default 10, at most 120); the program stops with kind
    /// `interrupted` and the session stays usable.
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

macro_rules! run_command {
    ($ty:ident, $name:literal, $summary:literal, $doc:literal, $req:expr) => {
        #[doc = $summary]
        pub struct $ty;

        #[async_trait]
        impl Command for $ty {
            type Args = DebugRunArgs;
            type Output = DebugStopOut;

            fn spec() -> CommandSpec {
                CommandSpec::new($name, $summary, CommandKind::Query, Permission::Safe).doc($doc)
            }

            async fn run(
                &self,
                s: &Session,
                _c: &CallContext,
                a: DebugRunArgs,
            ) -> Result<DebugStopOut, ProtoError> {
                let (budget, wall_ms) = limits(a.max_steps, a.timeout_seconds)?;
                let make: fn(u64, u64) -> DebugRequest = $req;
                run_request(s, a.session, move |_| Ok(make(budget, wall_ms))).await
            }
        }
    };
}

run_command!(
    DebugStepOver,
    "debug_step_over",
    "Execute one instruction of the debugged program, running a call to its return",
    "Executes one instruction; if it is a call, the callee runs to its return first (a breakpoint \
     inside it still stops the run).\n\
     Example: debug_step_over {\"session\": 1}",
    |budget, wall_ms| DebugRequest::StepOver { budget, wall_ms }
);

run_command!(
    DebugStepOut,
    "debug_step_out",
    "Run the debugged program until the current function returns",
    "Runs until the function the program is in returns to its caller (or a breakpoint, a fault \
     or the end stops it first).\n\
     Example: debug_step_out {\"session\": 1}",
    |budget, wall_ms| DebugRequest::Finish { budget, wall_ms }
);

run_command!(
    DebugContinue,
    "debug_continue",
    "Run the debugged program to the next breakpoint or its end",
    "Runs until a breakpoint, a fault, the program's end, the instruction budget or the \
     wall-clock limit. Standard output written meanwhile comes back in `stdout_new`.\n\
     Example: debug_continue {\"session\": 1, \"timeout_seconds\": 30}",
    |budget, wall_ms| DebugRequest::Run { budget, wall_ms }
);

/// Arguments of `debug_run_to`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugRunToArgs {
    /// The session.
    pub session: u64,
    /// Listing address to run to (give this or `symbol`).
    #[serde(default)]
    pub address: Option<Hex64>,
    /// A function symbol of the program, such as `main` (give this or `address`).
    #[serde(default)]
    pub symbol: Option<String>,
    /// Instruction budget (default 100000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit in seconds (default 10).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Runs to an address.
pub struct DebugRunTo;

#[async_trait]
impl Command for DebugRunTo {
    type Args = DebugRunToArgs;
    type Output = DebugStopOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_run_to",
            "Run the debugged program to an address or function, ignoring no breakpoints",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Runs until the program counter reaches `address` or the function `symbol` (stops \
             at other breakpoints on the way).\n\
             Example: debug_run_to {\"session\": 1, \"symbol\": \"main\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugRunToArgs,
    ) -> Result<DebugStopOut, ProtoError> {
        let (budget, wall_ms) = limits(a.max_steps, a.timeout_seconds)?;
        run_request(s, a.session, move |live| {
            let addr = resolve(live, a.address, a.symbol.as_deref())?;
            Ok(DebugRequest::RunTo {
                addr,
                budget,
                wall_ms,
            })
        })
        .await
    }
}

// ---------------------------------------------------------------------------------------------
// breakpoints

/// Arguments of `debug_break_set` and `debug_break_remove`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugBreakArgs {
    /// The session.
    pub session: u64,
    /// Listing address (give this or `symbol`).
    #[serde(default)]
    pub address: Option<Hex64>,
    /// A function symbol of the program (give this or `address`).
    #[serde(default)]
    pub symbol: Option<String>,
}

/// The breakpoints of a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugBreakOut {
    /// The session.
    pub session: u64,
    /// Whether the set changed.
    pub changed: bool,
    /// Every breakpoint (listing addresses).
    pub breakpoints: Vec<Hex64>,
}

fn break_list(live: &mut Live, id: u64, changed: bool) -> Result<DebugBreakOut, ProtoError> {
    let DebugReply::State { state } = ask(live, &DebugRequest::State)? else {
        return Err(unexpected());
    };
    Ok(DebugBreakOut {
        session: id,
        changed,
        breakpoints: state
            .breakpoints
            .iter()
            .map(|a| Hex64(live.to_listing(*a)))
            .collect(),
    })
}

fn break_op(
    s: &Session,
    a: DebugBreakArgs,
    add: bool,
) -> impl std::future::Future<Output = Result<DebugBreakOut, ProtoError>> {
    let table = s.debug().clone();
    blocking(move || {
        let live = table.get(session_arg(a.session)?)?;
        let mut live = lock(&live);
        let addr = resolve(&mut live, a.address, a.symbol.as_deref())?;
        if add {
            let n = break_list(&mut live, a.session, false)?.breakpoints.len();
            if n >= MAX_BREAKPOINTS {
                return Err(invalid(format!(
                    "a session holds at most {MAX_BREAKPOINTS} breakpoints"
                )));
            }
        }
        let req = if add {
            DebugRequest::AddBreakpoint { addr }
        } else {
            DebugRequest::RemoveBreakpoint { addr }
        };
        let DebugReply::Changed { changed } = ask(&mut live, &req)? else {
            return Err(unexpected());
        };
        break_list(&mut live, a.session, changed)
    })
}

/// Sets a breakpoint.
pub struct DebugBreakSet;

#[async_trait]
impl Command for DebugBreakSet {
    type Args = DebugBreakArgs;
    type Output = DebugBreakOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_break_set",
            "Set a breakpoint in the debugged program at an address or function",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Sets a breakpoint at a listing `address` or at the function `symbol`; \
             `debug_continue` stops there. Returns all breakpoints. Breakpoints belong to the \
             session, not the project.\n\
             Example: debug_break_set {\"session\": 1, \"address\": \"0x401136\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugBreakArgs,
    ) -> Result<DebugBreakOut, ProtoError> {
        break_op(s, a, true).await
    }
}

/// Removes a breakpoint.
pub struct DebugBreakRemove;

#[async_trait]
impl Command for DebugBreakRemove {
    type Args = DebugBreakArgs;
    type Output = DebugBreakOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_break_remove",
            "Remove a breakpoint of the debugged program",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Removes the breakpoint at `address` or `symbol`; `changed` says whether there was \
             one.\n\
             Example: debug_break_remove {\"session\": 1, \"address\": \"0x401136\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugBreakArgs,
    ) -> Result<DebugBreakOut, ProtoError> {
        break_op(s, a, false).await
    }
}

pub use gdb::{DebugGdbServe, DebugGdbServeArgs, DebugGdbServeOut};

/// Arguments of the commands that take only a session.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugSessionArgs {
    /// The session.
    pub session: u64,
}

/// Lists breakpoints.
pub struct DebugBreakList;

#[async_trait]
impl Command for DebugBreakList {
    type Args = DebugSessionArgs;
    type Output = DebugBreakOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_break_list",
            "List the breakpoints of a debug session",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Lists the session's breakpoints as listing addresses.\n\
             Example: debug_break_list {\"session\": 1}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugSessionArgs,
    ) -> Result<DebugBreakOut, ProtoError> {
        let table = s.debug().clone();
        blocking(move || {
            let live = table.get(session_arg(a.session)?)?;
            let mut live = lock(&live);
            break_list(&mut live, a.session, false)
        })
        .await
    }
}

// ---------------------------------------------------------------------------------------------
// inspection

/// One register.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugRegister {
    /// Register name.
    pub name: String,
    /// Its value (the emulator's own, not translated to listing addresses).
    pub value: Hex64,
}

/// Result of `debug_regs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugRegsOut {
    /// The session.
    pub session: u64,
    /// The program counter as a listing address.
    pub pc: Hex64,
    /// General purpose registers in display order.
    pub registers: Vec<DebugRegister>,
}

/// Reads registers.
pub struct DebugRegs;

#[async_trait]
impl Command for DebugRegs {
    type Args = DebugSessionArgs;
    type Output = DebugRegsOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_regs",
            "Read the registers of the debugged program",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "The general purpose registers (names as in the architecture's SLEIGH spec) and the \
             program counter. Values are the emulator's; for a position-independent program add \
             nothing, they are real emulator addresses (listing address = value - \
             `address_delta` from `debug_start`).\n\
             Example: debug_regs {\"session\": 1}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugSessionArgs,
    ) -> Result<DebugRegsOut, ProtoError> {
        let table = s.debug().clone();
        blocking(move || {
            let live = table.get(session_arg(a.session)?)?;
            let mut live = lock(&live);
            let DebugReply::Registers { regs } = ask(&mut live, &DebugRequest::Registers)? else {
                return Err(unexpected());
            };
            let DebugReply::State { state } = ask(&mut live, &DebugRequest::State)? else {
                return Err(unexpected());
            };
            Ok(DebugRegsOut {
                session: a.session,
                pc: Hex64(live.to_listing(state.pc)),
                registers: regs
                    .into_iter()
                    .map(|(name, v)| DebugRegister {
                        name,
                        value: Hex64(v),
                    })
                    .collect(),
            })
        })
        .await
    }
}

/// Arguments of `debug_mem_read`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugMemReadArgs {
    /// The session.
    pub session: u64,
    /// Where to read.
    pub address: Hex64,
    /// Bytes to read (default 64, at most 4096).
    #[serde(default)]
    pub length: Option<usize>,
    /// Treat `address` as an emulator address (a stack or heap pointer from a register) instead
    /// of a listing address (default false).
    #[serde(default)]
    pub emulator_address: bool,
}

/// Result of `debug_mem_read`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugMemOut {
    /// The session.
    pub session: u64,
    /// The address read, as given.
    pub address: Hex64,
    /// The bytes, lowercase hex.
    pub hex: String,
    /// The bytes as text, `.` for the unprintable. Program data, so untrusted.
    pub ascii: Untrusted<String>,
}

/// Reads guest memory.
pub struct DebugMemRead;

#[async_trait]
impl Command for DebugMemRead {
    type Args = DebugMemReadArgs;
    type Output = DebugMemOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_mem_read",
            "Read bytes of the debugged program's memory",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Reads up to 4096 bytes at a listing address (or, with `emulator_address`, at a \
             pointer taken from a register such as the stack pointer). Fails for unmapped \
             memory.\n\
             Example: debug_mem_read {\"session\": 1, \"address\": \"0x7ffffff0\", \
             \"emulator_address\": true, \"length\": 32}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugMemReadArgs,
    ) -> Result<DebugMemOut, ProtoError> {
        let len = a.length.unwrap_or(64);
        if len == 0 || len > MAX_READ {
            return Err(invalid(format!("length must be between 1 and {MAX_READ}")));
        }
        let table = s.debug().clone();
        blocking(move || {
            let live = table.get(session_arg(a.session)?)?;
            let mut live = lock(&live);
            let addr = if a.emulator_address {
                a.address.0
            } else {
                live.to_emu(a.address.0)
            };
            let DebugReply::Bytes { bytes } =
                ask(&mut live, &DebugRequest::ReadMemory { addr, len })?
            else {
                return Err(unexpected());
            };
            let ascii: String = bytes
                .iter()
                .map(|b| {
                    if (0x20..0x7f).contains(b) {
                        char::from(*b)
                    } else {
                        '.'
                    }
                })
                .collect();
            Ok(DebugMemOut {
                session: a.session,
                address: a.address,
                hex: hex_bytes(&bytes),
                ascii: Untrusted(ascii),
            })
        })
        .await
    }
}

/// Arguments of `debug_disasm`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugDisasmArgs {
    /// The session.
    pub session: u64,
    /// Where to start, as a listing address (default: the program counter).
    #[serde(default)]
    pub address: Option<Hex64>,
    /// Instructions to return (default 20, at most 200).
    #[serde(default)]
    pub count: Option<usize>,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugInsn {
    /// Listing address.
    pub address: Hex64,
    /// Raw bytes, lowercase hex.
    pub bytes: String,
    /// Disassembly.
    pub text: String,
    /// True for the instruction the program counter is on.
    pub is_pc: bool,
}

/// Result of `debug_disasm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugDisasmOut {
    /// The session.
    pub session: u64,
    /// The instructions.
    pub instructions: Vec<DebugInsn>,
}

/// Disassembles what the emulator will execute.
pub struct DebugDisasm;

#[async_trait]
impl Command for DebugDisasm {
    type Args = DebugDisasmArgs;
    type Output = DebugDisasmOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_disasm",
            "Disassemble the debugged program's memory from the program counter or an address",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Disassembles `count` instructions (default 20) from `address` or the program \
             counter, from the bytes in the emulator's memory (so decrypted or patched code \
             shows as it runs). `is_pc` marks the current instruction.\n\
             Example: debug_disasm {\"session\": 1, \"count\": 8}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugDisasmArgs,
    ) -> Result<DebugDisasmOut, ProtoError> {
        let count = a.count.unwrap_or(20);
        if count == 0 || count > MAX_DISASM {
            return Err(invalid(format!("count must be between 1 and {MAX_DISASM}")));
        }
        let table = s.debug().clone();
        blocking(move || {
            let live = table.get(session_arg(a.session)?)?;
            let mut live = lock(&live);
            let DebugReply::State { state } = ask(&mut live, &DebugRequest::State)? else {
                return Err(unexpected());
            };
            let addr = a.address.map(|x| live.to_emu(x.0));
            let DebugReply::Insns { insns } =
                ask(&mut live, &DebugRequest::Disasm { addr, count })?
            else {
                return Err(unexpected());
            };
            Ok(DebugDisasmOut {
                session: a.session,
                instructions: insns
                    .into_iter()
                    .map(|i| DebugInsn {
                        address: Hex64(live.to_listing(i.addr)),
                        bytes: hex_bytes(&i.bytes),
                        text: sanitize(&i.text),
                        is_pc: i.addr == state.pc,
                    })
                    .collect(),
            })
        })
        .await
    }
}

// ---------------------------------------------------------------------------------------------
// state, sessions, stop

/// Result of `debug_state`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugStateOut {
    /// The session.
    pub session: u64,
    /// File name of the program being debugged.
    pub program: String,
    /// True when a patched copy runs.
    pub patched: bool,
    /// The architecture.
    pub arch: String,
    /// The program counter as a listing address.
    pub pc: Hex64,
    /// Emulator address minus listing address.
    pub address_delta: Hex64,
    /// Instructions executed so far.
    pub instructions: u64,
    /// How the last run command stopped (absent before the first).
    pub last_stop: Option<DebugStop>,
    /// True when the program has ended.
    pub finished: bool,
    /// Breakpoints (listing addresses).
    pub breakpoints: Vec<Hex64>,
    /// All standard output so far (last 4000 characters). Untrusted.
    pub stdout: Untrusted<String>,
    /// All standard error so far (last 4000 characters). Untrusted.
    pub stderr: Untrusted<String>,
}

fn state_of(live: &mut Live, id: u64) -> Result<DebugStateOut, ProtoError> {
    let DebugReply::State { state } = ask(live, &DebugRequest::State)? else {
        return Err(unexpected());
    };
    let (out, err) = match ask(
        live,
        &DebugRequest::Output {
            out_from: state.stdout_len.saturating_sub(OUTPUT_CHARS * 4),
            err_from: state.stderr_len.saturating_sub(OUTPUT_CHARS * 4),
        },
    )? {
        DebugReply::Output { stdout, stderr } => (stdout, stderr),
        _ => return Err(unexpected()),
    };
    let finished = live.last_stop.as_ref().is_some_and(|s| s.kind == "exited");
    Ok(DebugStateOut {
        session: id,
        program: live.program.clone(),
        patched: live.patched,
        arch: live.arch.clone(),
        pc: Hex64(live.to_listing(state.pc)),
        address_delta: Hex64(live.delta),
        instructions: state.icount,
        last_stop: live.last_stop.clone(),
        finished,
        breakpoints: state
            .breakpoints
            .iter()
            .map(|a| Hex64(live.to_listing(*a)))
            .collect(),
        stdout: cut(&out, true),
        stderr: cut(&err, true),
    })
}

/// Reports where a session is.
pub struct DebugStateCommand;

#[async_trait]
impl Command for DebugStateCommand {
    type Args = DebugSessionArgs;
    type Output = DebugStateOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_state",
            "Report where a debug session is: pc, last stop, breakpoints and the program's output so far",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "The program counter (listing address), instruction count, how the last run command \
             stopped, the breakpoints and the standard output and error written so far (last \
             4000 characters each, untrusted program data).\n\
             Example: debug_state {\"session\": 1}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugSessionArgs,
    ) -> Result<DebugStateOut, ProtoError> {
        let table = s.debug().clone();
        blocking(move || {
            let live = table.get(session_arg(a.session)?)?;
            let mut live = lock(&live);
            state_of(&mut live, a.session)
        })
        .await
    }
}

/// Result of `debug_sessions`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DebugSessionsOut {
    /// The open sessions, oldest first.
    pub sessions: Vec<DebugStateOut>,
}

/// Lists open sessions.
pub struct DebugSessions;

#[async_trait]
impl Command for DebugSessions {
    type Args = NoArgs;
    type Output = DebugSessionsOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_sessions",
            "List the open debug sessions of the project",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Every open debug session with the state `debug_state` gives. Use it to find a \
             session again after a reconnect.\n\
             Example: debug_sessions {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        _a: NoArgs,
    ) -> Result<DebugSessionsOut, ProtoError> {
        let table = s.debug().clone();
        blocking(move || {
            let mut sessions = Vec::new();
            for (id, live) in table.ids() {
                let mut live = lock(&live);
                if let Ok(st) = state_of(&mut live, id) {
                    sessions.push(st);
                }
            }
            Ok(DebugSessionsOut { sessions })
        })
        .await
    }
}

/// No arguments.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

/// Result of `debug_stop`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugStopSessionOut {
    /// The session.
    pub session: u64,
    /// True when it was open.
    pub ended: bool,
}

/// Ends a session.
pub struct DebugStopSession;

#[async_trait]
impl Command for DebugStopSession {
    type Args = DebugSessionArgs;
    type Output = DebugStopSessionOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_stop",
            "End a debug session and its emulator child",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Ends the session, stops the child process and removes its private directory. \
             Ending one that is already gone is not an error.\n\
             Example: debug_stop {\"session\": 1}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _c: &CallContext,
        a: DebugSessionArgs,
    ) -> Result<DebugStopSessionOut, ProtoError> {
        let table = s.debug().clone();
        blocking(move || {
            Ok(DebugStopSessionOut {
                session: a.session,
                ended: table.remove(a.session),
            })
        })
        .await
    }
}

#[cfg(test)]
mod slot_tests {
    use super::*;

    #[test]
    fn slots_are_reserved_before_a_start_and_given_back() {
        let t = DebugTable::default();
        let slots: Vec<_> = (0..MAX_SESSIONS).map(|_| t.reserve().unwrap()).collect();
        assert!(t.reserve().is_err());
        drop(slots);
        assert!(t.reserve().is_ok());
    }
}

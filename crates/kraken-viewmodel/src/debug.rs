//! The Debug tab's state and actions: a session on KRAKEN's emulator driven through the
//! `debug_*` registry commands.
//!
//! The panel keeps the breakpoints the person wants (they can be set before a session exists and
//! are sent when it starts), the last registers, the disassembly around the program counter, a
//! hex dump and the program's output. Every action is one command and its reply is applied on
//! the next frame; nothing here blocks.

use std::collections::BTreeSet;

use kraken_proto::{Hex64, Untrusted};
use serde::Deserialize;
use serde_json::json;

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// Bytes per row of the memory dump.
pub const MEM_ROW: usize = 8;
/// Rows of the memory dump.
pub const MEM_ROWS: usize = 16;
/// Instructions shown in the disassembly.
pub const DISASM_ROWS: usize = 24;
/// Most characters of program output kept.
const OUTPUT_KEEP: usize = 20_000;
/// A stop this close to a known function is in the program's own image, so the Listing follows
/// it (the loader and libc are far away).
const SAME_IMAGE: u64 = 16 << 20;

/// How the program is moved on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugStep {
    /// One instruction, entering calls.
    Into,
    /// One instruction, running a call to its return.
    Over,
    /// Until the current function returns.
    Out,
    /// To the next breakpoint or the end.
    Continue,
}

impl DebugStep {
    fn command(self) -> &'static str {
        match self {
            DebugStep::Into => "debug_step",
            DebugStep::Over => "debug_step_over",
            DebugStep::Out => "debug_step_out",
            DebugStep::Continue => "debug_continue",
        }
    }
}

/// One register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegItem {
    /// Name.
    pub name: String,
    /// Value (the emulator's).
    pub value: u64,
    /// It changed since the previous stop.
    pub changed: bool,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsnItem {
    /// Listing address.
    pub address: u64,
    /// Bytes as hex.
    pub bytes: String,
    /// Disassembly.
    pub text: String,
    /// The program counter is here.
    pub is_pc: bool,
}

/// What the memory dump shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemTarget {
    /// The stack pointer.
    Stack,
    /// A listing address.
    Listing(u64),
    /// An emulator address (a pointer taken from a register).
    Emulator(u64),
}

/// The memory dump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemDump {
    /// First address as given to the command.
    pub address: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Why the read failed (unmapped memory).
    pub error: Option<String>,
}

/// The GDB remote server of a session (`debug_gdb_serve`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GdbAttach {
    /// The Unix socket.
    pub socket: String,
    /// The loopback TCP port.
    pub tcp_port: Option<u16>,
    /// gdb command for the socket (needs `socat`).
    pub gdb_command: String,
    /// gdb command for the TCP port.
    pub gdb_tcp_command: Option<String>,
}

/// State of the Debug tab.
#[derive(Debug, Clone)]
pub struct DebugPanel {
    /// The open session.
    pub session: Option<u64>,
    /// `debug_start` is running.
    pub starting: bool,
    /// A step or run is in flight.
    pub busy: bool,
    /// Why the last command failed.
    pub error: Option<String>,
    /// Architecture of the session.
    pub arch: String,
    /// Program counter (listing address).
    pub pc: u64,
    /// Instructions executed.
    pub instructions: u64,
    /// One line on how the program last stopped.
    pub status: String,
    /// The program has ended.
    pub finished: bool,
    /// Registers.
    pub regs: Vec<RegItem>,
    /// Disassembly from the program counter.
    pub disasm: Vec<InsnItem>,
    /// What the memory view follows.
    pub mem_target: MemTarget,
    /// The memory dump.
    pub memory: MemDump,
    /// The address field of the memory view.
    pub mem_input: String,
    /// Breakpoints (listing addresses), kept across sessions.
    pub breakpoints: BTreeSet<u64>,
    /// Standard output so far.
    pub stdout: String,
    /// Standard error so far.
    pub stderr: String,
    /// Arguments for the next start, split on spaces.
    pub argv: String,
    /// Standard input for the next start.
    pub stdin: String,
    /// Debug with the staged byte patches applied.
    pub patched: bool,
    /// The Listing follows the program counter.
    pub follow_listing: bool,
    /// Facts from `debug_start`.
    pub notes: Vec<String>,
    /// How to attach gdb, once `debug_gdb_serve` has answered.
    pub gdb: Option<GdbAttach>,
    generation: u64,
    break_pending: u32,
    queued: Option<DebugStep>,
}

impl Default for DebugPanel {
    fn default() -> Self {
        DebugPanel {
            session: None,
            starting: false,
            busy: false,
            error: None,
            arch: String::new(),
            pc: 0,
            instructions: 0,
            status: String::new(),
            finished: false,
            regs: Vec::new(),
            disasm: Vec::new(),
            mem_target: MemTarget::Stack,
            memory: MemDump::default(),
            mem_input: String::new(),
            breakpoints: BTreeSet::new(),
            stdout: String::new(),
            stderr: String::new(),
            argv: String::new(),
            stdin: String::new(),
            patched: false,
            follow_listing: true,
            notes: Vec::new(),
            gdb: None,
            generation: 0,
            break_pending: 0,
            queued: None,
        }
    }
}

impl DebugPanel {
    /// A session is open (the program may have ended).
    pub fn active(&self) -> bool {
        self.session.is_some()
    }

    /// The program can be moved on.
    pub fn can_step(&self) -> bool {
        self.session.is_some() && !self.busy && !self.finished
    }

    /// Whether there is a breakpoint at `addr`.
    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains(&addr)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn set_generation(&mut self, g: u64) {
        self.generation = g;
    }

    fn reset_session(&mut self) {
        self.session = None;
        self.busy = false;
        self.finished = false;
        self.regs.clear();
        self.disasm.clear();
        self.memory = MemDump::default();
        self.status.clear();
        self.gdb = None;
        self.instructions = 0;
        self.generation += 1;
        self.break_pending = 0;
        self.queued = None;
    }
}

#[derive(Debug, Deserialize)]
struct StartWire {
    session: u64,
    arch: String,
    pc: Hex64,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExitWire {
    kind: String,
    value: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct StopWire {
    kind: String,
    pc: Hex64,
    detail: Option<String>,
    exit: Option<ExitWire>,
}

#[derive(Debug, Deserialize)]
struct RunWire {
    stop: StopWire,
    instructions: u64,
    stdout_new: Untrusted<String>,
    stderr_new: Untrusted<String>,
}

#[derive(Debug, Deserialize)]
struct RegWire {
    name: String,
    value: Hex64,
}

#[derive(Debug, Deserialize)]
struct RegsWire {
    pc: Hex64,
    registers: Vec<RegWire>,
}

#[derive(Debug, Deserialize)]
struct InsnWire {
    address: Hex64,
    bytes: String,
    text: String,
    is_pc: bool,
}

#[derive(Debug, Deserialize)]
struct DisasmWire {
    instructions: Vec<InsnWire>,
}

#[derive(Debug, Deserialize)]
struct MemWire {
    hex: String,
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn describe(stop: &StopWire) -> String {
    match stop.kind.as_str() {
        "stepped" => format!("Stopped at {}", hex(stop.pc.0)),
        "breakpoint" => format!("Hit a breakpoint at {}", hex(stop.pc.0)),
        "reached" => format!("Reached {}", hex(stop.pc.0)),
        "returned" => format!("Returned to {}", hex(stop.pc.0)),
        "budget" => "Paused: the instruction budget ran out".into(),
        "interrupted" => "Paused: the time limit of this command ran out".into(),
        "import" => format!(
            "Stopped at the import {}",
            stop.detail.as_deref().unwrap_or("?")
        ),
        "fault" => format!(
            "Crashed at {}: {}",
            hex(stop.pc.0),
            stop.detail.as_deref().unwrap_or("fault")
        ),
        "exited" => match &stop.exit {
            Some(e) if e.kind == "code" => {
                format!("The program exited with code {}", e.value.unwrap_or(0))
            }
            Some(e) if e.kind == "signal" => {
                format!("The program was killed by signal {}", e.value.unwrap_or(0))
            }
            Some(e) => format!("The program ended ({})", e.kind),
            None => "The program ended".into(),
        },
        other => other.to_string(),
    }
}

fn keep_tail(s: &mut String) {
    let n = s.chars().count();
    if n > OUTPUT_KEEP {
        *s = s.chars().skip(n - OUTPUT_KEEP).collect();
    }
}

impl ViewModel {
    /// Starts a session on the emulator, stopped before the first instruction, and sends the
    /// breakpoints already chosen.
    pub fn debug_start(&mut self) {
        if self.debug.session.is_some() || self.debug.starting {
            return;
        }
        let argv: Vec<String> = self
            .debug
            .argv
            .split_whitespace()
            .map(str::to_string)
            .collect();
        let mut stdin = self.debug.stdin.clone();
        if !stdin.is_empty() && !stdin.ends_with('\n') {
            stdin.push('\n');
        }
        let args = json!({"argv": argv, "stdin": stdin, "patched": self.debug.patched});
        self.debug.starting = true;
        self.debug.error = None;
        self.debug.stdout.clear();
        self.debug.stderr.clear();
        self.debug.generation += 1;
        let generation = self.debug.generation;
        self.call("debug_start", args, move |vm, res| {
            if vm.debug.generation != generation {
                return;
            }
            vm.debug.starting = false;
            match res.and_then(parse::<StartWire>) {
                Ok(w) => {
                    vm.debug.session = Some(w.session);
                    vm.debug.arch = w.arch;
                    vm.debug.pc = w.pc.0;
                    vm.debug.notes = w.notes;
                    vm.debug.finished = false;
                    vm.debug.status = format!("Ready at {}; nothing has run yet", hex(w.pc.0));
                    let stops: Vec<u64> = vm.debug.breakpoints.iter().copied().collect();
                    for a in stops {
                        vm.debug.break_pending += 1;
                        vm.call(
                            "debug_break_set",
                            json!({"session": w.session, "address": hex(a)}),
                            move |vm, _| vm.debug_break_landed(generation),
                        );
                    }
                    vm.debug_refresh();
                }
                Err(e) => vm.debug.error = Some(plain_error(&e)),
            }
        });
    }

    /// Moves the program on.
    pub fn debug_step(&mut self, how: DebugStep) {
        let Some(session) = self.debug.session.filter(|_| self.debug.can_step()) else {
            return;
        };
        if self.debug.break_pending > 0 {
            // A breakpoint change is still on its way to the emulator; run after it lands.
            self.debug.queued = Some(how);
            return;
        }
        self.debug.busy = true;
        self.debug.error = None;
        let generation = self.debug.generation;
        self.call(
            how.command(),
            json!({"session": session}),
            move |vm, res| {
                vm.debug_applied(generation, res);
            },
        );
    }

    /// Runs to `addr` (a listing address), stopping at breakpoints on the way.
    pub fn debug_run_to(&mut self, addr: u64) {
        let Some(session) = self.debug.session.filter(|_| self.debug.can_step()) else {
            return;
        };
        self.debug.busy = true;
        self.debug.error = None;
        let generation = self.debug.generation;
        self.call(
            "debug_run_to",
            json!({"session": session, "address": hex(addr)}),
            move |vm, res| vm.debug_applied(generation, res),
        );
    }

    /// Runs to the function `main` of the program (by its symbol; a stripped program has none and
    /// the error says so).
    pub fn debug_run_to_main(&mut self) {
        let Some(session) = self.debug.session.filter(|_| self.debug.can_step()) else {
            return;
        };
        self.debug.busy = true;
        self.debug.error = None;
        let generation = self.debug.generation;
        self.call(
            "debug_run_to",
            json!({"session": session, "symbol": "main"}),
            move |vm, res| vm.debug_applied(generation, res),
        );
    }

    fn debug_applied(
        &mut self,
        generation: u64,
        res: Result<serde_json::Value, kraken_proto::ProtoError>,
    ) {
        if self.debug.generation != generation {
            return;
        }
        self.debug.busy = false;
        match res.and_then(parse::<RunWire>) {
            Ok(w) => {
                self.debug.pc = w.stop.pc.0;
                self.debug.instructions = w.instructions;
                self.debug.status = describe(&w.stop);
                self.debug.finished = w.stop.kind == "exited";
                self.debug.stdout.push_str(&w.stdout_new.0);
                self.debug.stderr.push_str(&w.stderr_new.0);
                keep_tail(&mut self.debug.stdout);
                keep_tail(&mut self.debug.stderr);
                if self.debug.follow_listing
                    && self
                        .functions
                        .items
                        .iter()
                        .any(|f| f.address.abs_diff(w.stop.pc.0) < SAME_IMAGE)
                    && !self.debug.finished
                {
                    self.navigate_to(w.stop.pc.0);
                }
                self.debug_refresh();
            }
            Err(e) => {
                self.debug.error = Some(plain_error(&e));
                if e.code == kraken_proto::ErrorCode::NotFound {
                    self.debug.reset_session();
                }
            }
        }
    }

    /// Reloads the registers, the disassembly and the memory dump.
    pub fn debug_refresh(&mut self) {
        let Some(session) = self.debug.session else {
            return;
        };
        let generation = self.debug.generation;
        self.call("debug_regs", json!({"session": session}), move |vm, res| {
            if vm.debug.generation != generation {
                return;
            }
            if let Ok(w) = res.and_then(parse::<RegsWire>) {
                let old = std::mem::take(&mut vm.debug.regs);
                vm.debug.pc = w.pc.0;
                vm.debug.regs = w
                    .registers
                    .into_iter()
                    .map(|r| {
                        let changed = old
                            .iter()
                            .find(|o| o.name == r.name)
                            .is_some_and(|o| o.value != r.value.0);
                        RegItem {
                            name: r.name,
                            value: r.value.0,
                            changed,
                        }
                    })
                    .collect();
                if vm.debug.mem_target == MemTarget::Stack {
                    vm.debug_load_memory();
                }
            }
        });
        self.call(
            "debug_disasm",
            json!({"session": session, "count": DISASM_ROWS}),
            move |vm, res| {
                if vm.debug.generation != generation {
                    return;
                }
                if let Ok(w) = res.and_then(parse::<DisasmWire>) {
                    vm.debug.disasm = w
                        .instructions
                        .into_iter()
                        .map(|i| InsnItem {
                            address: i.address.0,
                            bytes: i.bytes,
                            text: i.text,
                            is_pc: i.is_pc,
                        })
                        .collect();
                }
            },
        );
        if self.debug.mem_target != MemTarget::Stack {
            self.debug_load_memory();
        }
    }

    fn stack_pointer(&self) -> Option<u64> {
        self.debug
            .regs
            .iter()
            .find(|r| matches!(r.name.to_ascii_lowercase().as_str(), "rsp" | "esp" | "sp"))
            .map(|r| r.value)
    }

    fn debug_load_memory(&mut self) {
        let Some(session) = self.debug.session else {
            return;
        };
        let (address, emulator) = match self.debug.mem_target.clone() {
            MemTarget::Stack => match self.stack_pointer() {
                Some(sp) => (sp, true),
                None => return,
            },
            MemTarget::Listing(a) => (a, false),
            MemTarget::Emulator(a) => (a, true),
        };
        let generation = self.debug.generation;
        self.call(
            "debug_mem_read",
            json!({
                "session": session,
                "address": hex(address),
                "length": MEM_ROW * MEM_ROWS,
                "emulator_address": emulator,
            }),
            move |vm, res| {
                if vm.debug.generation != generation {
                    return;
                }
                vm.debug.memory = match res.and_then(parse::<MemWire>) {
                    Ok(w) => MemDump {
                        address,
                        bytes: decode_hex(&w.hex),
                        error: None,
                    },
                    Err(e) => MemDump {
                        address,
                        bytes: Vec::new(),
                        error: Some(plain_error(&e)),
                    },
                };
            },
        );
    }

    /// Points the memory dump at what the person typed (a hex listing address); empty follows
    /// the stack pointer.
    pub fn debug_set_memory_input(&mut self) {
        let text = self.debug.mem_input.trim().to_string();
        if text.is_empty() {
            self.debug.mem_target = MemTarget::Stack;
        } else {
            let t = text.trim_start_matches("0x").trim_start_matches("0X");
            match u64::from_str_radix(t, 16) {
                Ok(a) => self.debug.mem_target = MemTarget::Listing(a),
                Err(_) => {
                    self.debug.error = Some("Type the address in hex, like 0x401000.".into());
                    return;
                }
            }
        }
        self.debug_load_memory();
    }

    /// Shows the memory a register value points at.
    pub fn debug_view_pointer(&mut self, value: u64) {
        self.debug.mem_input = hex(value);
        self.debug.mem_target = MemTarget::Emulator(value);
        self.debug_load_memory();
    }

    /// Sets or clears a breakpoint at a listing address; with a session open it takes effect
    /// at once.
    pub fn debug_toggle_breakpoint(&mut self, addr: u64) {
        let add = self.debug.breakpoints.insert(addr);
        if !add {
            self.debug.breakpoints.remove(&addr);
        }
        if let Some(session) = self.debug.session {
            let cmd = if add {
                "debug_break_set"
            } else {
                "debug_break_remove"
            };
            self.debug.break_pending += 1;
            let generation = self.debug.generation;
            self.call(
                cmd,
                json!({"session": session, "address": hex(addr)}),
                move |vm, _| vm.debug_break_landed(generation),
            );
        }
    }

    fn debug_break_landed(&mut self, generation: u64) {
        if self.debug.generation != generation {
            return;
        }
        self.debug.break_pending = self.debug.break_pending.saturating_sub(1);
        if self.debug.break_pending == 0
            && let Some(how) = self.debug.queued.take()
        {
            self.debug_step(how);
        }
    }

    /// Ends the session.
    pub fn debug_stop(&mut self) {
        let Some(session) = self.debug.session else {
            return;
        };
        self.debug.reset_session();
        self.debug.status = "Debugging ended".into();
        self.call("debug_stop", json!({"session": session}), |vm, res| {
            if let Err(e) = res {
                vm.toast(ToastLevel::Warning, plain_error(&e));
            }
        });
    }

    /// Starts serving the session to gdb and keeps the answer for the Debug tab to show.
    pub fn debug_gdb_serve(&mut self) {
        let Some(session) = self.debug.session else {
            return;
        };
        self.call(
            "debug_gdb_serve",
            json!({"session": session, "tcp": true}),
            move |vm, res| match res.and_then(parse::<GdbAttach>) {
                Ok(g) if vm.debug.session == Some(session) => vm.debug.gdb = Some(g),
                Ok(_) => {}
                Err(e) => vm.toast(ToastLevel::Warning, plain_error(&e)),
            },
        );
    }

    /// Shows the Debug tab.
    pub fn show_debug(&mut self) {
        self.tools.request_tab(crate::navtools::NavTab::Debug);
    }
}

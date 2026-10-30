//! The GDB Remote Serial Protocol in front of a debug session: [`serve_connection`] lets gdb (or
//! anything that speaks RSP: Ghidra's debugger, IDA, lldb's `gdb-remote`) read and write the
//! registers and memory of the emulated program, set breakpoints, step and continue.
//!
//! The target talks to the session through a [`DebugLink`], the same requests the `debug_*`
//! commands use. Addresses are the emulator's own (for a position-independent program they differ
//! from the listing's by the session's `address_delta`). Each architecture has a generated target
//! description with the registers gdb needs; registers the emulator does not model read as zero.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;

use gdbstub::common::Signal;
use gdbstub::conn::{Connection, ConnectionExt};
use gdbstub::stub::run_blocking::{BlockingEventLoop, Event, WaitForStopReasonError};
use gdbstub::stub::{DisconnectReason, GdbStub, SingleThreadStopReason};
use gdbstub::target::ext::base::BaseOps;
use gdbstub::target::ext::base::singlethread::{
    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps, SingleThreadSingleStep,
    SingleThreadSingleStepOps,
};
use gdbstub::target::ext::breakpoints::{
    Breakpoints, BreakpointsOps, SwBreakpoint, SwBreakpointOps,
};
use gdbstub::target::ext::target_description_xml_override::{
    TargetDescriptionXmlOverride, TargetDescriptionXmlOverrideOps,
};
use gdbstub::target::{Target, TargetError, TargetResult};

use crate::arch::Arch;
use crate::confined::{DebugChild, DebugReply, DebugRequest};
use crate::error::EmuError;
use crate::linux::Exit;
use crate::session::SessionStop;

/// The way the server reaches the session.
pub trait DebugLink {
    /// One request and its answer.
    fn request(&mut self, req: &DebugRequest) -> Result<DebugReply, EmuError>;
}

impl DebugLink for DebugChild {
    fn request(&mut self, req: &DebugRequest) -> Result<DebugReply, EmuError> {
        DebugChild::request(self, req)
    }
}

/// Where a register's value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Src {
    Reg(&'static str),
    Zero,
    Eflags,
    Cpsr,
}

#[derive(Debug, Clone)]
struct Slot {
    name: String,
    bytes: usize,
    src: Src,
    /// `type` attribute in the description.
    ty: &'static str,
}

fn slot(name: &str, bytes: usize, src: Src, ty: &'static str) -> Slot {
    Slot {
        name: name.to_string(),
        bytes,
        src,
        ty,
    }
}

const X86_FLAGS: [(&str, u32); 9] = [
    ("CF", 0),
    ("PF", 2),
    ("AF", 4),
    ("ZF", 6),
    ("SF", 7),
    ("TF", 8),
    ("IF", 9),
    ("DF", 10),
    ("OF", 11),
];
const ARM_FLAGS: [(&str, u32); 5] = [("NG", 31), ("ZR", 30), ("CY", 29), ("OV", 28), ("TB", 5)];

/// (gdb name, SLEIGH name, gdb type)
type RegRow = (&'static str, &'static str, &'static str);

const X86_64_REGS: [RegRow; 17] = [
    ("rax", "RAX", "int64"),
    ("rbx", "RBX", "int64"),
    ("rcx", "RCX", "int64"),
    ("rdx", "RDX", "int64"),
    ("rsi", "RSI", "int64"),
    ("rdi", "RDI", "int64"),
    ("rbp", "RBP", "data_ptr"),
    ("rsp", "RSP", "data_ptr"),
    ("r8", "R8", "int64"),
    ("r9", "R9", "int64"),
    ("r10", "R10", "int64"),
    ("r11", "R11", "int64"),
    ("r12", "R12", "int64"),
    ("r13", "R13", "int64"),
    ("r14", "R14", "int64"),
    ("r15", "R15", "int64"),
    ("rip", "RIP", "code_ptr"),
];

const X86_REGS: [RegRow; 9] = [
    ("eax", "EAX", "int32"),
    ("ecx", "ECX", "int32"),
    ("edx", "EDX", "int32"),
    ("ebx", "EBX", "int32"),
    ("esp", "ESP", "data_ptr"),
    ("ebp", "EBP", "data_ptr"),
    ("esi", "ESI", "int32"),
    ("edi", "EDI", "int32"),
    ("eip", "EIP", "code_ptr"),
];

fn x86_layout(rows: &[RegRow], width: usize) -> Vec<Slot> {
    let mut v: Vec<Slot> = rows
        .iter()
        .map(|(g, e, t)| slot(g, width, Src::Reg(e), t))
        .collect();
    v.push(slot("eflags", 4, Src::Eflags, "i386_eflags"));
    for (g, e) in [
        ("cs", "CS"),
        ("ss", "SS"),
        ("ds", "DS"),
        ("es", "ES"),
        ("fs", "FS"),
        ("gs", "GS"),
    ] {
        v.push(slot(g, 4, Src::Reg(e), "int32"));
    }
    for i in 0..8 {
        v.push(slot(&format!("st{i}"), 10, Src::Zero, "i387_ext"));
    }
    for g in [
        "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
    ] {
        v.push(slot(g, 4, Src::Zero, "int"));
    }
    v
}

fn plain(names: &[&'static str], bytes: usize, ty: &'static str) -> Vec<Slot> {
    names
        .iter()
        .map(|n| slot(n, bytes, Src::Reg(n), ty))
        .collect()
}

fn layout(arch: Arch) -> Vec<Slot> {
    match arch {
        Arch::X86_64 => x86_layout(&X86_64_REGS, 8),
        Arch::X86 => x86_layout(&X86_REGS, 4),
        Arch::Aarch64 => {
            const X: [&str; 31] = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28", "x29", "x30",
            ];
            let mut v = plain(&X, 8, "int");
            v.push(slot("sp", 8, Src::Reg("sp"), "data_ptr"));
            v.push(slot("pc", 8, Src::Reg("pc"), "code_ptr"));
            v.push(slot("cpsr", 4, Src::Cpsr, "int"));
            v
        }
        Arch::Arm => {
            const R: [&str; 13] = [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
            ];
            let mut v = plain(&R, 4, "uint32");
            v.push(slot("sp", 4, Src::Reg("sp"), "data_ptr"));
            v.push(slot("lr", 4, Src::Reg("lr"), "int"));
            v.push(slot("pc", 4, Src::Reg("pc"), "code_ptr"));
            // The legacy FPA registers gdb still reserves between pc and cpsr.
            v.push(slot("padding", 100, Src::Zero, "padding"));
            v.push(slot("cpsr", 4, Src::Cpsr, "int"));
            v
        }
        Arch::Riscv32 | Arch::Riscv64 => {
            let w = arch.ptr_size();
            let mut v = vec![slot("zero", w, Src::Zero, "int")];
            const R: [&str; 31] = [
                "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
                "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
                "t3", "t4", "t5", "t6",
            ];
            for n in R {
                let ty = match n {
                    "sp" => "data_ptr",
                    "ra" => "code_ptr",
                    _ => "int",
                };
                v.push(slot(n, w, Src::Reg(n), ty));
            }
            v.push(slot("pc", w, Src::Reg("pc"), "code_ptr"));
            v
        }
    }
}

fn target_xml(arch: Arch, slots: &[Slot]) -> String {
    let (gdb_arch, feature) = match arch {
        Arch::X86_64 => ("i386:x86-64", "org.gnu.gdb.i386.core"),
        Arch::X86 => ("i386", "org.gnu.gdb.i386.core"),
        Arch::Aarch64 => ("aarch64", "org.gnu.gdb.aarch64.core"),
        Arch::Arm => ("arm", "org.gnu.gdb.arm.core"),
        Arch::Riscv32 => ("riscv:rv32", "org.gnu.gdb.riscv.cpu"),
        Arch::Riscv64 => ("riscv:rv64", "org.gnu.gdb.riscv.cpu"),
    };
    let mut x = String::from(
        "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n<target version=\"1.0\">\n",
    );
    let _ = writeln!(x, "<architecture>{gdb_arch}</architecture>");
    let _ = writeln!(x, "<feature name=\"{feature}\">");
    if slots.iter().any(|s| s.ty == "i386_eflags") {
        x.push_str(EFLAGS_XML);
    }
    let mut regnum = 0;
    for s in slots {
        if s.ty == "padding" {
            let _ = writeln!(x, "<reg name=\"padding\" bitsize=\"32\" type=\"padding\"/>");
            regnum += s.bytes / 4;
            continue;
        }
        let group = if s.ty == "i387_ext" || (s.ty == "int" && s.name.starts_with('f')) {
            " group=\"float\""
        } else {
            ""
        };
        let _ = writeln!(
            x,
            "<reg name=\"{}\" bitsize=\"{}\" type=\"{}\" regnum=\"{}\"{group}/>",
            s.name,
            s.bytes * 8,
            s.ty,
            regnum
        );
        regnum += 1;
    }
    x.push_str("</feature>\n</target>\n");
    x
}

const EFLAGS_XML: &str = "<flags id=\"i386_eflags\" size=\"4\">\n\
<field name=\"\" start=\"22\" end=\"31\"/>\n\
<field name=\"CF\" start=\"0\" end=\"0\"/>\n<field name=\"\" start=\"1\" end=\"1\"/>\n\
<field name=\"PF\" start=\"2\" end=\"2\"/>\n<field name=\"AF\" start=\"4\" end=\"4\"/>\n\
<field name=\"ZF\" start=\"6\" end=\"6\"/>\n<field name=\"SF\" start=\"7\" end=\"7\"/>\n\
<field name=\"TF\" start=\"8\" end=\"8\"/>\n<field name=\"IF\" start=\"9\" end=\"9\"/>\n\
<field name=\"DF\" start=\"10\" end=\"10\"/>\n<field name=\"OF\" start=\"11\" end=\"11\"/>\n\
<field name=\"NT\" start=\"14\" end=\"14\"/>\n<field name=\"RF\" start=\"16\" end=\"16\"/>\n\
<field name=\"VM\" start=\"17\" end=\"17\"/>\n<field name=\"AC\" start=\"18\" end=\"18\"/>\n\
<field name=\"VIF\" start=\"19\" end=\"19\"/>\n<field name=\"VIP\" start=\"20\" end=\"20\"/>\n\
<field name=\"ID\" start=\"21\" end=\"21\"/>\n</flags>\n";

/// The register block of a `g` packet.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RegBlock {
    pc: u64,
    bytes: Vec<u8>,
}

impl gdbstub::arch::Registers for RegBlock {
    type ProgramCounter = u64;
    fn pc(&self) -> u64 {
        self.pc
    }
    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        for b in &self.bytes {
            write_byte(Some(*b));
        }
    }
    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.bytes = bytes.to_vec();
        Ok(())
    }
}

/// The architecture to gdbstub: registers are a byte block laid out by the target description.
#[derive(Debug)]
pub enum DynArch {}

impl gdbstub::arch::Arch for DynArch {
    type Usize = u64;
    type Registers = RegBlock;
    type BreakpointKind = usize;
    type RegId = ();
}

/// A debug session seen as a gdb target.
pub struct GdbTarget<L: DebugLink> {
    link: L,
    slots: Vec<Slot>,
    xml: String,
    stepping: bool,
}

impl<L: DebugLink> GdbTarget<L> {
    /// A target for a session of `arch`.
    pub fn new(link: L, arch: Arch) -> GdbTarget<L> {
        let slots = layout(arch);
        let xml = target_xml(arch, &slots);
        GdbTarget {
            link,
            slots,
            xml,
            stepping: false,
        }
    }

    /// The target description gdb is sent.
    pub fn description(&self) -> &str {
        &self.xml
    }

    fn ask(&mut self, req: DebugRequest) -> Result<DebugReply, String> {
        self.link.request(&req).map_err(|e| e.to_string())
    }

    fn wanted(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for s in &self.slots {
            match &s.src {
                Src::Reg(n) => names.push((*n).to_string()),
                Src::Eflags => names.extend(X86_FLAGS.iter().map(|(n, _)| (*n).to_string())),
                Src::Cpsr => names.extend(ARM_FLAGS.iter().map(|(n, _)| (*n).to_string())),
                Src::Zero => {}
            }
        }
        names
    }

    fn read_map(&mut self) -> Result<HashMap<String, u64>, String> {
        let names = self.wanted();
        match self.ask(DebugRequest::ReadRegs { names })? {
            DebugReply::Registers { regs } => Ok(regs.into_iter().collect()),
            _ => Err("unexpected reply to a register read".into()),
        }
    }

    fn pack(&self, map: &HashMap<String, u64>) -> RegBlock {
        let mut bytes = Vec::new();
        let flags = |table: &[(&str, u32)], base: u64| {
            table.iter().fold(base, |acc, (n, bit)| {
                acc | (map.get(*n).copied().unwrap_or(0) & 1) << bit
            })
        };
        let mut pc = 0;
        for s in &self.slots {
            let v = match &s.src {
                Src::Reg(n) => map.get(*n).copied().unwrap_or(0),
                Src::Zero => 0,
                Src::Eflags => flags(&X86_FLAGS, 2),
                Src::Cpsr => flags(&ARM_FLAGS, 0),
            };
            if matches!(s.name.as_str(), "rip" | "eip" | "pc") {
                pc = v;
            }
            let le = v.to_le_bytes();
            bytes.extend((0..s.bytes).map(|i| le.get(i).copied().unwrap_or(0)));
        }
        RegBlock { pc, bytes }
    }

    /// The stop to report for a run request's end; `None` when the run only paused.
    fn after(stop: SessionStop) -> Option<SingleThreadStopReason<u64>> {
        Some(match stop {
            SessionStop::Stepped | SessionStop::Returned { .. } => SingleThreadStopReason::DoneStep,
            SessionStop::Breakpoint { .. } | SessionStop::Reached { .. } => {
                SingleThreadStopReason::SwBreak(())
            }
            SessionStop::Exited { exit } => match exit {
                Exit::Code { code } => SingleThreadStopReason::Exited((code & 0xff) as u8),
                Exit::Signal { signal, .. } => SingleThreadStopReason::Terminated(
                    u8::try_from(signal).map_or(Signal::SIGABRT, Signal),
                ),
                _ => SingleThreadStopReason::Terminated(Signal::SIGKILL),
            },
            SessionStop::Fault { .. } => SingleThreadStopReason::Signal(Signal::SIGSEGV),
            SessionStop::Import { .. } => SingleThreadStopReason::Signal(Signal::SIGTRAP),
            SessionStop::Budget | SessionStop::Interrupted => return None,
        })
    }
}

impl<L: DebugLink> Target for GdbTarget<L> {
    type Arch = DynArch;
    type Error = String;

    #[inline(always)]
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::SingleThread(self)
    }

    #[inline(always)]
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }

    #[inline(always)]
    fn support_target_description_xml_override(
        &mut self,
    ) -> Option<TargetDescriptionXmlOverrideOps<'_, Self>> {
        Some(self)
    }

    fn guard_rail_implicit_sw_breakpoints(&self) -> bool {
        true
    }
}

impl<L: DebugLink> TargetDescriptionXmlOverride for GdbTarget<L> {
    fn target_description_xml(
        &self,
        annex: &[u8],
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        if annex != b"target.xml" {
            return Err(TargetError::NonFatal);
        }
        let xml = self.xml.as_bytes();
        let start = (offset as usize).min(xml.len());
        let end = (start + length).min(xml.len()).min(start + buf.len());
        buf[..end - start].copy_from_slice(&xml[start..end]);
        Ok(end - start)
    }
}

impl<L: DebugLink> SingleThreadBase for GdbTarget<L> {
    fn read_registers(&mut self, regs: &mut RegBlock) -> TargetResult<(), Self> {
        let map = self.read_map().map_err(TargetError::Fatal)?;
        *regs = self.pack(&map);
        Ok(())
    }

    fn write_registers(&mut self, regs: &RegBlock) -> TargetResult<(), Self> {
        let map = self.read_map().map_err(TargetError::Fatal)?;
        let mut at = 0;
        let mut changes = Vec::new();
        for s in &self.slots {
            let Some(raw) = regs.bytes.get(at..at + s.bytes) else {
                return Err(TargetError::NonFatal);
            };
            at += s.bytes;
            if let Src::Reg(n) = &s.src {
                let mut buf = [0u8; 8];
                let k = s.bytes.min(8);
                buf[..k].copy_from_slice(&raw[..k]);
                let v = u64::from_le_bytes(buf);
                if map.get(*n) != Some(&v) {
                    changes.push(((*n).to_string(), v));
                }
            }
        }
        for (name, value) in changes {
            self.ask(DebugRequest::WriteReg { name, value })
                .map_err(TargetError::Fatal)?;
        }
        Ok(())
    }

    fn read_addrs(&mut self, start_addr: u64, data: &mut [u8]) -> TargetResult<usize, Self> {
        match self.link.request(&DebugRequest::ReadMemory {
            addr: start_addr,
            len: data.len(),
        }) {
            Ok(DebugReply::Bytes { bytes }) => {
                let n = bytes.len().min(data.len());
                data[..n].copy_from_slice(&bytes[..n]);
                Ok(n)
            }
            Ok(_) => Err(TargetError::NonFatal),
            Err(EmuError::Io(e)) => Err(TargetError::Fatal(e)),
            Err(_) => Err(TargetError::Errno(14)),
        }
    }

    fn write_addrs(&mut self, start_addr: u64, data: &[u8]) -> TargetResult<(), Self> {
        match self.link.request(&DebugRequest::WriteMemory {
            addr: start_addr,
            data: data.to_vec(),
        }) {
            Ok(_) => Ok(()),
            Err(EmuError::Io(e)) => Err(TargetError::Fatal(e)),
            Err(_) => Err(TargetError::Errno(14)),
        }
    }

    #[inline(always)]
    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<L: DebugLink> SingleThreadResume for GdbTarget<L> {
    fn resume(&mut self, _signal: Option<Signal>) -> Result<(), String> {
        self.stepping = false;
        Ok(())
    }

    #[inline(always)]
    fn support_single_step(&mut self) -> Option<SingleThreadSingleStepOps<'_, Self>> {
        Some(self)
    }
}

impl<L: DebugLink> SingleThreadSingleStep for GdbTarget<L> {
    fn step(&mut self, _signal: Option<Signal>) -> Result<(), String> {
        self.stepping = true;
        Ok(())
    }
}

impl<L: DebugLink> Breakpoints for GdbTarget<L> {
    #[inline(always)]
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        Some(self)
    }
}

impl<L: DebugLink> SwBreakpoint for GdbTarget<L> {
    fn add_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        self.ask(DebugRequest::AddBreakpoint { addr })
            .map(|_| true)
            .map_err(TargetError::Fatal)
    }

    fn remove_sw_breakpoint(&mut self, addr: u64, _kind: usize) -> TargetResult<bool, Self> {
        match self.ask(DebugRequest::RemoveBreakpoint { addr }) {
            Ok(DebugReply::Changed { changed }) => Ok(changed),
            Ok(_) => Ok(false),
            Err(e) => Err(TargetError::Fatal(e)),
        }
    }
}

/// Instructions per run request: the connection is looked at between slices, so this is also
/// how long a Ctrl-C in gdb can wait. (Slicing by the wall clock would interrupt the guest in the
/// middle of a block, which the emulator does not resume from reliably.)
const RUN_BUDGET: u64 = 5_000_000;
/// The wall-clock safety net of one slice, in milliseconds.
const SLICE_MS: u64 = 120_000;

type Conn = Box<dyn ConnectionExt<Error = io::Error>>;

enum Loop<L> {
    _Never(std::marker::PhantomData<L>, std::convert::Infallible),
}

impl<L: DebugLink> BlockingEventLoop for Loop<L> {
    type Target = GdbTarget<L>;
    type Connection = Conn;
    type StopReason = SingleThreadStopReason<u64>;

    fn wait_for_stop_reason(
        target: &mut GdbTarget<L>,
        conn: &mut Conn,
    ) -> Result<
        Event<SingleThreadStopReason<u64>>,
        WaitForStopReasonError<String, <Conn as Connection>::Error>,
    > {
        loop {
            let req = if target.stepping {
                DebugRequest::Step {
                    n: 1,
                    wall_ms: 5_000,
                }
            } else {
                DebugRequest::Run {
                    budget: RUN_BUDGET,
                    wall_ms: SLICE_MS,
                }
            };
            let reply = target.ask(req).map_err(WaitForStopReasonError::Target)?;
            let DebugReply::Stop { stop, .. } = reply else {
                return Err(WaitForStopReasonError::Target(
                    "unexpected reply to a run request".into(),
                ));
            };
            if let Some(reason) = GdbTarget::<L>::after(stop) {
                return Ok(Event::TargetStopped(reason));
            }
            if conn
                .peek()
                .map_err(WaitForStopReasonError::Connection)?
                .is_some()
            {
                let b = conn.read().map_err(WaitForStopReasonError::Connection)?;
                return Ok(Event::IncomingData(b));
            }
        }
    }

    fn on_interrupt(
        _target: &mut GdbTarget<L>,
    ) -> Result<Option<SingleThreadStopReason<u64>>, String> {
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}

/// How a connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The client disconnected or detached; the session stays where it is.
    Detached,
    /// The client killed the program.
    Killed,
    /// The program ended.
    ProgramEnded,
}

/// Serves one gdb connection until it ends.
pub fn serve_connection<L: DebugLink>(
    link: L,
    arch: Arch,
    conn: Box<dyn ConnectionExt<Error = io::Error>>,
) -> Result<Ended, String> {
    let mut target = GdbTarget::new(link, arch);
    match GdbStub::new(conn).run_blocking::<Loop<L>>(&mut target) {
        Ok(DisconnectReason::Disconnect) => Ok(Ended::Detached),
        Ok(DisconnectReason::Kill) => Ok(Ended::Killed),
        Ok(DisconnectReason::TargetExited(_) | DisconnectReason::TargetTerminated(_)) => {
            Ok(Ended::ProgramEnded)
        }
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_architecture_has_a_description_and_a_consistent_layout() {
        for arch in Arch::ALL {
            let slots = layout(arch);
            let xml = target_xml(arch, &slots);
            assert!(xml.contains("<architecture>"), "{arch:?}");
            let regs = slots.iter().filter(|s| s.ty != "padding").count();
            let pads = slots.len() - regs;
            assert_eq!(xml.matches("<reg ").count(), regs + pads, "{arch:?}");
            let total: usize = slots.iter().map(|s| s.bytes).sum();
            assert!(total >= arch.ptr_size() * 16, "{arch:?}");
        }
    }
}

//! KRAKEN's emulation layer: run code of x86, x86-64, ARM (A32 and Thumb-2), AArch64, RISC-V 32
//! and RISC-V 64 on an x86-64 host.
//!
//! The CPU is icicle-emu's SLEIGH p-code interpreter (`MIT OR Apache-2.0`, pinned by commit like
//! kraken-rewrite's), built from the same Ghidra processor specs engine-native reads
//! ([`specs`]). On top of it:
//!
//! * [`arch`]: which CPU a file or an engine language id is for, its SLEIGH language, registers
//!   for display, program counter, stack pointer, Thumb handling.
//! * [`machine`]: one CPU with memory, registers by name, disassembly, breakpoints, snapshots.
//! * [`call`]: function-level calls with each architecture's C calling convention (SysV x86-64,
//!   cdecl, AAPCS hard-float, AAPCS64, RISC-V lp64d/ilp32): integer, pointer, `float` and
//!   `double` arguments and results, stack arguments, a return trap, an instruction budget.
//! * [`linux`]: whole-program Linux user-mode runs of static or dynamic ELF files with KRAKEN's
//!   own system call layer (file access only inside a private directory and a read-only
//!   sysroot; deterministic time and randomness).
//! * [`session`]: the stepping API for a debugger: step, step over, run to a breakpoint, an
//!   address, the return or the exit, registers, memory, disassembly, snapshots. Synchronous and
//!   `Send` (the emulator lives on its own thread).
//! * [`confined`]: the same whole-program run inside the sandbox child (`kraken-emu-run`), for
//!   the daemon.
//!
//! Guest code never runs natively: every instruction is interpreted, and the guest reaches the
//! host only through the system calls this crate answers itself.

pub mod arch;
pub mod call;
#[cfg(unix)]
pub mod confined;
pub mod error;
#[cfg(unix)]
pub mod gdbserve;
pub mod hostlibs;
pub mod linux;
pub mod loader;
pub mod machine;
mod neon;
pub mod session;
pub mod specs;
mod vfp;

pub use arch::Arch;
pub use call::{
    CallOutcome, CallSpec, CallTermination, Callee, FunctionCaller, RetKind, StartAt, Value,
};
pub use error::EmuError;
pub use linux::{Exit, ProgramOutcome, RunSpec, run_program};
pub use machine::{BlockLog, Machine, Perm, Stop};
pub use session::{Interrupter, Session, SessionStop, Target};
pub use specs::SpecRoots;

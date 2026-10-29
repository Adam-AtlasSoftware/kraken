//! KRAKEN's native (JVM-free) engine (ADR 0014), phases 1 to 3 and the mutator of phase 4.
//!
//! ELF images are loaded with the `object` crate, functions are discovered by recursive descent
//! over Sleigh flow information (with `.eh_frame` landing pads and noreturn propagation), and
//! Ghidra's C++ decompiler (built from source by `engine-native-sys`) runs in-process behind the
//! same capability traits as the Ghidra sidecar: loader, analyzer, function lister, decompiler,
//! disassembler, memory, cross-references, CFGs, strings, imports and exports, and a type store
//! whose definitions and library prototypes reach the decompiler. The mutator applies edit-log
//! operations (renames, labels, comments, prototypes, calling conventions, function create,
//! delete and bounds, code and data) to the open program; with a state directory
//! ([`NativeConfig::state_dir`]) the applied operations are saved there and replayed when the
//! same binary is opened again.
//!
//! By default the decompiler and the loaded program live in a confined worker process,
//! `kraken-native-worker`, under a watchdog that turns hangs and crashes into structured errors
//! and restarts the worker (see [`worker`]); [`Isolation::InProcess`] keeps them in-process.
//!
//! Only Sleigh specification files are read at run time (see [`NativeConfig`]): the ones
//! `cargo xtask native-sla` compiles from the pinned sources, or a Ghidra install's. No JVM is
//! involved.

mod analyze;
pub mod arm;
pub mod cfg;
pub mod constprop;
pub mod ctypes;
mod data;
pub mod debugfile;
pub mod demangle;
pub mod discover;
pub mod dwarf;
pub mod eh;
pub mod elf;
mod engine;
mod jumpcache;
pub mod libc;
pub mod listing;
mod mutate;
mod native;
pub mod objfile;
pub mod pe;
pub mod raw;
pub mod refs;
mod relocs;
pub mod strings;
pub mod symbols;
pub mod typestore;
pub mod win32;
pub mod worker;

pub use engine::{
    BUILD, DEFAULT_DECOMPILE_TIMEOUT, InProcessEngine, NativeConfig, NativeStats, SOURCE_TAG,
    compiled_specs_dir, has_specs,
};
pub use native::NativeEngine;
pub use worker::{Isolation, WorkerOptions};

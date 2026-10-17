//! KRAKEN's native (JVM-free) engine (ADR 0014), phases 1 to 3.
//!
//! ELF images are loaded with the `object` crate, functions are discovered by recursive descent
//! over Sleigh flow information (with `.eh_frame` landing pads and noreturn propagation), and
//! Ghidra's C++ decompiler (built from source by `engine-native-sys`) runs in-process behind the
//! same capability traits as the Ghidra sidecar: loader, analyzer, function lister, decompiler,
//! disassembler, memory, cross-references, CFGs, strings, imports and exports, and a type store
//! whose definitions and library prototypes reach the decompiler. Mutation is not provided yet.
//!
//! By default the decompiler and the loaded program live in a confined worker process,
//! `kraken-native-worker`, under a watchdog that turns hangs and crashes into structured errors
//! and restarts the worker (see [`worker`]); [`Isolation::InProcess`] keeps them in-process.
//!
//! Only Sleigh specification files are read at run time (see [`NativeConfig`]): the ones
//! `cargo xtask native-sla` compiles from the pinned sources, or a Ghidra install's. No JVM is
//! involved.

mod analyze;
pub mod cfg;
pub mod ctypes;
mod data;
pub mod discover;
pub mod eh;
pub mod elf;
mod engine;
pub mod libc;
pub mod listing;
mod native;
pub mod refs;
pub mod strings;
pub mod symbols;
pub mod typestore;
pub mod worker;

pub use engine::{
    BUILD, DEFAULT_DECOMPILE_TIMEOUT, InProcessEngine, NativeConfig, NativeStats, SOURCE_TAG,
    compiled_specs_dir, has_specs,
};
pub use native::NativeEngine;
pub use worker::{Isolation, WorkerOptions};

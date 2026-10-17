//! KRAKEN's native (JVM-free) engine, phase 1 (ADR 0014).
//!
//! ELF images are loaded with the `object` crate, functions are discovered by recursive descent
//! over Sleigh flow information, and Ghidra's C++ decompiler (built from source by
//! `engine-native-sys`) runs in-process behind the same capability traits as the Ghidra sidecar:
//! [`Loader`](kraken_engine::Loader), [`FunctionLister`](kraken_engine::FunctionLister),
//! [`Decompiler`](kraken_engine::Decompiler), [`Disassembler`](kraken_engine::Disassembler) and
//! [`MemoryReader`](kraken_engine::MemoryReader). Mutation, types, cross-references, CFGs,
//! strings and symbols are not provided yet, so those capabilities are absent.
//!
//! Only the Sleigh specifications of a Ghidra install are read at run time (see
//! [`NativeConfig`]); no JVM is involved.

pub mod discover;
pub mod elf;
mod engine;
pub mod listing;

pub use engine::{BUILD, NativeConfig, NativeEngine, has_specs};

//! KRAKEN rewrite pipeline spike (decisions 2, 46, 53): prove the core loop on single
//! functions. See `spikes/rewrite-loop/NOTES.md`.
//!
//! lift (KRAKEN decompile) -> translate ([`task::RewriteTask`]) -> differential test against the
//! original under emulation ([`oracle::FunctionOracle`], [`difftest`]) -> versioned record
//! ([`unit::RewriteUnit`]).

pub mod abi;
pub mod clib;
pub mod difftest;
pub mod error;
pub mod fetch;
pub mod native;
pub mod oracle;
pub mod pipeline;
pub mod sandbox;
pub mod targets;
pub mod task;
pub mod unit;

pub use error::RewriteError;

/// Identifies the emulator build in unit records.
pub const EMULATOR_PIN: &str = "icicle-emu@638508b72f480f9be6fe2e267ef09de8f1541f9a";
/// Oracle kind in unit records.
pub const ORACLE_KIND: &str = "icicle-emu/x86-64-sleigh";

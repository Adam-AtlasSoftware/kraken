//! KRAKEN rewrite pipeline core (decisions 2, 46, 53; ADR 0013).
//!
//! lift (KRAKEN decompile) -> translate ([`task::RewriteTask`], or reimplement from a cited spec,
//! [`task::SpecTask`]) -> differential test against the original under emulation
//! ([`oracle::FunctionOracle`], [`difftest`]) -> versioned record ([`unit::RewriteUnit`]) in
//! `<project>/rewrite.sqlite` ([`store::RewriteStore`]) -> accept (a user) -> export a Cargo
//! workspace with an FFI shim ([`export`]).
//!
//! The `rewrite_*` registry commands are defined in `kraken-registry`; [`service::RewriteService`]
//! is what runs them once attached with `Session::with_rewrite`. Generated code only ever runs
//! inside [`sandbox`]. The spike this grew from is described in `spikes/rewrite-loop/NOTES.md`.

pub mod abi;
pub mod clib;
pub mod collect;
pub mod difftest;
pub mod error;
pub mod export;
pub mod fetch;
pub mod infer;
pub mod lift;
pub mod lint;
pub mod native;
pub mod oracle;
pub mod pipeline;
pub mod plan;
pub mod sandbox;
pub mod service;
pub mod store;
pub mod targets;
pub mod task;
pub mod unit;

pub use error::RewriteError;
pub use service::{ConfigProvider, FixedProvider, ProviderSource, RewriteConfig, RewriteService};

/// Identifies the emulator build in unit records.
pub const EMULATOR_PIN: &str = "icicle-emu@638508b72f480f9be6fe2e267ef09de8f1541f9a";
/// Oracle kind in unit records.
pub const ORACLE_KIND: &str = "icicle-emu/x86-64-sleigh";

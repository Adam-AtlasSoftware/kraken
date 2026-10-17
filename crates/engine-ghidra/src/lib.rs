//! KRAKEN engine backed by a confined Ghidra JVM sidecar.
//!
//! [`GhidraEngine`] implements every `kraken-engine` capability trait. It talks to the
//! `kraken-ghidra` Java extension with length-prefixed JSON-RPC over one end of a Unix socketpair
//! that the child receives as stdin (decisions 9, 41, 87, 88). The pieces:
//!
//! - [`install`]: locating Ghidra, a JDK and the extension jar, restricted to tested versions.
//! - [`sandbox`]: the confined spawner (scrubbed environment, Landlock, network namespace,
//!   parent-death signal from a dedicated spawner thread).
//! - [`rpc`]: the multiplexing client (request ids, deadlines, notifications).
//! - [`supervisor`]: handshake, death detection, bounded restart and [`SidecarEvent`]s.
//! - [`engine`]: the trait implementations.
//!
//! Nothing is started until the first `open_binary`; the heap and the filesystem rules depend on
//! the binary, so opening a different binary starts a new sidecar.

pub mod config;
pub mod engine;
pub mod error;
pub mod install;
pub mod launch;

pub mod supervisor;

#[cfg(all(test, unix))]
mod tests;
#[cfg(all(test, unix))]
mod testutil;

pub use config::{Deadlines, EngineConfig, heap_mb};
pub use engine::GhidraEngine;
pub use error::GhidraError;
pub use install::{GhidraInstall, InstallConfig, TESTED_GHIDRA_VERSIONS};
pub use kraken_sidecar::{ConfinementOptions, ConfinementReport};
pub use kraken_sidecar::{LogSink, log, rpc, sandbox};
pub use launch::{GhidraLauncher, LaunchPlan, Launcher};
pub use supervisor::{Diagnostics, SidecarEvent};

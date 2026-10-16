//! `krakend`, the KRAKEN daemon.
//!
//! The daemon owns the project sessions and the Ghidra sidecars; the CLI, the MCP server and the
//! GUI are clients (decision 13). It serves the command registry over `kraken-ipc`:
//!
//! - [`handler`]: the RPC methods (`call`, `commands`, `status`, `events`, `shutdown`).
//! - [`host`]: sessions per canonical project directory, opened on demand, closed when idle,
//!   limited in number; one ordered write queue per session.
//! - [`events`]: the change event stream (`entry_applied`, `proposal_created`, `job_progress`,
//!   `job_done`, `sidecar_restarted`, ...) with catch-up by sequence number.
//! - [`daemon`]: start-up, idle exit, shutdown.
//! - [`logfile`]: the size-rotated `krakend.log` in the runtime directory.
//! - `fake` (feature `fake-engine`): a scripted engine for tests.

pub mod daemon;
pub mod events;
pub mod handler;
pub mod host;
pub mod logfile;

#[cfg(feature = "fake-engine")]
pub mod fake;

pub use daemon::{Daemon, DaemonError, DaemonOptions, start};
pub use events::EventHub;
pub use host::{HostConfig, SessionHost};

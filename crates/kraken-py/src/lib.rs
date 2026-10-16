//! Python bindings for KRAKEN.
//!
//! The Python package `kraken` (this crate's compiled half is `kraken._native`) gives scripts a
//! small, Pythonic API over the same command registry as the CLI, the MCP server and the GUI.
//! Commands run in `krakend` through [`kraken_host::backend::DaemonBackend`], or in this process
//! through [`kraken_host::backend::LocalBackend`] when the daemon is not wanted or not available.
//!
//! The crate is split so that everything except type conversion is plain Rust and testable
//! without an interpreter:
//!
//! - [`conn`]: connections, per-project handles, authors, the error-code to exception table.
//! - [`schema`]: argument validation against each command's JSON Schema.
//! - [`runtime`]: the single tokio runtime and interruptible blocking calls on it.
//! - `py` (feature `python`): the PyO3 module `kraken._native`.
//! - `testing` (feature `testing`): a FakeEngine-backed connection for the Python tests.
//!
//! Release rules this crate keeps: the GIL is released (`Python::detach`, called
//! `allow_threads` before PyO3 0.26) whenever a call blocks; there is one runtime per process;
//! a `KeyboardInterrupt` cancels the call in flight, and the Python layer cancels analysis jobs.

pub mod conn;
pub mod runtime;
pub mod schema;

#[cfg(feature = "python")]
mod py;
#[cfg(feature = "testing")]
pub mod testing;

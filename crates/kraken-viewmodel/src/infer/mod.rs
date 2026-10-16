//! Running a model on this computer, in the GUI (decisions 21, 30, 69): the settings form
//! generated from an engine's schema ([`form`]) and the panel's state and logic ([`panel`]).
//!
//! The panel talks to `kraken_host::infer::InferApi`, implemented by the daemon client and by an
//! in-process manager, so the same code serves both modes.

#[cfg(feature = "daemon")]
mod daemon;
#[cfg(all(test, feature = "daemon"))]
mod daemon_tests;
mod form;
mod panel;
#[cfg(test)]
mod tests;

#[cfg(feature = "daemon")]
pub use daemon::DaemonInfer;
pub use form::{Field, FieldKind, SettingsForm};
pub use kraken_host::infer::{
    BackendInfo, InferApi, InferListReply, InferManager, LogEntry, StatusReply,
};
pub use panel::{HintLevel, InferPanel, MemoryHint};

//! Running a model on this computer, in the GUI (decisions 21, 30, 69): the settings form
//! generated from an engine's schema ([`form`]) and the panel's state and logic ([`panel`]).
//!
//! The panel talks to `kraken_host::infer::InferApi`, implemented by the daemon client and by an
//! in-process manager, so the same code serves both modes.

pub mod card;
#[cfg(feature = "daemon")]
mod daemon;
#[cfg(all(test, feature = "daemon"))]
mod daemon_tests;
pub mod fake;
mod form;
mod hub;
mod panel;
pub mod setup;
pub mod setup_probe;
mod store;
#[cfg(test)]
mod tests;

#[cfg(feature = "daemon")]
pub use daemon::{BackendServing, DaemonInfer};
pub use form::{Field, FieldKind, SettingsForm};
pub use hub::{FitOption, FitPrompt, ServingHub};
pub use kraken_host::infer::{
    BackendInfo, InferApi, InferListReply, InferManager, LogEntry, StatusReply,
};
pub use kraken_host::infer::{ModelStatus, ServingApi, StartOptions};
pub use panel::{HintLevel, InferPanel, LOCAL_INFER_ACCOUNT, MemoryHint};
pub use setup::{
    Choice, Computer, FitLevel, LocalSetup, Progress, RawSurvey, SetupProbe, SetupStep, Snapshot,
    Stage, Survey, SurveyState, survey_from,
};
pub use setup_probe::BackendSetupProbe;
pub use store::LocalModelStore;

//! KRAKEN GUI view-model: all GUI state and logic, with no egui dependency.
//!
//! A [`ViewModel`] talks to a [`Backend`] (commands in, JSON out). Calls run on a tokio runtime
//! and their results are applied by [`ViewModel::poll`], which the window calls once per frame.
//!
//! Backends: [`InProcessBackend`] (feature `inprocess`) runs the command registry inside the GUI
//! process; [`DaemonClientBackend`] (feature `daemon`, the GUI default) implements the same trait
//! over the `krakend` socket and turns its change events into [`BackendEvent`]s. [`testing::FakeBackend`] scripts
//! replies for tests.

pub mod activity;
pub mod agents;
pub mod ai;
mod approval;
pub mod assist;
mod backend;
pub mod debug;
mod errors;
mod fuzzy;
pub mod history;
pub mod infer;
pub mod integrations;
mod loading;
mod nav;
pub mod navtools;
mod palette;
pub mod rewrite;
mod state;
pub mod testing;
mod tokens;
pub mod views;
mod vm;
mod wire;

#[cfg(feature = "daemon")]
pub mod daemon;
#[cfg(feature = "demo")]
pub mod demo;
#[cfg(feature = "inprocess")]
mod inprocess;

pub use approval::ApprovalBroker;
pub use backend::{
    ApprovalPrompt, Approver, Backend, BackendEvent, CallAs, ChangeInfo, CommandInfo, CommandKind,
    EngineActivity, JobInfo, JobProgress, JobState, JobStep, Permission,
};
#[cfg(feature = "daemon")]
pub use daemon::{
    BackendOptions, Backoff, Connector, DaemonClientBackend, attach_connector, default_connector,
    start_connector,
};
pub use errors::plain_error;
pub use fuzzy::score as fuzzy_score;
#[cfg(feature = "inprocess")]
pub use inprocess::{ExtraQuery, GUI_USER, InProcessBackend};
pub use loading::{LoadingState, clock, thousands};
pub use nav::NavHistory;
pub use palette::{
    AppAction, PaletteItem, PaletteState, PaletteTarget, SHORTCUTS, SetupButton, Shortcut,
    UiRequest, humanize_command,
};
pub use state::*;
pub use tokens::tokenize;
pub use views::{
    ByteCache, ByteState, FnRef, GraphBlock, GraphData, GraphEdgeKind, GraphState, HexState,
    ListingOperand, ListingRowItem, ListingState, MemoryBlockItem, MemoryMap, PagedList,
    ProgramViews, ReferencesTo, Reveal, StringItem, SymbolItem, SymbolTable, XrefItem, XrefList,
    XrefWhich, XrefsPanel, mnemonic_kind, operand_kind,
};
pub use vm::{FUNCTION_PAGE, MAX_NAME_LEN, RawLoad, ViewModel, validate_name};

#[cfg(test)]
mod stub_tests;
#[cfg(test)]
mod tests;

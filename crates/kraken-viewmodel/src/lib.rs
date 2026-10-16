//! KRAKEN GUI view-model: all GUI state and logic, with no egui dependency.
//!
//! A [`ViewModel`] talks to a [`Backend`] (commands in, JSON out). Calls run on a tokio runtime
//! and their results are applied by [`ViewModel::poll`], which the window calls once per frame.
//!
//! Backends: [`InProcessBackend`] (feature `inprocess`) runs the command registry inside the GUI
//! process; a daemon client implements the same trait over IPC. [`testing::FakeBackend`] scripts
//! replies for tests.

mod backend;
mod errors;
mod fuzzy;
mod nav;
mod palette;
mod state;
pub mod testing;
mod tokens;
mod vm;
mod wire;

#[cfg(feature = "demo")]
pub mod demo;
#[cfg(feature = "inprocess")]
mod inprocess;

pub use backend::{
    Backend, BackendEvent, CommandInfo, CommandKind, JobInfo, JobProgress, JobState, Permission,
};
pub use errors::plain_error;
pub use fuzzy::score as fuzzy_score;
#[cfg(feature = "inprocess")]
pub use inprocess::{GUI_USER, InProcessBackend};
pub use nav::NavHistory;
pub use palette::{AppAction, PaletteItem, PaletteState, PaletteTarget, UiRequest};
pub use state::*;
pub use tokens::tokenize;
pub use vm::{FUNCTION_PAGE, MAX_NAME_LEN, ViewModel, validate_name};

#[cfg(test)]
mod tests;

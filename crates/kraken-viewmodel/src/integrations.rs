//! The Integrations window: the emulators and tools KRAKEN can use, with Install, Use existing,
//! Remove and "Run in emulator", and no egui in it.
//!
//! Every action is a registry command (`integrations_list`, `integration_install`,
//! `integration_use_path`, `integration_remove`, `emulator_run`), so the CLI, MCP and Python do
//! the same. Install runs in the background; while one runs the window polls the list for its
//! progress.

use std::time::{Duration, Instant};

use kraken_registry::commands::{EmulatorRunOut, IntegrationStatus, IntegrationView};
mod hub;
pub use hub::IntegrationsHub;

/// How often the list is re-read while something installs.
const POLL_BUSY: Duration = Duration::from_millis(500);

/// What to hand to the emulator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunWhat {
    /// The program the project was made from.
    #[default]
    Original,
    /// A copy with the project's byte patches applied.
    Patched,
}

impl RunWhat {
    pub(crate) fn wire(self) -> &'static str {
        match self {
            RunWhat::Original => "original",
            RunWhat::Patched => "patched",
        }
    }
}

/// The "Run in emulator" dialog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunDialog {
    /// The emulator chosen, by id.
    pub emulator: Option<String>,
    /// What to run.
    pub what: RunWhat,
    /// Start the GDB stub and wait for a debugger.
    pub debug: bool,
}

/// State of the Integrations window and the run dialog.
#[derive(Debug, Default)]
pub struct IntegrationsState {
    /// The window is open.
    pub open: bool,
    /// Entries in catalogue order.
    pub rows: Vec<IntegrationView>,
    /// The card in the detail pane.
    pub selected: Option<String>,
    /// Filter text over names and platforms.
    pub filter: String,
    /// The person ticked "I have read the licence and notice" for `selected`.
    pub accepted: bool,
    /// Text of the "use existing" path box.
    pub path_input: String,
    /// The last message, with whether it is an error.
    pub message: Option<(String, bool)>,
    /// Ids with an install, removal or path change in flight.
    pub busy: Vec<String>,
    /// The run dialog, when open.
    pub run: Option<RunDialog>,
    /// A run is being started.
    pub running: bool,
    /// The result of the last run.
    pub last_run: Option<EmulatorRunOut>,
    /// The list has been read at least once.
    pub loaded: bool,
    pub(crate) inflight: bool,
    pub(crate) last_poll: Option<Instant>,
}

impl IntegrationsState {
    /// The row with `id`.
    pub fn row(&self, id: &str) -> Option<&IntegrationView> {
        self.rows.iter().find(|r| r.id == id)
    }

    /// Rows whose name, summary or platforms contain the filter, case-insensitively.
    pub fn visible(&self) -> Vec<&IntegrationView> {
        let f = self.filter.trim().to_lowercase();
        self.rows
            .iter()
            .filter(|r| {
                f.is_empty()
                    || r.name.to_lowercase().contains(&f)
                    || r.id.contains(&f)
                    || r.summary.to_lowercase().contains(&f)
                    || r.platforms.iter().any(|p| p.to_lowercase().contains(&f))
            })
            .collect()
    }

    /// Emulators that can run now.
    pub fn ready(&self) -> Vec<&IntegrationView> {
        self.rows
            .iter()
            .filter(|r| r.status == IntegrationStatus::Ready)
            .collect()
    }

    /// True while a download runs (here or started elsewhere).
    pub fn installing(&self) -> bool {
        self.rows
            .iter()
            .any(|r| r.status == IntegrationStatus::Installing)
            || !self.busy.is_empty()
    }

    /// Whether the window should re-read the list now.
    pub fn due(&self) -> bool {
        if self.inflight {
            return false;
        }
        match self.last_poll {
            None => true,
            Some(t) => self.installing() && t.elapsed() >= POLL_BUSY,
        }
    }
}

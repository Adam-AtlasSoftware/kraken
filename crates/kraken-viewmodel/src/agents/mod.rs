//! Terminal agents in the GUI (decisions 35, 50, 69): the Agents tab's state and logic over
//! `kraken-acp`.
//!
//! Everything is plain data on [`AgentsState`] (`vm.agents`) plus methods on the view-model, so
//! the window only draws. The flow is: the list of agents with what each needs
//! ([`AgentRow`]), an explicit consent step before anything is downloaded ([`SetupState`]), the
//! one-time warning that must be acknowledged before the first run, then one live session
//! ([`AgentSession`]) with the agent's words, tool calls and permission requests.

mod catalogue;
mod session;
mod setup;
// The tests drive shell-script fakes for node and npm, so they run on Unix only.
#[cfg(all(test, unix))]
mod tests;

use kraken_acp::NoticeStore;

pub use catalogue::{AgentRow, AgentsConfig, Availability};
pub use kraken_acp::{WARNING_TEXT, WARNING_TITLE};
pub use session::{
    AgentItem, AgentSession, AgentTool, PermissionCard, PermissionState, PlanLine, SessionPhase,
    classify_tool,
};
pub use setup::{SetupPlan, SetupProgress, SetupState};

/// Whether the one-time warning has been acknowledged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoticeState {
    /// The warning was acknowledged (now or earlier).
    pub acknowledged: bool,
    /// The acknowledgement could not be saved (it still counts for this run; the warning is
    /// advice, not a lock).
    pub save_error: Option<String>,
}

/// Everything the Agents tab shows.
#[derive(Default)]
pub struct AgentsState {
    /// The known agents, built-in ones first.
    pub rows: Vec<AgentRow>,
    /// The list has been built at least once.
    pub loaded: bool,
    /// The list is being rebuilt.
    pub loading: bool,
    /// Why `agents.toml` could not be read (the built-in agents still work).
    pub catalogue_error: Option<String>,
    /// The first line of what this computer can or cannot do, when it cannot run agents.
    pub platform_note: Option<String>,
    /// The one-time warning.
    pub notice: NoticeState,
    /// An agent waiting for the warning to be acknowledged before it starts.
    pub pending_notice: Option<String>,
    /// Downloading and installing an agent.
    pub setup: SetupState,
    /// The running (or just ended) session.
    pub session: Option<AgentSession>,
    /// Why a start was refused (plain language).
    pub error: Option<String>,
    pub(crate) config: Option<AgentsConfig>,
    pub(crate) store: Option<NoticeStore>,
    pub(crate) seq: u64,
    pub(crate) refresh_seq: u64,
}

impl AgentsState {
    /// The agent with `id`.
    pub fn row(&self, id: &str) -> Option<&AgentRow> {
        self.rows.iter().find(|r| r.id == id)
    }

    /// A session is starting or running.
    pub fn in_session(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| !matches!(s.phase, SessionPhase::Ended(_)))
    }
}

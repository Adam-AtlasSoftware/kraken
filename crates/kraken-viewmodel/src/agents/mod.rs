//! Terminal agents as assistant backends (decisions 35, 50, 94): which agents exist, whether
//! they can run here, setting one up, the one-time notice and a connection test. These are the
//! things the AI settings show next to the model providers.
//!
//! An agent that is chosen as the assistant is run by `kraken-assist` (see
//! [`crate::assist`]); this module only prepares the ground. [`AgentsHub`] is plain data plus
//! background tasks and needs no open project, so the settings window works from the welcome
//! screen too.

mod catalogue;
mod hub;
mod setup;
mod test_agent;
// The tests drive shell-script fakes for node and npm, so they run on Unix only.
#[cfg(all(test, unix))]
mod tests;

pub(crate) use catalogue::profiles;
pub use catalogue::{AgentRow, AgentsConfig, Availability};
pub use hub::{AgentEnv, AgentsHub, NoticeState};
pub use kraken_acp::{WARNING_TEXT, WARNING_TITLE};
pub use setup::{SetupPlan, SetupProgress, SetupState};
pub use test_agent::AgentTestState;

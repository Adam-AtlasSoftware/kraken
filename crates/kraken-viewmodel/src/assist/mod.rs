//! The built-in assistant (decisions 12, 19, 20): chat, "explain anything", the guided first
//! overview, the auto-naming review and learn mode, over `kraken-assist`.
//!
//! All of it is plain data on [`AssistState`] (`vm.assist`) plus methods on the view-model, so
//! the window only draws. Model calls run on the tokio runtime; their events come back through
//! the same queue as every other backend result.

mod adapter;
mod learn;
mod picker;
mod provider;
mod review;
mod run;
pub mod script;
#[cfg(test)]
mod tests;
// The agent tests run the fake ACP agent, a Unix-style process.
#[cfg(all(test, unix))]
mod agent_tests;

use std::sync::Arc;

use kraken_agent::{ApprovalHandle, ChatProvider, Usage};
use kraken_assist::{Arch, AssistBackend, Glossary};
use kraken_host::RunIdGen;
use kraken_registry::Registry;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

pub use crate::agents::AgentEnv;
pub use adapter::VmCommands;
pub use kraken_assist::{
    AgentChoice, AutomateGoal, BackendInfo, BackendKind, Confidence, SelectionKind,
};
pub use learn::{PANEL_HELP, PanelHelp, panel_help};
pub use picker::{CLOUD, PickEntry, PickGroup, SERVERS, groups as picker_groups};
pub use provider::{
    ProviderBadge, ProviderDraft, ProviderKind, ProviderStore, SECRETS_FILE, SECRETS_SERVICE,
    SaveOutcome, SecretsFile, TestReport, badge_of, external_server, is_local_url,
    plain_agent_error, test_connection,
};
pub use review::{ApplyWhich, confidence_label, evidence_text};
pub use run::ASSISTANT_CHAT_PROMPT;
pub use script::scripted_provider;

/// What a run is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    /// A free-form conversation turn.
    Chat,
    /// Explain a function.
    ExplainFunction,
    /// Explain a selection.
    ExplainSelection,
    /// The first overview.
    Overview,
    /// A dry-run auto-naming pass.
    AutoName,
    /// The whole flow: understand, name, rewrite (the Automate dialog).
    Automate,
}

impl RunKind {
    /// What the progress line says while it works.
    pub fn working_text(self) -> &'static str {
        match self {
            RunKind::Chat => "Thinking...",
            RunKind::ExplainFunction => "Reading the function...",
            RunKind::ExplainSelection => "Reading the selection...",
            RunKind::Overview => "Looking over the program...",
            RunKind::AutoName => "Looking for better names...",
            RunKind::Automate => "Working through the steps...",
        }
    }
}

/// One tool call, shown as a compact chip.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolChip {
    /// Call id.
    pub id: String,
    /// Command name.
    pub name: String,
    /// Arguments as sent.
    pub args: Value,
    /// Arguments on one short line.
    pub args_short: String,
    /// One of the terminal agent's own tools (shell, files), outside KRAKEN's safety net. False
    /// for KRAKEN's tools and for every tool of a model API.
    pub own_tool: bool,
    /// Short result summary once the call finished.
    pub summary: Option<String>,
    /// True when the call failed.
    pub is_error: bool,
}

/// Where a proposal stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalState {
    /// Waiting for the person.
    Waiting,
    /// A decision is being sent.
    Working,
    /// Accepted and applied as the person's edit.
    Accepted,
    /// Rejected.
    Rejected,
    /// The decision failed (plain-language reason).
    Failed(String),
}

/// Where a permission request of a terminal agent stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionState {
    /// Waiting for the person.
    Waiting,
    /// Allowed once.
    Allowed,
    /// Denied.
    Denied,
    /// Withdrawn (the run was stopped or ended).
    Withdrawn,
}

/// A terminal agent asking to use one of its own tools. KRAKEN cannot undo what that does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionCard {
    /// Id to answer with (`ViewModel::assist_answer_permission`).
    pub id: String,
    /// What the agent wants to do, in its words.
    pub title: String,
    /// `execute`, `edit`, `read`, ... when the agent says.
    pub kind: Option<String>,
    /// The tool's input, shortened.
    pub input: Option<String>,
    /// Files involved.
    pub paths: Vec<String>,
    /// Where it stands.
    pub state: PermissionState,
}

/// A change the assistant wanted to make that needs the person's say-so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalCard {
    /// The tool call that created it.
    pub call_id: String,
    /// Proposal id for `proposal_accept` / `proposal_reject`.
    pub proposal_id: Option<u64>,
    /// What it would do, in words ("Rename 0x401340 to fatal_out_of_memory").
    pub what: String,
    /// Why it was not applied automatically.
    pub reason: String,
    /// State.
    pub state: ProposalState,
}

/// A plain-language explanation of a function or a piece of code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainCard {
    /// Heading ("Function at 0x401000", "Selected code").
    pub title: String,
    /// The function it is about, shown as a clickable address.
    pub address: Option<u64>,
    /// Short summary.
    pub summary: String,
    /// What the code does, point by point.
    pub key_behaviours: Vec<String>,
    /// Names worth considering: (name, reason).
    pub suggested_names: Vec<(String, String)>,
    /// What the assistant is unsure about.
    pub caveats: Vec<String>,
    /// Problems with the answer itself (not parseable, run stopped early).
    pub warnings: Vec<String>,
}

/// A function the overview points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterestingRow {
    /// Entry address, when the model gave a valid one.
    pub address: Option<u64>,
    /// Current name.
    pub name: String,
    /// Why to look there.
    pub reason: String,
}

/// The guided first look at the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverviewCard {
    /// What the program is.
    pub what_it_is: String,
    /// Main parts: (name, description).
    pub components: Vec<(String, String)>,
    /// Functions to open first.
    pub interesting: Vec<InterestingRow>,
    /// What to do next.
    pub next_steps: Vec<String>,
    /// Data this build could not offer the assistant.
    pub missing_data: Vec<String>,
    /// Problems with the answer.
    pub warnings: Vec<String>,
}

/// One entry of the conversation.
#[derive(Debug, Clone, PartialEq)]
pub enum ChatItem {
    /// What the person typed (or a button asked for).
    User(String),
    /// What the assistant said; `streaming` while words still arrive.
    Assistant {
        /// Text so far.
        text: String,
        /// More is coming.
        streaming: bool,
    },
    /// A tool call.
    Tool(ToolChip),
    /// A proposal to review.
    Proposal(ProposalCard),
    /// A terminal agent asking to use one of its own tools.
    Permission(PermissionCard),
    /// An explanation card.
    Explanation(ExplainCard),
    /// The overview card.
    Overview(OverviewCard),
    /// A neutral line ("Stopped.").
    Notice(String),
    /// Something went wrong (plain language).
    Error(String),
}

/// The banner offering the first overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverviewOffer {
    /// Nothing to offer (yet, or already dealt with).
    #[default]
    Hidden,
    /// Analysis just finished: offer the overview.
    Offered,
}

/// Where a suggestion in the review table stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowStatus {
    /// Not applied.
    Pending,
    /// Applied as the person's edit.
    Applied,
    /// Applied and then undone.
    Undone,
    /// Could not be applied (plain-language reason).
    Failed(String),
}

/// One suggestion in the auto-name review table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRow {
    /// Function address.
    pub address: u64,
    /// Name now.
    pub old_name: String,
    /// Suggested name.
    pub new_name: Option<String>,
    /// Suggested comment.
    pub comment: Option<String>,
    /// What the suggestion rests on, one line per piece.
    pub evidence: Vec<String>,
    /// How much evidence backs it.
    pub confidence: Confidence,
    /// How the label was derived.
    pub basis: String,
    /// Ticked for "Apply selected".
    pub selected: bool,
    /// Outcome.
    pub status: RowStatus,
}

/// The auto-name review.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AutoNameReview {
    /// Suggestions.
    pub rows: Vec<ReviewRow>,
    /// A reminder of what the confidence labels mean.
    pub note: String,
    /// Edits are being applied or undone.
    pub busy: bool,
    /// How many of the person's latest edits "Undo" would reverse.
    pub undoable: usize,
    /// Result line ("Applied 3 names.").
    pub message: Option<String>,
}

/// State of the auto-naming flow.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AutoNameState {
    /// Not started.
    #[default]
    Idle,
    /// The model is looking.
    Running,
    /// Suggestions wait for review.
    Review(AutoNameReview),
    /// It could not run (plain-language reason).
    Failed(String),
}

/// What the assistant is set to use: a model API, or a terminal agent.
#[derive(Clone)]
pub enum BackendChoice {
    /// A chat model API (cloud or local).
    Api(Arc<dyn ChatProvider>),
    /// Claude Code, Codex, Gemini CLI or another agent over ACP.
    Agent(AgentChoice),
}

/// The backend in use.
pub struct ActiveBackend {
    /// What was chosen.
    pub choice: BackendChoice,
    /// What the panel shows about it.
    pub badge: ProviderBadge,
    /// The running backend, made when the first question is asked (a terminal agent needs the
    /// open project) and dropped when the project or the choice changes.
    pub(crate) engine: Option<Arc<dyn AssistBackend>>,
}

impl ActiveBackend {
    /// A terminal agent is selected.
    pub fn is_agent(&self) -> bool {
        matches!(self.choice, BackendChoice::Agent(_))
    }

    /// The selected agent's id.
    pub fn agent_id(&self) -> Option<&str> {
        match &self.choice {
            BackendChoice::Agent(a) => Some(&a.agent),
            BackendChoice::Api(_) => None,
        }
    }

    /// The badge with the model the agent reported, once it has started.
    pub fn current_badge(&self) -> ProviderBadge {
        let mut b = self.badge.clone();
        if let Some(m) = self
            .engine
            .as_ref()
            .filter(|_| self.is_agent())
            .and_then(|e| e.info().model)
        {
            b.model = m;
        }
        b
    }
}

pub(crate) struct ActiveRun {
    pub(crate) seq: u64,
    pub(crate) kind: RunKind,
    pub(crate) cancel: CancellationToken,
    pub(crate) filter: kraken_assist::ResultTagFilter,
    /// Index in `items` where this run's output starts.
    pub(crate) first_item: usize,
    pub(crate) stopping: bool,
    pub(crate) title: String,
    pub(crate) address: Option<u64>,
    pub(crate) wrote: bool,
    /// Text of the model's current step (history for the next question).
    pub(crate) last_text: String,
    /// Where approval answers go (a terminal agent asking for one of its own tools).
    pub(crate) approvals: Option<ApprovalHandle>,
}

/// Everything the assistant panels show.
pub struct AssistState {
    /// The backend in use, if one is configured.
    pub backend: Option<ActiveBackend>,
    /// Where terminal agents are found and whether the one-time notice was read. Without it a
    /// terminal agent cannot start.
    pub agent_env: Option<AgentEnv>,
    /// The conversation, oldest first.
    pub items: Vec<ChatItem>,
    /// Tokens used since the window opened.
    pub usage: Usage,
    /// The prompt size of the most recent model call: how full the model's context is.
    pub last_input_tokens: u64,
    /// The first-overview banner.
    pub overview_offer: OverviewOffer,
    /// The auto-name flow.
    pub autoname: AutoNameState,
    /// Learn mode: explain RE terms on hover.
    pub learn_mode: bool,
    /// The window should bring the Assistant tab to the front.
    pub show_requested: bool,
    /// Why the saved provider could not be used (shown in the chat panel's setup screen).
    pub provider_problem: Option<String>,
    pub(crate) glossary: &'static Glossary,
    pub(crate) registry: Arc<Registry>,
    pub(crate) run: Option<ActiveRun>,
    pub(crate) history: Vec<kraken_agent::Message>,
    pub(crate) run_ids: RunIdGen,
    pub(crate) seq: u64,
    pub(crate) offered_once: bool,
    /// Automatic continuations used for the question in progress.
    pub(crate) auto_continues: u32,
    /// Replaces `[ai_limits] auto_continue` in tests.
    #[cfg(test)]
    pub(crate) auto_continue_override: Option<u32>,
}

impl Default for AssistState {
    fn default() -> Self {
        AssistState {
            backend: None,
            agent_env: None,
            items: Vec::new(),
            usage: Usage::default(),
            last_input_tokens: 0,
            overview_offer: OverviewOffer::Hidden,
            autoname: AutoNameState::Idle,
            learn_mode: false,
            show_requested: false,
            provider_problem: None,
            glossary: Glossary::builtin(),
            registry: Arc::new(Registry::standard()),
            run: None,
            history: Vec::new(),
            run_ids: RunIdGen::new(),
            seq: 0,
            offered_once: false,
            auto_continues: 0,
            #[cfg(test)]
            auto_continue_override: None,
        }
    }
}

impl AssistState {
    /// Uses the model API `provider` from now on.
    pub fn set_provider(&mut self, provider: Arc<dyn ChatProvider>, badge: ProviderBadge) {
        self.set_backend(BackendChoice::Api(provider), badge);
    }

    /// Uses `choice` from now on. A running terminal agent session is ended; the conversation on
    /// screen stays, and the new backend is caught up from it on the next question.
    pub fn set_backend(&mut self, choice: BackendChoice, badge: ProviderBadge) {
        self.close_engine();
        self.backend = Some(ActiveBackend {
            choice,
            badge,
            engine: None,
        });
    }

    /// The context window of the model API in use, when it is known.
    pub fn context_window(&self) -> Option<u32> {
        match &self.backend.as_ref()?.choice {
            BackendChoice::Api(p) => p.info().context_window,
            BackendChoice::Agent(_) => None,
        }
    }

    /// Forgets the backend (settings cleared).
    pub fn clear_provider(&mut self) {
        self.close_engine();
        self.backend = None;
    }

    /// Ends what the backend keeps between questions (a terminal agent's session).
    pub(crate) fn close_engine(&mut self) {
        if let Some(e) = self.backend.as_mut().and_then(|b| b.engine.take()) {
            e.close();
        }
    }

    /// The badge of the backend in use, with the model a terminal agent reported.
    pub fn badge(&self) -> Option<ProviderBadge> {
        self.backend.as_ref().map(ActiveBackend::current_badge)
    }

    /// A terminal agent is the backend and the one-time notice has not been read yet.
    pub fn agent_notice_pending(&self) -> bool {
        self.backend.as_ref().is_some_and(ActiveBackend::is_agent)
            && !self.agent_env.as_ref().is_some_and(|e| e.acknowledged)
    }

    /// True while a run is in flight.
    pub fn busy(&self) -> bool {
        self.run.is_some()
    }

    /// What the run in flight is doing, for the progress line.
    pub fn running(&self) -> Option<RunKind> {
        self.run.as_ref().map(|r| r.kind)
    }

    /// True once the person asked to stop and the run is winding down.
    pub fn stopping(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.stopping)
    }

    /// Clears everything tied to the open project (a different one is loading).
    pub(crate) fn reset_for_project(&mut self) {
        if let Some(r) = &self.run {
            r.cancel.cancel();
        }
        self.run = None;
        self.close_engine();
        self.items.clear();
        self.history.clear();
        self.last_input_tokens = 0;
        self.auto_continues = 0;
        self.overview_offer = OverviewOffer::Hidden;
        self.autoname = AutoNameState::Idle;
        self.offered_once = false;
    }

    /// The registry the assistant's tools come from.
    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// The glossary entry for an RE term.
    pub fn term(&self, term: &str) -> Option<&'static kraken_assist::GlossaryEntry> {
        self.glossary.get(term)
    }

    /// Every concept entry of the glossary (not the instruction mnemonics), sorted by term, or
    /// those matching `query` best first when it is not empty.
    pub fn glossary_terms(&self, query: &str) -> Vec<&'static kraken_assist::GlossaryEntry> {
        let all = self.glossary.entries();
        if query.trim().is_empty() {
            let mut v: Vec<_> = all.iter().filter(|e| e.arch.is_none()).collect();
            v.sort_by_key(|e| e.term.to_lowercase());
            return v;
        }
        self.glossary
            .lookup(query, 60)
            .into_iter()
            .filter(|m| m.entry.arch.is_none())
            .filter_map(|m| self.glossary.get(&m.entry.term))
            .collect()
    }

    /// The glossary entry for an assembly mnemonic of `arch` (a language id such as
    /// `x86:LE:64:default`).
    pub fn mnemonic(
        &self,
        arch: &str,
        mnemonic: &str,
    ) -> Option<&'static kraken_assist::GlossaryEntry> {
        let arch = Arch::from_name(arch)?;
        self.glossary.mnemonic(arch, mnemonic)
    }
}

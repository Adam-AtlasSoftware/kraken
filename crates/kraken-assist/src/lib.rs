//! KRAKEN assistant core (decisions 12, 20, 29, 61).
//!
//! - [`AssistBackend`] is what answers: a model API ([`ApiBackend`], the `kraken-agent` loop over
//!   a [`RegistryToolHost`]) or a terminal agent ([`AcpBackend`], Claude Code, Codex or Gemini CLI
//!   over ACP, using KRAKEN's tools through the `kraken mcp` server it is launched with). Both
//!   produce the same event stream, so every task and the chat run on either (decision 94).
//! - [`RegistryToolHost`] exposes command-registry commands to the `kraken-agent` loop as tools,
//!   over any [`kraken_host::backend::CommandBackend`] (an in-process session or `krakend`).
//! - [`Task`] builders turn the beginner features into agent runs: explain a function or a
//!   selection, a guided overview, and an auto-naming pass. [`Assistant::run`] executes one and
//!   parses the structured result.
//! - [`Glossary`] is the offline dictionary of reverse-engineering terms and mnemonics behind the
//!   GUI learn-mode tooltips.
//! - [`provider`] loads the `[provider]` table of `config.toml` and explains how to set one up.
//!
//! No GUI dependencies. Binary-derived text only ever reaches the model as delimited data: tool
//! results (already wrapped as untrusted by the registry) and the `<selection>` block of
//! `explain_selection`; the system prompt never contains it.

pub mod acp;
pub mod ai_config;
pub mod assistant;
pub mod backend;
pub mod error;
pub mod glossary;
pub mod host;
pub mod meter;
pub mod output;
pub mod pricing;
pub mod provider;
pub mod tasks;

pub use acp::{
    AcpBackend, AcpSettings, AgentChoice, PlanError, classify_tool, find_kraken_exe, plan_agent,
};
pub use ai_config::{
    AiLimits, AiPolicy, ModelChoice, ModelSource, REPAIR_ATTEMPTS, REPAIR_SUSPECTS,
    REWRITE_ATTEMPTS, RewriteModel, is_local_url, model_of, provider_kind_of, rewrite_choice,
    rewrite_max_calls, save_rewrite_config, with_model,
};
pub use assistant::{Assistant, ResultTagFilter, TaskResult, ToolCallSummary};
pub use backend::{
    ApiBackend, AssistBackend, BackendInfo, BackendKind, Purpose, RunSpec, TextFuture, TextReply,
    UnusedBackend,
};
pub use error::AssistError;
pub use glossary::{Arch, Glossary, GlossaryEntry, GlossaryKind, GlossaryMatch, MatchKind};
pub use host::{CallRecord, DEFAULT_EXCLUDED, HostOptions, HostStats, RegistryToolHost};
pub use meter::{Meter, MeterBuilder, MeterObserver, MeterSpec, daily_budget_message};
pub use output::{
    AutoNameReport, Component, Confidence, Evidence, EvidenceKind, Explanation,
    InterestingFunction, NameSuggestion, Outcome, Overview, SuggestedName, TaskOutput,
};
pub use pricing::{DEFAULT_PRICES, Price, Pricing};
pub use provider::{
    SAMPLES, load_provider_config, load_rewrite_config, no_provider_message, provider_config_path,
    sample_config, text_backend, text_backend_from_config,
};
pub use tasks::{
    AUTOMATE_JOB_TIMEOUT, AUTOMATE_REWRITE_UNLOCK, AutoNameOptions, AutomateGoal, Budget,
    SelectionKind, Task, TaskKind,
};

/// The agent id edits are logged under.
pub const ASSISTANT_ID: &str = "kraken-assistant";

//! `ai_usage` and `ai_jobs`: what AI work cost and what is running.

use async_trait::async_trait;
use kraken_model::{DailyLedger, UsageFilter, utc_day};
use kraken_proto::{AiCallRecord, AiFeature, AiJobView, AiUsageTotals, ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

/// What `ai_usage` adds up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiUsageScope {
    /// Every model call made for the open project.
    #[default]
    Project,
    /// Today (UTC): all projects together, with this project's calls listed.
    Today,
    /// One piece of AI work: `run_id` is its AI run id or its job id.
    Run,
}

/// Arguments of `ai_usage`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiUsageArgs {
    /// `project` (default), `today` or `run`.
    #[serde(default)]
    pub scope: AiUsageScope,
    /// For `scope: run`: the AI run id (`ai-3`) or job id (`job-3`).
    #[serde(default)]
    pub run_id: Option<String>,
}

/// Totals of one feature and model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiUsageGroupView {
    /// What the calls were for.
    pub feature: AiFeature,
    /// The model (or the provider when no model is known).
    pub model: String,
    /// Their totals.
    pub totals: AiUsageTotals,
}

/// Result of `ai_usage`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiUsageOut {
    /// The scope added up.
    pub scope: AiUsageScope,
    /// The totals. For `today` they count every project.
    pub totals: AiUsageTotals,
    /// This project's calls by feature and model.
    pub groups: Vec<AiUsageGroupView>,
    /// This project's latest calls, newest first (at most 20).
    pub recent: Vec<AiCallRecord>,
    /// One line: calls, tokens and the estimated cost.
    pub summary: String,
    /// Money is an estimate; what it is based on.
    pub note: String,
}

/// Most recent calls listed.
const RECENT: u32 = 20;

/// What the money figures are.
pub const ESTIMATE_NOTE: &str = "Costs are estimates from the reported tokens and the price \
table ([pricing] in config.toml, with built-in list prices); your provider's bill is what \
counts. Terminal agents are billed by their own subscription and report no tokens; local \
models are free.";

fn start_of_today_ms() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    now - now.rem_euclid(86_400_000)
}

/// Shows what AI work cost.
pub struct AiUsage;

#[async_trait]
impl Command for AiUsage {
    type Args = AiUsageArgs;
    type Output = AiUsageOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "ai_usage",
            "Show the model calls made and their estimated cost (project, today or one run)",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Adds up the model calls KRAKEN made: calls, tokens, time and an estimated cost, by \
             feature (assistant, auto_name, automate, rewrite) and model. `scope` is `project` \
             (default), `today` (all projects, UTC day) or `run` with a `run_id` (an AI run id \
             or a job id). Costs are estimates.\n\
             Example: ai_usage {\"scope\": \"today\"}",
        )
        .details(
            "Every model call (assistant chat, explain and overview, Suggest names, Automate, \
             each rewrite translation, spec and repair attempt, evaluation runs) is recorded in \
             the project database with the provider, the model, the feature, the job or run it \
             belongs to, the tokens the provider reported, the time it took and a cost estimated \
             from the price table (`[pricing]` in config.toml over built-in list prices). \
             Terminal agents report no tokens: their calls are counted and marked as billed by \
             the agent's subscription. Local models cost nothing. A small file in the KRAKEN \
             data directory keeps the daily totals of all projects, which the daily budget \
             (`[ai_limits]`) is checked against; `scope: today` reads it.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: AiUsageArgs,
    ) -> Result<AiUsageOut, ProtoError> {
        let filter = match args.scope {
            AiUsageScope::Project => UsageFilter::default(),
            AiUsageScope::Today => UsageFilter {
                since_ms: Some(start_of_today_ms()),
                run: None,
            },
            AiUsageScope::Run => {
                let run = args
                    .run_id
                    .clone()
                    .filter(|r| !r.trim().is_empty())
                    .ok_or_else(|| {
                        ProtoError::new(
                            ErrorCode::InvalidArgument,
                            "`scope: run` needs a `run_id` (an AI run id such as ai-3, or a job id)",
                        )
                    })?;
                UsageFilter {
                    since_ms: None,
                    run: Some(run),
                }
            }
        };
        let project = match (args.scope, s.project()) {
            (_, Ok(p)) => Some(p),
            (AiUsageScope::Today, Err(_)) => None,
            (_, Err(e)) => return Err(e),
        };
        let (mut totals, groups, recent) = match project {
            Some(p) => {
                let f = filter.clone();
                p.with_store(move |st| {
                    let (t, g) = st.ai_usage_summary(&f)?;
                    let r = st.ai_usage_calls(&f, RECENT)?;
                    Ok((t, g, r))
                })
                .await?
            }
            None => (AiUsageTotals::default(), Vec::new(), Vec::new()),
        };
        if args.scope == AiUsageScope::Today
            && let Some(d) = DailyLedger::standard()
        {
            let all = d.day(&utc_day(start_of_today_ms()));
            // The file may lag behind or miss calls of a process that could not write it.
            if all.calls >= totals.calls {
                totals = all;
            }
        }
        Ok(AiUsageOut {
            scope: args.scope,
            summary: totals.line(),
            totals,
            groups: groups
                .into_iter()
                .map(|g| AiUsageGroupView {
                    feature: g.feature,
                    model: g.model,
                    totals: g.totals,
                })
                .collect(),
            recent,
            note: ESTIMATE_NOTE.to_string(),
        })
    }
}

/// Result of `ai_jobs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiJobsOut {
    /// Running work first, then the latest finished work.
    pub jobs: Vec<AiJobView>,
    /// Pieces of work still running.
    pub running: u32,
}

/// Lists running and recent AI work.
pub struct AiJobs;

#[async_trait]
impl Command for AiJobs {
    type Args = super::NoArgs;
    type Output = AiJobsOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "ai_jobs",
            "List running and recent AI work with its model, who started it and its usage so far",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Lists the AI work of this session (rewrite jobs started from the window, the \
             command line or by agents): feature, model, who started it, status and usage so \
             far (calls, tokens, estimated cost). Stop one with `job_cancel` and its `job_id`.\n\
             Example: ai_jobs {}",
        )
        .details(
            "The daemon keeps the board per project session: running work first, then the \
             latest 40 finished pieces. The same changes are published as `ai_started`, \
             `ai_progress` and `ai_done` events. Assistant runs inside the window or a CLI \
             process are metered there and show in `ai_usage`, not here.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<AiJobsOut, ProtoError> {
        let jobs = s.ai().list();
        let running = jobs.iter().filter(|j| !j.status.is_terminal()).count();
        Ok(AiJobsOut {
            jobs,
            running: u32::try_from(running).unwrap_or(u32::MAX),
        })
    }
}

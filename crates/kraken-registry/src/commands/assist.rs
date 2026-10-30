//! The assistant as jobs: `assist_explain`, `assist_overview` and `assist_auto_name`.
//!
//! Each starts one assistant task (the same ones the GUI chat and `kraken explain` run) as a job
//! and returns a `job_id`; `job_status` / `job_await` give the task result: the answer text, the
//! structured output and the run id the task's edits were logged under (`undo_run` takes it).
//! The model calls are metered and go on the AI board like the rewrite's. The work is done by an
//! [`AssistJobs`] backend that `kraken-assist` provides; attach it with [`Session::with_assist`].

use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use super::JobStarted;
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext};
use crate::jobs::JobReporter;
use crate::session::Session;

/// Most functions one `assist_auto_name` call may name.
pub const MAX_AUTO_NAME: usize = 50;
/// Functions `assist_auto_name` names when the call gives no `limit`.
pub const DEFAULT_AUTO_NAME: usize = 10;

/// One assistant task a job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssistRequest {
    /// Explain the function at `address`.
    Explain {
        /// Address text as given.
        address: String,
    },
    /// Summarise the whole program.
    Overview,
    /// Suggest and apply names for unnamed functions.
    AutoName {
        /// Most functions to name.
        limit: usize,
        /// Suggest only; write nothing.
        dry_run: bool,
    },
}

impl AssistRequest {
    /// The command that starts it.
    pub fn command(&self) -> &'static str {
        match self {
            AssistRequest::Explain { .. } => "assist_explain",
            AssistRequest::Overview => "assist_overview",
            AssistRequest::AutoName { .. } => "assist_auto_name",
        }
    }
}

/// What the `assist_*` commands run on. Implemented by `kraken-assist`.
#[async_trait]
pub trait AssistJobs: Send + Sync {
    /// Checks that a model is set up and today's budget allows more work (cheap, before the job
    /// starts). Errors say what to fix.
    fn check_ready(&self) -> Result<(), ProtoError>;

    /// What a person is asked before this call runs: `Some(text)` (the model and the estimated
    /// cost) when this caller must approve, `None` when it may start. Agents and MCP callers
    /// always approve; a person only when the estimate crosses the confirmation threshold.
    async fn approval(
        &self,
        s: &Session,
        ctx: &CallContext,
        request: &AssistRequest,
    ) -> Option<String>;

    /// The body of the job: runs the task and returns its result as JSON.
    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        request: AssistRequest,
        job: &JobReporter,
    ) -> Result<Value, ProtoError>;
}

impl std::fmt::Debug for dyn AssistJobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AssistJobs")
    }
}

impl Session {
    /// The attached assistant jobs; `unsupported` when this build or surface has none.
    pub fn assist(&self) -> Result<&Arc<dyn AssistJobs>, ProtoError> {
        self.assist_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "the assistant is not attached to this session; use the kraken CLI or krakend, \
                 which link it",
            )
        })
    }
}

async fn start(
    s: &Session,
    ctx: &CallContext,
    request: AssistRequest,
) -> Result<JobStarted, ProtoError> {
    let backend = s.assist()?.clone();
    s.project()?;
    backend.check_ready()?;
    if let Some(summary) = backend.approval(s, ctx, &request).await {
        let decision = ctx
            .approval
            .request(ApprovalRequest {
                command: request.command().into(),
                summary,
                args: serde_json::json!({ "model_calls": true }),
                author: ctx.author.clone(),
                surface: ctx.surface,
            })
            .await;
        if let ApprovalDecision::Deny { reason } = decision {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("approval denied: {reason}"),
            )
            .with_details(serde_json::json!({ "approval": "denied" })));
        }
    }
    let (s2, ctx2) = (s.clone(), ctx.clone());
    let name = request.command();
    let id = s.jobs().spawn(name, move |reporter| async move {
        backend.run(&s2, &ctx2, request, &reporter).await
    });
    Ok(JobStarted { job_id: id.0 })
}

/// Arguments of `assist_explain`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssistExplainArgs {
    /// The function (any address inside it, or its name).
    pub address: String,
}

/// Has the assistant explain one function (job).
pub struct AssistExplain;

#[async_trait]
impl Command for AssistExplain {
    type Args = AssistExplainArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "assist_explain",
            "Have the assistant explain one function (job)",
            CommandKind::Job,
            Permission::Safe,
        )
        .doc(
            "Runs the assistant's explain task with the configured model and returns a `job_id`; \
             `job_await` returns the answer text, a structured explanation (summary, key \
             behaviours, names to consider, caveats) and the run id. Changes nothing in the \
             project. Sends decompiled code to the provider; an agent or MCP caller needs a \
             person's approval.\n\
             Example: assist_explain {\"address\": \"0x401136\"}",
        )
        .details(
            "The same task as `kraken explain` and the Explain button. The model works through \
             the read-only commands (decompile, xrefs, strings), is metered like every model \
             call (`ai_usage`, `ai_jobs`) and stops at the per-run cap and the daily budget of \
             `[ai_limits]`. Only model APIs are supported here; a terminal agent is run with \
             `kraken explain` or in the GUI.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: AssistExplainArgs,
    ) -> Result<JobStarted, ProtoError> {
        if args.address.trim().is_empty() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "`address` is required",
            ));
        }
        start(
            s,
            ctx,
            AssistRequest::Explain {
                address: args.address,
            },
        )
        .await
    }
}

/// Has the assistant summarise the whole program (job).
pub struct AssistOverview;

#[async_trait]
impl Command for AssistOverview {
    type Args = super::NoArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "assist_overview",
            "Have the assistant summarise the whole program (job)",
            CommandKind::Job,
            Permission::Safe,
        )
        .doc(
            "Runs the assistant's overview task and returns a `job_id`; `job_await` returns what \
             the program is, its main parts, where to look first and next steps. Changes nothing \
             in the project. Sends decompiled code to the provider; an agent or MCP caller needs \
             a person's approval.\n\
             Example: assist_overview {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<JobStarted, ProtoError> {
        start(s, ctx, AssistRequest::Overview).await
    }
}

/// Arguments of `assist_auto_name`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssistAutoNameArgs {
    /// Most functions to name (default 10, at most 50).
    #[serde(default)]
    pub limit: Option<usize>,
    /// Only suggest names; write nothing (default false).
    #[serde(default)]
    pub dry_run: bool,
}

/// Has the assistant name unnamed functions (job).
pub struct AssistAutoName;

#[async_trait]
impl Command for AssistAutoName {
    type Args = AssistAutoNameArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "assist_auto_name",
            "Have the assistant name unnamed functions (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Runs the assistant's auto-name task and returns a `job_id`; `job_await` returns each \
             suggestion with its evidence and what happened to it, and the `run_id`. Renames and \
             comments are logged under that run, so `undo_run` takes them all back at once. With \
             `dry_run` nothing is written. Sends decompiled code to the provider; an agent or MCP \
             caller needs a person's approval.\n\
             Example: assist_auto_name {\"limit\": 10, \"dry_run\": true}",
        )
        .details(
            "The same task as `kraken auto-name`. Names the assistant is not sure about become \
             proposals for you to review instead of edits, as for every agent write that is not \
             purely additive. Metered like every model call (`ai_usage`, `ai_jobs`).",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: AssistAutoNameArgs,
    ) -> Result<JobStarted, ProtoError> {
        let limit = args.limit.unwrap_or(DEFAULT_AUTO_NAME);
        if limit == 0 || limit > MAX_AUTO_NAME {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("`limit` is between 1 and {MAX_AUTO_NAME}"),
            ));
        }
        start(
            s,
            ctx,
            AssistRequest::AutoName {
                limit,
                dry_run: args.dry_run,
            },
        )
        .await
    }
}

//! `analyze` and the job control commands.

use std::time::Duration;

use async_trait::async_trait;
use kraken_engine::{AnalyzeRequest, Cap, unsupported};
use kraken_proto::{ErrorCode, ProtoError, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::jobs::{JobId, JobProgress, JobSnapshot, JobStatus as Status};
use crate::session::{AnalysisPhase, Session};

/// Output of `analyze`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeOut {
    /// The analysis job.
    pub job_id: String,
    /// True when an analysis was already running and its job is returned.
    pub already_running: bool,
}

/// Result of a finished analysis job (the `result` of `job_status`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeResult {
    /// Stages that finished, in order.
    pub stages_completed: Vec<String>,
    /// Functions known afterwards.
    pub function_count: u64,
    /// Queued edits pushed to the engine after analysis.
    pub flushed_entries: u64,
    /// Queued edits the engine refused.
    pub rejected_entries: u64,
}

/// Starts staged analysis.
pub struct Analyze;

#[async_trait]
impl Command for Analyze {
    type Args = super::NoArgs;
    type Output = AnalyzeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "analyze",
            "Analyse the binary (job): functions, types and references",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Runs the staged analysis (load, core, expensive) as a job; poll with `job_status` or \
             `job_await`. Results are partial until it finishes. Edits made meanwhile are logged \
             and reported as `queued`; they are pushed to the engine when analysis completes. If \
             an analysis is already running its job is returned.",
        )
        .needs(&[Cap::Analyzer])
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<AnalyzeOut, ProtoError> {
        let project = s.project()?;
        if project.engine().analyzer().is_none() {
            return Err(unsupported("analyzer"));
        }
        let started = project.begin_analysis(|| {
            let project = project.clone();
            s.jobs().spawn("analyze", move |reporter| async move {
                run_analysis(project, reporter).await
            })
        });
        match started {
            Ok(id) => Ok(AnalyzeOut {
                job_id: id.0,
                already_running: false,
            }),
            Err(Some(id)) => Ok(AnalyzeOut {
                job_id: id.0,
                already_running: true,
            }),
            Err(None) => Err(ProtoError::new(
                ErrorCode::Internal,
                "analysis is marked running without a job",
            )),
        }
    }
}

async fn run_analysis(
    project: std::sync::Arc<crate::session::Project>,
    reporter: crate::jobs::JobReporter,
) -> Result<Value, ProtoError> {
    let token = reporter.cancel_token();
    let outcome = analyse(&project, &reporter).await;
    match outcome {
        Ok(summary) => {
            project.end_analysis(AnalysisPhase::Complete, Some(summary.function_count), None);
            project.update_meta(|m| m.analysis_complete = true);
            let _ = project.persist_meta().await;
            let (flushed, rejected) = {
                let _w = project.write_lock.lock().await;
                match project.flush_pending(&token).await {
                    Ok(r) => (r.pushed.len() as u64, r.rejected.len() as u64),
                    Err(_) => (0, 0),
                }
            };
            serde_json::to_value(AnalyzeResult {
                stages_completed: summary
                    .stages_completed
                    .iter()
                    .map(|st| st.as_str().to_string())
                    .collect(),
                function_count: summary.function_count,
                flushed_entries: flushed,
                rejected_entries: rejected,
            })
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))
        }
        Err(e) => {
            let phase = if e.code == ErrorCode::Cancelled {
                AnalysisPhase::Cancelled
            } else {
                AnalysisPhase::Failed
            };
            project.end_analysis(phase, None, Some(e.message.clone()));
            Err(e)
        }
    }
}

async fn analyse(
    project: &crate::session::Project,
    reporter: &crate::jobs::JobReporter,
) -> Result<kraken_engine::AnalysisSummary, ProtoError> {
    let engine = project.engine();
    let analyzer = engine.analyzer().ok_or_else(|| unsupported("analyzer"))?;
    let mut job = analyzer
        .analyze(AnalyzeRequest::default(), reporter.cancel_token())
        .await?;
    while let Some(p) = job.next_progress().await {
        reporter.progress(JobProgress {
            phase: p.stage.as_str().to_string(),
            done: p.done,
            total: p.total,
            message: sanitize(&p.message),
        });
    }
    job.wait().await
}

/// A job as shown by the job commands.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct JobView {
    /// Job id.
    pub job_id: String,
    /// Command that started it.
    pub command: String,
    /// `running`, `succeeded`, `failed` or `cancelled`.
    pub status: Status,
    /// Latest progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<JobProgress>,
    /// Command-specific result once succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Why the job failed or was cancelled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtoError>,
    /// True when `job_await` returned because its timeout passed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub timed_out: bool,
}

impl JobView {
    fn new(s: JobSnapshot, timed_out: bool) -> JobView {
        JobView {
            job_id: s.id.0,
            command: s.command,
            status: s.status,
            progress: s.progress.map(|mut p| {
                p.message = sanitize(&p.message);
                p
            }),
            result: s.result,
            error: s.error.map(|mut e| {
                e.message = sanitize(&e.message);
                e
            }),
            timed_out,
        }
    }
}

/// Arguments naming a job.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobIdArgs {
    /// Job id such as `job-1`.
    pub job_id: String,
}

/// Shows a job.
pub struct JobStatus;

#[async_trait]
impl Command for JobStatus {
    type Args = JobIdArgs;
    type Output = JobView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "job_status",
            "Show a job's status, progress and result",
            CommandKind::Query,
            Permission::Safe,
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: JobIdArgs,
    ) -> Result<JobView, ProtoError> {
        Ok(JobView::new(s.jobs().snapshot(&JobId(args.job_id))?, false))
    }
}

/// Arguments of `job_await`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobAwaitArgs {
    /// Job id such as `job-1`.
    pub job_id: String,
    /// Longest wait in milliseconds (default 30000, capped by the session).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

/// Waits for a job.
pub struct JobAwait;

#[async_trait]
impl Command for JobAwait {
    type Args = JobAwaitArgs;
    type Output = JobView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "job_await",
            "Wait for a job to finish or a timeout to pass",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Returns the job as soon as it ends, or after `timeout_ms` with `timed_out: true` \
             and the job still running; call again to keep waiting.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: JobAwaitArgs,
    ) -> Result<JobView, ProtoError> {
        let ms = args
            .timeout_ms
            .unwrap_or(30_000)
            .min(s.config().max_await_ms);
        let (snap, timed_out) = s
            .jobs()
            .wait(&JobId(args.job_id), Duration::from_millis(ms), &ctx.cancel)
            .await?;
        Ok(JobView::new(snap, timed_out))
    }
}

/// Cancels a job.
pub struct JobCancel;

#[async_trait]
impl Command for JobCancel {
    type Args = JobIdArgs;
    type Output = JobView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "job_cancel",
            "Request cancellation of a running job",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc("Cancellation is cooperative; use `job_await` to see the job end as `cancelled`.")
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: JobIdArgs,
    ) -> Result<JobView, ProtoError> {
        Ok(JobView::new(s.jobs().cancel(&JobId(args.job_id))?, false))
    }
}

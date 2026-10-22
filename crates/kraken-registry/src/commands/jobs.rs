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
            "Finds the functions, types and references of the binary. Returns a `job_id`: wait \
             with `job_await`. Run it once after opening a new project; other tools give partial \
             results until it finishes. If it is already running, that job is returned.\n\
             Example: analyze {}",
        )
        .details(
            "Runs the staged analysis (load, core, expensive) as a job. Edits made meanwhile are \
             logged and reported as `queued`; they are pushed to the engine when analysis \
             completes.",
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

/// How often a running analysis reports, even when the engine says nothing.
pub const ANALYSIS_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(2);
/// Processor use below which the engine counts as quiet.
const QUIET_CPU_PERCENT: u32 = 3;

async fn analyse(
    project: &crate::session::Project,
    reporter: &crate::jobs::JobReporter,
) -> Result<kraken_engine::AnalysisSummary, ProtoError> {
    let engine = project.engine();
    let analyzer = engine.analyzer().ok_or_else(|| unsupported("analyzer"))?;
    let mut job = analyzer
        .analyze(AnalyzeRequest::default(), reporter.cancel_token())
        .await?;
    let started = std::time::Instant::now();
    let mut sampler = engine.process_id().map(crate::activity::CpuSampler::new);
    let mut cpu: Option<u32> = None;
    let mut last_sign = started;
    let mut last = JobProgress {
        phase: "load".into(),
        message: "starting the analysis".into(),
        ..Default::default()
    };
    let mut tick = tokio::time::interval(ANALYSIS_HEARTBEAT);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            p = job.next_progress() => {
                let Some(p) = p else { break };
                let next = JobProgress {
                    phase: p.stage.as_str().to_string(),
                    done: p.done,
                    total: p.total,
                    message: sanitize(&p.message),
                    step: p.step.map(|s| crate::jobs::JobStep {
                        name: sanitize(&s.name),
                        done: s.done,
                        total: s.total,
                    }),
                    ..Default::default()
                };
                if (&next.phase, next.done, &next.message, &next.step)
                    != (&last.phase, last.done, &last.message, &last.step)
                {
                    last_sign = std::time::Instant::now();
                }
                last = next;
            }
            _ = tick.tick() => {
                if let Some(s) = sampler.as_mut() {
                    cpu = s.sample();
                    if cpu.is_some_and(|c| c >= QUIET_CPU_PERCENT) {
                        last_sign = std::time::Instant::now();
                    }
                }
            }
        }
        reporter.progress(JobProgress {
            elapsed_ms: Some(started.elapsed().as_millis() as u64),
            activity: cpu.map(|c| crate::jobs::EngineActivity {
                cpu_percent: c,
                quiet_secs: last_sign.elapsed().as_secs(),
            }),
            ..last.clone()
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
    /// For a `project_create` or `project_open` job: the stage list, the current stage, the
    /// overall fraction and the function counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_progress: Option<kraken_proto::OpenProgress>,
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
            open_progress: s.open,
        }
    }
}

/// Arguments naming a job.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobIdArgs {
    /// Job id such as `job-1`, or `open-1` for a project that is opening.
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
        .doc(
            "Looks at a job without waiting: `status` is `running`, `succeeded`, `failed` \
             or `cancelled`, with `progress` while it runs and the `result` once it succeeded. \
             A project that is opening is the job `open-N` (named in its progress events), with \
             its stages in `open_progress`. To block until it ends use `job_await`.\n\
             Example: job_status {\"job_id\": \"job-1\"}",
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
            "Blocks until the job ends and returns it. After `timeout_ms` it returns early with \
             `timed_out: true` and the job still running: call again to keep waiting.\n\
             Example: job_await {\"job_id\": \"job-1\", \"timeout_ms\": 60000}",
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
        .doc(
            "Asks a running job to stop. It stops cooperatively: `job_await` shows when it ends \
             as `cancelled`. Cancelling an `open-N` job stops opening that project; nothing of \
             it stays open.\n\
             Example: job_cancel {\"job_id\": \"job-1\"}",
        )
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

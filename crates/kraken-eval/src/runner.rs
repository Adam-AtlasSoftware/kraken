//! Running a suite: prepare each binary, ask every task, score the reply.
//!
//! The runner knows nothing about which model or agent answers, or which engine serves the
//! tools. An [`Environment`] opens the binaries (a recorded fixture in CI, a real engine live) and
//! an [`AssistantSource`] hands out the assistant for each task (a cassette, a fake agent, a
//! configured API or terminal agent).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_agent::{AgentEvent, StopReason};
use kraken_assist::{Assistant, BackendInfo, Budget, Task, TaskResult};
use kraken_host::backend::CommandBackend;
use kraken_registry::Registry;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::corpus::Corpus;
use crate::error::EvalError;
use crate::report::{
    MAX_REPLY, Price, REPORT_VERSION, Report, Summary, TaskReport, TokenUse, TranscriptEntry, clip,
};
use crate::score::{extract_answer, score};
use crate::suite::{Kind, ResolvedTask, Suite};

/// A binary opened for the tasks that ask about it.
#[derive(Clone)]
pub struct Prepared {
    /// Corpus binary name.
    pub binary: String,
    /// Where the tools run.
    pub backend: Arc<dyn CommandBackend>,
    /// The project directory, which a terminal agent's KRAKEN server opens.
    pub project_dir: Option<PathBuf>,
    /// The address the engine loaded the image at.
    pub base: u64,
}

/// Opens corpus binaries for a run. Its futures need not be `Send`: a run is driven from one
/// task, and an environment may borrow things (a writer for warnings) that are not.
#[async_trait(?Send)]
pub trait Environment: Send + Sync {
    /// What serves the tools, for the report.
    fn describe(&self) -> String;

    /// True when a run must give the same report every time (no timings).
    fn deterministic(&self) -> bool {
        false
    }

    /// Opens `binary` and analyses it.
    async fn prepare(&self, binary: &str) -> Result<Prepared, EvalError>;

    /// Closes what `prepare` opened.
    async fn finish(&self) {}
}

/// Hands out the assistant that answers each task.
pub trait AssistantSource: Send + Sync {
    /// The assistant for `task` on the opened binary.
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        task: &ResolvedTask,
    ) -> Result<Assistant, EvalError>;

    /// Called after the task ran, with its transcript, so a recorder can save what it saw.
    fn finished(&self, _task: &ResolvedTask) {}
}

/// Which tasks to run and how.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Run only tasks whose id starts with one of these (all when empty).
    pub only: Vec<String>,
    /// Run only these kinds (all when empty).
    pub kinds: Vec<Kind>,
    /// Stop after this many tasks.
    pub limit: Option<usize>,
    /// Longest a task may run before it is cancelled.
    pub timeout: Duration,
    /// Dollars per million tokens, for a cost estimate.
    pub price: Option<Price>,
    /// `live`, `ci-replay` or `ci-agent`; goes into the report.
    pub mode: String,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            only: Vec::new(),
            kinds: Vec::new(),
            limit: None,
            timeout: Duration::from_secs(900),
            price: None,
            mode: "live".into(),
        }
    }
}

impl RunOptions {
    /// True when the options select `id` of `kind`.
    pub fn selects(&self, id: &str, kind: Kind) -> bool {
        (self.only.is_empty() || self.only.iter().any(|p| id.starts_with(p.as_str())))
            && (self.kinds.is_empty() || self.kinds.contains(&kind))
    }
}

fn budget_for(kind: Kind) -> Budget {
    let (steps, calls) = match kind {
        Kind::NameFunctions => (40, 60),
        Kind::FindFunction => (24, 30),
        Kind::Question => (16, 20),
    };
    Budget {
        max_steps: steps,
        max_tool_calls: calls,
        token_budget: Some(400_000),
        max_tokens: Some(2500),
        temperature: Some(0.0),
    }
}

/// Runs a suite against one environment and one assistant source.
pub struct Runner<'a> {
    /// The corpus.
    pub corpus: &'a Corpus,
    /// Opens the binaries.
    pub env: &'a dyn Environment,
    /// Answers the tasks.
    pub source: &'a dyn AssistantSource,
    /// The command registry the tools come from.
    pub registry: Arc<Registry>,
    /// What to run.
    pub options: RunOptions,
}

impl Runner<'_> {
    /// Runs the selected tasks of `suite` and returns the report. `progress` is called after
    /// each task. Binaries are opened one at a time, in order of first use.
    pub async fn run(
        &self,
        suite: &Suite,
        progress: &mut dyn FnMut(&TaskReport),
    ) -> Result<Report, EvalError> {
        suite.check_shape()?;
        let mut selected: Vec<&crate::suite::TaskDef> = suite
            .tasks
            .iter()
            .filter(|t| self.options.selects(&t.id, t.kind))
            .collect();
        if let Some(n) = self.options.limit {
            selected.truncate(n);
        }
        if selected.is_empty() {
            return Err(EvalError::Suite("no task matches the selection".into()));
        }
        let started = Instant::now();
        let mut reports: Vec<TaskReport> = Vec::new();
        let mut backend_info: Option<BackendInfo> = None;
        let mut binaries: Vec<&str> = Vec::new();
        for t in &selected {
            if !binaries.contains(&t.binary.as_str()) {
                binaries.push(&t.binary);
            }
        }
        for binary in binaries {
            let prepared = self.env.prepare(binary).await?;
            let truth = self.corpus.truth(binary)?;
            for def in selected.iter().filter(|t| t.binary == binary) {
                let task = def.resolve(&truth, prepared.base)?;
                let assistant = self.source.assistant(&self.registry, &prepared, &task)?;
                backend_info.get_or_insert_with(|| assistant.backend_info());
                let report = self.run_task(&assistant, &task).await;
                self.source.finished(&task);
                progress(&report);
                reports.push(report);
            }
        }
        self.env.finish().await;
        let duration = (!self.env.deterministic()).then(|| started.elapsed().as_millis() as u64);
        let backend =
            backend_info.ok_or_else(|| EvalError::Backend("no assistant was created".into()))?;
        Ok(Report {
            schema_version: REPORT_VERSION,
            suite: suite.name.clone(),
            mode: self.options.mode.clone(),
            backend,
            engine: self.env.describe(),
            summary: Summary::of(&reports, duration),
            tasks: reports,
        })
    }

    async fn run_task(&self, assistant: &Assistant, task: &ResolvedTask) -> TaskReport {
        let assist_task = Task::custom(
            &self.registry,
            &task.goal,
            &task.instructions,
            budget_for(task.kind),
        );
        let cancel = CancellationToken::new();
        let mut transcript = Transcript::new(&task.goal);
        let started = Instant::now();
        // A task that runs too long is cancelled; the run then ends as `cancelled` with whatever
        // it had said so far.
        let timer = {
            let cancel = cancel.clone();
            let limit = self.options.timeout;
            tokio::spawn(async move {
                tokio::time::sleep(limit).await;
                cancel.cancel();
            })
        };
        let result = assistant
            .run(assist_task, &cancel, &mut |e| transcript.event(e))
            .await;
        timer.abort();
        let timed_out = cancel.is_cancelled();
        let duration = (!self.env.deterministic()).then(|| started.elapsed().as_millis() as u64);
        let mut report = self.report_of(task, result, transcript.finish(), duration);
        if timed_out {
            report.problem = Some(format!(
                "timed out after {} s",
                self.options.timeout.as_secs()
            ));
        }
        report
    }

    fn report_of(
        &self,
        task: &ResolvedTask,
        result: TaskResult,
        transcript: Vec<TranscriptEntry>,
        duration_ms: Option<u64>,
    ) -> TaskReport {
        let answer = extract_answer(&result.text);
        let scored = score(&task.expected, answer.as_ref().map_err(String::as_str));
        let mut problem = scored.problem.clone();
        let failed = matches!(result.stop, StopReason::Error | StopReason::Cancelled);
        if problem.is_none() && failed {
            problem = Some(format!("the run ended early ({})", stop_name(result.stop)));
        }
        if let Some(e) = &result.error {
            problem = Some(
                format!("{} ({e})", problem.unwrap_or_default())
                    .trim()
                    .to_string(),
            );
        }
        let reported = result.usage.input_tokens + result.usage.output_tokens > 0;
        let tokens = reported.then_some(TokenUse {
            input: result.usage.input_tokens,
            output: result.usage.output_tokens,
        });
        TaskReport {
            id: task.id.clone(),
            kind: task.kind,
            binary: task.binary.clone(),
            score: round4(scored.score),
            correct: scored.correct,
            problem,
            detail: scored.detail,
            answer: answer.ok(),
            reply: clip(&result.text, MAX_REPLY),
            stop: stop_name(result.stop).to_string(),
            error: result.error.clone(),
            tokens,
            cost_usd: match (tokens, self.options.price) {
                (Some(t), Some(p)) => Some(p.cost(t)),
                _ => None,
            },
            tool_calls: result.tool_calls.len(),
            tool_errors: result.tool_calls.iter().filter(|c| c.is_error).count(),
            duration_ms,
            transcript,
        }
    }
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

fn stop_name(s: StopReason) -> &'static str {
    match s {
        StopReason::Completed => "completed",
        StopReason::MaxSteps => "max_steps",
        StopReason::MaxToolCalls => "max_tool_calls",
        StopReason::TokenBudget => "token_budget",
        StopReason::Cancelled => "cancelled",
        StopReason::Error => "error",
    }
}

/// Folds the event stream of a run into transcript entries.
struct Transcript {
    entries: Vec<TranscriptEntry>,
    text: String,
    pending: Vec<(String, String, Value)>,
}

impl Transcript {
    fn new(goal: &str) -> Transcript {
        Transcript {
            entries: vec![TranscriptEntry::Prompt {
                text: goal.to_string(),
            }],
            text: String::new(),
            pending: Vec::new(),
        }
    }

    fn flush_text(&mut self) {
        let t = std::mem::take(&mut self.text);
        if !t.trim().is_empty() {
            self.entries.push(TranscriptEntry::Text { text: t });
        }
    }

    fn event(&mut self, e: &AgentEvent) {
        match e {
            AgentEvent::TextDelta { text } => self.text.push_str(text),
            AgentEvent::ToolCallStarted {
                id,
                name,
                arguments,
            } => {
                self.flush_text();
                self.pending
                    .push((id.clone(), name.clone(), arguments.clone()));
            }
            AgentEvent::ToolCallFinished {
                id,
                name,
                summary,
                is_error,
            } => {
                let arguments = self
                    .pending
                    .iter()
                    .position(|(p, _, _)| p == id)
                    .map(|i| self.pending.remove(i).2)
                    .unwrap_or(Value::Null);
                self.entries.push(TranscriptEntry::ToolCall {
                    name: name.clone(),
                    arguments,
                    result: clip(summary, 300),
                    is_error: *is_error,
                });
            }
            AgentEvent::Error { message } => {
                self.flush_text();
                self.entries.push(TranscriptEntry::Error {
                    message: message.clone(),
                });
            }
            AgentEvent::Done { stop, .. } => {
                self.flush_text();
                self.entries.push(TranscriptEntry::Done {
                    stop: stop_name(*stop).to_string(),
                });
            }
            AgentEvent::ApprovalRequired { .. } | AgentEvent::ProposalCreated { .. } => {}
        }
    }

    fn finish(mut self) -> Vec<TranscriptEntry> {
        self.flush_text();
        self.entries
    }
}

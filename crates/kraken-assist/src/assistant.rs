//! Running a [`Task`]: the agent loop over a [`RegistryToolHost`], and parsing its answer.

use std::sync::Arc;

use kraken_agent::{
    AgentEvent, ApprovalHandle, ChatProvider, Message, ProviderInfo, StopReason, Usage,
};
use kraken_host::RunIdGen;
use kraken_host::backend::CommandBackend;
use kraken_proto::sanitize;
use kraken_registry::{Registry, Surface};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::ASSISTANT_ID;
use crate::backend::{ApiBackend, AssistBackend, BackendKind, Purpose, RunSpec};
use crate::host::{HostOptions, RegistryToolHost};
use crate::output::{
    RESULT_OPEN, TaskOutput, build_autoname, parse_explanation, parse_overview, split_result,
};
use crate::tasks::{Task, TaskKind};

/// One tool call, for display and audit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCallSummary {
    /// Command name.
    pub name: String,
    /// Arguments as sent.
    pub arguments: Value,
    /// Short sanitised summary of the result.
    pub summary: String,
    /// True when the call failed.
    pub is_error: bool,
}

/// What a task run produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskResult {
    /// Which task.
    pub task: TaskKind,
    /// The run id edits were logged under (`undo_run` takes it).
    pub run_id: String,
    /// The provider and model that answered (for a terminal agent: the agent and its model).
    pub provider: ProviderInfo,
    /// Which kind of backend answered.
    #[serde(default)]
    pub backend: BackendKind,
    /// The answer text without the machine-readable block.
    pub text: String,
    /// The parsed result, when the model produced one.
    pub output: Option<TaskOutput>,
    /// Why the output is partial or missing, if it is.
    pub warnings: Vec<String>,
    /// Things this build could not offer.
    pub notes: Vec<String>,
    /// How the run ended.
    pub stop: StopReason,
    /// The error message when `stop` is `Error`.
    pub error: Option<String>,
    /// Token usage.
    pub usage: Usage,
    /// Every tool call, in order.
    pub tool_calls: Vec<ToolCallSummary>,
    /// Proposals created by the run (writes the registry held back for review).
    pub proposals: Vec<Value>,
}

/// Called with each run's approval handle, so the caller can answer approval requests.
type Approver = Arc<dyn Fn(ApprovalHandle) + Send + Sync>;

/// Runs tasks with one assistant backend (a model API or a terminal agent) against one command
/// backend.
pub struct Assistant {
    registry: Arc<Registry>,
    backend: Arc<dyn CommandBackend>,
    engine: Arc<dyn AssistBackend>,
    surface: Surface,
    agent_id: String,
    run_ids: RunIdGen,
    approver: Option<Approver>,
}

impl Assistant {
    /// An assistant that calls registry commands through `backend`, answered by the model API
    /// `provider`.
    pub fn new(
        registry: Arc<Registry>,
        backend: Arc<dyn CommandBackend>,
        provider: Arc<dyn ChatProvider>,
    ) -> Self {
        Self::with_engine(registry, backend, Arc::new(ApiBackend::new(provider)))
    }

    /// An assistant answered by `engine`: a model API ([`ApiBackend`]) or a terminal agent
    /// ([`AcpBackend`](crate::AcpBackend)). `backend` serves the API path's tools; a terminal
    /// agent reaches the registry through its own MCP server instead.
    pub fn with_engine(
        registry: Arc<Registry>,
        backend: Arc<dyn CommandBackend>,
        engine: Arc<dyn AssistBackend>,
    ) -> Self {
        Assistant {
            registry,
            backend,
            engine,
            surface: Surface::Cli,
            agent_id: ASSISTANT_ID.to_string(),
            run_ids: RunIdGen::new(),
            approver: None,
        }
    }

    /// Hands every run's approval handle to `f` and leaves approval requests to it. Without
    /// this, requests are denied (a terminal agent asking to run one of its own tools in a
    /// read-only task, for example).
    pub fn with_approver(mut self, f: impl Fn(ApprovalHandle) + Send + Sync + 'static) -> Self {
        self.approver = Some(Arc::new(f));
        self
    }

    /// What the backend shows about itself.
    pub fn backend_info(&self) -> crate::BackendInfo {
        self.engine.info()
    }

    /// Sets the surface reported to the registry (default `Cli`).
    pub fn with_surface(mut self, surface: Surface) -> Self {
        self.surface = surface;
        self
    }

    /// Sets the agent id edits are logged under (default [`ASSISTANT_ID`]).
    pub fn with_agent_id(mut self, id: impl Into<String>) -> Self {
        self.agent_id = id.into();
        self
    }

    /// The tool host a task would run with (for inspection and tests).
    pub fn host_for(&self, task: &Task) -> RegistryToolHost {
        RegistryToolHost::new(
            self.registry.clone(),
            self.backend.clone(),
            HostOptions {
                agent_id: self.agent_id.clone(),
                surface: self.surface,
                allow: Some(task.allow.clone()),
                read_only: task.read_only,
                max_writes: task.max_writes,
                unlock: task.unlock.clone(),
                job_timeout: task
                    .job_timeout
                    .unwrap_or_else(|| HostOptions::default().job_timeout),
            },
        )
    }

    /// Runs `task`, calling `on_event` for every agent event as it happens (streamed text,
    /// tool calls, proposals). Cancelling `cancel` stops the run.
    ///
    /// A failed model call is not an `Err`: the result has `stop == Error` and the message.
    pub async fn run(
        &self,
        task: Task,
        cancel: &CancellationToken,
        on_event: &mut dyn FnMut(&AgentEvent),
    ) -> TaskResult {
        let run_id = self.run_ids.next_id();
        let host = Arc::new(self.host_for(&task));
        let mut run = self.engine.start(RunSpec {
            messages: vec![Message::user(task.goal.clone())],
            config: task.agent_config(&run_id),
            tools: host.clone(),
            purpose: Purpose::Task {
                read_only: task.read_only,
            },
        });
        if let Some(approver) = &self.approver {
            approver(run.approvals());
        }
        let mut full = String::new();
        let mut last_step = String::new();
        let mut after_tool = false;
        let mut tool_calls: Vec<ToolCallSummary> = Vec::new();
        let mut pending: Vec<(String, Value)> = Vec::new();
        let mut proposals = Vec::new();
        let mut done: Option<(StopReason, Usage)> = None;
        let mut error: Option<String> = None;

        loop {
            let ev = tokio::select! {
                () = cancel.cancelled() => {
                    run.cancel();
                    // Keep draining until Done arrives.
                    match run.next_event().await {
                        Some(e) => e,
                        None => break,
                    }
                }
                e = run.next_event() => match e {
                    Some(e) => e,
                    None => break,
                },
            };
            on_event(&ev);
            match ev {
                AgentEvent::TextDelta { text } => {
                    if after_tool {
                        last_step.clear();
                        after_tool = false;
                    }
                    full.push_str(&text);
                    last_step.push_str(&text);
                }
                AgentEvent::ToolCallStarted { id, arguments, .. } => {
                    after_tool = true;
                    pending.push((id, arguments));
                }
                AgentEvent::ToolCallFinished {
                    id,
                    name,
                    summary,
                    is_error,
                } => {
                    let arguments = pending
                        .iter()
                        .position(|(p, _)| *p == id)
                        .map(|i| pending.remove(i).1)
                        .unwrap_or(Value::Null);
                    tool_calls.push(ToolCallSummary {
                        name,
                        arguments,
                        summary,
                        is_error,
                    });
                }
                AgentEvent::ProposalCreated { proposal, .. } => proposals.push(proposal),
                AgentEvent::Error { message } => error = Some(message),
                AgentEvent::Done { usage, stop, .. } => {
                    done = Some((stop, usage));
                    break;
                }
                AgentEvent::ApprovalRequired { id, .. } => {
                    // Nothing dangerous is offered to a model API, and a terminal agent asking
                    // for one of its own tools has nobody to ask unless an approver is set:
                    // never leave a run hanging.
                    if self.approver.is_none() {
                        run.approvals()
                            .decide(id, kraken_agent::ApprovalDecision::Deny);
                    }
                }
            }
        }

        let (stop, usage) = done.unwrap_or((StopReason::Cancelled, Usage::default()));
        let answer = if last_step.trim().is_empty() {
            &full
        } else {
            &last_step
        };
        let (prose, json) = split_result(answer);
        let stats = self
            .engine
            .take_stats(&run_id)
            .unwrap_or_else(|| host.stats());
        let mut warnings = Vec::new();
        if task.read_only && stats.calls.iter().any(|c| c.is_write && c.ok) {
            warnings.push(format!(
                "the agent changed the project during a read-only task; undo it with `undo_run` ({run_id})"
            ));
        }
        let (output, text) =
            if matches!(stop, StopReason::Error | StopReason::Cancelled) && json.is_none() {
                (None, prose)
            } else {
                match task.kind {
                    TaskKind::ExplainFunction | TaskKind::ExplainSelection => {
                        let (e, w) = parse_explanation(&prose, json);
                        warnings.extend(w);
                        (Some(TaskOutput::Explanation(e)), prose)
                    }
                    TaskKind::Overview => {
                        let (mut o, w) = parse_overview(&prose, json);
                        o.missing_data = task.notes.clone();
                        warnings.extend(w);
                        (Some(TaskOutput::Overview(o)), prose)
                    }
                    TaskKind::Custom | TaskKind::Automate => (None, prose),
                    TaskKind::AutoName => {
                        let opts = task.autoname.unwrap_or_default();
                        let (r, w) = build_autoname(json, &stats, opts.dry_run, opts.limit);
                        warnings.extend(w);
                        (Some(TaskOutput::AutoName(r)), prose)
                    }
                }
            };
        match stop {
            StopReason::Completed => {}
            StopReason::Error => {}
            other => warnings.push(format!("the run stopped early ({other:?})")),
        }
        TaskResult {
            task: task.kind,
            run_id,
            provider: self.engine.provider_info(),
            backend: self.engine.info().kind,
            text: sanitize(&text),
            output,
            warnings,
            notes: {
                let mut notes = task.notes;
                notes.extend(self.engine.take_notes());
                notes
            },
            stop,
            error,
            usage,
            tool_calls,
            proposals,
        }
    }
}

/// Hides the trailing `<kraken-result>...` block of streamed text.
///
/// Feed it each text delta; it returns what is safe to show. Text that could be the start of the
/// tag is held back until the next chunk settles it.
#[derive(Debug, Default)]
pub struct ResultTagFilter {
    held: String,
    hidden: bool,
}

impl ResultTagFilter {
    /// A filter at the start of a stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the filter (a new model step begins).
    pub fn reset(&mut self) {
        self.held.clear();
        self.hidden = false;
    }

    /// Takes the next chunk and returns the visible part.
    pub fn push(&mut self, chunk: &str) -> String {
        if self.hidden {
            return String::new();
        }
        self.held.push_str(chunk);
        if let Some(i) = self.held.find(RESULT_OPEN) {
            let visible = self.held[..i].to_string();
            self.hidden = true;
            self.held.clear();
            return visible;
        }
        // Hold back the longest suffix that is a proper prefix of the tag.
        let keep = (1..RESULT_OPEN.len().min(self.held.len() + 1))
            .rev()
            .find(|&n| {
                self.held.is_char_boundary(self.held.len() - n)
                    && RESULT_OPEN.starts_with(&self.held[self.held.len() - n..])
            })
            .unwrap_or(0);
        let cut = self.held.len() - keep;
        let visible = self.held[..cut].to_string();
        self.held = self.held[cut..].to_string();
        visible
    }

    /// Ends the stream; returns text that was held back but turned out not to be a tag.
    pub fn finish(&mut self) -> String {
        if self.hidden {
            return String::new();
        }
        std::mem::take(&mut self.held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&str]) -> String {
        let mut f = ResultTagFilter::new();
        let mut out = String::new();
        for c in chunks {
            out.push_str(&f.push(c));
        }
        out.push_str(&f.finish());
        out
    }

    #[test]
    fn the_result_block_is_hidden_however_it_is_chunked() {
        let whole = "Hello <kraken-result>{\"a\":1}</kraken-result>";
        assert_eq!(run(&[whole]), "Hello ");
        assert_eq!(run(&["Hello <krak", "en-res", "ult>{}"]), "Hello ");
        let chars: Vec<String> = whole.chars().map(String::from).collect();
        let refs: Vec<&str> = chars.iter().map(String::as_str).collect();
        assert_eq!(run(&refs), "Hello ");
    }

    #[test]
    fn near_misses_are_released() {
        assert_eq!(run(&["a <kraken", "-ish text"]), "a <kraken-ish text");
        assert_eq!(run(&["ends with <kra"]), "ends with <kra");
        assert_eq!(run(&["x < y"]), "x < y");
    }
}

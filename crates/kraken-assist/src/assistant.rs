//! Running a [`Task`]: the agent loop over a [`RegistryToolHost`], and parsing its answer.

use std::sync::Arc;

use kraken_agent::{Agent, AgentEvent, ChatProvider, Message, ProviderInfo, StopReason, Usage};
use kraken_host::RunIdGen;
use kraken_host::backend::CommandBackend;
use kraken_proto::sanitize;
use kraken_registry::{Registry, Surface};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::ASSISTANT_ID;
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
    /// The provider and model that answered.
    pub provider: ProviderInfo,
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

/// Runs tasks with one provider against one backend.
pub struct Assistant {
    registry: Arc<Registry>,
    backend: Arc<dyn CommandBackend>,
    provider: Arc<dyn ChatProvider>,
    surface: Surface,
    agent_id: String,
    run_ids: RunIdGen,
}

impl Assistant {
    /// An assistant that calls registry commands through `backend`.
    pub fn new(
        registry: Arc<Registry>,
        backend: Arc<dyn CommandBackend>,
        provider: Arc<dyn ChatProvider>,
    ) -> Self {
        Assistant {
            registry,
            backend,
            provider,
            surface: Surface::Cli,
            agent_id: ASSISTANT_ID.to_string(),
            run_ids: RunIdGen::new(),
        }
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
                ..HostOptions::default()
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
        let mut run = Agent::run(
            vec![Message::user(task.goal.clone())],
            host.clone(),
            self.provider.clone(),
            task.agent_config(&run_id),
        );
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
                    // Nothing dangerous is ever offered, but never leave a run hanging.
                    run.approvals()
                        .decide(id, kraken_agent::ApprovalDecision::Deny);
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
        let stats = host.stats();
        let mut warnings = Vec::new();
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
            provider: self.provider.info(),
            text: sanitize(&text),
            output,
            warnings,
            notes: task.notes,
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

//! Assistant sources: the things that answer the tasks.
//!
//! - [`ApiSource`]: a chat model API (hosted, or local through Ollama or llama-server).
//! - [`RecordingSource`]: an [`ApiSource`] that also records every exchange into an
//!   [`EvalCassette`].
//! - [`ReplaySource`]: replays an [`EvalCassette`] through `ReplayProvider`; no network.
//! - [`FakeAgentSource`]: the fake ACP agent, which replays a script; no network, no account.
//! - [`FnSource`]: anything else (a terminal agent the CLI planned), from a closure.

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_acp::{AgentProfile, LaunchSpec, McpServerConfig};
use kraken_agent::{ChatProvider, ProviderInfo, RecordingProvider, ReplayProvider};
use kraken_assist::{AcpBackend, AcpSettings, ApiBackend, AssistBackend, Assistant, UnusedBackend};
use kraken_registry::Registry;

use crate::cassette::EvalCassette;
use crate::error::EvalError;
use crate::runner::{AssistantSource, Prepared};
use crate::suite::ResolvedTask;

/// A chat model API answers.
pub struct ApiSource {
    provider: Arc<dyn ChatProvider>,
}

impl ApiSource {
    /// A source over `provider`.
    pub fn new(provider: Arc<dyn ChatProvider>) -> Self {
        ApiSource { provider }
    }
}

impl AssistantSource for ApiSource {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        _task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        Ok(Assistant::with_engine(
            registry.clone(),
            prepared.backend.clone(),
            Arc::new(ApiBackend::new(self.provider.clone())),
        ))
    }
}

/// A chat model API answers and every exchange is recorded.
pub struct RecordingSource {
    inner: Arc<dyn ChatProvider>,
    recorders: Mutex<Vec<(String, Arc<RecordingProvider>)>>,
    cassette: Mutex<EvalCassette>,
}

impl RecordingSource {
    /// A recorder over `provider`; `note` says what is being recorded (model, date).
    pub fn new(provider: Arc<dyn ChatProvider>, note: impl Into<String>) -> Self {
        RecordingSource {
            inner: provider,
            recorders: Mutex::new(Vec::new()),
            cassette: Mutex::new(EvalCassette::new(note)),
        }
    }

    /// What has been recorded so far.
    pub fn cassette(&self) -> EvalCassette {
        self.cassette
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl AssistantSource for RecordingSource {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        let rec = Arc::new(RecordingProvider::new(self.inner.clone()));
        self.recorders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((task.id.clone(), rec.clone()));
        Ok(Assistant::with_engine(
            registry.clone(),
            prepared.backend.clone(),
            Arc::new(ApiBackend::new(rec)),
        ))
    }

    fn finished(&self, task: &ResolvedTask) {
        let mut recorders = self
            .recorders
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(i) = recorders.iter().position(|(id, _)| *id == task.id) {
            let (_, rec) = recorders.remove(i);
            let steps: Vec<_> = rec
                .cassette()
                .entries
                .into_iter()
                .map(|e| e.events)
                .collect();
            self.cassette
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .tasks
                .insert(task.id.clone(), steps);
        }
    }
}

/// A cassette answers, through `ReplayProvider`.
pub struct ReplaySource {
    cassette: EvalCassette,
}

impl ReplaySource {
    /// A source over `cassette`.
    pub fn new(cassette: EvalCassette) -> Self {
        ReplaySource { cassette }
    }
}

impl AssistantSource for ReplaySource {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        let steps = self.cassette.tasks.get(&task.id).ok_or_else(|| {
            EvalError::Cassette(format!(
                "no recording for task `{}`; record it again or choose another cassette",
                task.id
            ))
        })?;
        let provider = ReplayProvider::scripted(steps.clone()).with_info(ProviderInfo {
            id: "replay".into(),
            model: self.cassette.recorded_with.clone(),
            supports_tools: true,
            context_window: None,
        });
        Ok(Assistant::with_engine(
            registry.clone(),
            prepared.backend.clone(),
            Arc::new(ApiBackend::new(Arc::new(provider))),
        ))
    }
}

/// The fake ACP agent answers from a script file.
pub struct FakeAgentSource {
    /// The `kraken-fake-acp-agent` executable.
    pub agent: PathBuf,
    /// Arguments the executable needs to act as the fake agent (`agents __fake-agent` when it is
    /// the `kraken` binary).
    pub args: Vec<String>,
    /// The script (`{"<task id>": {"tools": [...], "answer": "..."}}`).
    pub script: PathBuf,
    open: Mutex<Vec<Arc<AcpBackend>>>,
}

impl FakeAgentSource {
    /// A source that starts `agent` for every task, giving it `script`.
    pub fn new(agent: PathBuf, script: PathBuf) -> Self {
        FakeAgentSource {
            agent,
            args: Vec::new(),
            script,
            open: Mutex::new(Vec::new()),
        }
    }

    /// Passes `args` to the executable.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

impl AssistantSource for FakeAgentSource {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        _task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        let dir = prepared.project_dir.clone().ok_or_else(|| {
            EvalError::Backend("a terminal agent needs a project directory".into())
        })?;
        let profile = AgentProfile::custom(
            "fake",
            "Fake agent",
            self.agent.to_string_lossy(),
            self.args.clone(),
        )
        .with_env("FAKE_ACP_EVAL_ANSWERS", self.script.to_string_lossy());
        let settings = AcpSettings {
            profile,
            launch: LaunchSpec {
                program: self.agent.clone(),
                args: self.args.iter().map(OsString::from).collect(),
                path_prepend: None,
                via: "kraken eval".into(),
            },
            // The fake agent only checks that KRAKEN's server is announced; it never starts it.
            mcp: McpServerConfig::project("kraken", &dir),
            project_dir: dir,
            parent_env: Some(vec![
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                (OsString::from("HOME"), OsString::from("/nonexistent")),
            ]),
            start_timeout: Duration::from_secs(30),
            model: None,
        };
        let backend = Arc::new(AcpBackend::new(settings, registry.clone()));
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(backend.clone());
        Ok(Assistant::with_engine(
            registry.clone(),
            Arc::new(UnusedBackend),
            backend,
        ))
    }

    fn finished(&self, _task: &ResolvedTask) {
        for b in self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            b.close();
        }
    }
}

/// Anything else, built by a closure (the CLI plans a terminal agent per project this way).
pub struct FnSource<F>(pub F);

impl<F> AssistantSource for FnSource<F>
where
    F: Fn(&Arc<Registry>, &Prepared, &ResolvedTask) -> Result<Assistant, EvalError> + Send + Sync,
{
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        (self.0)(registry, prepared, task)
    }
}

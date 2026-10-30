//! Rewrite quality as a number: the `rewrite_function` and `rewrite_program` tasks of a suite,
//! scored by the differential verdict.
//!
//! A task opens a corpus binary on `engine-fake` over its recorded fixture, runs the rewrite
//! pipeline of `kraken-rewrite` (`RewriteService`, the backend of the `rewrite_*` commands)
//! through [`AssistBackend::complete_text`](kraken_assist::AssistBackend::complete_text), builds
//! the generated Rust in the sandbox and tests it against the original, exactly as a person's
//! `rewrite_function` or `rewrite_program` call would. What is measured:
//!
//! - the verdict (`pass` is a correct task; the score is the share of cases that agreed),
//! - cases run and cases that agreed (function level for a function task, program level for a
//!   program task),
//! - repair rounds (attempts after the first of every function, plus program-level rounds),
//! - model calls, tokens and cost.
//!
//! The model answers come from one of three places. In CI a cassette replays the recorded
//! replies of each task in order (`EvalCassette`, `ReplayProvider::scripted`): no network, no
//! model. `KRAKEN_EVAL_BLESS=1` in the CI test rewrites the committed cassette from the
//! reference translations of `kraken-rewrite/references`. A live run asks the configured model
//! and can record its exchanges as a new cassette.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use kraken_agent::{
    AgentError, AgentRun, ChatProvider, ChatRequest, FinishReason, Message, ProviderInfo,
    RecordingProvider, ReplayProvider, StreamEvent, Usage,
};
use kraken_assist::{ApiBackend, AssistBackend, BackendInfo, HostStats, RunSpec, TextFuture};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::oracle::OracleConfig;
use kraken_rewrite::service::{FixedBackend, RewriteConfig, RewriteService};
use kraken_rewrite::task::RewriteTask;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::cassette::EvalCassette;
use crate::corpus::{Corpus, engine_address};
use crate::error::EvalError;
use crate::report::{
    MAX_REPLY, Price, REPORT_VERSION, Report, Summary, TaskReport, TokenUse, TranscriptEntry, clip,
};
use crate::runner::RunOptions;
use crate::suite::{Suite, TaskDef};

/// The committed cassette of the built-in rewrite suite (reference translations, not a model).
pub const CASSETTE_JSON: &str = include_str!("../data/rewrite-cassette.json");

/// The committed cassette of the built-in rewrite suite.
pub fn committed_cassette() -> Result<EvalCassette, EvalError> {
    EvalCassette::from_json(CASSETTE_JSON)
}

/// What one rewrite task measured.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewriteMetrics {
    /// `pass`, `fail`, `rejected`, `inconclusive`, or `error` when the pipeline did not finish.
    pub verdict: String,
    /// Functions translated (1 for a function task).
    pub units: u32,
    /// Of those, the ones that did not pass.
    pub units_failed: u32,
    /// Differential cases that ran on both sides.
    pub cases_run: u32,
    /// Cases on which the rewrite agreed with the original.
    pub cases_passed: u32,
    /// Attempts after the first, summed over the functions, plus program-level repair rounds.
    pub repair_rounds: u32,
    /// Requests sent to the model.
    pub model_calls: u32,
    /// Why a function was rejected or the verdict inconclusive, when the pipeline said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The rewrite numbers of a whole run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RewriteSummary {
    /// Rewrite tasks run.
    pub tasks: usize,
    /// Tasks whose verdict was `pass`.
    pub passed: usize,
    /// `passed / tasks`.
    pub pass_rate: f64,
    /// Cases run, summed.
    pub cases_run: u32,
    /// Cases that agreed, summed.
    pub cases_passed: u32,
    /// `cases_passed / cases_run`.
    pub case_pass_rate: f64,
    /// Repair rounds, summed.
    pub repair_rounds: u32,
    /// Model calls, summed.
    pub model_calls: u32,
    /// Functions translated, summed.
    pub units: u32,
    /// Of those, the ones that did not pass.
    pub units_failed: u32,
}

fn round4(x: f64) -> f64 {
    (x * 10_000.0).round() / 10_000.0
}

impl RewriteSummary {
    /// The totals over the rewrite tasks among `tasks`; `None` when there are none.
    pub fn of(tasks: &[TaskReport]) -> Option<RewriteSummary> {
        let rows: Vec<&RewriteMetrics> = tasks.iter().filter_map(|t| t.rewrite.as_ref()).collect();
        if rows.is_empty() {
            return None;
        }
        let mut s = RewriteSummary {
            tasks: rows.len(),
            ..RewriteSummary::default()
        };
        for m in &rows {
            s.passed += usize::from(m.verdict == "pass");
            s.cases_run += m.cases_run;
            s.cases_passed += m.cases_passed;
            s.repair_rounds += m.repair_rounds;
            s.model_calls += m.model_calls;
            s.units += m.units;
            s.units_failed += m.units_failed;
        }
        s.pass_rate = round4(s.passed as f64 / s.tasks as f64);
        s.case_pass_rate = if s.cases_run == 0 {
            0.0
        } else {
            round4(f64::from(s.cases_passed) / f64::from(s.cases_run))
        };
        Some(s)
    }
}

/// Where the model's answers come from.
pub enum Answers {
    /// Replay the recorded replies of each task, in order.
    Replay(EvalCassette),
    /// Ask this provider (a model, or the reference translations when blessing) and record the
    /// exchanges; `note` goes into the recorded cassette.
    Live {
        /// The model API.
        provider: Arc<dyn ChatProvider>,
        /// What is being recorded.
        note: String,
    },
}

/// The provider of one task, and the recorder around it when its replies are being recorded.
type Provided = (Arc<dyn ChatProvider>, Option<Arc<RecordingProvider>>);

/// Counts the model calls and tokens of one task.
struct CountingBackend {
    inner: Arc<dyn AssistBackend>,
    calls: Mutex<u32>,
    usage: Mutex<Usage>,
}

impl AssistBackend for CountingBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }

    fn provider_info(&self) -> ProviderInfo {
        self.inner.provider_info()
    }

    fn start(&self, spec: RunSpec) -> AgentRun {
        self.inner.start(spec)
    }

    fn take_stats(&self, run_id: &str) -> Option<HostStats> {
        self.inner.take_stats(run_id)
    }

    fn take_notes(&self) -> Vec<String> {
        self.inner.take_notes()
    }

    fn close(&self) {
        self.inner.close();
    }

    // The rewrite service's meter wraps a backend that offers its chat provider at that level,
    // past this counter; saying there is none makes it wrap the backend itself.
    fn chat_provider(&self) -> Option<Arc<dyn ChatProvider>> {
        None
    }

    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_> {
        Box::pin(async move {
            *self.calls.lock().unwrap_or_else(PoisonError::into_inner) += 1;
            let reply = self.inner.complete_text(req, cancel).await?;
            self.usage
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .add(reply.usage);
            Ok(reply)
        })
    }
}

struct FixtureFactory {
    fixture: engine_fake::FixtureFile,
}

#[async_trait]
impl EngineFactory for FixtureFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(engine_fake::FakeEngine::new(self.fixture.clone())))
    }
}

/// Runs the rewrite tasks of a suite.
pub struct RewriteRunner<'a> {
    /// The corpus.
    pub corpus: &'a Corpus,
    /// Where the projects and generated crates go (one folder per task).
    pub work: PathBuf,
    /// Where the model answers come from.
    pub answers: Answers,
    /// What to run (selection, limit, timeout, price, mode).
    pub options: RunOptions,
    /// A Ghidra install for the SLEIGH specs of the function-level oracle; the spec roots
    /// `kraken-emu` discovers are used without it.
    pub ghidra_home: Option<PathBuf>,
    /// Run the function-level differential test in program tasks (needs the SLEIGH specs).
    /// Without it a program task is judged by its program-level test alone.
    pub verify_functions: bool,
    recorded: Mutex<Option<EvalCassette>>,
}

impl<'a> RewriteRunner<'a> {
    /// A runner; `verify_functions` is off.
    pub fn new(
        corpus: &'a Corpus,
        work: PathBuf,
        answers: Answers,
        options: RunOptions,
        ghidra_home: Option<PathBuf>,
    ) -> Self {
        let recorded = match &answers {
            Answers::Live { note, .. } => Some(EvalCassette::new(note.clone())),
            Answers::Replay(_) => None,
        };
        RewriteRunner {
            corpus,
            work,
            answers,
            options,
            ghidra_home,
            verify_functions: false,
            recorded: Mutex::new(recorded),
        }
    }

    /// What a live run has recorded so far (`None` when replaying).
    pub fn recorded(&self) -> Option<EvalCassette> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Runs the selected tasks and returns the report; `progress` is called after each task.
    pub async fn run(
        &self,
        suite: &Suite,
        progress: &mut dyn FnMut(&TaskReport),
    ) -> Result<Report, EvalError> {
        suite.check_shape()?;
        let mut selected: Vec<&TaskDef> = suite
            .tasks
            .iter()
            .filter(|t| t.kind.is_rewrite() && self.options.selects(&t.id, t.kind))
            .collect();
        if let Some(n) = self.options.limit {
            selected.truncate(n);
        }
        if selected.is_empty() {
            return Err(EvalError::Suite("no task matches the selection".into()));
        }
        let deterministic = self.options.mode.starts_with("ci");
        let started = Instant::now();
        let mut reports = Vec::new();
        let mut backend_info: Option<BackendInfo> = None;
        for def in selected {
            let (report, info) = self.run_task(def, deterministic).await;
            backend_info.get_or_insert(info);
            progress(&report);
            reports.push(report);
        }
        let backend =
            backend_info.ok_or_else(|| EvalError::Backend("no backend was created".into()))?;
        let duration = (!deterministic).then(|| started.elapsed().as_millis() as u64);
        Ok(Report {
            schema_version: REPORT_VERSION,
            suite: suite.name.clone(),
            mode: self.options.mode.clone(),
            backend,
            engine: "recorded fixtures (engine-fake); generated code built and run in the sandbox"
                .into(),
            summary: Summary::of(&reports, duration),
            tasks: reports,
        })
    }

    fn provider_for(&self, id: &str) -> Result<Provided, EvalError> {
        match &self.answers {
            Answers::Replay(c) => {
                let steps = c.tasks.get(id).ok_or_else(|| {
                    EvalError::Cassette(format!(
                        "no recording for task `{id}`; record it again or choose another cassette"
                    ))
                })?;
                let p = ReplayProvider::scripted(steps.clone()).with_info(ProviderInfo {
                    id: "replay".into(),
                    model: c.recorded_with.clone(),
                    supports_tools: false,
                    context_window: None,
                });
                Ok((Arc::new(p), None))
            }
            Answers::Live { provider, .. } => {
                let rec = Arc::new(RecordingProvider::new(provider.clone()));
                Ok((rec.clone(), Some(rec)))
            }
        }
    }

    async fn run_task(&self, def: &TaskDef, deterministic: bool) -> (TaskReport, BackendInfo) {
        let started = Instant::now();
        let (provider, rec) = match self.provider_for(&def.id) {
            Ok(p) => p,
            Err(e) => {
                let info = BackendInfo {
                    kind: kraken_assist::BackendKind::Api,
                    id: "replay".into(),
                    name: "replay".into(),
                    model: None,
                };
                return (self.failed(def, e.to_string(), None), info);
            }
        };
        let counting = Arc::new(CountingBackend {
            inner: Arc::new(ApiBackend::new(provider)),
            calls: Mutex::new(0),
            usage: Mutex::new(Usage::default()),
        });
        let info = counting.info();
        let outcome = self.drive(def, counting.clone()).await;
        if let Some(rec) = rec {
            let steps: Vec<Vec<StreamEvent>> = rec
                .cassette()
                .entries
                .into_iter()
                .map(|e| e.events)
                .collect();
            if let Some(c) = self
                .recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_mut()
            {
                c.tasks.insert(def.id.clone(), steps);
            }
        }
        let calls = *counting
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let usage = *counting
            .usage
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let duration = (!deterministic).then(|| started.elapsed().as_millis() as u64);
        (self.report_of(def, outcome, calls, usage, duration), info)
    }

    fn failed(&self, def: &TaskDef, problem: String, duration: Option<u64>) -> TaskReport {
        self.report_of(
            def,
            Err(Failure {
                message: problem,
                tool: None,
            }),
            0,
            Usage::default(),
            duration,
        )
    }

    /// Opens the project, runs the command and reads what it measured.
    async fn drive(&self, def: &TaskDef, backend: Arc<CountingBackend>) -> Result<Driven, Failure> {
        let fail = |m: String| Failure {
            message: m,
            tool: None,
        };
        let truth = self
            .corpus
            .truth(&def.binary)
            .map_err(|e| fail(e.to_string()))?;
        let fixture = self
            .corpus
            .fixture(&def.binary)
            .map_err(|e| fail(e.to_string()))?;
        let base = fixture.program.base.0;
        let service = Arc::new(RewriteService::new(
            Arc::new(FixedBackend(backend)),
            RewriteConfig {
                oracle: OracleConfig {
                    ghidra_home: self.ghidra_home.clone(),
                    ..OracleConfig::default()
                },
                ..RewriteConfig::default()
            },
        ));
        let rewrite: Arc<dyn RewriteBackend> = service;
        let session = Session::new(Arc::new(FixtureFactory { fixture })).with_rewrite(rewrite);
        let dir = self.work.join("projects").join(def.id.replace('/', "-"));
        if dir.exists() {
            std::fs::remove_dir_all(&dir).map_err(|e| fail(format!("{}: {e}", dir.display())))?;
        }
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| fail(format!("{}: {e}", parent.display())))?;
        }
        session
            .create_project(&dir, &self.corpus.binary(&def.binary))
            .await
            .map_err(|e| fail(format!("project: {}", e.message)))?;

        let (command, args) = if let Some(name) = &def.function {
            let f = truth
                .functions
                .iter()
                .find(|f| &f.name == name)
                .ok_or_else(|| fail(format!("`{name}` is not in the truth file")))?;
            let mut args = json!({"address": format!("{:#x}", engine_address(f.entry, base))});
            if let Some(c) = def.cases {
                args["cases"] = json!(c);
            }
            ("rewrite_function", args)
        } else {
            // One function at a time keeps the order of the model calls, so a cassette replays.
            let mut args = json!({
                "scope": "all",
                "parallel": 1,
                "verify_functions": self.verify_functions,
            });
            if let Some(c) = def.cases {
                args["cases"] = json!(c);
            }
            ("rewrite_program", args)
        };
        let registry = Registry::standard();
        let ctx = CallContext::user("kraken-eval", Surface::Test);
        let tool_error = |m: String| Failure {
            message: m,
            tool: Some((command.to_string(), args.clone())),
        };
        let started = registry
            .call_json(command, &session, &ctx, args.clone())
            .await
            .map_err(|e| tool_error(e.message))?;
        let id = started["job_id"]
            .as_str()
            .ok_or_else(|| tool_error("no job id".into()))?
            .to_string();
        let limit = self.options.timeout;
        let done = registry
            .call_json(
                "job_await",
                &session,
                &ctx,
                json!({"job_id": id, "timeout_ms": limit.as_millis() as u64}),
            )
            .await
            .map_err(|e| tool_error(e.message))?;
        match done["status"].as_str() {
            Some("succeeded") => Ok(Driven {
                command,
                args,
                result: done["result"].clone(),
            }),
            Some("failed") => {
                let e: Result<ProtoError, _> = serde_json::from_value(done["error"].clone());
                Err(tool_error(e.map_or_else(
                    |_| done["error"].to_string(),
                    |e| {
                        if e.code == ErrorCode::Unsupported {
                            format!("{} (this host cannot run the sandbox?)", e.message)
                        } else {
                            e.message
                        }
                    },
                )))
            }
            other => Err(tool_error(format!(
                "the job did not finish within {} s ({})",
                limit.as_secs(),
                other.unwrap_or("unknown")
            ))),
        }
    }

    fn report_of(
        &self,
        def: &TaskDef,
        outcome: Result<Driven, Failure>,
        calls: u32,
        usage: Usage,
        duration_ms: Option<u64>,
    ) -> TaskReport {
        let goal = match &def.function {
            Some(f) => format!(
                "<kraken-eval id=\"{}\" kind=\"{}\">\nRewrite `{f}` of `{}` to Rust and check it \
                 against the original.",
                def.id,
                def.kind.as_str(),
                def.binary
            ),
            None => format!(
                "<kraken-eval id=\"{}\" kind=\"{}\">\nRewrite the whole program `{}` to a Rust \
                 crate and check it against the original.",
                def.id,
                def.kind.as_str(),
                def.binary
            ),
        };
        let mut transcript = vec![TranscriptEntry::Prompt { text: goal }];
        let (metrics, problem, reply, error) = match outcome {
            Ok(d) => {
                let m = metrics_of(&d.result, calls);
                let summary = format!(
                    "{}: {} of {} cases agreed, {} repair round(s), {} model call(s)",
                    m.verdict, m.cases_passed, m.cases_run, m.repair_rounds, m.model_calls
                );
                transcript.push(TranscriptEntry::ToolCall {
                    name: d.command.to_string(),
                    arguments: d.args,
                    result: summary.clone(),
                    is_error: false,
                });
                transcript.push(TranscriptEntry::Done {
                    stop: "completed".into(),
                });
                let problem = (m.verdict == "inconclusive" || m.cases_run == 0)
                    .then(|| "the differential test ran no case".to_string());
                (m, problem, summary, None)
            }
            Err(f) => {
                if let Some((name, arguments)) = f.tool {
                    transcript.push(TranscriptEntry::ToolCall {
                        name,
                        arguments,
                        result: clip(&f.message, 300),
                        is_error: true,
                    });
                }
                transcript.push(TranscriptEntry::Error {
                    message: f.message.clone(),
                });
                let m = RewriteMetrics {
                    verdict: "error".into(),
                    model_calls: calls,
                    ..RewriteMetrics::default()
                };
                (m, Some(f.message.clone()), String::new(), Some(f.message))
            }
        };
        let correct = metrics.verdict == "pass";
        let score = if correct {
            1.0
        } else if metrics.cases_run > 0 {
            round4(f64::from(metrics.cases_passed) / f64::from(metrics.cases_run)).min(0.9999)
        } else {
            0.0
        };
        let tokens = (usage.total() > 0).then_some(TokenUse {
            input: usage.input_tokens,
            output: usage.output_tokens,
        });
        TaskReport {
            id: def.id.clone(),
            kind: def.kind,
            binary: def.binary.clone(),
            score,
            correct,
            problem,
            detail: json!(metrics),
            answer: None,
            reply: clip(&reply, MAX_REPLY),
            stop: if error.is_some() {
                "error"
            } else {
                "completed"
            }
            .into(),
            error,
            tokens,
            cost_usd: match (tokens, self.options.price) {
                (Some(t), Some(p)) => Some(Price::cost(p, t)),
                _ => None,
            },
            tool_calls: 1,
            tool_errors: usize::from(metrics.verdict == "error"),
            duration_ms,
            transcript,
            rewrite: Some(metrics),
        }
    }
}

struct Failure {
    message: String,
    tool: Option<(String, Value)>,
}

struct Driven {
    command: &'static str,
    args: Value,
    result: Value,
}

fn count(v: &Value) -> u32 {
    v.as_u64().map_or(0, |n| n as u32)
}

/// Reads the measured numbers out of a finished `rewrite_function` or `rewrite_program` job.
fn metrics_of(result: &Value, model_calls: u32) -> RewriteMetrics {
    if let Some(rows) = result["functions"].as_array() {
        // A program: the program-level verdict and cases, the functions' attempts.
        let v = &result["verdict"];
        let attempts: u32 = rows.iter().map(|r| count(&r["attempts"]).max(1) - 1).sum();
        let program_rounds = result["repairs"].as_array().map_or(0, Vec::len) as u32;
        RewriteMetrics {
            verdict: v["verdict"].as_str().unwrap_or("error").to_string(),
            units: count(&result["translated"]),
            units_failed: count(&result["failed"]),
            cases_run: count(&v["cases_run"]),
            cases_passed: count(&v["passed"]),
            repair_rounds: attempts + program_rounds,
            model_calls,
            note: v["detail"]["value"].as_str().map(|n| clip(n, 200)),
        }
    } else {
        RewriteMetrics {
            verdict: result["verdict"].as_str().unwrap_or("error").to_string(),
            units: 1,
            units_failed: u32::from(result["verdict"] != "pass"),
            cases_run: count(&result["cases_run"]),
            cases_passed: count(&result["passed"]),
            repair_rounds: count(&result["attempts"]).max(1) - 1,
            model_calls,
            note: result["verdict_detail"]["value"]
                .as_str()
                .map(|n| clip(n, 200)),
        }
    }
}

/// Which reference set a corpus binary's translations are in, and what its stripped entry
/// function is called in the project.
const REFERENCE_SETS: &[(&str, &str)] = &[
    ("pie_list", "fn_1014da"),
    ("static_strops", "fn_401a5e"),
    ("stripped_calc", "fn_1014c1"),
    ("switch_vm", "fn_101707"),
];

/// Answers each translation request with the hand-checked reference translation of the function
/// it asks for (`kraken-rewrite/references/program`). Used to bless the committed cassette.
pub struct ReferenceProvider {
    by_function: BTreeMap<String, String>,
}

impl ReferenceProvider {
    /// Reads the references under `root` (the `references/program` folder of `kraken-rewrite`).
    pub fn load(root: &Path) -> Result<Self, EvalError> {
        let mut by_function = BTreeMap::new();
        for (set, entry) in REFERENCE_SETS {
            let dir = root.join(set);
            let read = |name: &str| {
                std::fs::read_to_string(dir.join(format!("{name}.rs")))
                    .map_err(|e| EvalError::Setup(format!("{}: {e}", dir.display())))
            };
            by_function.insert((*entry).to_string(), read("main")?);
            for f in std::fs::read_dir(&dir)
                .map_err(|e| EvalError::Setup(format!("{}: {e}", dir.display())))?
                .filter_map(Result::ok)
            {
                let path = f.path();
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if path.extension().is_some_and(|e| e == "rs") && stem != "main" {
                    by_function.entry(stem.to_string()).or_insert(read(stem)?);
                }
            }
        }
        Ok(ReferenceProvider { by_function })
    }
}

#[async_trait]
impl ChatProvider for ReferenceProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "reference".into(),
            model: "reference translations".into(),
            supports_tools: false,
            context_window: None,
        }
    }

    async fn complete(
        &self,
        req: ChatRequest,
        _cancel: CancellationToken,
    ) -> Result<kraken_agent::ChatStream, AgentError> {
        let Some(Message::User { content }) = req.messages.first() else {
            return Err(AgentError::Cassette("no user message".into()));
        };
        let name = content
            .strip_prefix("Translate the function `")
            .and_then(|r| r.split('`').next())
            .ok_or_else(|| AgentError::Cassette("not a translation request".into()))?;
        let code = self
            .by_function
            .get(name)
            .ok_or_else(|| AgentError::Cassette(format!("no reference for `{name}`")))?;
        let events = vec![
            StreamEvent::TextDelta {
                text: RewriteTask::reply_text(code, &[]),
            },
            StreamEvent::Finish {
                reason: FinishReason::Stop,
            },
        ];
        Ok(futures_util::stream::iter(events.into_iter().map(Ok)).boxed())
    }
}

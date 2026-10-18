//! `kraken eval list | run`: measure an assistant on the test corpus (see `docs/assistant.md`).
//!
//! The assistant is the one the `[provider]` table of `config.toml` selects (a model API, local or
//! hosted, or a terminal agent such as Claude Code), or one of the two deterministic offline
//! stand-ins (`--backend ci-replay`, `--backend ci-agent`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command};
use kraken_agent::ChatProvider;
use kraken_assist::{AgentChoice, AssistBackend, Assistant, UnusedBackend};
use kraken_eval::ci::{self, FixtureEnvironment};
use kraken_eval::{
    ApiSource, AssistantSource, Corpus, Environment as EvalEnvironment, EvalCassette, EvalError,
    FakeAgentSource, Kind, Prepared, Price, RecordingSource, ReplaySource, ResolvedTask,
    RunOptions, Runner, Suite, write_report,
};
use kraken_proto::ProtoError;
use kraken_registry::Registry;
use serde_json::json;

use crate::app::{CliEnv, DaemonMode, bad, emit, fail};
use crate::assist_cmd::{Selection, agent_backend, selection_from_config};

const BACKENDS: [&str; 3] = ["config", "ci-replay", "ci-agent"];
const KINDS: [&str; 3] = ["name_functions", "find_function", "question"];

/// The clap tree of `kraken eval`.
pub(crate) fn command() -> Command {
    let suite = || {
        Arg::new("suite")
            .long("suite")
            .value_name("FILE")
            .help("A task suite (JSON). Default: the built-in suite over the corpus")
    };
    let corpus = || {
        Arg::new("corpus")
            .long("corpus")
            .value_name("DIR")
            .help("The corpus folder (binaries, truth, fixtures). Default: $KRAKEN_CORPUS, else a corpus/ folder here or above")
    };
    Command::new("eval")
        .about("Measure the assistant on the test corpus: name stripped functions, find functions, answer questions")
        .long_about(
            "Runs scripted tasks over the test corpus and scores the answers against ground \
             truth: naming stripped functions (token overlap with the DWARF names), finding the \
             function that does something, and questions about strings and imports. The assistant \
             is the one `config.toml` selects (a model API, a local model, or a terminal agent), \
             so any of them can be measured the same way. Writes report.json, report.md and one \
             transcript per task into --out. `--backend ci-replay` and `--backend ci-agent` run \
             the same tasks offline against scripted answers (no network, no model), to check \
             the harness itself. See docs/assistant.md.",
        )
        .subcommand_required(true)
        .subcommand(
            Command::new("list")
                .about("List the tasks of the suite")
                .arg(suite()),
        )
        .subcommand(
            Command::new("run")
                .about("Run the suite against an assistant and write the report")
                .arg(suite())
                .arg(corpus())
                .arg(
                    Arg::new("backend")
                        .long("backend")
                        .value_name("BACKEND")
                        .default_value("config")
                        .value_parser(PossibleValuesParser::new(BACKENDS))
                        .help("config: the [provider] table. ci-replay: replay a cassette. ci-agent: the fake terminal agent"),
                )
                .arg(
                    Arg::new("task")
                        .long("task")
                        .value_name("ID")
                        .action(ArgAction::Append)
                        .help("Run only tasks whose id starts with this (repeatable), e.g. find/ or name/switch_vm"),
                )
                .arg(
                    Arg::new("kind")
                        .long("kind")
                        .value_name("KIND")
                        .action(ArgAction::Append)
                        .value_parser(PossibleValuesParser::new(KINDS))
                        .help("Run only tasks of this kind (repeatable)"),
                )
                .arg(
                    Arg::new("limit")
                        .long("limit")
                        .value_name("N")
                        .value_parser(clap::value_parser!(usize))
                        .help("Stop after this many tasks"),
                )
                .arg(
                    Arg::new("out")
                        .long("out")
                        .value_name("DIR")
                        .help("Where to write the report (default: kraken-eval-<time> here)"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_name("SECONDS")
                        .default_value("900")
                        .value_parser(clap::value_parser!(u64))
                        .help("Longest one task may run before it is cancelled"),
                )
                .arg(
                    Arg::new("price-in")
                        .long("price-in")
                        .value_name("USD")
                        .value_parser(clap::value_parser!(f64))
                        .help("Dollars per million input tokens, for a cost estimate (leave out for local models)"),
                )
                .arg(
                    Arg::new("price-out")
                        .long("price-out")
                        .value_name("USD")
                        .value_parser(clap::value_parser!(f64))
                        .help("Dollars per million output tokens"),
                )
                .arg(
                    Arg::new("cassette")
                        .long("cassette")
                        .value_name("FILE")
                        .help("With ci-replay: replay this cassette instead of the built-in one"),
                )
                .arg(
                    Arg::new("record")
                        .long("record")
                        .value_name("FILE")
                        .help("With a model API: save every exchange as an eval cassette, to replay later with --backend ci-replay --cassette"),
                )
                .arg(
                    Arg::new("min-score")
                        .long("min-score")
                        .value_name("0..1")
                        .value_parser(clap::value_parser!(f64))
                        .help("Exit with status 1 when the mean score is below this"),
                ),
        )
}

fn proto(e: EvalError) -> ProtoError {
    bad(e.to_string())
}

fn load_suite(sm: &ArgMatches) -> Result<Suite, ProtoError> {
    match sm.get_one::<String>("suite") {
        Some(p) => Suite::from_path(Path::new(p)).map_err(proto),
        None => Ok(Suite::builtin()),
    }
}

/// Runs `kraken eval`. `provider` replaces the `[provider]` table for a model API (tests).
pub(crate) async fn run_eval(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    provider: Option<Arc<dyn ChatProvider>>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let result = match sm.subcommand() {
        Some(("list", m)) => list(m, json_out, out),
        Some(("run", m)) => run(env, m, json_out, provider, out, err).await,
        _ => Err(bad("choose one of: list, run")),
    };
    match result {
        Ok(code) => code,
        Err(e) => fail(&e, json_out, err),
    }
}

fn list(sm: &ArgMatches, json_out: bool, out: &mut dyn Write) -> Result<i32, ProtoError> {
    let suite = load_suite(sm)?;
    if json_out {
        emit(out, &format!("{}\n", json!(suite)));
        return Ok(0);
    }
    emit(
        out,
        &format!("suite {} ({} tasks)\n", suite.name, suite.tasks.len()),
    );
    for t in &suite.tasks {
        emit(
            out,
            &format!("  {:<28} {:<15} {}\n", t.id, t.kind.as_str(), t.binary),
        );
    }
    Ok(0)
}

fn parse_kinds(sm: &ArgMatches) -> Vec<Kind> {
    sm.get_many::<String>("kind")
        .into_iter()
        .flatten()
        .filter_map(|k| match k.as_str() {
            "name_functions" => Some(Kind::NameFunctions),
            "find_function" => Some(Kind::FindFunction),
            "question" => Some(Kind::Question),
            _ => None,
        })
        .collect()
}

fn default_out_dir() -> PathBuf {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    PathBuf::from(format!("kraken-eval-{secs}"))
}

async fn run(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    provider: Option<Arc<dyn ChatProvider>>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let suite = load_suite(sm)?;
    let corpus = Corpus::locate(
        sm.get_one::<String>("corpus").map(Path::new),
        env.var("KRAKEN_CORPUS").as_deref(),
    )
    .map_err(proto)?;
    let backend_name = sm
        .get_one::<String>("backend")
        .map_or("config", String::as_str);
    let out_dir = sm
        .get_one::<String>("out")
        .map_or_else(default_out_dir, PathBuf::from);
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| bad(format!("cannot create {}: {e}", out_dir.display())))?;
    let out_dir = std::path::absolute(&out_dir).unwrap_or(out_dir);

    let price = match (
        sm.get_one::<f64>("price-in"),
        sm.get_one::<f64>("price-out"),
    ) {
        (Some(i), Some(o)) => Some(Price {
            input_per_million: *i,
            output_per_million: *o,
        }),
        (None, None) => None,
        _ => return Err(bad("give both --price-in and --price-out, or neither")),
    };
    let options = RunOptions {
        only: sm
            .get_many::<String>("task")
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        kinds: parse_kinds(sm),
        limit: sm.get_one::<usize>("limit").copied(),
        timeout: Duration::from_secs(sm.get_one::<u64>("timeout").copied().unwrap_or(900)),
        price,
        mode: match backend_name {
            "ci-replay" | "ci-agent" => backend_name.to_string(),
            _ => "live".to_string(),
        },
    };
    let registry = env.registry.clone();
    let record_to = sm.get_one::<String>("record").map(PathBuf::from);
    let mut recorder: Option<Arc<RecordingSource>> = None;

    let environment: Box<dyn EvalEnvironment>;
    let source: Box<dyn AssistantSource>;
    match backend_name {
        "ci-replay" => {
            if record_to.is_some() {
                return Err(bad("--record needs a model API (--backend config)"));
            }
            let cassette = match sm.get_one::<String>("cassette") {
                Some(p) => EvalCassette::load(Path::new(p)).map_err(proto)?,
                None => ci::committed_cassette().map_err(proto)?,
            };
            environment = Box::new(FixtureEnvironment::new(
                corpus.clone(),
                out_dir.clone(),
                registry.clone(),
            ));
            source = Box::new(ReplaySource::new(cassette));
        }
        "ci-agent" => {
            let script_path = out_dir.join("ci-script.json");
            ci::write_script(&ci::committed_script().map_err(proto)?, &script_path)
                .map_err(proto)?;
            let exe = env
                .var("KRAKEN_EXE")
                .map(PathBuf::from)
                .or_else(|| std::env::current_exe().ok())
                .ok_or_else(|| bad("cannot find the kraken executable"))?;
            environment = Box::new(FixtureEnvironment::new(
                corpus.clone(),
                out_dir.clone(),
                registry.clone(),
            ));
            source = Box::new(
                FakeAgentSource::new(exe, script_path)
                    .with_args(vec!["agents".into(), "__fake-agent".into()]),
            );
        }
        _ => {
            let selection = match provider {
                Some(p) => Selection::Api(p),
                None => selection_from_config(env)?,
            };
            let no_daemon = env.no_daemon(sm);
            environment = Box::new(LiveEnvironment {
                env,
                corpus: corpus.clone(),
                work: out_dir.clone(),
                no_daemon,
            });
            match selection {
                Selection::Api(p) => {
                    if let Some(path) = &record_to {
                        let note = format!(
                            "{} / {} (recorded by kraken eval)",
                            p.info().id,
                            p.info().model
                        );
                        let r = Arc::new(RecordingSource::new(p, note));
                        recorder = Some(r.clone());
                        source = Box::new(SharedSource(r));
                        emit(err, &format!("recording to {}\n", path.display()));
                    } else {
                        source = Box::new(ApiSource::new(p));
                    }
                }
                Selection::Agent(choice) => {
                    if record_to.is_some() {
                        return Err(bad("--record needs a model API, not a terminal agent"));
                    }
                    let use_daemon = !no_daemon
                        && env.session.is_none()
                        && !matches!(env.daemon, DaemonMode::Direct);
                    if !use_daemon {
                        return Err(bad(
                            "a terminal agent opens the projects through krakend; run without \
                             --no-daemon so the agent and this command share the daemon",
                        ));
                    }
                    source = Box::new(AgentSource {
                        env,
                        sm,
                        choice,
                        open: Mutex::new(Vec::new()),
                    });
                }
            }
        }
    }

    let total = suite
        .tasks
        .iter()
        .filter(|t| options.selects(&t.id, t.kind))
        .count()
        .min(options.limit.unwrap_or(usize::MAX));
    let runner = Runner {
        corpus: &corpus,
        env: environment.as_ref(),
        source: source.as_ref(),
        registry,
        options,
    };
    let mut done = 0usize;
    let report = runner
        .run(&suite, &mut |t| {
            done += 1;
            emit(
                err,
                &format!(
                    "[{done}/{total}] {:<26} {:>5.1}%{}\n",
                    t.id,
                    t.score * 100.0,
                    t.problem
                        .as_deref()
                        .map(|p| format!("  ({p})"))
                        .unwrap_or_default()
                ),
            );
        })
        .await
        .map_err(proto);
    env.factory.shutdown().await;
    let report = report?;

    if let (Some(rec), Some(path)) = (recorder, &record_to) {
        rec.cassette().save(path).map_err(proto)?;
        emit(err, &format!("cassette written to {}\n", path.display()));
    }
    let written = write_report(&report, &out_dir).map_err(proto)?;
    if json_out {
        emit(out, &report.to_json().map_err(proto)?);
    } else {
        let s = &report.summary;
        emit(
            out,
            &format!(
                "{} / {}: mean score {:.1}% over {} tasks ({} perfect, {} with problems)\n",
                report.backend.title(),
                report.mode,
                s.mean_score * 100.0,
                s.tasks,
                s.correct,
                s.problems
            ),
        );
        for (k, v) in &s.by_kind {
            emit(
                out,
                &format!(
                    "  {k:<15} {:>5.1}% ({} tasks)\n",
                    v.mean_score * 100.0,
                    v.tasks
                ),
            );
        }
        match s.tokens {
            Some(t) => emit(
                out,
                &format!(
                    "tokens: {} in, {} out{}\n",
                    t.input,
                    t.output,
                    s.cost_usd
                        .map(|c| format!(", about ${c:.4}"))
                        .unwrap_or_default()
                ),
            ),
            None => emit(out, "tokens: not reported by this backend\n"),
        }
        emit(out, &format!("report: {}\n", written.markdown.display()));
    }
    if let Some(min) = sm.get_one::<f64>("min-score")
        && report.summary.mean_score < *min
    {
        emit(
            err,
            &format!(
                "mean score {:.3} is below --min-score {min}\n",
                report.summary.mean_score
            ),
        );
        return Ok(1);
    }
    Ok(0)
}

/// Lets a shared recorder act as the source.
struct SharedSource(Arc<RecordingSource>);

impl AssistantSource for SharedSource {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        self.0.assistant(registry, prepared, task)
    }

    fn finished(&self, task: &ResolvedTask) {
        self.0.finished(task);
    }
}

/// Opens the corpus binaries in the real engine (through the daemon, or in this process): a
/// project per binary under the report folder, analysed once.
struct LiveEnvironment<'a> {
    env: &'a CliEnv,
    corpus: Corpus,
    work: PathBuf,
    no_daemon: bool,
}

#[async_trait(?Send)]
impl EvalEnvironment for LiveEnvironment<'_> {
    fn describe(&self) -> String {
        if self.no_daemon || matches!(self.env.daemon, DaemonMode::Direct) {
            "engine in this process".to_string()
        } else {
            "engine in krakend".to_string()
        }
    }

    async fn prepare(&self, binary: &str) -> Result<Prepared, EvalError> {
        let setup = |e: ProtoError| EvalError::Setup(format!("{binary}: {}", e.message));
        let dir = self.work.join("projects").join(binary);
        let mut sink: Vec<u8> = Vec::new();
        let (backend, _session) = self
            .env
            .backend(dir.to_str(), self.no_daemon, &mut sink)
            .await
            .map_err(setup)?;
        let ctx = self.env.context(true);
        if dir.join("meta.json").exists() {
            backend
                .call("project_open", &ctx, json!({"project_dir": dir}))
                .await
                .map_err(setup)?;
        } else {
            backend
                .call(
                    "project_create",
                    &ctx,
                    json!({"binary": self.corpus.binary(binary), "project_dir": dir}),
                )
                .await
                .map_err(setup)?;
        }
        ci::analyze(backend.as_ref()).await.map_err(setup)?;
        let info = backend
            .call("project_info", &ctx, json!({}))
            .await
            .map_err(setup)?;
        let base = info["program"]["base"]
            .as_str()
            .and_then(|b| u64::from_str_radix(b.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        Ok(Prepared {
            binary: binary.to_string(),
            backend,
            project_dir: Some(dir),
            base,
        })
    }

    async fn finish(&self) {
        self.env.factory.shutdown().await;
    }
}

/// A terminal agent, started for each task on the task's project.
struct AgentSource<'a> {
    env: &'a CliEnv,
    sm: &'a ArgMatches,
    choice: AgentChoice,
    open: Mutex<Vec<Arc<dyn AssistBackend>>>,
}

impl AssistantSource for AgentSource<'_> {
    fn assistant(
        &self,
        registry: &Arc<Registry>,
        prepared: &Prepared,
        _task: &ResolvedTask,
    ) -> Result<Assistant, EvalError> {
        let project = prepared.project_dir.as_ref().and_then(|p| p.to_str());
        let mut stderr = std::io::stderr();
        let engine = agent_backend(self.env, self.sm, &self.choice, project, None, &mut stderr)
            .map_err(|e| EvalError::Backend(e.message))?;
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(engine.clone());
        Ok(Assistant::with_engine(
            registry.clone(),
            Arc::new(UnusedBackend),
            engine,
        ))
    }

    fn finished(&self, _task: &ResolvedTask) {
        for e in self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            e.close();
        }
    }
}

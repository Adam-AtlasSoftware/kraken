//! The harness end to end, offline: recorded fixtures for the engine, scripted answers for the
//! model, delivered through `ReplayProvider` and through the fake ACP agent.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::OnceLock;

use kraken_agent::{ChatProvider, ReplayProvider};
#[cfg(unix)]
use kraken_eval::FakeAgentSource;
use kraken_eval::ci::{
    FixtureEnvironment, committed_cassette, generate_script, script_cassette, write_script,
};
use kraken_eval::{
    AssistantSource, Corpus, EvalCassette, Kind, Price, RecordingSource, ReplaySource, Report,
    RunOptions, Runner, Suite, write_report,
};
use kraken_registry::Registry;

fn corpus() -> Corpus {
    Corpus::locate(None, None).expect("corpus")
}

/// Regenerates `data/ci-script.json` and `data/ci-cassette.json` when `KRAKEN_EVAL_BLESS=1`.
fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join(name)
}

#[test]
fn the_committed_script_and_cassette_are_what_the_stand_in_writes() {
    let script = generate_script(&corpus(), &Suite::builtin()).expect("script");
    let cassette = script_cassette(&script);
    if std::env::var_os("KRAKEN_EVAL_BLESS").is_some() {
        write_script(&script, &data("ci-script.json")).expect("write script");
        cassette
            .save(&data("ci-cassette.json"))
            .expect("write cassette");
    }
    assert_eq!(
        kraken_eval::ci::committed_script().expect("committed script"),
        script,
        "data/ci-script.json is out of date: run the tests with KRAKEN_EVAL_BLESS=1"
    );
    assert_eq!(
        committed_cassette().expect("committed cassette"),
        cassette,
        "data/ci-cassette.json is out of date: run the tests with KRAKEN_EVAL_BLESS=1"
    );
}

async fn run_with(source: &dyn AssistantSource, options: RunOptions, work: &Path) -> Report {
    let registry = Arc::new(Registry::standard());
    let env = FixtureEnvironment::new(corpus(), work.to_path_buf(), registry.clone());
    let corpus = corpus();
    let runner = Runner {
        corpus: &corpus,
        env: &env,
        source,
        registry,
        options,
    };
    runner
        .run(&Suite::builtin(), &mut |_| {})
        .await
        .expect("run")
}

fn replay_options() -> RunOptions {
    RunOptions {
        mode: "ci-replay".into(),
        ..RunOptions::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_whole_suite_replays_deterministically_from_the_cassette() {
    let source = ReplaySource::new(committed_cassette().expect("cassette"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = run_with(&source, replay_options(), tmp.path()).await;
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let b = run_with(&source, replay_options(), tmp2.path()).await;
    assert_eq!(a, b, "a CI run gives the same report every time");
    assert_eq!(a.to_json().expect("json"), b.to_json().expect("json"));

    let suite = Suite::builtin();
    assert_eq!(a.tasks.len(), suite.tasks.len());
    assert_eq!(a.backend.id, "replay");
    assert!(a.tasks.iter().all(|t| t.duration_ms.is_none()));
    assert!(a.summary.duration_ms.is_none());

    // The stand-in gets some right, some half right, some wrong; exactly one gives no answer.
    let by = |id: &str| a.tasks.iter().find(|t| t.id == id).expect(id);
    assert!(by("find/vm-interpreter").correct);
    assert!(
        !by("find/calc-number").correct,
        "every fourth function answer is wrong"
    );
    let names = by("name/switch_vm");
    assert!(names.score > 0.3 && names.score < 0.7, "{}", names.score);
    let unanswered: Vec<&str> = a
        .tasks
        .iter()
        .filter(|t| t.problem.is_some())
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(unanswered, ["qa/string-strops-joined"]);
    assert!(
        a.summary.mean_score > 0.5 && a.summary.mean_score < 0.95,
        "{}",
        a.summary.mean_score
    );
    for kind in [Kind::NameFunctions, Kind::FindFunction, Kind::Question] {
        assert!(a.summary.by_kind.contains_key(kind.as_str()), "{kind:?}");
    }

    // The tools really ran against the fixtures: the transcript has their results.
    let t = by("find/vm-interpreter");
    let call = t
        .transcript
        .iter()
        .find_map(|e| match e {
            kraken_eval::TranscriptEntry::ToolCall {
                name,
                result,
                is_error,
                ..
            } => Some((name.clone(), result.clone(), *is_error)),
            _ => None,
        })
        .expect("a tool call");
    assert_eq!(call.0, "decompile");
    assert!(!call.2, "{call:?}");
    assert!(t.tool_calls >= 1);
    assert!(
        t.tokens.is_none(),
        "a cassette of a stand-in reports no tokens"
    );

    // The Markdown and the transcripts come out.
    let out = tempfile::tempdir().expect("tempdir");
    let written = write_report(&a, out.path()).expect("write");
    let md = std::fs::read_to_string(&written.markdown).expect("md");
    assert!(md.contains("Mean score"));
    assert!(md.contains("qa/string-strops-joined"));
    assert!(written.transcripts.join("find-vm-interpreter.md").is_file());
}

#[tokio::test(flavor = "multi_thread")]
async fn selecting_tasks_by_prefix_kind_and_count() {
    let source = ReplaySource::new(committed_cassette().expect("cassette"));
    let tmp = tempfile::tempdir().expect("tempdir");
    let only = RunOptions {
        only: vec!["find/vm-".into()],
        ..replay_options()
    };
    let r = run_with(&source, only, tmp.path()).await;
    assert_eq!(r.tasks.len(), 3);
    assert!(r.tasks.iter().all(|t| t.id.starts_with("find/vm-")));

    let kinds = RunOptions {
        kinds: vec![Kind::Question],
        limit: Some(2),
        ..replay_options()
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let r = run_with(&source, kinds, tmp.path()).await;
    assert_eq!(r.tasks.len(), 2);
    assert!(r.tasks.iter().all(|t| t.kind == Kind::Question));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_model_that_fails_scores_zero_with_the_reason() {
    // A provider with nothing to say fails its first call.
    let provider: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![]));
    let source = kraken_eval::ApiSource::new(provider);
    let tmp = tempfile::tempdir().expect("tempdir");
    let options = RunOptions {
        only: vec!["find/vm-fatal".into()],
        ..replay_options()
    };
    let r = run_with(&source, options, tmp.path()).await;
    let t = &r.tasks[0];
    assert_eq!(t.score, 0.0);
    assert!(t.problem.is_some(), "{t:?}");
    assert_eq!(t.stop, "error");
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_and_cost_are_summed_when_the_backend_reports_them() {
    use kraken_agent::{FinishReason, StreamEvent, Usage};
    let reply = "<kraken-answer>{\"address\": \"0x101159\"}</kraken-answer>";
    let provider: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![vec![
        StreamEvent::TextDelta { text: reply.into() },
        StreamEvent::Usage(Usage {
            input_tokens: 2000,
            output_tokens: 50,
        }),
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]]));
    let source = kraken_eval::ApiSource::new(provider);
    let tmp = tempfile::tempdir().expect("tempdir");
    let options = RunOptions {
        only: vec!["find/vm-fatal".into(), "find/vm-pop".into()],
        price: Some(Price {
            input_per_million: 3.0,
            output_per_million: 15.0,
        }),
        ..replay_options()
    };
    let r = run_with(&source, options, tmp.path()).await;
    assert_eq!(r.tasks.len(), 2);
    // vm_fail is at 0x101159 in the fixture: the first answer is right, the second is not.
    assert!(r.tasks[0].correct && !r.tasks[1].correct, "{:?}", r.tasks);
    let tokens = r.summary.tokens.expect("tokens");
    assert_eq!((tokens.input, tokens.output), (4000, 100));
    // 4000 * 3 / 1e6 + 100 * 15 / 1e6
    assert!((r.summary.cost_usd.expect("cost") - 0.0135).abs() < 1e-9);
    assert!(r.to_markdown().contains("estimated cost $0.0135"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_recording_replays_to_the_same_report() {
    // Record one task from a scripted "model", then replay the recording.
    let cassette = committed_cassette().expect("cassette");
    let steps = cassette.tasks["find/vm-interpreter"].clone();
    let model: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(steps));
    let recorder = RecordingSource::new(model, "a test");
    let only = RunOptions {
        only: vec!["find/vm-interpreter".into()],
        ..replay_options()
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let recorded = run_with(&recorder, only.clone(), tmp.path()).await;
    let saved = recorder.cassette();
    assert_eq!(saved.tasks.len(), 1);
    assert_eq!(
        saved.tasks["find/vm-interpreter"].len(),
        2,
        "tool call, then answer"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let replayed = run_with(&ReplaySource::new(saved), only, tmp.path()).await;
    assert_eq!(recorded.tasks[0].score, replayed.tasks[0].score);
    assert_eq!(recorded.tasks[0].answer, replayed.tasks[0].answer);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_task_missing_from_the_cassette_is_a_clear_error() {
    let source = ReplaySource::new(EvalCassette::new("empty"));
    let registry = Arc::new(Registry::standard());
    let tmp = tempfile::tempdir().expect("tempdir");
    let env = FixtureEnvironment::new(corpus(), tmp.path().to_path_buf(), registry.clone());
    let corpus = corpus();
    let runner = Runner {
        corpus: &corpus,
        env: &env,
        source: &source,
        registry,
        options: replay_options(),
    };
    let err = runner
        .run(&Suite::builtin(), &mut |_| {})
        .await
        .expect_err("no recording");
    assert!(err.to_string().contains("no recording for task"), "{err}");
}

/// The `kraken-fake-acp-agent` binary. Cargo builds a package's binaries only for that
/// package's own tests, so this builds it (a no-op when up to date) and finds it next to the
/// running test binary.
#[cfg(unix)]
fn fake_agent() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().expect("test exe");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target profile dir")
            .to_path_buf();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "-q",
            "-p",
            "kraken-acp",
            "--bin",
            "kraken-fake-acp-agent",
        ]);
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
        assert!(cmd.status().expect("run cargo build").success());
        let bin = profile_dir.join(format!(
            "kraken-fake-acp-agent{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(bin.is_file(), "missing {}", bin.display());
        bin
    })
    .clone()
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_fake_terminal_agent_gives_the_same_scores_as_the_cassette() {
    let script = kraken_eval::ci::committed_script().expect("script");
    let tmp = tempfile::tempdir().expect("tempdir");
    let script_path = tmp.path().join("answers.json");
    write_script(&script, &script_path).expect("write script");

    let agent = FakeAgentSource::new(fake_agent(), script_path);
    let work = tempfile::tempdir().expect("tempdir");
    let options = RunOptions {
        mode: "ci-agent".into(),
        ..RunOptions::default()
    };
    let via_agent = run_with(&agent, options, work.path()).await;

    let replay = ReplaySource::new(committed_cassette().expect("cassette"));
    let work2 = tempfile::tempdir().expect("tempdir");
    let via_cassette = run_with(&replay, replay_options(), work2.path()).await;

    assert_eq!(
        via_agent.backend.kind,
        kraken_assist::BackendKind::TerminalAgent
    );
    assert_eq!(via_cassette.backend.kind, kraken_assist::BackendKind::Api);
    assert_eq!(via_agent.tasks.len(), via_cassette.tasks.len());
    for (a, c) in via_agent.tasks.iter().zip(&via_cassette.tasks) {
        assert_eq!(a.id, c.id);
        assert_eq!(a.score, c.score, "{}", a.id);
        assert_eq!(a.answer, c.answer, "{}", a.id);
        assert_eq!(a.problem.is_some(), c.problem.is_some(), "{}", a.id);
    }
    assert_eq!(
        via_agent.summary.mean_score,
        via_cassette.summary.mean_score
    );
    // The agent's tool calls appear in its transcripts, named after the commands.
    let t = via_agent
        .tasks
        .iter()
        .find(|t| t.id == "find/vm-interpreter")
        .expect("task");
    assert!(
        t.transcript.iter().any(|e| matches!(
            e,
            kraken_eval::TranscriptEntry::ToolCall { name, .. } if name == "decompile"
        )),
        "{:?}",
        t.transcript
    );
}

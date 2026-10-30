//! The rewrite suite in CI mode: recorded fixtures for the engine, a cassette for the model, the
//! real sandbox for the generated code. The program tasks need no Ghidra and no SLEIGH specs (the
//! program-level test against the original is the verdict); the function tasks run the emulation
//! oracle and are skipped without the specs (`KRAKEN_REQUIRE_SPECS=1` makes that a failure).
//!
//! `KRAKEN_EVAL_BLESS=1 cargo test -p kraken-eval --test rewrite` rewrites
//! `data/rewrite-cassette.json` from the reference translations of `kraken-rewrite` and
//! `data/rewrite-report.json` from what the replay then measures.

use std::path::{Path, PathBuf};

use kraken_eval::rewrite::ReferenceProvider;
use kraken_eval::{
    Answers, Corpus, EvalCassette, Kind, Report, RewriteRunner, RunOptions, Suite, write_report,
};
use kraken_rewrite::oracle::{OracleConfig, find_processors};

fn corpus() -> Corpus {
    Corpus::locate(None, None).expect("corpus")
}

fn data(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join(name)
}

fn bless() -> bool {
    std::env::var_os("KRAKEN_EVAL_BLESS").is_some()
}

fn have_specs() -> bool {
    if find_processors(&OracleConfig::default()).is_ok() {
        return true;
    }
    assert!(
        !std::env::var("KRAKEN_REQUIRE_SPECS").is_ok_and(|v| !v.is_empty() && v != "0"),
        "KRAKEN_REQUIRE_SPECS is set but no SLEIGH spec files were found"
    );
    eprintln!("skipped: no SLEIGH spec files (KRAKEN_NATIVE_SPECS or `cargo xtask native-sla`)");
    false
}

fn options(kinds: Vec<Kind>) -> RunOptions {
    RunOptions {
        kinds,
        mode: "ci-replay".into(),
        ..RunOptions::default()
    }
}

async fn replay(kinds: Vec<Kind>, work: &Path) -> Report {
    let corpus = corpus();
    let cassette = EvalCassette::load(&data("rewrite-cassette.json")).expect("cassette");
    let runner = RewriteRunner::new(
        &corpus,
        work.to_path_buf(),
        Answers::Replay(cassette),
        options(kinds),
        None,
    );
    runner
        .run(&Suite::rewrite_builtin(), &mut |_| {})
        .await
        .expect("run")
}

/// Records the cassette from the reference translations (all tasks, so it needs the specs).
async fn record(work: &Path) {
    let corpus = corpus();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kraken-rewrite/references/program");
    let provider = ReferenceProvider::load(&root).expect("references");
    let runner = RewriteRunner::new(
        &corpus,
        work.to_path_buf(),
        Answers::Live {
            provider: std::sync::Arc::new(provider),
            note: "kraken-eval rewrite: reference translations of kraken-rewrite (not a model)"
                .into(),
        },
        options(Vec::new()),
        None,
    );
    runner
        .run(&Suite::rewrite_builtin(), &mut |_| {})
        .await
        .expect("recording run");
    runner
        .recorded()
        .expect("a recording")
        .save(&data("rewrite-cassette.json"))
        .expect("save cassette");
}

#[test]
fn the_rewrite_suite_is_well_formed_and_agrees_with_the_corpus() {
    let suite = Suite::named("rewrite").expect("built in");
    assert!(suite.is_rewrite());
    suite.check_shape().expect("shape");
    suite.validate(&corpus()).expect("valid");
    for kind in [Kind::RewriteFunction, Kind::RewriteProgram] {
        assert!(suite.tasks.iter().any(|t| t.kind == kind), "{kind:?}");
    }
    assert!(!Suite::builtin().is_rewrite());
}

#[tokio::test]
async fn the_program_tasks_replay_from_the_cassette_into_a_stable_report() {
    if !kraken_rewrite::sandbox::enforced_or_skip() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    if bless() {
        if !have_specs() {
            panic!("blessing records the function tasks too and needs the SLEIGH specs");
        }
        record(&tmp.path().join("record")).await;
    }
    let first = replay(vec![Kind::RewriteProgram], &tmp.path().join("a")).await;
    let second = replay(vec![Kind::RewriteProgram], &tmp.path().join("b")).await;
    assert_eq!(
        first.to_json().expect("json"),
        second.to_json().expect("json"),
        "a replay must give the same report every time"
    );
    if bless() {
        std::fs::write(data("rewrite-report.json"), first.to_json().expect("json"))
            .expect("write report");
    }
    let committed = std::fs::read_to_string(data("rewrite-report.json")).expect("report");
    assert_eq!(
        committed,
        first.to_json().expect("json"),
        "data/rewrite-report.json is out of date: run the tests with KRAKEN_EVAL_BLESS=1"
    );

    let s = &first.summary;
    let r = s.rewrite.as_ref().expect("rewrite numbers");
    assert_eq!(first.tasks.len(), 3);
    assert_eq!(r.tasks, 3);
    assert_eq!(r.passed, 3, "{}", first.to_markdown());
    assert!((r.pass_rate - 1.0).abs() < f64::EPSILON);
    assert_eq!(r.repair_rounds, 0);
    assert!(r.cases_run >= 30 && r.cases_passed == r.cases_run);
    // One request per function, nothing more.
    assert_eq!(r.model_calls, r.units);
    assert_eq!(r.units_failed, 0);
    assert!(s.duration_ms.is_none(), "a CI report has no timings");

    let md = first.to_markdown();
    assert!(md.contains("## Rewrite quality"), "{md}");
    assert!(md.contains("**Pass rate: 100.0%**"), "{md}");
    assert!(md.contains("rw-prog/stripped_calc"), "{md}");
    let out = tmp.path().join("report");
    let written = write_report(&first, &out).expect("write");
    assert!(written.markdown.is_file());
}

#[tokio::test]
async fn the_function_tasks_replay_and_pass_the_differential_test() {
    if !kraken_rewrite::sandbox::enforced_or_skip() || !have_specs() {
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let report = replay(vec![Kind::RewriteFunction], tmp.path()).await;
    let r = report.summary.rewrite.as_ref().expect("rewrite numbers");
    assert_eq!(r.tasks, 6);
    assert_eq!(r.passed, 6, "{}", report.to_markdown());
    assert_eq!(r.model_calls, 6);
    assert!(r.cases_run >= 6 * 60 && r.cases_passed == r.cases_run);
}

#[tokio::test]
async fn a_task_missing_from_the_cassette_is_a_problem_not_a_crash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let corpus = corpus();
    let runner = RewriteRunner::new(
        &corpus,
        tmp.path().to_path_buf(),
        Answers::Replay(EvalCassette::new("empty")),
        options(vec![Kind::RewriteProgram]),
        None,
    );
    let report = runner
        .run(&Suite::rewrite_builtin(), &mut |_| {})
        .await
        .expect("run");
    assert!(
        report
            .tasks
            .iter()
            .all(|t| !t.correct && t.problem.is_some())
    );
    assert_eq!(report.summary.rewrite.as_ref().map(|r| r.passed), Some(0));
}

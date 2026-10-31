//! `kraken eval`: the task list, the offline CI modes, and a live run against a scripted model
//! API. No network, no daemon, no real Ghidra, no real model.

mod common;

use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;

use common::*;
use kraken_agent::{ChatProvider, FinishReason, ReplayProvider, StreamEvent, Usage};
use kraken_cli::{CliAuthor, CliEnv, run_with_provider};
use serde_json::Value;

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

async fn kraken_with(env: &CliEnv, provider: Option<Arc<dyn ChatProvider>>, args: &[&str]) -> Run {
    let argv: Vec<OsString> = std::iter::once("kraken")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run_with_provider(argv, env, provider, &mut out, &mut err).await;
    Run {
        code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }
}

fn plain_rig() -> Rig {
    rig(
        CliAuthor::User("tester".into()),
        vec![("KRAKEN_NO_DAEMON", "1".into())],
    )
}

#[tokio::test]
async fn list_shows_every_task_of_the_suite() {
    let r = plain_rig();
    let run = kraken_with(&r.env, None, &["eval", "list"]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("name/switch_vm"), "{}", run.stdout);
    assert!(run.stdout.contains("find/vm-interpreter"));
    assert!(run.stdout.contains("qa/imports-strcmp"));
    let json = kraken_with(&r.env, None, &["--json", "eval", "list"]).await;
    let v = json.json();
    assert_eq!(v["name"], "corpus");
    assert!(v["tasks"].as_array().is_some_and(|t| t.len() >= 20));
}

#[tokio::test]
async fn the_replay_mode_runs_offline_and_writes_the_report() {
    let r = plain_rig();
    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("report"));
    let run = kraken_with(
        &r.env,
        None,
        &[
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--task",
            "find/vm-",
            "--out",
            &dir,
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(run.stdout.contains("mean score"), "{}", run.stdout);
    assert!(run.stdout.contains("find_function"), "{}", run.stdout);
    assert!(run.stderr.contains("[3/3] find/vm-pop"), "{}", run.stderr);
    for f in ["report.json", "report.md", "transcripts/find-vm-fatal.md"] {
        assert!(Path::new(&dir).join(f).is_file(), "{f} is missing");
    }
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(&dir).join("report.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["mode"], "ci-replay");
    assert_eq!(report["summary"]["tasks"], 3);
    assert_eq!(report["backend"]["kind"], "api");

    // The same run with --json prints that report.
    let dir2 = path_str(&out.path().join("report2"));
    let json = kraken_with(
        &r.env,
        None,
        &[
            "--json",
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--task",
            "find/vm-",
            "--out",
            &dir2,
        ],
    )
    .await;
    assert_eq!(json.code, 0, "{}", json.stderr);
    assert_eq!(json.json()["summary"], report["summary"]);
}

#[tokio::test]
async fn the_min_score_gates_the_exit_code() {
    let r = plain_rig();
    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("r"));
    let run = kraken_with(
        &r.env,
        None,
        &[
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--task",
            "name/",
            "--out",
            &dir,
            "--min-score",
            "0.99",
        ],
    )
    .await;
    assert_eq!(run.code, 1, "{}{}", run.stdout, run.stderr);
    assert!(run.stderr.contains("below --min-score"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_agent_mode_runs_the_fake_terminal_agent() {
    let r = rig(
        CliAuthor::User("tester".into()),
        vec![
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_EXE", env!("CARGO_BIN_EXE_kraken").into()),
        ],
    );
    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("agent"));
    let run = kraken_with(
        &r.env,
        None,
        &[
            "--json",
            "eval",
            "run",
            "--backend",
            "ci-agent",
            "--task",
            "find/vm-",
            "--out",
            &dir,
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["mode"], "ci-agent");
    assert_eq!(v["backend"]["kind"], "terminal_agent");
    assert_eq!(v["summary"]["tasks"], 3);
    // The same script scores the same as through the cassette (all three are right here).
    let scores: Vec<f64> = v["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["score"].as_f64().unwrap())
        .collect();
    assert_eq!(scores, [1.0, 1.0, 1.0]);
    assert!(v["tasks"][0]["tool_calls"].as_u64().unwrap() >= 1);
}

fn reply(text: &str, usage: Usage) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta { text: text.into() },
        StreamEvent::Usage(usage),
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

#[tokio::test]
async fn a_live_run_measures_the_configured_model_and_can_record_it() {
    // The model API answers every question with the same address; the engine is the tiny fake
    // one, so this checks the plumbing (project per binary, tokens, cost, cassette), not the
    // scores.
    let r = plain_rig();
    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("live"));
    let cassette = path_str(&out.path().join("recorded.json"));
    let provider: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![reply(
        "<kraken-answer>{\"address\": \"0x401000\"}</kraken-answer>",
        Usage {
            input_tokens: 1000,
            output_tokens: 20,
        },
    )]));
    let run = kraken_with(
        &r.env,
        Some(provider),
        &[
            "--json",
            "eval",
            "run",
            "--task",
            "find/vm-fatal",
            "--task",
            "find/vm-pop",
            "--out",
            &dir,
            "--record",
            &cassette,
            "--price-in",
            "3",
            "--price-out",
            "15",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let v = run.json();
    assert_eq!(v["mode"], "live");
    assert_eq!(v["backend"]["id"], "replay");
    assert_eq!(v["summary"]["tasks"], 2);
    assert_eq!(v["summary"]["tokens"]["input"], 2000);
    assert_eq!(v["summary"]["tokens"]["output"], 40);
    let cost = v["summary"]["cost_usd"].as_f64().unwrap();
    assert!((cost - 0.0066).abs() < 1e-9, "{cost}");
    assert!(v["tasks"][0]["duration_ms"].is_u64(), "live runs are timed");
    // The recording has both tasks and replays.
    let rec: Value = serde_json::from_str(&std::fs::read_to_string(&cassette).unwrap()).unwrap();
    assert_eq!(rec["tasks"].as_object().unwrap().len(), 2);
    let replay = kraken_with(
        &r.env,
        None,
        &[
            "--json",
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--cassette",
            &cassette,
            "--task",
            "find/vm-fatal",
            "--out",
            &path_str(&out.path().join("again")),
        ],
    )
    .await;
    assert_eq!(replay.code, 0, "{}", replay.stderr);
}

#[tokio::test]
async fn bad_arguments_are_refused() {
    let r = plain_rig();
    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("x"));
    for args in [
        vec![
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--price-in",
            "3",
            "--out",
            &dir,
        ],
        vec![
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--record",
            "x.json",
            "--out",
            &dir,
        ],
        vec![
            "eval",
            "run",
            "--backend",
            "ci-replay",
            "--task",
            "nothing/",
            "--out",
            &dir,
        ],
    ] {
        let run = kraken_with(&r.env, None, &args).await;
        assert_eq!(run.code, 2, "{args:?}: {}{}", run.stdout, run.stderr);
    }
}

#[tokio::test]
async fn the_rewrite_suite_replays_and_reports_the_differential_numbers() {
    if !kraken_rewrite::sandbox::enforced_or_skip() {
        return;
    }
    let r = plain_rig();
    let list = kraken_with(&r.env, None, &["eval", "list", "--suite", "rewrite"]).await;
    assert_eq!(list.code, 0, "{}", list.stderr);
    assert!(list.stdout.contains("rw-prog/pie_list"), "{}", list.stdout);

    let out = tempfile::tempdir().expect("tempdir");
    let dir = path_str(&out.path().join("rw"));
    let run = kraken_with(
        &r.env,
        None,
        &[
            "eval",
            "run",
            "--suite",
            "rewrite",
            "--backend",
            "ci-replay",
            "--kind",
            "rewrite_program",
            "--out",
            &dir,
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}{}", run.stdout, run.stderr);
    assert!(
        run.stdout.contains("3 of 3 rewrite tasks passed"),
        "{}",
        run.stdout
    );
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(&dir).join("report.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["summary"]["rewrite"]["pass_rate"], 1.0);
    assert_eq!(report["summary"]["rewrite"]["repair_rounds"], 0);
    let md = std::fs::read_to_string(Path::new(&dir).join("report.md")).unwrap();
    assert!(md.contains("## Rewrite quality"), "{md}");
}

#[tokio::test]
async fn a_live_rewrite_run_is_held_to_the_configured_limits() {
    // `[ai_limits]` applies to the live rewrite suite as to every other model call: with no
    // calls allowed, the model is never asked.
    let out = tempfile::tempdir().expect("tempdir");
    let config = out.path().join("config.toml");
    std::fs::write(&config, "[ai_limits]\nmax_calls_per_run = 0\n").expect("config");
    let r = rig(
        CliAuthor::User("tester".into()),
        vec![
            ("KRAKEN_NO_DAEMON", "1".into()),
            ("KRAKEN_CONFIG", path_str(&config)),
        ],
    );
    let provider: Arc<dyn ChatProvider> = Arc::new(ReplayProvider::scripted(vec![reply(
        "```rust\nfn x() {}\n```",
        Usage {
            input_tokens: 1000,
            output_tokens: 20,
        },
    )]));
    let dir = path_str(&out.path().join("rw"));
    let run = kraken_with(
        &r.env,
        Some(provider),
        &[
            "--json",
            "eval",
            "run",
            "--suite",
            "rewrite",
            "--task",
            "rw-fn/pie_list/cmp_id",
            "--out",
            &dir,
        ],
    )
    .await;
    let v = run.json();
    assert_eq!(v["summary"]["rewrite"]["passed"], 0, "{v:#}");
    assert!(
        v["tasks"][0]["problem"]
            .as_str()
            .is_some_and(|p| p.contains("max_calls_per_run")),
        "{v:#}\n{}",
        run.stderr
    );
    // the refused call never reached the model: no tokens were used
    assert!(
        v["summary"]["tokens"].is_null() || v["summary"]["tokens"]["input"] == 0,
        "{v:#}"
    );
}

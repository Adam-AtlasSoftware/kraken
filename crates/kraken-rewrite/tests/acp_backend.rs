//! The rewrite pipeline on a terminal agent: `rewrite_function` and `rewrite_program` with the
//! fake ACP agent (a separate process speaking raw ACP) answering with the reference
//! translations, deterministically. The same prompts that go to a model API go to the agent as a
//! text-only request; the agent returns the translation in the usual `<kraken-rust>` /
//! `<kraken-result>` format, KRAKEN builds and checks it in its own sandbox, and every permission
//! request the agent makes for its own tools is denied.
//!
//! Like the cassette tests, the function-level test needs a Ghidra install for the SLEIGH specs
//! (`#[ignore]`, runs in the real-ghidra job); the program-level tests compile the translations
//! and run the original and the rewrite side by side, which needs only Landlock.
// The fake agent is a Unix-style process in these tests.
#![cfg(unix)]

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use common::{config, corpus_bin};
use engine_fake::{FakeEngine, FixtureFile};
use kraken_acp::{AgentProfile, LaunchSpec, McpServerConfig};
use kraken_assist::{AcpBackend, AcpSettings, AssistBackend};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::service::{FixedBackend, RewriteConfig, RewriteService};
use kraken_rewrite::targets::target;
use kraken_rewrite::task::RewriteTask;
use serde_json::{Value, json};

/// The `kraken-fake-acp-agent` binary: built on demand (a no-op when up to date) and found next
/// to the running test binary.
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
        let status = cmd.status().expect("run cargo build");
        assert!(status.success(), "building the fake ACP agent failed");
        let bin = profile_dir.join(format!(
            "kraken-fake-acp-agent{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(bin.is_file(), "missing {}", bin.display());
        bin
    })
    .clone()
}

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

fn user() -> CallContext {
    CallContext::user("tester", Surface::Test)
}

/// An answers file for the fake agent: for each `(function, Rust source)` the reply to the
/// request that starts `Translate the function `<function>``.
fn by_function(refs: &[(&str, &str)]) -> Vec<(String, String)> {
    refs.iter()
        .map(|(name, code)| {
            (
                format!("Translate the function `{name}`"),
                RewriteTask::reply_text(code, &[]),
            )
        })
        .collect()
}

/// The answers file of the fake agent: the first `(text the prompt contains, reply)` that fits
/// answers.
fn write_answers(tmp: &Path, answers: &[(String, String)]) -> String {
    let entries: Vec<Value> = answers
        .iter()
        .map(|(m, reply)| json!({"match": m, "reply": reply}))
        .collect();
    let path = tmp.join("answers.json");
    std::fs::write(&path, Value::Array(entries).to_string()).expect("answers");
    path.to_string_lossy().into_owned()
}

fn agent_backend(tmp: &Path, env: &[(&str, &str)]) -> Arc<AcpBackend> {
    let exe = fake_agent();
    let mut profile = AgentProfile::custom("fake", "Fake agent", exe.to_string_lossy(), vec![])
        // The rewrite requests carry no KRAKEN MCP server.
        .with_env("FAKE_ACP_ALLOW_NO_MCP", "1");
    for (k, v) in env {
        profile = profile.with_env(*k, *v);
    }
    let settings = AcpSettings {
        profile,
        launch: LaunchSpec {
            program: exe,
            args: vec![],
            path_prepend: None,
            via: "test".into(),
        },
        // Never started by a text-only request.
        mcp: McpServerConfig::project("/opt/kraken/kraken", tmp),
        project_dir: tmp.to_path_buf(),
        parent_env: Some(vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("HOME"), OsString::from("/nonexistent")),
        ]),
        start_timeout: Duration::from_secs(30),
        model: None,
    };
    Arc::new(AcpBackend::new(settings, Arc::new(Registry::standard())))
}

struct Rig {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    session: Session,
    registry: Registry,
    backend: Arc<AcpBackend>,
}

async fn rig(binary: &str, answers: &[(String, String)], env: &[(&str, &str)]) -> Rig {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{binary}.json"));
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::Builder::new()
        .prefix("kraken-rewrite-acp-")
        .tempdir()
        .expect("tempdir");
    let answers = write_answers(tmp.path(), answers);
    let mut vars = vec![("FAKE_ACP_COMPLETION_ANSWERS", answers.as_str())];
    vars.extend_from_slice(env);
    let backend = agent_backend(tmp.path(), &vars);
    let service = Arc::new(RewriteService::new(
        Arc::new(FixedBackend(backend.clone())),
        RewriteConfig {
            oracle: config(),
            ..RewriteConfig::default()
        },
    ));
    let rewrite: Arc<dyn RewriteBackend> = service;
    let session = Session::new(Arc::new(FakeFactory { fixture })).with_rewrite(rewrite);
    let dir = tmp.path().join("p");
    session
        .create_project(&dir, &corpus_bin(binary))
        .await
        .expect("project");
    Rig {
        _tmp: tmp,
        dir,
        session,
        registry: Registry::standard(),
        backend,
    }
}

impl Rig {
    async fn call(&self, name: &str, args: Value) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, &user(), args)
            .await
    }

    async fn job(&self, name: &str, args: Value) -> Result<Value, ProtoError> {
        let started = self.call(name, args).await?;
        let id = started["job_id"].as_str().expect("job id").to_string();
        let done = self
            .call("job_await", json!({"job_id": id, "timeout_ms": 900_000}))
            .await?;
        match done["status"].as_str() {
            Some("succeeded") => Ok(done["result"].clone()),
            _ => Err(serde_json::from_value(done["error"].clone())
                .unwrap_or_else(|_| ProtoError::new(ErrorCode::Internal, done.to_string()))),
        }
    }
}

fn sandbox_available() -> bool {
    if kraken_rewrite::sandbox::enforced() {
        true
    } else {
        eprintln!("skipped: this host cannot confine generated code (Landlock ABI 4+ needed)");
        false
    }
}

const CMP_ID: &str = include_str!("../references/cmp_id.rs");

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn rewrite_function_on_a_terminal_agent_is_verified_and_the_agent_cannot_act() {
    if !sandbox_available() {
        return;
    }
    let marker = std::env::temp_dir().join(format!(
        "kraken-acp-marker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let r = rig(
        "pie_list-O0",
        &by_function(&[("cmp_id", CMP_ID)]),
        &[(
            "FAKE_ACP_COMPLETION_MISBEHAVE",
            marker.to_str().expect("utf8"),
        )],
    )
    .await;
    let out = r
        .job(
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 40}),
        )
        .await
        .expect("rewrite_function");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["status"], "verified");
    assert_eq!(out["version"], 1);
    assert_eq!(out["provider"], "fake", "the unit names the agent");
    assert_eq!(out["cases_run"], out["passed"]);
    assert!(
        out["sandbox"]
            .as_str()
            .is_some_and(|s| s.starts_with("landlock")),
        "KRAKEN built and ran it in its own sandbox: {out:#}"
    );

    // The agent asked to write a file and to run the build; both were denied.
    let granted = marker.exists();
    let _ = std::fs::remove_file(&marker);
    assert!(!granted, "a permission request of the agent was granted");
    let notes = r.backend.take_notes();
    assert!(
        notes.iter().any(|n| n.contains("every request was denied")),
        "{notes:?}"
    );

    // The stored unit is the reference translation, with the agent as its provenance.
    let sha = r.session.project().expect("project").program().sha256;
    let store = kraken_rewrite::store::RewriteStore::in_project(&r.dir).expect("store");
    let unit = store.latest(&sha, "0x10124e").expect("read").expect("unit");
    assert!(unit.rust_code.contains("fn cmp_id("));
    assert_eq!(unit.provenance.provider.as_deref(), Some("fake"));
    assert_eq!(unit.anchor.name, "cmp_id");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn a_repair_attempt_goes_to_the_agent_with_the_counterexample() {
    if !sandbox_available() {
        return;
    }
    let reference = target("cmp_id").expect("target").reference;
    let wrong = reference.replace(
        "(*a).id.wrapping_sub((*b).id)",
        "(*a).id.cmp(&(*b).id) as i32",
    );
    assert_ne!(wrong, reference);
    // The repair request is the one that carries the failed attempt.
    let answers = vec![
        (
            "Attempt 1 failed (it behaves differently from the original)".to_string(),
            RewriteTask::reply_text(reference, &[]),
        ),
        (
            "Translate the function `cmp_id`".to_string(),
            RewriteTask::reply_text(&wrong, &[]),
        ),
    ];
    let r = rig("pie_list-O0", &answers, &[]).await;
    let out = r
        .job(
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 30}),
        )
        .await
        .expect("rewrite_function");
    assert_eq!(out["attempts"], 2, "{out:#}");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["version"], 2);
    assert_eq!(out["provider"], "fake");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn spec_mode_runs_both_model_calls_on_the_agent() {
    if !sandbox_available() {
        return;
    }
    let spec = include_str!("../references/spec_cmp_id.md");
    let answers = vec![
        (
            "Write the behavioural spec of this function.".to_string(),
            spec.to_string(),
        ),
        (
            "Implement the function `cmp_id`".to_string(),
            RewriteTask::reply_text(CMP_ID, &["ids are compared as i32"]),
        ),
    ];
    let r = rig("pie_list-O0", &answers, &[]).await;
    let out = r
        .job(
            "rewrite_function",
            json!({"address": "0x10124e", "mode": "spec", "cases": 30}),
        )
        .await
        .expect("rewrite_function spec");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["mode"], "spec");
    assert_eq!(out["provider"], "fake");
    assert_eq!(out["assumptions"][0]["value"], "ids are compared as i32");
    let sha = r.session.project().expect("project").program().sha256;
    let store = kraken_rewrite::store::RewriteStore::in_project(&r.dir).expect("store");
    let unit = store.latest(&sha, "0x10124e").expect("read").expect("unit");
    let spec = store
        .spec(unit.spec_id.expect("spec id"))
        .expect("spec")
        .expect("stored");
    assert_eq!(spec.provider, "fake");
    assert_eq!(spec.citations, vec![0x10124e]);
}

#[tokio::test]
async fn a_function_the_agent_cannot_translate_is_a_failure_not_a_hang() {
    if !sandbox_available() {
        return;
    }
    // No answer for the function: the agent replies without a result block, as one that gave up.
    let r = rig("stripped_calc-O0", &[], &[]).await;
    let err = r
        .job(
            "rewrite_program",
            json!({"scope": "all", "verify_functions": false}),
        )
        .await;
    // Either the run ends with an error or every function failed; it must not succeed.
    match err {
        Err(_) => {}
        Ok(out) => {
            assert_eq!(out["translated"], 0, "{out:#}");
            assert_ne!(out["verdict"]["verdict"], "pass", "{out:#}");
        }
    }
}

const CALC: &[(&str, &str)] = &[
    (
        "skip_ws",
        include_str!("../references/program/stripped_calc/skip_ws.rs"),
    ),
    (
        "parse_number",
        include_str!("../references/program/stripped_calc/parse_number.rs"),
    ),
    (
        "parse_atom",
        include_str!("../references/program/stripped_calc/parse_atom.rs"),
    ),
    (
        "parse_term",
        include_str!("../references/program/stripped_calc/parse_term.rs"),
    ),
    (
        "parse_expr",
        include_str!("../references/program/stripped_calc/parse_expr.rs"),
    ),
    (
        "evaluate",
        include_str!("../references/program/stripped_calc/evaluate.rs"),
    ),
    (
        "fn_1014c1",
        include_str!("../references/program/stripped_calc/main.rs"),
    ),
];

#[tokio::test]
async fn rewrite_program_on_a_terminal_agent_matches_the_original() {
    if !sandbox_available() {
        return;
    }
    let marker = std::env::temp_dir().join(format!(
        "kraken-acp-prog-marker-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    let r = rig(
        "stripped_calc-O0",
        &by_function(CALC),
        &[(
            "FAKE_ACP_COMPLETION_MISBEHAVE",
            marker.to_str().expect("utf8"),
        )],
    )
    .await;
    let out = r
        .job(
            "rewrite_program",
            json!({"scope": "all", "verify_functions": false}),
        )
        .await
        .expect("rewrite_program");

    // The same run as with the cassette: every function translated bottom-up, one attempt each.
    assert_eq!(out["functions_planned"], 7, "{out:#}");
    assert_eq!(out["translated"], 7);
    assert_eq!(out["failed"], 0);
    assert_eq!(out["included"], 7);
    assert_eq!(out["provider"], "fake");
    for f in out["functions"].as_array().expect("functions") {
        assert_eq!(f["check"], "compile_only", "{f}");
        assert_eq!(f["status"], "translated", "{f}");
        assert_eq!(f["attempts"], 1);
    }
    assert_eq!(out["built"], true);

    // KRAKEN built the crate and ran it next to the original; the verdict is its own.
    let v = &out["verdict"];
    assert_eq!(v["verdict"], "pass", "{v:#}");
    assert_eq!(v["failed"], 0);
    assert!(
        v["sandbox"]
            .as_str()
            .expect("sandbox")
            .starts_with("landlock")
    );
    let base = v["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == "baseline");
    if let Some(base) = base {
        assert_eq!(base["agree"], true);
        assert_eq!(base["rewritten"]["stdout"], base["original"]["stdout"]);
    }

    // Seven agent sessions each asked to write a file and run the build; none was allowed.
    let granted = marker.exists();
    let _ = std::fs::remove_file(&marker);
    assert!(!granted, "a permission request of the agent was granted");
    let notes = r.backend.take_notes();
    assert!(
        notes.iter().any(|n| n.contains("every request was denied")),
        "{notes:?}"
    );
    // The agent never wrote into the project: only KRAKEN's own files are there.
    let crate_dir = r.dir.join("rewrite-program");
    assert!(crate_dir.join("src/u_skip_ws.rs").is_file());
    assert!(!r.dir.join("translation.rs").exists());
}

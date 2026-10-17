//! `rewrite_program` end to end on corpus programs, offline: FakeEngine on a corpus fixture, the
//! `RewriteService` backend, a `ReplayProvider` cassette whose replies are hand-checked reference
//! translations (`references/program/`), the real sandbox, and the original corpus binary run
//! next to the generated Rust crate.
//!
//! The default tests compile the translations but skip the function-level differential test, so
//! they need no Ghidra install: the program-level test is the evidence. The `#[ignore]` ones
//! also run the emulation oracle and need the SLEIGH specs of a Ghidra install.
//!
//! Regenerate the cassettes after a prompt change with
//! `KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test program`.

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{config, corpus_bin};
use engine_fake::{FakeEngine, FixtureFile};
use futures_util::StreamExt;
use kraken_agent::{
    AgentError, Cassette, ChatProvider, ChatRequest, FinishReason, Message, RecordingProvider,
    ReplayProvider, StreamEvent,
};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{AutoApprove, CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::service::{ProviderSource, RewriteConfig, RewriteService};
use kraken_rewrite::store::RewriteStore;
use kraken_rewrite::task::RewriteTask;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

struct Source(Arc<dyn ChatProvider>);

impl ProviderSource for Source {
    fn provider(&self) -> Result<Arc<dyn ChatProvider>, ProtoError> {
        Ok(self.0.clone())
    }
}

/// Answers each translation request with the reference translation of the function it asks for.
struct ReferenceProvider {
    by_function: HashMap<String, String>,
}

impl ReferenceProvider {
    fn new(refs: &[(&str, &str)]) -> Self {
        ReferenceProvider {
            by_function: refs
                .iter()
                .map(|(n, c)| ((*n).to_string(), (*c).to_string()))
                .collect(),
        }
    }

    fn with(mut self, name: &str, code: &str) -> Self {
        self.by_function.insert(name.into(), code.into());
        self
    }
}

#[async_trait]
impl ChatProvider for ReferenceProvider {
    fn info(&self) -> kraken_agent::ProviderInfo {
        kraken_agent::ProviderInfo {
            id: "replay".into(),
            model: "cassette".into(),
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

fn user() -> CallContext {
    CallContext::user("tester", Surface::Test)
}

/// An agent whose person approves running the original program.
fn agent() -> CallContext {
    CallContext::agent("bot", "run-1", Surface::Test).with_approval(Arc::new(AutoApprove))
}

struct Rig {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    session: Session,
    registry: Registry,
}

async fn rig(binary: &str, provider: Arc<dyn ChatProvider>) -> Rig {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{binary}.json"));
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::Builder::new()
        .prefix("kraken-rewrite-prog-")
        .tempdir()
        .expect("tempdir");
    let service = Arc::new(RewriteService::new(
        Arc::new(Source(provider)),
        RewriteConfig {
            oracle: config(),
            ..RewriteConfig::default()
        },
    ));
    let backend: Arc<dyn RewriteBackend> = service;
    let session = Session::new(Arc::new(FakeFactory { fixture })).with_rewrite(backend);
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
    }
}

impl Rig {
    async fn call(&self, ctx: &CallContext, name: &str, args: Value) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, ctx, args)
            .await
    }

    async fn job(&self, ctx: &CallContext, name: &str, args: Value) -> Result<Value, ProtoError> {
        let started = self.call(ctx, name, args).await?;
        let id = started["job_id"].as_str().expect("job id").to_string();
        let done = self
            .call(
                &user(),
                "job_await",
                json!({"job_id": id, "timeout_ms": 900_000}),
            )
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

fn cassette_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("cassettes")
        .join(name)
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

const VM: &[(&str, &str)] = &[
    (
        "vm_fail",
        include_str!("../references/program/switch_vm/vm_fail.rs"),
    ),
    (
        "push",
        include_str!("../references/program/switch_vm/push.rs"),
    ),
    (
        "pop",
        include_str!("../references/program/switch_vm/pop.rs"),
    ),
    (
        "vm_run",
        include_str!("../references/program/switch_vm/vm_run.rs"),
    ),
    (
        "op_name",
        include_str!("../references/program/switch_vm/op_name.rs"),
    ),
    (
        "fn_101707",
        include_str!("../references/program/switch_vm/main.rs"),
    ),
];

const STROPS: &[(&str, &str)] = &[
    (
        "hash_str",
        include_str!("../references/program/static_strops/hash_str.rs"),
    ),
    (
        "str_reverse",
        include_str!("../references/program/static_strops/str_reverse.rs"),
    ),
    (
        "str_count_char",
        include_str!("../references/program/static_strops/str_count_char.rs"),
    ),
    (
        "str_upper",
        include_str!("../references/program/static_strops/str_upper.rs"),
    ),
    (
        "is_palindrome",
        include_str!("../references/program/static_strops/is_palindrome.rs"),
    ),
    (
        "caesar",
        include_str!("../references/program/static_strops/caesar.rs"),
    ),
    (
        "join_words",
        include_str!("../references/program/static_strops/join_words.rs"),
    ),
    (
        "fn_401a5e",
        include_str!("../references/program/static_strops/main.rs"),
    ),
];

/// The provider of a cassette-backed test. With `KRAKEN_UPDATE_CASSETTES` the reference
/// translations are asked for the real prompts and the cassette is rewritten first.
async fn cassette_provider(
    cassette: &str,
    binary: &str,
    refs: &[(&str, &str)],
) -> Arc<dyn ChatProvider> {
    static WRITE: Mutex<()> = Mutex::new(());
    let path = cassette_path(cassette);
    if std::env::var_os("KRAKEN_UPDATE_CASSETTES").is_some() {
        let recorder = Arc::new(RecordingProvider::new(Arc::new(ReferenceProvider::new(
            refs,
        ))));
        let r = rig(binary, recorder.clone()).await;
        r.job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false, "build": false}),
        )
        .await
        .expect("recording run");
        let _g = WRITE.lock().unwrap_or_else(|e| e.into_inner());
        recorder.cassette().save(&path).expect("save cassette");
    }
    let cassette = Cassette::load(&path).unwrap_or_else(|e| {
        panic!(
            "{e}; regenerate with KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test program"
        )
    });
    Arc::new(ReplayProvider::new(cassette))
}

fn function<'a>(result: &'a Value, name: &str) -> &'a Value {
    result["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|f| f["name"]["value"] == name)
        .unwrap_or_else(|| panic!("no function {name} in {result:#}"))
}

/// The function table of a result, one line each, for the log of the ignored tests.
fn table(result: &Value) -> String {
    let mut s = String::new();
    for f in result["functions"].as_array().expect("functions") {
        s.push_str(&format!(
            "{:<14} {:<13} {:<10} {:<13} {}\n",
            f["name"]["value"].as_str().unwrap_or("?"),
            f["check"].as_str().unwrap_or("?"),
            f["status"].as_str().unwrap_or("?"),
            f["verdict"].as_str().unwrap_or("?"),
            f["check_note"]["value"].as_str().unwrap_or(""),
        ));
    }
    s
}

fn baseline(result: &Value) -> &Value {
    result["verdict"]["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|c| c["name"] == "baseline")
        .expect("baseline case")
}

// ----- the corpus programs, default (no Ghidra) -----

#[tokio::test]
async fn stripped_calc_is_rewritten_and_matches_the_original() {
    if !sandbox_available() {
        return;
    }
    let provider = cassette_provider("program-stripped-calc.json", "stripped_calc-O0", CALC).await;
    let r = rig("stripped_calc-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"scope": "all", "verify_functions": false}),
        )
        .await
        .expect("rewrite_program");

    // Bottom-up: every function was translated, each calling what was translated before it.
    assert_eq!(out["functions_planned"], 7, "{out:#}");
    assert_eq!(out["translated"], 7);
    assert_eq!(out["failed"], 0);
    assert_eq!(out["included"], 7);
    assert_eq!(out["entry_name"]["value"], "main");
    let order: Vec<&str> = out["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| f["name"]["value"].as_str().expect("name"))
        .collect();
    assert_eq!(
        order,
        [
            "skip_ws",
            "parse_number",
            "parse_atom",
            "parse_term",
            "parse_expr",
            "evaluate",
            "main"
        ]
    );
    assert!(function(&out, "skip_ws").get("reused_callees").is_none());
    assert_eq!(
        function(&out, "parse_number")["reused_callees"],
        json!(["skip_ws"])
    );
    // The recursive group is translated once, in its first member; the others call it.
    assert_eq!(
        function(&out, "parse_atom")["reused_callees"],
        json!(["skip_ws", "parse_number"])
    );
    assert_eq!(
        function(&out, "parse_term")["reused_callees"],
        json!(["skip_ws", "parse_atom"])
    );
    assert_eq!(
        function(&out, "evaluate")["reused_callees"],
        json!(["skip_ws", "parse_expr"])
    );
    for f in out["functions"].as_array().expect("functions") {
        assert_eq!(f["check"], "compile_only", "{f}");
        assert_eq!(f["status"], "translated", "{f}");
        assert_eq!(f["attempts"], 1);
    }

    // The crate.
    assert_eq!(out["built"], true);
    let crate_dir = PathBuf::from(out["crate_dir"].as_str().expect("crate dir"));
    assert_eq!(crate_dir, r.dir.join("rewrite-program"));
    for f in [
        "Cargo.toml",
        "README.md",
        "kraken-program.json",
        "src/main.rs",
        "src/rt.rs",
        "src/u_skip_ws.rs",
        "src/u_fn_1014c1.rs",
    ] {
        assert!(crate_dir.join(f).is_file(), "missing {f}");
    }
    assert_eq!(
        std::fs::read_to_string(crate_dir.join("src/rt.rs")).expect("rt.rs"),
        kraken_rewrite::RT_SOURCE
    );
    let evaluate_src = std::fs::read_to_string(crate_dir.join("src/u_evaluate.rs")).expect("src");
    assert!(evaluate_src.contains("use super::u_parse_expr::parse_expr;"));
    assert!(!evaluate_src.contains("no_mangle"));

    // The program-level verdict.
    let v = &out["verdict"];
    assert_eq!(v["verdict"], "pass", "{v:#}");
    assert!(v["cases_run"].as_u64().expect("cases") >= 12, "{v:#}");
    assert_eq!(v["failed"], 0);
    assert!(
        v["sandbox"]
            .as_str()
            .expect("sandbox")
            .starts_with("landlock")
    );
    let base = baseline(&out);
    assert_eq!(base["agree"], true);
    let stdout = base["original"]["stdout"]["value"]
        .as_str()
        .expect("stdout");
    assert!(stdout.contains("1 + 2 * 3          = 7\n"), "{stdout}");
    assert!(stdout.contains("100 / (5 - 5)      : error\n"), "{stdout}");
    assert!(stdout.ends_with("errors: 2\n"), "{stdout}");
    assert_eq!(base["rewritten"]["stdout"], base["original"]["stdout"]);
    assert_eq!(base["rewritten"]["exit"], "exit 0");
    // Cases derived from the program's source, and generated ones, ran too.
    let origins: Vec<&str> = v["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| c["origin"].as_str().expect("origin"))
        .collect();
    assert!(origins.contains(&"corpus") && origins.contains(&"generated"));

    // The status command reads it back.
    let st = r
        .call(&agent(), "rewrite_program_status", json!({}))
        .await
        .expect("status");
    assert_eq!(st["present"], true);
    assert_eq!(st["runs"][0]["run"], 1);
    assert_eq!(st["runs"][0]["verdict"], "pass");
    assert_eq!(st["run"]["entry_name"]["value"], "main");
    assert_eq!(
        st["run"]["verdict"]["cases"].as_array().map(Vec::len),
        Some(0),
        "only differing cases by default"
    );
    let all = r
        .call(
            &agent(),
            "rewrite_program_status",
            json!({"all_cases": true}),
        )
        .await
        .expect("status all");
    assert_eq!(all["run"]["verdict"]["cases"], out["verdict"]["cases"]);
    let missing = r
        .call(&agent(), "rewrite_program_status", json!({"run": 9}))
        .await
        .expect_err("no such run");
    assert_eq!(missing.code, ErrorCode::NotFound);

    // Each translation was stored as a unit, none accepted.
    let status = r
        .call(&user(), "rewrite_status", json!({}))
        .await
        .expect("rewrite_status");
    assert_eq!(status["counts"]["translated"], 7, "{status:#}");
    assert_eq!(status["counts"]["accepted"], 0);
}

#[tokio::test]
async fn switch_vm_is_rewritten_and_matches_the_original() {
    if !sandbox_available() {
        return;
    }
    let provider = cassette_provider("program-switch-vm.json", "switch_vm-O0", VM).await;
    let r = rig("switch_vm-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"scope": "all", "verify_functions": false, "generated_cases": 12}),
        )
        .await
        .expect("rewrite_program");
    assert_eq!(out["functions_planned"], 6, "{out:#}");
    assert_eq!(out["included"], 6);
    assert_eq!(out["failed"], 0);
    assert_eq!(
        function(&out, "vm_run")["reused_callees"],
        json!(["vm_fail", "push", "pop"])
    );
    assert_eq!(function(&out, "push")["reused_callees"], json!(["vm_fail"]));
    // `op_name` returns a pointer, which the function-level test cannot compare.
    let op_name = function(&out, "op_name");
    assert_eq!(op_name["check"], "compile_only");
    let v = &out["verdict"];
    assert_eq!(v["verdict"], "pass", "{v:#}");
    assert_eq!(v["failed"], 0);
    let base = baseline(&out);
    let stdout = base["original"]["stdout"]["value"]
        .as_str()
        .expect("stdout");
    assert!(stdout.starts_with("out: 5\nout: 4\n"), "{stdout}");
    assert!(stdout.contains("first=push\n"), "{stdout}");
    assert_eq!(base["rewritten"]["stdout"], base["original"]["stdout"]);
    // The rewritten crate is a standalone binary crate with the shim.
    let crate_dir = PathBuf::from(out["crate_dir"].as_str().expect("crate dir"));
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(crate_dir.join("kraken-program.json")).expect("manifest"),
    )
    .expect("json");
    assert_eq!(manifest["generator"], "kraken-rewrite/program");
    assert_eq!(manifest["entry"], "fn_101707");
    assert_eq!(manifest["functions"].as_array().map(Vec::len), Some(6));
}

#[tokio::test]
async fn static_strops_is_rewritten_and_the_linked_in_libc_is_left_alone() {
    if !sandbox_available() {
        return;
    }
    let provider =
        cassette_provider("program-static-strops.json", "static_strops-O0", STROPS).await;
    let r = rig("static_strops-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false}),
        )
        .await
        .expect("rewrite_program");
    // The binary carries its libc: 68 functions in the plan, 8 of them the program.
    assert_eq!(out["functions_planned"], 68, "{}", table(&out));
    assert_eq!(out["skipped"], 60);
    assert_eq!(out["included"], 8);
    assert_eq!(out["failed"], 0, "{}", table(&out));
    let v = &out["verdict"];
    assert_eq!(v["verdict"], "pass", "{v:#}");
    let stdout = baseline(&out)["original"]["stdout"]["value"]
        .as_str()
        .expect("stdout")
        .to_string();
    assert!(
        stdout.starts_with("joined: static linking keeps libc inside (32)\n"),
        "{stdout}"
    );
    assert!(stdout.contains("caesar changed"), "{stdout}");
    assert!(stdout.contains("hash="), "{stdout}");
}

/// The reference translations of stripped_calc under the names Ghidra gives in the stripped
/// binary (`FUN_<address>`); the code is the same.
fn stripped_names() -> Vec<(String, String)> {
    let names = [
        ("skip_ws", "FUN_00101149"),
        ("parse_number", "FUN_00101197"),
        ("parse_atom", "FUN_00101247"),
        ("parse_term", "FUN_0010130d"),
        ("parse_expr", "FUN_001013cf"),
        ("evaluate", "FUN_0010145b"),
        ("fn_1014c1", "FUN_001014c1"),
    ];
    CALC.iter()
        .map(|(name, code)| {
            let mut code = (*code).to_string();
            for (from, to) in names {
                code = code.replace(from, to);
            }
            let to = names
                .iter()
                .find(|(f, _)| f == name)
                .map_or(*name, |(_, t)| t);
            (to.to_string(), code)
        })
        .collect()
}

#[tokio::test]
async fn stripped_calc_without_symbols_is_rewritten_from_the_entry_stub() {
    if !sandbox_available() {
        return;
    }
    let owned = stripped_names();
    let refs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_str()))
        .collect();
    let provider = cassette_provider(
        "program-stripped-calc-stripped.json",
        "stripped_calc-O0-stripped",
        &refs,
    )
    .await;
    let r = rig("stripped_calc-O0-stripped", provider).await;
    // No function is called `main`: the entry stub hands `FUN_001014c1` to `__libc_start_main`.
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false}),
        )
        .await
        .expect("rewrite_program");
    assert_eq!(out["entry"], "0x1014c1", "{out:#}");
    assert_eq!(out["entry_name"]["value"], "FUN_001014c1");
    // Seven functions are the program; four more are loader glue the stripped binary gives no
    // names to, and the entry point does not reach them.
    assert_eq!(out["functions_planned"], 11, "{}", table(&out));
    assert_eq!(out["skipped"], 4);
    assert_eq!(out["included"], 7);
    assert_eq!(out["failed"], 0, "{}", table(&out));
    assert_eq!(out["verdict"]["verdict"], "pass", "{:#}", out["verdict"]);
    let base = baseline(&out);
    assert!(
        base["original"]["stdout"]["value"]
            .as_str()
            .expect("stdout")
            .ends_with("errors: 2\n")
    );
    // The cases come from the source of the unstripped twin.
    assert!(
        out["verdict"]["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .any(|c| c["origin"] == "corpus")
    );
}

// ----- failures are reported, not hidden -----

#[tokio::test]
async fn a_wrong_translation_is_a_failed_program_verdict_with_the_diff() {
    if !sandbox_available() {
        return;
    }
    // `vm_run` whose PRINT writes two spaces: it compiles and almost everything still agrees.
    let wrong = VM
        .iter()
        .find(|(n, _)| *n == "vm_run")
        .map(|(_, c)| c.replace("b\"out: %d\\n\\0\"", "b\"out:  %d\\n\\0\""))
        .expect("vm_run");
    assert!(wrong.contains("out:  %d"));
    let provider = Arc::new(ReferenceProvider::new(VM).with("vm_run", &wrong));
    let r = rig("switch_vm-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false}),
        )
        .await
        .expect("rewrite_program");
    let v = &out["verdict"];
    assert_eq!(v["verdict"], "fail", "{v:#}");
    assert!(v["failed"].as_u64().expect("failed") >= 1);
    let bad = baseline(&out);
    assert_eq!(bad["agree"], false);
    let d = bad["differences"][0]["value"].as_str().expect("diff");
    assert!(
        d.starts_with("stdout:") && d.contains("first difference at byte 5"),
        "{d}"
    );
    assert_eq!(bad["original"]["exit"], "exit 0");
    // The status command lists the failing cases by default.
    let st = r
        .call(&agent(), "rewrite_program_status", json!({}))
        .await
        .expect("status");
    assert_eq!(st["run"]["verdict"]["verdict"], "fail");
    assert!(
        st["run"]["verdict"]["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .all(|c| c["agree"] == false)
    );
}

#[tokio::test]
async fn a_function_that_does_not_compile_makes_the_program_incomplete() {
    if !sandbox_available() {
        return;
    }
    // `main` does not compile; with one attempt there is no repair.
    let provider = Arc::new(ReferenceProvider::new(VM).with(
        "fn_101707",
        "#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn fn_101707() -> i32 { let x: i32 = \"no\"; x }",
    ));
    let r = rig("switch_vm-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false, "max_attempts": 1}),
        )
        .await
        .expect("rewrite_program");
    assert_eq!(out["failed"], 1, "{out:#}");
    let main = function(&out, "main");
    assert_eq!(main["status"], "failed");
    assert_eq!(main["included"], false);
    assert_eq!(out["built"], false);
    assert_eq!(out["verdict"]["verdict"], "incomplete");
    assert_eq!(out["verdict"]["cases_run"], 0);
    let why = out["verdict"]["detail"]["value"].as_str().expect("detail");
    assert!(
        why.contains("main") && why.contains("no usable translation"),
        "{why}"
    );
    // The functions below it are still translated and stored.
    assert_eq!(function(&out, "vm_run")["status"], "translated");
}

#[tokio::test]
async fn given_cases_run_and_agents_cannot_accept() {
    if !sandbox_available() {
        return;
    }
    let provider = Arc::new(ReferenceProvider::new(VM));
    let r = rig("switch_vm-O0", provider).await;
    let denied = r
        .call(
            &agent(),
            "rewrite_program",
            json!({"accept_verified": true, "verify_functions": false}),
        )
        .await
        .expect_err("agents cannot accept");
    assert_eq!(denied.code, ErrorCode::RejectedHumanPriority);
    let out = r
        .job(
            &agent(),
            "rewrite_program",
            json!({
                "verify_functions": false,
                "generated_cases": 0,
                "dir": "out/vm",
                "inputs": [
                    {"name": "mine", "argv": ["--flag", "x y"], "stdin": "hello\n"},
                    {"name": "empty-arg", "argv": [""]}
                ]
            }),
        )
        .await
        .expect("rewrite_program");
    assert_eq!(out["crate_dir"], r.dir.join("out/vm").display().to_string());
    let cases = out["verdict"]["cases"].as_array().expect("cases");
    let mine = cases.iter().find(|c| c["name"] == "mine").expect("mine");
    assert_eq!(mine["origin"], "user");
    assert_eq!(mine["argv"][1]["value"], "x y");
    assert_eq!(mine["stdin_bytes"], 6);
    assert!(cases.iter().any(|c| c["name"] == "empty-arg"));
    assert!(!cases.iter().any(|c| c["origin"] == "generated"));
    assert_eq!(out["verdict"]["verdict"], "pass");

    // A second run into the same directory replaces the crate; any other directory is refused.
    r.job(
        &user(),
        "rewrite_program",
        json!({"verify_functions": false, "dir": "out/vm", "build": false}),
    )
    .await
    .expect("second run");
    let junk = r.dir.join("junk");
    std::fs::create_dir_all(&junk).expect("mkdir");
    std::fs::write(junk.join("keep.txt"), "x").expect("write");
    let err = r
        .job(
            &user(),
            "rewrite_program",
            json!({"verify_functions": false, "dir": "junk"}),
        )
        .await
        .expect_err("not an earlier program rewrite");
    assert!(err.message.contains("not empty"), "{}", err.message);
    assert!(junk.join("keep.txt").is_file());
    let escape = r
        .call(&user(), "rewrite_program", json!({"dir": "../escape"}))
        .await
        .expect_err("..");
    assert_eq!(escape.code, ErrorCode::InvalidArgument);
    let runs = RewriteStore::in_project(&r.dir).expect("store");
    assert!(
        runs.program_run(&common_sha("switch_vm-O0"), None)
            .expect("run")
            .is_some()
    );
}

fn common_sha(binary: &str) -> String {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{binary}.json"));
    FixtureFile::from_path(&fx).expect("fixture").program.sha256
}

// ----- with the emulation oracle (needs a Ghidra install for the SLEIGH specs) -----

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn switch_vm_is_checked_function_by_function_and_as_a_program() {
    if !sandbox_available() {
        return;
    }
    let provider = cassette_provider("program-switch-vm.json", "switch_vm-O0", VM).await;
    let r = rig("switch_vm-O0", provider).await;
    let out = r
        .job(&user(), "rewrite_program", json!({"scope": "all"}))
        .await
        .expect("rewrite_program");
    eprintln!("{}", table(&out));
    for name in ["vm_fail", "push", "pop", "vm_run"] {
        let f = function(&out, name);
        assert_eq!(f["check"], "differential", "{f}");
        assert_eq!(f["verdict"], "pass", "{f}");
        assert_eq!(f["status"], "verified", "{f}");
    }
    assert_eq!(function(&out, "op_name")["check"], "compile_only");
    assert_eq!(out["verdict"]["verdict"], "pass");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn stripped_calc_is_checked_function_by_function_and_as_a_program() {
    if !sandbox_available() {
        return;
    }
    let provider = cassette_provider("program-stripped-calc.json", "stripped_calc-O0", CALC).await;
    let r = rig("stripped_calc-O0", provider).await;
    let out = r
        .job(
            &user(),
            "rewrite_program",
            json!({"scope": "all", "accept_verified": true}),
        )
        .await
        .expect("rewrite_program");
    eprintln!("{}", table(&out));
    // Curated inputs exist for `evaluate`; the parser functions take a struct that holds a
    // pointer, which random bytes cannot build, so their test says it could not tell (it used to
    // pass because both sides crash on every input).
    for name in [
        "skip_ws",
        "parse_number",
        "parse_atom",
        "parse_term",
        "parse_expr",
    ] {
        let f = function(&out, name);
        assert_eq!(f["check"], "differential", "{f}");
        assert_eq!(f["verdict"], "inconclusive", "{f}");
        assert_eq!(f["status"], "translated", "{f}");
        assert!(
            f["check_note"]["value"]
                .as_str()
                .expect("note")
                .contains("faulted on 200 of 200"),
            "{f}"
        );
    }
    for name in ["evaluate", "main"] {
        let f = function(&out, name);
        assert_eq!(f["check"], "differential", "{f}");
        assert_eq!(f["verdict"], "pass", "{f}");
        assert_eq!(f["status"], "accepted", "{f}");
    }
    assert_eq!(out["verdict"]["verdict"], "pass");
}

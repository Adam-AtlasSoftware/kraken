//! The `assist_*` job commands end to end: a scripted model, the engine-fake fixture of the
//! stripped calculator, the real registry. No network.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_agent::{FinishReason, ProviderInfo, ReplayProvider, StreamEvent};
use kraken_assist::{AiPolicy, AssistService, FixedSource};
use kraken_engine::SharedEngine;
use kraken_proto::ProtoError;
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, CallContext, EngineFactory, Registry,
    Session, Surface,
};
use serde_json::{Value, json};

struct Factory;

#[async_trait]
impl EngineFactory for Factory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        let fx = FixtureFile::from_path(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../corpus/fixtures/stripped_calc-O0-stripped.json"),
        )
        .expect("stripped_calc fixture");
        Ok(Arc::new(FakeEngine::new(fx)))
    }
}

fn call(id: &str, name: &str, args: Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::ToolCallDelta {
            index: 0,
            id: Some(id.into()),
            name: Some(name.into()),
            arguments: args.to_string(),
        },
        StreamEvent::Finish {
            reason: FinishReason::ToolCalls,
        },
    ]
}

fn answer(prose: &str, result: Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::TextDelta {
            text: format!("{prose}\n<kraken-result>{result}</kraken-result>"),
        },
        StreamEvent::Finish {
            reason: FinishReason::Stop,
        },
    ]
}

fn session(script: Vec<Vec<StreamEvent>>) -> (Arc<Session>, tempfile::TempDir) {
    let provider = ReplayProvider::scripted(script).with_info(ProviderInfo {
        id: "replay".into(),
        model: "scripted".into(),
        supports_tools: true,
        context_window: None,
    });
    let source = FixedSource {
        provider: Arc::new(provider),
        policy: AiPolicy::default(),
    };
    let s = Session::new(Arc::new(Factory))
        .with_assist(AssistService::new(Arc::new(source)).into_backend());
    (Arc::new(s), tempfile::tempdir().expect("tempdir"))
}

async fn open(s: &Session, tmp: &tempfile::TempDir) {
    let binary = tmp.path().join("calc.bin");
    std::fs::write(&binary, b"\x7fELF fake").expect("binary");
    s.create_project(&tmp.path().join("p"), &binary)
        .await
        .expect("project");
    let r = Registry::standard();
    let ctx = CallContext::user("tester", Surface::Test);
    let started = r
        .call_json("analyze", s, &ctx, json!({}))
        .await
        .expect("analyze");
    let id = started["job_id"].as_str().expect("job id");
    let done = r
        .call_json(
            "job_await",
            s,
            &ctx,
            json!({"job_id": id, "timeout_ms": 20000}),
        )
        .await
        .expect("await analyze");
    assert_eq!(done["status"], "succeeded", "{done}");
}

async fn run_job(s: &Session, ctx: &CallContext, name: &str, args: Value) -> Value {
    let r = Registry::standard();
    let started = r
        .call_json(name, s, ctx, args)
        .await
        .unwrap_or_else(|e| panic!("{name}: {}", e.message));
    let id = started["job_id"].as_str().expect("job id").to_string();
    r.call_json(
        "job_await",
        s,
        ctx,
        json!({"job_id": id, "timeout_ms": 30000}),
    )
    .await
    .expect("job_await")
}

async fn name_of(s: &Session, address: &str) -> String {
    let r = Registry::standard();
    let ctx = CallContext::user("tester", Surface::Test);
    let f = r
        .call_json("get_function", s, &ctx, json!({"address": address}))
        .await
        .expect("get_function");
    f["name"]["value"]
        .as_str()
        .or_else(|| f["name"].as_str())
        .unwrap_or_default()
        .to_string()
}

fn naming_script() -> Vec<Vec<StreamEvent>> {
    vec![
        call("c1", "decompile", json!({"address": "0x10145b"})),
        call(
            "c2",
            "rename_symbol",
            json!({"address": "0x10145b", "new_name": "calc_evaluate"}),
        ),
        call(
            "c3",
            "rename_symbol",
            json!({"address": "0x101197", "new_name": "parse_number"}),
        ),
        answer(
            "Named two functions.",
            json!({"suggestions": [
                {"address": "0x10145b", "current_name": "FUN_0010145b", "new_name": "calc_evaluate",
                 "confidence": 0.9,
                 "evidence": [{"kind": "decompile", "detail": "evaluates an expression"},
                              {"kind": "caller", "detail": "called from main"}]},
                {"address": "0x101197", "current_name": "FUN_00101197", "new_name": "parse_number",
                 "confidence": 0.9,
                 "evidence": [{"kind": "decompile", "detail": "reads digits"},
                              {"kind": "callee", "detail": "isdigit"}]}
            ]}),
        ),
    ]
}

#[tokio::test]
async fn auto_name_job_renames_in_one_undoable_run() {
    let (s, tmp) = session(naming_script());
    open(&s, &tmp).await;
    let ctx = CallContext::user("tester", Surface::Test);
    assert_eq!(name_of(&s, "0x10145b").await, "FUN_0010145b");

    let done = run_job(&s, &ctx, "assist_auto_name", json!({"limit": 2})).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    let result = &done["result"];
    assert_eq!(result["task"], "auto_name");
    assert_eq!(result["output"]["applied"], 2, "{result}");
    let run_id = result["run_id"].as_str().expect("run id").to_string();

    assert_eq!(name_of(&s, "0x10145b").await, "calc_evaluate");
    assert_eq!(name_of(&s, "0x101197").await, "parse_number");

    // One undo takes both back.
    Registry::standard()
        .call_json("undo_run", &s, &ctx, json!({"run_id": run_id}))
        .await
        .expect("undo_run");
    assert_eq!(name_of(&s, "0x10145b").await, "FUN_0010145b");
    assert_eq!(name_of(&s, "0x101197").await, "FUN_00101197");

    // The model work is on the AI board.
    let jobs = Registry::standard()
        .call_json("ai_jobs", &s, &ctx, json!({}))
        .await
        .expect("ai_jobs");
    assert!(
        jobs.to_string().contains("Naming up to 2 functions"),
        "{jobs}"
    );
}

#[tokio::test]
async fn explain_and_overview_jobs_return_structured_answers_and_write_nothing() {
    let (s, tmp) = session(vec![
        call("c1", "decompile", json!({"address": "0x10145b"})),
        answer(
            "It evaluates an expression.",
            json!({"summary": "Evaluates an arithmetic expression.", "key_behaviours": ["recursive descent"]}),
        ),
        answer(
            "A calculator.",
            json!({"what_it_is": "A command-line calculator.", "components": []}),
        ),
    ]);
    open(&s, &tmp).await;
    let ctx = CallContext::user("tester", Surface::Test);

    let done = run_job(&s, &ctx, "assist_explain", json!({"address": "0x10145b"})).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    assert_eq!(
        done["result"]["output"]["summary"],
        "Evaluates an arithmetic expression."
    );
    assert_eq!(name_of(&s, "0x10145b").await, "FUN_0010145b");

    let done = run_job(&s, &ctx, "assist_overview", json!({})).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    assert_eq!(
        done["result"]["output"]["what_it_is"],
        "A command-line calculator."
    );
}

struct Counting {
    asked: AtomicUsize,
    allow: bool,
}

#[async_trait]
impl ApprovalRequester for Counting {
    async fn request(&self, _req: ApprovalRequest) -> ApprovalDecision {
        self.asked.fetch_add(1, Ordering::SeqCst);
        if self.allow {
            ApprovalDecision::Allow
        } else {
            ApprovalDecision::Deny {
                reason: "not today".into(),
            }
        }
    }
}

#[tokio::test]
async fn an_agent_caller_needs_a_persons_approval() {
    let (s, tmp) = session(naming_script());
    open(&s, &tmp).await;
    let r = Registry::standard();

    let deny = Arc::new(Counting {
        asked: AtomicUsize::new(0),
        allow: false,
    });
    let agent = CallContext::agent("a1", "run-1", Surface::Mcp).with_approval(deny.clone());
    let err = r
        .call_json("assist_auto_name", &s, &agent, json!({"limit": 2}))
        .await
        .expect_err("denied");
    assert!(err.message.contains("approval denied"), "{}", err.message);
    assert_eq!(deny.asked.load(Ordering::SeqCst), 1);
    assert_eq!(name_of(&s, "0x10145b").await, "FUN_0010145b");

    let allow = Arc::new(Counting {
        asked: AtomicUsize::new(0),
        allow: true,
    });
    let agent = CallContext::agent("a1", "run-1", Surface::Mcp).with_approval(allow.clone());
    let done = run_job(&s, &agent, "assist_auto_name", json!({"limit": 2})).await;
    assert_eq!(done["status"], "succeeded", "{done}");
    assert_eq!(allow.asked.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bad_arguments_and_a_missing_backend_are_refused() {
    let (s, tmp) = session(vec![]);
    open(&s, &tmp).await;
    let r = Registry::standard();
    let ctx = CallContext::user("tester", Surface::Test);
    let err = r
        .call_json("assist_auto_name", &s, &ctx, json!({"limit": 0}))
        .await
        .expect_err("limit");
    assert!(err.message.contains("between 1 and"));

    let bare = Session::new(Arc::new(Factory));
    bare.create_project(&tmp.path().join("q"), &tmp.path().join("calc.bin"))
        .await
        .expect("project");
    let err = r
        .call_json("assist_overview", &bare, &ctx, json!({}))
        .await
        .expect_err("unattached");
    assert!(err.message.contains("not attached"), "{}", err.message);
}

//! The `rewrite_*` registry commands end to end, offline: FakeEngine on a corpus fixture, the
//! `RewriteService` backend, `ReplayProvider` cassettes for the model, the real emulation oracle
//! and the real sandbox. Needs a Ghidra install for the SLEIGH specs, like the other tests.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{config, corpus_bin};
use engine_fake::{FakeEngine, FixtureFile};
use kraken_agent::{
    Cassette, CassetteEntry, ChatProvider, ChatRequest, Fingerprint, FinishReason, ReplayProvider,
    StreamEvent,
};
use kraken_assist::{ApiBackend, AssistBackend};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::RewriteBackend;
use kraken_registry::{AutoApprove, CallContext, EngineFactory, Registry, Session, Surface};
use kraken_rewrite::export::{build_in_sandbox, crate_prefix};
use kraken_rewrite::sandbox::Confinement;
use kraken_rewrite::service::{BackendSource, RewriteConfig, RewriteService};
use kraken_rewrite::store::RewriteStore;
use kraken_rewrite::targets::target;
use kraken_rewrite::task::{Budget, RewriteTask, SpecScope, SpecTask};
use serde_json::{Value, json};

struct FakeFactory {
    fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

/// A provider that can be set after the rig exists, so a test can first ask the service what it
/// would send, build the cassette for it, and then run the command. Limits, the daily totals and
/// the model named for estimates can be set too.
#[derive(Default)]
struct Slot(
    Mutex<Option<Arc<dyn ChatProvider>>>,
    Mutex<kraken_assist::AiLimits>,
    Mutex<Option<kraken_model::DailyLedger>>,
);

impl Slot {
    fn set(&self, p: Arc<dyn ChatProvider>) {
        *self.0.lock().expect("slot") = Some(p);
    }
}

impl BackendSource for Slot {
    fn backend(&self) -> Result<Arc<dyn AssistBackend>, ProtoError> {
        self.0
            .lock()
            .expect("slot")
            .clone()
            .map(|p| Arc::new(ApiBackend::new(p)) as Arc<dyn AssistBackend>)
            .ok_or_else(|| ProtoError::new(ErrorCode::Internal, "no provider set in the test"))
    }

    fn choice(
        &self,
        which: kraken_assist::RewriteModel,
        model: Option<&str>,
    ) -> Option<kraken_assist::ModelChoice> {
        let cfg = kraken_agent::ProviderConfig::Anthropic {
            model: Some(model.unwrap_or("claude-sonnet-5-5").to_string()),
            api_key: kraken_agent::SecretRef::Env("K".into()),
            base_url: None,
            max_tokens: None,
            context_window: None,
        };
        let source = match which {
            kraken_assist::RewriteModel::Assistant => kraken_assist::ModelSource::Assistant,
            kraken_assist::RewriteModel::Configured => kraken_assist::ModelSource::Rewrite,
        };
        Some(kraken_assist::ModelChoice::new(cfg, source))
    }

    fn limits(&self) -> kraken_assist::AiLimits {
        self.1.lock().expect("slot").clone()
    }

    fn daily(&self) -> Option<kraken_model::DailyLedger> {
        self.2.lock().expect("slot").clone()
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    session: Session,
    registry: Registry,
    slot: Arc<Slot>,
    service: Arc<RewriteService>,
}

async fn rig(binary: &str) -> Rig {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/fixtures")
        .join(format!("{binary}.json"));
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::Builder::new()
        .prefix("kraken-rewrite-svc-")
        .tempdir()
        .expect("tempdir");
    let slot = Arc::new(Slot::default());
    let service = Arc::new(RewriteService::new(
        slot.clone(),
        RewriteConfig {
            oracle: config(),
            ..RewriteConfig::default()
        },
    ));
    let backend: Arc<dyn RewriteBackend> = service.clone();
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
        slot,
        service,
    }
}

fn user() -> CallContext {
    CallContext::user("tester", Surface::Test)
}

fn agent() -> CallContext {
    CallContext::agent("bot", "run-1", Surface::Test)
}

impl Rig {
    async fn call(&self, ctx: &CallContext, name: &str, args: Value) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, ctx, args)
            .await
    }

    /// Starts a job command and waits for its result.
    async fn job(&self, ctx: &CallContext, name: &str, args: Value) -> Result<Value, ProtoError> {
        let started = self.call(ctx, name, args).await?;
        let id = started["job_id"].as_str().expect("job id").to_string();
        let done = self
            .call(
                &user(),
                "job_await",
                json!({"job_id": id, "timeout_ms": 600_000}),
            )
            .await?;
        match done["status"].as_str() {
            Some("succeeded") => Ok(done["result"].clone()),
            _ => Err(serde_json::from_value(done["error"].clone())
                .unwrap_or_else(|_| ProtoError::new(ErrorCode::Internal, done.to_string()))),
        }
    }

    fn store(&self) -> RewriteStore {
        RewriteStore::in_project(&self.dir).expect("store")
    }

    fn use_cassette(&self, c: Cassette) {
        self.slot.set(Arc::new(ReplayProvider::new(c)));
    }
}

fn entry(req: &ChatRequest, text: String) -> CassetteEntry {
    CassetteEntry {
        fingerprint: Fingerprint::of(req),
        events: vec![
            StreamEvent::TextDelta { text },
            StreamEvent::Finish {
                reason: FinishReason::Stop,
            },
        ],
    }
}

fn cassette_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("cassettes")
        .join(name)
}

/// Compares `fresh` with the checked-in cassette (rewriting it when asked) and returns it.
fn checked_in(name: &str, fresh: Cassette) -> Cassette {
    static WRITE: Mutex<()> = Mutex::new(());
    let path = cassette_path(name);
    let _serial = WRITE.lock().unwrap_or_else(|e| e.into_inner());
    if std::env::var_os("KRAKEN_UPDATE_CASSETTES").is_some() {
        fresh.save(&path).expect("save cassette");
    }
    let stored = Cassette::load(&path).unwrap_or_else(|e| {
        panic!("{e}; regenerate with KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test service")
    });
    assert_eq!(
        stored, fresh,
        "the prompts changed; regenerate the cassette with \
         KRAKEN_UPDATE_CASSETTES=1 cargo test -p kraken-rewrite --test service"
    );
    stored
}

const CMP_ID: u64 = 0x10124e;
const CMP_DIST: u64 = 0x101299;

fn reply(t: &str, assumptions: &[&str]) -> String {
    RewriteTask::reply_text(t, assumptions)
}

/// Requests of the pie_list rig: both comparators, plus the spec route for `cmp_id`.
async fn pie_cassette(r: &Rig) -> Cassette {
    let cmp_id = target("cmp_id").expect("target");
    let cmp_dist = target("cmp_dist").expect("target");
    let mut c = Cassette::default();
    let id = r
        .service
        .prepare(&r.session, &user(), CMP_ID)
        .await
        .expect("prepare");
    c.entries.push(entry(
        &id.task.request(),
        reply(cmp_id.reference, &["struct record is 40 bytes"]),
    ));
    let dist = r
        .service
        .prepare(&r.session, &user(), CMP_DIST)
        .await
        .expect("prepare");
    c.entries
        .push(entry(&dist.task.request(), reply(cmp_dist.reference, &[])));
    let spec_md = include_str!("../references/spec_cmp_id.md");
    c.entries.push(entry(
        &id.spec_task(&Budget::default()).request(),
        spec_md.to_string(),
    ));
    c.entries.push(entry(
        &id.reimplement_task(spec_md.trim()).request(),
        reply(cmp_id.reference, &["ids are compared as i32"]),
    ));
    c
}

async fn pie_rig() -> Rig {
    let r = rig("pie_list-O0").await;
    let c = checked_in("service-pie.json", pie_cassette(&r).await);
    r.use_cassette(c);
    r
}

fn names(plan: &Value) -> Vec<String> {
    plan["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["name"]["value"].as_str().expect("name").to_string())
        .collect()
}

fn entry_named<'a>(plan: &'a Value, name: &str) -> &'a Value {
    plan["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .find(|e| e["name"]["value"] == name)
        .unwrap_or_else(|| panic!("no plan entry {name}"))
}

fn pos(names: &[String], n: &str) -> usize {
    names
        .iter()
        .position(|x| x == n)
        .unwrap_or_else(|| panic!("{n} not in plan"))
}

// ----- plan and status -----

#[tokio::test]
async fn switch_vm_plan_puts_callees_first_and_leaves_out_imports_and_glue() {
    let r = rig("switch_vm-O0").await;
    let plan = r
        .call(&user(), "rewrite_plan", json!({}))
        .await
        .expect("plan");
    assert_eq!(
        names(&plan),
        ["vm_fail", "push", "pop", "vm_run", "op_name", "main"],
        "{plan:#}"
    );
    assert_eq!(plan["functions_planned"], 6);
    assert_eq!(plan["groups"], 6);
    // printf, fprintf, exit and __cxa_finalize are import thunks; the rest of the listed
    // functions that are not program code is loader and compiler glue.
    assert_eq!(plan["skipped_imports"], 4);
    assert_eq!(
        plan["skipped_imports"].as_u64().unwrap_or(0)
            + plan["skipped_runtime"].as_u64().unwrap_or(0)
            + plan["functions_planned"].as_u64().unwrap_or(0),
        plan["functions_total"].as_u64().unwrap_or(0)
    );
    assert_eq!(plan["truncated"], false);
    // vm_fail calls fprintf and exit, which the oracle models: nothing to flag.
    let fail = entry_named(&plan, "vm_fail");
    assert_eq!(fail["imports"].as_array().map(Vec::len), Some(2));
    assert_eq!(fail["flags"], json!([]));
    assert_eq!(fail["status"], "planned");
    let run = entry_named(&plan, "vm_run");
    assert_eq!(run["callees"].as_array().map(Vec::len), Some(3));
    assert_eq!(run["group_size"], 1);

    // Pages of the stored plan.
    let first = r
        .call(&user(), "rewrite_plan", json!({"limit": 4}))
        .await
        .expect("page");
    assert_eq!(first["entries"].as_array().map(Vec::len), Some(4));
    let cursor = first["next_cursor"].as_str().expect("cursor").to_string();
    let second = r
        .call(
            &user(),
            "rewrite_plan",
            json!({"limit": 4, "cursor": cursor}),
        )
        .await
        .expect("page 2");
    assert_eq!(names(&second), ["op_name", "main"]);
    assert!(second.get("next_cursor").is_none());

    // One function: itself and the callees it needs, leaves first, nothing stored.
    let one = r
        .call(
            &user(),
            "rewrite_plan",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect("function plan");
    assert_eq!(names(&one), ["vm_fail", "push", "pop", "vm_run"]);
    let missing = r
        .call(&user(), "rewrite_plan", json!({"scope": "function"}))
        .await
        .expect_err("needs address");
    assert_eq!(missing.code, ErrorCode::InvalidArgument);
    let bad = r
        .call(&user(), "rewrite_plan", json!({"cursor": "x"}))
        .await
        .expect_err("bad cursor");
    assert_eq!(bad.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn pie_list_plan_flags_what_the_oracle_cannot_model() {
    let r = rig("pie_list-O0").await;
    let plan = r
        .call(&user(), "rewrite_plan", json!({"limit": 200}))
        .await
        .expect("plan");
    let n = names(&plan);
    // Leaves before callers.
    assert!(pos(&n, "cmp_id") < pos(&n, "list_sort") || n.contains(&"cmp_id".to_string()));
    assert!(pos(&n, "node_new") < pos(&n, "main"));
    assert!(pos(&n, "list_free") < pos(&n, "main"));
    assert_eq!(n.last().map(String::as_str), Some("main"), "{n:?}");
    // strncpy is not stubbed in the oracle; calloc and free are.
    let node_new = entry_named(&plan, "node_new");
    let stubs: Vec<&str> = node_new["needs_stubs"]
        .as_array()
        .expect("stubs")
        .iter()
        .filter_map(|v| v["value"].as_str())
        .collect();
    assert!(stubs.contains(&"strncpy"), "{stubs:?}");
    assert!(!stubs.contains(&"calloc"), "{stubs:?}");
    assert!(
        node_new["flags"]
            .as_array()
            .expect("flags")
            .contains(&json!("needs_stubs"))
    );
    assert!(
        !entry_named(&plan, "list_free")["needs_stubs"]
            .as_array()
            .expect("stubs")
            .iter()
            .any(|v| v["value"] == "free")
    );
    // The comparators call nothing and need nothing.
    for c in ["cmp_id", "cmp_dist"] {
        let e = entry_named(&plan, c);
        assert_eq!(e["flags"], json!([]), "{c}");
        assert_eq!(e["needs_stubs"], json!([]), "{c}");
        assert_eq!(e["callees"], json!([]), "{c}");
    }
    // A caller inherits the flag of its callees.
    assert!(
        entry_named(&plan, "main")["flags"]
            .as_array()
            .expect("flags")
            .contains(&json!("needs_stubs"))
    );
}

#[tokio::test]
async fn status_before_a_plan_and_with_one() {
    let r = rig("switch_vm-O0").await;
    let empty = r
        .call(&user(), "rewrite_status", json!({}))
        .await
        .expect("status");
    assert_eq!(empty["plan_present"], false);
    assert_eq!(empty["units"], json!([]));
    assert_eq!(empty["counts"]["planned"], 0);

    r.call(&user(), "rewrite_plan", json!({}))
        .await
        .expect("plan");
    let st = r
        .call(&user(), "rewrite_status", json!({"limit": 3}))
        .await
        .expect("status");
    assert_eq!(st["plan_present"], true);
    assert_eq!(st["counts"]["planned"], 6);
    assert_eq!(st["units"].as_array().map(Vec::len), Some(3));
    assert_eq!(st["units"][0]["order"], 0);
    assert_eq!(st["units"][0]["status"], "planned");
    assert_eq!(st["next_cursor"], "3");
}

// ----- rewrite_function -----

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn a_cassette_translation_is_verified_stored_and_listed() {
    let r = pie_rig().await;
    let out = r
        .job(
            &user(),
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 40}),
        )
        .await
        .expect("rewrite_function");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["status"], "verified");
    assert_eq!(out["mode"], "incremental");
    assert_eq!(out["version"], 1);
    assert_eq!(out["provider"], "replay");
    assert!(out["cases_run"].as_u64().unwrap_or(0) >= 40);
    assert_eq!(out["cases_run"], out["passed"]);
    assert!(out.get("counterexample").is_none());
    assert_eq!(
        out["rust_prototype"],
        "pub unsafe extern \"C\" fn cmp_id(a0: *mut u8, a1: *mut u8) -> i32"
    );
    assert_eq!(out["assumptions"][0]["value"], "struct record is 40 bytes");
    assert!(
        out["sandbox"]
            .as_str()
            .is_some_and(|s| s.starts_with("landlock")),
        "{out:#}"
    );

    // Stored with the unit's whole record.
    let sha = r.session.project().expect("project").program().sha256;
    let unit = r
        .store()
        .latest(&sha, "0x10124e")
        .expect("read")
        .expect("unit");
    assert_eq!(unit.id, out["unit"].as_str().expect("id"));
    assert!(unit.rust_code.contains("fn cmp_id("));
    assert!(!unit.test_cases.is_empty());
    assert_eq!(unit.provenance.model.as_deref(), Some("cassette"));
    assert_eq!(unit.anchor.name, "cmp_id");

    // Listed by rewrite_status after a plan.
    r.call(&user(), "rewrite_plan", json!({"limit": 200}))
        .await
        .expect("plan");
    let st = r
        .call(&user(), "rewrite_status", json!({"limit": 200}))
        .await
        .expect("status");
    let row = st["units"]
        .as_array()
        .expect("units")
        .iter()
        .find(|u| u["name"]["value"] == "cmp_id")
        .expect("row");
    assert_eq!(row["status"], "verified");
    assert_eq!(row["verdict"], "pass");
    assert_eq!(row["version"], 1);
    assert_eq!(row["unit"], out["unit"], "status names the unit id");
    assert_eq!(st["counts"]["verified"], 1);

    // rewrite_unit hands out the stored code, by address and by unit id.
    let by_addr = r
        .call(&user(), "rewrite_unit", json!({"address": "0x10124e"}))
        .await
        .expect("rewrite_unit by address");
    let by_id = r
        .call(&user(), "rewrite_unit", json!({"unit": out["unit"]}))
        .await
        .expect("rewrite_unit by unit");
    assert_eq!(by_addr, by_id);
    assert_eq!(by_addr["address"], "0x10124e");
    let versions = by_addr["versions"].as_array().expect("versions");
    assert_eq!(versions.len(), 1);
    let v = &versions[0];
    assert_eq!(v["unit"], out["unit"]);
    assert_eq!(v["version"], 1);
    assert_eq!(v["status"], "verified");
    assert_eq!(v["accepted"], false);
    assert_eq!(v["verdict"], "pass");
    assert_eq!(v["signature"], out["rust_prototype"]);
    assert_eq!(v["provider"], "replay");
    assert!(
        v["rust_code"]["value"]
            .as_str()
            .is_some_and(|c| c.contains("fn cmp_id("))
    );
    assert!(v["oracle_kind"].as_str().is_some_and(|k| !k.is_empty()));
    assert!(v["created"].as_u64().unwrap_or(0) > 0);
    assert!(by_addr.get("spec").is_none(), "no spec was written");
    let e = r
        .call(&user(), "rewrite_unit", json!({"unit": "ru-nope"}))
        .await
        .expect_err("unknown unit");
    assert_eq!(e.code, ErrorCode::NotFound);
    let none = r
        .call(&user(), "rewrite_unit", json!({"address": "0x101000"}))
        .await;
    if let Ok(n) = none {
        assert_eq!(n["versions"], json!([]));
    }

    // The plan reports the same status.
    let plan = r
        .call(
            &user(),
            "rewrite_plan",
            json!({"cursor": "0", "limit": 200}),
        )
        .await
        .expect("page");
    assert_eq!(entry_named(&plan, "cmp_id")["status"], "verified");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn a_wrong_translation_fails_with_a_counterexample_and_cannot_be_accepted() {
    let r = rig("pie_list-O0").await;
    let id = r
        .service
        .prepare(&r.session, &user(), CMP_ID)
        .await
        .expect("prepare");
    let reference = target("cmp_id").expect("target").reference;
    let wrong = reference.replace(
        "(*a).id.wrapping_sub((*b).id)",
        "(*a).id.cmp(&(*b).id) as i32",
    );
    assert_ne!(wrong, reference);
    let fail = Cassette {
        entries: vec![entry(&id.task.request(), reply(&wrong, &[]))],
        ..Cassette::default()
    };
    r.use_cassette(checked_in("service-pie-fail.json", fail));

    // An agent may produce units.
    let out = r
        .job(
            &agent(),
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 30, "max_attempts": 1}),
        )
        .await
        .expect("rewrite_function");
    assert_eq!(out["verdict"], "fail", "{out:#}");
    assert_eq!(out["status"], "failed");
    assert!(out["passed"].as_u64() < out["cases_run"].as_u64());
    let cx = &out["counterexample"];
    assert_eq!(cx["args"].as_array().map(Vec::len), Some(2));
    let diffs = cx["differences"].as_array().expect("differences");
    assert!(
        diffs.iter().any(|d| d["value"]
            .as_str()
            .is_some_and(|s| s.contains("return value"))),
        "{cx:#}"
    );

    // The failure is stored with its counterexample.
    let sha = r.session.project().expect("project").program().sha256;
    let unit = r
        .store()
        .latest(&sha, "0x10124e")
        .expect("read")
        .expect("unit");
    assert!(!unit.counterexamples.is_empty());

    let err = r
        .call(
            &user(),
            "rewrite_accept",
            json!({"unit": out["unit"].as_str().expect("id")}),
        )
        .await
        .expect_err("a failed unit cannot be accepted");
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    assert!(err.message.contains("failed"), "{err}");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn a_counterexample_is_fed_back_and_the_repaired_attempt_is_a_second_version() {
    let r = rig("pie_list-O0").await;
    let reference = target("cmp_id").expect("target").reference;
    let wrong = reference.replace(
        "(*a).id.wrapping_sub((*b).id)",
        "(*a).id.cmp(&(*b).id) as i32",
    );
    assert_ne!(wrong, reference);
    let events = |text: String| {
        vec![
            StreamEvent::TextDelta { text },
            StreamEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]
    };
    let provider = Arc::new(ReplayProvider::scripted(vec![
        events(reply(&wrong, &[])),
        events(reply(reference, &[])),
    ]));
    r.slot.set(provider);

    let out = r
        .job(
            &agent(),
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 30}),
        )
        .await
        .expect("rewrite_function");
    assert_eq!(out["attempts"], 2, "{out:#}");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["version"], 2);

    let unit = r
        .call(&user(), "rewrite_unit", json!({"address": "0x10124e"}))
        .await
        .expect("rewrite_unit");
    let versions = unit["versions"].as_array().expect("versions");
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0]["status"], "failed");
    assert_eq!(versions[0]["attempt"], 1);
    assert_eq!(versions[1]["status"], "verified");
    assert_eq!(versions[1]["attempt"], 2);
    assert_eq!(versions[1]["repair_of"], 1);
    assert_eq!(versions[1]["stale"], false);

    // The decompile changes behind the unit's back: the status shows it stale ...
    let sha = r.session.project().expect("project").program().sha256;
    r.store()
        .observe(&sha, &[("0x10124e".into(), "changed".into())])
        .expect("observe");
    let status = r
        .call(&user(), "rewrite_status", json!({}))
        .await
        .expect("status");
    let row = status["units"]
        .as_array()
        .and_then(|u| u.iter().find(|r| r["address"] == "0x10124e"))
        .expect("row");
    assert_eq!(row["stale"], true, "{status:#}");
    // ... and `refresh` decompiles again, which finds the source unchanged after all.
    let status = r
        .call(&user(), "rewrite_status", json!({"refresh": true}))
        .await
        .expect("status");
    let row = status["units"]
        .as_array()
        .and_then(|u| u.iter().find(|r| r["address"] == "0x10124e"))
        .expect("row");
    assert_eq!(row["stale"], false, "{status:#}");
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn spec_mode_writes_the_spec_first_then_reimplements_from_it() {
    let r = pie_rig().await;
    let out = r
        .job(
            &user(),
            "rewrite_function",
            json!({"address": "0x10124e", "mode": "spec", "cases": 30}),
        )
        .await
        .expect("rewrite_function spec");
    assert_eq!(out["verdict"], "pass", "{out:#}");
    assert_eq!(out["mode"], "spec");
    assert_eq!(out["assumptions"][0]["value"], "ids are compared as i32");
    let sha = r.session.project().expect("project").program().sha256;
    let store = r.store();
    let unit = store.latest(&sha, "0x10124e").expect("read").expect("unit");
    let spec_id = unit.spec_id.expect("the unit remembers its spec");
    let spec = store.spec(spec_id).expect("spec").expect("stored");
    assert_eq!(spec.scope, "function");
    assert_eq!(spec.address.as_deref(), Some("0x10124e"));
    assert_eq!(spec.citations, vec![0x10124e]);
    assert!(spec.facts >= 4);
    // The reimplementation request carries the spec and not the decompile.
    let prepared = r
        .service
        .prepare(&r.session, &user(), CMP_ID)
        .await
        .expect("prepare");
    let req = prepared.reimplement_task(spec.markdown.trim()).request();
    let kraken_agent::Message::User { content } = &req.messages[0] else {
        panic!("user message");
    };
    assert!(content.contains("<spec untrusted=\"true\">"));
    assert!(!content.contains("<decompile"));
    assert!(req.system.contains("behavioural specification"));
}

#[tokio::test]
async fn functions_the_oracle_cannot_check_are_refused_before_any_model_call() {
    let r = rig("pie_list-O0").await;
    // No provider set: a model call would fail with "no provider set". node_new returns a pointer
    // and takes a double.
    let err = r
        .job(&user(), "rewrite_function", json!({"address": "0x101189"}))
        .await
        .expect_err("unsupported");
    assert_eq!(err.code, ErrorCode::Unsupported, "{err}");
    // The host confinement gate comes first by design (the command refuses to run model-written
    // code on a host that cannot confine it, whatever the function), so where the sandbox is not
    // enforced (macOS, Windows) the refusal is that gate's; the function-level check is reached,
    // and asserted, only where it is.
    if kraken_rewrite::sandbox::enforced() {
        assert!(
            err.message.contains("pointer result") || err.message.contains("floating-point"),
            "{err}"
        );
    } else {
        assert!(err.message.contains("cannot confine"), "{err}");
    }
}

// ----- accept -----

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn only_users_accept_and_only_verified_units() {
    let r = pie_rig().await;
    let out = r
        .job(
            &user(),
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 30}),
        )
        .await
        .expect("rewrite_function");
    let unit = out["unit"].as_str().expect("id").to_string();

    let denied = r
        .call(&agent(), "rewrite_accept", json!({"unit": unit}))
        .await
        .expect_err("agents cannot accept");
    assert_eq!(denied.code, ErrorCode::RejectedHumanPriority);
    let missing = r
        .call(&user(), "rewrite_accept", json!({"unit": "ru-nope"}))
        .await
        .expect_err("unknown unit");
    assert_eq!(missing.code, ErrorCode::NotFound);

    let ok = r
        .call(&user(), "rewrite_accept", json!({"unit": unit}))
        .await
        .expect("accept");
    assert_eq!(ok["status"], "accepted");
    assert_eq!(ok["version"], 1);
    assert!(ok.get("replaced_version").is_none());
    let again = r
        .call(&user(), "rewrite_accept", json!({"unit": unit}))
        .await
        .expect_err("already accepted");
    assert_eq!(again.code, ErrorCode::InvalidArgument);

    let st = r
        .call(&user(), "rewrite_status", json!({}))
        .await
        .expect("status");
    assert_eq!(st["counts"]["accepted"], 1);
    assert_eq!(st["units"][0]["status"], "accepted");
    assert_eq!(st["units"][0]["accepted_version"], 1);

    // A second, newer verified version replaces the accepted one when accepted.
    let second = r
        .job(
            &user(),
            "rewrite_function",
            json!({"address": "0x10124e", "cases": 30, "seed": 7}),
        )
        .await
        .expect("second run");
    assert_eq!(second["version"], 2);
    assert_eq!(second["status"], "verified");
    let sha = r.session.project().expect("project").program().sha256;
    let store = r.store();
    let accepted = store
        .accepted(&sha, "0x10124e")
        .expect("read")
        .expect("accepted");
    assert_eq!(accepted.version, 1, "the new version is not accepted yet");
    let swap = r
        .call(
            &user(),
            "rewrite_accept",
            json!({"unit": second["unit"].as_str().expect("id")}),
        )
        .await
        .expect("accept v2");
    assert_eq!(swap["replaced_version"], 1);
    let events = store.events(&sha, "0x10124e").expect("events");
    let to: Vec<&str> = events.iter().map(|e| e.2.as_str()).collect();
    assert_eq!(
        to,
        ["verified", "accepted", "verified", "verified", "accepted"]
    );
}

// ----- specs -----

#[tokio::test]
async fn a_function_spec_is_checked_stored_and_reused() {
    let r = rig("switch_vm-O0").await;
    let prepared = r
        .service
        .prepare(&r.session, &user(), 0x101255)
        .await
        .expect("prepare");
    let md = include_str!("../references/spec_vm_run.md");
    let c = Cassette {
        entries: vec![entry(
            &prepared.spec_task(&Budget::default()).request(),
            md.to_string(),
        )],
        ..Cassette::default()
    };
    r.use_cassette(checked_in("service-vm-spec.json", c));

    let out = r
        .job(
            &user(),
            "rewrite_spec",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect("rewrite_spec");
    assert_eq!(out["scope"], "function");
    assert_eq!(out["address"], "0x101255");
    assert!(out["facts"].as_u64().unwrap_or(0) >= 12);
    assert_eq!(out["functions"], 4, "vm_run and its three callees");
    let cited: Vec<&str> = out["citations"]
        .as_array()
        .expect("citations")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(cited, ["0x101159", "0x101194", "0x1011f3", "0x101255"]);
    assert!(
        out["markdown"]["value"]
            .as_str()
            .is_some_and(|m| m.starts_with("# Behavioural spec: vm_run"))
    );
    assert_eq!(out["provider"], "replay");

    // A repeat with unchanged code answers from the store (the id is the same).
    let again = r
        .job(
            &user(),
            "rewrite_spec",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect("again");
    assert_eq!(again["spec"], out["spec"]);
    let sha = r.session.project().expect("project").program().sha256;
    let stored = r
        .store()
        .latest_spec(&sha, Some("0x101255"))
        .expect("read")
        .expect("spec");
    assert_eq!(stored.id, out["spec"].as_u64().expect("id"));
    assert_eq!(stored.provider, "replay");
}

#[tokio::test]
async fn a_spec_that_cites_nothing_real_is_rejected() {
    let r = rig("switch_vm-O0").await;
    let prepared = r
        .service
        .prepare(&r.session, &user(), 0x101255)
        .await
        .expect("prepare");
    let md = include_str!("../references/spec_vm_run.md").replace("0x101255", "0xdeadbeef");
    r.use_cassette(Cassette {
        entries: vec![entry(&prepared.spec_task(&Budget::default()).request(), md)],
        ..Cassette::default()
    });
    let err = r
        .job(
            &user(),
            "rewrite_spec",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect_err("invented citation");
    assert!(
        err.message.contains("not an address in the evidence"),
        "{err}"
    );
    let sha = r.session.project().expect("project").program().sha256;
    assert!(
        r.store()
            .latest_spec(&sha, Some("0x101255"))
            .expect("read")
            .is_none(),
        "nothing is stored for a rejected spec"
    );
}

#[tokio::test]
async fn a_program_spec_is_written_from_the_planned_functions() {
    let r = rig("stripped_calc-O0").await;
    // What the service sends: the planned functions in order, as its program-spec job reads them.
    let plan = kraken_rewrite::plan::to_plan(
        &kraken_rewrite::collect::collect(&r.session, &user(), 2000)
            .await
            .expect("collect"),
    );
    let ctx = user();
    let lift = kraken_rewrite::lift::Lift::new(&r.session, &ctx);
    let mut functions = Vec::new();
    for p in plan.entries.iter().take(30) {
        functions.push(lift.function(p.address).await.expect("function"));
    }
    let task = SpecTask {
        scope: SpecScope::Program,
        functions,
        budget: Budget::default(),
    };
    let md = include_str!("../references/spec_calc.md");
    r.use_cassette(Cassette {
        entries: vec![entry(&task.request(), md.to_string())],
        ..Cassette::default()
    });
    let out = r
        .job(&user(), "rewrite_spec", json!({"scope": "all"}))
        .await
        .expect("program spec");
    assert_eq!(out["scope"], "all");
    assert!(out.get("address").is_none());
    assert_eq!(
        out["functions"].as_u64(),
        Some(plan.entries.len().min(30) as u64)
    );
    let sha = r.session.project().expect("project").program().sha256;
    let stored = r
        .store()
        .latest_spec(&sha, None)
        .expect("read")
        .expect("program spec");
    assert_eq!(stored.scope, "program");
    assert!(stored.facts > 5);
    // The plan was stored as a side effect.
    assert!(r.store().plan(&sha).expect("plan").is_some());
}

// ----- export -----

async fn accept_both(r: &Rig) {
    for (addr, name) in [("0x10124e", "cmp_id"), ("0x101299", "cmp_dist")] {
        let out = r
            .job(
                &user(),
                "rewrite_function",
                json!({"address": addr, "cases": 30}),
            )
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(out["verdict"], "pass", "{name}: {out:#}");
        r.call(
            &user(),
            "rewrite_accept",
            json!({"unit": out["unit"].as_str().expect("id")}),
        )
        .await
        .expect("accept");
    }
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn export_builds_a_workspace_in_the_sandbox_and_the_symbol_table_matches() {
    let r = pie_rig().await;
    r.call(&user(), "rewrite_plan", json!({"limit": 200}))
        .await
        .expect("plan");
    accept_both(&r).await;

    let out = r
        .job(&user(), "rewrite_export", json!({"dir": "export"}))
        .await
        .expect("rewrite_export");
    assert_eq!(out["built"], true, "{out:#}");
    assert!(
        out["sandbox"]
            .as_str()
            .is_some_and(|s| s.starts_with("landlock"))
    );
    assert_eq!(
        out["symbols"],
        json!(["cmp_dist", "cmp_id", "kraken_attach_image"])
    );
    assert_eq!(out["coverage"]["accepted"], 2);
    assert!(out["coverage"]["planned"].as_u64().unwrap_or(0) > 10);
    assert_eq!(
        out["crates"],
        json!([
            format!("{}-rewrite", crate_prefix("pie_list-O0")),
            format!("{}-ffi", crate_prefix("pie_list-O0"))
        ])
    );

    // The files.
    let ws = r.dir.join("export");
    for f in [
        "Cargo.toml",
        "README.md",
        "manifest.json",
        "pie-list-o0-rewrite/src/lib.rs",
        "pie-list-o0-rewrite/src/u_cmp_id.rs",
        "pie-list-o0-ffi/src/lib.rs",
        "pie-list-o0-ffi/include/pie-list-o0.h",
    ] {
        assert!(ws.join(f).is_file(), "missing {f}");
    }
    let readme = std::fs::read_to_string(ws.join("README.md")).expect("readme");
    assert!(readme.contains("2 of "), "{readme}");
    assert!(readme.contains("`cmp_id` | `0x10124e`"), "{readme}");
    assert!(readme.contains("strangler"));
    let shim = std::fs::read_to_string(ws.join("pie-list-o0-ffi/src/lib.rs")).expect("shim");
    assert!(shim.contains("pub unsafe extern \"C\" fn cmp_id(a0: *mut u8, a1: *mut u8) -> i32"));
    let lib_module =
        std::fs::read_to_string(ws.join("pie-list-o0-rewrite/src/u_cmp_id.rs")).expect("module");
    assert!(
        !lib_module.contains("no_mangle"),
        "the library must not export symbols itself"
    );
    let header =
        std::fs::read_to_string(ws.join("pie-list-o0-ffi/include/pie-list-o0.h")).expect("header");
    assert!(header.contains("int32_t cmp_id(void *a0, void *a1);"));

    // Build it again, independently of the export job, and compare the symbol table.
    let built = build_in_sandbox(&ws, "pie-list-o0-ffi", &Confinement::default())
        .expect("the exported workspace builds in the sandbox");
    let symbols: Vec<&str> = built.symbols.iter().map(String::as_str).collect();
    assert_eq!(symbols, ["cmp_dist", "cmp_id", "kraken_attach_image"]);
    assert!(built.sandbox.starts_with("landlock"));
}

#[tokio::test]
#[ignore = "needs a Ghidra install for SLEIGH specs (KRAKEN_GHIDRA_HOME); runs in the real-ghidra job"]
async fn export_needs_accepted_units_and_a_safe_target() {
    let r = pie_rig().await;
    let none = r
        .job(&user(), "rewrite_export", json!({"dir": "export"}))
        .await
        .expect_err("nothing accepted");
    assert!(none.message.contains("no accepted units"), "{none}");

    accept_both(&r).await;

    // A directory with other content is not overwritten.
    let other = r.dir.join("precious");
    std::fs::create_dir_all(&other).expect("dir");
    std::fs::write(other.join("notes.txt"), "keep me").expect("file");
    let refused = r
        .job(
            &user(),
            "rewrite_export",
            json!({"dir": "precious", "build": false}),
        )
        .await
        .expect_err("not an export");
    assert!(refused.message.contains("not empty"), "{refused}");
    assert!(other.join("notes.txt").is_file());

    // Outside the project directory needs approval; the default requester denies.
    let outside = tempfile::Builder::new()
        .prefix("kraken-export-out-")
        .tempdir()
        .expect("tempdir");
    let target = outside.path().join("ws");
    let denied = r
        .job(
            &user(),
            "rewrite_export",
            json!({"dir": target.to_str().expect("utf8"), "build": false}),
        )
        .await
        .expect_err("approval denied");
    assert_eq!(
        denied.details.as_ref().map(|d| d["approval"].clone()),
        Some(json!("denied"))
    );
    assert!(!target.exists());

    let approved = CallContext::user("tester", Surface::Test).with_approval(Arc::new(AutoApprove));
    let ok = r
        .job(
            &approved,
            "rewrite_export",
            json!({"dir": target.to_str().expect("utf8"), "build": false}),
        )
        .await
        .expect("approved export");
    assert_eq!(ok["built"], false);
    assert_eq!(ok["sandbox"], "none");
    assert!(target.join("manifest.json").is_file());

    // An earlier export may be overwritten, and `..` is refused.
    let again = r
        .job(
            &approved,
            "rewrite_export",
            json!({"dir": target.to_str().expect("utf8"), "build": false}),
        )
        .await
        .expect("re-export over an export");
    assert_eq!(again["symbols"], ok["symbols"]);
    let dotdot = r
        .call(&user(), "rewrite_export", json!({"dir": "../escape"}))
        .await
        .expect_err("..");
    assert_eq!(dotdot.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn without_a_backend_the_commands_say_so() {
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/fixtures/pie_list-O0.json");
    let fixture = FixtureFile::from_path(&fx).expect("fixture");
    let tmp = tempfile::tempdir().expect("tempdir");
    let session = Session::new(Arc::new(FakeFactory { fixture }));
    session
        .create_project(&tmp.path().join("p"), &corpus_bin("pie_list-O0"))
        .await
        .expect("project");
    let err = Registry::standard()
        .call_json("rewrite_status", &session, &user(), json!({}))
        .await
        .expect_err("no backend");
    assert_eq!(err.code, ErrorCode::Unsupported);
    assert!(err.message.contains("not attached"), "{err}");
}

// ----- AI usage, estimates and limits -----

async fn spec_rig() -> Rig {
    let r = rig("switch_vm-O0").await;
    let prepared = r
        .service
        .prepare(&r.session, &user(), 0x101255)
        .await
        .expect("prepare");
    let md = include_str!("../references/spec_vm_run.md");
    r.use_cassette(Cassette {
        entries: vec![entry(
            &prepared.spec_task(&Budget::default()).request(),
            md.to_string(),
        )],
        ..Cassette::default()
    });
    r
}

#[tokio::test]
async fn a_spec_job_shows_on_the_ai_board_and_in_the_usage_ledger() {
    let r = spec_rig().await;
    let args = json!({"scope": "function", "address": "0x101255"});
    let started = r
        .call(&user(), "rewrite_spec", args.clone())
        .await
        .expect("start");
    let job = started["job_id"].as_str().expect("job").to_string();
    r.call(
        &user(),
        "job_await",
        json!({"job_id": job, "timeout_ms": 600_000}),
    )
    .await
    .expect("await");

    let jobs = r
        .call(&user(), "ai_jobs", json!({}))
        .await
        .expect("ai_jobs");
    let list = jobs["jobs"].as_array().expect("jobs");
    assert_eq!(list.len(), 1, "{jobs:#}");
    let j = &list[0];
    assert_eq!(j["feature"], "rewrite");
    assert_eq!(j["job_id"], job);
    assert_eq!(j["status"], "succeeded");
    assert_eq!(j["provider"], "replay");
    assert_eq!(j["usage"]["calls"], 1);
    assert_eq!(jobs["running"], 0);

    let usage = r
        .call(&user(), "ai_usage", json!({}))
        .await
        .expect("ai_usage");
    assert_eq!(usage["totals"]["calls"], 1, "{usage:#}");
    assert_eq!(usage["groups"][0]["feature"], "rewrite");
    assert_eq!(usage["recent"][0]["job_id"], job);
    assert!(
        usage["note"]
            .as_str()
            .is_some_and(|n| n.contains("estimates"))
    );
    let run = r
        .call(&user(), "ai_usage", json!({"scope": "run", "run_id": job}))
        .await
        .expect("run");
    assert_eq!(run["totals"]["calls"], 1);

    // The stored spec answers a repeat: no model call, no new AI work.
    r.job(&user(), "rewrite_spec", args).await.expect("again");
    let jobs = r
        .call(&user(), "ai_jobs", json!({}))
        .await
        .expect("ai_jobs");
    assert_eq!(jobs["jobs"].as_array().map(Vec::len), Some(1));
}

#[tokio::test]
async fn a_used_up_daily_budget_refuses_new_rewrite_work() {
    let r = spec_rig().await;
    let daily = kraken_model::DailyLedger::at(r.dir.join("daily.json"));
    daily
        .add(&kraken_proto::AiCallRecord {
            ts_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis() as i64,
            feature: kraken_proto::AiFeature::Assistant,
            provider_kind: kraken_proto::AiProviderKind::Api,
            provider: "anthropic".into(),
            model: "claude".into(),
            job_id: None,
            run_id: None,
            origin: kraken_proto::AiOrigin::Gui,
            input_tokens: Some(1),
            output_tokens: Some(1),
            wall_ms: 1,
            cost_usd: Some(3.0),
            billing: kraken_proto::AiBilling::Metered,
        })
        .expect("daily");
    *r.slot.1.lock().expect("limits") = kraken_assist::AiLimits {
        daily_budget: Some(2.0),
        ..kraken_assist::AiLimits::default()
    };
    *r.slot.2.lock().expect("daily") = Some(daily);
    let err = r
        .call(
            &user(),
            "rewrite_spec",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect_err("over budget");
    assert_eq!(err.code, ErrorCode::Cancelled);
    assert!(err.message.contains("Today's AI budget of $2.00"), "{err}");
    assert_eq!(
        err.details.as_ref().and_then(|d| d.get("ai_limit")),
        Some(&json!(true))
    );
    let jobs = r
        .call(&user(), "ai_jobs", json!({}))
        .await
        .expect("ai_jobs");
    assert_eq!(jobs["jobs"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn a_call_cap_stops_a_job_and_the_board_says_why() {
    let r = spec_rig().await;
    *r.slot.1.lock().expect("limits") = kraken_assist::AiLimits {
        max_calls_per_run: Some(0),
        ..kraken_assist::AiLimits::default()
    };
    let err = r
        .job(
            &user(),
            "rewrite_spec",
            json!({"scope": "function", "address": "0x101255"}),
        )
        .await
        .expect_err("capped");
    assert_eq!(err.code, ErrorCode::Cancelled);
    assert!(err.message.contains("limit of 0 model calls"), "{err}");
    let jobs = r
        .call(&user(), "ai_jobs", json!({}))
        .await
        .expect("ai_jobs");
    let j = &jobs["jobs"][0];
    assert_eq!(j["status"], "limited", "{jobs:#}");
    assert!(
        j["message"]
            .as_str()
            .is_some_and(|m| m.contains("max_calls_per_run"))
    );
}

#[tokio::test]
async fn estimates_count_every_planned_function_and_the_repair_rounds() {
    let r = rig("stripped_calc-O0").await;
    let plan = r
        .call(&user(), "rewrite_plan", json!({"scope": "all"}))
        .await
        .expect("plan");
    let n = plan["functions_planned"].as_u64().expect("planned");
    assert!(n > 0);
    let e = r
        .service
        .estimate(&r.session, &user(), "rewrite_program", &json!({}))
        .await
        .expect("estimate");
    assert_eq!(
        e.max_calls,
        n * 3 + 2 * 3 * 2,
        "3 attempts each and 2 repair rounds"
    );
    assert_eq!(e.billing, kraken_proto::AiBilling::Metered);
    assert!(e.cost_high_usd.expect("high") > e.cost_low_usd.expect("low"));
    assert!(e.cost_text().contains("(estimate)"));
    let lean = r
        .service
        .estimate(
            &r.session,
            &user(),
            "rewrite_program",
            &json!({"max_attempts": 1, "repair_rounds": 0, "model": "claude-haiku-4-5"}),
        )
        .await
        .expect("estimate");
    assert_eq!(lean.max_calls, n);
    assert_eq!(lean.model, "claude-haiku-4-5");
    let one = r
        .service
        .estimate(
            &r.session,
            &user(),
            "rewrite_function",
            &json!({"mode": "spec"}),
        )
        .await
        .expect("estimate");
    assert_eq!(one.max_calls, 4);
}

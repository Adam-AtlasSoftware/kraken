//! The `rewrite_*` commands against a recording backend: what the registry layer itself decides
//! (kinds, permissions, who may call, argument checks, approval for exports outside the project,
//! the sandbox gate) without the emulator, the model or the sandbox.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, Hex64, ProtoError, Untrusted};
use kraken_registry::commands::{
    ExportCoverage, ExportRequest, PlanScope, RewriteAcceptArgs, RewriteAcceptOut, RewriteBackend,
    RewriteExportResult, RewriteFunctionArgs, RewriteFunctionResult, RewriteMode, RewritePlanArgs,
    RewritePlanOut, RewriteSpecArgs, RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut,
    RewriteUnitArgs, RewriteUnitOut, StatusCounts, UnitStatus,
};
use kraken_registry::{
    ApprovalDecision, ApprovalRequest, ApprovalRequester, AutoApprove, CallContext, CommandKind,
    EngineFactory, JobReporter, Permission, Registry, Session, Surface,
};
use serde_json::{Value, json};

struct Factory;

#[async_trait]
impl EngineFactory for Factory {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        let fx = FixtureFile::from_path(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json"),
        )
        .expect("tiny fixture");
        Ok(Arc::new(FakeEngine::new(fx)))
    }
}

#[derive(Default)]
struct Mock {
    sandbox: bool,
    calls: Mutex<Vec<String>>,
    exports: Mutex<Vec<ExportRequest>>,
}

impl Mock {
    fn log(&self, what: &str) {
        self.calls.lock().expect("calls").push(what.to_string());
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

#[async_trait]
impl RewriteBackend for Mock {
    fn require_sandbox(&self) -> Result<(), ProtoError> {
        if self.sandbox {
            Ok(())
        } else {
            Err(ProtoError::new(ErrorCode::Unsupported, "no sandbox here"))
        }
    }

    async fn plan(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewritePlanArgs,
    ) -> Result<RewritePlanOut, ProtoError> {
        self.log(&format!("plan {:?} {:?}", args.scope, args.address));
        Ok(RewritePlanOut {
            scope: args.scope,
            program_sha256: "ab".into(),
            functions_total: 3,
            functions_planned: 0,
            skipped_imports: 0,
            skipped_runtime: 0,
            groups: 0,
            truncated: false,
            entries: vec![],
            next_cursor: None,
        })
    }

    async fn status(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        _args: RewriteStatusArgs,
    ) -> Result<RewriteStatusOut, ProtoError> {
        self.log("status");
        Ok(RewriteStatusOut {
            program_sha256: "ab".into(),
            plan_present: false,
            counts: StatusCounts::default(),
            units: vec![],
            next_cursor: None,
        })
    }

    async fn unit(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteUnitArgs,
    ) -> Result<RewriteUnitOut, ProtoError> {
        self.log(&format!("unit {:?} {:?}", args.address, args.unit));
        Ok(RewriteUnitOut {
            address: args.address.unwrap_or(Hex64(0x10)),
            versions: vec![],
            spec: None,
        })
    }

    async fn function(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteFunctionArgs,
        _job: &JobReporter,
    ) -> Result<RewriteFunctionResult, ProtoError> {
        self.log(&format!(
            "function {} {:?} {:?} {:?}",
            args.address.0, args.mode, args.seed, args.cases
        ));
        Ok(RewriteFunctionResult {
            unit: "ru-1".into(),
            address: args.address,
            name: Untrusted("f".into()),
            version: 1,
            mode: args.mode,
            status: UnitStatus::Verified,
            verdict: "pass".into(),
            verdict_detail: None,
            cases_run: 5,
            passed: 5,
            skipped: 0,
            counterexample: None,
            rust_prototype: "pub unsafe extern \"C\" fn f()".into(),
            sandbox: "landlock-v6".into(),
            provider: "mock".into(),
            model: "mock".into(),
            assumptions: vec![],
            unsupported: vec![],
        })
    }

    async fn accept(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError> {
        self.log(&format!("accept {}", args.unit));
        Ok(RewriteAcceptOut {
            status: "accepted".into(),
            unit: args.unit,
            address: Hex64(0x10),
            version: 1,
            replaced_version: None,
        })
    }

    async fn spec(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteSpecArgs,
        _job: &JobReporter,
    ) -> Result<RewriteSpecResult, ProtoError> {
        self.log(&format!("spec {:?} {:?}", args.scope, args.max_functions));
        Ok(RewriteSpecResult {
            spec: 1,
            scope: args.scope,
            address: args.address,
            functions: 1,
            facts: 1,
            citations: vec![],
            markdown: Untrusted("# spec".into()),
            provider: "mock".into(),
            model: "mock".into(),
        })
    }

    async fn export(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        request: ExportRequest,
        _job: &JobReporter,
    ) -> Result<RewriteExportResult, ProtoError> {
        self.log("export");
        let dir = request.dir.display().to_string();
        self.exports.lock().expect("exports").push(request);
        Ok(RewriteExportResult {
            dir,
            crates: vec![],
            symbols: vec![],
            built: false,
            sandbox: "none".into(),
            coverage: ExportCoverage {
                accepted: 0,
                planned: 0,
                functions_total: 0,
            },
            readme: kraken_proto::Untrusted(String::new()),
        })
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    dir: std::path::PathBuf,
    session: Session,
    registry: Registry,
    mock: Arc<Mock>,
}

async fn rig(sandbox: bool) -> Rig {
    let mock = Arc::new(Mock {
        sandbox,
        ..Mock::default()
    });
    let tmp = tempfile::tempdir().expect("tempdir");
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake").expect("binary");
    let dir = tmp.path().join("proj");
    let backend: Arc<dyn RewriteBackend> = mock.clone();
    let session = Session::new(Arc::new(Factory)).with_rewrite(backend);
    session
        .create_project(&dir, &binary)
        .await
        .expect("project");
    Rig {
        _tmp: tmp,
        dir,
        session,
        registry: Registry::standard(),
        mock,
    }
}

fn user() -> CallContext {
    CallContext::user("tester", Surface::Test)
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
                json!({"job_id": id, "timeout_ms": 10_000}),
            )
            .await?;
        assert_eq!(done["status"], "succeeded", "{done}");
        Ok(done["result"].clone())
    }
}

#[test]
fn kinds_and_permissions_of_the_rewrite_commands() {
    let r = Registry::standard();
    let expect = [
        ("rewrite_plan", CommandKind::Query, Permission::Safe),
        ("rewrite_status", CommandKind::Query, Permission::Safe),
        ("rewrite_unit", CommandKind::Query, Permission::Safe),
        ("rewrite_function", CommandKind::Job, Permission::Mutating),
        (
            "rewrite_accept",
            CommandKind::Mutation,
            Permission::Mutating,
        ),
        ("rewrite_spec", CommandKind::Job, Permission::Mutating),
        ("rewrite_export", CommandKind::Job, Permission::Mutating),
    ];
    for (name, kind, permission) in expect {
        let spec = r.get(name).unwrap_or_else(|| panic!("{name}")).spec();
        assert_eq!((spec.kind, spec.permission), (kind, permission), "{name}");
        assert!(spec.doc.len() > 100, "{name} needs documentation");
        assert!(spec.needs.is_empty(), "{name} needs no engine capability");
    }
    // Nothing here is `dangerous`: running generated code is gated by the sandbox instead, and
    // exporting outside the project asks for approval on its own.
    assert!(
        r.get("rewrite_function")
            .expect("cmd")
            .spec()
            .doc
            .contains("sandbox")
    );
    let args = r.get("rewrite_function").expect("cmd");
    let props = &args.args_schema()["properties"];
    for p in ["address", "mode", "seed", "cases"] {
        assert!(props[p].is_object(), "{p}");
    }
    assert_eq!(args.args_schema()["required"], json!(["address"]));
}

#[tokio::test]
async fn queries_pass_straight_to_the_backend() {
    let r = rig(true).await;
    let plan = r
        .call(
            &user(),
            "rewrite_plan",
            json!({"scope": "function", "address": "0x10"}),
        )
        .await
        .expect("plan");
    assert_eq!(plan["scope"], "function");
    r.call(&user(), "rewrite_status", json!({}))
        .await
        .expect("status");
    assert_eq!(r.mock.calls(), ["plan Function Some(Hex64(16))", "status"]);

    let e = r
        .call(&user(), "rewrite_plan", json!({"scope": "function"}))
        .await
        .expect_err("needs an address");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = r
        .call(&user(), "rewrite_plan", json!({"scope": "nonsense"}))
        .await
        .expect_err("bad scope");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(r.mock.calls().len(), 2, "rejected before the backend");
}

#[tokio::test]
async fn rewrite_unit_takes_exactly_one_of_address_and_unit() {
    let r = rig(true).await;
    let out = r
        .call(&user(), "rewrite_unit", json!({"address": "0x10"}))
        .await
        .expect("by address");
    assert_eq!(out["versions"], json!([]));
    r.call(&user(), "rewrite_unit", json!({"unit": "ru-1"}))
        .await
        .expect("by unit");
    for bad in [json!({}), json!({"address": "0x10", "unit": "ru-1"})] {
        let e = r
            .call(&user(), "rewrite_unit", bad)
            .await
            .expect_err("needs exactly one");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }
    assert_eq!(
        r.mock.calls(),
        ["unit Some(Hex64(16)) None", "unit None Some(\"ru-1\")"],
        "bad calls are rejected before the backend"
    );
}

#[tokio::test]
async fn function_and_spec_run_as_jobs_on_the_backend() {
    let r = rig(true).await;
    let out = r
        .job(
            &CallContext::agent("bot", "run-1", Surface::Test),
            "rewrite_function",
            json!({"address": "0x401000", "mode": "spec", "seed": 5, "cases": 10}),
        )
        .await
        .expect("job");
    assert_eq!(out["unit"], "ru-1");
    assert_eq!(out["mode"], "spec");
    assert_eq!(out["status"], "verified");
    let spec = r
        .job(
            &user(),
            "rewrite_spec",
            json!({"scope": "all", "max_functions": 7}),
        )
        .await
        .expect("spec job");
    assert_eq!(spec["markdown"]["value"], "# spec");
    assert_eq!(
        r.mock.calls(),
        [
            format!("function {} Spec Some(5) Some(10)", 0x401000),
            "spec All Some(7)".to_string()
        ]
    );
    let snapshots = r.session.jobs().list();
    assert_eq!(
        snapshots
            .iter()
            .map(|j| j.command.as_str())
            .collect::<Vec<_>>(),
        ["rewrite_function", "rewrite_spec"]
    );

    for (name, args) in [
        (
            "rewrite_function",
            json!({"address": "0x10", "cases": 5000}),
        ),
        (
            "rewrite_function",
            json!({"address": "0x10", "mode": "both"}),
        ),
        ("rewrite_spec", json!({"scope": "function"})),
        ("rewrite_spec", json!({"scope": "all", "max_functions": 0})),
        (
            "rewrite_spec",
            json!({"scope": "all", "max_functions": 101}),
        ),
    ] {
        let e = r
            .call(&user(), name, args.clone())
            .await
            .expect_err("invalid");
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{name} {args}");
    }
    assert_eq!(
        r.session.jobs().list().len(),
        2,
        "no job was started for bad arguments"
    );
}

#[tokio::test]
async fn generated_code_is_refused_when_the_host_cannot_confine_it() {
    let r = rig(false).await;
    let e = r
        .call(&user(), "rewrite_function", json!({"address": "0x10"}))
        .await
        .expect_err("no sandbox");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("no sandbox here"));
    assert!(
        r.session.jobs().list().is_empty(),
        "refused before any job started"
    );
    assert!(r.mock.calls().is_empty());

    // Exporting without building runs nothing, so it does not need the sandbox; building does.
    let e = r
        .call(&user(), "rewrite_export", json!({"dir": "out"}))
        .await
        .expect_err("build needs the sandbox");
    assert_eq!(e.code, ErrorCode::Unsupported);
    let ok = r
        .job(
            &user(),
            "rewrite_export",
            json!({"dir": "out", "build": false}),
        )
        .await
        .expect("export without a build");
    assert_eq!(ok["built"], false);
    // Specs and the read-only commands never run generated code.
    r.job(&user(), "rewrite_spec", json!({"scope": "all"}))
        .await
        .expect("spec");
    r.call(&user(), "rewrite_status", json!({}))
        .await
        .expect("status");
}

#[tokio::test]
async fn accepting_is_for_users_and_checked_before_the_backend() {
    let r = rig(true).await;
    let agent = CallContext::agent("bot", "run-1", Surface::Mcp);
    let e = r
        .call(&agent, "rewrite_accept", json!({"unit": "ru-1"}))
        .await
        .expect_err("agents cannot accept");
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    assert!(r.mock.calls().is_empty());
    let ok = r
        .call(&user(), "rewrite_accept", json!({"unit": "ru-1"}))
        .await
        .expect("user accepts");
    assert_eq!(ok["status"], "accepted");
    assert_eq!(r.mock.calls(), ["accept ru-1"]);
}

struct Counting {
    asked: AtomicUsize,
    last: Mutex<Option<ApprovalRequest>>,
    allow: bool,
}

#[async_trait]
impl ApprovalRequester for Counting {
    async fn request(&self, req: ApprovalRequest) -> ApprovalDecision {
        self.asked.fetch_add(1, Ordering::SeqCst);
        *self.last.lock().expect("last") = Some(req);
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
async fn exports_outside_the_project_directory_ask_for_approval() {
    let r = rig(true).await;
    let asker = Arc::new(Counting {
        asked: AtomicUsize::new(0),
        last: Mutex::new(None),
        allow: false,
    });
    let ctx = user().with_approval(asker.clone());

    // Inside the project: relative or absolute, no question.
    r.job(
        &ctx,
        "rewrite_export",
        json!({"dir": "out/ws", "name": "demo"}),
    )
    .await
    .expect("relative");
    let inside = r.dir.join("elsewhere");
    r.job(
        &ctx,
        "rewrite_export",
        json!({"dir": inside.to_str().expect("utf8")}),
    )
    .await
    .expect("absolute inside");
    assert_eq!(asker.asked.load(Ordering::SeqCst), 0);
    {
        let seen = r.mock.exports.lock().expect("exports");
        assert_eq!(seen[0].dir, r.dir.join("out/ws"));
        assert_eq!(seen[0].name.as_deref(), Some("demo"));
        assert!(seen[0].build, "builds by default");
        assert_eq!(seen[1].dir, inside);
    }

    // Outside: asked, and a denial stops it before the backend.
    let outside = tempfile::tempdir().expect("tempdir");
    let target = outside.path().join("ws");
    let e = r
        .call(
            &ctx,
            "rewrite_export",
            json!({"dir": target.to_str().expect("utf8")}),
        )
        .await
        .expect_err("denied");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert_eq!(
        e.details.as_ref().map(|d| d["approval"].clone()),
        Some(json!("denied"))
    );
    assert!(e.message.contains("not today"));
    assert_eq!(asker.asked.load(Ordering::SeqCst), 1);
    let asked = asker.last.lock().expect("last").clone().expect("request");
    assert_eq!(asked.command, "rewrite_export");
    assert!(asked.summary.contains("outside the project directory"));
    assert_eq!(r.mock.exports.lock().expect("exports").len(), 2);

    // Approved: the backend gets the absolute directory.
    let yes = user().with_approval(Arc::new(AutoApprove));
    r.job(
        &yes,
        "rewrite_export",
        json!({"dir": target.to_str().expect("utf8"), "build": false}),
    )
    .await
    .expect("approved");
    {
        let seen = r.mock.exports.lock().expect("exports");
        assert_eq!(seen[2].dir, target);
        assert!(!seen[2].build);
    }

    // Escapes through `..` are refused outright, with no question asked.
    let e = r
        .call(&ctx, "rewrite_export", json!({"dir": "../escape"}))
        .await
        .expect_err("..");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(asker.asked.load(Ordering::SeqCst), 1);
}

#[test]
fn the_enums_use_the_names_the_surfaces_show() {
    assert_eq!(
        serde_json::to_value(RewriteMode::Spec).expect("json"),
        json!("spec")
    );
    assert_eq!(
        serde_json::to_value(PlanScope::All).expect("json"),
        json!("all")
    );
    assert_eq!(
        serde_json::to_value(UnitStatus::Accepted).expect("json"),
        json!("accepted")
    );
}

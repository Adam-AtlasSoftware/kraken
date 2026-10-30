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
    ExportCoverage, ExportRequest, PlanScope, ProgramVerdictView, RewriteAcceptArgs,
    RewriteAcceptOut, RewriteBackend, RewriteBuildArgs, RewriteBuildResult, RewriteExportResult,
    RewriteFunctionArgs, RewriteFunctionResult, RewriteMode, RewritePlanArgs, RewritePlanOut,
    RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatusArgs, RewriteProgramStatusOut,
    RewriteSpecArgs, RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut, RewriteUnitArgs,
    RewriteUnitOut, StatusCounts, UnitStatus,
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
    programs: Mutex<Vec<RewriteProgramArgs>>,
    builds: Mutex<Vec<RewriteBuildArgs>>,
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
            attempts: 1,
            reused_callees: vec![],
            hints_used: false,
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

    async fn program(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteProgramArgs,
        _job: &JobReporter,
    ) -> Result<RewriteProgramResult, ProtoError> {
        self.log("program");
        self.programs.lock().expect("programs").push(args);
        Ok(program_result())
    }

    async fn build(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteBuildArgs,
        _job: &JobReporter,
    ) -> Result<RewriteBuildResult, ProtoError> {
        self.log("build");
        let dir = args.dir.clone();
        self.builds.lock().expect("builds").push(args);
        Ok(RewriteBuildResult {
            dir,
            kind: "export".into(),
            passed: true,
            steps: vec![],
            sandbox: "mock".into(),
        })
    }

    async fn program_status(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteProgramStatusArgs,
    ) -> Result<RewriteProgramStatusOut, ProtoError> {
        self.log(&format!("program_status {:?} {}", args.run, args.all_cases));
        Ok(RewriteProgramStatusOut {
            program_sha256: "ab".into(),
            present: true,
            runs: vec![],
            run: Some(program_result()),
        })
    }
}

fn program_result() -> RewriteProgramResult {
    RewriteProgramResult {
        run: 1,
        program_sha256: "ab".into(),
        entry: Hex64(0x10),
        entry_name: Untrusted("main".into()),
        functions_planned: 1,
        skipped: 0,
        translated: 1,
        reused_from_store: 0,
        cache_hits: 0,
        parallel: 1,
        failed: 0,
        verified: 1,
        unchecked: 0,
        included: 1,
        functions: vec![],
        crate_dir: "/tmp/crate".into(),
        built: true,
        crate_sha256: "cd".into(),
        provider: "mock".into(),
        model: "mock".into(),
        created: 0,
        verdict: ProgramVerdictView {
            verdict: "pass".into(),
            detail: None,
            cases_run: 3,
            passed: 3,
            failed: 0,
            cases: vec![],
            sandbox: "landlock-v6".into(),
        },
        repairs: vec![],
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
        ("rewrite_program", CommandKind::Job, Permission::Mutating),
        (
            "rewrite_program_status",
            CommandKind::Query,
            Permission::Safe,
        ),
        ("rewrite_build", CommandKind::Job, Permission::Mutating),
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

#[tokio::test]
async fn program_runs_as_a_job_with_the_directory_resolved_and_arguments_checked() {
    let r = rig(true).await;
    let agent = CallContext::agent("bot", "run-1", Surface::Test);
    // An agent acts for a person, who approves running the original program.
    let approved = agent.clone().with_approval(Arc::new(AutoApprove));
    let denied = r
        .call(&agent, "rewrite_program", json!({"scope": "all"}))
        .await
        .expect_err("running the original needs approval");
    assert_eq!(denied.code, ErrorCode::Unsupported);
    assert_eq!(
        denied.details.as_ref().map(|d| d["approval"].clone()),
        Some(json!("denied"))
    );
    assert!(r.mock.calls().is_empty(), "denied before the backend");
    let out = r
        .job(
            &approved,
            "rewrite_program",
            json!({"scope": "all", "cases": 10}),
        )
        .await
        .expect("job");
    assert_eq!(out["verdict"]["verdict"], "pass");
    assert_eq!(out["entry_name"]["value"], "main");
    r.job(
        &user(),
        "rewrite_program",
        json!({
            "dir": "out/prog", "accept_verified": true, "verify_functions": false,
            "generated_cases": 3,
            "inputs": [{"name": "a", "argv": ["x"], "stdin": "y"}]
        }),
    )
    .await
    .expect("job with options");
    {
        let seen = r.mock.programs.lock().expect("programs");
        // The backend always gets an absolute directory inside (or approved outside) the project.
        assert_eq!(
            seen[0].dir.as_deref(),
            r.dir.join("rewrite-program").to_str()
        );
        assert_eq!(seen[1].dir.as_deref(), r.dir.join("out/prog").to_str());
        assert_eq!(seen[1].accept_verified, Some(true));
        assert_eq!(seen[1].inputs.len(), 1);
        assert_eq!(seen[1].inputs[0].stdin.as_deref(), Some("y"));
    }

    for (args, why) in [
        (json!({"scope": "function"}), "scope"),
        (json!({"mode": "spec"}), "spec mode"),
        (json!({"cases": 5000}), "cases"),
        (json!({"max_attempts": 0}), "attempts"),
        (json!({"generated_cases": 201}), "generated"),
        (json!({"dir": "../escape"}), "dir"),
        (json!({"inputs": [{"name": " ", "argv": []}]}), "unnamed"),
        (json!({"inputs": [{"name": "n", "argv": ["a\0b"]}]}), "NUL"),
        (json!({"unknown": 1}), "unknown field"),
    ] {
        let e = r
            .call(&user(), "rewrite_program", args)
            .await
            .expect_err(why);
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{why}");
    }
    let too_many: Vec<Value> = (0..65)
        .map(|i| json!({"name": format!("c{i}"), "argv": []}))
        .collect();
    let e = r
        .call(&user(), "rewrite_program", json!({"inputs": too_many}))
        .await
        .expect_err("too many cases");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(
        r.mock.calls(),
        ["program", "program"],
        "rejected before the backend"
    );

    // Accepting is a person's decision, also here.
    let e = r
        .call(&agent, "rewrite_program", json!({"accept_verified": true}))
        .await
        .expect_err("agents cannot accept");
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    r.job(
        &approved,
        "rewrite_program",
        json!({"accept_verified": false}),
    )
    .await
    .expect("an agent may say no");
    // Without a build nothing is executed, so nothing is asked.
    r.job(&agent, "rewrite_program", json!({"build": false}))
        .await
        .expect("no build, no approval needed");

    // The status query is safe for everyone.
    let st = r
        .call(
            &agent,
            "rewrite_program_status",
            json!({"run": 1, "all_cases": true}),
        )
        .await
        .expect("status");
    assert_eq!(st["run"]["crate_dir"], "/tmp/crate");
    assert_eq!(
        r.mock.calls().last().map(String::as_str),
        Some("program_status Some(1) true")
    );
}

#[tokio::test]
async fn program_needs_the_sandbox_and_asks_before_writing_outside_the_project() {
    let r = rig(false).await;
    let e = r
        .call(&user(), "rewrite_program", json!({}))
        .await
        .expect_err("no sandbox");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("no sandbox here"));
    // The status query reads only.
    r.call(&user(), "rewrite_program_status", json!({}))
        .await
        .expect("status needs no sandbox");

    let r = rig(true).await;
    let asker = Arc::new(Counting {
        asked: AtomicUsize::new(0),
        last: Mutex::new(None),
        allow: false,
    });
    let ctx = user().with_approval(asker.clone());
    let outside = tempfile::tempdir().expect("tempdir");
    let target = outside.path().join("crate");
    let e = r
        .call(
            &ctx,
            "rewrite_program",
            json!({"dir": target.to_str().expect("utf8")}),
        )
        .await
        .expect_err("denied");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("not today"));
    let asked = asker.last.lock().expect("last").clone().expect("request");
    assert_eq!(asked.command, "rewrite_program");
    assert!(asked.summary.contains("outside the project directory"));
    assert!(r.mock.programs.lock().expect("programs").is_empty());
    let yes = user().with_approval(Arc::new(AutoApprove));
    r.job(
        &yes,
        "rewrite_program",
        json!({"dir": target.to_str().expect("utf8"), "build": false}),
    )
    .await
    .expect("approved");
    let seen = r.mock.programs.lock().expect("programs");
    assert_eq!(seen[0].dir.as_deref(), target.to_str());
    assert_eq!(seen[0].build, Some(false));
}

// ---- rewrite_build ----------------------------------------------------------------------------

fn write_marker(dir: &Path, file: &str, generator: &str) {
    std::fs::create_dir_all(dir).expect("mkdir");
    std::fs::write(dir.join(file), format!("{{\"generator\":\"{generator}\"}}")).expect("marker");
}

#[tokio::test]
async fn build_refuses_a_folder_kraken_did_not_export_before_the_backend_sees_it() {
    let r = rig(true).await;
    let plain = r.dir.join("notes");
    std::fs::create_dir_all(&plain).expect("mkdir");
    std::fs::write(plain.join("Cargo.toml"), "[package]").expect("file");
    for dir in ["notes", "missing", "/"] {
        let e = r
            .call(&user(), "rewrite_build", json!({ "dir": dir }))
            .await
            .expect_err("not an export");
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{dir}: {e:?}");
    }
    let e = r
        .call(&user(), "rewrite_build", json!({"dir": "../up"}))
        .await
        .expect_err("..");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    // A manifest from someone else is not the marker.
    write_marker(&r.dir.join("foreign"), "manifest.json", "cargo");
    let e = r
        .call(&user(), "rewrite_build", json!({"dir": "foreign"}))
        .await
        .expect_err("foreign manifest");
    assert!(
        e.message.contains("not a crate KRAKEN exported"),
        "{}",
        e.message
    );
    assert!(r.mock.calls().is_empty(), "nothing reached the backend");
}

#[tokio::test]
async fn build_needs_the_sandbox_and_checks_its_arguments() {
    let r = rig(false).await;
    write_marker(&r.dir.join("exp"), "manifest.json", "kraken-rewrite");
    let e = r
        .call(&user(), "rewrite_build", json!({"dir": "exp"}))
        .await
        .expect_err("no sandbox");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("no sandbox here"));

    let r = rig(true).await;
    write_marker(&r.dir.join("exp"), "manifest.json", "kraken-rewrite");
    write_marker(
        &r.dir.join("prog"),
        "kraken-program.json",
        "kraken-rewrite/program",
    );
    // An export is a library: nothing to run.
    let e = r
        .call(
            &user(),
            "rewrite_build",
            json!({"dir": "exp", "run_args": ["x"]}),
        )
        .await
        .expect_err("library");
    assert!(e.message.contains("program crate"), "{}", e.message);
    let many: Vec<String> = (0..40).map(|i| i.to_string()).collect();
    let e = r
        .call(
            &user(),
            "rewrite_build",
            json!({"dir": "prog", "run_args": many}),
        )
        .await
        .expect_err("too many");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = r
        .call(
            &user(),
            "rewrite_build",
            json!({"dir": "prog", "run_args": ["a\u{0}b"]}),
        )
        .await
        .expect_err("nul");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert!(r.mock.calls().is_empty());
}

#[tokio::test]
async fn build_runs_as_a_job_with_the_resolved_directory_and_asks_agents_first() {
    let r = rig(true).await;
    write_marker(&r.dir.join("exp"), "manifest.json", "kraken-rewrite");
    write_marker(
        &r.dir.join("prog"),
        "kraken-program.json",
        "kraken-rewrite/program",
    );
    // A person typing the command is the approval.
    let out = r
        .job(&user(), "rewrite_build", json!({"dir": "exp"}))
        .await
        .expect("job");
    assert_eq!(out["passed"], true);
    assert_eq!(out["sandbox"], "mock");
    {
        let seen = r.mock.builds.lock().expect("builds");
        assert_eq!(seen[0].dir, r.dir.join("exp").to_str().expect("utf8"));
        assert_eq!(seen[0].test, None);
    }
    // An agent acts for a person, who must approve running generated code.
    let agent = CallContext::agent("bot", "run-1", Surface::Test);
    let e = r
        .call(&agent, "rewrite_build", json!({"dir": "prog"}))
        .await
        .expect_err("needs approval");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert_eq!(
        e.details.as_ref().map(|d| d["approval"].clone()),
        Some(json!("denied"))
    );
    assert_eq!(r.mock.builds.lock().expect("builds").len(), 1);
    let approved = agent.with_approval(Arc::new(AutoApprove));
    r.job(
        &approved,
        "rewrite_build",
        json!({"dir": "prog", "test": false, "run_args": ["-v", "x y"]}),
    )
    .await
    .expect("approved");
    let seen = r.mock.builds.lock().expect("builds");
    assert_eq!(seen[1].test, Some(false));
    assert_eq!(
        seen[1].run_args.as_deref(),
        Some(&["-v".to_string(), "x y".to_string()][..])
    );
}

#[test]
fn the_unit_controls_have_the_right_kinds() {
    let r = Registry::standard();
    for (name, kind, permission) in [
        (
            "rewrite_reject",
            CommandKind::Mutation,
            Permission::Mutating,
        ),
        (
            "rewrite_unaccept",
            CommandKind::Mutation,
            Permission::Mutating,
        ),
        ("rewrite_add_case", CommandKind::Job, Permission::Mutating),
        ("rewrite_verify", CommandKind::Job, Permission::Mutating),
        ("rewrite_harvest", CommandKind::Job, Permission::Mutating),
        (
            "rewrite_spec_edit",
            CommandKind::Mutation,
            Permission::Mutating,
        ),
        ("rewrite_check", CommandKind::Query, Permission::Safe),
        ("rewrite_cache", CommandKind::Mutation, Permission::Mutating),
        ("rewrite_hint_get", CommandKind::Query, Permission::Safe),
        (
            "rewrite_hint_set",
            CommandKind::Mutation,
            Permission::Mutating,
        ),
        (
            "rewrite_preload_build",
            CommandKind::Job,
            Permission::Mutating,
        ),
    ] {
        let spec = r.get(name).unwrap_or_else(|| panic!("{name}")).spec();
        assert_eq!((spec.kind, spec.permission), (kind, permission), "{name}");
        assert!(spec.doc.contains("Example:"), "{name} needs an example");
        assert!(!spec.details.is_empty(), "{name} needs details");
    }
}

#[tokio::test]
async fn deciding_about_a_unit_is_for_users_and_adding_evidence_is_open_to_agents() {
    let r = rig(true).await;
    let agent = CallContext::agent("bot", "run-1", Surface::Mcp);
    for (cmd, args) in [
        ("rewrite_reject", json!({"unit": "ru-1"})),
        ("rewrite_unaccept", json!({"unit": "ru-1"})),
    ] {
        let e = r
            .call(&agent, cmd, args)
            .await
            .expect_err("agents cannot decide about a unit");
        assert_eq!(e.code, ErrorCode::RejectedHumanPriority, "{cmd}");
    }
    assert!(r.mock.calls().is_empty(), "refused before the backend");

    // Evidence commands pass the gate; this backend implements none of them, so the answer is
    // the backend's, not a refusal.
    let e = r
        .call(
            &agent,
            "rewrite_spec_edit",
            json!({"address": "0x10", "markdown": "x"}),
        )
        .await
        .expect_err("the mock has no spec editing");
    assert_eq!(e.code, ErrorCode::Unsupported);
    let e = r
        .call(&agent, "rewrite_cache", json!({}))
        .await
        .expect_err("the mock has no cache");
    assert_eq!(e.code, ErrorCode::Unsupported);
    let e = r
        .call(&agent, "rewrite_check", json!({}))
        .await
        .expect_err("the mock has no check");
    assert_eq!(e.code, ErrorCode::Unsupported);
    for (cmd, args) in [
        ("rewrite_verify", json!({"unit": "ru-1"})),
        ("rewrite_add_case", json!({"unit": "ru-1", "args": [1]})),
        ("rewrite_harvest", json!({"address": "0x401040"})),
    ] {
        let started = r
            .call(&agent, cmd, args)
            .await
            .expect("an agent may start the job");
        assert!(started["job_id"].is_string(), "{cmd}");
    }
    let e = r
        .call(
            &agent,
            "rewrite_add_case",
            json!({"unit": "ru-1", "args": vec![0; 17]}),
        )
        .await
        .expect_err("too many arguments");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn hints_are_checked_before_the_backend_and_agents_may_set_them() {
    let r = rig(true).await;
    let agent = CallContext::agent("bot", "run-1", Surface::Test);
    let e = r
        .call(
            &agent,
            "rewrite_hint_set",
            json!({"address": "0x10", "hints": {"uses": ["libc::system"]}}),
        )
        .await
        .expect_err("not a std path");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = r
        .call(
            &agent,
            "rewrite_hint_set",
            json!({"address": "0x10", "hints": {"notes": "ok"}}),
        )
        .await
        .expect_err("the mock stores no hints");
    assert_eq!(e.code, ErrorCode::Unsupported);
    let e = r
        .call(&agent, "rewrite_preload_build", json!({"dir": "nowhere"}))
        .await
        .expect_err("not an export");
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn the_unit_jobs_need_the_sandbox() {
    let r = rig(false).await;
    for (cmd, args) in [
        ("rewrite_verify", json!({"unit": "ru-1"})),
        ("rewrite_add_case", json!({"unit": "ru-1", "args": [1]})),
    ] {
        let e = r
            .call(&user(), cmd, args)
            .await
            .expect_err("no sandbox here");
        assert_eq!(e.code, ErrorCode::Unsupported, "{cmd}");
    }
}

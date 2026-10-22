//! Engine and supervisor tests against an in-process fake sidecar (no JVM involved).

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Decompiler, Engine, FunctionLister, Loader,
    LoaderSpec, Mutator, Stage,
};
use kraken_proto::{
    Anchor, ErrorCode, Hex64, Locator, LogOp, PageRequest, Primitive, PrimitiveClass, TypeDef,
    TypeRef, TypedefDef, VersionedLogOp,
};
use serde_json::{Value, json};

use crate::config::{Deadlines, EngineConfig};
use crate::engine::GhidraEngine;
use crate::install::GhidraInstall;
use crate::rpc::SIDECAR_EXITED;
use crate::supervisor::SidecarEvent;
use crate::testutil::{FakeLauncher, FakeSide, Handler, Reply};

/// `tempfile::tempdir` makes `.tmpXXXX`, whose leading dot the engine rejects in project paths.
fn scratch_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-unit-")
        .tempdir()
        .unwrap()
}

#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(String, Value)>>,
    analyze_id: Mutex<Option<Value>>,
    hold_analyze: AtomicBool,
    protocol_minor: Mutex<Option<u32>>,
    opened_stages: Mutex<Vec<&'static str>>,
}

impl Fake {
    fn called(&self, method: &str) -> usize {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(m, _)| m == method)
            .count()
    }

    fn last_params(&self, method: &str) -> Value {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(m, _)| m == method)
            .map(|(_, p)| p.clone())
            .unwrap_or(Value::Null)
    }
}

fn func(offset: &str, name: &str) -> Value {
    json!({
        "locator": {"kind": "native", "space": "ram", "offset": offset},
        "name": name, "size": 16, "fn_hash": "h",
        "completeness": {"kind": "complete"},
    })
}

fn handler(fake: Arc<Fake>) -> Handler {
    Arc::new(move |method, params, id, side: &FakeSide| {
        fake.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((method.to_string(), params.clone()));
        match method {
            "handshake" => {
                let minor = fake
                    .protocol_minor
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .unwrap_or(1);
                let caps: Vec<Value> = crate::supervisor::REQUIRED_SIDECAR_CAPABILITIES
                    .iter()
                    .map(|n| json!({"name": n, "version": 1}))
                    .collect();
                Reply::Result(json!({
                    "protocol": {"major": 0, "minor": minor},
                    "build": "fake-sidecar",
                    "capabilities": caps,
                }))
            }
            "open_binary" => Reply::Result(json!({
                "stages_done": *fake.opened_stages.lock().unwrap_or_else(PoisonError::into_inner),
                "language": "x86:LE:64:default",
                "format": "Executable and Linking Format (ELF)",
                "image_base": "0x100000",
                "sha256": "abc",
            })),
            "get_function" => match params["locator"]["offset"].as_str() {
                Some("0x1000") => Reply::Result(func("0x1000", "main")),
                Some("0x1004") => Reply::Result(func("0x1000", "main")),
                _ => Reply::Error("not_found", "no function"),
            },
            "list_functions" => Reply::Result(json!({
                "items": [func("0x1000", "main")], "total": 1,
            })),
            "get_types" => Reply::Result(json!({
                "items": [
                    {"kind": "typedef", "name": "other_t",
                     "target": {"kind": "named", "name": "int"}},
                    {"kind": "typedef", "name": "my_t",
                     "target": {"kind": "named", "name": "int"}},
                ],
                "total": 2,
            })),
            "define_type" => Reply::Result(params["def"].clone()),
            "apply_op" => Reply::Result(json!({"ok": true})),
            "save" => Reply::Result(json!({"checkpoint": "save-1"})),
            "shutdown" => Reply::Result(json!({"ok": true})),
            "analyze" => {
                if fake.hold_analyze.load(Ordering::SeqCst) {
                    *fake
                        .analyze_id
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner) = Some(id.clone());
                    return Reply::Manual;
                }
                let job = params["job_id"].clone();
                for (stage, done) in [("core", 0), ("core", 1), ("expensive", 1), ("expensive", 2)]
                {
                    side.notify(
                        "progress",
                        json!({"job_id": job, "stage": stage, "done": done, "total": 2, "message": "m"}),
                    );
                }
                side.notify(
                    "progress",
                    json!({"job_id": "someone-else", "stage": "core", "done": 0, "total": 1}),
                );
                Reply::Delayed(
                    Duration::from_millis(20),
                    json!({"job_id": job, "stages_completed": ["core", "expensive"], "function_count": 7}),
                )
            }
            "cancel" => {
                let held = fake
                    .analyze_id
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                match held {
                    Some(analyze_id) => {
                        side.fail(&analyze_id, "cancelled", "analysis cancelled");
                        Reply::Result(json!({"cancelled": true}))
                    }
                    None => Reply::Error("not_found", "no running job"),
                }
            }
            "decompile" => Reply::Result(json!({
                "function": {"kind": "native", "space": "ram", "offset": "0x1000"},
                "text": "int main(void)",
                "tokens": [{"start": 4, "end": 8, "kind": "function"}], "warnings": [],
                "completeness": {"kind": "complete"},
            })),
            "memory_map" => Reply::Result(json!([{
                "name": ".text", "space": "ram", "start": "0x1000", "end": "0x2000",
                "perms": "r-x", "initialized": true, "kind": "default",
            }])),
            "read_bytes" => Reply::Result(json!({
                "start": params["locator"]["offset"], "bytes": "AAEC",
                "uninitialized": [{"space": "ram", "start": "0x1002", "end": "0x1003"}],
            })),
            "assemble" => Reply::Result(json!({"encodings": ["b807000000", "c7c007000000"]})),
            "disassemble" => Reply::Result(json!({
                "items": [{"address": "0x1000", "bytes": "90", "mnemonic": "nop",
                           "operands": [], "flow": "fallthrough"}],
                "next_cursor": "0x1001",
            })),
            "xrefs" => Reply::Result(json!({
                "items": [{"from": "0x1000", "to": params["address"], "kind": "call"}],
                "total": 1,
            })),
            "cfg" => Reply::Result(json!({
                "function": "0x1000",
                "blocks": [{"start": "0x1000", "end": "0x1010", "instructions": 4}],
                "edges": [],
            })),
            "strings" => Reply::Result(json!({
                "items": [{"address": "0x2000", "value": "hi", "encoding": "ascii", "length": 3}],
            })),
            "imports" | "exports" => Reply::Result(json!({
                "items": [{"name": "puts", "address": "0x1030", "kind": "function"}],
            })),
            "slow" => Reply::Never,
            "die" => Reply::Hangup,
            _ => Reply::Error("unsupported", "method not found"),
        }
    })
}

struct Rig {
    engine: Arc<GhidraEngine>,
    fake: Arc<Fake>,
    launcher: Arc<FakeLauncher>,
    binary: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

fn rig_with(tweak: impl FnOnce(&mut EngineConfig)) -> Rig {
    let dir = scratch_dir();
    let binary = dir.path().join("prog");
    std::fs::write(&binary, vec![0u8; 2048]).unwrap();
    let p = dir.path().to_path_buf();
    let mut cfg = EngineConfig::new(
        GhidraInstall {
            ghidra_home: p.clone(),
            java_home: p.clone(),
            ext_jar: p.join("x.jar"),
            ghidra_version: "12.1.4".into(),
        },
        p.join("project"),
    );
    cfg.restart_backoff = Duration::from_millis(5);
    cfg.startup_timeout = Duration::from_secs(5);
    tweak(&mut cfg);
    let fake = Arc::new(Fake::default());
    let launcher = FakeLauncher::new(handler(fake.clone()));
    let engine = Arc::new(GhidraEngine::with_launcher(cfg, launcher.clone()));
    Rig {
        engine,
        fake,
        launcher,
        binary,
        _dir: dir,
    }
}

fn rig() -> Rig {
    rig_with(|_| {})
}

async fn open(r: &Rig) {
    r.engine
        .open_binary(&r.binary, &LoaderSpec::default(), &CancellationToken::new())
        .await
        .unwrap();
}

fn at(offset: u64) -> Locator {
    Locator::ram(offset)
}

fn rename(offset: u64, old: Option<&str>, new: &str) -> VersionedLogOp {
    VersionedLogOp::new(LogOp::Rename {
        anchor: Anchor::Native {
            space: "ram".into(),
            offset: Hex64(offset),
            fn_entry: Hex64(offset),
            fn_hash: "h".into(),
        },
        old_name: old.map(str::to_string),
        new_name: new.into(),
    })
}

#[tokio::test]
async fn capabilities_cover_every_trait() {
    let r = rig();
    let caps = r.engine.capabilities();
    assert_eq!(caps.present.len(), 13);
    assert!(r.engine.disassembler().is_some() && r.engine.symbol_lister().is_some());
    assert!(r.engine.assembler().is_some());
    assert!(r.engine.loader().is_some() && r.engine.mutator().is_some());
    assert_eq!(caps.handshake.protocol, kraken_proto::PROTOCOL_VERSION);
    assert!(caps.handshake.build.contains("12.1.4"));
}

#[tokio::test]
async fn open_binary_maps_program_info_and_launches_once() {
    let r = rig();
    let cancel = CancellationToken::new();
    let info = r
        .engine
        .open_binary(&r.binary, &LoaderSpec::default(), &cancel)
        .await
        .unwrap();
    assert_eq!(
        (
            info.arch.as_str(),
            info.format.as_str(),
            info.base,
            info.size
        ),
        ("x86:LE:64:default", "elf", Hex64(0x100000), 2048)
    );
    assert_eq!(info.sha256, "abc");
    let sent = r.fake.last_params("open_binary");
    assert!(sent["path"].as_str().unwrap().ends_with("prog"));
    assert!(sent["project_dir"].as_str().unwrap().ends_with("project"));
    assert!(sent.get("loader_spec").is_none());

    // same plan: the sidecar is reused; a spec is forwarded
    let spec = LoaderSpec {
        format: Some("elf".into()),
        ..LoaderSpec::default()
    };
    r.engine
        .open_binary(&r.binary, &spec, &cancel)
        .await
        .unwrap();
    assert_eq!(r.launcher.launches.load(Ordering::SeqCst), 1);
    assert_eq!(
        r.fake.last_params("open_binary")["loader_spec"],
        "Executable and Linking Format (ELF);"
    );

    // a different binary needs its own confinement: new sidecar
    let other = r.binary.with_file_name("other");
    std::fs::write(&other, b"x").unwrap();
    r.engine
        .open_binary(&other, &LoaderSpec::default(), &cancel)
        .await
        .unwrap();
    assert_eq!(r.launcher.launches.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn bad_open_requests_never_reach_a_sidecar() {
    let r = rig();
    let cancel = CancellationToken::new();
    let bad = LoaderSpec {
        format: Some("kraken-no-such-format".into()),
        ..LoaderSpec::default()
    };
    let e = r
        .engine
        .open_binary(&r.binary, &bad, &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    let e = r
        .engine
        .open_binary(
            Path::new("/nonexistent/kraken"),
            &LoaderSpec::default(),
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = r
        .engine
        .open_binary(r.binary.parent().unwrap(), &LoaderSpec::default(), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let done = CancellationToken::new();
    done.cancel();
    let e = r
        .engine
        .open_binary(&r.binary, &LoaderSpec::default(), &done)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    assert_eq!(r.launcher.launches.load(Ordering::SeqCst), 0);
    // nothing opened yet
    let e = r
        .engine
        .list_functions(&PageRequest::default(), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
async fn queries_map_requests_and_results() {
    let r = rig();
    open(&r).await;
    let cancel = CancellationToken::new();

    let page = r
        .engine
        .list_functions(
            &PageRequest {
                cursor: Some("0x1000".into()),
                limit: Some(0),
            },
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(page.items[0].name, "main");
    let sent = r.fake.last_params("list_functions");
    assert_eq!(
        (sent["limit"].clone(), sent["cursor"].clone()),
        (json!(1), json!("0x1000"))
    );
    for garbage in ["\u{1}nope", "1000", ""] {
        let e = r
            .engine
            .list_functions(
                &PageRequest {
                    cursor: Some(garbage.into()),
                    limit: None,
                },
                &cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument, "{garbage:?}");
    }

    assert_eq!(
        r.engine
            .get_function(&at(0x1000), &cancel)
            .await
            .unwrap()
            .name,
        "main"
    );
    // inside a function: the sidecar answers, the trait wants entries only
    let e = r
        .engine
        .get_function(&at(0x1004), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
    let e = r
        .engine
        .get_function(&at(0x2000), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);

    let d = r.engine.decompile(&at(0x1000), &cancel).await.unwrap();
    assert_eq!(d.text, "int main(void)");
    let sent = r.fake.last_params("decompile");
    assert_eq!(sent["timeout_ms"], 30_000);
    assert_eq!(sent["locator"]["offset"], "0x1000");

    assert_eq!(r.engine.save(&cancel).await.unwrap().0, "save-1");

    let ts = r.engine.type_store().unwrap();
    assert!(
        matches!(ts.get_type("my_t", &cancel).await.unwrap(), TypeDef::Typedef(t) if t.name == "my_t")
    );
    assert_eq!(
        ts.get_type("missing", &cancel).await.unwrap_err().code,
        ErrorCode::NotFound
    );
    let def = TypeDef::Typedef(TypedefDef {
        name: "x_t".into(),
        target: TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size: 4,
            signed: true,
        }),
    });
    ts.define_type(def, &cancel).await.unwrap();
    assert_eq!(r.fake.called("define_type"), 1);
    let anon = TypeDef::Function(kraken_proto::FunctionPrototype {
        name: None,
        return_type: Box::new(TypeRef::Named {
            name: "void".into(),
        }),
        params: vec![],
        calling_convention: String::new(),
        varargs: false,
        noreturn: false,
    });
    assert_eq!(
        ts.define_type(anon, &cancel).await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    let e = ts
        .list_types(
            &PageRequest {
                cursor: Some("0x1".into()),
                limit: None,
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    assert_eq!(
        ts.list_types(&PageRequest::default(), &cancel)
            .await
            .unwrap()
            .items
            .len(),
        2
    );

    // a cancelled token never reaches the sidecar
    let done = CancellationToken::new();
    done.cancel();
    let before = r.fake.called("list_functions");
    let e = r
        .engine
        .list_functions(&PageRequest::default(), &done)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    assert_eq!(r.fake.called("list_functions"), before);
}

#[tokio::test]
async fn mutator_checks_stale_reads_idempotence_and_versions() {
    let r = rig();
    open(&r).await;
    let cancel = CancellationToken::new();

    // already in effect: Ok without touching the sidecar
    r.engine
        .apply(&rename(0x1000, Some("old"), "main"), &cancel)
        .await
        .unwrap();
    assert_eq!(r.fake.called("apply_op"), 0);
    // stale old_name
    let e = r
        .engine
        .apply(&rename(0x1000, Some("not_main"), "x"), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ConflictStaleRead);
    assert_eq!(r.fake.called("apply_op"), 0);
    // fresh rename goes through; no function at the address means a label rename: also forwarded
    r.engine
        .apply(&rename(0x1000, Some("main"), "entry"), &cancel)
        .await
        .unwrap();
    r.engine
        .apply(&rename(0x2000, None, "label"), &cancel)
        .await
        .unwrap();
    assert_eq!(r.fake.called("apply_op"), 2);
    assert_eq!(r.fake.last_params("apply_op")["op"]["op"]["op"], "rename");

    // reserved anchors and newer schemas are unsupported
    let managed = VersionedLogOp::new(LogOp::Rename {
        anchor: Anchor::Managed {
            token: "0x06000001".into(),
        },
        old_name: None,
        new_name: "x".into(),
    });
    let sent = r.fake.called("apply_op");
    let e = r.engine.apply(&managed, &cancel).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    let mut future = rename(0x1000, None, "x");
    future.schema_version = u32::MAX;
    let e = r.engine.apply(&future, &cancel).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert_eq!(
        r.fake.called("apply_op"),
        sent,
        "neither reached the sidecar"
    );
}

#[tokio::test]
async fn analysis_runs_staged_and_routes_progress_by_job() {
    let r = rig();
    open(&r).await;
    let mut job = r
        .engine
        .analyze(AnalyzeRequest::default(), CancellationToken::new())
        .await
        .unwrap();
    let mut seen = Vec::new();
    while let Some(p) = job.next_progress().await {
        seen.push((p.stage, p.done, p.total));
    }
    assert_eq!(seen.first(), Some(&(Stage::Load, 1, 1)));
    assert_eq!(
        seen.len(),
        5,
        "load + 4 sidecar events, none from other jobs: {seen:?}"
    );
    assert!(seen.windows(2).all(|w| w[0].0 <= w[1].0));
    let summary = job.wait().await.unwrap();
    assert_eq!(summary.stages_completed, Stage::ALL);
    assert_eq!(summary.function_count, 7);
    assert_eq!(
        r.fake.last_params("analyze")["stages"],
        json!(["core", "expensive"])
    );

    let resumed = r
        .engine
        .analyze(
            AnalyzeRequest {
                resume_from: Some(Stage::Expensive),
            },
            CancellationToken::new(),
        )
        .await
        .unwrap()
        .wait()
        .await
        .unwrap();
    assert_eq!(resumed.stages_completed, [Stage::Expensive]);
    assert_eq!(
        r.fake.last_params("analyze")["stages"],
        json!(["expensive"])
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_a_job_cancels_the_sidecar_job() {
    let r = rig();
    open(&r).await;
    r.fake.hold_analyze.store(true, Ordering::SeqCst);
    let job = r
        .engine
        .analyze(AnalyzeRequest::default(), CancellationToken::new())
        .await
        .unwrap();
    // cancel once the sidecar holds the job; the first `cancel` may race its registration
    let started = std::time::Instant::now();
    while r.fake.called("analyze") == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "analyze never arrived"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    job.cancel();
    let e = tokio::time::timeout(Duration::from_secs(10), job.wait())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
    assert!(r.fake.called("cancel") >= 1);

    // cancelled before the job even starts
    let token = CancellationToken::new();
    token.cancel();
    let e = r
        .engine
        .analyze(AnalyzeRequest::default(), token)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Cancelled);
}

#[tokio::test]
async fn request_deadlines_become_timeouts() {
    let r = rig_with(|c| {
        c.deadlines = Deadlines {
            default: Duration::from_millis(60),
            ..Deadlines::default()
        };
    });
    open(&r).await;
    let e = r
        .engine
        .rpc_for_test("slow", json!({}), &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Timeout);
    // the channel is still healthy afterwards
    r.engine.save(&CancellationToken::new()).await.unwrap();
}

#[tokio::test]
async fn sidecar_death_fails_in_flight_requests_and_restart_reopens() {
    let r = rig();
    let mut events = r.engine.subscribe();
    open(&r).await;
    let cancel = CancellationToken::new();

    let e = r
        .engine
        .rpc_for_test("die", json!({}), &cancel)
        .await
        .unwrap_err();
    assert_eq!(
        (e.code, e.message.as_str()),
        (ErrorCode::Internal, SIDECAR_EXITED)
    );
    let e = r
        .engine
        .list_functions(&PageRequest::default(), &cancel)
        .await
        .unwrap_err();
    assert_eq!(e.message, SIDECAR_EXITED);
    let details = e.details.unwrap();
    assert!(!details["log_tail"].as_array().unwrap().is_empty());
    assert_eq!(r.engine.diagnostics().state, "exited");

    r.engine.restart().await.unwrap();
    assert_eq!(r.launcher.launches.load(Ordering::SeqCst), 2);
    assert_eq!(
        r.fake.called("open_binary"),
        2,
        "restart replays open_binary"
    );
    assert_eq!(r.engine.diagnostics().restarts, 1);
    assert_eq!(r.engine.diagnostics().state, "running");
    assert_eq!(
        r.engine
            .list_functions(&PageRequest::default(), &cancel)
            .await
            .unwrap()
            .items
            .len(),
        1
    );

    let mut got = Vec::new();
    while let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
        got.push(ev);
    }
    assert_eq!(
        got,
        [
            SidecarEvent::Started,
            SidecarEvent::Exited { code: None },
            SidecarEvent::Started,
            SidecarEvent::Restarted,
        ]
    );
}

#[tokio::test]
async fn restart_is_bounded_and_needs_an_opened_binary() {
    let r = rig();
    assert_eq!(
        r.engine.restart().await.unwrap_err().code,
        ErrorCode::InvalidArgument
    );
    open(&r).await;
    r.launcher.fail_after.store(1, Ordering::SeqCst);
    let _ = r
        .engine
        .rpc_for_test("die", json!({}), &CancellationToken::new())
        .await;
    let e = r.engine.restart().await.unwrap_err();
    assert!(e.message.contains("after 3 attempts"), "{e}");
    assert_eq!(r.launcher.launches.load(Ordering::SeqCst), 1 + 3);
}

#[tokio::test]
async fn handshake_mismatch_is_reported_clearly() {
    let r = rig();
    *r.fake
        .protocol_minor
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(9);
    let e = r
        .engine
        .open_binary(&r.binary, &LoaderSpec::default(), &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("restart the daemon"), "{e}");
}

#[tokio::test]
async fn startup_failures_carry_the_exit_and_log() {
    let dir = scratch_dir();
    let binary = dir.path().join("prog");
    std::fs::write(&binary, b"x").unwrap();
    let p = dir.path().to_path_buf();
    let cfg = EngineConfig::new(
        GhidraInstall {
            ghidra_home: p.clone(),
            java_home: p.clone(),
            ext_jar: p.join("x.jar"),
            ghidra_version: "12.1.4".into(),
        },
        p.join("project"),
    );
    // a sidecar that dies before it says ready
    let launcher =
        FakeLauncher::with_start(handler(Arc::new(Fake::default())), |side, _| side.kill());
    let engine = GhidraEngine::with_launcher(cfg, launcher);
    let e = engine
        .open_binary(&binary, &LoaderSpec::default(), &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        e.message.contains("startup failed") && e.message.contains("signal Some(9)"),
        "{e}"
    );
    assert!(e.message.contains("fake sidecar #1 started"), "{e}");
}

#[tokio::test]
async fn stages_the_sidecar_already_completed_are_still_reported() {
    let r = rig();
    *r.fake
        .opened_stages
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = vec!["core"];
    open(&r).await;
    let mut job = r
        .engine
        .analyze(AnalyzeRequest::default(), CancellationToken::new())
        .await
        .unwrap();
    let first = job.next_progress().await.unwrap();
    assert_eq!(first.stage, Stage::Load);
    let second = job.next_progress().await.unwrap();
    assert_eq!(
        (second.stage, second.message.as_str()),
        (Stage::Core, "already complete")
    );
    let mut rest = Vec::new();
    while let Some(p) = job.next_progress().await {
        rest.push(p.stage);
    }
    assert!(rest.contains(&Stage::Expensive));
    assert!(rest.windows(2).all(|w| w[0] <= w[1]));
    assert_eq!(job.wait().await.unwrap().stages_completed, Stage::ALL);

    // everything is complete now: a second run reports all stages without ever running them
    let mut job = r
        .engine
        .analyze(AnalyzeRequest::default(), CancellationToken::new())
        .await
        .unwrap();
    let mut stages = Vec::new();
    while let Some(p) = job.next_progress().await {
        if p.message == "already complete" {
            stages.push(p.stage);
        }
    }
    assert_eq!(stages, [Stage::Core, Stage::Expensive]);
}

#[tokio::test]
async fn data_queries_map_requests_and_results() {
    use kraken_engine::{
        DisasmRequest, Disassembler, FlowGraph, MemoryReader, StringLister, StringsRequest,
        SymbolLister, XrefProvider, XrefRequest,
    };
    use kraken_proto::{DisasmScope, XrefDirection, XrefKind};

    let r = rig();
    open(&r).await;
    let cancel = CancellationToken::new();
    let e = &r.engine;
    let last_call = |method: &str| -> Value {
        r.fake
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(m, _)| m == method)
            .map(|(_, p)| p.clone())
            .unwrap_or_else(|| panic!("no {method} call"))
    };

    let map = e.memory_map(&cancel).await.unwrap();
    assert_eq!(map[0].name, ".text");
    assert_eq!(map[0].perms, "r-x");

    let asm = e
        .assembler()
        .expect("assembler")
        .assemble(&at(0x1000), "mov eax, 0x7", &cancel)
        .await
        .unwrap();
    assert_eq!(
        asm,
        vec![vec![0xb8, 7, 0, 0, 0], vec![0xc7, 0xc0, 7, 0, 0, 0]]
    );
    assert_eq!(last_call("assemble")["text"], "mov eax, 0x7");

    let read = e.read_bytes(&at(0x1000), 3, &cancel).await.unwrap();
    assert_eq!(read.bytes, [0, 1, 2]);
    assert_eq!(read.uninitialized[0].start, Hex64(0x1002));
    assert_eq!(last_call("read_bytes")["length"], 3);
    assert_eq!(
        e.read_bytes(&at(0x1000), 0, &cancel)
            .await
            .unwrap_err()
            .code,
        ErrorCode::InvalidArgument
    );

    let req = DisasmRequest {
        start: Hex64(0x1000),
        scope: DisasmScope::Function,
    };
    let page = e
        .disassemble(
            &req,
            &PageRequest {
                cursor: None,
                limit: Some(7),
            },
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(page.items[0].mnemonic, "nop");
    assert_eq!(page.next_cursor.as_deref(), Some("0x1001"));
    let sent = last_call("disassemble");
    assert_eq!(sent["start"], "0x1000");
    assert_eq!(sent["scope"], "function");
    assert_eq!(sent["limit"], 7);
    for cursor in ["1001", "zz", "-1"] {
        let bad = e
            .disassemble(
                &req,
                &PageRequest {
                    cursor: Some(cursor.into()),
                    limit: None,
                },
                &cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(bad.code, ErrorCode::InvalidArgument, "{cursor}");
    }

    let x = XrefRequest {
        address: Hex64(0x1040),
        direction: XrefDirection::To,
        kind: Some(XrefKind::Call),
        whole_function: false,
    };
    let page = e.xrefs(&x, &PageRequest::default(), &cancel).await.unwrap();
    assert_eq!(page.items[0].to, Hex64(0x1040));
    let sent = last_call("xrefs");
    assert_eq!(
        (sent["direction"].as_str(), sent["kind"].as_str()),
        (Some("to"), Some("call"))
    );
    assert_eq!(sent["whole_function"], false);
    let bad = e
        .xrefs(
            &x,
            &PageRequest {
                cursor: Some("x".into()),
                limit: None,
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidArgument);

    let cfg = e.cfg(&at(0x1004), &cancel).await.unwrap();
    assert_eq!(cfg.blocks[0].instructions, 4);

    let sreq = StringsRequest {
        min_len: 5,
        filter: Some("hi".into()),
    };
    let strings = e
        .strings(&sreq, &PageRequest::default(), &cancel)
        .await
        .unwrap();
    assert_eq!(strings.items[0].value, "hi");
    let sent = last_call("strings");
    assert_eq!(
        (sent["min_len"].as_u64(), sent["filter"].as_str()),
        (Some(5), Some("hi"))
    );

    assert_eq!(
        e.imports(&PageRequest::default(), &cancel)
            .await
            .unwrap()
            .items[0]
            .name,
        "puts"
    );
    assert_eq!(
        e.exports(&PageRequest::default(), &cancel)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    let bad = e
        .imports(
            &PageRequest {
                cursor: Some("abc".into()),
                limit: None,
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidArgument);
}

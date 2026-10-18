//! Progress and cancellation of `project_create` and `project_open` on a scripted engine.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, OpenProgress, OpenStage, ProtoError};
use kraken_registry::{
    CallContext, EngineFactory, JobStatus, OpenProgressSink, Registry, Session, Surface,
};
use serde_json::json;

struct Slow(Duration);

#[async_trait]
impl EngineFactory for Slow {
    async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
        let fx = FixtureFile::from_path(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json"),
        )
        .expect("tiny fixture");
        Ok(Arc::new(FakeEngine::new(fx).with_open_delay(self.0)))
    }
}

fn recorder() -> (OpenProgressSink, Arc<Mutex<Vec<OpenProgress>>>) {
    let seen: Arc<Mutex<Vec<OpenProgress>>> = Arc::default();
    let sink: OpenProgressSink = {
        let seen = seen.clone();
        Arc::new(move |p| seen.lock().unwrap().push(p.clone()))
    };
    (sink, seen)
}

fn binary(dir: &Path) -> std::path::PathBuf {
    let b = dir.join("prog.bin");
    std::fs::write(&b, b"\x7fELF fake").unwrap();
    b
}

#[tokio::test]
async fn create_and_open_report_every_stage_in_order() {
    let t = tempfile::tempdir().unwrap();
    let b = binary(t.path());
    let proj = t.path().join("p");
    let registry = Registry::standard();
    let session = Session::new(Arc::new(Slow(Duration::ZERO)));
    let (sink, seen) = recorder();
    let ctx = CallContext::user("u", Surface::Test).with_open_progress(sink);
    registry
        .call_json(
            "project_create",
            &session,
            &ctx,
            json!({"binary": b, "project_dir": proj}),
        )
        .await
        .expect("create");
    let reports = std::mem::take(&mut *seen.lock().unwrap());
    let stages: Vec<OpenStage> = reports.iter().map(|p| p.stage).collect();
    assert_eq!(stages.first(), Some(&OpenStage::Prepare));
    assert_eq!(stages.last(), Some(&OpenStage::Ready));
    assert!(stages.windows(2).all(|w| w[0] <= w[1]), "{stages:?}");
    assert!(stages.contains(&OpenStage::Functions));
    let fractions: Vec<f64> = reports.iter().filter_map(|p| p.fraction).collect();
    assert!(fractions.windows(2).all(|w| w[0] <= w[1]), "{fractions:?}");
    assert_eq!(fractions.last(), Some(&1.0));
    let last = reports.last().unwrap();
    assert_eq!(last.program, "prog.bin");
    assert_eq!(last.command, "project_create");
    assert!(last.job_id.is_some());
    assert!(
        session.jobs().list().is_empty(),
        "a finished open leaves no job behind"
    );

    let again = Session::new(Arc::new(Slow(Duration::ZERO)));
    registry
        .call_json("project_open", &again, &ctx, json!({"project_dir": proj}))
        .await
        .expect("open");
    let reports = seen.lock().unwrap().clone();
    assert_eq!(reports[0].command, "project_open");
    assert!(reports.iter().any(|p| p.stage == OpenStage::Replay));
    assert_eq!(reports.last().map(|p| p.stage), Some(OpenStage::Ready));
}

#[tokio::test]
async fn job_cancel_stops_an_open_and_leaves_no_project() {
    let t = tempfile::tempdir().unwrap();
    let b = binary(t.path());
    let proj = t.path().join("p");
    let registry = Arc::new(Registry::standard());
    let session = Session::new(Arc::new(Slow(Duration::from_secs(30))));
    let (sink, seen) = recorder();
    let ctx = CallContext::user("u", Surface::Test).with_open_progress(sink);
    let create = {
        let (registry, session, ctx) = (registry.clone(), session.clone(), ctx.clone());
        let args = json!({"binary": b, "project_dir": proj});
        tokio::spawn(async move {
            registry
                .call_json("project_create", &session, &ctx, args)
                .await
        })
    };
    // wait for the open to reach the function search, then cancel it through its job
    let job = loop {
        let at = seen
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.stage == OpenStage::Functions)
            .and_then(|p| p.job_id.clone());
        if let Some(id) = at {
            break id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    let status = registry
        .call_json(
            "job_status",
            &session,
            &ctx,
            json!({ "job_id": job.clone() }),
        )
        .await
        .expect("status");
    assert_eq!(status["command"], "project_create");
    assert_eq!(status["open_progress"]["stage"], "functions");
    let started = std::time::Instant::now();
    registry
        .call_json(
            "job_cancel",
            &session,
            &ctx,
            json!({ "job_id": job.clone() }),
        )
        .await
        .expect("cancel");
    let e = create.await.unwrap().expect_err("cancelled");
    assert_eq!(e.code, ErrorCode::Cancelled, "{e:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(session.project().is_err(), "no half-open project");
    let snap = session
        .jobs()
        .snapshot(&kraken_registry::JobId(job))
        .unwrap();
    assert_eq!(snap.status, JobStatus::Cancelled);
    // the folder can be used again
    let quick = Session::new(Arc::new(Slow(Duration::ZERO)));
    registry
        .call_json(
            "project_create",
            &quick,
            &CallContext::user("u", Surface::Test),
            json!({"binary": b, "project_dir": proj}),
        )
        .await
        .expect("create after a cancelled one");
}

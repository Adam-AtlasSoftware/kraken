//! The machine-global setup commands on a session with no project: the report, the install jobs
//! with their `job-gN` ids, progress, cancel, and the approval an agent needs.

mod common;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use common::{agent, tiny, user};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::EngineFactory;
use kraken_registry::commands::{SetupBackend, SetupItem, SetupState, SetupTask};
use kraken_registry::{
    AutoApprove, CallContext, JobProgress, JobTable, Registry, Session, jobs::is_global_job,
};
use serde_json::{Value, json};

#[derive(Debug)]
struct Stub;

#[async_trait]
impl SetupBackend for Stub {
    fn status(&self) -> Result<Vec<SetupItem>, ProtoError> {
        let item = |id: &str, state| SetupItem {
            id: id.into(),
            name: id.into(),
            purpose: "test".into(),
            state,
            detail: "d".into(),
            fix: (state != SetupState::Ready).then(|| "install it".to_string()),
            fix_command: None,
        };
        Ok(vec![
            item("a", SetupState::Ready),
            item("b", SetupState::Missing),
        ])
    }

    async fn run(
        &self,
        task: SetupTask,
        _force: bool,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<Value, ProtoError> {
        progress(JobProgress {
            phase: "download".into(),
            done: 5,
            total: 10,
            message: format!("{} working", task.command()),
            ..Default::default()
        });
        std::future::pending::<()>().await;
        Ok(Value::Null)
    }
}

struct Factory;

#[async_trait]
impl EngineFactory for Factory {
    async fn create(&self, _engine_dir: &std::path::Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(engine_fake::FakeEngine::new(tiny())))
    }
}

fn session() -> Session {
    Session::new(Arc::new(Factory))
        .with_jobs(JobTable::global())
        .with_setup(Arc::new(Stub))
}

async fn call(
    s: &Session,
    ctx: &CallContext,
    name: &str,
    args: Value,
) -> Result<Value, ProtoError> {
    Registry::standard().call_json(name, s, ctx, args).await
}

#[tokio::test]
async fn status_needs_no_project_and_counts_the_parts() {
    let s = session();
    let out = call(&s, &user(), "setup_status", json!({})).await.unwrap();
    assert_eq!(out["ready"], 1);
    assert_eq!(out["not_ready"], 1);
    assert_eq!(out["items"][1]["fix"], "install it");
}

#[tokio::test]
async fn an_install_is_a_global_job_that_reports_progress_and_cancels() {
    let s = session();
    let out = call(&s, &user(), "setup_native", json!({})).await.unwrap();
    let id = out["job_id"].as_str().unwrap().to_string();
    assert_eq!(id, "job-g1");
    assert!(is_global_job(&id));
    let mut view = Value::Null;
    for _ in 0..100 {
        view = call(&s, &user(), "job_status", json!({"job_id": id}))
            .await
            .unwrap();
        if view["progress"]["done"] == 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(view["status"], "running", "{view}");
    assert_eq!(view["progress"]["message"], "setup_native working");
    call(&s, &user(), "job_cancel", json!({"job_id": id}))
        .await
        .unwrap();
    let done = call(
        &s,
        &user(),
        "job_await",
        json!({"job_id": id, "timeout_ms": 5000}),
    )
    .await
    .unwrap();
    assert_eq!(done["status"], "cancelled", "{done}");
    // ordinary job ids are not found in the global table
    let e = call(&s, &user(), "job_status", json!({"job_id": "job-1"}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::NotFound);
}

#[tokio::test]
async fn an_agent_is_asked_before_an_install_starts() {
    let s = session();
    let e = call(&s, &agent("r"), "setup_ghidra", json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    let ok = call(
        &s,
        &agent("r").with_approval(Arc::new(AutoApprove)),
        "setup_ghidra",
        json!({}),
    )
    .await
    .unwrap();
    assert_eq!(ok["job_id"], "job-g1");
}

#[tokio::test]
async fn without_a_backend_the_commands_say_so() {
    let s = Session::new(Arc::new(Factory));
    let e = call(&s, &user(), "setup_status", json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
}

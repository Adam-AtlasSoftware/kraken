//! An engine state saved over by another session is brought back in line with the edit log,
//! and a project is held by one process at a time.
//!
//! The engine here is the fake with a state directory: like the native engine it saves the ops
//! it holds to the project's engine directory, replays them on open and reports the checkpoint
//! of what it loaded.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::FakeEngine;
use kraken_engine::{CancellationToken, SharedEngine};
use kraken_proto::{ErrorCode, Locator, ProtoError};
use kraken_registry::project_lock::LOCK_FILE;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use serde_json::{Value, json};

mod common;

struct StateFactory;

#[async_trait]
impl EngineFactory for StateFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(
            FakeEngine::new(common::default_named())
                .with_stage_delay(Duration::ZERO)
                .with_state_dir(engine_dir),
        ))
    }
}

fn user() -> CallContext {
    CallContext::user("adam", Surface::Test)
}

struct World {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    binary: PathBuf,
    registry: Registry,
    factory: Arc<StateFactory>,
}

fn world() -> World {
    let tmp = tempfile::tempdir().expect("tempdir");
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake binary contents").expect("binary");
    World {
        dir: tmp.path().join("proj"),
        binary,
        _tmp: tmp,
        registry: Registry::standard(),
        factory: Arc::new(StateFactory),
    }
}

impl World {
    async fn call(&self, s: &Session, name: &str, args: Value) -> Value {
        match self.registry.call_json(name, s, &user(), args).await {
            Ok(v) => v,
            Err(e) => panic!("{name} failed: {e}"),
        }
    }

    async fn create(&self) -> Session {
        let s = Session::create(&self.dir, &self.binary, self.factory.clone())
            .await
            .expect("create");
        let started = self.call(&s, "analyze", json!({})).await;
        let done = self
            .call(
                &s,
                "job_await",
                json!({"job_id": started["job_id"], "timeout_ms": 20000}),
            )
            .await;
        assert_eq!(done["status"], "succeeded", "{done}");
        s
    }

    async fn open(&self) -> Session {
        Session::open(&self.dir, self.factory.clone())
            .await
            .expect("open")
    }

    async fn rename(&self, s: &Session, addr: &str, name: &str) {
        let r = self
            .call(
                s,
                "rename_symbol",
                json!({"address": addr, "new_name": name}),
            )
            .await;
        assert_eq!(r["status"], "applied", "{r}");
    }
}

async fn engine_name(s: &Session, addr: u64) -> String {
    s.engine()
        .expect("engine")
        .function_lister()
        .expect("lister")
        .get_function(&Locator::ram(addr), &CancellationToken::new())
        .await
        .expect("function")
        .name
}

/// Saves the engine the way a process that knows nothing of the other session's edits did:
/// its own state, straight to the engine directory.
async fn raw_save(s: &Session) {
    s.engine()
        .expect("engine")
        .mutator()
        .expect("mutator")
        .save(&CancellationToken::new())
        .await
        .expect("save");
}

#[tokio::test]
async fn edits_saved_over_by_a_stale_session_come_back_on_open() {
    let w = world();
    // `kraken auto`: creates and analyses the project, then waits for the agent
    let first = w.create().await;
    // the agent's own `kraken mcp` session: renames, which save the engine and the watermark
    let second = w.open().await;
    w.rename(&second, "0x401040", "parse_args").await;
    w.rename(&second, "0x401000", "entry_point").await;
    w.rename(&second, "0x401000", "start").await;
    assert_eq!(engine_name(&second, 0x401040).await, "parse_args");
    drop(second);
    // the first process still holds its engine without the renames and saves it last
    assert_eq!(engine_name(&first, 0x401040).await, "FUN_00401040");
    raw_save(&first).await;
    drop(first);

    let reopened = w.open().await;
    assert_eq!(engine_name(&reopened, 0x401040).await, "parse_args");
    assert_eq!(engine_name(&reopened, 0x401000).await, "start");
    let report = reopened
        .project()
        .expect("project")
        .resync_report()
        .expect("the stale state is reported");
    assert_eq!(report.reapplied, 3);
    assert!(report.failed.is_empty(), "{report:?}");
    let info = w.call(&reopened, "project_info", json!({})).await;
    let note = info["engine_resync"]
        .as_str()
        .expect("project_info says so");
    assert!(note.contains("applied again"), "{note}");
    assert_eq!(info["log_entries"], 3, "{info}");
    assert_eq!(info["pending_entries"], 0, "{info}");
    drop(reopened);

    // the repaired state was saved with a new watermark: the next open has nothing to do
    let again = w.open().await;
    assert_eq!(engine_name(&again, 0x401040).await, "parse_args");
    assert!(again.project().expect("project").resync_report().is_none());
    let info = w.call(&again, "project_info", json!({})).await;
    assert!(info.get("engine_resync").is_none(), "{info}");
}

#[tokio::test]
async fn a_session_saving_last_takes_the_other_sessions_edits_along() {
    let w = world();
    let first = w.create().await;
    let second = w.open().await;
    w.rename(&second, "0x401040", "parse_args").await;
    drop(second);
    // the first session's own edit after the other one's, then a regular close
    w.rename(&first, "0x401000", "start").await;
    assert_eq!(engine_name(&first, 0x401040).await, "parse_args");
    first.close_project().await.expect("was open");
    drop(first);

    let reopened = w.open().await;
    assert_eq!(engine_name(&reopened, 0x401040).await, "parse_args");
    assert_eq!(engine_name(&reopened, 0x401000).await, "start");
    assert!(
        reopened
            .project()
            .expect("project")
            .resync_report()
            .is_none()
    );
}

#[tokio::test]
async fn a_project_open_in_another_process_is_refused() {
    let w = world();
    let first = w.create().await;
    // sessions of one process share the lock
    let second = w.open().await;
    drop(second);

    // another open file description stands in for the lock of another process
    let lock_path = w.dir.join(LOCK_FILE);
    let text = std::fs::read_to_string(&lock_path).expect("lock file");
    assert_eq!(text.trim(), std::process::id().to_string());
    let other = std::fs::File::open(&lock_path).expect("open");
    assert!(other.try_lock().is_err(), "the project is locked");

    first.close_project().await.expect("was open");
    drop(first);
    other
        .try_lock()
        .expect("closing the last session releases the lock");

    let e = Session::open(&w.dir, w.factory.clone())
        .await
        .expect_err("held by the other process");
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(
        e.message.contains("open in another KRAKEN process"),
        "{}",
        e.message
    );
    assert!(e.message.contains("daemon"), "{}", e.message);
    drop(other);
    w.open().await;
}

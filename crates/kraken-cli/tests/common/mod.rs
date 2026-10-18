#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_cli::{CliAuthor, CliEnv, DaemonMode, run};
use kraken_engine::SharedEngine;
use kraken_host::{KrakenConfig, ManagedFactory};
use kraken_proto::{Locator, ProtoError};
use kraken_registry::{EngineFactory, Registry, Session};
use serde_json::Value;

/// An MCP client that supports elicitation and approves everything it is asked: the person
/// behind the agent saying yes to `project_create`.
pub struct ApprovingClient;

impl rmcp::ClientHandler for ApprovingClient {
    fn get_info(&self) -> rmcp::model::ClientConfig {
        rmcp::model::ClientConfig::new(
            rmcp::model::ClientCapabilities::builder()
                .enable_elicitation()
                .build(),
            rmcp::model::Implementation::new("approving-test-client", "1.0"),
        )
    }

    async fn create_elicitation(
        &self,
        _request: rmcp::model::ElicitRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleClient>,
    ) -> Result<rmcp::model::ElicitResult, rmcp::ErrorData> {
        Ok(
            rmcp::model::ElicitResult::new(rmcp::model::ElicitationAction::Accept)
                .with_content(serde_json::json!({"approve": true})),
        )
    }
}

/// The tiny fixture with every function carrying an engine default name.
pub fn default_named() -> FixtureFile {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
    let mut fx = FixtureFile::from_path(&path).expect("tiny fixture");
    for f in &mut fx.functions {
        if let Locator::Native { offset, .. } = &f.summary.locator {
            f.summary.name = format!("FUN_{:08x}", offset.0);
        }
    }
    fx
}

pub struct FakeFactory {
    pub fixture: FixtureFile,
}

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.fixture.clone())))
    }
}

#[async_trait]
impl ManagedFactory for FakeFactory {
    async fn shutdown(&self) {}
}

/// Fake engines that keep the ops they hold in the project's engine directory, like the native
/// engine: a reopen shows what the last save had.
pub struct StatefulFactory;

#[async_trait]
impl EngineFactory for StatefulFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(
            FakeEngine::new(default_named())
                .with_stage_delay(std::time::Duration::ZERO)
                .with_state_dir(engine_dir),
        ))
    }
}

#[async_trait]
impl ManagedFactory for StatefulFactory {
    async fn shutdown(&self) {}
}

pub struct Rig {
    pub factory: Arc<FakeFactory>,
    pub session: Arc<Session>,
    pub env: CliEnv,
}

pub fn rig(author: CliAuthor, vars: Vec<(&'static str, String)>) -> Rig {
    let factory = Arc::new(FakeFactory {
        fixture: default_named(),
    });
    let session = Arc::new(Session::new(factory.clone()));
    let env = CliEnv {
        registry: Arc::new(Registry::standard()),
        factory: factory.clone(),
        config: KrakenConfig::default(),
        author,
        vars: Box::new(move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())),
        interactive: false,
        session: Some(session.clone()),
        daemon: DaemonMode::Direct,
        rewrite: None,
    };
    Rig {
        factory,
        session,
        env,
    }
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// The JSON the command printed (stdout on success, stderr on failure).
    pub fn json(&self) -> Value {
        let text = if self.code == 0 {
            &self.stdout
        } else {
            &self.stderr
        };
        serde_json::from_str(text.trim()).unwrap_or_else(|e| {
            panic!(
                "not JSON ({e}): stdout={:?} stderr={:?}",
                self.stdout, self.stderr
            )
        })
    }
}

pub async fn kraken(env: &CliEnv, args: &[&str]) -> Run {
    let argv: Vec<OsString> = std::iter::once("kraken")
        .chain(args.iter().copied())
        .map(OsString::from)
        .collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(argv, env, &mut out, &mut err).await;
    Run {
        code,
        stdout: String::from_utf8_lossy(&out).into_owned(),
        stderr: String::from_utf8_lossy(&err).into_owned(),
    }
}

pub struct Workdir {
    pub tmp: tempfile::TempDir,
    pub binary: PathBuf,
}

pub fn workdir() -> Workdir {
    let tmp = tempfile::Builder::new()
        .prefix("kraken-cli-test-")
        .tempdir()
        .expect("tempdir");
    let binary = tmp.path().join("prog.bin");
    std::fs::write(&binary, b"\x7fELF fake binary contents").expect("binary");
    Workdir { tmp, binary }
}

/// An environment without a shared session: every invocation opens the project from disk, like
/// the real binary.
pub fn fresh_env(config: KrakenConfig, vars: Vec<(&'static str, String)>) -> CliEnv {
    let factory = Arc::new(FakeFactory {
        fixture: default_named(),
    });
    CliEnv {
        registry: Arc::new(Registry::standard()),
        factory,
        config,
        author: CliAuthor::User("tester".into()),
        vars: Box::new(move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())),
        interactive: false,
        session: None,
        daemon: DaemonMode::Direct,
        rewrite: None,
    }
}

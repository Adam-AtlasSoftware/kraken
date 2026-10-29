#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::{CancellationToken, Cap, SharedEngine};
use kraken_proto::{ErrorCode, Locator, ProtoError};
use kraken_registry::{CallContext, EngineFactory, Registry, Session, SessionConfig, Surface};
use serde_json::{Value, json};

pub fn tiny() -> FixtureFile {
    FixtureFile::from_path(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json"),
    )
    .expect("tiny fixture loads")
}

/// The tiny fixture with every function carrying an engine default name.
pub fn default_named() -> FixtureFile {
    let mut fx = tiny();
    for f in &mut fx.functions {
        let (_, off) = match &f.summary.locator {
            Locator::Native { space, offset } => (space.clone(), offset.0),
            _ => unreachable!(),
        };
        f.summary.name = format!("FUN_{off:08x}");
    }
    fx
}

type FixtureFn = Box<dyn Fn(usize) -> FixtureFile + Send + Sync>;

pub struct TestFactory {
    fixture: FixtureFn,
    delay: Duration,
    without: Option<Cap>,
    pub created: AtomicUsize,
}

#[async_trait]
impl EngineFactory for TestFactory {
    async fn create(&self, _engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let n = self.created.fetch_add(1, Ordering::SeqCst);
        let mut e = FakeEngine::new((self.fixture)(n)).with_stage_delay(self.delay);
        if let Some(c) = self.without {
            e = e.without(c);
        }
        Ok(Arc::new(e))
    }
}

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub session: Session,
    pub registry: Registry,
    pub factory: Arc<TestFactory>,
    pub binary: PathBuf,
    pub project_dir: PathBuf,
}

pub struct Setup {
    fixture: FixtureFn,
    delay: Duration,
    without: Option<Cap>,
    config: SessionConfig,
    integrations: Option<Arc<dyn kraken_registry::commands::IntegrationsBackend>>,
}

impl Setup {
    pub fn new(fixture: FixtureFile) -> Setup {
        Setup {
            fixture: Box::new(move |_| fixture.clone()),
            delay: Duration::ZERO,
            without: None,
            config: SessionConfig::default(),
            integrations: None,
        }
    }

    pub fn per_engine(mut self, f: impl Fn(usize) -> FixtureFile + Send + Sync + 'static) -> Setup {
        self.fixture = Box::new(f);
        self
    }

    pub fn delay(mut self, d: Duration) -> Setup {
        self.delay = d;
        self
    }

    pub fn without(mut self, c: Cap) -> Setup {
        self.without = Some(c);
        self
    }

    pub fn config(mut self, c: SessionConfig) -> Setup {
        self.config = c;
        self
    }

    /// Builds a session and creates the project through the `project_create` command.
    /// Attaches an integrations catalogue to the session.
    pub fn integrations(
        mut self,
        b: Arc<dyn kraken_registry::commands::IntegrationsBackend>,
    ) -> Setup {
        self.integrations = Some(b);
        self
    }

    pub async fn start(self) -> Env {
        let tmp = tempfile::tempdir().expect("tempdir");
        let binary = tmp.path().join("prog.bin");
        std::fs::write(&binary, b"\x7fELF fake binary contents").expect("write binary");
        let project_dir = tmp.path().join("proj");
        let factory = Arc::new(TestFactory {
            fixture: self.fixture,
            delay: self.delay,
            without: self.without,
            created: AtomicUsize::new(0),
        });
        let mut session = Session::new(factory.clone()).with_config(self.config);
        if let Some(b) = self.integrations {
            session = session.with_integrations(b);
        }
        let env = Env {
            tmp,
            session,
            registry: Registry::standard(),
            factory,
            binary,
            project_dir,
        };
        env.call(
            &user(),
            "project_create",
            json!({"binary": env.binary.to_str().unwrap(), "project_dir": env.project_dir.to_str().unwrap()}),
        )
        .await
        .expect("project_create");
        env
    }
}

impl Env {
    pub async fn call(
        &self,
        ctx: &CallContext,
        name: &str,
        args: Value,
    ) -> Result<Value, ProtoError> {
        self.registry
            .call_json(name, &self.session, ctx, args)
            .await
    }

    pub async fn ok(&self, ctx: &CallContext, name: &str, args: Value) -> Value {
        match self.call(ctx, name, args).await {
            Ok(v) => v,
            Err(e) => panic!("{name} failed: {e} {:?}", e.details),
        }
    }

    pub async fn err(&self, ctx: &CallContext, name: &str, args: Value) -> ProtoError {
        match self.call(ctx, name, args).await {
            Ok(v) => panic!("{name} unexpectedly succeeded: {v}"),
            Err(e) => e,
        }
    }

    /// Name of the function at `addr` according to the engine itself.
    pub async fn engine_name(&self, addr: u64) -> String {
        let engine = self.session.engine().expect("engine");
        engine
            .function_lister()
            .expect("lister")
            .get_function(&Locator::ram(addr), &CancellationToken::new())
            .await
            .expect("function")
            .name
    }

    /// Runs a started job to the end and returns the final job view.
    pub async fn finish(&self, started: &Value) -> Value {
        let v = self
            .ok(
                &user(),
                "job_await",
                json!({"job_id": started["job_id"], "timeout_ms": 20000}),
            )
            .await;
        assert_ne!(v["status"], "running", "job did not finish: {v}");
        v
    }

    pub async fn analyze(&self) -> Value {
        let started = self.ok(&user(), "analyze", json!({})).await;
        self.finish(&started).await
    }
}

pub fn user() -> CallContext {
    CallContext::user("adam", Surface::Test).with_cancel(CancellationToken::new())
}

pub fn agent(run: &str) -> CallContext {
    CallContext::agent("bot", run, Surface::Test)
}

pub fn code(e: &ProtoError) -> ErrorCode {
    e.code
}

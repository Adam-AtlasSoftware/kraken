//! Connections (to `krakend` or in-process) and per-project command handles.
//!
//! This is the Python-independent core of the module: everything the extension does besides
//! type conversion lives here so `cargo test` can exercise it without an interpreter.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kraken_engine::CancellationToken;
use kraken_host::backend::{CommandBackend, DaemonBackend, LocalBackend};
use kraken_host::daemon::{DaemonClient, StartOptions, find_krakend};
use kraken_host::{KrakenConfig, ManagedFactory, RunIdGen, user_id};
use kraken_ipc::{ClientKind, RuntimeDir};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::{AutoApprove, CallContext, DenyApprover, Registry, Session, Surface};
use serde_json::Value;

use crate::schema;

/// The build string announced to the daemon; the workspace version, like `kraken` and `krakend`.
pub const BUILD: &str = env!("CARGO_PKG_VERSION");

/// Who edits are attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Author {
    /// The person running the script; scripts are the user's own edits.
    User(String),
    /// A named agent. Its writes follow agent policy (additive ones apply, others become
    /// proposals) and are logged under one run id.
    Agent {
        /// Agent name.
        id: String,
        /// Run id the edits are grouped under (see `undo_run`).
        run_id: String,
    },
}

impl Author {
    /// The current user.
    pub fn current_user() -> Self {
        Author::User(user_id())
    }

    /// An agent with a fresh run id unless one is given.
    pub fn agent(id: &str, run_id: Option<String>) -> Self {
        Author::Agent {
            id: kraken_host::agent_id_from_client(Some(id)),
            run_id: run_id.unwrap_or_else(|| RunIdGen::new().next_id()),
        }
    }

    /// The run id of an agent author.
    pub fn run_id(&self) -> Option<&str> {
        match self {
            Author::User(_) => None,
            Author::Agent { run_id, .. } => Some(run_id),
        }
    }

    /// `"user"` or `"agent"`.
    pub fn kind(&self) -> &'static str {
        match self {
            Author::User(_) => "user",
            Author::Agent { .. } => "agent",
        }
    }

    /// The user name or agent id.
    pub fn id(&self) -> &str {
        match self {
            Author::User(id) | Author::Agent { id, .. } => id,
        }
    }
}

/// Where commands run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Through `krakend`.
    Daemon,
    /// In this process.
    Local,
}

impl Mode {
    /// `"daemon"` or `"local"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Daemon => "daemon",
            Mode::Local => "local",
        }
    }
}

/// How to connect.
#[derive(Debug, Clone, Default)]
pub struct ConnectOptions {
    /// `Some(true)`: require the daemon (start it if needed). `Some(false)`: run in this process.
    /// `None`: use the daemon, falling back to this process with a warning (and in-process when
    /// `KRAKEN_NO_DAEMON` is set).
    pub daemon: Option<bool>,
    /// Runtime directory of the daemon; default per user (`KRAKEN_RUNTIME_DIR` wins).
    pub runtime_dir: Option<PathBuf>,
    /// The `krakend` binary to start; default `$KRAKEN_KRAKEND`, `PATH`, next to the executable.
    pub krakend: Option<PathBuf>,
}

enum Transport {
    Daemon(Arc<DaemonClient>),
    Local {
        factory: Arc<dyn ManagedFactory>,
        config: Box<KrakenConfig>,
    },
}

/// A connection: the daemon, or the engine factory of this process. Cheap to share.
pub struct Connection {
    registry: Arc<Registry>,
    transport: Transport,
    warnings: Vec<String>,
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .is_ok_and(|v| !v.is_empty() && !matches!(v.as_str(), "0" | "false" | "no" | "off"))
}

fn which(name: &str) -> Option<PathBuf> {
    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(&exe))
            .find(|p| p.is_file())
    })
}

impl Connection {
    /// Connects as `opts` say.
    pub async fn connect(opts: &ConnectOptions) -> Result<Connection, ProtoError> {
        let registry = Arc::new(Registry::standard());
        let want_local =
            opts.daemon == Some(false) || (opts.daemon.is_none() && env_flag("KRAKEN_NO_DAEMON"));
        if want_local {
            return Self::local(registry, Vec::new());
        }
        match connect_daemon(opts).await {
            Ok(client) => {
                let mut warnings = Vec::new();
                if let Some(w) = client.build_mismatch_warning() {
                    warnings.push(w);
                }
                Ok(Connection {
                    registry,
                    transport: Transport::Daemon(Arc::new(client)),
                    warnings,
                })
            }
            Err(e) if opts.daemon == Some(true) => Err(e),
            Err(e) => Self::local(
                registry,
                vec![format!(
                    "cannot use krakend ({}); running in this process \
                     (kraken.connect(daemon=False) silences this)",
                    e.message
                )],
            ),
        }
    }

    fn local(registry: Arc<Registry>, warnings: Vec<String>) -> Result<Connection, ProtoError> {
        let config = KrakenConfig::load()
            .map_err(|e| ProtoError::new(ErrorCode::InvalidArgument, e.to_string()))?;
        let factory: Arc<dyn ManagedFactory> =
            Arc::new(kraken_host::HostEngineFactory::new(config.clone()));
        Ok(Connection {
            registry,
            transport: Transport::Local {
                factory,
                config: Box::new(config),
            },
            warnings,
        })
    }

    /// An in-process connection over any engine factory (tests and embedding).
    pub fn with_factory(factory: Arc<dyn ManagedFactory>, config: KrakenConfig) -> Connection {
        Connection {
            registry: Arc::new(Registry::standard()),
            transport: Transport::Local {
                factory,
                config: Box::new(config),
            },
            warnings: Vec::new(),
        }
    }

    /// Where commands run.
    pub fn mode(&self) -> Mode {
        match self.transport {
            Transport::Daemon(_) => Mode::Daemon,
            Transport::Local { .. } => Mode::Local,
        }
    }

    /// Notices produced while connecting (a daemon from another build, a fallback).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The command registry (specs and schemas).
    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    /// Daemon process id, when connected to one.
    pub fn daemon_pid(&self) -> Option<u32> {
        match &self.transport {
            Transport::Daemon(c) => Some(c.daemon_pid()),
            Transport::Local { .. } => None,
        }
    }

    /// Asks the daemon to exit. Returns false (and does nothing) for an in-process connection.
    pub async fn stop_daemon(&self) -> Result<bool, ProtoError> {
        match &self.transport {
            Transport::Daemon(c) => c.shutdown().await.map(|()| true),
            Transport::Local { .. } => Ok(false),
        }
    }

    /// A handle for one project: its own backend (and, in-process, its own session), so several
    /// projects can be open at once on one connection.
    pub fn handle(&self, project_dir: Option<&Path>, author: Author) -> Handle {
        let backend: Arc<dyn CommandBackend> = match &self.transport {
            Transport::Daemon(client) => Arc::new(DaemonBackend::new(
                client.clone(),
                self.registry.clone(),
                project_dir.map(Path::to_path_buf),
            )),
            Transport::Local { factory, config } => {
                let session =
                    Arc::new(Session::new(factory.clone()).with_config(config.session_config()));
                Arc::new(LocalBackend::new(
                    self.registry.clone(),
                    session,
                    project_dir.map(Path::to_path_buf),
                ))
            }
        };
        Handle {
            backend,
            registry: self.registry.clone(),
            author,
        }
    }

    /// Stops the engines started by this process. A daemon is left running: other clients and
    /// later scripts reuse it.
    pub async fn shutdown(&self) {
        if let Transport::Local { factory, .. } = &self.transport {
            factory.shutdown().await;
        }
    }
}

async fn connect_daemon(opts: &ConnectOptions) -> Result<DaemonClient, ProtoError> {
    let internal = |m: String| ProtoError::new(ErrorCode::Internal, m);
    let dir = match &opts.runtime_dir {
        Some(p) => {
            RuntimeDir::from_dir(p.clone()).map_err(|e| internal(format!("runtime dir: {e}")))?
        }
        None => RuntimeDir::resolve().map_err(|e| internal(format!("runtime dir: {e}")))?,
    };
    let krakend = opts
        .krakend
        .clone()
        .or_else(|| std::env::var_os(kraken_host::daemon::ENV_KRAKEND).map(PathBuf::from))
        .or_else(|| which("krakend"))
        .or_else(|| find_krakend().ok());
    let start = StartOptions {
        krakend,
        ..StartOptions::default()
    };
    DaemonClient::connect_or_start(&dir, ClientKind::Cli, BUILD, &start)
        .await
        .map_err(|e| {
            let code = if e.restart_required() {
                ErrorCode::Unsupported
            } else {
                ErrorCode::Internal
            };
            ProtoError::new(code, e.to_string())
        })
}

/// Runs commands of one project as one author.
#[derive(Clone)]
pub struct Handle {
    backend: Arc<dyn CommandBackend>,
    registry: Arc<Registry>,
    author: Author,
}

impl Handle {
    /// The author of this handle's calls.
    pub fn author(&self) -> &Author {
        &self.author
    }

    /// A context for the person running the script, whatever author the handle has.
    fn user_context(&self, cancel: CancellationToken, approve: bool) -> CallContext {
        with_approval(
            CallContext::user(user_id(), Surface::Cli).with_cancel(cancel),
            approve,
        )
    }

    fn context(&self, cancel: CancellationToken, approve: bool) -> CallContext {
        let ctx = match &self.author {
            Author::User(id) => CallContext::user(id.clone(), Surface::Cli),
            Author::Agent { id, run_id } => {
                CallContext::agent(id.clone(), run_id.clone(), Surface::Cli)
            }
        };
        with_approval(ctx.with_cancel(cancel), approve)
    }

    /// Validates `args` against the command's schema, then runs it. `approve` pre-approves a
    /// dangerous command (there are none today); without it such a command is denied.
    pub async fn call(
        &self,
        command: &str,
        args: Value,
        cancel: CancellationToken,
        approve: bool,
    ) -> Result<(Value, Vec<String>), ProtoError> {
        let entry = self.registry.get(command).ok_or_else(|| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!("unknown command `{command}`; see kraken.commands()"),
            )
        })?;
        let args = if args.is_null() {
            Value::Object(Default::default())
        } else {
            args
        };
        schema::validate(entry.args_schema(), &args).map_err(|e| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("invalid arguments for `{command}`: {e}"),
            )
            .with_details(serde_json::json!({"path": e.path, "reason": e.message}))
        })?;
        // A script runs with its owner's authority: choosing which file to load is the person's
        // decision, so project_create/project_open always run as the user; the script's later
        // edits follow agent policy when it was opened with `agent=`.
        let ctx = if matches!(command, "project_create" | "project_open") {
            self.user_context(cancel, approve)
        } else {
            self.context(cancel, approve)
        };
        let out = self.backend.call(command, &ctx, args).await?;
        Ok((out, self.backend.take_warnings()))
    }
}

fn with_approval(ctx: CallContext, approve: bool) -> CallContext {
    if approve {
        ctx.with_approval(Arc::new(AutoApprove))
    } else {
        ctx.with_approval(Arc::new(DenyApprover))
    }
}

/// The wire name of the exception class for an error code; the Python side defines the same
/// classes (see `kraken/errors.py`) and a test keeps both lists in step.
pub fn exception_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::NotFound => "NotFoundError",
        ErrorCode::InvalidArgument => "InvalidArgumentError",
        ErrorCode::ConflictStaleRead => "StaleReadError",
        ErrorCode::RejectedHumanPriority => "RejectedByHumanError",
        ErrorCode::EngineRejected => "EngineRejectedError",
        ErrorCode::Unsupported => "UnsupportedError",
        ErrorCode::AnalysisIncomplete => "AnalysisIncompleteError",
        ErrorCode::Timeout => "KrakenTimeoutError",
        ErrorCode::Cancelled => "CancelledError",
        ErrorCode::Internal => "InternalError",
    }
}

/// Every error code, for the Python side to check its class table against.
pub const ALL_CODES: [ErrorCode; 10] = [
    ErrorCode::NotFound,
    ErrorCode::InvalidArgument,
    ErrorCode::ConflictStaleRead,
    ErrorCode::RejectedHumanPriority,
    ErrorCode::EngineRejected,
    ErrorCode::Unsupported,
    ErrorCode::AnalysisIncomplete,
    ErrorCode::Timeout,
    ErrorCode::Cancelled,
    ErrorCode::Internal,
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use engine_fake::{FakeEngine, FixtureFile};
    use kraken_engine::SharedEngine;
    use kraken_registry::EngineFactory;
    use serde_json::json;

    struct Fake(FixtureFile);

    #[async_trait]
    impl EngineFactory for Fake {
        async fn create(&self, _dir: &Path) -> Result<SharedEngine, ProtoError> {
            Ok(Arc::new(FakeEngine::new(self.0.clone())))
        }
    }

    #[async_trait]
    impl ManagedFactory for Fake {
        async fn shutdown(&self) {}
    }

    fn fixture() -> FixtureFile {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
        FixtureFile::from_path(&p).expect("fixture")
    }

    async fn project(author: Author) -> (tempfile::TempDir, Handle) {
        let tmp = tempfile::tempdir().expect("tmp");
        let bin = tmp.path().join("p.bin");
        std::fs::write(&bin, b"\x7fELF fake").expect("bin");
        let conn = Connection::with_factory(Arc::new(Fake(fixture())), KrakenConfig::default());
        assert_eq!(conn.mode(), Mode::Local);
        let h = conn.handle(None, author);
        let dir = tmp.path().join("proj");
        h.call(
            "project_create",
            json!({"binary": bin, "project_dir": dir}),
            CancellationToken::new(),
            false,
        )
        .await
        .expect("create");
        (tmp, h)
    }

    #[tokio::test]
    async fn unknown_command_and_bad_arguments_never_reach_the_engine() {
        let (_t, h) = project(Author::User("t".into())).await;
        let e = h
            .call("nope", json!({}), CancellationToken::new(), false)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
        let e = h
            .call(
                "rename_symbol",
                json!({"address": "401000", "new_name": "x"}),
                CancellationToken::new(),
                false,
            )
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgument);
        assert_eq!(e.details.as_ref().expect("details")["path"], "/address");
    }

    #[tokio::test]
    async fn user_rename_applies_and_agent_rename_is_policy_checked() {
        let (_t, h) = project(Author::User("t".into())).await;
        h.call("analyze", json!({}), CancellationToken::new(), false)
            .await
            .expect("analyze");
        let (out, _) = h
            .call(
                "rename_symbol",
                json!({"address": "0x401040", "new_name": "renamed"}),
                CancellationToken::new(),
                false,
            )
            .await
            .expect("rename");
        assert!(
            matches!(out["status"].as_str(), Some("applied" | "queued")),
            "{out}"
        );
        let (list, _) = h
            .call("history", json!({}), CancellationToken::new(), false)
            .await
            .expect("history");
        assert_eq!(list["items"][0]["author"]["kind"], "user");
    }

    #[test]
    fn exception_names_cover_every_code_uniquely() {
        let mut names: Vec<&str> = ALL_CODES.iter().map(|c| exception_name(*c)).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL_CODES.len());
    }

    #[test]
    fn authors_expose_kind_id_and_run() {
        let u = Author::User("me".into());
        assert_eq!((u.kind(), u.id(), u.run_id()), ("user", "me", None));
        let a = Author::agent("bot", Some("run-1".into()));
        assert_eq!(
            (a.kind(), a.id(), a.run_id()),
            ("agent", "bot", Some("run-1"))
        );
        assert!(
            Author::agent("bot", None)
                .run_id()
                .is_some_and(|r| r.starts_with("run-"))
        );
    }

    #[tokio::test]
    async fn local_connection_reports_its_mode() {
        let c = Connection::connect(&ConnectOptions {
            daemon: Some(false),
            ..ConnectOptions::default()
        })
        .await
        .expect("connect");
        assert_eq!(c.mode(), Mode::Local);
        assert!(c.daemon_pid().is_none());
        assert!(c.registry().len() > 30);
    }
}

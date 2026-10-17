//! A scripted [`Backend`] for tests of the view-model and the GUI.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::Value;
use tokio::sync::broadcast;

use crate::backend::{Backend, BackendEvent, CommandInfo};

type Handler = Box<dyn FnMut(&Value) -> Result<Value, ProtoError> + Send>;

#[derive(Default)]
struct Script {
    handlers: HashMap<String, Handler>,
    calls: Vec<(String, Value)>,
}

/// Answers calls from per-command handlers and records every call. A command without a handler
/// fails with `unsupported`.
pub struct FakeBackend {
    script: Mutex<Script>,
    selections: Mutex<Vec<Option<Value>>>,
    commands: Vec<CommandInfo>,
    events: broadcast::Sender<BackendEvent>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBackend {
    /// An empty script.
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(64);
        FakeBackend {
            script: Mutex::new(Script::default()),
            selections: Mutex::new(Vec::new()),
            commands: Vec::new(),
            events,
        }
    }

    /// Sets the commands reported by [`Backend::commands`].
    pub fn with_commands(mut self, commands: Vec<CommandInfo>) -> Self {
        self.commands = commands;
        self
    }

    /// Answers `command` by calling `f` with the arguments.
    pub fn on(
        self,
        command: &str,
        f: impl FnMut(&Value) -> Result<Value, ProtoError> + Send + 'static,
    ) -> Self {
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handlers
            .insert(command.to_string(), Box::new(f));
        self
    }

    /// Always answers `command` with `value`.
    pub fn reply(self, command: &str, value: Value) -> Self {
        self.on(command, move |_| Ok(value.clone()))
    }

    /// Always fails `command`.
    pub fn fail(self, command: &str, code: ErrorCode, message: &str) -> Self {
        let message = message.to_string();
        self.on(command, move |_| {
            Err(ProtoError::new(code, message.clone()))
        })
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<(String, Value)> {
        self.script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clone()
    }

    /// Arguments of every call to `command`.
    pub fn calls_to(&self, command: &str) -> Vec<Value> {
        self.calls()
            .into_iter()
            .filter(|(c, _)| c == command)
            .map(|(_, a)| a)
            .collect()
    }

    /// Every selection the view-model published, oldest first.
    pub fn selections(&self) -> Vec<Option<Value>> {
        self.selections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Sends a backend event to subscribers.
    pub fn emit(&self, ev: BackendEvent) {
        let _ = self.events.send(ev);
    }

    /// Wraps the backend for sharing.
    pub fn shared(self) -> Arc<FakeBackend> {
        Arc::new(self)
    }
}

#[async_trait]
impl Backend for FakeBackend {
    async fn call(&self, command: &str, args: Value) -> Result<Value, ProtoError> {
        let mut s = self.script.lock().unwrap_or_else(PoisonError::into_inner);
        s.calls.push((command.to_string(), args.clone()));
        match s.handlers.get_mut(command) {
            Some(h) => h(&args),
            None => Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("no scripted reply for `{command}`"),
            )),
        }
    }

    async fn publish_selection(&self, selection: Option<Value>) -> Result<(), ProtoError> {
        self.selections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(selection);
        Ok(())
    }

    fn commands(&self) -> Vec<CommandInfo> {
        self.commands.clone()
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.events.subscribe()
    }
}

/// The `kraken-fake-acp-agent` binary, for tests that need a terminal agent to talk to. Cargo
/// builds a package's binaries only for that package's own tests, so this builds it (a no-op when
/// it is up to date) and looks it up next to the running test binary.
pub fn fake_agent() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let exe = std::env::current_exe().expect("test exe");
        let profile_dir = exe
            .parent()
            .and_then(Path::parent)
            .expect("target profile dir")
            .to_path_buf();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let mut cmd = Command::new(cargo);
        cmd.args([
            "build",
            "-q",
            "-p",
            "kraken-acp",
            "--bin",
            "kraken-fake-acp-agent",
        ]);
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            cmd.arg("--release");
        }
        cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
        let status = cmd.status().expect("run cargo build");
        assert!(status.success(), "building the fake ACP agent failed");
        let bin = profile_dir.join(format!(
            "kraken-fake-acp-agent{}",
            std::env::consts::EXE_SUFFIX
        ));
        assert!(bin.is_file(), "missing {}", bin.display());
        bin
    })
    .clone()
}

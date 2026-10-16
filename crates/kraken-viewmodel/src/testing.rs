//! A scripted [`Backend`] for tests of the view-model and the GUI.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

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

    fn commands(&self) -> Vec<CommandInfo> {
        self.commands.clone()
    }

    fn events(&self) -> broadcast::Receiver<BackendEvent> {
        self.events.subscribe()
    }
}

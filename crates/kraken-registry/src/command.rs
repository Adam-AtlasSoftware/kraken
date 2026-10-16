//! The [`Command`] trait and the type-erased [`Registry`].

use std::collections::BTreeMap;

use async_trait::async_trait;
use kraken_engine::Cap;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::{ApprovalDecision, ApprovalRequest, CallContext};
use crate::session::Session;

/// How a command behaves (decision 37).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    /// Reads state; no side effects.
    Query,
    /// A transactional edit logged under the caller's author and run.
    Mutation,
    /// Starts long work and returns a job id; poll with `job_status` / `job_await`.
    Job,
    /// Produces a stream of events.
    Stream,
}

/// Who may run a command without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Read-only.
    Safe,
    /// Changes the project.
    Mutating,
    /// Always asks the [`ApprovalRequester`](crate::ApprovalRequester) first.
    Dangerous,
}

/// Static description of a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    /// snake_case command name, unique in a registry.
    pub name: String,
    /// One-line summary for listings and help.
    pub summary: String,
    /// Long documentation (markdown allowed).
    pub doc: String,
    /// Command kind.
    pub kind: CommandKind,
    /// Permission class.
    pub permission: Permission,
    /// Engine capabilities the command needs; surfaces hide it when the engine lacks one.
    pub needs: Vec<Cap>,
}

impl CommandSpec {
    /// A spec with an empty long doc and no capability needs.
    pub fn new(
        name: &str,
        summary: &str,
        kind: CommandKind,
        permission: Permission,
    ) -> CommandSpec {
        CommandSpec {
            name: name.to_string(),
            summary: summary.to_string(),
            doc: String::new(),
            kind,
            permission,
            needs: Vec::new(),
        }
    }

    /// Sets the long documentation.
    pub fn doc(mut self, doc: &str) -> Self {
        self.doc = doc.to_string();
        self
    }

    /// Sets the engine capabilities the command needs.
    pub fn needs(mut self, needs: &[Cap]) -> Self {
        self.needs = needs.to_vec();
        self
    }
}

/// One operation. Implementors are usually unit structs.
///
/// `Args` should be a flat struct with simple field types (strings, integers, booleans, `Hex64`
/// addresses, enums) whose fields carry doc comments: surfaces turn the JSON Schema into CLI
/// flags and MCP tool schemas.
#[async_trait]
pub trait Command: Send + Sync + 'static {
    /// Arguments, deserialized from JSON.
    type Args: DeserializeOwned + JsonSchema + Send;
    /// Result, serialized to JSON.
    type Output: Serialize + JsonSchema;

    /// Static description.
    fn spec() -> CommandSpec;

    /// Runs the command.
    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: Self::Args,
    ) -> Result<Self::Output, ProtoError>;
}

#[async_trait]
trait Erased: Send + Sync {
    async fn call(&self, s: &Session, ctx: &CallContext, args: Value) -> Result<Value, ProtoError>;
}

struct Typed<C>(C);

#[async_trait]
impl<C: Command> Erased for Typed<C> {
    async fn call(&self, s: &Session, ctx: &CallContext, args: Value) -> Result<Value, ProtoError> {
        let args: C::Args = serde_json::from_value(args).map_err(|e| {
            ProtoError::new(ErrorCode::InvalidArgument, format!("bad arguments: {e}"))
        })?;
        let out = self.0.run(s, ctx, args).await?;
        serde_json::to_value(out).map_err(|e| {
            ProtoError::new(ErrorCode::Internal, format!("cannot serialize output: {e}"))
        })
    }
}

fn schema_of<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::SchemaGenerator::default().into_root_schema_for::<T>())
        .unwrap_or(Value::Null)
}

/// A registered command with its schemas; see [`Entry::call_json`].
pub struct Entry {
    spec: CommandSpec,
    args_schema: Value,
    output_schema: Value,
    handler: Box<dyn Erased>,
}

impl Entry {
    /// The command's static description.
    pub fn spec(&self) -> &CommandSpec {
        &self.spec
    }

    /// JSON Schema of the arguments object.
    pub fn args_schema(&self) -> &Value {
        &self.args_schema
    }

    /// JSON Schema of the result.
    pub fn output_schema(&self) -> &Value {
        &self.output_schema
    }

    /// Whether the session's engine (if a project is open) has every capability the command needs.
    pub fn available(&self, s: &Session) -> bool {
        match s.engine() {
            Ok(engine) => {
                let caps = engine.capabilities();
                self.spec.needs.iter().all(|c| caps.has(*c))
            }
            Err(_) => true,
        }
    }

    /// Runs the command with JSON arguments (`null` means no arguments).
    ///
    /// Order: cancelled check, argument shape is left to the command, engine capability check,
    /// approval for dangerous commands, then `run`. Errors are [`ProtoError`]s; a denied approval
    /// is `unsupported` with `details.approval = "denied"`.
    pub async fn call_json(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: Value,
    ) -> Result<Value, ProtoError> {
        if ctx.cancel.is_cancelled() {
            return Err(ProtoError::new(ErrorCode::Cancelled, "call cancelled"));
        }
        let args = if args.is_null() {
            Value::Object(Default::default())
        } else {
            args
        };
        if !self.available(s) {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "`{}` needs an engine capability this engine lacks",
                    self.spec.name
                ),
            ));
        }
        if self.spec.permission == Permission::Dangerous {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: self.spec.name.clone(),
                    summary: self.spec.summary.clone(),
                    args: args.clone(),
                    author: ctx.author.clone(),
                    surface: ctx.surface,
                })
                .await;
            if let ApprovalDecision::Deny { reason } = decision {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!("approval denied: {reason}"),
                )
                .with_details(serde_json::json!({ "approval": "denied" })));
            }
        }
        self.handler.call(s, ctx, args).await.map_err(|mut e| {
            // Engine reasons can quote binary-derived text.
            e.message = kraken_proto::sanitize(&e.message);
            e
        })
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("spec", &self.spec)
            .finish_non_exhaustive()
    }
}

/// A set of commands keyed by name.
#[derive(Debug, Default)]
pub struct Registry {
    entries: BTreeMap<String, Entry>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Registry {
        Registry::default()
    }

    /// The registry with every 0.1a command.
    pub fn standard() -> Registry {
        let mut r = Registry::new();
        crate::commands::register_all(&mut r);
        r
    }

    /// Adds a command; returns true when it replaced one of the same name.
    pub fn register<C: Command>(&mut self, command: C) -> bool {
        let spec = C::spec();
        let entry = Entry {
            args_schema: schema_of::<C::Args>(),
            output_schema: schema_of::<C::Output>(),
            handler: Box::new(Typed(command)),
            spec,
        };
        self.entries
            .insert(entry.spec.name.clone(), entry)
            .is_some()
    }

    /// The command named `name`.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    /// All commands, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// Number of commands.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no command is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks `name` up and runs it; an unknown name is `not_found`.
    pub async fn call_json(
        &self,
        name: &str,
        s: &Session,
        ctx: &CallContext,
        args: Value,
    ) -> Result<Value, ProtoError> {
        match self.get(name) {
            Some(e) => e.call_json(s, ctx, args).await,
            None => Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("unknown command `{name}`"),
            )),
        }
    }
}

//! `local_model_list`, `local_model_devices`, `local_model_status`, `local_model_start`,
//! `local_model_hold`, `local_model_release` and `local_model_stop`: the models KRAKEN serves on
//! this computer.
//!
//! The work is done by the [`ServingBackend`] the surface attaches: `krakend` (where the holder
//! of a model is the caller's connection, released when it ends), or the manager of the calling
//! process when there is no daemon. The per-run key of a server is never part of an output.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::infer::{DeviceInfo, DeviceRef, LocalEngine, ModelState, ModelStats};
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

/// Status of every local model (`ServingApi::models`).
pub const METHOD_MODELS: &str = "infer_models";
/// The cards of this computer.
pub const METHOD_DEVICES: &str = "infer_devices";
/// Holds a model for the caller, starting it when needed.
pub const METHOD_HOLD: &str = "infer_hold";
/// Gives up the caller's hold.
pub const METHOD_RELEASE: &str = "infer_release";
/// Starts a model by hand; it runs until stopped.
pub const METHOD_START: &str = "infer_model_start";
/// Stops a model whoever holds it.
pub const METHOD_STOP: &str = "infer_model_stop";
/// Log lines of a model.
pub const METHOD_LOGS: &str = "infer_model_logs";

/// The serving service behind the `local_model_*` commands, as JSON calls with the method names
/// above (the same ones `krakend` speaks). Provided by `kraken-host`.
#[async_trait]
pub trait ServingBackend: Send + Sync + std::fmt::Debug {
    /// Runs one serving method for the caller.
    async fn call(&self, method: &str, params: Value) -> Result<Value, ProtoError>;
}

impl Session {
    /// The attached serving service.
    pub fn serving(&self) -> Result<&Arc<dyn ServingBackend>, ProtoError> {
        self.serving_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "local model serving is not attached to this session; use the kraken CLI, krakend or the GUI",
            )
        })
    }
}

async fn ask<T: serde::de::DeserializeOwned>(
    s: &Session,
    method: &str,
    params: Value,
) -> Result<T, ProtoError> {
    let v = s.serving()?.call(method, params).await?;
    serde_json::from_value(v).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("unexpected reply from the serving service: {e}"),
        )
    })
}

/// One local model as shown.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ServedModelView {
    /// The model's id (what `local { model = "<id>" }` names).
    pub id: String,
    /// Name for people.
    pub name: String,
    /// The serving program.
    #[serde(default)]
    pub engine: Option<LocalEngine>,
    /// Where it is in its life.
    pub state: ModelState,
    /// OpenAI-compatible address while it runs.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Model name to put in chat requests.
    #[serde(default)]
    pub served_model: Option<String>,
    /// Process id.
    #[serde(default)]
    pub pid: Option<u32>,
    /// Load progress 0..1 when known.
    #[serde(default)]
    pub load_fraction: Option<f32>,
    /// Seconds since the start.
    #[serde(default)]
    pub uptime_secs: Option<u64>,
    /// Callers holding it.
    #[serde(default)]
    pub holders: usize,
    /// Started by hand: runs until stopped.
    #[serde(default)]
    pub pinned: bool,
    /// Nobody holds it any more: seconds until it stops.
    #[serde(default)]
    pub stops_in_secs: Option<u64>,
    /// Why it was not started automatically (it would not fit), in plain words.
    #[serde(default)]
    pub notice: Option<String>,
    /// Memory warnings of the latest start.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The cards it runs on (empty: the processor).
    #[serde(default)]
    pub devices: Vec<DeviceRef>,
    /// Live figures while it runs.
    #[serde(default)]
    pub stats: Option<ModelStats>,
    /// Used by the assistant or by rewriting.
    #[serde(default)]
    pub role_assigned: bool,
    /// Served automatically when KRAKEN opens.
    #[serde(default)]
    pub autostart: bool,
}

/// Result of `local_model_list`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelListOut {
    /// The models set up, in the configuration's order, then manual starts.
    pub models: Vec<ServedModelView>,
    /// Seconds a model keeps running after its last holder goes.
    pub grace_secs: u64,
}

/// Arguments of `local_model_list`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

/// Lists the local models and their state.
pub struct LocalModelList;

#[async_trait]
impl Command for LocalModelList {
    type Args = NoArgs;
    type Output = LocalModelListOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_list",
            "List the models served on this computer and their state",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Returns every model set up to run on this computer: id, state (stopped, loading, \
             ready, failed), address while running, who holds it, cards, memory and speed. The \
             run-time key of a server is not part of the answer.\n\
             Example: local_model_list {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<LocalModelListOut, ProtoError> {
        ask(s, METHOD_MODELS, Value::Null).await
    }
}

/// Result of `local_model_devices`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelDevicesOut {
    /// Every graphics card found, with memory and whether a model can use it.
    pub devices: Vec<DeviceInfo>,
}

/// Lists the cards of this computer.
pub struct LocalModelDevices;

#[async_trait]
impl Command for LocalModelDevices {
    type Args = NoArgs;
    type Output = LocalModelDevicesOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_devices",
            "List the graphics cards a local model could run on",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Returns each graphics card with its vendor, name, video memory (total and used) and \
             state: usable, broken, or not supported yet (Intel cards, NPUs). Models run on the \
             processor when no card is usable.\n\
             Example: local_model_devices {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<LocalModelDevicesOut, ProtoError> {
        ask(s, METHOD_DEVICES, Value::Null).await
    }
}

/// Arguments naming one model.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalModelArgs {
    /// The model's id from `local_model_list`.
    pub model: String,
}

/// Result of `local_model_status`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelStatusOut {
    /// The model.
    pub model: ServedModelView,
    /// The last lines of its log, oldest first.
    pub log_tail: Vec<String>,
}

const STATUS_LOG_LINES: usize = 10;

/// One model's state with the tail of its log.
pub struct LocalModelStatus;

#[async_trait]
impl Command for LocalModelStatus {
    type Args = LocalModelArgs;
    type Output = LocalModelStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_status",
            "Show one local model's state, memory, speed and recent log",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "State of one model from `local_model_list` plus the last lines of its log, which \
             say why a start failed. Use it to follow a model that is loading.\n\
             Example: local_model_status {\"model\": \"qwen3-8b-q4_k_m\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: LocalModelArgs,
    ) -> Result<LocalModelStatusOut, ProtoError> {
        let all: LocalModelListOut = ask(s, METHOD_MODELS, Value::Null).await?;
        let model = all
            .models
            .into_iter()
            .find(|m| m.id == args.model)
            .ok_or_else(|| no_such_model(&args.model))?;
        let logs: Value = ask(
            s,
            METHOD_LOGS,
            json!({"model": args.model, "limit": STATUS_LOG_LINES}),
        )
        .await
        .unwrap_or(Value::Null);
        let log_tail = logs["lines"]
            .as_array()
            .map(|l| {
                l.iter()
                    .filter_map(|e| e["text"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(LocalModelStatusOut { model, log_tail })
    }
}

fn no_such_model(id: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::NotFound,
        format!(
            "there is no local model called `{id}`; `local_model_list` shows the ones you have"
        ),
    )
}

/// Arguments of `local_model_start` and `local_model_hold`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalModelStartArgs {
    /// The model's id from `local_model_list`.
    pub model: String,
    /// Start even though the model does not seem to fit in memory.
    #[serde(default)]
    pub force: bool,
    /// Run on the processor only, whatever cards the model is set to use.
    #[serde(default)]
    pub cpu: bool,
}

fn start_params(a: &LocalModelStartArgs) -> Value {
    json!({"model": a.model, "force": a.force, "cpu": a.cpu})
}

/// Starts a model and keeps it running until stopped.
pub struct LocalModelStart;

#[async_trait]
impl Command for LocalModelStart {
    type Args = LocalModelStartArgs;
    type Output = ServedModelView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_start",
            "Start a local model and keep it running until stopped",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Starts the model and returns while it loads (follow it with `local_model_status`). \
             It keeps running until `local_model_stop`, even when nobody uses it. If it would \
             not fit in memory the answer says so and offers the choices: stop another model, \
             `cpu: true` to run on the processor, or `force: true` to start anyway. It runs a \
             program and takes memory, so the assistant only gets it when a task allows it.\n\
             Example: local_model_start {\"model\": \"qwen3-8b-q4_k_m\", \"cpu\": true}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: LocalModelStartArgs,
    ) -> Result<ServedModelView, ProtoError> {
        ask(s, METHOD_START, start_params(&args)).await
    }
}

/// Holds a model for the caller, starting it when needed.
pub struct LocalModelHold;

#[async_trait]
impl Command for LocalModelHold {
    type Args = LocalModelStartArgs;
    type Output = ServedModelView;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_hold",
            "Keep a local model running for as long as this connection lasts",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Starts the model if it is not running and keeps it for this connection: when the \
             connection ends (or after `local_model_release`) and nobody else holds it, it stops \
             after a grace period. Same memory choices as `local_model_start`.\n\
             Example: local_model_hold {\"model\": \"qwen3-8b-q4_k_m\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: LocalModelStartArgs,
    ) -> Result<ServedModelView, ProtoError> {
        ask(s, METHOD_HOLD, start_params(&args)).await
    }
}

/// Result of `local_model_release`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelReleaseOut {
    /// False when the caller did not hold the model.
    pub released: bool,
}

/// Gives up the caller's hold of a model.
pub struct LocalModelRelease;

#[async_trait]
impl Command for LocalModelRelease {
    type Args = LocalModelArgs;
    type Output = LocalModelReleaseOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_release",
            "Give up this connection's hold of a local model",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Removes the hold made by `local_model_hold`. The model stops after the grace period \
             when nobody else holds it and it was not started by hand.\n\
             Example: local_model_release {\"model\": \"qwen3-8b-q4_k_m\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: LocalModelArgs,
    ) -> Result<LocalModelReleaseOut, ProtoError> {
        ask(s, METHOD_RELEASE, json!({"model": args.model})).await
    }
}

/// Result of `local_model_stop`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelStopOut {
    /// False when the model was not running.
    pub stopped: bool,
}

/// Stops a model whoever holds it.
pub struct LocalModelStop;

#[async_trait]
impl Command for LocalModelStop {
    type Args = LocalModelArgs;
    type Output = LocalModelStopOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_stop",
            "Stop a local model now, whoever is using it",
            CommandKind::Query,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Stops the model's server at once and frees its memory. Anything using it (the \
             assistant, rewriting) starts it again on its next request if the model is assigned \
             to it.\n\
             Example: local_model_stop {\"model\": \"qwen3-8b-q4_k_m\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: LocalModelArgs,
    ) -> Result<LocalModelStopOut, ProtoError> {
        ask(s, METHOD_STOP, json!({"model": args.model})).await
    }
}

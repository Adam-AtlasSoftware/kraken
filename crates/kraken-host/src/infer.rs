//! Local inference hosting shared by `krakend`, the CLI and the GUI (decisions 21, 30, 69).
//!
//! An [`InferManager`] runs the local models: supervised `llama-server` or Strata processes (or an
//! engine described by a manifest) on 127.0.0.1, several at once, each on its own port with its
//! own per-run key. In `krakend` the daemon's idle monitor counts them as work
//! ([`InferManager::loaded_models`]); with `--no-daemon` the CLI or GUI process owns them.
//!
//! The models set up in `[[local_models]]` run while someone holds them; see [`serving`] for the
//! holds, the grace period, the fit check and autostart ([`ServingApi`]).
//!
//! [`InferApi`] is the older interface of five operations on one model (`list`, `start`,
//! `status`, `stop`, `logs`), kept for the CLI and GUI until they move to [`ServingApi`]: `start`
//! runs an engine with settings as a manual start ([`MANUAL_MODEL_ID`]); `status`, `stop` and
//! `logs` act on that manual start unless it was stopped, else on the model the assistant uses
//! when it runs, else on the latest one started. The manager implements it directly and [`DaemonClient`] implements it over the daemon's `infer_*`
//! RPC methods, so the CLI and the GUI do not care where the model runs.
//!
//! Before a start the memory budget is checked: the machine's RAM minus the JVM heaps of the open
//! Ghidra sessions ([`ghidra_reservations`]) minus the model. A tight fit becomes a warning in
//! the reply and the log, an impossible one is refused with a plain message.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};

use async_trait::async_trait;
use kraken_infer::budget::GIB;
use kraken_infer::llama::LlamaServerBackend;
use kraken_infer::{
    BackendCapabilities, BackendRegistry, GpuApi, InferError, InferenceBackend, LogStream,
    MemoryBudget, Phase, Reservation,
};
use kraken_proto::{ErrorCode, LocalEngine, LocalModel, MultiGpuMode, ProtoError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::daemon::DaemonClient;
use crate::factory::ManagedFactory;
use crate::llama_setup::{self, InstalledLlama, LlamaLayout};

pub mod serving;

pub use serving::{
    AutostartReport, DevicesReply, HeldBy, Holder, MANUAL_MODEL_ID, METHOD_INFER_AUTOSTART,
    METHOD_INFER_DEVICES, METHOD_INFER_HOLD, METHOD_INFER_MODEL_LOGS, METHOD_INFER_MODEL_START,
    METHOD_INFER_MODEL_STOP, METHOD_INFER_MODELS, METHOD_INFER_RELEASE, ModelLogsParams,
    ModelParams, ModelStatus, ModelsReply, ReleaseReply, ServingApi, ServingBridge, ServingConfig,
    SkippedModel, StartOptions, hold_role_models, serve_serving_rpc,
};
use serving::{ConfigFn, DevicesFn, LlamaDevicesFn, Slot, State};

/// Lists the backends this computer can run.
pub const METHOD_INFER_LIST: &str = "infer_list";
/// Starts a backend with settings.
pub const METHOD_INFER_START: &str = "infer_start";
/// State of the running model.
pub const METHOD_INFER_STATUS: &str = "infer_status";
/// Stops the running model.
pub const METHOD_INFER_STOP: &str = "infer_stop";
/// Recent log lines of the model process.
pub const METHOD_INFER_LOGS: &str = "infer_logs";

/// Environment variable naming the directory of engine manifests (`*.toml`).
pub const ENV_INFER_MANIFESTS: &str = "KRAKEN_INFER_MANIFESTS";

/// Id of the built-in llama.cpp backend.
pub const LLAMA_ID: &str = "llama-server";

/// JSON-Schema key that marks a string setting as a file path.
pub const WIDGET_KEY: &str = "x-kraken-widget";

const MIB: u64 = 1024 * 1024;
const BUDGET_WARNING_PREFIX: &str = "budget warning: ";
const DEFAULT_LOG_LIMIT: usize = 500;
const MAX_LOG_LIMIT: usize = 5000;

// ---------------------------------------------------------------------------------------------
// Wire types

/// The platform the daemon runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// `linux`, `macos` or `windows`.
    pub os: String,
    /// `x86_64` or `aarch64`.
    pub arch: String,
}

/// One engine that can be started on this computer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendInfo {
    /// Id to pass to `infer_start`.
    pub id: String,
    /// Name for people.
    pub display_name: String,
    /// What the engine needs and offers.
    pub capabilities: BackendCapabilities,
    /// JSON Schema of the settings (rendered generically as a form).
    pub settings_schema: Value,
    /// True for engines that ship with KRAKEN, false for ones loaded from a manifest.
    pub builtin: bool,
    /// Whether the engine's program is in place. `None` when KRAKEN cannot tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed: Option<bool>,
    /// What to do when it is not installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_hint: Option<String>,
}

/// Memory as the budget sees it, in bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// RAM of the machine (0 when it could not be read).
    pub total_ram: u64,
    /// JVM heaps of the open Ghidra sessions.
    pub ghidra_reserved: u64,
    /// RAM that is left for a model.
    pub available_ram: u64,
}

/// The llama.cpp build KRAKEN installed, and what it could install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlamaInfo {
    /// The pinned release tag `kraken infer setup llama` installs.
    pub pinned_tag: String,
    /// Build variants available for this platform (the first is the default).
    pub variants: Vec<String>,
    /// The installed build.
    pub installed: Option<InstalledLlama>,
}

/// Reply of `infer_list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferListReply {
    /// Where this runs.
    pub platform: PlatformInfo,
    /// Engines that support this platform.
    pub backends: Vec<BackendInfo>,
    /// Memory budget.
    pub memory: MemoryInfo,
    /// llama.cpp provisioning state.
    pub llama: LlamaInfo,
    /// Where engine manifests are looked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifests_dir: Option<PathBuf>,
    /// Problems the person should hear about (a broken manifest, memory not readable).
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Params of `infer_start`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartParams {
    /// Engine id from `infer_list`.
    pub backend: String,
    /// Settings object following the engine's schema; `null` means none.
    #[serde(default)]
    pub settings: Value,
}

/// Reply of `infer_start`: where the server is. The model may still be loading; follow it with
/// `infer_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StartReply {
    /// Engine id.
    pub backend: String,
    /// OpenAI-compatible base URL (`http://127.0.0.1:<port>/v1`).
    pub base_url: String,
    /// Model name to put in chat requests.
    pub model: Option<String>,
    /// Port on 127.0.0.1.
    pub port: u16,
    /// Process id.
    pub pid: Option<u32>,
    /// Per-run bearer token the server requires; send it as the provider's API key. Only
    /// authenticated clients of this user's daemon ever see it; never log it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Memory warnings.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Reply of `infer_status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReply {
    /// True while a model process is loading or serving (or being restarted).
    pub running: bool,
    /// `none`, `starting`, `loading`, `ready`, `restarting`, `failed` or `stopped`.
    pub phase: String,
    /// Engine id of the latest start.
    pub backend: Option<String>,
    /// Model name.
    pub model: Option<String>,
    /// Base URL of the latest start.
    pub base_url: Option<String>,
    /// Load progress 0..1 when the engine reports it.
    pub fraction: Option<f32>,
    /// Latest status line.
    pub message: String,
    /// Automatic restarts so far.
    pub restarts: u32,
    /// Process id.
    pub pid: Option<u32>,
    /// Seconds since the start.
    pub uptime_secs: Option<u64>,
    /// Per-run bearer token the server requires (see [`StartReply::api_key`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

impl StatusReply {
    fn none() -> Self {
        StatusReply {
            running: false,
            phase: "none".into(),
            backend: None,
            model: None,
            base_url: None,
            fraction: None,
            message: "no model has been started".into(),
            restarts: 0,
            pid: None,
            uptime_secs: None,
            api_key: None,
        }
    }

    /// True when the server answers requests.
    pub fn is_ready(&self) -> bool {
        self.phase == "ready"
    }

    /// True when the model will not come up without a new start.
    pub fn is_failed(&self) -> bool {
        self.phase == "failed"
    }
}

/// Reply of `infer_stop`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopReply {
    /// False when nothing was running.
    pub stopped: bool,
}

/// Params of `infer_logs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsParams {
    /// Only lines after this sequence number.
    #[serde(default)]
    pub after_seq: Option<u64>,
    /// At most this many (the latest ones); default 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Increasing line number.
    pub seq: u64,
    /// `stdout`, `stderr` or `system`.
    pub stream: String,
    /// The line.
    pub text: String,
}

/// Reply of `infer_logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsReply {
    /// Lines, oldest first.
    pub lines: Vec<LogEntry>,
    /// Sequence number of the newest line ever written (pass it as `after_seq` to follow).
    pub last_seq: u64,
}

/// The five operations, wherever the model runs.
#[async_trait]
pub trait InferApi: Send + Sync {
    /// Engines, memory and llama.cpp state.
    async fn list(&self) -> Result<InferListReply, ProtoError>;
    /// Starts `backend`. Returns once the process is spawned.
    async fn start(&self, backend: &str, settings: Value) -> Result<StartReply, ProtoError>;
    /// State of the running model.
    async fn status(&self) -> Result<StatusReply, ProtoError>;
    /// Stops the model.
    async fn stop(&self) -> Result<StopReply, ProtoError>;
    /// Log lines.
    async fn logs(&self, params: LogsParams) -> Result<LogsReply, ProtoError>;
}

/// Serves one `infer_*` RPC method with `api`; `None` when `method` is not one of them.
pub async fn serve_rpc(
    api: &dyn InferApi,
    method: &str,
    params: Value,
) -> Option<Result<Value, ProtoError>> {
    fn parse<T: serde::de::DeserializeOwned + Default>(params: Value) -> Result<T, ProtoError> {
        if params.is_null() {
            return Ok(T::default());
        }
        serde_json::from_value(params)
            .map_err(|e| ProtoError::new(ErrorCode::InvalidArgument, format!("bad params: {e}")))
    }
    fn encode<T: Serialize>(v: T) -> Result<Value, ProtoError> {
        serde_json::to_value(v)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot encode reply: {e}")))
    }
    Some(match method {
        METHOD_INFER_LIST => api.list().await.and_then(encode),
        METHOD_INFER_START => match serde_json::from_value::<StartParams>(params) {
            Ok(p) => api.start(&p.backend, p.settings).await.and_then(encode),
            Err(e) => Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("bad params: {e}"),
            )),
        },
        METHOD_INFER_STATUS => api.status().await.and_then(encode),
        METHOD_INFER_STOP => api.stop().await.and_then(encode),
        METHOD_INFER_LOGS => match parse::<LogsParams>(params) {
            Ok(p) => api.logs(p).await.and_then(encode),
            Err(e) => Err(e),
        },
        _ => return None,
    })
}

fn decode<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, ProtoError> {
    serde_json::from_value(v).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("malformed reply from krakend: {e}"),
        )
    })
}

#[async_trait]
impl InferApi for DaemonClient {
    async fn list(&self) -> Result<InferListReply, ProtoError> {
        decode(self.rpc(METHOD_INFER_LIST, Value::Null).await?)
    }

    async fn start(&self, backend: &str, settings: Value) -> Result<StartReply, ProtoError> {
        let p = json!({"backend": backend, "settings": settings});
        decode(self.rpc(METHOD_INFER_START, p).await?)
    }

    async fn status(&self) -> Result<StatusReply, ProtoError> {
        decode(self.rpc(METHOD_INFER_STATUS, Value::Null).await?)
    }

    async fn stop(&self) -> Result<StopReply, ProtoError> {
        decode(self.rpc(METHOD_INFER_STOP, Value::Null).await?)
    }

    async fn logs(&self, params: LogsParams) -> Result<LogsReply, ProtoError> {
        let p = serde_json::to_value(params)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        decode(self.rpc(METHOD_INFER_LOGS, p).await?)
    }
}

// ---------------------------------------------------------------------------------------------
// Settings from the command line

/// Turns `key=value` pairs into a settings object using the engine's schema: integers, numbers
/// and booleans are parsed, JSON is accepted for arrays and objects, everything else is text.
/// A relative value of a `file-path` setting is made absolute against `cwd`, because the daemon
/// does not share the caller's working directory.
pub fn settings_from_pairs(
    schema: &Value,
    pairs: &[String],
    cwd: Option<&Path>,
) -> Result<Value, String> {
    let props = schema.get("properties").and_then(Value::as_object);
    let mut out = Map::new();
    for pair in pairs {
        let (key, raw) = pair
            .split_once('=')
            .ok_or_else(|| format!("`{pair}` is not key=value"))?;
        let key = key.trim();
        let prop = props.and_then(|p| p.get(key));
        if let Some(p) = props
            && prop.is_none()
        {
            let known: Vec<&str> = p.keys().map(String::as_str).collect();
            return Err(format!(
                "this engine has no setting `{key}`; its settings are: {}",
                known.join(", ")
            ));
        }
        let ty = prop
            .and_then(|p| p.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("string");
        let mut v = match ty {
            "integer" => json!(
                raw.trim()
                    .parse::<i64>()
                    .map_err(|_| format!("`{key}` needs a whole number, not `{raw}`"))?
            ),
            "number" => json!(
                raw.trim()
                    .parse::<f64>()
                    .map_err(|_| format!("`{key}` needs a number, not `{raw}`"))?
            ),
            "boolean" => match raw.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => Value::Bool(true),
                "false" | "no" | "off" | "0" => Value::Bool(false),
                _ => return Err(format!("`{key}` needs true or false, not `{raw}`")),
            },
            "array" | "object" => {
                serde_json::from_str(raw).map_err(|e| format!("`{key}` needs JSON ({e}): {raw}"))?
            }
            _ => Value::String(raw.to_string()),
        };
        if is_path_prop(prop)
            && let (Value::String(s), Some(cwd)) = (&mut v, cwd)
            && !s.is_empty()
            && Path::new(s.as_str()).is_relative()
        {
            *s = cwd.join(s.as_str()).to_string_lossy().into_owned();
        }
        out.insert(key.to_string(), v);
    }
    Ok(Value::Object(out))
}

fn is_path_prop(prop: Option<&Value>) -> bool {
    prop.and_then(|p| p.get(WIDGET_KEY))
        .and_then(Value::as_str)
        .is_some_and(|w| w == "file-path")
}

/// The name of the setting that holds the model file (`model_path` for llama.cpp, `model` for
/// most manifests).
pub fn model_setting(schema: &Value) -> Option<&'static str> {
    let props = schema.get("properties")?.as_object()?;
    ["model_path", "model"]
        .into_iter()
        .find(|k| props.contains_key(*k))
}

// ---------------------------------------------------------------------------------------------
// Memory

/// One reservation per open Ghidra sidecar, from its JVM heap.
pub fn ghidra_reservations(factory: &dyn ManagedFactory) -> Vec<Reservation> {
    factory
        .diagnostics()
        .into_iter()
        .filter_map(|d| {
            let mb = d.value.get("heap_mb").and_then(Value::as_u64)?;
            let name = d
                .engine_dir
                .parent()
                .and_then(Path::file_name)
                .map_or_else(|| "a project".into(), |n| n.to_string_lossy().into_owned());
            Some(Reservation::new(
                format!("Ghidra heap of {name}"),
                mb * MIB,
                0,
            ))
        })
        .collect()
}

/// What tells one version of a file from another without reading it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    modified: Option<std::time::SystemTime>,
    len: u64,
    #[cfg(unix)]
    inode: (u64, u64),
}

impl FileStamp {
    /// `None` when the file is missing or cannot be read.
    fn of(path: &Path) -> Option<Self> {
        let md = std::fs::metadata(path).ok()?;
        Some(FileStamp {
            modified: md.modified().ok(),
            len: md.len(),
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                (md.dev(), md.ino())
            },
        })
    }
}

/// A value read from a file, read again only when the file's time, size or inode changed (a
/// save that replaces the file changes the inode even within one timestamp tick).
struct FileCache<T> {
    slot: Mutex<Option<(Option<FileStamp>, T)>>,
}

impl<T> Default for FileCache<T> {
    fn default() -> Self {
        FileCache {
            slot: Mutex::new(None),
        }
    }
}

impl<T: Clone> FileCache<T> {
    fn get(&self, path: &Path, read: impl FnOnce(&Path) -> T) -> T {
        let stamp = FileStamp::of(path);
        let mut slot = lock(&self.slot);
        if let Some((s, v)) = slot.as_ref()
            && *s == stamp
        {
            return v.clone();
        }
        let v = read(path);
        *slot = Some((stamp, v.clone()));
        v
    }
}

type ReservationFn = Arc<dyn Fn() -> Vec<Reservation> + Send + Sync>;
type MemoryFn = Box<dyn Fn() -> Option<MemoryBudget> + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// The manager

/// Owns the local models.
pub struct InferManager {
    registry: BackendRegistry,
    manifest_ids: Vec<String>,
    manifests_dir: Option<PathBuf>,
    load_warnings: Vec<String>,
    llama: Option<LlamaLayout>,
    path_var: Option<OsString>,
    reservations: RwLock<Option<ReservationFn>>,
    memory: MemoryFn,
    /// Serializes starts and stops.
    op: tokio::sync::Mutex<()>,
    state: Mutex<State>,
    config: ConfigFn,
    devices: DevicesFn,
    /// `llama-server --list-devices` of a binary (Vulkan builds are told their cards by name).
    llama_devices: LlamaDevicesFn,
    clock: RwLock<Arc<dyn kraken_ipc::Clock>>,
    stats: OnceLock<Arc<kraken_infer::stats::StatsSampler>>,
    llama_binary: Option<PathBuf>,
    strata_manifest: Option<PathBuf>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Starting => "starting",
        Phase::Loading => "loading",
        Phase::Ready => "ready",
        Phase::Restarting => "restarting",
        Phase::Failed => "failed",
        Phase::Stopped => "stopped",
    }
}

fn stream_name(s: LogStream) -> &'static str {
    match s {
        LogStream::Stdout => "stdout",
        LogStream::Stderr => "stderr",
        LogStream::System => "system",
    }
}

/// An [`InferError`] in words for the person, with the right code.
pub fn infer_error(e: InferError) -> ProtoError {
    match e {
        InferError::Settings(m) => ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("these settings cannot be used: {m}"),
        ),
        InferError::Manifest(m) => ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("the engine manifest is wrong: {m}"),
        ),
        InferError::BinaryNotFound(what) => ProtoError::new(
            ErrorCode::NotFound,
            format!(
                "the engine program was not found: {what}. For llama.cpp run \
                 `kraken infer setup llama`, or install llama-server and put it on PATH"
            ),
        ),
        InferError::Overcommit(m) => ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "there is not enough memory to load this model: {m}. Close a project, pick a \
                 smaller model or quantization, or keep more of it on disk"
            ),
        )
        .with_details(json!({"reason": "memory_budget"})),
        InferError::Spawn(e) => ProtoError::new(
            ErrorCode::Internal,
            format!("the engine could not be started: {e}"),
        ),
        InferError::NotReady(m) => ProtoError::new(ErrorCode::Timeout, m),
        InferError::Unsupported(m) => ProtoError::new(ErrorCode::Unsupported, m),
        InferError::Io(e) => ProtoError::new(ErrorCode::Internal, e.to_string()),
    }
}

impl InferManager {
    /// A manager over `registry` with the system memory budget and no llama.cpp install.
    pub fn with_registry(registry: BackendRegistry) -> Self {
        InferManager {
            registry,
            manifest_ids: Vec::new(),
            manifests_dir: None,
            load_warnings: Vec::new(),
            llama: None,
            path_var: std::env::var_os("PATH"),
            reservations: RwLock::new(None),
            memory: Box::new(|| MemoryBudget::from_system().ok()),
            op: tokio::sync::Mutex::new(()),
            state: Mutex::new(State::default()),
            config: Arc::new(ServingConfig::default),
            devices: Arc::new(Vec::new),
            llama_devices: Arc::new(|bin: &Path| {
                kraken_infer::hardware::list_llama_devices(
                    &kraken_infer::SystemProbe,
                    &bin.to_string_lossy(),
                )
            }),
            clock: RwLock::new(Arc::new(kraken_ipc::SystemClock::new())),
            stats: OnceLock::new(),
            llama_binary: None,
            strata_manifest: None,
        }
    }

    /// The real thing: llama-server plus the manifests of `$KRAKEN_INFER_MANIFESTS`, else
    /// `<data dir>/infer/manifests`.
    pub fn from_env() -> Self {
        Self::from_env_with(&|k| std::env::var_os(k))
    }

    /// [`from_env`](Self::from_env) with an injectable environment.
    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let data = llama_setup::data_dir_with(env);
        let mut registry = BackendRegistry::new();
        let mut llama = LlamaServerBackend::new();
        if let Some(d) = &data {
            llama = llama.with_data_dir(d.clone());
        }
        registry.register(Arc::new(llama));

        let dir = env(ENV_INFER_MANIFESTS)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| data.as_ref().map(|d| d.join("infer/manifests")));
        let mut manifest_ids = Vec::new();
        let mut load_warnings = Vec::new();
        if let Some(dir) = dir.as_deref().filter(|d| d.is_dir()) {
            match registry.load_manifest_dir(dir) {
                Ok(ids) => manifest_ids = ids,
                Err(e) => load_warnings.push(format!(
                    "the engine manifests in {} could not be loaded: {e}",
                    dir.display()
                )),
            }
        }
        let mut m = Self::with_registry(registry);
        m.manifest_ids = manifest_ids;
        m.manifests_dir = dir;
        m.load_warnings = load_warnings;
        m.llama = data.as_deref().map(LlamaLayout::in_data_dir);
        m.path_var = env("PATH");
        m.strata_manifest = data
            .as_deref()
            .map(|d| crate::strata_setup::StrataLayout::in_data_dir(d).backend_manifest());
        if let Some(path) = crate::KrakenConfig::default_path_with(env) {
            // Status polls and the maintenance tick ask often; the file is parsed again only
            // when it changed.
            let cache = FileCache::default();
            m.config = Arc::new(move || {
                cache.get(&path, |p| {
                    let cfg = crate::KrakenConfig::from_file(p).unwrap_or_else(|e| {
                        tracing::warn!(error = %e, "cannot read the configuration");
                        crate::KrakenConfig::default()
                    });
                    ServingConfig::from_config(&cfg)
                })
            });
        }
        let llama = m.llama.clone();
        let path_var = m.path_var.clone();
        m.devices = Arc::new(move || {
            let bin = llama
                .as_ref()
                .and_then(LlamaLayout::installed)
                .map(|i| i.binary)
                .or_else(|| kraken_infer::llama::discover_binary(None, path_var.as_deref(), None));
            let bin = bin.map(|b| b.to_string_lossy().into_owned());
            kraken_infer::hardware::detect_devices(&kraken_infer::SystemProbe, bin.as_deref())
        });
        m
    }

    /// Reads the models, roles and grace period from `f` instead of `config.toml`.
    #[must_use]
    pub fn with_config_source(
        mut self,
        f: impl Fn() -> ServingConfig + Send + Sync + 'static,
    ) -> Self {
        self.config = Arc::new(f);
        self
    }

    /// A fixed serving configuration (tests).
    #[must_use]
    pub fn with_serving_config(self, cfg: ServingConfig) -> Self {
        self.with_config_source(move || cfg.clone())
    }

    /// Replaces the card detection (tests, or a host that knows its cards).
    #[must_use]
    pub fn with_devices(
        mut self,
        f: impl Fn() -> Vec<kraken_proto::infer::DeviceInfo> + Send + Sync + 'static,
    ) -> Self {
        self.devices = Arc::new(f);
        self
    }

    /// Replaces `llama-server --list-devices` (tests).
    #[must_use]
    pub fn with_llama_devices(
        mut self,
        f: impl Fn(&Path) -> Vec<kraken_infer::hardware::LlamaDevice> + Send + Sync + 'static,
    ) -> Self {
        self.llama_devices = Arc::new(f);
        self
    }

    /// Runs this program as `llama-server` for the models set up (tests use the fake server).
    #[must_use]
    pub fn with_llama_binary(mut self, path: PathBuf) -> Self {
        self.llama_binary = Some(path);
        self
    }

    /// Where the Strata engine manifest (`backend.toml`) is.
    #[must_use]
    pub fn with_strata_manifest(mut self, path: PathBuf) -> Self {
        self.strata_manifest = Some(path);
        self
    }

    /// Uses `sampler` for the live figures instead of one reading the real machine.
    #[must_use]
    pub fn with_stats(self, sampler: Arc<kraken_infer::stats::StatsSampler>) -> Self {
        let _ = self.stats.set(sampler);
        self
    }

    /// Sets the time source of the grace period (the daemon passes its own clock).
    pub fn set_clock(&self, clock: Arc<dyn kraken_ipc::Clock>) {
        *self.clock.write().unwrap_or_else(PoisonError::into_inner) = clock;
    }

    /// Replaces the memory source (tests, or a machine whose VRAM is known).
    #[must_use]
    pub fn with_memory(
        mut self,
        f: impl Fn() -> Option<MemoryBudget> + Send + Sync + 'static,
    ) -> Self {
        self.memory = Box::new(f);
        self
    }

    /// A fixed memory size.
    #[must_use]
    pub fn with_total_memory(self, ram: u64, vram: Option<u64>) -> Self {
        self.with_memory(move || Some(MemoryBudget::new(ram, vram)))
    }

    /// Where llama.cpp builds are looked for.
    #[must_use]
    pub fn with_llama_layout(mut self, layout: LlamaLayout) -> Self {
        self.llama = Some(layout);
        self
    }

    /// Declares which registered ids came from manifests (for the listing).
    #[must_use]
    pub fn with_manifest_ids(mut self, ids: Vec<String>) -> Self {
        self.manifest_ids = ids;
        self
    }

    /// Sets what is subtracted from the budget before a model is checked (the Ghidra heaps).
    pub fn set_reservations(&self, f: impl Fn() -> Vec<Reservation> + Send + Sync + 'static) {
        *self
            .reservations
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(f));
    }

    fn extra_reservations(&self) -> Vec<Reservation> {
        let f = self
            .reservations
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        f.map(|f| f()).unwrap_or_default()
    }

    fn budget(&self) -> (MemoryBudget, Vec<Reservation>, Option<String>) {
        let extra = self.extra_reservations();
        let (mut b, note) = match (self.memory)() {
            Some(b) => (b, None),
            None => (
                MemoryBudget::new(u64::MAX / 4, None),
                Some(
                    "KRAKEN could not read how much memory this computer has, so the memory \
                     check is off"
                        .to_string(),
                ),
            ),
        };
        for r in &extra {
            b.reserve(r.clone());
        }
        (b, extra, note)
    }

    /// Number of loaded models, as the daemon's idle monitor counts them: the processes that are
    /// loading, serving or restarting.
    pub fn loaded_models(&self) -> usize {
        lock(&self.state)
            .slots
            .values()
            .filter(|s| s.live())
            .count()
    }

    /// Stops every model (for owners shutting down).
    pub async fn shutdown(&self) {
        let ids: Vec<String> = lock(&self.state).slots.keys().cloned().collect();
        for id in ids {
            self.stop_model(&id).await;
        }
    }

    /// The model the old single-model methods act on: the one started from an engine
    /// (`infer_start`, [`MANUAL_MODEL_ID`]) unless it was stopped, else the assistant's (or
    /// rewriting's) model when it was started, else the latest one started.
    fn default_slot(&self) -> Option<Arc<Slot>> {
        if let Some(manual) = lock(&self.state).slots.get(MANUAL_MODEL_ID).cloned()
            && manual.state() != kraken_proto::ModelState::Stopped
        {
            return Some(manual);
        }
        let roles = self.serving_config().roles;
        let st = lock(&self.state);
        roles
            .iter()
            .find_map(|r| st.slots.get(r))
            .or_else(|| st.order.last().and_then(|id| st.slots.get(id)))
            .cloned()
    }

    fn llama_installed(&self) -> Option<InstalledLlama> {
        self.llama.as_ref().and_then(LlamaLayout::installed)
    }

    fn llama_on_path(&self) -> bool {
        kraken_infer::llama::discover_binary(None, self.path_var.as_deref(), None).is_some()
    }

    fn info_for(&self, b: &Arc<dyn InferenceBackend>) -> BackendInfo {
        let mut caps = b.capabilities();
        let (mut installed, mut hint) = (None, None);
        if b.id() == LLAMA_ID {
            let inst = self.llama_installed();
            if let Some(i) = &inst {
                for r in llama_setup::pinned_releases() {
                    if r.variant == i.variant && !caps.gpu_apis.contains(&r.gpu_api) {
                        caps.gpu_apis.push(r.gpu_api);
                    }
                }
                caps.detected_version.get_or_insert_with(|| i.tag.clone());
            }
            let found = inst.is_some() || self.llama_on_path();
            installed = Some(found);
            if !found {
                hint = Some(
                    "Run `kraken infer setup llama` to download the official llama.cpp build, \
                     or install llama-server yourself and put it on PATH."
                        .to_string(),
                );
            }
        }
        BackendInfo {
            id: b.id().to_string(),
            display_name: b.display_name().to_string(),
            capabilities: caps,
            settings_schema: b.settings_schema(),
            builtin: !self.manifest_ids.iter().any(|m| m == b.id()),
            installed,
            setup_hint: hint,
        }
    }

    fn status_of(&self) -> StatusReply {
        let Some(a) = self.default_slot() else {
            return StatusReply::none();
        };
        let run = a.run();
        let p = run.status();
        let (phase, message) = match a.state() {
            kraken_proto::ModelState::Failed { message } => ("failed", message),
            _ => (phase_name(p.phase), p.message),
        };
        StatusReply {
            running: a.live(),
            phase: phase.into(),
            backend: Some(a.backend.clone()),
            model: run.model().map(str::to_string),
            base_url: Some(run.base_url()),
            fraction: p.fraction,
            message,
            restarts: p.restarts,
            pid: p.pid,
            uptime_secs: Some(a.started.elapsed().as_secs()),
            api_key: run.api_key().map(str::to_string),
        }
    }

    fn check_paths(schema: &Value, settings: &Value) -> Result<(), ProtoError> {
        let (Some(props), Some(obj)) = (
            schema.get("properties").and_then(Value::as_object),
            settings.as_object(),
        ) else {
            return Ok(());
        };
        for (k, v) in obj {
            if is_path_prop(props.get(k))
                && let Some(s) = v.as_str()
                && !s.is_empty()
                && Path::new(s).is_relative()
            {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "`{k}` must be an absolute path (the daemon does not share your \
                         working directory): {s}"
                    ),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl InferApi for InferManager {
    async fn list(&self) -> Result<InferListReply, ProtoError> {
        let (budget, extra, note) = self.budget();
        let ghidra: u64 = extra.iter().map(|r| r.ram).sum();
        let total = if note.is_some() {
            0
        } else {
            budget.total_ram()
        };
        let backends = self
            .registry
            .available()
            .iter()
            .map(|b| self.info_for(b))
            .collect();
        let mut warnings = self.load_warnings.clone();
        warnings.extend(note);
        Ok(InferListReply {
            platform: PlatformInfo {
                os: std::env::consts::OS.into(),
                arch: std::env::consts::ARCH.into(),
            },
            backends,
            memory: MemoryInfo {
                total_ram: total,
                ghidra_reserved: ghidra,
                available_ram: total.saturating_sub(ghidra),
            },
            llama: LlamaInfo {
                pinned_tag: llama_setup::LLAMA_TAG.into(),
                variants: llama_setup::current_releases()
                    .into_iter()
                    .map(|r| r.variant)
                    .collect(),
                installed: self.llama_installed(),
            },
            manifests_dir: self.manifests_dir.clone(),
            warnings,
        })
    }

    async fn start(&self, backend: &str, settings: Value) -> Result<StartReply, ProtoError> {
        let b = self.registry.get(backend).ok_or_else(|| {
            let known: Vec<String> = self
                .registry
                .available()
                .iter()
                .map(|b| b.id().to_string())
                .collect();
            ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "no engine called `{backend}`; this computer can run: {}",
                    known.join(", ")
                ),
            )
        })?;
        if !b.capabilities().supports_current_platform() {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "`{backend}` does not run on {} {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH
                ),
            ));
        }
        let mut settings = match settings {
            Value::Null => Value::Object(Map::new()),
            v @ Value::Object(_) => v,
            _ => {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "settings must be an object",
                ));
            }
        };
        Self::check_paths(&b.settings_schema(), &settings)?;
        if backend == LLAMA_ID
            && let Some(i) = self.llama_installed()
            && let Some(o) = settings.as_object_mut()
            && !o.contains_key("binary_path")
        {
            o.insert("binary_path".into(), json!(i.binary));
        }

        let _op = self.op.lock().await;
        let current = lock(&self.state).slots.get(MANUAL_MODEL_ID).cloned();
        if let Some(a) = current {
            if a.live() {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "a model is already running ({}); stop it first",
                        a.run().model().unwrap_or(&a.backend)
                    ),
                ));
            }
            a.stop().await;
        }

        let (budget, _extra, note) = self.budget();
        let running = b.start(settings, &budget).await.map_err(infer_error)?;
        let mut warnings: Vec<String> = note.into_iter().collect();
        warnings.extend(running.logs().into_iter().filter_map(|l| {
            (l.stream == LogStream::System)
                .then(|| {
                    l.text
                        .strip_prefix(BUDGET_WARNING_PREFIX)
                        .map(str::to_string)
                })
                .flatten()
        }));
        let reply = StartReply {
            backend: backend.to_string(),
            base_url: running.base_url(),
            model: running.model().map(str::to_string),
            port: running.port(),
            pid: running.status().pid,
            api_key: running.api_key().map(str::to_string),
            warnings: warnings.clone(),
        };
        let slot = Arc::new(Slot::new_manual(backend, running, warnings));
        let mut st = lock(&self.state);
        st.insert(slot);
        st.add_hold(MANUAL_MODEL_ID, Holder::Pinned);
        Ok(reply)
    }

    async fn status(&self) -> Result<StatusReply, ProtoError> {
        Ok(self.status_of())
    }

    async fn stop(&self) -> Result<StopReply, ProtoError> {
        let Some(a) = self.default_slot() else {
            return Ok(StopReply { stopped: false });
        };
        Ok(StopReply {
            stopped: self.stop_model(&a.id).await,
        })
    }

    async fn logs(&self, params: LogsParams) -> Result<LogsReply, ProtoError> {
        let slot = self.default_slot();
        Ok(serving::logs_of(
            slot.as_deref(),
            params.after_seq,
            params.limit,
        ))
    }
}

/// Environment variable `kraken infer start --use` points the provider's key at.
pub const LOCAL_KEY_ENV: &str = "KRAKEN_LOCAL_API_KEY";

/// The `[provider]` table that makes the assistant talk to a local server. When the server
/// requires a per-run key, the table names [`LOCAL_KEY_ENV`] rather than embedding the key.
pub fn provider_table(
    base_url: &str,
    model: Option<&str>,
    supports_tools: bool,
    needs_key: bool,
) -> Value {
    let mut t = json!({
        "kind": "openai_compatible",
        "base_url": base_url,
        "model": model.unwrap_or("local"),
        "supports_tools": supports_tools,
    });
    if needs_key {
        t["api_key"] = json!({ "env": LOCAL_KEY_ENV });
    }
    t
}

/// The `[provider]` table of a model served from this computer: `local { model = id }`, resolved
/// to the running server when a request is made.
pub fn local_provider_table(model_id: &str) -> Value {
    json!({ "kind": "local", "model": model_id })
}

/// The model id of `table` when KRAKEN itself wrote it for a server on this computer, `None`
/// for anything else (a server the person runs, a cloud provider).
///
/// Written by KRAKEN means a loopback `openai_compatible` table that either names
/// [`LOCAL_KEY_ENV`] as its key (what [`provider_table`] writes) or has exactly the shape the
/// old model setup wrote (no key, [`LOCAL_BASE_URL`](crate::local_models::LOCAL_BASE_URL)), and
/// whose model KRAKEN knows (`known`: a downloaded catalog model or a model already set up). A
/// person's own `llama-server` on the same address keeps its table, key and `supports_tools`.
fn kraken_written_model(table: &Value, known: &dyn Fn(&str) -> bool) -> Option<String> {
    if table["kind"] != "openai_compatible" {
        return None;
    }
    let url = table["base_url"].as_str()?;
    let parsed = reqwest::Url::parse(url).ok()?;
    // An IPv6 host comes back in brackets (`[::1]`).
    let host = parsed
        .host_str()?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let marker = table["api_key"]["env"] == LOCAL_KEY_ENV;
    let setup_shape = table.get("api_key").is_none() && url == crate::local_models::LOCAL_BASE_URL;
    let id = table["model"].as_str()?;
    (loopback && (marker || setup_shape) && known(id)).then(|| id.to_string())
}

/// A model entry with the defaults: the processor or the best card, served automatically.
pub fn new_local_model(id: &str, engine: LocalEngine, model_path: PathBuf) -> LocalModel {
    LocalModel {
        id: id.to_string(),
        name: id.to_string(),
        engine,
        model_path,
        devices: Vec::new(),
        cpu_only: false,
        multi_gpu: if engine == LocalEngine::Strata {
            MultiGpuMode::Auto
        } else {
            MultiGpuMode::default()
        },
        shares: None,
        main_device: None,
        context_size: None,
        autostart: true,
        extra: None,
    }
}

/// Adds `model` to `[[local_models]]` of the file at `path` (replacing the entry with its id)
/// and, with `assistant`, points `[provider]` at it. The rest of the file is kept.
pub fn upsert_local_model(path: &Path, model: LocalModel, assistant: bool) -> Result<(), String> {
    let mut cfg = crate::KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
    if assistant {
        cfg.provider = Some(local_provider_table(&model.id));
    }
    match cfg.local_models.iter_mut().find(|m| m.id == model.id) {
        Some(existing) => *existing = model,
        None => cfg.local_models.push(model),
    }
    cfg.save(path).map_err(|e| e.to_string())
}

/// Where the catalog model `id` is on disk, when it is a catalog model.
pub fn catalog_model_path(id: &str, env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let entry = kraken_infer::model_catalog()
        .into_iter()
        .find(|m| m.id == id)?;
    Some(kraken_infer::models_dir_with(env)?.join(entry.file))
}

/// Migrates the configuration file at `path` (see [`migrate_local_provider`]) and writes it back
/// when something changed. Returns the number of tables converted; a file that cannot be read
/// or written is left alone.
pub fn migrate_config_file(path: &Path, env: &dyn Fn(&str) -> Option<OsString>) -> usize {
    let Ok(mut cfg) = crate::KrakenConfig::from_file(path) else {
        return 0;
    };
    // Only a catalog model that was downloaded counts as one KRAKEN set up.
    let n = migrate_local_provider(&mut cfg, &|id| {
        catalog_model_path(id, env).filter(|p| p.is_file())
    });
    if n > 0
        && let Err(e) = cfg.save(path)
    {
        tracing::warn!(error = %e, "cannot write the migrated local model configuration");
        return 0;
    }
    n
}

/// Turns the `[provider]` and `[rewrite]` tables KRAKEN wrote for a local model into a
/// [`LocalModel`] in `local_models` plus a `local { model = id }` provider. Tables for other
/// servers (see [`kraken_written_model`]) are left alone, a model already listed is not added
/// twice, and running it again changes nothing. `locate` finds the model file of an id; a model
/// it does not find and that is not set up yet is not KRAKEN's, so its table stays. Returns how
/// many tables were converted.
pub fn migrate_local_provider(
    cfg: &mut crate::KrakenConfig,
    locate: &dyn Fn(&str) -> Option<PathBuf>,
) -> usize {
    let mut converted = 0;
    for slot in [&mut cfg.provider, &mut cfg.rewrite] {
        let models = &cfg.local_models;
        let known = |id: &str| models.iter().any(|m| m.id == id) || locate(id).is_some();
        let Some(table) = slot.as_ref() else {
            continue;
        };
        let Some(id) = kraken_written_model(table, &known) else {
            continue;
        };
        let engine = if table["engine"] == "strata" {
            LocalEngine::Strata
        } else {
            LocalEngine::Llama
        };
        *slot = Some(local_provider_table(&id));
        converted += 1;
        if !cfg.local_models.iter().any(|m| m.id == id) {
            let path = locate(&id).unwrap_or_default();
            cfg.local_models.push(new_local_model(&id, engine, path));
        }
    }
    converted
}

/// Makes `table` the `[provider]` table of the configuration file at `path`, keeping the other
/// settings (comments in the file are not kept). A missing file is created.
pub fn write_provider(path: &Path, table: Value) -> Result<(), String> {
    let mut cfg = crate::KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
    cfg.provider = Some(table);
    cfg.save(path).map_err(|e| e.to_string())
}

/// Memory in GiB for messages.
pub fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

/// The backend's reservation shown for a model file: what loading `bytes` of weights asks of RAM
/// (the file plus 10% for the context), for hints before a start.
pub fn model_ram_hint(bytes: u64) -> u64 {
    bytes + bytes / 10
}

/// Returns the GPU API names of a capability set, for display.
pub fn gpu_names(apis: &[GpuApi]) -> Vec<&'static str> {
    apis.iter()
        .map(|a| match a {
            GpuApi::Cpu => "CPU",
            GpuApi::Cuda => "CUDA",
            GpuApi::Rocm => "ROCm",
            GpuApi::Vulkan => "Vulkan",
            GpuApi::Metal => "Metal",
        })
        .collect()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod serving_tests;

#[cfg(test)]
mod migrate_tests {
    use super::*;
    use crate::KrakenConfig;

    #[test]
    fn a_local_provider_becomes_a_model_and_a_local_provider() {
        let mut cfg = KrakenConfig::from_toml("per_run_cap = 3\n").expect("config");
        cfg.provider = Some(provider_table(
            "http://127.0.0.1:8080/v1",
            Some("qwen"),
            true,
            true,
        ));
        cfg.rewrite = Some(provider_table(
            "http://127.0.0.1:8080/v1",
            Some("qwen"),
            true,
            false,
        ));
        let n =
            migrate_local_provider(&mut cfg, &|id| Some(PathBuf::from(format!("/m/{id}.gguf"))));
        assert_eq!(n, 2);
        assert_eq!(cfg.local_models.len(), 1);
        assert_eq!(
            cfg.local_models[0].model_path,
            PathBuf::from("/m/qwen.gguf")
        );
        assert_eq!(cfg.provider, Some(local_provider_table("qwen")));
        assert_eq!(cfg.rewrite, Some(local_provider_table("qwen")));
        assert_eq!(migrate_local_provider(&mut cfg, &|_| None), 0);
        assert_eq!(cfg.local_models.len(), 1);
        let again = KrakenConfig::from_toml(&cfg.to_toml().expect("toml")).expect("reparse");
        assert_eq!(again, cfg);
    }

    #[test]
    fn loading_the_configuration_migrates_the_file_once() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "per_run_cap = 3\n\n[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://127.0.0.1:8080/v1\"\nmodel = \"qwen3-8b-q4_k_m\"\nsupports_tools = true\n",
        )
        .expect("write");
        // The model the old setup downloaded.
        let data = dir.path().join("data");
        let file = catalog_model_path("qwen3-8b-q4_k_m", &|k| {
            (k == "XDG_DATA_HOME").then(|| data.clone().into_os_string())
        })
        .expect("catalog model");
        std::fs::create_dir_all(file.parent().expect("models dir")).expect("mkdir");
        std::fs::write(&file, b"gguf").expect("model file");
        let env_path = path.clone();
        let env = move |k: &str| match k {
            "KRAKEN_CONFIG" => Some(env_path.clone().into_os_string()),
            "XDG_DATA_HOME" => Some(data.clone().into_os_string()),
            _ => None,
        };
        let cfg = crate::KrakenConfig::load_with(&env).expect("loads");
        assert_eq!(cfg.provider, Some(local_provider_table("qwen3-8b-q4_k_m")));
        assert_eq!(cfg.local_models.len(), 1);
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("kind = \"local\""), "{text}");
        assert!(text.contains("per_run_cap = 3"), "{text}");
        // Nothing left to convert: the second load leaves the file as it is.
        assert_eq!(migrate_config_file(&path, &env), 0);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), text);
    }

    #[test]
    fn a_server_the_person_runs_on_the_default_address_is_left_alone() {
        // Their own llama-server on 127.0.0.1:8080 with their own key and tool setting.
        let own = json!({
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1:8080/v1",
            "model": "my-model",
            "api_key": "sk-mine",
            "supports_tools": false,
        });
        let mut cfg = KrakenConfig {
            provider: Some(own.clone()),
            ..Default::default()
        };
        assert_eq!(
            migrate_local_provider(&mut cfg, &|_| Some(PathBuf::from("/m/x.gguf"))),
            0
        );
        assert_eq!(cfg.provider, Some(own));
        // The old setup's shape, but a model KRAKEN never downloaded or set up.
        let unknown = json!({
            "kind": "openai_compatible",
            "base_url": "http://127.0.0.1:8080/v1",
            "model": "my-model",
            "supports_tools": true,
        });
        let mut cfg = KrakenConfig {
            provider: Some(unknown.clone()),
            ..Default::default()
        };
        assert_eq!(migrate_local_provider(&mut cfg, &|_| None), 0);
        assert_eq!(cfg.provider, Some(unknown));
        assert!(cfg.local_models.is_empty());
        // KRAKEN's key marker on an IPv6 loopback address with a model already set up.
        let mut cfg = KrakenConfig {
            provider: Some(provider_table(
                "http://[::1]:9000/v1",
                Some("m"),
                true,
                true,
            )),
            local_models: vec![new_local_model("m", LocalEngine::Llama, "/m/m.gguf".into())],
            ..Default::default()
        };
        assert_eq!(migrate_local_provider(&mut cfg, &|_| None), 1);
        assert_eq!(cfg.provider, Some(local_provider_table("m")));
        assert_eq!(cfg.local_models.len(), 1);
    }

    #[test]
    fn the_configuration_is_parsed_again_only_when_the_file_changes() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("config.toml");
        let cache: FileCache<String> = FileCache::default();
        let reads = std::cell::Cell::new(0);
        let read = |p: &Path| {
            reads.set(reads.get() + 1);
            std::fs::read_to_string(p).unwrap_or_default()
        };
        assert_eq!(cache.get(&path, read), "", "a missing file");
        assert_eq!(cache.get(&path, read), "");
        assert_eq!(reads.get(), 1);
        std::fs::write(&path, "a = 1\n").expect("write");
        assert_eq!(cache.get(&path, read), "a = 1\n");
        assert_eq!(cache.get(&path, read), "a = 1\n");
        assert_eq!(reads.get(), 2);
        // A save that replaces the file (as `KrakenConfig::save` does) is seen at once.
        let tmp = dir.path().join("config.toml.new");
        std::fs::write(&tmp, "a = 2\n").expect("write");
        std::fs::rename(&tmp, &path).expect("rename");
        assert_eq!(cache.get(&path, read), "a = 2\n");
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn a_cloud_or_lan_provider_is_left_alone() {
        let mut cfg = KrakenConfig {
            provider: Some(
                json!({"kind":"openai_compatible","base_url":"http://192.168.1.5:8080/v1","model":"m"}),
            ),
            rewrite: Some(json!({"kind":"anthropic","model":"x"})),
            ..Default::default()
        };
        let before = cfg.clone();
        assert_eq!(migrate_local_provider(&mut cfg, &|_| None), 0);
        assert_eq!(cfg, before);
    }
}

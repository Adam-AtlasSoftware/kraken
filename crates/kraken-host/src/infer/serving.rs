//! Several local models at once (plan 20261018-local-serving, T5).
//!
//! Every model set up in `[[local_models]]` gets its own slot in the [`InferManager`]: its own
//! port, per-run key, supervised process and stats. A model runs while someone holds it:
//!
//! - a connection to `krakend` ([`Holder::Connection`]), released when the connection ends;
//! - a manual start ([`Holder::Pinned`]), a sticky hold that only a stop removes;
//! - the process that owns the manager, when there is no daemon ([`Holder::Owner`]).
//!
//! When the last hold goes, the model keeps running for the grace period of
//! `[local_serving] grace_secs` and is then stopped by [`InferManager::tick`]; a new hold before
//! that cancels the stop. Starts are serialized; each one reads the cards' free memory again and
//! counts what the models still loading are about to take. A model that does not fit is refused
//! with the choices the person has (stop another model, run on the processor, start anyway).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_infer::budget::{MemoryPool, footprint};
use kraken_infer::generic::Manifest;
use kraken_infer::launch::launch_spec;
use kraken_infer::port::{generate_api_key, pick_free_port, shows_bind_failure};
use kraken_infer::stats::{StatsKind, StatsSampler, Target};
use kraken_infer::{GpuApi, InferError, LoadProgress, ManagedProcess, Phase, ProcessSpec};
use kraken_infer::{RunningBackend, budget::Fit};
use kraken_ipc::Clock;
use kraken_proto::infer::{DeviceInfo, DeviceRef, LocalEngine, LocalModel, ModelState, ModelStats};
use kraken_proto::{ErrorCode, ProtoError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{InferManager, LLAMA_ID, LogEntry, LogsReply, infer_error, lock, stream_name};
use crate::config::{KrakenConfig, LocalServingSettings};
use crate::daemon::DaemonClient;

/// Status of every local model.
pub const METHOD_INFER_MODELS: &str = "infer_models";
/// The cards (GPUs) of this computer.
pub const METHOD_INFER_DEVICES: &str = "infer_devices";
/// Holds a model for this connection, starting it when needed.
pub const METHOD_INFER_HOLD: &str = "infer_hold";
/// Gives up this connection's hold of a model.
pub const METHOD_INFER_RELEASE: &str = "infer_release";
/// Starts a model by hand: a hold that stays until the model is stopped.
pub const METHOD_INFER_MODEL_START: &str = "infer_model_start";
/// Stops a model whoever holds it.
pub const METHOD_INFER_MODEL_STOP: &str = "infer_model_stop";
/// Holds every model marked "serve automatically" that fits, for this connection.
pub const METHOD_INFER_AUTOSTART: &str = "infer_autostart";
/// Log lines of one model.
pub const METHOD_INFER_MODEL_LOGS: &str = "infer_model_logs";

/// The slot of a model started with the old single-model `infer_start` (an engine and settings
/// rather than a set-up model).
pub const MANUAL_MODEL_ID: &str = "(manual)";

const DEFAULT_CONTEXT: u32 = 8192;
const POLL: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------------------------
// Wire types

/// Who keeps a model running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Holder {
    /// A daemon connection (its server-unique id); released when the connection ends.
    Connection(u64),
    /// A manual start; stays until the model is stopped.
    Pinned,
    /// The process that owns the manager (no daemon).
    Owner,
}

/// How to start a model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartOptions {
    /// Start even though the model does not seem to fit.
    #[serde(default)]
    pub force: bool,
    /// Run on the processor only for this run, whatever the model's card choice.
    #[serde(default)]
    pub cpu: bool,
}

/// Params naming a model, with start options for the methods that start one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelParams {
    /// The model's id (`[[local_models]] id`).
    pub model: String,
    /// See [`StartOptions::force`].
    #[serde(default)]
    pub force: bool,
    /// See [`StartOptions::cpu`].
    #[serde(default)]
    pub cpu: bool,
}

impl ModelParams {
    fn options(&self) -> StartOptions {
        StartOptions {
            force: self.force,
            cpu: self.cpu,
        }
    }
}

/// Params of `infer_model_logs`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelLogsParams {
    /// The model's id.
    pub model: String,
    /// Only lines after this sequence number.
    #[serde(default)]
    pub after_seq: Option<u64>,
    /// At most this many (the latest ones); default 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// One local model as the daemon sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelStatus {
    /// The model's id.
    pub id: String,
    /// Name for people.
    pub name: String,
    /// The serving program; `None` for a manual start of another engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<LocalEngine>,
    /// Where it is in its life.
    pub state: ModelState,
    /// OpenAI-compatible base URL while it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Model name to put in chat requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_model: Option<String>,
    /// Per-run bearer token the server requires. Only the person's own clients see it; never
    /// log it or write it to disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Port on 127.0.0.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Process id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Load progress 0..1 when the engine reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_fraction: Option<f32>,
    /// Automatic restarts after crashes in this run.
    #[serde(default)]
    pub restarts: u32,
    /// Seconds since the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_secs: Option<u64>,
    /// Connections (and the owner) holding it.
    #[serde(default)]
    pub holders: usize,
    /// Started by hand: runs until stopped.
    #[serde(default)]
    pub pinned: bool,
    /// Nobody holds it any more: seconds until it stops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stops_in_secs: Option<u64>,
    /// Why it was not started automatically (it would not fit), in plain words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    /// Memory warnings of the latest start.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// The cards it runs on (empty: the processor).
    #[serde(default)]
    pub devices: Vec<DeviceRef>,
    /// Live figures while it runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<ModelStats>,
    /// Assigned to the assistant (`[provider]`) or rewriting (`[rewrite]`).
    #[serde(default)]
    pub role_assigned: bool,
    /// Serve automatically when KRAKEN opens.
    #[serde(default)]
    pub autostart: bool,
}

impl ModelStatus {
    /// True when the server answers requests.
    pub fn is_ready(&self) -> bool {
        self.state == ModelState::Ready
    }

    /// True while the process is loading or serving.
    pub fn is_running(&self) -> bool {
        matches!(self.state, ModelState::Loading | ModelState::Ready)
    }
}

/// Reply of `infer_models`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelsReply {
    /// The models set up, in the configuration's order, then manual starts.
    pub models: Vec<ModelStatus>,
    /// Seconds a model keeps running after its last hold goes.
    pub grace_secs: u64,
}

/// Reply of `infer_devices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicesReply {
    /// Every card found.
    pub devices: Vec<DeviceInfo>,
}

/// Reply of `infer_release`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReply {
    /// False when this holder did not hold the model.
    pub released: bool,
}

/// A model autostart left alone, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedModel {
    /// The model's id.
    pub model: String,
    /// Why, in plain words.
    pub reason: String,
    /// Machine-readable reason: `no_fit` or `error`.
    pub kind: String,
}

/// Reply of `infer_autostart`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutostartReport {
    /// Held (and started when they were not running), in start order.
    pub started: Vec<String>,
    /// Not started.
    pub skipped: Vec<SkippedModel>,
}

/// What the manager needs from `config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServingConfig {
    /// `[[local_models]]`.
    pub models: Vec<LocalModel>,
    /// Ids of the models a role uses (`[provider]`, then `[rewrite]`, of kind `local`).
    pub roles: Vec<String>,
    /// `[local_serving]`.
    pub serving: LocalServingSettings,
}

impl ServingConfig {
    /// The serving part of a configuration.
    pub fn from_config(cfg: &KrakenConfig) -> Self {
        let mut roles: Vec<String> = Vec::new();
        for t in [&cfg.provider, &cfg.rewrite].into_iter().flatten() {
            if t["kind"] == "local"
                && let Some(id) = t["model"].as_str()
                && !roles.iter().any(|r| r == id)
            {
                roles.push(id.to_string());
            }
        }
        ServingConfig {
            models: cfg.local_models.clone(),
            roles,
            serving: cfg.local_serving.clone(),
        }
    }

    fn model(&self, id: &str) -> Option<&LocalModel> {
        self.models.iter().find(|m| m.id == id)
    }

    /// Autostart order: models a role uses first, then the list order.
    fn autostart_order(&self) -> Vec<&LocalModel> {
        let mut out: Vec<&LocalModel> = self
            .roles
            .iter()
            .filter_map(|r| self.model(r))
            .filter(|m| m.autostart)
            .collect();
        for m in self.models.iter().filter(|m| m.autostart) {
            if !out.iter().any(|o| o.id == m.id) {
                out.push(m);
            }
        }
        out
    }
}

pub(super) type ConfigFn = Arc<dyn Fn() -> ServingConfig + Send + Sync>;
pub(super) type DevicesFn = Arc<dyn Fn() -> Vec<DeviceInfo> + Send + Sync>;
type Respawn = Arc<dyn Fn(u16) -> Result<RunningBackend, InferError> + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// Slots

/// Where a model's memory comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum PoolKey {
    Card(String),
    Ram,
}

fn card_key(uuid: &str, index: u32) -> PoolKey {
    if uuid.is_empty() {
        PoolKey::Card(format!("#{index}"))
    } else {
        PoolKey::Card(uuid.to_string())
    }
}

/// One started model.
pub(super) struct Slot {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) backend: String,
    pub(super) engine: Option<LocalEngine>,
    run: Mutex<Arc<RunningBackend>>,
    pub(super) started: Instant,
    /// What the model takes in each pool, for the starts that come while it loads.
    uses: Vec<(PoolKey, u64)>,
    pub(super) devices: Vec<DeviceRef>,
    pub(super) warnings: Vec<String>,
    failure: Mutex<Option<String>>,
    stopping: std::sync::atomic::AtomicBool,
    watcher: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Slot {
    pub(super) fn new_manual(
        backend: &str,
        running: RunningBackend,
        warnings: Vec<String>,
    ) -> Self {
        Slot {
            id: MANUAL_MODEL_ID.into(),
            name: running.model().unwrap_or(backend).to_string(),
            backend: backend.into(),
            engine: (backend == LLAMA_ID).then_some(LocalEngine::Llama),
            run: Mutex::new(Arc::new(running)),
            started: Instant::now(),
            uses: Vec::new(),
            devices: Vec::new(),
            warnings,
            failure: Mutex::new(None),
            stopping: false.into(),
            watcher: Mutex::new(None),
        }
    }

    pub(super) fn run(&self) -> Arc<RunningBackend> {
        lock(&self.run).clone()
    }

    fn failure(&self) -> Option<String> {
        lock(&self.failure).clone()
    }

    fn fail(&self, msg: String) {
        lock(&self.failure).get_or_insert(msg);
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(super) fn live(&self) -> bool {
        self.failure().is_none()
            && !self.is_stopping()
            && !matches!(self.run().status().phase, Phase::Failed | Phase::Stopped)
    }

    fn loading(&self) -> bool {
        self.live() && self.run().status().phase != Phase::Ready
    }

    pub(super) fn state(&self) -> ModelState {
        if let Some(message) = self.failure() {
            return ModelState::Failed { message };
        }
        let p = self.run().status();
        state_of(&p, self.is_stopping())
    }

    pub(super) async fn stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let watcher = lock(&self.watcher).take();
        if let Some(w) = watcher {
            w.abort();
        }
        self.run().stop().await;
    }
}

fn state_of(p: &LoadProgress, stopping: bool) -> ModelState {
    match p.phase {
        Phase::Ready if stopping => ModelState::Stopping,
        Phase::Ready => ModelState::Ready,
        Phase::Stopped => ModelState::Stopped,
        Phase::Failed => ModelState::Failed {
            message: crash_message(p),
        },
        _ if stopping => ModelState::Stopping,
        _ => ModelState::Loading,
    }
}

fn crash_message(p: &LoadProgress) -> String {
    if p.restarts > 0 {
        format!(
            "The model stopped working and was restarted {} times without success; it is not \
             restarted again. Last message: {}",
            p.restarts, p.message
        )
    } else {
        format!("The model could not be started: {}", p.message)
    }
}

/// Holds and the slots, under one lock.
#[derive(Default)]
pub(super) struct State {
    pub(super) slots: HashMap<String, Arc<Slot>>,
    holds: HashMap<String, HashSet<Holder>>,
    /// When the last hold of a running model went (clock time).
    idle_since: HashMap<String, Duration>,
    /// Why autostart left a model alone.
    notices: HashMap<String, String>,
    /// Why the latest start of a model failed before a process ran.
    errors: HashMap<String, String>,
    /// Start order, latest last.
    pub(super) order: Vec<String>,
}

impl State {
    pub(super) fn insert(&mut self, slot: Arc<Slot>) {
        let id = slot.id.clone();
        self.order.retain(|o| o != &id);
        self.order.push(id.clone());
        self.errors.remove(&id);
        self.slots.insert(id, slot);
    }

    pub(super) fn add_hold(&mut self, id: &str, holder: Holder) {
        self.holds.entry(id.to_string()).or_default().insert(holder);
        self.idle_since.remove(id);
    }

    fn held(&self, id: &str) -> bool {
        self.holds.get(id).is_some_and(|h| !h.is_empty())
    }

    /// Removes `holder`'s hold of `id`; starts the grace period when it was the last one.
    fn remove_hold(&mut self, id: &str, holder: Holder, now: Duration) -> bool {
        let removed = self
            .holds
            .get_mut(id)
            .is_some_and(|set| set.remove(&holder));
        if removed && !self.held(id) && self.slots.get(id).is_some_and(|s| s.live()) {
            self.idle_since.insert(id.to_string(), now);
        }
        removed
    }

    fn clear(&mut self, id: &str) {
        self.holds.remove(id);
        self.idle_since.remove(id);
    }
}

// ---------------------------------------------------------------------------------------------
// The manager's serving API

fn not_found(id: &str, cfg: &ServingConfig) -> ProtoError {
    let known: Vec<&str> = cfg.models.iter().map(|m| m.id.as_str()).collect();
    let tail = if known.is_empty() {
        "no model is set up on this computer yet".to_string()
    } else {
        format!("the models set up are: {}", known.join(", "))
    };
    ProtoError::new(
        ErrorCode::NotFound,
        format!("there is no local model called `{id}`; {tail}"),
    )
    .with_details(json!({"reason": "unknown_model", "model": id}))
}

/// Bytes of a model file, or of every file in a model directory (Strata).
fn path_bytes(p: &Path) -> u64 {
    let Ok(md) = std::fs::metadata(p) else {
        return 0;
    };
    if md.is_file() {
        return md.len();
    }
    std::fs::read_dir(p)
        .map(|d| d.flatten().map(|e| path_bytes(&e.path())).sum())
        .unwrap_or(0)
}

fn gib(b: u64) -> String {
    super::gib(b)
}

/// The cards a model will use: `launch_spec` has already checked them.
fn chosen_cards(model: &LocalModel, devices: &[DeviceInfo], apis: &[GpuApi]) -> Vec<DeviceInfo> {
    if model.cpu_only {
        return Vec::new();
    }
    let refs = if model.devices.is_empty() {
        kraken_infer::hardware::default_devices(model.engine, devices, apis)
    } else {
        model.devices.clone()
    };
    let mut out: Vec<DeviceInfo> = Vec::new();
    for r in refs {
        let found = devices.iter().find(|d| {
            if r.uuid.is_empty() {
                d.index == r.index && d.vendor == r.vendor
            } else {
                d.uuid == r.uuid
            }
        });
        if let Some(d) = found
            && !out.iter().any(|o| o.uuid == d.uuid && o.index == d.index)
        {
            out.push(d.clone());
        }
    }
    out
}

fn device_ref(d: &DeviceInfo) -> DeviceRef {
    DeviceRef {
        uuid: d.uuid.clone(),
        index: d.index,
        vendor: d.vendor,
    }
}

/// The plan of one start, before anything runs.
struct Prepared {
    model: LocalModel,
    cards: Vec<DeviceInfo>,
    uses: Vec<(PoolKey, u64)>,
    warnings: Vec<String>,
    respawn: Respawn,
    kind: StatsKind,
}

impl InferManager {
    /// The serving part of the configuration, read now.
    pub fn serving_config(&self) -> ServingConfig {
        (self.config)()
    }

    fn now(&self) -> Duration {
        self.clock().now()
    }

    fn clock(&self) -> Arc<dyn Clock> {
        self.clock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The live-figures sampler, created on first use (on the current tokio runtime).
    pub fn stats(&self) -> Arc<StatsSampler> {
        self.stats
            .get_or_init(|| {
                StatsSampler::spawn(
                    Arc::new(kraken_infer::stats::SystemEnv),
                    Duration::from_secs(1),
                )
            })
            .clone()
    }

    /// Every card of this computer, read now.
    pub async fn devices(&self) -> Vec<DeviceInfo> {
        let f = self.devices.clone();
        tokio::task::spawn_blocking(move || f())
            .await
            .unwrap_or_default()
    }

    fn llama_apis(&self) -> Vec<GpuApi> {
        let Some(i) = self.llama_installed() else {
            return Vec::new();
        };
        crate::llama_setup::pinned_releases()
            .into_iter()
            .filter(|r| r.variant == i.variant)
            .map(|r| r.gpu_api)
            .collect()
    }

    fn llama_binary(&self) -> Result<PathBuf, ProtoError> {
        if let Some(b) = &self.llama_binary {
            return Ok(b.clone());
        }
        if let Some(i) = self.llama_installed() {
            return Ok(i.binary);
        }
        kraken_infer::llama::discover_binary(None, self.path_var.as_deref(), None).ok_or_else(
            || {
                infer_error(InferError::BinaryNotFound(
                    "llama-server (not installed by KRAKEN and not on PATH)".into(),
                ))
            },
        )
    }

    fn strata_manifest(&self) -> Result<Manifest, ProtoError> {
        let path = self.strata_manifest.clone().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::NotFound,
                "Strata is not installed; set it up from the model list first",
            )
        })?;
        Manifest::load(&path).map_err(|e| {
            ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "Strata is not installed or its setup is broken ({}): {e}",
                    path.display()
                ),
            )
        })
    }

    /// Works out how to run `model` and whether it fits; nothing is started.
    async fn prepare(
        &self,
        mut model: LocalModel,
        opts: StartOptions,
        st_snapshot: &[Arc<Slot>],
    ) -> Result<Prepared, ProtoError> {
        if opts.cpu {
            if model.engine == LocalEngine::Strata {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    "The Strata engine needs an NVIDIA card; it cannot run on the processor alone.",
                ));
            }
            model.cpu_only = true;
        }
        if model.model_path.as_os_str().is_empty() || !model.model_path.exists() {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "The model file of {} was not found{}. Set the model up again.",
                    model.name,
                    if model.model_path.as_os_str().is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", model.model_path.display())
                    }
                ),
            ));
        }
        let devices = self.devices().await;
        let apis = self.llama_apis();
        // Validates the card choice (a card that is gone, a mode the engine cannot do).
        launch_spec(&model, &devices, &apis, 0).map_err(infer_error)?;
        let cards = chosen_cards(&model, &devices, &apis);

        let need = footprint(
            path_bytes(&model.model_path),
            model.context_size.unwrap_or(DEFAULT_CONTEXT),
        );
        let n = cards.len().max(1) as u64;
        let per_card = match model.multi_gpu {
            kraken_proto::MultiGpuMode::CopyPerCard => need,
            _ => need / n,
        };
        let uses: Vec<(PoolKey, u64)> = if cards.is_empty() {
            vec![(PoolKey::Ram, need)]
        } else {
            cards
                .iter()
                .map(|c| (card_key(&c.uuid, c.index), per_card))
                .collect()
        };

        let mut warnings = Vec::new();
        let pools = self.pools(&cards, st_snapshot, &mut warnings);
        if let Some(pools) = pools {
            let bytes = path_bytes(&model.model_path);
            let ctx = model.context_size.unwrap_or(DEFAULT_CONTEXT);
            match kraken_infer::budget::fit(bytes, ctx, &pools, model.multi_gpu) {
                Fit::Fits => {}
                Fit::Tight => warnings.push(format!(
                    "{} only just fits in the free memory; other programs may slow it down.",
                    model.name
                )),
                Fit::NoFit if opts.force => warnings.push(format!(
                    "{} did not seem to fit in the free memory and was started anyway.",
                    model.name
                )),
                Fit::NoFit => {
                    return Err(self.no_fit(&model, need, &pools, &cards, st_snapshot));
                }
            }
        }

        let (respawn, kind) = self.respawner(&model, devices, apis)?;
        Ok(Prepared {
            model,
            cards,
            uses,
            warnings,
            respawn,
            kind,
        })
    }

    /// Free memory per pool the model would use, minus what models still loading are about to
    /// take; `None` when the sizes are unknown (the check is skipped, with a warning).
    fn pools(
        &self,
        cards: &[DeviceInfo],
        slots: &[Arc<Slot>],
        warnings: &mut Vec<String>,
    ) -> Option<Vec<MemoryPool>> {
        let reserved = |key: &PoolKey, loading_only: bool| -> u64 {
            slots
                .iter()
                .filter(|s| if loading_only { s.loading() } else { s.live() })
                .flat_map(|s| s.uses.iter())
                .filter(|(k, _)| k == key)
                .map(|(_, b)| *b)
                .sum()
        };
        if cards.is_empty() {
            let (budget, _extra, note) = self.budget();
            if note.is_some() {
                warnings.extend(note);
                return None;
            }
            let free = budget.total_ram().saturating_sub(budget.committed_ram());
            // RAM use of running models does not show in the total, so all of them count.
            return Some(vec![MemoryPool {
                free,
                reserved: reserved(&PoolKey::Ram, false),
            }]);
        }
        if cards.iter().any(|c| c.vram_total == 0) {
            warnings.push(
                "KRAKEN could not read how much memory the card has, so the memory check is off"
                    .into(),
            );
            return None;
        }
        Some(
            cards
                .iter()
                .map(|c| MemoryPool {
                    free: c.vram_total.saturating_sub(c.vram_used),
                    reserved: reserved(&card_key(&c.uuid, c.index), true),
                })
                .collect(),
        )
    }

    fn no_fit(
        &self,
        model: &LocalModel,
        need: u64,
        pools: &[MemoryPool],
        cards: &[DeviceInfo],
        slots: &[Arc<Slot>],
    ) -> ProtoError {
        let free: u64 = pools
            .iter()
            .map(|p| p.free.saturating_sub(p.reserved))
            .sum();
        let place = if cards.is_empty() {
            "the computer's memory (RAM)".to_string()
        } else {
            let names: Vec<&str> = cards.iter().map(|c| c.name.as_str()).collect();
            format!("the memory on {} (VRAM)", names.join(" and "))
        };
        let mut choices: Vec<Value> = slots
            .iter()
            .filter(|s| s.live())
            .map(|s| json!({"kind": "stop_model", "model": s.id, "name": s.name}))
            .collect();
        let mut options = Vec::new();
        if !choices.is_empty() {
            options.push("stop another model");
        }
        if model.engine == LocalEngine::Llama && !model.cpu_only {
            choices.push(json!({"kind": "cpu"}));
            options.push("run it on the processor (slower)");
        }
        choices.push(json!({"kind": "start_anyway"}));
        options.push("start it anyway");
        ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "{} needs about {} but only {} is free in {place}. You can {}.",
                model.name,
                gib(need),
                gib(free),
                options.join(", or ")
            ),
        )
        .with_details(json!({
            "reason": "no_fit",
            "model": model.id,
            "need_bytes": need,
            "free_bytes": free,
            "choices": choices,
        }))
    }

    /// A function that starts the model's engine on a port.
    fn respawner(
        &self,
        model: &LocalModel,
        devices: Vec<DeviceInfo>,
        apis: Vec<GpuApi>,
    ) -> Result<(Respawn, StatsKind), ProtoError> {
        let model = model.clone();
        match model.engine {
            LocalEngine::Llama => {
                let binary = self.llama_binary()?;
                let key = generate_api_key().map_err(infer_error)?;
                let served = model
                    .model_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned());
                let f = move |port: u16| -> Result<RunningBackend, InferError> {
                    let l = launch_spec(&model, &devices, &apis, port)?;
                    let mut spec = ProcessSpec::new(binary.clone(), port, "/health");
                    spec.args = l.argv;
                    spec.env = l.env;
                    spec.env
                        .push((kraken_infer::llama::API_KEY_ENV.into(), key.clone()));
                    spec.progress_parser = Some(kraken_infer::llama::parse_progress);
                    let p = ManagedProcess::start(spec)?;
                    Ok(RunningBackend::new(LLAMA_ID, served.clone(), p).with_api_key(key.clone()))
                };
                Ok((Arc::new(f), StatsKind::Llama))
            }
            LocalEngine::Strata => {
                let m = self.strata_manifest()?;
                let f = move |port: u16| -> Result<RunningBackend, InferError> {
                    let l = launch_spec(&model, &devices, &apis, port)?;
                    // `{port}` is always KRAKEN's pick; a `port` setting of an older manifest
                    // is never read.
                    let mut argv = m.expand(&Value::Null, port)?.into_iter();
                    let program = argv.next().unwrap_or_default();
                    let mut spec = ProcessSpec::new(program, port, m.health_path.clone());
                    spec.args = argv.chain(l.argv).collect();
                    spec.env = m.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    spec.env.extend(l.env);
                    spec.health.ready_timeout = Duration::from_secs(m.ready_timeout_secs);
                    spec.grace = Duration::from_secs(m.grace_secs);
                    spec.cwd = m.cwd.as_ref().map(PathBuf::from);
                    let p = ManagedProcess::start(spec)?;
                    Ok(RunningBackend::new(m.id.clone(), Some(model.id.clone()), p))
                };
                Ok((Arc::new(f), StatsKind::Strata))
            }
        }
    }

    fn live_slots(&self) -> Vec<Arc<Slot>> {
        lock(&self.state)
            .slots
            .values()
            .filter(|s| s.live())
            .cloned()
            .collect()
    }

    /// Starts `id` unless it is running. Call with the `op` lock held.
    async fn ensure_running(&self, id: &str, opts: StartOptions) -> Result<(), ProtoError> {
        let existing = lock(&self.state).slots.get(id).cloned();
        if let Some(s) = &existing {
            if s.live() {
                return Ok(());
            }
            s.stop().await;
        }
        let cfg = self.serving_config();
        let model = cfg.model(id).cloned().ok_or_else(|| not_found(id, &cfg))?;
        let slots = self.live_slots();
        let prepared = match self.prepare(model, opts, &slots).await {
            Ok(p) => p,
            Err(e) => {
                let no_fit = e.details.as_ref().is_some_and(|d| d["reason"] == "no_fit");
                if !no_fit {
                    lock(&self.state)
                        .errors
                        .insert(id.to_string(), e.message.clone());
                }
                return Err(e);
            }
        };
        let port = pick_free_port().map_err(infer_error)?;
        let running = (prepared.respawn)(port).map_err(|e| {
            let e = infer_error(e);
            lock(&self.state)
                .errors
                .insert(id.to_string(), e.message.clone());
            e
        })?;
        let devices: Vec<DeviceRef> = prepared.cards.iter().map(device_ref).collect();
        let slot = Arc::new(Slot {
            id: id.to_string(),
            name: prepared.model.name.clone(),
            backend: running.backend_id().to_string(),
            engine: Some(prepared.model.engine),
            run: Mutex::new(Arc::new(running)),
            started: Instant::now(),
            uses: prepared.uses,
            devices: devices.clone(),
            warnings: prepared.warnings,
            failure: Mutex::new(None),
            stopping: false.into(),
            watcher: Mutex::new(None),
        });
        for w in &slot.warnings {
            tracing::warn!(model = %id, "{w}");
        }
        let stats = self.stats();
        stats.register(Target {
            model: id.to_string(),
            kind: prepared.kind,
            port,
            pid: slot.run().status().pid,
            devices,
        });
        let watcher = tokio::spawn(watch(
            slot.clone(),
            stats,
            self.devices.clone(),
            prepared.respawn,
            prepared.kind,
        ));
        *lock(&slot.watcher) = Some(watcher);
        let mut st = lock(&self.state);
        st.notices.remove(id);
        st.insert(slot);
        Ok(())
    }

    /// Holds `id` for `holder`, starting it when it is not running. A model that does not fit
    /// is refused (details `reason: "no_fit"` with the `choices`) unless `opts.force`.
    pub async fn hold_model(
        &self,
        holder: Holder,
        id: &str,
        opts: StartOptions,
    ) -> Result<ModelStatus, ProtoError> {
        {
            let _op = self.op.lock().await;
            self.ensure_running(id, opts).await?;
            lock(&self.state).add_hold(id, holder);
        }
        Ok(self.model_status(id))
    }

    /// A manual start: holds `id` until [`stop_model`](Self::stop_model).
    pub async fn pin_model(&self, id: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError> {
        self.hold_model(Holder::Pinned, id, opts).await
    }

    /// Gives up `holder`'s hold of `id`; the last one starts the grace period.
    pub async fn release_model(&self, holder: Holder, id: &str) -> ReleaseReply {
        let now = self.now();
        let released = lock(&self.state).remove_hold(id, holder, now);
        self.tick().await;
        ReleaseReply { released }
    }

    /// Gives up every hold of a daemon connection that has ended.
    pub fn release_connection(&self, conn: u64) {
        let now = self.now();
        let mut st = lock(&self.state);
        let ids: Vec<String> = st.holds.keys().cloned().collect();
        for id in ids {
            st.remove_hold(&id, Holder::Connection(conn), now);
        }
    }

    /// Stops `id` now, whoever holds it. False when it was not running.
    pub async fn stop_model(&self, id: &str) -> bool {
        let _op = self.op.lock().await;
        self.stop_locked(id).await
    }

    async fn stop_locked(&self, id: &str) -> bool {
        let slot = {
            let mut st = lock(&self.state);
            st.clear(id);
            st.slots.get(id).cloned()
        };
        let Some(slot) = slot else {
            return false;
        };
        let was_live = slot.live();
        slot.stop().await;
        if let Some(s) = self.stats.get() {
            s.unregister(id);
        }
        was_live
    }

    /// Stops the models whose grace period is over. The daemon calls it on its maintenance tick.
    pub async fn tick(&self) {
        if lock(&self.state).idle_since.is_empty() {
            return;
        }
        let grace = self.serving_config().serving.grace();
        let now = self.now();
        let due: Vec<String> = {
            let st = lock(&self.state);
            st.idle_since
                .iter()
                .filter(|(id, since)| !st.held(id) && now.saturating_sub(**since) >= grace)
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in due {
            let _op = self.op.lock().await;
            let still_due = {
                let st = lock(&self.state);
                !st.held(&id)
                    && st
                        .idle_since
                        .get(&id)
                        .is_some_and(|s| now.saturating_sub(*s) >= grace)
            };
            if still_due {
                tracing::info!(model = %id, "nobody uses the model any more; stopping it");
                self.stop_locked(&id).await;
            }
        }
    }

    /// Holds, for `holder`, every model marked "serve automatically": the ones a role uses
    /// first, then the list order. A model that does not fit (counting the ones started before
    /// it) is skipped and the reason kept for its status.
    pub async fn autostart_for(&self, holder: Holder) -> AutostartReport {
        let cfg = self.serving_config();
        let mut report = AutostartReport::default();
        for m in cfg.autostart_order() {
            match self
                .hold_model(holder, &m.id, StartOptions::default())
                .await
            {
                Ok(_) => report.started.push(m.id.clone()),
                Err(e) => {
                    let no_fit = e.details.as_ref().is_some_and(|d| d["reason"] == "no_fit");
                    let reason = if no_fit {
                        format!("Not started automatically: {}", e.message)
                    } else {
                        e.message.clone()
                    };
                    tracing::info!(model = %m.id, "{reason}");
                    lock(&self.state)
                        .notices
                        .insert(m.id.clone(), reason.clone());
                    report.skipped.push(SkippedModel {
                        model: m.id.clone(),
                        reason,
                        kind: if no_fit { "no_fit" } else { "error" }.into(),
                    });
                }
            }
        }
        report
    }

    /// The status of `id`, set up or running.
    pub fn model_status(&self, id: &str) -> ModelStatus {
        let cfg = self.serving_config();
        self.status_with(id, &cfg)
    }

    fn status_with(&self, id: &str, cfg: &ServingConfig) -> ModelStatus {
        let grace = cfg.serving.grace();
        let now = self.now();
        let model = cfg.model(id);
        let st = lock(&self.state);
        let slot = st.slots.get(id).cloned();
        let holds = st.holds.get(id);
        let pinned = holds.is_some_and(|h| h.contains(&Holder::Pinned));
        let holders = holds.map_or(0, |h| h.iter().filter(|x| **x != Holder::Pinned).count());
        let stops_in_secs = st
            .idle_since
            .get(id)
            .map(|since| grace.saturating_sub(now.saturating_sub(*since)).as_secs());
        let notice = st.notices.get(id).cloned();
        let error = st.errors.get(id).cloned();
        drop(st);

        let mut s = ModelStatus {
            id: id.to_string(),
            name: model.map_or_else(|| id.to_string(), |m| m.name.clone()),
            engine: model.map(|m| m.engine),
            state: match error {
                Some(message) => ModelState::Failed { message },
                None => ModelState::Stopped,
            },
            base_url: None,
            served_model: None,
            api_key: None,
            port: None,
            pid: None,
            load_fraction: None,
            restarts: 0,
            uptime_secs: None,
            holders,
            pinned,
            stops_in_secs,
            notice,
            warnings: Vec::new(),
            devices: model.map(|m| m.devices.clone()).unwrap_or_default(),
            stats: None,
            role_assigned: cfg.roles.iter().any(|r| r == id),
            autostart: model.is_some_and(|m| m.autostart),
        };
        if let Some(slot) = slot {
            let run = slot.run();
            let p = run.status();
            let state = slot.state();
            let running = matches!(state, ModelState::Loading | ModelState::Ready);
            if model.is_none() {
                s.name.clone_from(&slot.name);
                s.engine = slot.engine;
            }
            s.devices.clone_from(&slot.devices);
            s.warnings.clone_from(&slot.warnings);
            s.restarts = p.restarts;
            if running || matches!(state, ModelState::Stopping) {
                s.base_url = Some(run.base_url());
                s.served_model = run.model().map(str::to_string);
                s.api_key = run.api_key().map(str::to_string);
                s.port = Some(run.port());
                s.pid = p.pid;
                s.load_fraction = p.fraction;
                s.uptime_secs = Some(slot.started.elapsed().as_secs());
                s.stats = self.stats.get().and_then(|st| st.snapshot(id));
            }
            s.state = state;
        }
        s
    }

    /// Every model set up, then manual starts.
    pub fn model_statuses(&self) -> ModelsReply {
        let cfg = self.serving_config();
        let mut ids: Vec<String> = cfg.models.iter().map(|m| m.id.clone()).collect();
        for id in &lock(&self.state).order {
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        }
        ModelsReply {
            models: ids.iter().map(|id| self.status_with(id, &cfg)).collect(),
            grace_secs: cfg.serving.grace_secs,
        }
    }

    /// Log lines of `id`.
    pub fn model_logs(&self, p: &ModelLogsParams) -> LogsReply {
        let slot = lock(&self.state).slots.get(&p.model).cloned();
        logs_of(slot.as_deref(), p.after_seq, p.limit)
    }

    /// A view of the manager as one holder (a connection, or the owner process).
    pub fn holder(self: &Arc<Self>, holder: Holder) -> HeldBy {
        HeldBy {
            manager: self.clone(),
            holder,
        }
    }
}

pub(super) fn logs_of(
    slot: Option<&Slot>,
    after_seq: Option<u64>,
    limit: Option<usize>,
) -> LogsReply {
    let Some(slot) = slot else {
        return LogsReply {
            lines: Vec::new(),
            last_seq: after_seq.unwrap_or(0),
        };
    };
    let run = slot.run();
    let ring = run.process().ring();
    let all = ring.snapshot();
    let last_seq = all.last().map_or(after_seq.unwrap_or(0), |l| l.seq);
    let limit = limit
        .unwrap_or(super::DEFAULT_LOG_LIMIT)
        .min(super::MAX_LOG_LIMIT);
    let mut lines: Vec<LogEntry> = ring
        .since(after_seq)
        .into_iter()
        .map(|l| LogEntry {
            seq: l.seq,
            stream: stream_name(l.stream).into(),
            text: l.text,
        })
        .collect();
    if lines.len() > limit {
        lines.drain(..lines.len() - limit);
    }
    LogsReply { lines, last_seq }
}

/// Follows one model: feeds the stats sampler, moves to a new port once when the first one was
/// taken, and fails the model for good when its card is gone or it keeps crashing (the
/// supervisor gives up after its restart limit; nothing here restarts it again).
async fn watch(
    slot: Arc<Slot>,
    stats: Arc<StatsSampler>,
    devices: DevicesFn,
    respawn: Respawn,
    kind: StatsKind,
) {
    let mut moved_port = false;
    loop {
        let run = slot.run();
        let mut rx = run.progress();
        let mut last: Option<Phase> = None;
        let retry = loop {
            let p = rx.borrow_and_update().clone();
            stats.set_pid(&slot.id, p.pid);
            stats.set_phase(&slot.id, slot.state(), p.fraction);
            if slot.is_stopping() {
                return;
            }
            let entered = last != Some(p.phase);
            last = Some(p.phase);
            match p.phase {
                Phase::Failed => {
                    slot.fail(crash_message(&p));
                    stats.set_phase(&slot.id, slot.state(), None);
                    return;
                }
                Phase::Stopped => return,
                Phase::Restarting if entered && !slot.devices.is_empty() => {
                    let f = devices.clone();
                    let now = tokio::task::spawn_blocking(move || f())
                        .await
                        .unwrap_or_default();
                    if let Some(gone) = slot.devices.iter().find(|d| {
                        !now.iter().any(|n| {
                            if d.uuid.is_empty() {
                                n.index == d.index && n.vendor == d.vendor
                            } else {
                                n.uuid == d.uuid
                            }
                        })
                    }) {
                        slot.fail(format!(
                            "The card this model runs on (number {}) is no longer in this \
                             computer, so the model was stopped.",
                            gone.index
                        ));
                        stats.set_phase(&slot.id, slot.state(), None);
                        run.stop().await;
                        return;
                    }
                }
                Phase::Starting | Phase::Loading | Phase::Restarting
                    if !moved_port && shows_bind_failure(&run.logs()) =>
                {
                    break true;
                }
                _ => {}
            }
            let waiting = p.phase != Phase::Ready;
            tokio::select! {
                r = rx.changed() => if r.is_err() { return },
                () = tokio::time::sleep(POLL), if waiting => {}
            }
        };
        if !retry {
            return;
        }
        moved_port = true;
        run.stop().await;
        if slot.is_stopping() {
            return;
        }
        let next = loop {
            match pick_free_port() {
                Ok(p) if p != run.port() => break Ok(p),
                Ok(_) => {}
                Err(e) => break Err(e),
            }
        };
        match next.and_then(|port| respawn(port)) {
            Ok(new) => {
                let port = new.port();
                let pid = new.status().pid;
                *lock(&slot.run) = Arc::new(new);
                stats.unregister(&slot.id);
                stats.register(Target {
                    model: slot.id.clone(),
                    kind,
                    port,
                    pid,
                    devices: slot.devices.clone(),
                });
            }
            Err(e) => {
                slot.fail(format!("The model could not be started: {e}"));
                stats.set_phase(&slot.id, slot.state(), None);
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// One interface, in the daemon or in process

/// The serving operations as one holder sees them: [`HeldBy`] in process, [`DaemonClient`] over
/// the daemon (where the holder is the client's connection).
#[async_trait]
pub trait ServingApi: Send + Sync {
    /// Every local model.
    async fn models(&self) -> Result<ModelsReply, ProtoError>;
    /// The cards of this computer.
    async fn devices(&self) -> Result<DevicesReply, ProtoError>;
    /// Holds a model, starting it when needed.
    async fn hold(&self, model: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError>;
    /// Gives up the hold.
    async fn release(&self, model: &str) -> Result<ReleaseReply, ProtoError>;
    /// Starts a model by hand (it runs until stopped).
    async fn start_model(&self, model: &str, opts: StartOptions)
    -> Result<ModelStatus, ProtoError>;
    /// Stops a model.
    async fn stop_model(&self, model: &str) -> Result<super::StopReply, ProtoError>;
    /// Holds the models marked "serve automatically" that fit.
    async fn autostart(&self) -> Result<AutostartReport, ProtoError>;
    /// Log lines of a model.
    async fn model_logs(&self, params: ModelLogsParams) -> Result<LogsReply, ProtoError>;
}

/// The manager seen by one holder.
#[derive(Clone)]
pub struct HeldBy {
    manager: Arc<InferManager>,
    holder: Holder,
}

impl HeldBy {
    /// The holder.
    pub fn holder(&self) -> Holder {
        self.holder
    }
}

#[async_trait]
impl ServingApi for HeldBy {
    async fn models(&self) -> Result<ModelsReply, ProtoError> {
        Ok(self.manager.model_statuses())
    }

    async fn devices(&self) -> Result<DevicesReply, ProtoError> {
        Ok(DevicesReply {
            devices: self.manager.devices().await,
        })
    }

    async fn hold(&self, model: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError> {
        self.manager.hold_model(self.holder, model, opts).await
    }

    async fn release(&self, model: &str) -> Result<ReleaseReply, ProtoError> {
        Ok(self.manager.release_model(self.holder, model).await)
    }

    async fn start_model(
        &self,
        model: &str,
        opts: StartOptions,
    ) -> Result<ModelStatus, ProtoError> {
        self.manager.pin_model(model, opts).await
    }

    async fn stop_model(&self, model: &str) -> Result<super::StopReply, ProtoError> {
        Ok(super::StopReply {
            stopped: self.manager.stop_model(model).await,
        })
    }

    async fn autostart(&self) -> Result<AutostartReport, ProtoError> {
        Ok(self.manager.autostart_for(self.holder).await)
    }

    async fn model_logs(&self, params: ModelLogsParams) -> Result<LogsReply, ProtoError> {
        Ok(self.manager.model_logs(&params))
    }
}

fn bad_params(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, format!("bad params: {e}"))
}

fn encode<T: Serialize>(v: T) -> Result<Value, ProtoError> {
    serde_json::to_value(v)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot encode reply: {e}")))
}

/// Serves one of the model methods (`infer_models`, `infer_hold`, ...) with `api`; `None` when
/// `method` is not one of them.
pub async fn serve_serving_rpc(
    api: &dyn ServingApi,
    method: &str,
    params: Value,
) -> Option<Result<Value, ProtoError>> {
    let model = |params: Value| serde_json::from_value::<ModelParams>(params).map_err(bad_params);
    Some(match method {
        METHOD_INFER_MODELS => api.models().await.and_then(encode),
        METHOD_INFER_DEVICES => api.devices().await.and_then(encode),
        METHOD_INFER_AUTOSTART => api.autostart().await.and_then(encode),
        METHOD_INFER_HOLD => match model(params) {
            Ok(p) => api.hold(&p.model, p.options()).await.and_then(encode),
            Err(e) => Err(e),
        },
        METHOD_INFER_MODEL_START => match model(params) {
            Ok(p) => api
                .start_model(&p.model, p.options())
                .await
                .and_then(encode),
            Err(e) => Err(e),
        },
        METHOD_INFER_RELEASE => match model(params) {
            Ok(p) => api.release(&p.model).await.and_then(encode),
            Err(e) => Err(e),
        },
        METHOD_INFER_MODEL_STOP => match model(params) {
            Ok(p) => api.stop_model(&p.model).await.and_then(encode),
            Err(e) => Err(e),
        },
        METHOD_INFER_MODEL_LOGS => match serde_json::from_value::<ModelLogsParams>(params) {
            Ok(p) => api.model_logs(p).await.and_then(encode),
            Err(e) => Err(bad_params(e)),
        },
        _ => return None,
    })
}

/// Holds the models a role uses (the assistant, rewriting) for this holder, starting the ones
/// that are not running. Models that do not fit or cannot start are reported, not fatal.
pub async fn hold_role_models(api: &dyn ServingApi) -> Result<AutostartReport, ProtoError> {
    let reply = api.models().await?;
    let mut report = AutostartReport::default();
    for m in reply.models.iter().filter(|m| m.role_assigned) {
        match api.hold(&m.id, StartOptions::default()).await {
            Ok(_) => report.started.push(m.id.clone()),
            Err(e) => {
                let no_fit = e.details.as_ref().is_some_and(|d| d["reason"] == "no_fit");
                report.skipped.push(SkippedModel {
                    model: m.id.clone(),
                    reason: e.message,
                    kind: if no_fit { "no_fit" } else { "error" }.into(),
                });
            }
        }
    }
    Ok(report)
}

/// A [`ServingApi`] as the registry's serving service (`local_model_*` commands).
#[derive(Clone)]
pub struct ServingBridge(Arc<dyn ServingApi>);

impl ServingBridge {
    /// Serves the commands with `api`.
    pub fn new(api: Arc<dyn ServingApi>) -> Self {
        Self(api)
    }
}

impl std::fmt::Debug for ServingBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServingBridge")
    }
}

#[async_trait]
impl kraken_registry::commands::ServingBackend for ServingBridge {
    async fn call(&self, method: &str, params: Value) -> Result<Value, ProtoError> {
        match serve_serving_rpc(self.0.as_ref(), method, params).await {
            Some(r) => r,
            None => Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("unknown serving method `{method}`"),
            )),
        }
    }
}

fn params(model: &str, opts: StartOptions) -> Value {
    json!({"model": model, "force": opts.force, "cpu": opts.cpu})
}

#[async_trait]
impl ServingApi for DaemonClient {
    async fn models(&self) -> Result<ModelsReply, ProtoError> {
        super::decode(self.rpc(METHOD_INFER_MODELS, Value::Null).await?)
    }

    async fn devices(&self) -> Result<DevicesReply, ProtoError> {
        super::decode(self.rpc(METHOD_INFER_DEVICES, Value::Null).await?)
    }

    async fn hold(&self, model: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError> {
        super::decode(self.rpc(METHOD_INFER_HOLD, params(model, opts)).await?)
    }

    async fn release(&self, model: &str) -> Result<ReleaseReply, ProtoError> {
        let p = params(model, StartOptions::default());
        super::decode(self.rpc(METHOD_INFER_RELEASE, p).await?)
    }

    async fn start_model(
        &self,
        model: &str,
        opts: StartOptions,
    ) -> Result<ModelStatus, ProtoError> {
        super::decode(
            self.rpc(METHOD_INFER_MODEL_START, params(model, opts))
                .await?,
        )
    }

    async fn stop_model(&self, model: &str) -> Result<super::StopReply, ProtoError> {
        let p = params(model, StartOptions::default());
        super::decode(self.rpc(METHOD_INFER_MODEL_STOP, p).await?)
    }

    async fn autostart(&self) -> Result<AutostartReport, ProtoError> {
        super::decode(self.rpc(METHOD_INFER_AUTOSTART, Value::Null).await?)
    }

    async fn model_logs(&self, params: ModelLogsParams) -> Result<LogsReply, ProtoError> {
        let p = serde_json::to_value(params)
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        super::decode(self.rpc(METHOD_INFER_MODEL_LOGS, p).await?)
    }
}

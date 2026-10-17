//! The "Run a model on this computer" panel: engine choice, settings form, start/stop, load
//! progress, logs and the memory hint. All state is plain data; the window only draws it.
//!
//! The panel talks to an [`InferApi`], so it works the same against `krakend` and against a
//! manager owned by the GUI process (`--no-daemon`). Calls run on a tokio runtime; their results
//! are applied by [`InferPanel::poll`], which the window calls once per frame.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use kraken_agent::{ProviderConfig, SecretRef};
use kraken_host::infer::{
    BackendInfo, InferApi, InferListReply, LogEntry, LogsParams, LogsReply, StartReply,
    StatusReply, StopReply, gib, model_ram_hint,
};
use kraken_proto::ProtoError;
use tokio::runtime::Handle;

use super::form::SettingsForm;

/// How many log lines the panel keeps.
/// Account name of the local server's per-run API key in the secrets file.
pub const LOCAL_INFER_ACCOUNT: &str = "local-infer";

const MAX_LOG_LINES: usize = 2000;
/// Status refresh while a model is loading or running.
const POLL_BUSY: Duration = Duration::from_millis(800);
/// Status refresh when nothing is running.
const POLL_IDLE: Duration = Duration::from_secs(4);
/// RAM use above this share of the total is reported as tight (the budget's own threshold).
const TIGHT_FRACTION: f64 = 0.85;

/// How worried to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintLevel {
    /// Fits.
    Info,
    /// Fits tightly.
    Warn,
    /// Will be refused.
    Bad,
}

/// A sentence about whether the chosen model fits in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryHint {
    /// Severity.
    pub level: HintLevel,
    /// Plain-language text.
    pub text: String,
}

enum Msg {
    Listed(Result<InferListReply, ProtoError>),
    Started(Result<StartReply, ProtoError>),
    Status(Result<StatusReply, ProtoError>),
    Logs(Result<LogsReply, ProtoError>),
    Stopped(Result<StopReply, ProtoError>),
}

#[derive(Default)]
struct InFlight {
    list: bool,
    start: bool,
    stop: bool,
    status: bool,
    logs: bool,
}

/// State of the panel.
pub struct InferPanel {
    api: Arc<dyn InferApi>,
    rt: Handle,
    tx: Sender<Msg>,
    rx: Receiver<Msg>,
    repaint: Option<Arc<dyn Fn() + Send + Sync>>,
    /// The engines, memory and install state; `None` until the first answer.
    pub listing: Option<InferListReply>,
    /// Id of the chosen engine.
    pub selected: Option<String>,
    /// The settings form of the chosen engine.
    pub form: SettingsForm,
    forms: HashMap<String, SettingsForm>,
    /// What the running (or last) model is doing.
    pub status: StatusReply,
    /// Recent log lines, oldest first.
    pub logs: Vec<LogEntry>,
    last_seq: Option<u64>,
    /// Why the last action failed (plain language).
    pub error: Option<String>,
    /// Memory warnings of the last start.
    pub warnings: Vec<String>,
    /// The log viewer is open.
    pub show_logs: bool,
    flight: InFlight,
    last_poll: Option<Instant>,
}

impl InferPanel {
    /// A panel over `api`; call [`refresh`](Self::refresh) to load the engines.
    pub fn new(api: Arc<dyn InferApi>, rt: Handle) -> Self {
        let (tx, rx) = channel();
        InferPanel {
            api,
            rt,
            tx,
            rx,
            repaint: None,
            listing: None,
            selected: None,
            form: SettingsForm::default(),
            forms: HashMap::new(),
            status: StatusReply {
                running: false,
                phase: "none".into(),
                backend: None,
                model: None,
                base_url: None,
                fraction: None,
                message: String::new(),
                restarts: 0,
                pid: None,
                uptime_secs: None,
                api_key: None,
            },
            logs: Vec::new(),
            last_seq: None,
            error: None,
            warnings: Vec::new(),
            show_logs: false,
            flight: InFlight::default(),
            last_poll: None,
        }
    }

    /// Calls `f` whenever an answer arrives (to request a repaint).
    #[must_use]
    pub fn with_repaint(mut self, f: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.repaint = Some(f);
        self
    }

    fn spawn<T: Send + 'static>(
        &self,
        fut: impl std::future::Future<Output = T> + Send + 'static,
        wrap: fn(T) -> Msg,
    ) {
        let (tx, repaint) = (self.tx.clone(), self.repaint.clone());
        self.rt.spawn(async move {
            let r = fut.await;
            let _ = tx.send(wrap(r));
            if let Some(f) = repaint {
                f();
            }
        });
    }

    /// Asks for the engines, memory and install state.
    pub fn refresh(&mut self) {
        if self.flight.list {
            return;
        }
        self.flight.list = true;
        let api = self.api.clone();
        self.spawn(async move { api.list().await }, Msg::Listed);
    }

    /// The engines are being (re)listed.
    pub fn is_refreshing(&self) -> bool {
        self.flight.list
    }

    /// True once the first listing arrived.
    pub fn loaded(&self) -> bool {
        self.listing.is_some()
    }

    /// The engines.
    pub fn backends(&self) -> &[BackendInfo] {
        self.listing.as_ref().map_or(&[], |l| l.backends.as_slice())
    }

    /// The chosen engine.
    pub fn selected_backend(&self) -> Option<&BackendInfo> {
        let id = self.selected.as_deref()?;
        self.backends().iter().find(|b| b.id == id)
    }

    /// Chooses an engine and shows its settings (what was typed for it before is kept).
    pub fn select(&mut self, id: &str) {
        if self.selected.as_deref() == Some(id) {
            return;
        }
        let Some(schema) = self
            .backends()
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.settings_schema.clone())
        else {
            return;
        };
        if let Some(cur) = self.selected.take() {
            self.forms.insert(cur, std::mem::take(&mut self.form));
        }
        self.form = self
            .forms
            .remove(id)
            .unwrap_or_else(|| SettingsForm::from_schema(&schema));
        self.selected = Some(id.to_string());
        self.error = None;
    }

    /// Sets the model file (what the file picker returns).
    pub fn set_model_path(&mut self, path: &Path) {
        if let Some(key) = self.form.model_key().map(str::to_string) {
            self.form.set_text(&key, path.to_string_lossy());
        }
    }

    /// A model is loading, serving or being restarted.
    pub fn is_running(&self) -> bool {
        self.status.running
    }

    /// The model answers requests.
    pub fn is_ready(&self) -> bool {
        self.status.is_ready()
    }

    /// A start or stop request is on its way.
    pub fn is_busy(&self) -> bool {
        self.flight.start || self.flight.stop
    }

    /// Whether Start can be pressed.
    pub fn can_start(&self) -> bool {
        self.selected.is_some() && !self.is_running() && !self.is_busy()
    }

    /// Starts the chosen engine with the form's settings.
    pub fn start(&mut self) {
        self.error = None;
        let Some(id) = self.selected.clone() else {
            self.error = Some("Pick an engine first.".into());
            return;
        };
        if !self.can_start() {
            return;
        }
        let settings = match self.form.to_settings() {
            Ok(s) => s,
            Err(problems) => {
                self.error = Some(problems.join(". "));
                return;
            }
        };
        self.flight.start = true;
        self.warnings.clear();
        let api = self.api.clone();
        self.spawn(async move { api.start(&id, settings).await }, Msg::Started);
    }

    /// Stops the model.
    pub fn stop(&mut self) {
        if self.flight.stop {
            return;
        }
        self.error = None;
        self.flight.stop = true;
        let api = self.api.clone();
        self.spawn(async move { api.stop().await }, Msg::Stopped);
    }

    /// Fetches status (and new log lines while something runs or the viewer is open) when it is
    /// time. Call once per frame while the panel is visible.
    pub fn tick(&mut self, now: Instant) {
        if !self.loaded() {
            return;
        }
        let every = if self.status.running || self.flight.start {
            POLL_BUSY
        } else {
            POLL_IDLE
        };
        if self
            .last_poll
            .is_some_and(|t| now.duration_since(t) < every)
        {
            return;
        }
        self.last_poll = Some(now);
        if !self.flight.status {
            self.flight.status = true;
            let api = self.api.clone();
            self.spawn(async move { api.status().await }, Msg::Status);
        }
        if (self.status.running || self.show_logs) && !self.flight.logs {
            self.flight.logs = true;
            let (api, after_seq) = (self.api.clone(), self.last_seq);
            self.spawn(
                async move {
                    api.logs(LogsParams {
                        after_seq,
                        limit: Some(MAX_LOG_LINES),
                    })
                    .await
                },
                Msg::Logs,
            );
        }
    }

    /// How long until [`tick`](Self::tick) wants to run again.
    pub fn next_tick_in(&self) -> Duration {
        if self.status.running || self.flight.start {
            POLL_BUSY
        } else {
            POLL_IDLE
        }
    }

    /// Applies answers that arrived. Returns true when something changed.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        while let Ok(m) = self.rx.try_recv() {
            changed = true;
            match m {
                Msg::Listed(r) => {
                    self.flight.list = false;
                    match r {
                        Ok(l) => {
                            self.listing = Some(l);
                            let still = self
                                .selected
                                .as_deref()
                                .is_some_and(|id| self.backends().iter().any(|b| b.id == id));
                            if !still {
                                self.selected = None;
                                self.form = SettingsForm::default();
                                let first = self.backends().first().map(|b| b.id.clone());
                                if let Some(id) = first {
                                    self.select(&id);
                                }
                            }
                        }
                        Err(e) => self.error = Some(e.message),
                    }
                }
                Msg::Started(r) => {
                    self.flight.start = false;
                    match r {
                        Ok(s) => {
                            self.warnings = s.warnings.clone();
                            self.logs.clear();
                            self.last_seq = None;
                            self.status = StatusReply {
                                running: true,
                                phase: "starting".into(),
                                backend: Some(s.backend),
                                model: s.model,
                                base_url: Some(s.base_url),
                                fraction: None,
                                message: "starting".into(),
                                restarts: 0,
                                pid: s.pid,
                                uptime_secs: Some(0),
                                api_key: s.api_key,
                            };
                            self.last_poll = None;
                        }
                        Err(e) => self.error = Some(e.message),
                    }
                }
                Msg::Status(r) => {
                    self.flight.status = false;
                    match r {
                        Ok(s) => {
                            let was_running = self.status.running;
                            if s.is_failed() && was_running && self.error.is_none() {
                                self.error = Some(format!(
                                    "The model stopped working: {}. The log below says why.",
                                    s.message
                                ));
                                self.show_logs = true;
                            }
                            self.status = s;
                        }
                        Err(e) => self.error = Some(e.message),
                    }
                }
                Msg::Logs(r) => {
                    self.flight.logs = false;
                    if let Ok(l) = r {
                        if !l.lines.is_empty() {
                            self.logs.extend(l.lines);
                            let extra = self.logs.len().saturating_sub(MAX_LOG_LINES);
                            self.logs.drain(..extra);
                        }
                        self.last_seq = Some(l.last_seq);
                    }
                }
                Msg::Stopped(r) => {
                    self.flight.stop = false;
                    match r {
                        Ok(_) => self.last_poll = None,
                        Err(e) => self.error = Some(e.message),
                    }
                }
            }
        }
        changed
    }

    /// A sentence about what the model is doing, for the status line.
    pub fn phase_text(&self) -> String {
        if self.flight.start {
            return "Starting...".into();
        }
        if self.flight.stop {
            return "Stopping...".into();
        }
        let model = self.status.model.as_deref().unwrap_or("the model");
        match self.status.phase.as_str() {
            "starting" => format!("Starting {model}..."),
            "loading" => match self.status.fraction {
                Some(f) => format!("Loading {model}: {:.0}%", f * 100.0),
                None => format!("Loading {model}..."),
            },
            "ready" => format!("{model} is running and ready."),
            "restarting" => format!(
                "{model} stopped unexpectedly and is being restarted ({} so far).",
                self.status.restarts
            ),
            "failed" => format!("{model} could not run: {}", self.status.message),
            "stopped" => "Stopped.".into(),
            _ => "No model is running.".into(),
        }
    }

    /// Load progress for a progress bar: `Some(fraction)` while loading, `None` otherwise.
    pub fn progress(&self) -> Option<f32> {
        match self.status.phase.as_str() {
            "starting" => Some(self.status.fraction.unwrap_or(0.0)),
            "loading" => Some(self.status.fraction.unwrap_or(0.0)),
            _ => None,
        }
    }

    /// What to do when the chosen engine's program is missing.
    pub fn install_hint(&self) -> Option<&str> {
        let b = self.selected_backend()?;
        (b.installed == Some(false))
            .then_some(b.setup_hint.as_deref())
            .flatten()
    }

    /// Whether the model of the form fits in memory, from the file's size and the memory budget.
    pub fn memory_hint(&self) -> Option<MemoryHint> {
        let l = self.listing.as_ref()?;
        let key = self.form.model_key()?;
        let path = self.form.field(key)?.text.trim().to_string();
        if path.is_empty() {
            return None;
        }
        let size = std::fs::metadata(&path).ok().filter(|m| m.is_file())?.len();
        let m = &l.memory;
        if m.total_ram == 0 {
            return Some(MemoryHint {
                level: HintLevel::Info,
                text: format!(
                    "The model file is {}. KRAKEN could not read how much memory this computer has.",
                    gib(size)
                ),
            });
        }
        let on_gpu = self.form.number("gpu_layers").is_some_and(|n| n > 0.0)
            && self.form.number("n_cpu_moe").is_none();
        if on_gpu {
            return Some(MemoryHint {
                level: HintLevel::Info,
                text: format!(
                    "The model file is {}. With GPU layers set the weights go to video memory, \
                     which KRAKEN cannot measure; it counts about 0.5 GiB of your {} of RAM.",
                    gib(size),
                    gib(m.total_ram)
                ),
            });
        }
        let need = model_ram_hint(size);
        let after = m.ghidra_reserved.saturating_add(need);
        let held = if m.ghidra_reserved > 0 {
            format!(", {} of it held by open projects", gib(m.ghidra_reserved))
        } else {
            String::new()
        };
        let (level, text) = if after > m.total_ram {
            (
                HintLevel::Bad,
                format!(
                    "This model needs about {} of RAM but this computer has {}{held}. KRAKEN \
                     will not start it. Pick a smaller model or quantization, close a project, \
                     or send layers to the GPU.",
                    gib(need),
                    gib(m.total_ram)
                ),
            )
        } else if after as f64 > m.total_ram as f64 * TIGHT_FRACTION {
            (
                HintLevel::Warn,
                format!(
                    "This model needs about {} of {} RAM{held}. It fits, but little is left for \
                     everything else, so the computer may slow down.",
                    gib(need),
                    gib(m.total_ram)
                ),
            )
        } else {
            (
                HintLevel::Info,
                format!(
                    "This model needs about {} of {} RAM{held}. It fits.",
                    gib(need),
                    gib(m.total_ram)
                ),
            )
        };
        Some(MemoryHint { level, text })
    }

    /// The per-run API key of the running server, to store under [`LOCAL_INFER_ACCOUNT`] in the
    /// secrets file before [`provider_config`](Self::provider_config) is saved.
    pub fn api_key(&self) -> Option<&str> {
        self.status.api_key.as_deref()
    }

    /// The `[provider]` that makes the assistant use the running model; `None` until it is ready.
    pub fn provider_config(&self) -> Option<ProviderConfig> {
        if !self.is_ready() {
            return None;
        }
        let url = self.status.base_url.clone()?;
        let backend = self
            .status
            .backend
            .as_deref()
            .and_then(|id| self.backends().iter().find(|b| b.id == id));
        let ctx = ["context_size", "ctx"]
            .into_iter()
            .find_map(|k| self.form.number(k))
            .filter(|n| *n >= 1.0)
            .map(|n| n as u32);
        Some(ProviderConfig::OpenaiCompatible {
            base_url: url,
            model: self.status.model.clone().unwrap_or_else(|| "local".into()),
            api_key: self.status.api_key.as_ref().map(|_| SecretRef::Keyring {
                service: crate::assist::SECRETS_SERVICE.to_string(),
                account: LOCAL_INFER_ACCOUNT.to_string(),
            }),
            supports_tools: backend.is_none_or(|b| b.capabilities.supports_tool_calls),
            context_window: ctx,
        })
    }
}

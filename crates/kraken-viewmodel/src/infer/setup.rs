//! The guided setup of a model that runs on this computer: what each of its four steps shows
//! and does, with no egui in it.
//!
//! 1. Check this computer (cards, memory, disk).
//! 2. Pick a model (recommended first, each marked Fits, Tight or Won't fit).
//! 3. Pick the cards to run on.
//! 4. Download, start and test (then the model is set up, used by the assistant and served
//!    automatically).
//!
//! The work that needs the machine or the network goes through a [`SetupProbe`] (the daemon's
//! `local_model_*` commands in the window, a script in tests); starting the model goes through
//! the same [`ServingApi`] as the model cards. The window draws what this module says and
//! presses its buttons; an agent presses the same ones through `ui_action`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_host::infer::{ModelStatus, ServingApi, StartOptions};
use kraken_infer::budget::{self, Fit, MemoryPool};
use kraken_infer::hardware::{default_devices, usable};
use kraken_infer::{ModelEntry, model_catalog};
use kraken_proto::infer::{
    DeviceInfo, DeviceRef, DeviceState, LocalEngine, LocalModel, ModelState, MultiGpuMode,
};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{LocalModelRecommendOut, StrataView};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use super::card::{self, gb};
use super::store::LocalModelStore;
use crate::assist::TestReport;

const GIB: u64 = 1 << 30;
/// Tokens of context a model is sized for when judging whether it fits.
const CONTEXT: u32 = 4096;
/// Share of the computer's memory a model on the processor may count on.
const RAM_SHARE: u64 = 3;
/// Models above this many billions of parameters are slow on the processor.
const CPU_MAX_PARAMS_B: u32 = 8;
const SAMPLE_EVERY: Duration = Duration::from_millis(500);
const LOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const LOAD_POLL: Duration = Duration::from_millis(400);

type Repaint = Arc<dyn Fn() + Send + Sync>;

// ---------------------------------------------------------------------------------------------
// What the computer says

/// What the commands of the setup return, before it is turned into plain words.
#[derive(Debug, Clone)]
pub struct RawSurvey {
    /// `local_model_devices`.
    pub devices: Vec<DeviceInfo>,
    /// `local_model_recommend` for llama.cpp.
    pub llama: LocalModelRecommendOut,
    /// `local_model_recommend` for Strata, when it could be asked.
    pub strata: Option<LocalModelRecommendOut>,
}

/// The work of the setup that reaches outside the window.
#[async_trait]
pub trait SetupProbe: Send + Sync {
    /// Looks at the computer and at what can be installed on it.
    async fn survey(&self) -> Result<RawSurvey, ProtoError>;

    /// Downloads and registers the model (asks the person first; downloads are large). When it
    /// returns the model is in `config.toml` and the assistant uses it.
    async fn install(&self, id: &str, engine: LocalEngine) -> Result<(), ProtoError>;

    /// Bytes on disk where downloads and installs land, to show how far a download is.
    fn bytes_on_disk(&self) -> u64;

    /// Sends one short request to the running model.
    async fn test(&self, model: &str) -> Result<TestReport, String>;
}

/// Whether a model fits, in the three answers the list shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FitLevel {
    /// Fits with room to spare.
    Fits,
    /// Fits, but only just.
    Tight,
    /// Does not fit.
    WontFit,
}

impl FitLevel {
    /// The word on the badge.
    pub fn label(self) -> &'static str {
        match self {
            FitLevel::Fits => "Fits",
            FitLevel::Tight => "Tight",
            FitLevel::WontFit => "Won't fit",
        }
    }

    fn rank(self) -> u8 {
        match self {
            FitLevel::Fits => 0,
            FitLevel::Tight => 1,
            FitLevel::WontFit => 2,
        }
    }
}

impl From<Fit> for FitLevel {
    fn from(f: Fit) -> Self {
        match f {
            Fit::Fits => FitLevel::Fits,
            Fit::Tight => FitLevel::Tight,
            Fit::NoFit => FitLevel::WontFit,
        }
    }
}

/// The first step: this computer, in numbers.
#[derive(Debug, Clone, PartialEq)]
pub struct Computer {
    /// Every card found, with its state.
    pub cards: Vec<DeviceInfo>,
    /// Memory of the computer in GiB.
    pub ram_gib: f64,
    /// Free disk space in GiB.
    pub free_disk_gib: f64,
    /// Processor cores.
    pub cpu_cores: u32,
}

impl Computer {
    /// The lines of the first step, in plain words.
    pub fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        let working: Vec<&DeviceInfo> = self
            .cards
            .iter()
            .filter(|d| d.state == DeviceState::Ok)
            .collect();
        match working.len() {
            0 => out.push(
                "No graphics card that KRAKEN can use was found, so models will run on the processor. That works, but it is slow."
                    .to_string(),
            ),
            1 => out.push(card_line("Your graphics card", working[0])),
            _ => {
                out.push("Your graphics cards:".to_string());
                out.extend(working.iter().map(|d| card_line("  ", d)));
            }
        }
        for d in self.cards.iter().filter(|d| d.state != DeviceState::Ok) {
            out.push(match &d.state {
                DeviceState::Error { message } => format!("{} cannot be used: {message}", d.name),
                DeviceState::Unsupported { reason } => {
                    format!("{} cannot be used: {reason}", d.name)
                }
                DeviceState::Ok => String::new(),
            });
        }
        out.push(format!("Computer memory (RAM): {:.1} GB", self.ram_gib));
        out.push(format!("Free disk space: {:.0} GB", self.free_disk_gib));
        out.push(format!("Processor: {} cores", self.cpu_cores));
        out
    }
}

fn card_line(prefix: &str, d: &DeviceInfo) -> String {
    let sep = if prefix.trim().is_empty() { "" } else { ": " };
    format!(
        "{prefix}{sep}{} with {} of video memory",
        d.name,
        gb(d.vram_total)
    )
}

/// One model the person can pick.
#[derive(Debug, Clone, PartialEq)]
pub struct Choice {
    /// Catalog id.
    pub id: String,
    /// Name for people.
    pub name: String,
    /// The program that serves it.
    pub engine: LocalEngine,
    /// Weights and precision, such as `Q4_K_M`.
    pub quant: String,
    /// Bytes the model itself takes.
    pub size_bytes: u64,
    /// Bytes to download, the engine included.
    pub download_bytes: u64,
    /// Bytes on disk afterwards.
    pub disk_bytes: u64,
    /// Whether it fits.
    pub fit: FitLevel,
    /// One line about why.
    pub why: String,
    /// The one KRAKEN suggests.
    pub recommended: bool,
}

impl Choice {
    /// `4.7 GB download`.
    pub fn download_label(&self) -> String {
        format!("{} download", gb(self.download_bytes))
    }

    /// True unless it cannot work on this computer.
    pub fn selectable(&self) -> bool {
        self.fit != FitLevel::WontFit
    }

    /// The program's name for people.
    pub fn engine_label(&self) -> &'static str {
        match self.engine {
            LocalEngine::Llama => "llama.cpp",
            LocalEngine::Strata => "Strata",
        }
    }
}

/// Everything the first two steps show.
#[derive(Debug, Clone, PartialEq)]
pub struct Survey {
    /// This computer.
    pub computer: Computer,
    /// The models, the suggested one first.
    pub choices: Vec<Choice>,
    /// Things to do by hand before some model can be used (Strata).
    pub notes: Vec<String>,
}

/// Turns the answers of the commands into the lists the steps show.
pub fn survey_from(raw: &RawSurvey, catalog: &[ModelEntry]) -> Survey {
    let computer = Computer {
        cards: raw.devices.clone(),
        ram_gib: raw.llama.ram_gib,
        free_disk_gib: raw.llama.free_disk_gib,
        cpu_cores: raw.llama.cpu_cores,
    };
    let mut choices = llama_choices(raw, catalog);
    let mut notes = Vec::new();
    let has_nvidia = raw
        .devices
        .iter()
        .any(|d| usable(LocalEngine::Strata, d, &[]).is_ok());
    if let Some(s) = raw.strata.as_ref().and_then(|r| r.strata.as_ref())
        && has_nvidia
    {
        let (more, mut n) = strata_choices(s);
        choices.extend(more);
        notes.append(&mut n);
    }
    let best_strata = choices
        .iter()
        .position(|c| c.engine == LocalEngine::Strata && c.fit == FitLevel::Fits && c.recommended);
    if best_strata.is_some() {
        for c in &mut choices {
            c.recommended = c.engine == LocalEngine::Strata && c.recommended;
        }
    } else {
        for c in &mut choices {
            c.recommended = c.engine == LocalEngine::Llama && c.recommended;
        }
    }
    choices.sort_by(|a, b| {
        b.recommended
            .cmp(&a.recommended)
            .then(a.fit.rank().cmp(&b.fit.rank()))
            .then(b.size_bytes.cmp(&a.size_bytes))
    });
    Survey {
        computer,
        choices,
        notes,
    }
}

fn llama_choices(raw: &RawSurvey, catalog: &[ModelEntry]) -> Vec<Choice> {
    let cards = default_devices(LocalEngine::Llama, &raw.devices, &[]);
    let pools = pools_of(&cards, &raw.devices, ram_pool(raw.llama.ram_gib));
    let on_cpu = cards.is_empty();
    let place = if on_cpu {
        "the computer's memory".to_string()
    } else {
        raw.devices
            .iter()
            .find(|d| cards.iter().any(|c| same_card(c, d)))
            .map_or_else(
                || "the card".into(),
                |d| format!("{} (video memory)", d.name),
            )
    };
    let free_disk = (raw.llama.free_disk_gib * GIB as f64) as u64;
    let suggested = raw.llama.model.as_ref().map(|m| m.id.clone());
    catalog
        .iter()
        .map(|m| {
            let mut fit = FitLevel::from(budget::fit(m.size, CONTEXT, &pools, MultiGpuMode::Split));
            let need = budget::footprint(m.size, CONTEXT);
            let free: u64 = pools.iter().map(|p| p.free).sum();
            let mut why = match fit {
                FitLevel::Fits => format!("Fits in {place} with room to spare."),
                FitLevel::Tight => format!(
                    "Fits in {place}, but only just. Close other programs that use it first."
                ),
                FitLevel::WontFit => format!(
                    "Needs about {} but only {} is free in {place}.",
                    gb(need),
                    gb(free)
                ),
            };
            if on_cpu && fit != FitLevel::WontFit && m.params_b > CPU_MAX_PARAMS_B {
                fit = FitLevel::Tight;
                why =
                    "Fits in the computer's memory, but a model this big is slow on the processor."
                        .to_string();
            }
            if m.size > free_disk {
                fit = FitLevel::WontFit;
                why = format!(
                    "Needs {} of free disk space and only {} is free.",
                    gb(m.size),
                    gb(free_disk)
                );
            }
            Choice {
                id: m.id.clone(),
                name: m.name.clone(),
                engine: LocalEngine::Llama,
                quant: m.quant.clone(),
                size_bytes: m.size,
                download_bytes: m.size,
                disk_bytes: m.size,
                fit,
                why,
                recommended: suggested.as_deref() == Some(&m.id) && fit != FitLevel::WontFit,
            }
        })
        .collect()
}

fn strata_choices(s: &StrataView) -> (Vec<Choice>, Vec<String>) {
    let blocked: Option<String> = (!s.missing.is_empty()).then(|| {
        s.missing
            .iter()
            .map(|m| format!("{} ({})", m.what, m.how_to_fix))
            .collect::<Vec<_>>()
            .join("; ")
    });
    let mut notes = Vec::new();
    if let Some(b) = &blocked {
        notes.push(format!(
            "Strata needs this on your computer first, and KRAKEN installs no system software: {b}"
        ));
    }
    let choices = s
        .candidates
        .iter()
        .map(|c| {
            let total: u64 = c.downloads.iter().map(|d| d.size_bytes).sum();
            let (mut fit, mut why) = match c.fit.as_str() {
                "fits" => (FitLevel::Fits, c.speed.clone()),
                "below_minimum" => (
                    FitLevel::Tight,
                    c.warnings
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Below what Strata asks for.".into()),
                ),
                _ => (
                    FitLevel::WontFit,
                    c.warnings
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Not enough free disk space.".into()),
                ),
            };
            if let Some(b) = &blocked {
                fit = FitLevel::WontFit;
                why = format!("Needs something installed first: {b}");
            }
            Choice {
                id: c.id.clone(),
                name: format!("{} (Strata)", c.name),
                engine: LocalEngine::Strata,
                quant: c.quant.clone(),
                size_bytes: c.download_bytes,
                download_bytes: total.max(c.download_bytes),
                disk_bytes: c.disk_bytes,
                fit,
                why,
                recommended: s.recommended.as_deref() == Some(&c.id),
            }
        })
        .collect();
    (choices, notes)
}

fn ram_pool(ram_gib: f64) -> MemoryPool {
    MemoryPool {
        free: (ram_gib * GIB as f64) as u64 / 4 * RAM_SHARE,
        reserved: 0,
    }
}

fn same_card(c: &DeviceRef, d: &DeviceInfo) -> bool {
    if !c.uuid.is_empty() && !d.uuid.is_empty() {
        c.uuid == d.uuid
    } else {
        c.index == d.index && c.vendor == d.vendor
    }
}

/// The memory pools of the chosen cards, or the computer's memory for the processor.
fn pools_of(chosen: &[DeviceRef], found: &[DeviceInfo], ram: MemoryPool) -> Vec<MemoryPool> {
    if chosen.is_empty() {
        return vec![ram];
    }
    chosen
        .iter()
        .filter_map(|c| found.iter().find(|d| same_card(c, d)))
        .map(|d| MemoryPool {
            free: d.vram_total.saturating_sub(d.vram_used),
            reserved: 0,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The steps

/// The four steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Look at this computer.
    Check,
    /// Choose a model.
    PickModel,
    /// Choose the cards.
    PickCards,
    /// Download, start and test.
    Download,
}

impl SetupStep {
    /// 1 to 4.
    pub fn number(self) -> usize {
        match self {
            SetupStep::Check => 1,
            SetupStep::PickModel => 2,
            SetupStep::PickCards => 3,
            SetupStep::Download => 4,
        }
    }

    /// The step's id for agents.
    pub fn id(self) -> &'static str {
        match self {
            SetupStep::Check => "check_computer",
            SetupStep::PickModel => "pick_model",
            SetupStep::PickCards => "pick_cards",
            SetupStep::Download => "download_and_test",
        }
    }

    /// The step's name.
    pub fn title(self) -> &'static str {
        match self {
            SetupStep::Check => "Check this computer",
            SetupStep::PickModel => "Pick a model",
            SetupStep::PickCards => "Pick cards",
            SetupStep::Download => "Download and test",
        }
    }

    /// One line about what the step is for.
    pub fn explain(self) -> &'static str {
        match self {
            SetupStep::Check => {
                "A model runs best on a graphics card with enough video memory (VRAM). Here is what this computer has."
            }
            SetupStep::PickModel => {
                "Bigger models answer better but need more memory. The first one is what KRAKEN suggests for this computer."
            }
            SetupStep::PickCards => {
                "Choose where the model runs. A graphics card is much faster than the processor."
            }
            SetupStep::Download => {
                "KRAKEN downloads the model, starts it and asks it one short question to check that it works."
            }
        }
    }

    fn next(self) -> Option<SetupStep> {
        match self {
            SetupStep::Check => Some(SetupStep::PickModel),
            SetupStep::PickModel => Some(SetupStep::PickCards),
            SetupStep::PickCards => Some(SetupStep::Download),
            SetupStep::Download => None,
        }
    }

    fn previous(self) -> Option<SetupStep> {
        match self {
            SetupStep::Check => None,
            SetupStep::PickModel => Some(SetupStep::Check),
            SetupStep::PickCards => Some(SetupStep::PickModel),
            SetupStep::Download => Some(SetupStep::PickCards),
        }
    }
}

/// Where the last step is.
#[derive(Debug, Clone, PartialEq)]
pub enum Stage {
    /// Not started.
    Idle,
    /// Downloading and installing.
    Downloading,
    /// The model is loading; how far, when the engine says.
    Starting(Option<f32>),
    /// The test question is on its way.
    Testing,
    /// It works.
    Done,
    /// Something went wrong; what, and what to do.
    Failed(String),
}

/// The look at the computer.
#[derive(Debug, Clone, PartialEq)]
pub enum SurveyState {
    /// Still looking.
    Loading,
    /// It did not work.
    Failed(String),
    /// Done.
    Ready(Arc<Survey>),
}

/// The progress bar of the last step.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    /// 0 to 1.
    pub fraction: f32,
    /// What it says next to the bar.
    pub text: String,
}

/// What the page of the window shows, for agents and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The step.
    pub step: SetupStep,
    /// The model picked, if any.
    pub chosen: Option<String>,
    /// What the last step is doing.
    pub stage: String,
    /// Why "Next" does nothing now.
    pub blocked: Option<String>,
}

#[derive(Default)]
struct Shared {
    survey: Option<Result<Arc<Survey>, String>>,
    survey_run: u64,
    stage: Option<Stage>,
    grown: u64,
    reply: Option<TestReport>,
    finished: Option<String>,
    run: u64,
}

fn lock(m: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The setup: its step, the choices made, and the work in progress.
pub struct LocalSetup {
    rt: Handle,
    probe: Arc<dyn SetupProbe>,
    serving: Arc<dyn ServingApi>,
    store: LocalModelStore,
    repaint: Option<Repaint>,
    shared: Arc<Mutex<Shared>>,
    step: SetupStep,
    chosen: Option<String>,
    draft: Option<LocalModel>,
    task: Option<JoinHandle<()>>,
    closed: bool,
}

impl Drop for LocalSetup {
    fn drop(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

impl LocalSetup {
    /// A setup that starts by looking at the computer.
    pub fn new(
        probe: Arc<dyn SetupProbe>,
        serving: Arc<dyn ServingApi>,
        config_path: Option<PathBuf>,
        rt: Handle,
    ) -> Self {
        let mut s = LocalSetup {
            rt,
            probe,
            serving,
            store: LocalModelStore::new(config_path),
            repaint: None,
            shared: Arc::new(Mutex::new(Shared::default())),
            step: SetupStep::Check,
            chosen: None,
            draft: None,
            task: None,
            closed: false,
        };
        s.look();
        s
    }

    /// Wakes the window when something changed.
    pub fn with_repaint(mut self, f: Repaint) -> Self {
        self.repaint = Some(f);
        self
    }

    fn wake(repaint: &Option<Repaint>) {
        if let Some(f) = repaint {
            f();
        }
    }

    /// Looks at the computer (again).
    pub fn look(&mut self) {
        let run = {
            let mut s = lock(&self.shared);
            s.survey = None;
            s.survey_run += 1;
            s.survey_run
        };
        let (probe, shared, repaint) = (
            self.probe.clone(),
            self.shared.clone(),
            self.repaint.clone(),
        );
        self.rt.spawn(async move {
            let out = probe
                .survey()
                .await
                .map(|raw| Arc::new(survey_from(&raw, &model_catalog())))
                .map_err(|e| look_error(&e));
            {
                let mut s = lock(&shared);
                if s.survey_run == run {
                    s.survey = Some(out);
                }
            }
            Self::wake(&repaint);
        });
    }

    // -- reading ------------------------------------------------------------------------------

    /// The step on show.
    pub fn step(&self) -> SetupStep {
        self.step
    }

    /// True once the person (or an agent) closed it, or it finished and was dismissed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// The look at the computer.
    pub fn survey(&self) -> SurveyState {
        match &lock(&self.shared).survey {
            None => SurveyState::Loading,
            Some(Err(e)) => SurveyState::Failed(e.clone()),
            Some(Ok(s)) => SurveyState::Ready(s.clone()),
        }
    }

    /// The cards found.
    pub fn cards(&self) -> Vec<DeviceInfo> {
        match self.survey() {
            SurveyState::Ready(s) => s.computer.cards.clone(),
            _ => Vec::new(),
        }
    }

    /// The model picked.
    pub fn chosen(&self) -> Option<Choice> {
        let id = self.chosen.as_deref()?;
        match self.survey() {
            SurveyState::Ready(s) => s.choices.iter().find(|c| c.id == id).cloned(),
            _ => None,
        }
    }

    /// Picks a model. Returns false for one that does not fit or is not on the list.
    pub fn choose(&mut self, id: &str) -> bool {
        let SurveyState::Ready(s) = self.survey() else {
            return false;
        };
        let Some(c) = s
            .choices
            .iter()
            .find(|c| c.id == id)
            .filter(|c| c.selectable())
        else {
            return false;
        };
        if self.chosen.as_deref() != Some(id) {
            let mut model = kraken_host::infer::new_local_model(&c.id, c.engine, PathBuf::new());
            model.name = c.name.clone();
            model.devices = default_devices(c.engine, &s.computer.cards, &[]);
            model.cpu_only = model.devices.is_empty() && card::cpu_allowed(&model);
            self.draft = Some(model);
            self.chosen = Some(c.id.clone());
        }
        true
    }

    /// The record being filled in by the third step.
    pub fn draft(&self) -> Option<&LocalModel> {
        self.draft.as_ref()
    }

    /// Changes the cards of the record.
    pub fn edit_draft(&mut self, f: impl FnOnce(&mut LocalModel, &[DeviceInfo])) {
        let cards = self.cards();
        if let Some(d) = self.draft.as_mut() {
            f(d, &cards);
        }
    }

    /// Whether the chosen model fits the cards ticked now.
    pub fn fit_on_chosen_cards(&self) -> Option<FitLevel> {
        let c = self.chosen()?;
        let d = self.draft.as_ref()?;
        let SurveyState::Ready(s) = self.survey() else {
            return None;
        };
        if c.engine == LocalEngine::Strata {
            return Some(c.fit);
        }
        let chosen = card::effective_devices(d, &s.computer.cards);
        let pools = pools_of(&chosen, &s.computer.cards, ram_pool(s.computer.ram_gib));
        let mut fit = FitLevel::from(budget::fit(c.size_bytes, CONTEXT, &pools, d.multi_gpu));
        if chosen.is_empty() && fit == FitLevel::Fits {
            let slow = model_catalog()
                .iter()
                .any(|m| m.id == c.id && m.params_b > CPU_MAX_PARAMS_B);
            if slow {
                fit = FitLevel::Tight;
            }
        }
        Some(fit)
    }

    /// One line about the third step's fit.
    pub fn fit_text(&self) -> Option<String> {
        let c = self.chosen()?;
        Some(match self.fit_on_chosen_cards()? {
            FitLevel::Fits => format!("{} fits on these cards.", c.name),
            FitLevel::Tight => format!(
                "{} fits on these cards, but only just. It may be slow or fail to load.",
                c.name
            ),
            FitLevel::WontFit => format!(
                "{} does not fit on these cards. Tick another card, or go back and pick a smaller model.",
                c.name
            ),
        })
    }

    /// Why "Next" cannot be pressed now, or `None` when it can.
    pub fn blocked(&self) -> Option<String> {
        match self.step {
            SetupStep::Check => match self.survey() {
                SurveyState::Loading => Some("Still looking at this computer.".into()),
                SurveyState::Failed(_) => {
                    Some("Could not look at this computer. Check again.".into())
                }
                SurveyState::Ready(_) => None,
            },
            SetupStep::PickModel => {
                if self.chosen.is_some() {
                    None
                } else {
                    Some("Pick a model first.".into())
                }
            }
            SetupStep::PickCards => {
                if self.fit_on_chosen_cards() == Some(FitLevel::WontFit) {
                    Some("The model does not fit on these cards.".into())
                } else {
                    None
                }
            }
            SetupStep::Download => match self.stage() {
                Stage::Done => None,
                Stage::Failed(_) => Some("Press Try again, or go back.".into()),
                _ => Some("Wait until the test is done.".into()),
            },
        }
    }

    /// Where the last step is.
    pub fn stage(&self) -> Stage {
        lock(&self.shared).stage.clone().unwrap_or(Stage::Idle)
    }

    /// The bar of the last step.
    pub fn progress(&self) -> Option<Progress> {
        let c = self.chosen()?;
        let s = lock(&self.shared);
        match s.stage.as_ref()? {
            Stage::Downloading => {
                let total = c.disk_bytes.max(1);
                let f = (s.grown as f32 / total as f32).clamp(0.0, 0.99);
                Some(Progress {
                    fraction: f,
                    text: format!(
                        "Downloading {}: about {} of {}",
                        c.name,
                        gb(s.grown.min(total)),
                        gb(total)
                    ),
                })
            }
            Stage::Starting(f) => Some(Progress {
                fraction: f.unwrap_or(0.0).clamp(0.0, 1.0),
                text: match f {
                    Some(f) => format!("Loading {} into memory: {:.0}%", c.name, f * 100.0),
                    None => format!("Loading {} into memory...", c.name),
                },
            }),
            Stage::Testing => Some(Progress {
                fraction: 1.0,
                text: "Asking the model a short question...".into(),
            }),
            Stage::Done => Some(Progress {
                fraction: 1.0,
                text: "Done.".into(),
            }),
            _ => None,
        }
    }

    /// What the model answered to the test.
    pub fn test_reply(&self) -> Option<TestReport> {
        lock(&self.shared).reply.clone()
    }

    /// The model that was just set up, once: the window makes the assistant use it.
    pub fn take_finished(&mut self) -> Option<String> {
        lock(&self.shared).finished.take()
    }

    /// What is on show, for tests and agents.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            step: self.step,
            chosen: self.chosen.clone(),
            stage: match self.stage() {
                Stage::Idle => "idle",
                Stage::Downloading => "downloading",
                Stage::Starting(_) => "starting",
                Stage::Testing => "testing",
                Stage::Done => "done",
                Stage::Failed(_) => "failed",
            }
            .into(),
            blocked: self.blocked(),
        }
    }

    /// The window in one or two sentences, for `ui_state`: which step it is on, what is
    /// chosen, and what the buttons do.
    pub fn describe(&self) -> String {
        let step = self.step;
        let mut out = format!(
            "Set up a model on this computer: step {} of 4, {} (`{}`).",
            step.number(),
            step.title(),
            step.id()
        );
        match step {
            SetupStep::Check => match self.survey() {
                SurveyState::Loading => out.push_str(" Looking at the computer."),
                SurveyState::Failed(e) => out.push_str(&format!(" It failed: {e}")),
                SurveyState::Ready(s) => {
                    out.push_str(&format!(" {}", s.computer.lines().join(" ")))
                }
            },
            SetupStep::PickModel => {
                if let SurveyState::Ready(s) = self.survey() {
                    let list: Vec<String> = s
                        .choices
                        .iter()
                        .take(6)
                        .map(|c| format!("{} ({})", c.id, c.fit.label()))
                        .collect();
                    out.push_str(&format!(" Models: {}.", list.join(", ")));
                }
                match &self.chosen {
                    Some(id) => out.push_str(&format!(" Chosen: {id}.")),
                    None => out.push_str(" None chosen yet; the person picks one."),
                }
            }
            SetupStep::PickCards => {
                if let Some(t) = self.fit_text() {
                    out.push_str(&format!(" {t}"));
                }
            }
            SetupStep::Download => match self.stage() {
                Stage::Failed(e) => out.push_str(&format!(" It failed: {e}")),
                _ => out.push_str(&format!(" Stage: {}.", self.snapshot().stage)),
            },
        }
        match self.blocked() {
            Some(why) => out.push_str(&format!(" Next is not possible now: {why}")),
            None if step == SetupStep::Download => {
                out.push_str(" Next closes the window; the model is ready.")
            }
            None => out.push_str(" Next is possible."),
        }
        out
    }

    // -- doing --------------------------------------------------------------------------------

    /// Goes on. On the third step this starts the download (the person is asked first).
    pub fn go_next(&mut self) -> bool {
        if self.blocked().is_some() {
            return false;
        }
        match self.step.next() {
            Some(SetupStep::Download) => {
                self.step = SetupStep::Download;
                self.begin();
            }
            Some(n) => self.step = n,
            None => self.closed = true,
        }
        true
    }

    /// Goes back one step. Leaving the last step while it works stops waiting for it.
    pub fn go_back(&mut self) -> bool {
        let Some(p) = self.step.previous() else {
            return false;
        };
        if self.step == SetupStep::Download {
            self.abandon();
        }
        self.step = p;
        true
    }

    /// Closes the setup. A download in progress is no longer waited for; what arrived stays and
    /// is picked up again next time.
    pub fn cancel(&mut self) {
        self.abandon();
        self.closed = true;
    }

    fn abandon(&mut self) {
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let mut s = lock(&self.shared);
        s.run += 1;
        s.stage = None;
        s.reply = None;
    }

    /// Tries the last step again after a failure.
    pub fn retry(&mut self) {
        if self.step == SetupStep::Download && matches!(self.stage(), Stage::Failed(_)) {
            self.begin();
        }
    }

    fn begin(&mut self) {
        let (Some(choice), Some(draft)) = (self.chosen(), self.draft.clone()) else {
            return;
        };
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let run = {
            let mut s = lock(&self.shared);
            s.run += 1;
            s.stage = Some(Stage::Downloading);
            s.grown = 0;
            s.reply = None;
            s.run
        };
        let job = Job {
            probe: self.probe.clone(),
            serving: self.serving.clone(),
            store: self.store.clone(),
            shared: self.shared.clone(),
            repaint: self.repaint.clone(),
            run,
        };
        self.task = Some(self.rt.spawn(job.go(choice, draft)));
    }
}

fn look_error(e: &ProtoError) -> String {
    format!(
        "KRAKEN could not look at this computer: {}. Check that krakend is running, then try again.",
        e.message
    )
}

struct Job {
    probe: Arc<dyn SetupProbe>,
    serving: Arc<dyn ServingApi>,
    store: LocalModelStore,
    shared: Arc<Mutex<Shared>>,
    repaint: Option<Repaint>,
    run: u64,
}

impl Job {
    /// Sets the stage unless the person moved on (cancelled, went back) in the meantime.
    fn set(&self, stage: Stage) -> bool {
        let mut s = lock(&self.shared);
        if s.run != self.run {
            return false;
        }
        s.stage = Some(stage);
        drop(s);
        LocalSetup::wake(&self.repaint);
        true
    }

    fn fail(&self, why: String) {
        self.set(Stage::Failed(why));
    }

    async fn go(self, choice: Choice, draft: LocalModel) {
        let sampler = self.sample();
        let installed = self.probe.install(&choice.id, choice.engine).await;
        sampler.abort();
        if let Err(e) = installed {
            self.fail(download_error(&e));
            return;
        }
        if let Err(e) = self.apply(&choice, &draft) {
            self.fail(e);
            return;
        }
        if !self.set(Stage::Starting(None)) {
            return;
        }
        match self.start(&choice).await {
            Ok(()) => {}
            Err(e) => {
                self.fail(e);
                return;
            }
        }
        if !self.set(Stage::Testing) {
            return;
        }
        match self.probe.test(&choice.id).await {
            Ok(r) => {
                {
                    let mut s = lock(&self.shared);
                    if s.run != self.run {
                        return;
                    }
                    s.reply = Some(r);
                    s.finished = Some(choice.id.clone());
                }
                self.set(Stage::Done);
            }
            Err(e) => self.fail(format!(
                "The model started but did not answer the test question: {e} You can press Try again."
            )),
        }
    }

    /// Watches the disk grow while the download runs.
    fn sample(&self) -> JoinHandle<()> {
        let (probe, shared, repaint, run) = (
            self.probe.clone(),
            self.shared.clone(),
            self.repaint.clone(),
            self.run,
        );
        let base = probe.bytes_on_disk();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SAMPLE_EVERY).await;
                let now = probe.bytes_on_disk();
                {
                    let mut s = lock(&shared);
                    if s.run != run {
                        return;
                    }
                    s.grown = now.saturating_sub(base);
                }
                LocalSetup::wake(&repaint);
            }
        })
    }

    /// Puts the chosen cards and the name into the model's record, and makes sure it is served
    /// automatically.
    fn apply(&self, choice: &Choice, draft: &LocalModel) -> Result<(), String> {
        let mut model = self
            .store
            .load()
            .map_err(|e| {
                format!("The model was downloaded, but the model list could not be read: {e}")
            })?
            .into_iter()
            .find(|m| m.id == choice.id)
            .ok_or_else(|| {
                "The model was downloaded, but it is not in the model list. Press Try again."
                    .to_string()
            })?;
        model.name = draft.name.clone();
        model.devices = draft.devices.clone();
        model.cpu_only = draft.cpu_only;
        model.multi_gpu = draft.multi_gpu;
        model.shares = draft.shares.clone();
        model.main_device = draft.main_device.clone();
        model.autostart = true;
        self.store
            .update(&model)
            .map_err(|e| format!("The settings of the model could not be saved: {e}"))
    }

    async fn start(&self, choice: &Choice) -> Result<(), String> {
        let status = self
            .serving
            .start_model(&choice.id, StartOptions::default())
            .await
            .map_err(|e| start_error(&e))?;
        let deadline = Instant::now() + LOAD_TIMEOUT;
        let mut status = status;
        loop {
            match &status.state {
                ModelState::Ready => return Ok(()),
                ModelState::Failed { message } => {
                    return Err(format!(
                        "The model did not start: {message} Go back to pick other cards or a smaller model."
                    ));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(
                    "The model is taking very long to load. Go back and pick a smaller model, or try again."
                        .into(),
                );
            }
            if !self.set(Stage::Starting(status.load_fraction)) {
                return Ok(());
            }
            tokio::time::sleep(LOAD_POLL).await;
            status = self.refresh(&choice.id).await?;
        }
    }

    async fn refresh(&self, id: &str) -> Result<ModelStatus, String> {
        let reply = self.serving.models().await.map_err(|e| start_error(&e))?;
        reply
            .models
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| "The model disappeared from the list while it was loading.".into())
    }
}

fn download_error(e: &ProtoError) -> String {
    if e.details
        .as_ref()
        .is_some_and(|d| d["approval"] == "denied")
        || e.message.contains("approval denied")
    {
        return "Nothing was downloaded because it was not allowed. Press Try again to be asked once more, or Cancel."
            .into();
    }
    match e.code {
        ErrorCode::Unsupported if e.message.contains("missing what Strata needs") => format!(
            "This computer is missing something this model needs. {} Then press Try again.",
            e.message
        ),
        _ => format!(
            "The download did not finish: {} Check your internet connection and the free disk space, then press Try again. What arrived is kept.",
            e.message
        ),
    }
}

fn start_error(e: &ProtoError) -> String {
    if e.details.as_ref().is_some_and(|d| d["reason"] == "no_fit") {
        return format!(
            "{} Go back and pick another card or a smaller model.",
            e.message
        );
    }
    format!(
        "The model was downloaded but could not be started: {} You can press Try again.",
        e.message
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use kraken_host::KrakenConfig;
    use kraken_proto::infer::{DeviceState, GpuVendor};

    use super::*;
    use crate::infer::fake::{FakeCall, FakeServing, FakeSetupProbe, sample_survey};

    fn card(index: u32, vendor: GpuVendor, name: &str, gib: u64, state: DeviceState) -> DeviceInfo {
        DeviceInfo {
            index,
            uuid: format!("GPU-{index}"),
            vendor,
            name: name.into(),
            vram_total: gib << 30,
            vram_used: 512 << 20,
            state,
        }
    }

    fn rtx() -> DeviceInfo {
        card(0, GpuVendor::Nvidia, "RTX 3070 Ti", 8, DeviceState::Ok)
    }

    #[test]
    fn the_computer_is_described_in_plain_words() {
        let raw = sample_survey(
            vec![
                rtx(),
                card(
                    1,
                    GpuVendor::Intel,
                    "Intel UHD 750",
                    1,
                    DeviceState::Unsupported {
                        reason: "not supported yet".into(),
                    },
                ),
            ],
            31.2,
            412.0,
        );
        let s = survey_from(&raw, &model_catalog());
        let lines = s.computer.lines();
        assert_eq!(
            lines[0],
            "Your graphics card: RTX 3070 Ti with 8.0 GB of video memory"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("Intel UHD 750 cannot be used: not supported yet"))
        );
        assert!(lines.iter().any(|l| l == "Computer memory (RAM): 31.2 GB"));
        assert!(lines.iter().any(|l| l == "Free disk space: 412 GB"));

        let none = survey_from(&sample_survey(Vec::new(), 16.0, 100.0), &model_catalog());
        assert!(none.computer.lines()[0].contains("run on the processor"));
    }

    #[test]
    fn models_are_judged_against_the_card_and_the_suggested_one_comes_first() {
        let s = survey_from(&sample_survey(vec![rtx()], 31.0, 400.0), &model_catalog());
        let first = &s.choices[0];
        assert!(first.recommended);
        assert_eq!(first.id, "qwen3-8b-q4_k_m");
        assert_eq!(first.fit, FitLevel::Fits);
        let by = |id: &str| s.choices.iter().find(|c| c.id == id).unwrap();
        assert_eq!(by("qwen3-4b-q4_k_m").fit, FitLevel::Fits);
        assert_eq!(by("qwen3-32b-q4_k_m").fit, FitLevel::WontFit);
        assert!(by("qwen3-32b-q4_k_m").why.contains("free in"));
        assert!(!by("qwen3-32b-q4_k_m").selectable());
        let ranks: Vec<u8> = s.choices.iter().skip(1).map(|c| c.fit.rank()).collect();
        assert!(
            ranks.windows(2).all(|w| w[0] <= w[1]),
            "fits, then tight, then won't"
        );
        assert!(first.download_label().ends_with("download"));
    }

    #[test]
    fn disk_and_processor_limits_count_and_strata_needs_an_nvidia_card() {
        let low_disk = survey_from(&sample_survey(vec![rtx()], 31.0, 3.0), &model_catalog());
        let big = low_disk
            .choices
            .iter()
            .find(|c| c.id == "qwen3-8b-q4_k_m")
            .unwrap();
        assert_eq!(big.fit, FitLevel::WontFit);
        assert!(big.why.contains("free disk"));

        let cpu = survey_from(&sample_survey(Vec::new(), 64.0, 400.0), &model_catalog());
        let c14 = cpu
            .choices
            .iter()
            .find(|c| c.id == "qwen3-14b-q4_k_m")
            .unwrap();
        assert_eq!(
            c14.fit,
            FitLevel::Tight,
            "big models are slow on the processor"
        );
        assert!(cpu.choices.iter().all(|c| c.engine == LocalEngine::Llama));

        let nv = survey_from(&sample_survey(vec![rtx()], 64.0, 400.0), &model_catalog());
        let strata = nv
            .choices
            .iter()
            .find(|c| c.engine == LocalEngine::Strata)
            .unwrap();
        assert_eq!(strata.id, "strata-iq1-m");
        assert_eq!(strata.fit, FitLevel::Fits);
        assert!(strata.name.ends_with("(Strata)"));
        let amd = survey_from(
            &sample_survey(
                vec![card(0, GpuVendor::Amd, "RX 7900", 24, DeviceState::Ok)],
                64.0,
                400.0,
            ),
            &model_catalog(),
        );
        assert!(amd.choices.iter().all(|c| c.engine == LocalEngine::Llama));
    }

    struct Rig {
        rt: tokio::runtime::Runtime,
        fake: Arc<FakeServing>,
        probe: Arc<FakeSetupProbe>,
        config: PathBuf,
        setup: LocalSetup,
        _dir: tempfile::TempDir,
    }

    fn rig_with(raw: RawSurvey, slow: Duration) -> Rig {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kraken/config.toml");
        KrakenConfig::default().save(&config).unwrap();
        let fake = Arc::new(FakeServing::new(Vec::new(), raw.devices.clone()));
        let probe = Arc::new(FakeSetupProbe::new(raw, fake.clone(), &config).slow(slow));
        let setup = LocalSetup::new(
            probe.clone(),
            fake.clone(),
            Some(config.clone()),
            rt.handle().clone(),
        );
        Rig {
            rt,
            fake,
            probe,
            config,
            setup,
            _dir: dir,
        }
    }

    fn rig() -> Rig {
        rig_with(sample_survey(vec![rtx()], 31.0, 400.0), Duration::ZERO)
    }

    impl Rig {
        fn until(&mut self, what: &str, cond: impl Fn(&LocalSetup) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !cond(&self.setup) {
                assert!(Instant::now() < deadline, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = &self.rt;
        }

        fn go_to_download(&mut self) {
            self.until("the survey", |s| {
                matches!(s.survey(), SurveyState::Ready(_))
            });
            assert!(self.setup.go_next());
            assert!(self.setup.choose("qwen3-8b-q4_k_m"));
            assert!(self.setup.go_next());
            assert!(self.setup.go_next());
        }
    }

    #[test]
    fn the_steps_go_in_order_and_next_waits_for_what_it_needs() {
        let mut r = rig();
        assert_eq!(r.setup.step(), SetupStep::Check);
        assert_eq!(r.setup.step().number(), 1);
        r.until("the survey", |s| {
            matches!(s.survey(), SurveyState::Ready(_))
        });
        assert!(!r.setup.go_back(), "nothing before the first step");
        assert!(r.setup.go_next());
        assert_eq!(r.setup.step(), SetupStep::PickModel);
        assert!(!r.setup.go_next(), "no model picked");
        assert_eq!(r.setup.blocked().as_deref(), Some("Pick a model first."));
        assert!(!r.setup.choose("qwen3-32b-q4_k_m"), "does not fit");
        assert!(!r.setup.choose("nonsense"));
        assert!(r.setup.choose("qwen3-8b-q4_k_m"));
        assert!(r.setup.go_next());
        assert_eq!(r.setup.step().id(), "pick_cards");
        let d = r.setup.draft().unwrap();
        assert_eq!(d.devices.len(), 1, "the card is chosen already");
        assert_eq!(d.devices[0].uuid, "GPU-0");
        assert!(r.setup.fit_text().unwrap().contains("fits on these cards"));
        assert!(r.setup.go_back());
        assert_eq!(r.setup.step(), SetupStep::PickModel);
        assert!(r.setup.describe().contains("step 2 of 4"));
        assert!(r.setup.describe().contains("Chosen: qwen3-8b-q4_k_m"));
    }

    #[test]
    fn setting_up_downloads_registers_starts_and_tests() {
        let mut r = rig_with(
            sample_survey(vec![rtx()], 31.0, 400.0),
            Duration::from_millis(200),
        );
        r.until("the survey", |s| {
            matches!(s.survey(), SurveyState::Ready(_))
        });
        r.setup.go_next();
        r.setup.choose("qwen3-8b-q4_k_m");
        r.setup.go_next();
        r.setup.go_next();
        assert_eq!(r.setup.step(), SetupStep::Download);
        assert!(r.setup.blocked().is_some(), "not done yet");
        r.until("the download shows", |s| {
            s.progress()
                .is_some_and(|p| p.text.starts_with("Downloading Qwen3 8B"))
        });
        r.until("done", |s| s.stage() == Stage::Done);

        assert_eq!(
            r.probe.installs(),
            vec![("qwen3-8b-q4_k_m".into(), LocalEngine::Llama)]
        );
        let reply = r.setup.test_reply().unwrap();
        assert_eq!(
            (reply.reply.as_str(), reply.model.as_str()),
            ("ready", "qwen3-8b-q4_k_m")
        );
        assert!(r.fake.calls().contains(&FakeCall::Start(
            "qwen3-8b-q4_k_m".into(),
            StartOptions::default()
        )));
        let cfg = KrakenConfig::from_file(&r.config).unwrap();
        let m = &cfg.local_models[0];
        assert_eq!(m.name, "Qwen3 8B");
        assert!(m.autostart);
        assert_eq!(m.devices.len(), 1);
        assert_eq!(
            cfg.provider.unwrap()["model"],
            "qwen3-8b-q4_k_m",
            "the assistant uses it"
        );
        assert_eq!(r.setup.take_finished().as_deref(), Some("qwen3-8b-q4_k_m"));
        assert!(r.setup.take_finished().is_none(), "once");
        assert!(r.setup.blocked().is_none());
        assert!(r.setup.go_next(), "Done closes the window");
        assert!(r.setup.is_closed());
    }

    #[test]
    fn the_cards_chosen_in_step_three_are_what_the_model_is_saved_with() {
        let two = vec![
            rtx(),
            card(1, GpuVendor::Nvidia, "RTX 3060", 12, DeviceState::Ok),
        ];
        let mut r = rig_with(sample_survey(two, 31.0, 400.0), Duration::ZERO);
        r.until("the survey", |s| {
            matches!(s.survey(), SurveyState::Ready(_))
        });
        r.setup.go_next();
        r.setup.choose("qwen3-8b-q4_k_m");
        r.setup.go_next();
        assert_eq!(
            r.setup.draft().unwrap().devices[0].uuid,
            "GPU-1",
            "the larger card"
        );
        r.setup.edit_draft(|m, found| {
            let first = DeviceRef {
                uuid: "GPU-0".into(),
                index: 0,
                vendor: GpuVendor::Nvidia,
            };
            card::set_device(m, found, &first, true);
            card::set_mode(m, MultiGpuMode::SplitEveryLayer);
        });
        r.setup.go_next();
        r.until("done", |s| s.stage() == Stage::Done);
        let cfg = KrakenConfig::from_file(&r.config).unwrap();
        let m = &cfg.local_models[0];
        assert_eq!(m.devices.len(), 2);
        assert_eq!(m.multi_gpu, MultiGpuMode::SplitEveryLayer);
    }

    #[test]
    fn a_refused_download_says_so_and_trying_again_works() {
        let mut r = rig();
        r.probe.fail_install(
            ProtoError::new(ErrorCode::Unsupported, "approval denied: x")
                .with_details(serde_json::json!({"approval": "denied"})),
        );
        r.go_to_download();
        r.until("the failure", |s| matches!(s.stage(), Stage::Failed(_)));
        let Stage::Failed(why) = r.setup.stage() else {
            unreachable!()
        };
        assert!(why.starts_with("Nothing was downloaded"), "{why}");
        assert!(r.setup.describe().contains("It failed"));
        r.setup.retry();
        r.until("done", |s| s.stage() == Stage::Done);
    }

    #[test]
    fn a_failed_download_start_or_test_each_tell_what_happened() {
        let mut r = rig();
        r.probe
            .fail_install(ProtoError::new(ErrorCode::Internal, "connection reset"));
        r.go_to_download();
        r.until("failure", |s| matches!(s.stage(), Stage::Failed(_)));
        let Stage::Failed(why) = r.setup.stage() else {
            unreachable!()
        };
        assert!(
            why.contains("did not finish") && why.contains("connection reset"),
            "{why}"
        );
        assert!(why.contains("internet connection"));

        let mut r = rig();
        r.fake.refuse_start("qwen3-8b-q4_k_m");
        r.go_to_download();
        r.until("failure", |s| matches!(s.stage(), Stage::Failed(_)));
        let Stage::Failed(why) = r.setup.stage() else {
            unreachable!()
        };
        assert!(
            why.contains("pick another card or a smaller model"),
            "{why}"
        );

        let mut r = rig();
        r.probe.fail_test("The model did not answer.");
        r.go_to_download();
        r.until("failure", |s| matches!(s.stage(), Stage::Failed(_)));
        let Stage::Failed(why) = r.setup.stage() else {
            unreachable!()
        };
        assert!(why.contains("did not answer the test question"), "{why}");
        r.setup.retry();
        r.until("done", |s| s.stage() == Stage::Done);
    }

    #[test]
    fn going_back_or_cancelling_stops_waiting_and_a_late_result_is_ignored() {
        let mut r = rig_with(
            sample_survey(vec![rtx()], 31.0, 400.0),
            Duration::from_millis(300),
        );
        r.go_to_download();
        assert!(r.setup.go_back());
        assert_eq!(r.setup.step(), SetupStep::PickCards);
        assert_eq!(r.setup.stage(), Stage::Idle);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(r.setup.stage(), Stage::Idle);
        assert!(r.setup.take_finished().is_none());
        r.setup.cancel();
        assert!(r.setup.is_closed());
    }

    #[test]
    fn a_survey_that_fails_says_what_to_do_and_can_be_repeated() {
        let mut r = rig();
        r.probe.fail_survey("no daemon");
        r.setup.look();
        r.until("the failure", |s| {
            matches!(s.survey(), SurveyState::Failed(_))
        });
        let SurveyState::Failed(e) = r.setup.survey() else {
            unreachable!()
        };
        assert!(e.contains("no daemon") && e.contains("try again"));
        assert!(r.setup.blocked().is_some());
        assert!(!r.setup.go_next());
    }
}

//! `local_model_recommend` and `local_model_setup`: pick and install a model that runs on this
//! computer.
//!
//! The recommendation is pure (`kraken-infer`: hardware detection and the bundled, hash-pinned
//! catalog). Setup downloads, so it asks for approval first with the download size and disk use,
//! exactly like `rewrite_program` does for running the original program, and only ever fetches
//! catalog entries (an argument names an entry id, never a URL).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kraken_infer::strata::{self, Assessment, Fit, StrataManifest, StrataModel};
use kraken_infer::{
    EngineChoice, GpuApi, HardwareInfo, ModelEntry, Recommendation, SystemProbe, detect_hardware,
    model_catalog, models_dir_with, recommend,
};
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::{ApprovalDecision, ApprovalRequest, CallContext, Surface};
use crate::session::Session;

/// Which AI feature a local model is set up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalFeature {
    /// The assistant (`[provider]`).
    Assistant,
    /// The rewrite pipeline (`[rewrite]`).
    Rewrite,
}

/// What `local_model_setup` is about to do, handed to the backend after approval.
#[derive(Debug, Clone)]
pub struct LocalSetupPlan {
    pub engine: EngineChoice,
    pub model: ModelEntry,
    pub models_dir: PathBuf,
    pub assign: Vec<LocalFeature>,
    /// Set for the Strata engine: the model with its files, and the pinned manifest. Then
    /// `model` is a summary entry (id, quant, total size).
    pub strata: Option<StrataPlan>,
    /// Where the backend reports progress for a progress bar.
    pub progress: Option<Arc<Mutex<SetupProgress>>>,
}

/// The Strata part of a setup plan.
#[derive(Debug, Clone)]
pub struct StrataPlan {
    pub model: StrataModel,
    pub manifest: StrataManifest,
}

/// Progress of a running setup, shared with whoever draws a progress bar.
#[derive(Debug, Clone, Default)]
pub struct SetupProgress {
    /// 1-based step and number of steps.
    pub step: usize,
    pub steps: usize,
    pub label: String,
    /// Bytes of the current file.
    pub done: u64,
    pub total: u64,
}

impl SetupProgress {
    /// Overall fraction in 0..=1.
    pub fn fraction(&self) -> f32 {
        if self.steps == 0 {
            return 0.0;
        }
        let within = if self.total > 0 {
            (self.done as f32 / self.total as f32).clamp(0.0, 1.0)
        } else {
            0.0
        };
        (self.step.saturating_sub(1) as f32 + within) / self.steps as f32
    }
}

/// What the backend did.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelSetupOut {
    /// Catalog id of the model.
    pub model_id: String,
    /// Where the verified model file is.
    pub path: String,
    /// Engine id and build that will run it.
    pub engine: String,
    /// True: the file's SHA-256 matched the catalog.
    pub sha256_verified: bool,
    /// Features now using the local model.
    pub configured: Vec<LocalFeature>,
    /// What to do next.
    pub note: String,
}

/// Downloads and configures a local model (provided by `kraken-host`; the daemon, the CLI and
/// the GUI attach it).
#[async_trait]
pub trait LocalModelBackend: Send + Sync + std::fmt::Debug {
    /// Installs the engine and the model of `plan`, verifies the model's SHA-256 against
    /// `plan.model.sha256` and writes the configuration for `plan.assign`.
    async fn setup(&self, plan: LocalSetupPlan) -> Result<LocalModelSetupOut, ProtoError>;
}

impl Session {
    /// The attached local-model backend.
    pub fn local_models(&self) -> Result<&Arc<dyn LocalModelBackend>, ProtoError> {
        self.local_models_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "local model setup is not attached to this session; use the kraken CLI, krakend or the GUI",
            )
        })
    }
}

/// A graphics card, as shown.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GpuView {
    pub vendor: String,
    pub name: String,
    /// Video memory in GiB when known.
    pub vram_gib: Option<f64>,
}

/// A catalog model, as shown.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModelView {
    pub id: String,
    pub name: String,
    pub quant: String,
    /// Billions of parameters.
    pub params_b: u32,
    pub file: String,
    pub size_bytes: u64,
    pub sha256: String,
}

impl From<&ModelEntry> for ModelView {
    fn from(m: &ModelEntry) -> Self {
        ModelView {
            id: m.id.clone(),
            name: m.name.clone(),
            quant: m.quant.clone(),
            params_b: m.params_b,
            file: m.file.clone(),
            size_bytes: m.size,
            sha256: m.sha256.clone(),
        }
    }
}

/// Result of `local_model_recommend`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelRecommendOut {
    pub gpus: Vec<GpuView>,
    pub ram_gib: f64,
    pub free_disk_gib: f64,
    pub cpu_cores: u32,
    /// `llama-server` or `strata`.
    pub engine: String,
    /// "llama-server (CUDA)".
    pub engine_label: String,
    /// `cpu`, `cuda`, `rocm`, `vulkan` or `metal`.
    pub gpu_api: String,
    /// The recommended model; none when nothing fits.
    pub model: Option<ModelView>,
    /// Bytes `local_model_setup` would download.
    pub download_bytes: u64,
    /// Bytes it would occupy on disk.
    pub disk_bytes: u64,
    /// Why, in plain sentences.
    pub reasons: Vec<String>,
    /// The Strata engine's models and what is missing for it, when the engine is Strata.
    pub strata: Option<StrataView>,
}

/// One file to download, as shown in the confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DownloadView {
    pub name: String,
    pub url: String,
    pub size_bytes: u64,
    /// Lower-case hex SHA-256 the file must match.
    pub sha256: String,
}

/// Something the computer lacks that KRAKEN will not install.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MissingView {
    pub what: String,
    pub how_to_fix: String,
}

/// One Strata model with its verdict.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StrataCandidateView {
    pub id: String,
    pub name: String,
    pub quant: String,
    pub min_ram_gib: u64,
    /// `fits`, `below_minimum` (offered with the warnings) or `no_disk`.
    pub fit: String,
    pub warnings: Vec<String>,
    /// Rough, unmeasured speed expectation.
    pub speed: String,
    pub download_bytes: u64,
    pub disk_bytes: u64,
    /// Every download this model needs, engine sources included.
    pub downloads: Vec<DownloadView>,
}

/// The Strata part of a recommendation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StrataView {
    /// Best first.
    pub candidates: Vec<StrataCandidateView>,
    /// Id of the recommended candidate.
    pub recommended: Option<String>,
    /// System pieces to install by hand before `local_model_setup` can work.
    pub missing: Vec<MissingView>,
    pub notes: Vec<String>,
    /// The pinned Strata revision.
    pub revision: String,
}

const GIB: f64 = (1u64 << 30) as f64;

fn gib(b: u64) -> f64 {
    (b as f64 / GIB * 10.0).round() / 10.0
}

/// Every download Strata's setup makes for `model`: the two pinned source archives and the files.
pub fn strata_downloads(m: &StrataManifest, model: &StrataModel) -> Vec<DownloadView> {
    let mut v = vec![
        DownloadView {
            name: format!("Strata {} source", m.engine.version),
            url: m.engine.source.url.clone(),
            size_bytes: m.engine.source.size,
            sha256: m.engine.source.sha256.clone(),
        },
        DownloadView {
            name: "llama.cpp source (ggml) pinned by Strata".into(),
            url: m.llama_cpp.url.clone(),
            size_bytes: m.llama_cpp.size,
            sha256: m.llama_cpp.sha256.clone(),
        },
    ];
    v.extend(model.files.iter().map(|f| DownloadView {
        name: f.name.clone(),
        url: f.url.clone(),
        size_bytes: f.size,
        sha256: f.sha256.clone(),
    }));
    v
}

/// Detects the hardware and assesses the Strata models (blocking).
pub fn strata_now() -> (HardwareInfo, Assessment, StrataManifest, PathBuf) {
    let dir = models_dir_with(&|k| std::env::var_os(k)).unwrap_or_else(std::env::temp_dir);
    let hw = detect_hardware(&SystemProbe, &dir);
    let m = strata::manifest();
    let missing = strata::missing_prerequisites(&SystemProbe, &hw, &m.engine.python_min);
    let a = strata::assess(&hw, &m, missing);
    (hw, a, m, dir)
}

fn fit_name(f: Fit) -> &'static str {
    match f {
        Fit::Fits => "fits",
        Fit::BelowMinimum => "below_minimum",
        Fit::NoDisk => "no_disk",
    }
}

/// The view of a Strata assessment: the llama-server style fields filled for Strata, plus
/// `strata` with every candidate.
pub fn strata_view(
    hw: &HardwareInfo,
    a: &Assessment,
    m: &StrataManifest,
) -> LocalModelRecommendOut {
    let base = recommend_view(
        hw,
        &Recommendation {
            engine: EngineChoice {
                id: "strata".into(),
                gpu_api: GpuApi::Cuda,
                label: "Strata".into(),
            },
            model: None,
            download_bytes: 0,
            disk_bytes: 0,
            reasons: Vec::new(),
        },
    );
    let pick = a.recommended.map(|i| &a.candidates[i]);
    let mut reasons = a.notes.clone();
    if let Some(c) = pick {
        reasons.extend(c.warnings.iter().cloned());
    }
    LocalModelRecommendOut {
        model: pick.map(|c| ModelView {
            id: c.model.id.clone(),
            name: c.model.name.clone(),
            quant: c.model.quant.clone(),
            params_b: 0,
            file: c
                .model
                .files
                .first()
                .map(|f| f.name.clone())
                .unwrap_or_default(),
            size_bytes: c.download_bytes,
            sha256: "per file; see strata.candidates[].downloads".into(),
        }),
        download_bytes: pick.map_or(0, |c| {
            c.download_bytes + m.engine.source.size + m.llama_cpp.size
        }),
        disk_bytes: pick.map_or(0, |c| c.disk_bytes),
        reasons,
        strata: Some(StrataView {
            candidates: a
                .candidates
                .iter()
                .map(|c| StrataCandidateView {
                    id: c.model.id.clone(),
                    name: c.model.name.clone(),
                    quant: c.model.quant.clone(),
                    min_ram_gib: c.model.min_ram_gib,
                    fit: fit_name(c.fit).into(),
                    warnings: c.warnings.clone(),
                    speed: c.speed.clone(),
                    download_bytes: c.download_bytes,
                    disk_bytes: c.disk_bytes,
                    downloads: strata_downloads(m, &c.model),
                })
                .collect(),
            recommended: pick.map(|c| c.model.id.clone()),
            missing: a
                .missing
                .iter()
                .map(|x| MissingView {
                    what: x.what.clone(),
                    how_to_fix: x.how_to_fix.clone(),
                })
                .collect(),
            notes: a.notes.clone(),
            revision: format!("v{} ({})", m.engine.version, m.engine.source.commit),
        }),
        engine: "strata".into(),
        engine_label: "Strata".into(),
        gpu_api: "cuda".into(),
        ..base
    }
}

/// Detects the hardware and recommends (blocking: runs `nvidia-smi` and friends).
pub fn recommendation_now() -> (HardwareInfo, Recommendation, PathBuf) {
    let dir = models_dir_with(&|k| std::env::var_os(k)).unwrap_or_else(std::env::temp_dir);
    let hw = detect_hardware(&SystemProbe, &dir);
    let rec = recommend(&hw, &model_catalog());
    (hw, rec, dir)
}

/// The view of a hardware reading and its recommendation.
pub fn recommend_view(hw: &HardwareInfo, rec: &Recommendation) -> LocalModelRecommendOut {
    LocalModelRecommendOut {
        gpus: hw
            .gpus
            .iter()
            .map(|g| GpuView {
                vendor: format!("{:?}", g.vendor).to_lowercase(),
                name: g.name.clone(),
                vram_gib: g.vram_bytes.map(gib),
            })
            .collect(),
        ram_gib: gib(hw.ram_bytes),
        free_disk_gib: gib(hw.free_disk_bytes),
        cpu_cores: hw.cpu_cores,
        engine: rec.engine.id.clone(),
        engine_label: rec.engine.label.clone(),
        gpu_api: format!("{:?}", rec.engine.gpu_api).to_lowercase(),
        model: rec.model.as_ref().map(ModelView::from),
        download_bytes: rec.download_bytes,
        disk_bytes: rec.disk_bytes,
        reasons: rec.reasons.clone(),
        strata: None,
    }
}

/// Arguments of `local_model_recommend`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalModelRecommendArgs {
    /// `strata` assesses the Strata engine and its models (all candidates, missing system
    /// pieces); `llama-server` the llama-server catalog; omitted: Strata only when the machine
    /// meets its minimums, else llama-server.
    #[serde(default)]
    pub engine: Option<String>,
}

/// Recommends an engine and a model for this computer.
pub struct LocalModelRecommend;

#[async_trait]
impl Command for LocalModelRecommend {
    type Args = LocalModelRecommendArgs;
    type Output = LocalModelRecommendOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_recommend",
            "Recommend a local engine and model that fit this computer",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Detects GPU, video memory, RAM, free disk and CPU cores and returns the engine \
             (llama-server on CPU, CUDA or Vulkan; the Strata engine only with 12 GiB video \
             memory, 32 GiB RAM and 80 GiB free disk), the largest model that fits, its download \
             size and the reasons. With `engine: \"strata\"` it assesses Strata, which keeps MoE \
             experts in RAM so a small GPU with much RAM runs big models: every model with fit, \
             warnings and speed, plus missing system pieces. Downloads nothing; \
             `local_model_setup` does.\n\
             Example: local_model_recommend {\"engine\": \"strata\"}",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: LocalModelRecommendArgs,
    ) -> Result<LocalModelRecommendOut, ProtoError> {
        if is_strata(args.engine.as_deref())? {
            let (hw, a, m, _) = tokio::task::spawn_blocking(strata_now)
                .await
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
            return Ok(strata_view(&hw, &a, &m));
        }
        let (hw, rec, _) = tokio::task::spawn_blocking(recommendation_now)
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(recommend_view(&hw, &rec))
    }
}

fn is_strata(engine: Option<&str>) -> Result<bool, ProtoError> {
    match engine {
        None | Some("auto" | "llama-server") => Ok(false),
        Some("strata") => Ok(true),
        Some(other) => Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("unknown engine `{other}`; use `strata` or `llama-server`"),
        )),
    }
}

/// Arguments of `local_model_setup`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalModelSetupArgs {
    /// Catalog id from `local_model_recommend` (`qwen3-8b-q4_k_m`); the recommended model when
    /// left out.
    #[serde(default)]
    pub model: Option<String>,
    /// `strata` sets up the Strata engine (its model ids start with `strata-`); `llama-server`
    /// the catalog. A `strata-` model id implies Strata.
    #[serde(default)]
    pub engine: Option<String>,
    /// Features that should use the model afterwards; the assistant when left out.
    #[serde(default)]
    pub use_for: Option<Vec<LocalFeature>>,
}

/// Downloads a recommended model and configures it, after approval.
pub struct LocalModelSetup;

#[async_trait]
impl Command for LocalModelSetup {
    type Args = LocalModelSetupArgs;
    type Output = LocalModelSetupOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "local_model_setup",
            "Download and configure a local model (asks for approval first)",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Downloads the engine and the model from `local_model_recommend` (or the catalog \
             model you name), checks the model's SHA-256 against the catalog and points the \
             assistant (and optionally the rewrite pipeline) at it. A person is asked first, with \
             the download size and disk use; agents cannot skip that question. Large download.\n\
             Example: local_model_setup {\"model\": \"qwen3-8b-q4_k_m\", \"use_for\": [\"assistant\"]}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: LocalModelSetupArgs,
    ) -> Result<LocalModelSetupOut, ProtoError> {
        let backend = s.local_models()?.clone();
        let want_strata = is_strata(args.engine.as_deref())?
            || args
                .model
                .as_deref()
                .is_some_and(|m| m.starts_with("strata-"));
        let assign = args
            .use_for
            .clone()
            .unwrap_or_else(|| vec![LocalFeature::Assistant]);
        let features = assign
            .iter()
            .map(|f| format!("{f:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(" and ");

        let (engine, model, models_dir, strata_plan, summary, details) = if want_strata {
            let (_, a, m, models_dir) = tokio::task::spawn_blocking(strata_now)
                .await
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
            if !a.missing.is_empty() {
                return Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "this computer is missing what Strata needs; KRAKEN installs no system \
                         software, so install these yourself first: {}",
                        a.missing
                            .iter()
                            .map(|x| format!("{} ({})", x.what, x.how_to_fix))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                ));
            }
            let cand = match &args.model {
                Some(id) => a.candidates.iter().find(|c| &c.model.id == id),
                None => a.recommended.map(|i| &a.candidates[i]),
            }
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "no such Strata model, or none fits the free disk; see `local_model_recommend` with engine strata",
                )
            })?;
            if cand.fit == Fit::NoDisk {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!(
                        "{} does not fit the free disk: {}",
                        cand.model.id,
                        cand.warnings.join(" ")
                    ),
                ));
            }
            let downloads = strata_downloads(&m, &cand.model);
            let total: u64 = downloads.iter().map(|d| d.size_bytes).sum();
            let listing = downloads
                .iter()
                .map(|d| format!("{} ({:.1} GiB)", d.name, gib(d.size_bytes)))
                .collect::<Vec<_>>()
                .join("; ");
            let mut summary = format!(
                "download {} files for Strata {} ({:.1} GiB in total, {:.1} GiB of disk under \
                 <data dir>/engines/strata, compile the engine there, no sudo), and set it up for the {}: {}",
                downloads.len(),
                cand.model.quant,
                gib(total),
                gib(cand.disk_bytes),
                features,
                listing
            );
            if cand.fit == Fit::BelowMinimum {
                summary.push_str(&format!(" WARNING: {}", cand.warnings.join(" ")));
            }
            let details = serde_json::json!({
                "model": cand.model.id,
                "download_bytes": total,
                "disk_bytes": cand.disk_bytes,
                "downloads": downloads,
            });
            let synth = ModelEntry {
                id: cand.model.id.clone(),
                name: cand.model.name.clone(),
                params_b: 0,
                quant: cand.model.quant.clone(),
                file: cand
                    .model
                    .files
                    .first()
                    .map(|f| f.name.clone())
                    .unwrap_or_default(),
                url: cand
                    .model
                    .files
                    .first()
                    .map(|f| f.url.clone())
                    .unwrap_or_default(),
                size: cand.download_bytes,
                sha256: cand
                    .model
                    .files
                    .first()
                    .map(|f| f.sha256.clone())
                    .unwrap_or_default(),
                license: cand.model.license.clone(),
            };
            let plan = StrataPlan {
                model: cand.model.clone(),
                manifest: m,
            };
            (
                EngineChoice {
                    id: "strata".into(),
                    gpu_api: GpuApi::Cuda,
                    label: "Strata".into(),
                },
                synth,
                models_dir,
                Some(plan),
                summary,
                details,
            )
        } else {
            let (_, rec, models_dir) = tokio::task::spawn_blocking(recommendation_now)
                .await
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
            let model = match &args.model {
                Some(id) => model_catalog()
                    .into_iter()
                    .find(|m| &m.id == id)
                    .ok_or_else(|| {
                        ProtoError::new(
                            ErrorCode::InvalidArgument,
                            format!("no model `{id}` in the catalog; see `local_model_recommend`"),
                        )
                    })?,
                None => rec.model.clone().ok_or_else(|| {
                    ProtoError::new(
                        ErrorCode::InvalidArgument,
                        format!("no model fits this computer: {}", rec.reasons.join(" ")),
                    )
                })?,
            };
            let summary = format!(
                "download {} ({}, {:.1} GiB) with {}, using {:.1} GiB of disk under {}, and set it up for the {}",
                model.name,
                model.quant,
                gib(model.size),
                rec.engine.label,
                gib(model.size),
                models_dir.display(),
                features
            );
            let details = serde_json::json!({
                "model": model.id,
                "download_bytes": model.size,
                "disk_bytes": model.size,
                "url": model.url,
            });
            (rec.engine, model, models_dir, None, summary, details)
        };

        if ctx.needs_user_approval() || ctx.surface == Surface::Gui {
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "local_model_setup".into(),
                    summary,
                    args: details,
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
        backend
            .setup(LocalSetupPlan {
                engine,
                model,
                models_dir,
                assign,
                strata: strata_plan,
                progress: None,
            })
            .await
    }
}

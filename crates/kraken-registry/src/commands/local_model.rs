//! `local_model_recommend` and `local_model_setup`: pick and install a model that runs on this
//! computer.
//!
//! The recommendation is pure (`kraken-infer`: hardware detection and the bundled, hash-pinned
//! catalog). Setup downloads, so it asks for approval first with the download size and disk use,
//! exactly like `rewrite_program` does for running the original program, and only ever fetches
//! catalog entries (an argument names an entry id, never a URL).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use kraken_infer::{
    EngineChoice, HardwareInfo, ModelEntry, Recommendation, SystemProbe, detect_hardware,
    model_catalog, models_dir_with, recommend,
};
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::NoArgs;
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
}

const GIB: f64 = (1u64 << 30) as f64;

fn gib(b: u64) -> f64 {
    (b as f64 / GIB * 10.0).round() / 10.0
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
    }
}

/// Recommends an engine and a model for this computer.
pub struct LocalModelRecommend;

#[async_trait]
impl Command for LocalModelRecommend {
    type Args = NoArgs;
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
             size and the reasons. Downloads nothing; `local_model_setup` does.\n\
             Example: local_model_recommend {}",
        )
    }

    async fn run(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<LocalModelRecommendOut, ProtoError> {
        let (hw, rec, _) = tokio::task::spawn_blocking(recommendation_now)
            .await
            .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(recommend_view(&hw, &rec))
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
        let assign = args
            .use_for
            .unwrap_or_else(|| vec![LocalFeature::Assistant]);
        if ctx.needs_user_approval() || ctx.surface == Surface::Gui {
            let summary = format!(
                "download {} ({}, {:.1} GiB) with {}, using {:.1} GiB of disk under {}, and set it up for the {}",
                model.name,
                model.quant,
                gib(model.size),
                rec.engine.label,
                gib(model.size),
                models_dir.display(),
                assign
                    .iter()
                    .map(|f| format!("{f:?}").to_lowercase())
                    .collect::<Vec<_>>()
                    .join(" and ")
            );
            let decision = ctx
                .approval
                .request(ApprovalRequest {
                    command: "local_model_setup".into(),
                    summary,
                    args: serde_json::json!({
                        "model": model.id,
                        "download_bytes": model.size,
                        "disk_bytes": model.size,
                        "url": model.url,
                    }),
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
                engine: rec.engine,
                model,
                models_dir,
                assign,
            })
            .await
    }
}

//! `local_model_setup` for real: installs llama-server, downloads the chosen model with its
//! SHA-256 checked against the catalog, and points the assistant and/or the rewrite pipeline at
//! it in `config.toml`.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use kraken_infer::GpuApi;
use kraken_proto::{ErrorCode, LocalEngine, ProtoError};
use kraken_registry::commands::{
    LocalFeature, LocalModelBackend, LocalModelSetupOut, LocalSetupPlan,
};

use crate::config::KrakenConfig;
use crate::infer::{local_provider_table, new_local_model};
use crate::llama_setup::{LlamaLayout, choose, current_releases, install_llama};
use crate::provision::{ArchiveFormat, ArtifactSpec, Fetcher, HttpsFetcher, download};
use crate::strata_setup::{
    ModelSource, Runner, StrataError, StrataLayout, StrataRequest, SystemRunner, install_strata,
};

/// The base URL the written provider points at: llama-server's default port.
pub const LOCAL_BASE_URL: &str = "http://127.0.0.1:8080/v1";

/// Installs and configures local models on this computer.
pub struct LocalModels {
    fetcher: Arc<dyn Fetcher>,
    config_path: Option<std::path::PathBuf>,
    runner: Option<Arc<dyn Runner>>,
}

impl std::fmt::Debug for LocalModels {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalModels").finish_non_exhaustive()
    }
}

impl LocalModels {
    /// Real downloads, the user's `config.toml`.
    pub fn system() -> Result<Self, ProtoError> {
        let fetcher = HttpsFetcher::new().map_err(internal)?;
        Ok(LocalModels {
            fetcher: Arc::new(fetcher),
            config_path: KrakenConfig::default_path(),
            runner: None,
        })
    }

    /// A given fetcher and config file (tests).
    pub fn new(fetcher: Arc<dyn Fetcher>, config_path: Option<std::path::PathBuf>) -> Self {
        LocalModels {
            fetcher,
            config_path,
            runner: None,
        }
    }

    /// Runs the Strata build commands through `runner` instead of the system (tests).
    pub fn with_runner(mut self, runner: Arc<dyn Runner>) -> Self {
        self.runner = Some(runner);
        self
    }

    async fn setup_strata(
        &self,
        plan: LocalSetupPlan,
        sp: kraken_registry::commands::StrataPlan,
    ) -> Result<LocalModelSetupOut, ProtoError> {
        let data_dir = plan
            .models_dir
            .parent()
            .ok_or_else(|| internal("the models directory has no parent"))?
            .to_path_buf();
        let layout = StrataLayout::in_data_dir(&data_dir);
        let python_min = sp.manifest.engine.python_min.clone();
        let method = sp.options.method;
        let missing = tokio::task::spawn_blocking(move || {
            let hw = kraken_infer::detect_hardware(&kraken_infer::SystemProbe, &data_dir);
            kraken_infer::strata::missing_prerequisites(
                &kraken_infer::SystemProbe,
                &hw,
                &python_min,
                method,
            )
        })
        .await
        .map_err(internal)?;
        let runner: Arc<dyn Runner> = match &self.runner {
            Some(r) => r.clone(),
            None => Arc::new(SystemRunner::new(&layout)),
        };
        let sink = plan.progress.clone();
        let mut on_event = |e: crate::strata_setup::StrataEvent| {
            if let Some(p) = &sink
                && let Ok(mut p) = p.lock()
            {
                *p = kraken_registry::commands::SetupProgress {
                    step: e.index,
                    steps: e.steps,
                    label: e.label,
                    done: e.done,
                    total: e.total,
                };
            }
        };
        let request = StrataRequest {
            manifest: &sp.manifest,
            options: sp.options,
            model: match &sp.existing {
                Some(m) => ModelSource::Existing(m),
                None => ModelSource::Catalog(&sp.model),
            },
        };
        let out = install_strata(
            &layout,
            self.fetcher.as_ref(),
            runner.as_ref(),
            &request,
            missing,
            &mut on_event,
        )
        .await
        .map_err(|e| match e {
            StrataError::Missing(_) => ProtoError::new(ErrorCode::Unsupported, e.to_string()),
            other => internal(other),
        })?;

        // Register the supervised server with kraken-infer's manifest directory.
        let manifests = layout
            .root()
            .parent()
            .and_then(Path::parent)
            .map(|d| d.join("infer").join("manifests"))
            .ok_or_else(|| internal("no manifest directory"))?;
        std::fs::create_dir_all(&manifests).map_err(internal)?;
        std::fs::copy(&out.backend_manifest, manifests.join("strata.toml")).map_err(internal)?;

        let mut configured = Vec::new();
        if let Some(cfg_path) = &self.config_path {
            write_local_provider(
                cfg_path,
                &sp.model.id,
                LocalEngine::Strata,
                &out.gguf_dir,
                &plan.assign,
            )?;
            configured = plan.assign.clone();
        }
        Ok(LocalModelSetupOut {
            model_id: sp.model.id.clone(),
            path: out.gguf_dir.display().to_string(),
            engine: out.description.clone(),
            sha256_verified: sp.existing.is_none(),
            configured,
            note: format!(
                "Start it with `kraken infer start {}` (or Settings); KRAKEN supervises it and \
                 starts it by itself when the assistant needs it. Setup log: {}",
                sp.model.id.clone(),
                layout.log().display()
            ),
        })
    }
}

fn internal(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, e.to_string())
}

/// Adds the model to `[[local_models]]` (or updates its file) and points `[provider]` /
/// `[rewrite]` at it as `local { model = id }`, keeping the rest of the file.
pub fn write_local_provider(
    path: &Path,
    model_id: &str,
    engine: LocalEngine,
    model_path: &Path,
    features: &[LocalFeature],
) -> Result<(), ProtoError> {
    let mut cfg = KrakenConfig::from_file(path).map_err(internal)?;
    match cfg.local_models.iter_mut().find(|m| m.id == model_id) {
        Some(m) => {
            m.engine = engine;
            m.model_path = model_path.to_path_buf();
        }
        None => cfg
            .local_models
            .push(new_local_model(model_id, engine, model_path.to_path_buf())),
    }
    let table = local_provider_table(model_id);
    for f in features {
        match f {
            LocalFeature::Assistant => cfg.provider = Some(table.clone()),
            LocalFeature::Rewrite => cfg.rewrite = Some(table.clone()),
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    cfg.save(path).map_err(internal)
}

#[async_trait]
impl LocalModelBackend for LocalModels {
    async fn setup(&self, plan: LocalSetupPlan) -> Result<LocalModelSetupOut, ProtoError> {
        if let Some(sp) = plan.strata.clone() {
            return self.setup_strata(plan, sp).await;
        }
        let mut progress = |_p: crate::provision::Progress| {};
        // The engine. Strata has no installer yet; llama-server serves every catalog model.
        let layout = LlamaLayout::from_env_with(&|k| std::env::var_os(k));
        let mut engine = "llama-server (already installed)".to_string();
        if let Some(layout) = layout.as_ref().filter(|l| l.installed().is_none()) {
            let releases = current_releases();
            let variant = match plan.engine.gpu_api {
                GpuApi::Cuda | GpuApi::Vulkan | GpuApi::Rocm => "vulkan",
                _ => "cpu",
            };
            let release = choose(&releases, Some(variant)).or_else(|_| choose(&releases, None));
            if let Ok(release) = release {
                let installed = install_llama(
                    layout,
                    self.fetcher.as_ref(),
                    &release,
                    false,
                    &mut progress,
                )
                .await
                .map_err(internal)?;
                engine = format!("llama-server {} ({})", installed.tag, installed.variant);
            }
        }

        let spec = ArtifactSpec {
            name: plan.model.id.clone(),
            file_name: plan.model.file.clone(),
            url: plan.model.url.clone(),
            sha256: plan.model.sha256.clone(),
            format: ArchiveFormat::TarGz,
            top_dir: String::new(),
        };
        let path = download(
            self.fetcher.as_ref(),
            &spec,
            &plan.models_dir,
            &mut progress,
        )
        .await
        .map_err(internal)?;

        let mut configured = Vec::new();
        if let Some(cfg_path) = &self.config_path {
            write_local_provider(
                cfg_path,
                &plan.model.id,
                LocalEngine::Llama,
                &path,
                &plan.assign,
            )?;
            configured = plan.assign.clone();
        }
        Ok(LocalModelSetupOut {
            model_id: plan.model.id.clone(),
            path: path.display().to_string(),
            engine,
            sha256_verified: true,
            configured,
            note: format!(
                "Start it with `kraken infer start {id}` (or Settings); KRAKEN supervises it and \
                 starts it by itself when the assistant needs it.",
                id = plan.model.id
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provider_tables_are_written_and_the_rest_kept() {
        let dir = std::env::temp_dir().join(format!("kraken-localmodels-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config.toml");
        std::fs::write(&path, "per_run_cap = 7\n").expect("write");
        write_local_provider(
            &path,
            "qwen3-8b-q4_k_m",
            LocalEngine::Llama,
            Path::new("/m/qwen3.gguf"),
            &[LocalFeature::Assistant, LocalFeature::Rewrite],
        )
        .expect("written");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("per_run_cap = 7"), "{text}");
        assert!(
            text.contains("[provider]") && text.contains("[rewrite]"),
            "{text}"
        );
        assert!(
            text.contains("kind = \"local\"") && text.contains("[[local_models]]"),
            "{text}"
        );
        assert!(!text.contains("127.0.0.1"), "{text}");
        let cfg = KrakenConfig::from_file(&path).expect("reads back");
        assert_eq!(cfg.local_models.len(), 1);
        assert_eq!(cfg.local_models[0].model_path, Path::new("/m/qwen3.gguf"));
        assert_eq!(cfg.provider, Some(local_provider_table("qwen3-8b-q4_k_m")));
        // Again: no second entry.
        write_local_provider(
            &path,
            "qwen3-8b-q4_k_m",
            LocalEngine::Llama,
            Path::new("/m/other.gguf"),
            &[LocalFeature::Assistant],
        )
        .expect("rewritten");
        let cfg = KrakenConfig::from_file(&path).expect("reads back");
        assert_eq!(cfg.local_models.len(), 1);
        assert_eq!(cfg.local_models[0].model_path, Path::new("/m/other.gguf"));
        std::fs::remove_dir_all(&dir).ok();
    }
}

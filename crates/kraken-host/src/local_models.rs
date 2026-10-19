//! `local_model_setup` for real: installs llama-server, downloads the chosen model with its
//! SHA-256 checked against the catalog, and points the assistant and/or the rewrite pipeline at
//! it in `config.toml`.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use kraken_infer::GpuApi;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    LocalFeature, LocalModelBackend, LocalModelSetupOut, LocalSetupPlan,
};
use serde_json::json;

use crate::config::KrakenConfig;
use crate::llama_setup::{LlamaLayout, choose, current_releases, install_llama};
use crate::provision::{ArchiveFormat, ArtifactSpec, Fetcher, HttpsFetcher, download};

/// The base URL the written provider points at: llama-server's default port.
pub const LOCAL_BASE_URL: &str = "http://127.0.0.1:8080/v1";

/// Installs and configures local models on this computer.
pub struct LocalModels {
    fetcher: Arc<dyn Fetcher>,
    config_path: Option<std::path::PathBuf>,
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
        })
    }

    /// A given fetcher and config file (tests).
    pub fn new(fetcher: Arc<dyn Fetcher>, config_path: Option<std::path::PathBuf>) -> Self {
        LocalModels {
            fetcher,
            config_path,
        }
    }
}

fn internal(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, e.to_string())
}

/// Writes `[provider]` / `[rewrite]` for a local server serving `model_id`, keeping the rest of
/// the file.
pub fn write_local_provider(
    path: &Path,
    model_id: &str,
    features: &[LocalFeature],
) -> Result<(), ProtoError> {
    let mut cfg = KrakenConfig::from_file(path).map_err(internal)?;
    let table = json!({
        "kind": "openai_compatible",
        "base_url": LOCAL_BASE_URL,
        "model": model_id,
        "supports_tools": true,
    });
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
            write_local_provider(cfg_path, &plan.model.id, &plan.assign)?;
            configured = plan.assign.clone();
        }
        Ok(LocalModelSetupOut {
            model_id: plan.model.id,
            path: path.display().to_string(),
            engine,
            sha256_verified: true,
            configured,
            note: format!(
                "Start the model in Settings > Local model (or `kraken infer start`) with this \
                 file; the configuration expects it at {LOCAL_BASE_URL}."
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
            text.contains("qwen3-8b-q4_k_m") && text.contains("127.0.0.1"),
            "{text}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

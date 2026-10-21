//! The setup's link to the machine: the daemon's `local_model_*` commands, and a request to the
//! running model.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use kraken_agent::ProviderConfig;
use kraken_infer::strata::{EngineMethod, EngineVersion};
use kraken_proto::infer::LocalEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{LocalModelDevicesOut, LocalModelRecommendOut};
use serde_json::{Value, json};

use super::setup::{InstallRequest, RawSurvey, SetupProbe};
use crate::assist::{ProviderStore, TestReport, test_connection};
use crate::backend::Backend;

/// Looks at the computer and installs models through a [`Backend`] (the daemon in the window).
pub struct BackendSetupProbe {
    backend: Arc<dyn Backend>,
    config_path: Option<PathBuf>,
}

impl BackendSetupProbe {
    /// A probe over `backend`; `config_path` is the `config.toml` the model is registered in.
    pub fn new(backend: Arc<dyn Backend>, config_path: Option<PathBuf>) -> Self {
        BackendSetupProbe {
            backend,
            config_path,
        }
    }

    async fn ask<T: serde::de::DeserializeOwned>(
        &self,
        command: &str,
        args: Value,
    ) -> Result<T, ProtoError> {
        let v = self.backend.call(command, args).await?;
        serde_json::from_value(v).map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("`{command}` answered something unexpected: {e}"),
            )
        })
    }
}

#[async_trait]
impl SetupProbe for BackendSetupProbe {
    async fn survey(&self) -> Result<RawSurvey, ProtoError> {
        let devices: LocalModelDevicesOut = self.ask("local_model_devices", json!({})).await?;
        let llama: LocalModelRecommendOut = self
            .ask("local_model_recommend", json!({"engine": "llama-server"}))
            .await?;
        // Strata is optional: a machine that cannot run it just does not list it.
        let strata: Option<LocalModelRecommendOut> = self
            .ask("local_model_recommend", json!({"engine": "strata"}))
            .await
            .ok();
        Ok(RawSurvey {
            devices: devices.devices,
            llama,
            strata,
        })
    }

    async fn install(
        &self,
        id: &str,
        engine: LocalEngine,
        request: &InstallRequest,
    ) -> Result<(), ProtoError> {
        self.backend
            .call("local_model_setup", install_args(id, engine, request))
            .await
            .map(|_| ())
    }

    fn bytes_on_disk(&self) -> u64 {
        data_dir().map_or(0, |d| {
            dir_bytes(&d.join("models"), 0) + dir_bytes(&d.join("engines"), 0)
        })
    }

    async fn test(&self, model: &str) -> Result<TestReport, String> {
        let store = ProviderStore::new(self.config_path.clone());
        let provider = store.build(&ProviderConfig::Local {
            model: model.to_string(),
        })?;
        test_connection(provider).await
    }
}

/// The arguments of `local_model_setup` for one install.
fn install_args(id: &str, engine: LocalEngine, request: &InstallRequest) -> Value {
    match engine {
        LocalEngine::Llama => {
            json!({"model": id, "engine": "llama-server", "use_for": ["assistant"]})
        }
        LocalEngine::Strata => {
            let mut args = json!({
                "model": id,
                "engine": "strata",
                "use_for": ["assistant"],
                "strata_engine": match request.strata.method {
                    EngineMethod::Prebuilt => "prebuilt",
                    EngineMethod::Build => "build",
                },
                "strata_version": match request.strata.version {
                    EngineVersion::LatestRelease => "latest_release",
                    EngineVersion::Pinned => "pinned",
                    EngineVersion::LatestCommit => "latest_commit",
                },
            });
            if let Some(file) = &request.model_file {
                args["model_file"] = json!(file.display().to_string());
            }
            args
        }
    }
}

fn data_dir() -> Option<PathBuf> {
    kraken_infer::models_dir_with(&|k| std::env::var_os(k))
        .and_then(|m| m.parent().map(Path::to_path_buf))
}

/// Bytes of the files under `dir`, without descending into build trees and virtual
/// environments (thousands of small files that say nothing about a download).
fn dir_bytes(dir: &Path, depth: usize) -> u64 {
    const SKIP: [&str; 4] = ["venv", ".git", "build", "src"];
    if depth > 4 {
        return 0;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| {
            let Ok(meta) = e.metadata() else { return 0 };
            if meta.is_dir() {
                if SKIP.iter().any(|s| e.file_name() == *s) {
                    0
                } else {
                    dir_bytes(&e.path(), depth + 1)
                }
            } else {
                meta.len()
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strata_installs_carry_the_engine_choice_and_the_picked_file() {
        let mut request = InstallRequest::default();
        let a = install_args("strata-iq2-xs", LocalEngine::Strata, &request);
        assert_eq!(a["strata_engine"], "prebuilt");
        assert_eq!(a["strata_version"], "latest_release");
        assert!(a.get("model_file").is_none());
        request.strata.method = EngineMethod::Build;
        request.strata.version = EngineVersion::LatestCommit;
        request.model_file = Some("/m/x-00001-of-00002.gguf".into());
        let a = install_args(
            "strata-existing-swift-iq2_xs",
            LocalEngine::Strata,
            &request,
        );
        assert_eq!(a["strata_engine"], "build");
        assert_eq!(a["strata_version"], "latest_commit");
        assert_eq!(a["model_file"], "/m/x-00001-of-00002.gguf");
        let l = install_args("m", LocalEngine::Llama, &request);
        assert!(l.get("strata_engine").is_none() && l.get("model_file").is_none());
    }

    #[test]
    fn the_size_counts_files_and_skips_environments() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("a/venv")).unwrap();
        std::fs::write(d.path().join("a/x.part"), vec![0u8; 100]).unwrap();
        std::fs::write(d.path().join("a/venv/y"), vec![0u8; 1000]).unwrap();
        std::fs::write(d.path().join("z"), vec![0u8; 5]).unwrap();
        assert_eq!(dir_bytes(d.path(), 0), 105);
        assert_eq!(dir_bytes(&d.path().join("nothing"), 0), 0);
    }
}

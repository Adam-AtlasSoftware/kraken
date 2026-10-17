use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

use crate::budget::MemoryBudget;
use crate::error::Result;
use crate::logring::LogLine;
use crate::port::LOOPBACK;
use crate::supervisor::{LoadProgress, ManagedProcess};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuApi {
    Cpu,
    Cuda,
    Rocm,
    Vulkan,
    Metal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// `std::env::consts::OS` values ("linux", "windows", "macos").
    pub os: Vec<String>,
    /// `std::env::consts::ARCH` values ("x86_64", "aarch64").
    pub arch: Vec<String>,
    pub gpu_apis: Vec<GpuApi>,
    /// Bytes of system RAM the engine needs before any model is loaded.
    pub min_ram: u64,
    pub supports_moe_offload: bool,
    pub supports_tool_calls: bool,
    pub license: String,
    /// Engine version when it could be detected on this machine.
    pub detected_version: Option<String>,
}

impl BackendCapabilities {
    pub fn supports_platform(&self, os: &str, arch: &str) -> bool {
        self.os.iter().any(|o| o == os) && self.arch.iter().any(|a| a == arch)
    }

    pub fn supports_current_platform(&self) -> bool {
        self.supports_platform(std::env::consts::OS, std::env::consts::ARCH)
    }
}

/// An inference engine that can be launched as a supervised local OpenAI-compatible server.
/// Nothing here assumes a particular engine; llama.cpp is one implementation.
#[async_trait]
pub trait InferenceBackend: Send + Sync {
    fn id(&self) -> &str;

    fn display_name(&self) -> &str {
        self.id()
    }

    fn capabilities(&self) -> BackendCapabilities;

    /// JSON Schema (object with `properties`, optional `required`, per-property `default`,
    /// `title`, `description`) that the GUI renders generically as a settings form.
    fn settings_schema(&self) -> Value;

    /// Validates `settings`, checks the memory budget, spawns the engine and returns at once;
    /// follow loading with [`RunningBackend::progress`] or [`RunningBackend::wait_ready`].
    async fn start(&self, settings: Value, budget: &MemoryBudget) -> Result<RunningBackend>;
}

/// A started backend: the OpenAI-compatible endpoint plus lifecycle handles.
pub struct RunningBackend {
    backend_id: String,
    model: Option<String>,
    process: ManagedProcess,
    api_key: Option<String>,
}

impl RunningBackend {
    pub fn new(
        backend_id: impl Into<String>,
        model: Option<String>,
        process: ManagedProcess,
    ) -> Self {
        Self {
            backend_id: backend_id.into(),
            model,
            process,
            api_key: None,
        }
    }

    /// Records the per-run API key the engine was started with.
    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    /// The bearer token clients must send (`Authorization: Bearer ...`), when the engine
    /// requires one.
    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn backend_id(&self) -> &str {
        &self.backend_id
    }

    /// Model name to put in chat requests, when the backend knows one.
    pub fn model(&self) -> Option<&str> {
        self.model.as_deref()
    }

    /// Base URL for `kraken_agent::OpenAiCompatible::new` (it appends `/chat/completions`).
    pub fn base_url(&self) -> String {
        format!("http://{LOOPBACK}:{}/v1", self.process.port())
    }

    pub fn port(&self) -> u16 {
        self.process.port()
    }

    pub async fn health(&self) -> bool {
        self.process.health().await
    }

    pub async fn wait_ready(&self, timeout: Duration) -> Result<()> {
        self.process.wait_ready(timeout).await
    }

    /// Loading-progress / phase stream.
    pub fn progress(&self) -> watch::Receiver<LoadProgress> {
        self.process.subscribe()
    }

    pub fn status(&self) -> LoadProgress {
        self.process.status()
    }

    /// Recent stdout/stderr/supervisor lines (bounded ring buffer).
    pub fn logs(&self) -> Vec<LogLine> {
        self.process.logs()
    }

    pub fn process(&self) -> &ManagedProcess {
        &self.process
    }

    pub async fn stop(&self) {
        self.process.stop().await;
    }
}

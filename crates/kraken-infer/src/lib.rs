//! Supervised local inference backends for KRAKEN.
//!
//! An [`InferenceBackend`] launches an engine as a supervised child process that exposes an
//! OpenAI-compatible server on 127.0.0.1; [`RunningBackend::base_url`] is what
//! `kraken_agent::OpenAiCompatible` talks to. llama.cpp ([`LlamaServerBackend`]) is the first
//! engine; [`GenericOpenAiServerBackend`] adds others from a TOML manifest without new Rust code.

pub mod backend;
pub mod budget;
pub mod error;
pub mod generic;
pub mod hardware;
pub mod launch;
pub mod llama;
pub mod logring;
pub mod port;
pub mod recommend;
pub mod registry;
pub mod stats;
pub mod strata;
pub mod strata_plan;
pub mod supervisor;
#[doc(hidden)]
pub mod testing;

pub use backend::{BackendCapabilities, GpuApi, InferenceBackend, RunningBackend};
pub use budget::{MemoryBudget, Reservation, Verdict};
pub use error::{InferError, Result};
pub use generic::{GenericOpenAiServerBackend, Manifest};
pub use hardware::{
    GpuInfo, GpuVendor, HardwareInfo, Probe, SystemProbe, detect as detect_hardware,
};
pub use launch::{LaunchSpec, launch_spec};
pub use llama::{LlamaServerBackend, LlamaSettings};
pub use logring::{LogLine, LogRing, LogStream};
pub use recommend::{
    EngineChoice, ModelEntry, Recommendation, catalog as model_catalog, models_dir_with, recommend,
};
pub use registry::{BackendRegistry, CapabilityFilter};
pub use supervisor::{
    HealthCheck, LoadProgress, ManagedProcess, Phase, ProcessSpec, RestartPolicy,
};

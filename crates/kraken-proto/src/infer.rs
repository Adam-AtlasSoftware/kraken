//! Local model serving: the models a user has set up on this computer, the cards (GPUs) they can
//! run on, and the live figures of a running model.
//!
//! `LocalModel` is persisted as `[[local_models]]` in `config.toml`; `DeviceInfo`, `ModelState`
//! and `ModelStats` travel over the daemon's RPC.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The program that serves a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalEngine {
    /// llama.cpp's `llama-server`.
    Llama,
    /// Strata (CUDA only).
    Strata,
}

/// Who made a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GpuVendor {
    /// NVIDIA.
    Nvidia,
    /// AMD.
    Amd,
    /// Intel.
    Intel,
    /// Anything else, including processors for AI work (NPUs).
    Other,
}

/// How a model uses several cards.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MultiGpuMode {
    /// Split the model across the cards, a block of layers on each.
    #[default]
    Split,
    /// Each card runs its own full copy of the model (Strata replicas).
    CopyPerCard,
    /// Split every layer between the cards (llama.cpp row split).
    SplitEveryLayer,
}

/// A card, named so it survives a renumbering: the UUID is the identity, the index only a hint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct DeviceRef {
    /// The vendor's unique id of the card (`GPU-...` for NVIDIA).
    pub uuid: String,
    /// The card's number when it was chosen.
    pub index: u32,
    /// Who made it.
    pub vendor: GpuVendor,
}

/// A model set up on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LocalModel {
    /// Stable id (the catalog id for catalog models); what `local { model = "<id>" }` names.
    pub id: String,
    /// Name shown to people.
    pub name: String,
    /// The program that serves it.
    pub engine: LocalEngine,
    /// The model file (or, for Strata, its model directory); empty when not yet located.
    pub model_path: PathBuf,
    /// The cards to run on; empty means the default selection.
    #[serde(default)]
    pub devices: Vec<DeviceRef>,
    /// Run on the processor only, no card.
    #[serde(default)]
    pub cpu_only: bool,
    /// What to do with several cards.
    #[serde(default)]
    pub multi_gpu: MultiGpuMode,
    /// Share of the model per selected card, in percent, in `devices` order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<u8>>,
    /// The main card among `devices`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_device: Option<DeviceRef>,
    /// Context size in tokens; unset means the engine's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_size: Option<u32>,
    /// Serve automatically when KRAKEN opens.
    #[serde(default = "default_true")]
    pub autostart: bool,
    /// Engine-specific settings, passed through untouched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

fn default_true() -> bool {
    true
}

/// Whether a card can be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceState {
    /// Working.
    Ok,
    /// Present but failing (driver missing or broken).
    Error {
        /// What is wrong, in plain words.
        message: String,
    },
    /// Present but not usable by KRAKEN.
    Unsupported {
        /// Why.
        reason: String,
    },
}

/// A card found on this computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceInfo {
    /// The card's number as the vendor tool reports it.
    pub index: u32,
    /// The vendor's unique id; empty when the tool gives none.
    pub uuid: String,
    /// Who made it.
    pub vendor: GpuVendor,
    /// Product name.
    pub name: String,
    /// Memory on the card in bytes (VRAM).
    pub vram_total: u64,
    /// Memory in use right now, in bytes.
    pub vram_used: u64,
    /// Whether it can be used.
    pub state: DeviceState,
}

/// Where a served model is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ModelState {
    /// Not running.
    Stopped,
    /// Starting; the weights are being loaded.
    Loading,
    /// Serving requests.
    Ready,
    /// Shutting down.
    Stopping,
    /// Could not run, or stopped for good.
    Failed {
        /// Why, in plain words.
        message: String,
    },
}

/// Where the words-per-second figure comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokSource {
    /// Reported by the engine.
    Engine,
    /// Measured by KRAKEN from replies; shown as "about N".
    Approx,
}

/// Memory a model uses on one card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DeviceVram {
    /// The card.
    pub device: DeviceRef,
    /// Bytes in use by this model.
    pub bytes: u64,
}

/// Live figures of one model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelStats {
    /// The model's id.
    pub model: String,
    /// Where it is in its life.
    pub phase: ModelState,
    /// How much of the loading is done, 0 to 1; `None` when the engine does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_fraction: Option<f32>,
    /// Card memory used by this model, per card.
    #[serde(default)]
    pub vram_per_device: Vec<DeviceVram>,
    /// Memory used on the computer (RAM) in bytes, summed over the engine's processes.
    #[serde(default)]
    pub ram_bytes: u64,
    /// Words per second, roughly (tokens per second); `None` before the first reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tok_s: Option<f32>,
    /// Where `tok_s` comes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tok_s_source: Option<TokSource>,
    /// The cards in use.
    #[serde(default)]
    pub devices: Vec<DeviceRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceRef {
        DeviceRef {
            uuid: "GPU-1".into(),
            index: 0,
            vendor: GpuVendor::Nvidia,
        }
    }

    #[test]
    fn a_minimal_model_gets_the_defaults() {
        let m: LocalModel = serde_json::from_str(
            r#"{"id":"a","name":"A","engine":"llama","model_path":"/m/a.gguf"}"#,
        )
        .expect("parses");
        assert!(m.autostart && !m.cpu_only);
        assert_eq!(m.multi_gpu, MultiGpuMode::Split);
        assert!(m.devices.is_empty() && m.shares.is_none());
    }

    #[test]
    fn states_use_a_kind_tag() {
        let s = serde_json::to_value(ModelState::Failed {
            message: "x".into(),
        })
        .expect("json");
        assert_eq!(s["kind"], "failed");
        let st = ModelStats {
            model: "a".into(),
            phase: ModelState::Ready,
            load_fraction: None,
            vram_per_device: vec![DeviceVram {
                device: dev(),
                bytes: 5,
            }],
            ram_bytes: 1,
            tok_s: Some(12.5),
            tok_s_source: Some(TokSource::Approx),
            devices: vec![dev()],
        };
        let back: ModelStats =
            serde_json::from_value(serde_json::to_value(&st).expect("json")).expect("back");
        assert_eq!(back, st);
    }
}

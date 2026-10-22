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
    /// Strata: KRAKEN chooses the main card, the context and the draft layer from the free
    /// video memory each time the model starts. It always runs on one card and names the
    /// second-card choices in its advice.
    Auto,
    /// Strata: a second card keeps extra experts and helps read prompts and answer. Prompts are
    /// read about 30 to 40 percent faster, answers about a third slower.
    PeerTier,
    /// Strata: a second card keeps extra experts in a cache that answers use too. Measured slower
    /// than one card on mismatched cards; offered for completeness.
    HelperCache,
    /// Strata (engines that support it): a second card helps read prompts and stays out of
    /// answering, so answers run at one-card speed.
    PrefillPeer,
}

/// Strata settings kept in [`LocalModel::extra`] under the key `strata`. Unset fields are
/// chosen from the hardware each time the model starts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StrataTuning {
    /// Read pictures. Off saves memory on the main card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<bool>,
    /// Video memory the second card leaves free, in MiB (default 1000).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_reserve_mib: Option<u32>,
    /// Use the model's draft layer, which speeds answers up but takes video memory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<bool>,
    /// Video memory the main card keeps free, in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vram_reserve_mib: Option<u32>,
    /// The longest context to run with, in tokens. KRAKEN sets it when video memory is short and
    /// only ever lowers the context Strata was installed with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_cap: Option<u32>,
    /// How rarely routed an expert must be for a missed one to be skipped in a verify window
    /// (Strata's tail skip): lower skips more, 0 turns it off. Unset keeps Strata's own default (7).
    /// Skipping makes answers faster and changes them slightly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail_skip: Option<u32>,
    /// How many tokens the draft layer proposes per check (Strata's `--spec`, usually 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<u32>,
    /// How sure the draft layer must be to extend a window by one more guess, in percent
    /// (Strata's `--spec-min-p`, usually 50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_min_p_percent: Option<u32>,
}

impl StrataTuning {
    /// Reads the tuning out of a model's `extra`; a field that cannot be read counts as unset and
    /// leaves the others alone.
    pub fn from_extra(extra: Option<&serde_json::Value>) -> Self {
        let Some(v) = extra.and_then(|e| e.get("strata")) else {
            return Self::default();
        };
        let flag = |k: &str| v.get(k).and_then(serde_json::Value::as_bool);
        let num = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
        };
        Self {
            vision: flag("vision"),
            peer_reserve_mib: num("peer_reserve_mib"),
            draft: flag("draft"),
            vram_reserve_mib: num("vram_reserve_mib"),
            context_cap: num("context_cap"),
            tail_skip: num("tail_skip"),
            spec: num("spec"),
            spec_min_p_percent: num("spec_min_p_percent"),
        }
    }

    /// Stores the tuning in `extra`, leaving other keys alone; an empty tuning removes the key.
    pub fn store(&self, extra: &mut Option<serde_json::Value>) {
        let mut map = match extra.take() {
            Some(serde_json::Value::Object(m)) => m,
            _ => serde_json::Map::new(),
        };
        if *self == Self::default() {
            map.remove("strata");
        } else if let Ok(v) = serde_json::to_value(self) {
            map.insert("strata".into(), v);
        }
        *extra = (!map.is_empty()).then_some(serde_json::Value::Object(map));
    }
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
    /// The card's number as the engines count it. NVIDIA: `nvidia-smi`'s index (PCI bus order,
    /// what CUDA uses with `CUDA_DEVICE_ORDER=PCI_BUS_ID`). AMD: the HIP number, the card's place
    /// among the AMD cards in PCI bus order (what `HIP_VISIBLE_DEVICES` takes). Other cards and
    /// accelerators: their DRM card or accelerator number.
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

//! Which engine and which model fit this computer, with the reasons.

use serde::{Deserialize, Serialize};

use crate::backend::GpuApi;
use crate::hardware::{GpuVendor, HardwareInfo};

const GIB: u64 = 1 << 30;

/// The Strata manifest engine is recommended only on machines with at least this much video
/// memory, RAM and free disk.
pub const STRATA_MIN_VRAM: u64 = 12 * GIB;
pub const STRATA_MIN_RAM: u64 = 32 * GIB;
pub const STRATA_MIN_DISK: u64 = 80 * GIB;

/// Room kept for the context (KV cache) and the driver on top of the weights.
const VRAM_HEADROOM: u64 = 2 * GIB;
/// Largest model run on the CPU alone (billions of parameters): bigger ones are too slow.
const CPU_MAX_PARAMS_B: u32 = 8;

/// One downloadable model file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelEntry {
    pub id: String,
    pub name: String,
    pub params_b: u32,
    pub quant: String,
    pub file: String,
    pub url: String,
    pub size: u64,
    /// Lower-case hex SHA-256 of the file; a download that differs is deleted.
    pub sha256: String,
    pub license: String,
}

#[derive(Deserialize)]
struct CatalogFile {
    model: Vec<ModelEntry>,
}

/// The bundled catalog (`data/models.toml`).
pub fn catalog() -> Vec<ModelEntry> {
    toml::from_str::<CatalogFile>(include_str!("../data/models.toml"))
        .map(|f| f.model)
        .unwrap_or_default()
}

/// Where model files go: `<data dir>/models` (`$XDG_DATA_HOME/kraken`, else
/// `~/.local/share/kraken`, else `%LOCALAPPDATA%\\kraken`).
pub fn models_dir_with(
    env: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let non_empty = |k: &str| {
        env(k)
            .filter(|v| !v.is_empty())
            .map(std::path::PathBuf::from)
    };
    let base = non_empty("XDG_DATA_HOME")
        .filter(|p| p.is_absolute())
        .map(|x| x.join("kraken"))
        .or_else(|| non_empty("HOME").map(|h| h.join(".local/share/kraken")))
        .or_else(|| {
            cfg!(windows)
                .then(|| non_empty("LOCALAPPDATA").map(|l| l.join("kraken")))
                .flatten()
        })?;
    Some(base.join("models"))
}

/// The engine to run the model with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineChoice {
    /// `llama-server` or `strata`.
    pub id: String,
    pub gpu_api: GpuApi,
    /// Human label ("llama-server (CUDA)").
    pub label: String,
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendation {
    pub engine: EngineChoice,
    /// `None` when nothing in the catalog fits.
    pub model: Option<ModelEntry>,
    /// Bytes to download (the model file).
    pub download_bytes: u64,
    /// Bytes the model occupies on disk once installed.
    pub disk_bytes: u64,
    pub reasons: Vec<String>,
}

fn gib(b: u64) -> String {
    format!("{:.1} GiB", b as f64 / GIB as f64)
}

/// Picks the engine and the biggest, best-quality model that fits `hw` from `catalog`.
pub fn recommend(hw: &HardwareInfo, catalog: &[ModelEntry]) -> Recommendation {
    let mut reasons = Vec::new();
    let vram = hw.vram_bytes();
    let gpu = hw.best_gpu();

    let (gpu_api, api_label) = match gpu {
        Some(g) if g.vendor == GpuVendor::Nvidia && vram >= 4 * GIB => {
            reasons.push(format!("{} found: using CUDA.", g.name));
            (GpuApi::Cuda, "CUDA")
        }
        Some(g) if matches!(g.vendor, GpuVendor::Amd | GpuVendor::Nvidia) => {
            reasons.push(format!(
                "{} found: using Vulkan, which works on every maker's driver.",
                g.name
            ));
            (GpuApi::Vulkan, "Vulkan")
        }
        _ => {
            reasons.push("No usable GPU found: running on the CPU.".into());
            (GpuApi::Cpu, "CPU")
        }
    };
    let gpu_api = if gpu_api != GpuApi::Cpu && vram == 0 {
        reasons.push("The GPU's memory size is unknown, so the model is sized for the CPU.".into());
        GpuApi::Cpu
    } else {
        gpu_api
    };

    let strata = vram >= STRATA_MIN_VRAM
        && hw.ram_bytes >= STRATA_MIN_RAM
        && hw.free_disk_bytes >= STRATA_MIN_DISK;
    let engine = if strata {
        reasons.push(format!(
            "{} of video memory, {} of RAM and {} free disk meet the Strata engine's minimum \
             (12 GiB, 32 GiB, 80 GiB).",
            gib(vram),
            gib(hw.ram_bytes),
            gib(hw.free_disk_bytes)
        ));
        EngineChoice {
            id: "strata".into(),
            gpu_api,
            label: "Strata".into(),
        }
    } else {
        if vram >= STRATA_MIN_VRAM {
            reasons.push(
                "Not enough RAM or free disk for the Strata engine (needs 12 GiB video memory, \
                 32 GiB RAM, 80 GiB disk); using llama-server."
                    .into(),
            );
        }
        EngineChoice {
            id: "llama-server".into(),
            gpu_api,
            label: format!("llama-server ({api_label})"),
        }
    };

    // Memory the weights may use, and where they live.
    let budget = if gpu_api == GpuApi::Cpu {
        hw.ram_bytes / 2
    } else {
        vram.saturating_sub(VRAM_HEADROOM)
    };
    let place = if gpu_api == GpuApi::Cpu {
        "half of the RAM"
    } else {
        "video memory after 2 GiB of headroom"
    };

    let mut fit: Vec<&ModelEntry> = catalog
        .iter()
        .filter(|m| gpu_api != GpuApi::Cpu || m.params_b <= CPU_MAX_PARAMS_B)
        .filter(|m| m.size <= budget)
        .filter(|m| m.size.saturating_add(m.size / 10) + 2 * GIB <= hw.free_disk_bytes)
        .collect();
    fit.sort_by_key(|m| (m.params_b, m.size));
    let model = fit.last().map(|m| (*m).clone());

    match &model {
        Some(m) => reasons.push(format!(
            "{} {} ({}) is the largest model that fits {place} ({}).",
            m.name,
            m.quant,
            gib(m.size),
            gib(budget)
        )),
        None => reasons.push(format!(
            "No model in the catalog fits {place} ({}) with {} free on disk.",
            gib(budget),
            gib(hw.free_disk_bytes)
        )),
    }
    if gpu_api == GpuApi::Cpu && model.is_some() {
        reasons.push(format!(
            "CPU-only models above {CPU_MAX_PARAMS_B}B parameters are left out: they answer too slowly."
        ));
    }
    let size = model.as_ref().map_or(0, |m| m.size);
    Recommendation {
        engine,
        model,
        download_bytes: size,
        disk_bytes: size,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware::GpuInfo;

    fn hw(vendor: Option<GpuVendor>, vram_gib: u64, ram_gib: u64, disk_gib: u64) -> HardwareInfo {
        HardwareInfo {
            gpus: vendor
                .map(|v| {
                    vec![GpuInfo {
                        vendor: v,
                        name: "Test GPU".into(),
                        vram_bytes: Some(vram_gib * GIB),
                    }]
                })
                .unwrap_or_default(),
            ram_bytes: ram_gib * GIB,
            free_disk_bytes: disk_gib * GIB,
            cpu_cores: 8,
        }
    }

    #[test]
    fn the_bundled_catalog_is_pinned() {
        let c = catalog();
        assert!(c.len() >= 6);
        for m in &c {
            assert_eq!(m.sha256.len(), 64, "{}", m.id);
            assert!(m.url.starts_with("https://"), "{}", m.id);
        }
    }

    #[test]
    fn cpu_only_picks_a_small_model_on_llama_server() {
        let r = recommend(&hw(None, 0, 16, 100), &catalog());
        assert_eq!(r.engine.id, "llama-server");
        assert_eq!(r.engine.gpu_api, GpuApi::Cpu);
        let m = r.model.expect("a model");
        assert!(m.params_b <= CPU_MAX_PARAMS_B);
        assert!(m.size <= 8 * GIB);
    }

    #[test]
    fn nvidia_with_24_gib_gets_cuda_and_a_big_model_without_strata_on_little_ram() {
        let r = recommend(&hw(Some(GpuVendor::Nvidia), 24, 16, 200), &catalog());
        assert_eq!(r.engine.id, "llama-server");
        assert_eq!(r.engine.gpu_api, GpuApi::Cuda);
        let m = r.model.expect("a model");
        assert_eq!(m.params_b, 32);
        assert!(r.reasons.iter().any(|x| x.contains("Strata")));
    }

    #[test]
    fn strata_only_when_all_three_minimums_are_met() {
        let ok = recommend(&hw(Some(GpuVendor::Nvidia), 12, 32, 80), &catalog());
        assert_eq!(ok.engine.id, "strata");
        for (v, r, d) in [(11, 32, 80), (12, 31, 80), (12, 32, 79)] {
            let r = recommend(&hw(Some(GpuVendor::Nvidia), v, r, d), &catalog());
            assert_eq!(r.engine.id, "llama-server", "{v} {d}");
        }
    }

    #[test]
    fn amd_uses_vulkan() {
        let r = recommend(&hw(Some(GpuVendor::Amd), 8, 16, 100), &catalog());
        assert_eq!(r.engine.gpu_api, GpuApi::Vulkan);
        assert_eq!(r.model.expect("model").params_b, 8);
    }

    #[test]
    fn a_full_disk_leaves_no_model_and_says_why() {
        let r = recommend(&hw(None, 0, 32, 2), &catalog());
        assert!(r.model.is_none());
        assert_eq!(r.download_bytes, 0);
        assert!(r.reasons.iter().any(|x| x.contains("No model")));
    }
}

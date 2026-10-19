//! What this computer can run: GPUs and their memory, RAM, free disk, CPU cores.
//!
//! Detection reads through [`Probe`], so tests feed fake command output and files. The real
//! probe runs `nvidia-smi` / `rocm-smi` and reads sysfs and `/proc/meminfo`.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// GPU maker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Other,
}

/// One graphics card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: GpuVendor,
    pub name: String,
    /// Video memory in bytes when known.
    pub vram_bytes: Option<u64>,
}

/// The facts the recommender needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub gpus: Vec<GpuInfo>,
    pub ram_bytes: u64,
    /// Free bytes on the disk that will hold the models.
    pub free_disk_bytes: u64,
    pub cpu_cores: u32,
}

impl HardwareInfo {
    /// The GPU with the most memory, if any card has a known size.
    pub fn best_gpu(&self) -> Option<&GpuInfo> {
        self.gpus
            .iter()
            .filter(|g| g.vram_bytes.is_some())
            .max_by_key(|g| g.vram_bytes)
            .or_else(|| self.gpus.first())
    }

    /// Video memory of [`best_gpu`](Self::best_gpu).
    pub fn vram_bytes(&self) -> u64 {
        self.best_gpu().and_then(|g| g.vram_bytes).unwrap_or(0)
    }
}

/// Where facts come from.
pub trait Probe {
    /// Standard output of `program args`, or `None` when it is missing or fails.
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
    /// A file's text.
    fn read(&self, path: &str) -> Option<String>;
    /// Names inside a directory.
    fn list(&self, path: &str) -> Vec<String>;
    fn cpu_cores(&self) -> u32;
}

/// The real machine.
pub struct SystemProbe;

impl Probe for SystemProbe {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn list(&self, path: &str) -> Vec<String> {
        std::fs::read_dir(path)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cpu_cores(&self) -> u32 {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    }
}

const MIB: u64 = 1 << 20;

/// Detects the hardware; `models_dir` is where downloads will go (its disk is measured).
pub fn detect(probe: &dyn Probe, models_dir: &Path) -> HardwareInfo {
    let mut gpus = nvidia(probe);
    if gpus.is_empty() {
        gpus = rocm(probe);
    }
    if gpus.is_empty() {
        gpus = sysfs(probe);
    }
    HardwareInfo {
        gpus,
        ram_bytes: probe
            .read("/proc/meminfo")
            .and_then(|t| parse_meminfo_total(&t))
            .unwrap_or(0),
        free_disk_bytes: free_disk(probe, models_dir),
        cpu_cores: probe.cpu_cores(),
    }
}

/// `nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits` (MiB).
pub fn nvidia(probe: &dyn Probe) -> Vec<GpuInfo> {
    let Some(text) = probe.run(
        "nvidia-smi",
        &[
            "--query-gpu=name,memory.total",
            "--format=csv,noheader,nounits",
        ],
    ) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| {
            let (name, mem) = l.rsplit_once(',')?;
            Some(GpuInfo {
                vendor: GpuVendor::Nvidia,
                name: name.trim().to_string(),
                vram_bytes: mem.trim().parse::<u64>().ok().map(|m| m * MIB),
            })
        })
        .collect()
}

/// `rocm-smi --showmeminfo vram --showproductname --json`.
pub fn rocm(probe: &dyn Probe) -> Vec<GpuInfo> {
    let Some(text) = probe.run(
        "rocm-smi",
        &["--showmeminfo", "vram", "--showproductname", "--json"],
    ) else {
        return Vec::new();
    };
    let Ok(serde_json::Value::Object(cards)) = serde_json::from_str::<serde_json::Value>(&text)
    else {
        return Vec::new();
    };
    cards
        .iter()
        .filter(|(k, _)| k.starts_with("card"))
        .map(|(_, v)| {
            let get = |key: &str| v.get(key).and_then(|x| x.as_str());
            GpuInfo {
                vendor: GpuVendor::Amd,
                name: get("Card series")
                    .or_else(|| get("Card Series"))
                    .unwrap_or("AMD GPU")
                    .to_string(),
                vram_bytes: get("VRAM Total Memory (B)").and_then(|s| s.trim().parse().ok()),
            }
        })
        .collect()
}

/// `/sys/class/drm/card*/device/{vendor,mem_info_vram_total}`.
pub fn sysfs(probe: &dyn Probe) -> Vec<GpuInfo> {
    let mut names = probe.list("/sys/class/drm");
    names.sort();
    names
        .into_iter()
        .filter(|n| n.starts_with("card") && n[4..].bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|n| {
            let base = format!("/sys/class/drm/{n}/device");
            let vendor = match probe.read(&format!("{base}/vendor"))?.trim() {
                "0x10de" => GpuVendor::Nvidia,
                "0x1002" => GpuVendor::Amd,
                "0x8086" => GpuVendor::Intel,
                _ => GpuVendor::Other,
            };
            let vram = probe
                .read(&format!("{base}/mem_info_vram_total"))
                .and_then(|s| s.trim().parse().ok());
            Some(GpuInfo {
                vendor,
                name: format!("{vendor:?} GPU ({n})"),
                vram_bytes: vram,
            })
        })
        .collect()
}

/// `MemTotal` of `/proc/meminfo` in bytes.
pub fn parse_meminfo_total(text: &str) -> Option<u64> {
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb * 1024)
}

/// Free bytes on the disk holding `dir` (the nearest existing parent), from `df`.
fn free_disk(probe: &dyn Probe, dir: &Path) -> u64 {
    let mut at = dir;
    while !at.exists() {
        match at.parent() {
            Some(p) => at = p,
            None => break,
        }
    }
    let path = at.to_string_lossy();
    probe
        .run("df", &["-Pk", &path])
        .and_then(|t| parse_df_free(&t))
        .unwrap_or(0)
}

/// Available bytes from `df -Pk` output.
pub fn parse_df_free(text: &str) -> Option<u64> {
    let line = text.lines().nth(1)?;
    let kb: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(kb * 1024)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Default)]
    pub(crate) struct Fake {
        pub cmds: HashMap<&'static str, &'static str>,
        pub files: HashMap<&'static str, &'static str>,
        pub dirs: HashMap<&'static str, Vec<&'static str>>,
    }

    impl Probe for Fake {
        fn run(&self, program: &str, _: &[&str]) -> Option<String> {
            self.cmds.get(program).map(|s| s.to_string())
        }
        fn read(&self, path: &str) -> Option<String> {
            self.files.get(path).map(|s| s.to_string())
        }
        fn list(&self, path: &str) -> Vec<String> {
            self.dirs
                .get(path)
                .map(|v| v.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default()
        }
        fn cpu_cores(&self) -> u32 {
            8
        }
    }

    const DF: &str =
        "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1000 10 500000 2% /\n";

    #[test]
    fn nvidia_smi_gives_name_and_vram() {
        let mut f = Fake::default();
        f.cmds
            .insert("nvidia-smi", "NVIDIA GeForce RTX 4090, 24564\n");
        f.cmds.insert("df", DF);
        f.files
            .insert("/proc/meminfo", "MemTotal:       65536000 kB\n");
        let hw = detect(&f, Path::new("/"));
        assert_eq!(hw.gpus.len(), 1);
        assert_eq!(hw.gpus[0].vendor, GpuVendor::Nvidia);
        assert_eq!(hw.vram_bytes(), 24564 * MIB);
        assert_eq!(hw.ram_bytes, 65536000 * 1024);
        assert_eq!(hw.free_disk_bytes, 500000 * 1024);
        assert_eq!(hw.cpu_cores, 8);
    }

    #[test]
    fn rocm_json_is_read() {
        let mut f = Fake::default();
        f.cmds.insert(
            "rocm-smi",
            r#"{"card0": {"VRAM Total Memory (B)": "17163091968", "Card series": "Radeon RX 7900 XT"}}"#,
        );
        let g = rocm(&f);
        assert_eq!(g[0].vendor, GpuVendor::Amd);
        assert_eq!(g[0].vram_bytes, Some(17163091968));
        assert_eq!(g[0].name, "Radeon RX 7900 XT");
    }

    #[test]
    fn sysfs_is_the_fallback_and_skips_connectors() {
        let mut f = Fake::default();
        f.dirs.insert(
            "/sys/class/drm",
            vec!["card0", "card0-HDMI-A-1", "renderD128"],
        );
        f.files
            .insert("/sys/class/drm/card0/device/vendor", "0x8086\n");
        let hw = detect(&f, Path::new("/"));
        assert_eq!(hw.gpus.len(), 1);
        assert_eq!(hw.gpus[0].vendor, GpuVendor::Intel);
        assert_eq!(hw.gpus[0].vram_bytes, None);
    }

    #[test]
    fn no_tools_means_no_gpu_and_zeroes() {
        let hw = detect(&Fake::default(), Path::new("/"));
        assert!(hw.gpus.is_empty());
        assert_eq!(hw.ram_bytes, 0);
    }
}

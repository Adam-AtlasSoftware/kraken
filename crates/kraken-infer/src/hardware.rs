//! What this computer can run: GPUs and their memory, RAM, free disk, CPU cores.
//!
//! Detection reads through [`Probe`], so tests feed fake command output and files. The real
//! probe runs `nvidia-smi` / `rocm-smi` and reads sysfs and `/proc/meminfo`. Every vendor is
//! enumerated (one vendor's tool never hides another's cards); a broken driver shows up as a
//! card in the [`DeviceState::Error`] state instead of vanishing.

use std::path::Path;

use kraken_proto::infer::{DeviceInfo, DeviceRef, DeviceState, LocalEngine};
use serde::{Deserialize, Serialize};

use crate::backend::GpuApi;

pub use kraken_proto::infer::GpuVendor;

/// One graphics card that can be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: GpuVendor,
    pub name: String,
    /// Video memory in bytes when known.
    pub vram_bytes: Option<u64>,
}

/// The facts the recommender needs. `gpus` holds the working cards only; see [`detect_devices`]
/// for every card with its state.
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

/// What a finished command printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Where facts come from.
pub trait Probe {
    /// Standard output of `program args`, or `None` when it is missing or fails.
    fn run(&self, program: &str, args: &[&str]) -> Option<String>;
    /// Like [`run`](Self::run) but also tells a failing program from a missing one: `None` only
    /// when the program cannot be started.
    fn run_output(&self, program: &str, args: &[&str]) -> Option<CmdOutput> {
        self.run(program, args).map(|stdout| CmdOutput {
            success: true,
            stdout,
            stderr: String::new(),
        })
    }
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
        self.run_output(program, args)
            .filter(|o| o.success)
            .map(|o| o.stdout)
    }

    fn run_output(&self, program: &str, args: &[&str]) -> Option<CmdOutput> {
        let out = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        Some(CmdOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
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
    let gpus = detect_devices(probe, None)
        .into_iter()
        .filter(|d| d.state == DeviceState::Ok)
        .map(|d| GpuInfo {
            vendor: d.vendor,
            name: d.name,
            vram_bytes: (d.vram_total > 0).then_some(d.vram_total),
        })
        .collect();
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

/// What one vendor's tool said.
enum Tool {
    Missing,
    Failed(String),
    Found(Vec<DeviceInfo>),
}

/// Every card and accelerator on this computer, NVIDIA first, then AMD, Intel, the rest and
/// NPUs. `llama_server` (the binary, when installed) fills in memory sizes the vendor tools
/// could not give.
pub fn detect_devices(probe: &dyn Probe, llama_server: Option<&str>) -> Vec<DeviceInfo> {
    let cards = sysfs_cards(probe);
    let mut out = Vec::new();

    out.extend(vendor_devices(GpuVendor::Nvidia, nvidia(probe), &cards));
    out.extend(vendor_devices(GpuVendor::Amd, rocm(probe), &cards));
    for c in cards
        .iter()
        .filter(|c| matches!(c.vendor, GpuVendor::Intel | GpuVendor::Other))
    {
        let reason = if c.vendor == GpuVendor::Intel {
            "Intel graphics cards are not supported yet."
        } else {
            "KRAKEN does not know how to use this graphics card."
        };
        out.push(c.device(DeviceState::Unsupported {
            reason: reason.into(),
        }));
    }
    out.extend(npus(probe));

    if let Some(bin) = llama_server {
        let seen = list_llama_devices(probe, bin);
        for d in out.iter_mut().filter(|d| d.vram_total == 0) {
            if let Some(l) = seen
                .iter()
                .find(|l| l.name.contains(&d.name) || d.name.contains(&l.name))
            {
                d.vram_total = l.total;
                d.vram_used = l.total.saturating_sub(l.free);
            }
        }
    }
    out
}

/// A vendor's cards: from its tool when that worked; otherwise the sysfs cards of that vendor
/// (as failing cards when the tool is broken or missing, except AMD, which sysfs can size).
fn vendor_devices(vendor: GpuVendor, tool: Tool, cards: &[SysCard]) -> Vec<DeviceInfo> {
    let mine = cards.iter().filter(|c| c.vendor == vendor);
    match tool {
        Tool::Found(devs) => devs,
        Tool::Failed(msg) => mine
            .map(|c| {
                c.device(DeviceState::Error {
                    message: msg.clone(),
                })
            })
            .collect(),
        Tool::Missing if vendor == GpuVendor::Nvidia => mine
            .map(|c| {
                c.device(DeviceState::Error {
                    message: "The NVIDIA driver tools (nvidia-smi) were not found. Install the \
                              NVIDIA driver to use this card."
                        .into(),
                })
            })
            .collect(),
        Tool::Missing => mine.map(|c| c.device(DeviceState::Ok)).collect(),
    }
}

fn first_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no details given")
        .to_string()
}

/// `nvidia-smi --query-gpu=index,uuid,name,memory.total,memory.used` (MiB).
fn nvidia(probe: &dyn Probe) -> Tool {
    let Some(out) = probe.run_output(
        "nvidia-smi",
        &[
            "--query-gpu=index,uuid,name,memory.total,memory.used",
            "--format=csv,noheader,nounits",
        ],
    ) else {
        return Tool::Missing;
    };
    if !out.success {
        let why = if out.stderr.trim().is_empty() {
            &out.stdout
        } else {
            &out.stderr
        };
        return Tool::Failed(format!(
            "The NVIDIA driver is not working: {}",
            first_line(why)
        ));
    }
    Tool::Found(parse_nvidia(&out.stdout))
}

/// Parses the `nvidia-smi` CSV above.
pub fn parse_nvidia(text: &str) -> Vec<DeviceInfo> {
    text.lines()
        .filter_map(|l| {
            let (index, rest) = l.split_once(',')?;
            let (uuid, rest) = rest.split_once(',')?;
            let mut tail = rest.rsplitn(3, ',');
            let used = tail.next()?;
            let total = tail.next()?;
            let name = tail.next()?;
            let mib = |s: &str| s.trim().parse::<u64>().map_or(0, |m| m * MIB);
            Some(DeviceInfo {
                index: index.trim().parse().ok()?,
                uuid: uuid.trim().to_string(),
                vendor: GpuVendor::Nvidia,
                name: name.trim().to_string(),
                vram_total: mib(total),
                vram_used: mib(used),
                state: DeviceState::Ok,
            })
        })
        .collect()
}

/// `rocm-smi --showmeminfo vram --showproductname --showuniqueid --json`.
fn rocm(probe: &dyn Probe) -> Tool {
    let Some(out) = probe.run_output(
        "rocm-smi",
        &[
            "--showmeminfo",
            "vram",
            "--showproductname",
            "--showuniqueid",
            "--json",
        ],
    ) else {
        return Tool::Missing;
    };
    if !out.success {
        let why = if out.stderr.trim().is_empty() {
            &out.stdout
        } else {
            &out.stderr
        };
        return Tool::Failed(format!(
            "The AMD driver is not working: {}",
            first_line(why)
        ));
    }
    match parse_rocm(&out.stdout) {
        Some(devs) => Tool::Found(devs),
        None => {
            Tool::Failed("The AMD driver tool (rocm-smi) gave an answer KRAKEN cannot read.".into())
        }
    }
}

/// Parses the `rocm-smi` JSON above; `None` when it is not JSON.
pub fn parse_rocm(text: &str) -> Option<Vec<DeviceInfo>> {
    let serde_json::Value::Object(cards) = serde_json::from_str::<serde_json::Value>(text).ok()?
    else {
        return None;
    };
    let mut devs: Vec<DeviceInfo> = cards
        .iter()
        .filter_map(|(k, v)| {
            let index: u32 = k.strip_prefix("card")?.parse().ok()?;
            let get = |key: &str| v.get(key).and_then(|x| x.as_str());
            let num = |key: &str| get(key).and_then(|s| s.trim().parse::<u64>().ok());
            Some(DeviceInfo {
                index,
                uuid: get("Unique ID").unwrap_or_default().to_string(),
                vendor: GpuVendor::Amd,
                name: get("Card series")
                    .or_else(|| get("Card Series"))
                    .unwrap_or("AMD GPU")
                    .to_string(),
                vram_total: num("VRAM Total Memory (B)").unwrap_or(0),
                vram_used: num("VRAM Total Used Memory (B)").unwrap_or(0),
                state: DeviceState::Ok,
            })
        })
        .collect();
    devs.sort_by_key(|d| d.index);
    Some(devs)
}

/// A card as sysfs shows it.
struct SysCard {
    number: u32,
    vendor: GpuVendor,
    name: String,
    vram_total: u64,
    vram_used: u64,
}

impl SysCard {
    fn device(&self, state: DeviceState) -> DeviceInfo {
        DeviceInfo {
            index: self.number,
            uuid: String::new(),
            vendor: self.vendor,
            name: self.name.clone(),
            vram_total: self.vram_total,
            vram_used: self.vram_used,
            state,
        }
    }
}

/// `/sys/class/drm/card*/device/{vendor,product_name,mem_info_vram_*}`.
fn sysfs_cards(probe: &dyn Probe) -> Vec<SysCard> {
    let mut names = probe.list("/sys/class/drm");
    names.sort();
    names
        .into_iter()
        .filter(|n| n.starts_with("card") && n[4..].bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|n| {
            let number: u32 = n[4..].parse().ok()?;
            let base = format!("/sys/class/drm/{n}/device");
            let (vendor, maker) = match probe.read(&format!("{base}/vendor"))?.trim() {
                "0x10de" => (GpuVendor::Nvidia, "NVIDIA"),
                "0x1002" => (GpuVendor::Amd, "AMD"),
                "0x8086" => (GpuVendor::Intel, "Intel"),
                _ => (GpuVendor::Other, "Unknown"),
            };
            let num = |f: &str| {
                probe
                    .read(&format!("{base}/{f}"))
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            let name = probe
                .read(&format!("{base}/product_name"))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("{maker} GPU ({n})"));
            Some(SysCard {
                number,
                vendor,
                name,
                vram_total: num("mem_info_vram_total"),
                vram_used: num("mem_info_vram_used"),
            })
        })
        .collect()
}

/// AI accelerators (`/sys/class/accel`): listed so people see them, never usable.
fn npus(probe: &dyn Probe) -> Vec<DeviceInfo> {
    let mut names = probe.list("/sys/class/accel");
    names.sort();
    names
        .into_iter()
        .filter_map(|n| {
            let number: u32 = n.strip_prefix("accel")?.parse().ok()?;
            let uevent = probe
                .read(&format!("/sys/class/accel/{n}/device/uevent"))
                .unwrap_or_default();
            let driver = uevent
                .lines()
                .find_map(|l| l.strip_prefix("DRIVER="))
                .unwrap_or("unknown")
                .trim()
                .to_string();
            let name = match driver.as_str() {
                "amdxdna" => "AMD NPU".to_string(),
                "intel_vpu" => "Intel NPU".to_string(),
                other => format!("AI accelerator ({other})"),
            };
            Some(DeviceInfo {
                index: number,
                uuid: String::new(),
                vendor: GpuVendor::Other,
                name,
                vram_total: 0,
                vram_used: 0,
                state: DeviceState::Unsupported {
                    reason: "NPUs (AI accelerator chips) are not supported yet.".into(),
                },
            })
        })
        .collect()
}

/// A device `llama-server --list-devices` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlamaDevice {
    /// Backend and number, like `CUDA0` or `Vulkan1`.
    pub id: String,
    pub name: String,
    pub total: u64,
    pub free: u64,
}

/// `<binary> --list-devices`; empty when it cannot run.
pub fn list_llama_devices(probe: &dyn Probe, binary: &str) -> Vec<LlamaDevice> {
    probe
        .run_output(binary, &["--list-devices"])
        .filter(|o| o.success)
        .map(|o| parse_llama_devices(&format!("{}\n{}", o.stdout, o.stderr)))
        .unwrap_or_default()
}

/// Lines like `  CUDA0: NVIDIA GeForce RTX 4090 (24217 MiB, 23700 MiB free)`.
pub fn parse_llama_devices(text: &str) -> Vec<LlamaDevice> {
    text.lines()
        .filter_map(|l| {
            let (id, rest) = l.trim().split_once(": ")?;
            if id.contains(' ') || !id.ends_with(|c: char| c.is_ascii_digit()) {
                return None;
            }
            let rest = rest.trim_end().strip_suffix(')')?;
            let (name, mem) = rest.rsplit_once(" (")?;
            let mut nums = mem.split(',').map(|p| {
                p.split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|m| m * MIB)
            });
            let total = nums.next()??;
            let free = nums.next().flatten().unwrap_or(0);
            Some(LlamaDevice {
                id: id.to_string(),
                name: name.trim().to_string(),
                total,
                free,
            })
        })
        .collect()
}

/// Whether `engine` can run on `device`; the error is a reason in plain words.
///
/// `llama_apis` are the GPU APIs the installed `llama-server` was built with
/// ([`crate::llama::detect_gpu_apis`]); an empty slice means unknown and allows the usual
/// vendor match (NVIDIA through CUDA, AMD through ROCm).
pub fn usable(
    engine: LocalEngine,
    device: &DeviceInfo,
    llama_apis: &[GpuApi],
) -> Result<(), String> {
    match &device.state {
        DeviceState::Ok => {}
        DeviceState::Error { message } => return Err(message.clone()),
        DeviceState::Unsupported { reason } => return Err(reason.clone()),
    }
    let has = |api: GpuApi| llama_apis.is_empty() || llama_apis.contains(&api);
    match (engine, device.vendor) {
        (LocalEngine::Strata, GpuVendor::Nvidia) => Ok(()),
        (LocalEngine::Strata, _) => Err("The Strata engine runs on NVIDIA cards only.".into()),
        (LocalEngine::Llama, GpuVendor::Nvidia) => {
            if has(GpuApi::Cuda) || llama_apis.contains(&GpuApi::Vulkan) {
                Ok(())
            } else {
                Err("This copy of llama.cpp was built without NVIDIA (CUDA) support.".into())
            }
        }
        (LocalEngine::Llama, GpuVendor::Amd) => {
            if has(GpuApi::Rocm) || llama_apis.contains(&GpuApi::Vulkan) {
                Ok(())
            } else {
                Err("This copy of llama.cpp was built without AMD (ROCm or Vulkan) support.".into())
            }
        }
        (LocalEngine::Llama, _) => Err("KRAKEN cannot use this kind of card yet.".into()),
    }
}

/// The cards to use when the person has not chosen: the single usable card; with several, the
/// one with the most memory; with none, an empty list (the processor).
pub fn default_devices(
    engine: LocalEngine,
    devices: &[DeviceInfo],
    llama_apis: &[GpuApi],
) -> Vec<DeviceRef> {
    devices
        .iter()
        .filter(|d| usable(engine, d, llama_apis).is_ok())
        .max_by_key(|d| (d.vram_total, std::cmp::Reverse(d.index)))
        .map(|d| {
            vec![DeviceRef {
                uuid: d.uuid.clone(),
                index: d.index,
                vendor: d.vendor,
            }]
        })
        .unwrap_or_default()
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

    fn dev(vendor: GpuVendor, vram_gib: u64) -> DeviceInfo {
        DeviceInfo {
            index: 0,
            uuid: "u".into(),
            vendor,
            name: "Card".into(),
            vram_total: vram_gib << 30,
            vram_used: 0,
            state: DeviceState::Ok,
        }
    }

    #[test]
    fn nvidia_smi_gives_name_and_vram() {
        let mut f = Fake::default();
        f.cmds.insert(
            "nvidia-smi",
            "0, GPU-abc, NVIDIA GeForce RTX 4090, 24564, 100\n",
        );
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
        let d = &detect_devices(&f, None)[0];
        assert_eq!((d.index, d.uuid.as_str()), (0, "GPU-abc"));
        assert_eq!(d.vram_used, 100 * MIB);
    }

    #[test]
    fn a_name_with_a_comma_survives() {
        let d = parse_nvidia("1, GPU-x, Tesla T4, rev 2, 15360, 0\n");
        assert_eq!(d[0].name, "Tesla T4, rev 2");
        assert_eq!(d[0].vram_total, 15360 * MIB);
    }

    #[test]
    fn rocm_json_is_read() {
        let d = parse_rocm(
            r#"{"card0": {"VRAM Total Memory (B)": "17163091968", "VRAM Total Used Memory (B)": "5", "Card series": "Radeon RX 7900 XT"}}"#,
        )
        .expect("json");
        assert_eq!(d[0].vendor, GpuVendor::Amd);
        assert_eq!(d[0].vram_total, 17163091968);
        assert_eq!(d[0].vram_used, 5);
        assert_eq!(d[0].name, "Radeon RX 7900 XT");
        assert!(parse_rocm("not json").is_none());
    }

    #[test]
    fn sysfs_intel_is_listed_but_unsupported_and_skips_connectors() {
        let mut f = Fake::default();
        f.dirs.insert(
            "/sys/class/drm",
            vec!["card0", "card0-HDMI-A-1", "renderD128"],
        );
        f.files
            .insert("/sys/class/drm/card0/device/vendor", "0x8086\n");
        let devs = detect_devices(&f, None);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].vendor, GpuVendor::Intel);
        assert!(matches!(devs[0].state, DeviceState::Unsupported { .. }));
        assert!(detect(&f, Path::new("/")).gpus.is_empty());
    }

    #[test]
    fn no_tools_means_no_gpu_and_zeroes() {
        let hw = detect(&Fake::default(), Path::new("/"));
        assert!(hw.gpus.is_empty());
        assert_eq!(hw.ram_bytes, 0);
    }

    #[test]
    fn llama_device_lines_are_parsed() {
        let d = parse_llama_devices(
            "Available devices:\n  CUDA0: NVIDIA GeForce RTX 4090 (24217 MiB, 23700 MiB free)\n  Vulkan1: AMD Radeon RX 7900 XT (20464 MiB, 20000 MiB free)\nnoise: here\n",
        );
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].id, "CUDA0");
        assert_eq!(d[1].name, "AMD Radeon RX 7900 XT");
        assert_eq!(d[1].free, 20000 * MIB);
    }

    #[test]
    fn the_matrix_follows_engine_and_build() {
        let nv = dev(GpuVendor::Nvidia, 24);
        let amd = dev(GpuVendor::Amd, 16);
        let intel = dev(GpuVendor::Intel, 8);
        assert!(usable(LocalEngine::Strata, &nv, &[]).is_ok());
        assert!(usable(LocalEngine::Strata, &amd, &[]).is_err());
        assert!(usable(LocalEngine::Llama, &nv, &[GpuApi::Cpu, GpuApi::Cuda]).is_ok());
        assert!(usable(LocalEngine::Llama, &nv, &[GpuApi::Cpu]).is_err());
        assert!(usable(LocalEngine::Llama, &amd, &[GpuApi::Vulkan]).is_ok());
        assert!(usable(LocalEngine::Llama, &amd, &[GpuApi::Cuda]).is_err());
        assert!(usable(LocalEngine::Llama, &intel, &[]).is_err());
        let mut broken = nv;
        broken.state = DeviceState::Error {
            message: "driver".into(),
        };
        assert_eq!(
            usable(LocalEngine::Llama, &broken, &[]),
            Err("driver".into())
        );
    }

    #[test]
    fn default_is_the_largest_usable_card_or_the_processor() {
        let mut small = dev(GpuVendor::Nvidia, 8);
        small.index = 0;
        small.uuid = "small".into();
        let mut big = dev(GpuVendor::Nvidia, 24);
        big.index = 1;
        big.uuid = "big".into();
        let amd = dev(GpuVendor::Amd, 48);
        let all = [small.clone(), big, amd];
        let pick = default_devices(LocalEngine::Strata, &all, &[]);
        assert_eq!(pick.len(), 1);
        assert_eq!(pick[0].uuid, "big");
        let pick = default_devices(LocalEngine::Llama, &all, &[GpuApi::Vulkan]);
        assert_eq!(pick[0].vendor, GpuVendor::Amd);
        assert_eq!(default_devices(LocalEngine::Llama, &[small], &[]).len(), 1);
        assert!(default_devices(LocalEngine::Strata, &[dev(GpuVendor::Amd, 8)], &[]).is_empty());
        assert!(default_devices(LocalEngine::Llama, &[], &[]).is_empty());
    }
}

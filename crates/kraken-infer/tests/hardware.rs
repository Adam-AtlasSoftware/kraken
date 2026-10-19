//! Enumeration against recorded command output and sysfs trees (`tests/fixtures/hw/<scenario>`).

use std::path::PathBuf;
use std::process::Command;

use kraken_infer::hardware::{CmdOutput, Probe, detect_devices, list_llama_devices, usable};
use kraken_proto::infer::{DeviceInfo, DeviceState, GpuVendor, LocalEngine};

struct Fixture(PathBuf);

fn fixture(name: &str) -> Fixture {
    Fixture(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/hw")
            .join(name),
    )
}

impl Fixture {
    fn path(&self, p: &str) -> PathBuf {
        self.0.join(p.trim_start_matches('/'))
    }
}

impl Probe for Fixture {
    fn run(&self, program: &str, args: &[&str]) -> Option<String> {
        self.run_output(program, args)
            .filter(|o| o.success)
            .map(|o| o.stdout)
    }

    fn run_output(&self, program: &str, _: &[&str]) -> Option<CmdOutput> {
        let program = program.rsplit('/').next()?;
        if let Ok(stdout) = std::fs::read_to_string(self.path(&format!("cmd/{program}.out"))) {
            return Some(CmdOutput {
                success: true,
                stdout,
                stderr: String::new(),
            });
        }
        let stderr = std::fs::read_to_string(self.path(&format!("cmd/{program}.fail"))).ok()?;
        Some(CmdOutput {
            success: false,
            stdout: String::new(),
            stderr,
        })
    }

    fn read(&self, path: &str) -> Option<String> {
        std::fs::read_to_string(self.path(path)).ok()
    }

    fn list(&self, path: &str) -> Vec<String> {
        std::fs::read_dir(self.path(path))
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn cpu_cores(&self) -> u32 {
        4
    }
}

fn find(devs: &[DeviceInfo], vendor: GpuVendor, index: u32) -> &DeviceInfo {
    devs.iter()
        .find(|d| d.vendor == vendor && d.index == index)
        .unwrap_or_else(|| panic!("no {vendor:?} card {index} in {devs:#?}"))
}

#[test]
fn mixed_vendors_are_all_listed() {
    let f = fixture("mixed");
    let devs = detect_devices(&f, Some("llama-server"));
    // 2 NVIDIA, 1 AMD, 1 Intel, 1 NPU; the NVIDIA cards are not repeated from sysfs.
    assert_eq!(devs.len(), 5, "{devs:#?}");
    let a = find(&devs, GpuVendor::Nvidia, 0);
    assert_eq!(a.uuid, "GPU-5f0c1a2e-1111-2222-3333-444455556666");
    assert_eq!(a.name, "NVIDIA GeForce RTX 3090");
    assert_eq!(a.vram_total, 24576 << 20);
    assert_eq!(a.vram_used, 1203 << 20);
    assert_eq!(a.state, DeviceState::Ok);
    assert_eq!(find(&devs, GpuVendor::Nvidia, 1).vram_total, 12288 << 20);
    // rocm-smi's card2 is the only AMD card: HIP number 0.
    let amd = find(&devs, GpuVendor::Amd, 0);
    assert_eq!(amd.name, "Radeon RX 7900 XTX");
    assert_eq!(amd.uuid, "0x8a1b2c3d4e5f6071");
    assert_eq!(amd.vram_total, 25_753_026_560);
    let intel = find(&devs, GpuVendor::Intel, 3);
    assert!(
        matches!(&intel.state, DeviceState::Unsupported { reason } if reason.contains("not supported yet"))
    );
    let npu = devs.iter().find(|d| d.name == "AMD NPU").expect("npu");
    assert!(matches!(npu.state, DeviceState::Unsupported { .. }));
}

#[test]
fn mixed_matrix() {
    let f = fixture("mixed");
    let devs = detect_devices(&f, None);
    let nv = find(&devs, GpuVendor::Nvidia, 0);
    let amd = find(&devs, GpuVendor::Amd, 0);
    assert!(usable(LocalEngine::Strata, nv, &[]).is_ok());
    assert!(usable(LocalEngine::Strata, amd, &[]).is_err());
    assert!(usable(LocalEngine::Llama, amd, &[]).is_ok());
    let intel = find(&devs, GpuVendor::Intel, 3);
    assert!(usable(LocalEngine::Llama, intel, &[]).is_err());
}

#[test]
fn llama_lists_its_devices() {
    let f = fixture("mixed");
    let l = list_llama_devices(&f, "llama-server");
    assert_eq!(l.len(), 2);
    assert_eq!(l[1].id, "CUDA1");
    assert!(list_llama_devices(&fixture("broken_nvidia"), "llama-server").is_empty());
}

#[test]
fn a_broken_driver_is_a_card_in_error() {
    let devs = detect_devices(&fixture("broken_nvidia"), None);
    let nv = find(&devs, GpuVendor::Nvidia, 0);
    let DeviceState::Error { message } = &nv.state else {
        panic!("{nv:#?}")
    };
    assert!(message.contains("couldn't communicate with the NVIDIA driver"));
    assert!(usable(LocalEngine::Llama, nv, &[]).is_err());
    let npu = devs.iter().find(|d| d.name == "Intel NPU").expect("npu");
    assert!(matches!(npu.state, DeviceState::Unsupported { .. }));
}

#[test]
fn without_vendor_tools_amd_comes_from_sysfs_and_nvidia_is_an_error() {
    let devs = detect_devices(&fixture("amd_sysfs_only"), None);
    // DRM card1 (card0 is the NVIDIA card) is the first AMD card HIP sees: number 0.
    let amd = find(&devs, GpuVendor::Amd, 0);
    assert_eq!(amd.state, DeviceState::Ok);
    assert_eq!(amd.vram_total, 8_573_157_376);
    assert_eq!(amd.vram_used, 1 << 20);
    let nv = find(&devs, GpuVendor::Nvidia, 0);
    assert!(matches!(&nv.state, DeviceState::Error { message } if message.contains("nvidia-smi")));
}

#[test]
fn the_real_probe_tells_missing_from_failing() {
    let p = kraken_infer::hardware::SystemProbe;
    assert!(p.run_output("kraken-no-such-program", &[]).is_none());
    if Command::new("false").output().is_ok() {
        let o = p.run_output("false", &[]).expect("runs");
        assert!(!o.success);
        assert!(p.run("false", &[]).is_none());
    }
}

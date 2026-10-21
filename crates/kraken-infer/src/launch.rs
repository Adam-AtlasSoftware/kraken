//! How a [`LocalModel`] becomes a command line and an environment: a pure function per engine,
//! so every combination of engine and multi-card mode can be tested without starting anything.

use kraken_proto::infer::{
    DeviceInfo, DeviceRef, GpuVendor, LocalEngine, LocalModel, MultiGpuMode,
};
use serde_json::{Map, Value};

use crate::backend::GpuApi;
use crate::error::{InferError, Result};
use crate::hardware::{LlamaDevice, default_devices, llama_gpu_api, usable};
use crate::llama::{LlamaSettings, build_argv};

/// What to run for one model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// llama.cpp: the full argument list (without the program). Strata: only the overrides to
    /// append to the installed command (`--gpu`, `--replicas`); the port is already in that
    /// command, and is always the one KRAKEN picked.
    pub argv: Vec<String>,
    /// Environment variables to set, applied after the inherited allowlist.
    pub env: Vec<(String, String)>,
}

fn bad(msg: impl Into<String>) -> InferError {
    InferError::Settings(msg.into())
}

/// Finds the card a [`DeviceRef`] names: by UUID, else (when the reference has none) by number.
fn resolve<'a>(r: &DeviceRef, devices: &'a [DeviceInfo]) -> Result<&'a DeviceInfo> {
    let found = if r.uuid.is_empty() {
        devices
            .iter()
            .find(|d| d.index == r.index && d.vendor == r.vendor)
    } else {
        devices.iter().find(|d| d.uuid == r.uuid)
    };
    found.ok_or_else(|| {
        bad(format!(
            "The card chosen for this model (number {}) is no longer in this computer.",
            r.index
        ))
    })
}

/// The cards the model runs on, in the order the person chose them; empty means the processor.
fn selected<'a>(
    model: &LocalModel,
    devices: &'a [DeviceInfo],
    llama_apis: &[GpuApi],
) -> Result<Vec<&'a DeviceInfo>> {
    if model.cpu_only {
        return Ok(Vec::new());
    }
    let refs = if model.devices.is_empty() {
        default_devices(model.engine, devices, llama_apis)
    } else {
        model.devices.clone()
    };
    let mut out: Vec<&DeviceInfo> = Vec::new();
    for r in &refs {
        let d = resolve(r, devices)?;
        usable(model.engine, d, llama_apis)
            .map_err(|why| bad(format!("{} cannot be used: {why}", d.name)))?;
        if !out.iter().any(|o| std::ptr::eq(*o, d)) {
            out.push(d);
        }
    }
    Ok(out)
}

/// Builds the launch description of `model` on `devices` (what [`crate::hardware`] found).
/// `llama_apis` are the GPU APIs of the installed `llama-server`; `port` is the one KRAKEN
/// picked (llama.cpp only, see [`LaunchSpec::argv`]). For a `llama-server` that drives the
/// chosen cards through Vulkan use [`launch_spec_with`].
///
/// Both engines get `CUDA_DEVICE_ORDER=PCI_BUS_ID`, so card numbers agree with `nvidia-smi`.
pub fn launch_spec(
    model: &LocalModel,
    devices: &[DeviceInfo],
    llama_apis: &[GpuApi],
    port: u16,
) -> Result<LaunchSpec> {
    launch_spec_with(model, devices, llama_apis, &[], port)
}

/// [`launch_spec`] with what `llama-server --list-devices` reported
/// ([`crate::hardware::list_llama_devices`]). A Vulkan build ignores `CUDA_VISIBLE_DEVICES` and
/// `HIP_VISIBLE_DEVICES`, so the cards are named to it with `--device Vulkan<n>`, matched by
/// name; when a card cannot be told apart from another the start is refused rather than run on
/// the wrong card.
pub fn launch_spec_with(
    model: &LocalModel,
    devices: &[DeviceInfo],
    llama_apis: &[GpuApi],
    llama_devices: &[LlamaDevice],
    port: u16,
) -> Result<LaunchSpec> {
    let cards = selected(model, devices, llama_apis)?;
    let mut env = vec![("CUDA_DEVICE_ORDER".to_string(), "PCI_BUS_ID".to_string())];
    let argv = match model.engine {
        LocalEngine::Llama => llama(model, &cards, llama_apis, llama_devices, port, &mut env)?,
        LocalEngine::Strata => strata(model, &cards)?,
    };
    Ok(LaunchSpec { argv, env })
}

/// True when `llama-server` would drive any of the model's cards through Vulkan, so
/// [`launch_spec_with`] needs `llama-server --list-devices`.
pub fn needs_llama_devices(
    model: &LocalModel,
    devices: &[DeviceInfo],
    llama_apis: &[GpuApi],
) -> bool {
    model.engine == LocalEngine::Llama
        && selected(model, devices, llama_apis).is_ok_and(|cards| {
            cards
                .iter()
                .any(|c| llama_gpu_api(c.vendor, llama_apis) == Some(GpuApi::Vulkan))
        })
}

fn same_card_name(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    !a.is_empty() && !b.is_empty() && (a.contains(&b) || b.contains(&a))
}

/// The `Vulkan<n>` names of `cards`, in their order. A card matches the Vulkan devices whose
/// name contains its name or the other way round; several identical cards are told apart only
/// when all of them are chosen (then which is which does not matter).
fn vulkan_names(cards: &[&DeviceInfo], llama_devices: &[LlamaDevice]) -> Result<Vec<String>> {
    let vulkan: Vec<&LlamaDevice> = llama_devices
        .iter()
        .filter(|d| d.id.starts_with("Vulkan"))
        .collect();
    let listed = || {
        if vulkan.is_empty() {
            "it lists no Vulkan devices".to_string()
        } else {
            let names: Vec<String> = vulkan
                .iter()
                .map(|d| format!("{} ({})", d.id, d.name))
                .collect();
            format!("it lists {}", names.join(", "))
        }
    };
    let mut out: Vec<String> = Vec::new();
    for c in cards {
        let candidates: Vec<&&LlamaDevice> = vulkan
            .iter()
            .filter(|d| same_card_name(&d.name, &c.name))
            .collect();
        let twins = cards
            .iter()
            .filter(|o| same_card_name(&o.name, &c.name))
            .count();
        let pick = match candidates.len() {
            0 => None,
            1 => Some(candidates[0]),
            n if n == twins => candidates.iter().find(|d| !out.contains(&d.id)).copied(),
            _ => None,
        };
        let Some(d) = pick else {
            return Err(bad(format!(
                "This copy of llama.cpp uses {} through Vulkan, and KRAKEN cannot tell which \
                 Vulkan device it is ({}), so the model was not started on a card that may be \
                 the wrong one. Run it on the processor, choose all cards of that model, or \
                 install a llama.cpp build with {} support.",
                c.name,
                listed(),
                if c.vendor == GpuVendor::Amd {
                    "ROCm"
                } else {
                    "CUDA"
                }
            )));
        };
        out.push(d.id.clone());
    }
    Ok(out)
}

fn llama(
    model: &LocalModel,
    cards: &[&DeviceInfo],
    llama_apis: &[GpuApi],
    llama_devices: &[LlamaDevice],
    port: u16,
    env: &mut Vec<(String, String)>,
) -> Result<Vec<String>> {
    let mut obj: Map<String, Value> = match &model.extra {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err(bad("the extra settings of a model must be an object")),
    };
    // The port is always KRAKEN's pick, and the binary is found by the backend.
    obj.remove("port");
    obj.remove("binary_path");
    obj.insert(
        "model_path".into(),
        Value::String(model.model_path.display().to_string()),
    );
    if let Some(c) = model.context_size {
        obj.insert("context_size".into(), c.into());
    }
    let cpu = cards.is_empty();
    if cpu {
        obj.insert("gpu_layers".into(), 0.into());
    }
    let settings = LlamaSettings::from_value(Value::Object(obj))?;
    let mut argv = build_argv(&settings, port);

    if cpu {
        return Ok(argv);
    }
    let vendor = cards[0].vendor;
    if cards.iter().any(|c| c.vendor != vendor) {
        return Err(bad(
            "Cards from different makers cannot share one model yet. Pick cards from one maker.",
        ));
    }
    let (var, ids): (&str, Vec<String>) = match vendor {
        _ if llama_gpu_api(vendor, llama_apis) == Some(GpuApi::Vulkan) => {
            // `--main-gpu` and `--tensor-split` below index this list, as they index the
            // renumbered cards of CUDA and HIP.
            argv.extend([
                "--device".into(),
                vulkan_names(cards, llama_devices)?.join(","),
            ]);
            ("", Vec::new())
        }
        GpuVendor::Nvidia => (
            "CUDA_VISIBLE_DEVICES",
            cards
                .iter()
                .map(|c| {
                    if c.uuid.is_empty() {
                        c.index.to_string()
                    } else {
                        c.uuid.clone()
                    }
                })
                .collect(),
        ),
        GpuVendor::Amd => (
            "HIP_VISIBLE_DEVICES",
            cards.iter().map(|c| c.index.to_string()).collect(),
        ),
        _ => return Err(bad("KRAKEN cannot use this kind of card yet.")),
    };
    if !var.is_empty() {
        env.push((var.into(), ids.join(",")));
    }

    // The visible-devices variable (or `--device`) renumbers the cards 0..n in the order given;
    // the flags below index that filtered list.
    let n = cards.len();
    if n < 2 {
        argv.extend(["--split-mode".into(), "none".into()]);
    } else {
        let mode = match model.multi_gpu {
            MultiGpuMode::Split | MultiGpuMode::Auto => "layer",
            MultiGpuMode::SplitEveryLayer => "row",
            MultiGpuMode::CopyPerCard => {
                return Err(bad(
                    "A full copy of the model on each card needs the Strata engine.",
                ));
            }
            MultiGpuMode::PeerTier | MultiGpuMode::HelperCache | MultiGpuMode::PrefillPeer => {
                return Err(bad(
                    "Keeping extra experts on a second card needs the Strata engine.",
                ));
            }
        };
        argv.extend(["--split-mode".into(), mode.into()]);
        if let Some(shares) = &model.shares {
            if shares.len() != n {
                return Err(bad(format!(
                    "There are {} card shares but {n} cards.",
                    shares.len()
                )));
            }
            if shares.iter().all(|s| *s == 0) {
                return Err(bad("The card shares are all zero."));
            }
            argv.extend([
                "--tensor-split".into(),
                shares
                    .iter()
                    .map(u8::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ]);
        }
        if let Some(main) = &model.main_device {
            let pos = cards
                .iter()
                .position(|c| {
                    if main.uuid.is_empty() {
                        c.index == main.index
                    } else {
                        c.uuid == main.uuid
                    }
                })
                .ok_or_else(|| {
                    bad("The main card is not one of the cards chosen for the model.")
                })?;
            argv.extend(["--main-gpu".into(), pos.to_string()]);
        }
    }
    Ok(argv)
}

fn strata(model: &LocalModel, cards: &[&DeviceInfo]) -> Result<Vec<String>> {
    if cards.is_empty() {
        return Err(bad(
            "The Strata engine needs an NVIDIA card; it cannot run on the processor alone.",
        ));
    }
    let n = cards.len();
    let replicas = match model.multi_gpu {
        MultiGpuMode::Split | MultiGpuMode::Auto => 1,
        MultiGpuMode::CopyPerCard => n,
        MultiGpuMode::SplitEveryLayer => {
            return Err(bad(
                "Splitting every layer between cards needs the llama.cpp engine.",
            ));
        }
        // The cards and their roles are written into the run's own config (`strata_run`); an
        // appended `--gpu` would turn them into a layer split.
        MultiGpuMode::PeerTier | MultiGpuMode::HelperCache | MultiGpuMode::PrefillPeer => {
            return Ok(vec!["--replicas".into(), "1".into()]);
        }
    };
    if !n.is_multiple_of(replicas) {
        return Err(bad(format!(
            "{n} cards do not divide into {replicas} equal groups."
        )));
    }
    // Always both flags: argv beats the installer's config, so a "replicas" left in that file
    // cannot regroup the cards chosen here.
    Ok(vec![
        "--gpu".into(),
        cards
            .iter()
            .map(|c| c.index.to_string())
            .collect::<Vec<_>>()
            .join(","),
        "--replicas".into(),
        replicas.to_string(),
    ])
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kraken_proto::infer::DeviceState;
    use serde_json::json;

    use super::*;

    fn card(index: u32, vendor: GpuVendor, uuid: &str) -> DeviceInfo {
        DeviceInfo {
            index,
            uuid: uuid.into(),
            vendor,
            name: format!("Card {index}"),
            vram_total: 24 << 30,
            vram_used: 0,
            state: DeviceState::Ok,
        }
    }

    fn r(d: &DeviceInfo) -> DeviceRef {
        DeviceRef {
            uuid: d.uuid.clone(),
            index: d.index,
            vendor: d.vendor,
        }
    }

    fn model(engine: LocalEngine, cards: &[&DeviceInfo], mode: MultiGpuMode) -> LocalModel {
        LocalModel {
            id: "m".into(),
            name: "M".into(),
            engine,
            model_path: PathBuf::from("/m/x.gguf"),
            devices: cards.iter().map(|d| r(d)).collect(),
            cpu_only: false,
            multi_gpu: mode,
            shares: None,
            main_device: None,
            context_size: None,
            autostart: true,
            extra: None,
        }
    }

    fn base_argv(extra: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = [
            "-m",
            "/m/x.gguf",
            "-c",
            "8192",
            "--host",
            "127.0.0.1",
            "--port",
            "9000",
            "--no-slots",
            "--metrics",
            "--jinja",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        v.extend(extra.iter().map(|s| (*s).to_string()));
        v
    }

    fn env_of(s: &LaunchSpec, k: &str) -> Option<String> {
        s.env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    fn nv() -> Vec<DeviceInfo> {
        vec![
            card(0, GpuVendor::Nvidia, "GPU-aaa"),
            card(1, GpuVendor::Nvidia, "GPU-bbb"),
            card(2, GpuVendor::Nvidia, "GPU-ccc"),
        ]
    }

    #[test]
    fn llama_one_card_uses_uuid_and_no_split() {
        let d = nv();
        let m = model(LocalEngine::Llama, &[&d[2]], MultiGpuMode::Split);
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(s.argv, base_argv(&["--split-mode", "none"]));
        assert_eq!(
            env_of(&s, "CUDA_DEVICE_ORDER").as_deref(),
            Some("PCI_BUS_ID")
        );
        assert_eq!(
            env_of(&s, "CUDA_VISIBLE_DEVICES").as_deref(),
            Some("GPU-ccc")
        );
    }

    #[test]
    fn llama_layer_split_with_shares_and_main_card_indexes_the_filtered_list() {
        let d = nv();
        let mut m = model(LocalEngine::Llama, &[&d[2], &d[0]], MultiGpuMode::Split);
        m.shares = Some(vec![60, 40]);
        m.main_device = Some(r(&d[0]));
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(
            s.argv,
            base_argv(&[
                "--split-mode",
                "layer",
                "--tensor-split",
                "60,40",
                "--main-gpu",
                "1"
            ])
        );
        assert_eq!(
            env_of(&s, "CUDA_VISIBLE_DEVICES").as_deref(),
            Some("GPU-ccc,GPU-aaa")
        );
    }

    #[test]
    fn llama_row_split() {
        let d = nv();
        let m = model(
            LocalEngine::Llama,
            &[&d[0], &d[1]],
            MultiGpuMode::SplitEveryLayer,
        );
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(s.argv, base_argv(&["--split-mode", "row"]));
    }

    #[test]
    fn llama_amd_uses_hip_indices() {
        let d = vec![card(0, GpuVendor::Amd, ""), card(1, GpuVendor::Amd, "")];
        let m = model(LocalEngine::Llama, &[&d[1]], MultiGpuMode::Split);
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(env_of(&s, "HIP_VISIBLE_DEVICES").as_deref(), Some("1"));
        assert_eq!(env_of(&s, "CUDA_VISIBLE_DEVICES"), None);
    }

    fn vk(id: &str, name: &str) -> LlamaDevice {
        LlamaDevice {
            id: id.into(),
            name: name.into(),
            total: 24 << 30,
            free: 20 << 30,
        }
    }

    #[test]
    fn llama_through_vulkan_names_the_cards_with_device_not_cuda_variables() {
        let mut d = nv();
        d[0].name = "NVIDIA GeForce RTX 3060".into();
        d[1].name = "NVIDIA GeForce RTX 4090".into();
        // llama.cpp's Vulkan numbering skips the integrated GPU and follows its own order.
        let listed = [
            vk("Vulkan0", "NVIDIA GeForce RTX 4090"),
            vk("Vulkan1", "NVIDIA GeForce RTX 3060"),
        ];
        let mut m = model(LocalEngine::Llama, &[&d[0], &d[1]], MultiGpuMode::Split);
        m.main_device = Some(r(&d[1]));
        let s = launch_spec_with(&m, &d, &[GpuApi::Vulkan], &listed, 9000).unwrap();
        assert!(
            s.argv
                .windows(2)
                .any(|w| w == ["--device", "Vulkan1,Vulkan0"]),
            "{:?}",
            s.argv
        );
        assert!(s.argv.windows(2).any(|w| w == ["--main-gpu", "1"]));
        assert_eq!(env_of(&s, "CUDA_VISIBLE_DEVICES"), None);
        assert_eq!(env_of(&s, "HIP_VISIBLE_DEVICES"), None);
        assert!(needs_llama_devices(&m, &d, &[GpuApi::Vulkan]));
        assert!(!needs_llama_devices(&m, &d, &[GpuApi::Cuda]));
        assert!(!needs_llama_devices(&m, &d, &[]));

        // AMD on a Vulkan-only build.
        let amd = vec![DeviceInfo {
            name: "Radeon RX 7900 XTX".into(),
            ..card(0, GpuVendor::Amd, "")
        }];
        let m = model(LocalEngine::Llama, &[&amd[0]], MultiGpuMode::Split);
        let s = launch_spec_with(
            &m,
            &amd,
            &[GpuApi::Vulkan],
            &[vk("Vulkan0", "AMD Radeon RX 7900 XTX (RADV NAVI31)")],
            9000,
        )
        .unwrap();
        assert!(s.argv.windows(2).any(|w| w == ["--device", "Vulkan0"]));
        assert_eq!(env_of(&s, "HIP_VISIBLE_DEVICES"), None);
    }

    #[test]
    fn llama_through_vulkan_refuses_when_it_cannot_tell_the_card() {
        let mut d = nv();
        for c in &mut d {
            c.name = "NVIDIA GeForce RTX 4090".into();
        }
        let twins = [
            vk("Vulkan0", "NVIDIA GeForce RTX 4090"),
            vk("Vulkan1", "NVIDIA GeForce RTX 4090"),
            vk("Vulkan2", "NVIDIA GeForce RTX 4090"),
        ];
        // One of three identical cards: which Vulkan device it is cannot be known.
        let one = model(LocalEngine::Llama, &[&d[1]], MultiGpuMode::Split);
        let e = launch_spec_with(&one, &d, &[GpuApi::Vulkan], &twins, 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("cannot tell which Vulkan device"), "{e}");
        // All of them: the set is the same whatever the order.
        let all = model(
            LocalEngine::Llama,
            &[&d[0], &d[1], &d[2]],
            MultiGpuMode::Split,
        );
        let s = launch_spec_with(&all, &d, &[GpuApi::Vulkan], &twins, 1).unwrap();
        assert!(
            s.argv
                .windows(2)
                .any(|w| w == ["--device", "Vulkan0,Vulkan1,Vulkan2"])
        );
        // No list at all (llama-server --list-devices did not run).
        let e = launch_spec_with(&one, &d, &[GpuApi::Vulkan], &[], 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("lists no Vulkan devices"), "{e}");
    }

    #[test]
    fn llama_cpu_only_offloads_nothing_and_names_no_card() {
        let d = nv();
        let mut m = model(LocalEngine::Llama, &[&d[0]], MultiGpuMode::Split);
        m.cpu_only = true;
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(
            s.argv,
            [
                "-m",
                "/m/x.gguf",
                "-c",
                "8192",
                "--host",
                "127.0.0.1",
                "--port",
                "9000",
                "--no-slots",
                "--metrics",
                "-ngl",
                "0",
                "--jinja"
            ]
        );
        assert_eq!(env_of(&s, "CUDA_VISIBLE_DEVICES"), None);
    }

    #[test]
    fn llama_no_choice_takes_the_default_card() {
        let d = nv();
        let m = model(LocalEngine::Llama, &[], MultiGpuMode::Split);
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert_eq!(
            env_of(&s, "CUDA_VISIBLE_DEVICES").as_deref(),
            Some("GPU-aaa")
        );
        // No usable card at all: the processor.
        let m = model(LocalEngine::Llama, &[], MultiGpuMode::Split);
        let s = launch_spec(&m, &[], &[], 9000).unwrap();
        assert!(s.argv.windows(2).any(|w| w == ["-ngl", "0"]));
    }

    #[test]
    fn llama_extra_settings_pass_through_but_not_the_port() {
        let d = nv();
        let mut m = model(LocalEngine::Llama, &[&d[0]], MultiGpuMode::Split);
        m.context_size = Some(4096);
        m.extra = Some(json!({"threads": 8, "port": 1234, "jinja": false}));
        let s = launch_spec(&m, &d, &[], 9000).unwrap();
        assert!(s.argv.windows(2).any(|w| w == ["-c", "4096"]));
        assert!(s.argv.windows(2).any(|w| w == ["-t", "8"]));
        assert!(s.argv.windows(2).any(|w| w == ["--port", "9000"]));
        assert!(!s.argv.contains(&"--jinja".to_string()));
    }

    #[test]
    fn llama_rejects_bad_choices() {
        let d = nv();
        let two = |mode| model(LocalEngine::Llama, &[&d[0], &d[1]], mode);
        assert!(launch_spec(&two(MultiGpuMode::CopyPerCard), &d, &[], 1).is_err());
        let mut m = two(MultiGpuMode::Split);
        m.shares = Some(vec![100]);
        assert!(launch_spec(&m, &d, &[], 1).is_err());
        let mut m = two(MultiGpuMode::Split);
        m.main_device = Some(r(&d[2]));
        assert!(launch_spec(&m, &d, &[], 1).is_err());
        // A vanished card is a message, not a silent fallback.
        let gone = card(5, GpuVendor::Nvidia, "GPU-gone");
        let m = model(LocalEngine::Llama, &[&gone], MultiGpuMode::Split);
        assert!(
            launch_spec(&m, &d, &[], 1)
                .unwrap_err()
                .to_string()
                .contains("no longer")
        );
        // Mixed makers.
        let mixed = vec![
            card(0, GpuVendor::Nvidia, "GPU-a"),
            card(0, GpuVendor::Amd, ""),
        ];
        let m = model(
            LocalEngine::Llama,
            &[&mixed[0], &mixed[1]],
            MultiGpuMode::Split,
        );
        assert!(launch_spec(&m, &mixed, &[], 1).is_err());
    }

    // Checked against Strata's serve/server.py (main(), after parse_args): the run config is read
    // first, then `--replicas N` sets cfg["replicas"] and `--gpu X` sets cfg["gpu"] (a digit
    // string becomes an int, anything else stays "0,2"), so argv wins over the installer's JSON
    // for both keys. A config "replicas" given as a list of {"gpus": [...]} is replaced by the
    // number too, and `--replicas 1` means no replicas (replicas.gpu_groups returns []), which is
    // why Split passes it: a "replicas" left in the config cannot regroup the chosen cards. A
    // number N cuts the "gpu" list into N equal groups and errors when N does not divide it.
    #[test]
    fn strata_golden_per_mode() {
        let d = nv();
        let argv = |cards: &[&DeviceInfo], mode| {
            launch_spec(&model(LocalEngine::Strata, cards, mode), &d, &[], 9000)
                .unwrap()
                .argv
        };
        assert_eq!(
            argv(&[&d[1]], MultiGpuMode::Split),
            ["--gpu", "1", "--replicas", "1"]
        );
        assert_eq!(
            argv(&[&d[0], &d[2]], MultiGpuMode::Split),
            ["--gpu", "0,2", "--replicas", "1"]
        );
        assert_eq!(
            argv(&[&d[0], &d[2]], MultiGpuMode::CopyPerCard),
            ["--gpu", "0,2", "--replicas", "2"]
        );
        let s = launch_spec(
            &model(LocalEngine::Strata, &[&d[0]], MultiGpuMode::Split),
            &d,
            &[],
            9000,
        )
        .unwrap();
        assert_eq!(
            env_of(&s, "CUDA_DEVICE_ORDER").as_deref(),
            Some("PCI_BUS_ID")
        );
        assert_eq!(env_of(&s, "CUDA_VISIBLE_DEVICES"), None);
    }

    #[test]
    fn strata_rejects_what_it_cannot_do() {
        let d = nv();
        let m = model(
            LocalEngine::Strata,
            &[&d[0], &d[1]],
            MultiGpuMode::SplitEveryLayer,
        );
        assert!(launch_spec(&m, &d, &[], 1).is_err());
        let mut m = model(LocalEngine::Strata, &[&d[0]], MultiGpuMode::Split);
        m.cpu_only = true;
        assert!(launch_spec(&m, &d, &[], 1).is_err());
        let amd = vec![card(0, GpuVendor::Amd, "")];
        let m = model(LocalEngine::Strata, &[&amd[0]], MultiGpuMode::Split);
        assert!(
            launch_spec(&m, &amd, &[], 1)
                .unwrap_err()
                .to_string()
                .contains("NVIDIA")
        );
    }
}

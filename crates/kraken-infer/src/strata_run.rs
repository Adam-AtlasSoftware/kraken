//! The config Strata is started with this time: the installed config with the cards, their roles
//! and the planner's choices written in. The installed file itself is never changed.

use kraken_proto::infer::{DeviceInfo, LocalModel, MultiGpuMode, StrataTuning};
use serde_json::{Map, Value, json};

use crate::error::{InferError, Result};
use crate::strata_plan::PEER_RESERVE_MIB;

/// Flags this module writes. Each is removed first so a config that already went through here
/// comes out the same. The bool says whether the flag takes a value.
const OWNED: [(&str, bool); 9] = [
    ("--peer-device", true),
    ("--peer-reserve-mib", true),
    ("--peer-slots", true),
    ("--peer-prefill-only", false),
    ("--expert-cache-device1", true),
    ("--expert-cache-device2", true),
    ("--expert-cache-device3", true),
    ("--remote-expert-opt", false),
    ("--layer-split", true),
];

fn strip(args: Vec<Value>, owned: &[(&str, bool)]) -> Vec<Value> {
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str().and_then(|s| owned.iter().find(|(f, _)| *f == s)) {
            Some((_, true)) => {
                it.next();
            }
            Some((_, false)) => {}
            None => out.push(a),
        }
    }
    out
}

fn push(args: &mut Vec<Value>, items: &[&str]) {
    args.extend(items.iter().map(|s| Value::String((*s).into())));
}

/// Sets the value after `flag`, appending the flag when it is absent.
fn set_value(args: &mut Vec<Value>, flag: &str, value: &str) {
    match args.iter().position(|a| a.as_str() == Some(flag)) {
        Some(i) if i + 1 < args.len() => args[i + 1] = Value::String(value.into()),
        Some(_) => args.push(Value::String(value.into())),
        None => push(args, &[flag, value]),
    }
}

fn value_of<'a>(args: &'a [Value], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a.as_str() == Some(flag))?;
    args.get(i + 1)?.as_str()
}

fn merge_env(obj: &mut Map<String, Value>, pairs: &[(&str, String)]) {
    if !obj.get("env").is_some_and(Value::is_object) {
        obj.insert("env".into(), json!({}));
    }
    if let Some(Value::Object(env)) = obj.get_mut("env") {
        for (k, v) in pairs {
            env.insert((*k).into(), Value::String(v.clone()));
        }
    }
}

/// Strata's installed config with `model`'s cards, mode, context and tuning applied. `model` is
/// the effective model (the planner already ran) and `cards` its devices in order.
pub fn run_config(base: &Value, model: &LocalModel, cards: &[&DeviceInfo]) -> Result<Value> {
    let Some(obj) = base.as_object() else {
        return Err(InferError::Settings(
            "Strata's config is not a JSON object.".into(),
        ));
    };
    let mut obj = obj.clone();
    let tuning = StrataTuning::from_extra(model.extra.as_ref());
    let mut owned = OWNED.to_vec();
    if tuning.vram_reserve_mib.is_some() {
        owned.push(("--vram-reserve-mib", true));
    }
    let mut args = strip(
        obj.get("args")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        &owned,
    );

    match model.multi_gpu {
        MultiGpuMode::Split | MultiGpuMode::Auto | MultiGpuMode::CopyPerCard => {}
        MultiGpuMode::SplitEveryLayer => {
            return Err(InferError::Settings(
                "Splitting every layer between cards needs the llama.cpp engine.".into(),
            ));
        }
        MultiGpuMode::PeerTier | MultiGpuMode::PrefillPeer => {
            let [main, second] = cards else {
                return Err(InferError::Settings(format!(
                    "A second card helping needs exactly two cards, not {}.",
                    cards.len()
                )));
            };
            obj.insert("gpu".into(), json!([main.index, second.index]));
            let reserve = tuning
                .peer_reserve_mib
                .unwrap_or(PEER_RESERVE_MIB)
                .to_string();
            push(
                &mut args,
                &["--peer-device", "1", "--peer-reserve-mib", &reserve],
            );
            let mut env = vec![("STRATA_PEER_NO_P2P", "1".to_string())];
            if model.multi_gpu == MultiGpuMode::PrefillPeer {
                push(&mut args, &["--peer-prefill-only"]);
                env.push(("STRATA_PEER_HOT", "0".to_string()));
            }
            merge_env(&mut obj, &env);
        }
        MultiGpuMode::HelperCache => {
            let [main, helper] = cards else {
                return Err(InferError::Settings(format!(
                    "A helper cache needs exactly two cards, not {}.",
                    cards.len()
                )));
            };
            obj.insert("gpu".into(), json!(main.index));
            merge_env(
                &mut obj,
                &[
                    ("CUDA_DEVICE_ORDER", "PCI_BUS_ID".to_string()),
                    (
                        "CUDA_VISIBLE_DEVICES",
                        format!("{},{}", main.index, helper.index),
                    ),
                ],
            );
            push(
                &mut args,
                &["--expert-cache-device1", "auto", "--remote-expert-opt"],
            );
        }
    }

    if let Some(c) = model.context_size {
        set_value(&mut args, "--max-context", &c.to_string());
        if value_of(&args, "--kv-resident")
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|r| r > c)
        {
            set_value(&mut args, "--kv-resident", &c.to_string());
        }
    }
    if tuning.draft == Some(false) {
        obj.insert("mtp".into(), Value::Bool(false));
    }
    if tuning.vision == Some(false) {
        obj.remove("vision");
        args.retain(|a| a.as_str() != Some("--vision"));
    }
    if let Some(n) = tuning.vram_reserve_mib {
        set_value(&mut args, "--vram-reserve-mib", &n.to_string());
    }

    obj.insert("args".into(), Value::Array(args));
    Ok(Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use kraken_proto::infer::{DeviceState, GpuVendor, LocalEngine};

    use super::*;

    fn base() -> Value {
        json!({
            "exe": "/opt/strata/engine/strata",
            "args": [
                "--pack", "/opt/strata/data/packs/swift", "--native", "/models/m.gguf",
                "--expert-cache", "auto", "--spec", "4", "--mtp", "/opt/strata/data/mtp/rt",
                "--max-context", "65536", "--kv", "q4_0", "--kv-resident", "32768", "--vision"
            ],
            "cwd": "/opt/strata/src",
            "model_name": "swift",
            "port": 8080,
            "gpu": 1,
            "gpus_asked": true,
            "env": {"LD_LIBRARY_PATH": "/opt/lib"},
            "vision": {"exe": "/opt/strata/engine/strata-vision", "gpu": false},
            "mtp": true,
            "args_written": ["--pack", "/opt/strata/data/packs/swift", "--vision"]
        })
    }

    fn card(index: u32) -> DeviceInfo {
        DeviceInfo {
            index,
            uuid: format!("GPU-{index}"),
            vendor: GpuVendor::Nvidia,
            name: format!("Card {index}"),
            vram_total: 8 << 30,
            vram_used: 0,
            state: DeviceState::Ok,
        }
    }

    fn model(mode: MultiGpuMode) -> LocalModel {
        LocalModel {
            id: "s".into(),
            name: "S".into(),
            engine: LocalEngine::Strata,
            model_path: "/m".into(),
            devices: Vec::new(),
            cpu_only: false,
            multi_gpu: mode,
            shares: None,
            main_device: None,
            context_size: None,
            autostart: true,
            extra: None,
        }
    }

    fn args(v: &Value) -> Vec<&str> {
        v["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(Value::as_str)
            .collect()
    }

    #[test]
    fn single_card_modes_leave_the_config_alone() {
        let c = card(1);
        for mode in [
            MultiGpuMode::Split,
            MultiGpuMode::Auto,
            MultiGpuMode::CopyPerCard,
        ] {
            let out = run_config(&base(), &model(mode), &[&c]).expect("config");
            assert_eq!(out, base(), "{mode:?}");
        }
    }

    #[test]
    fn peer_tier_writes_both_cards_and_the_peer_flags() {
        let (a, b) = (card(1), card(0));
        let out = run_config(&base(), &model(MultiGpuMode::PeerTier), &[&a, &b]).expect("config");
        assert_eq!(out["gpu"], json!([1, 0]));
        let args = args(&out);
        let tail = &args[args.len() - 4..];
        assert_eq!(tail, ["--peer-device", "1", "--peer-reserve-mib", "1000"]);
        assert_eq!(out["env"]["STRATA_PEER_NO_P2P"], "1");
        assert_eq!(out["env"]["LD_LIBRARY_PATH"], "/opt/lib");
        assert!(out["env"].get("STRATA_PEER_HOT").is_none());
        assert_eq!(out["args_written"], base()["args_written"]);
    }

    #[test]
    fn prefill_peer_keeps_the_second_card_out_of_answers() {
        let (a, b) = (card(1), card(0));
        let mut m = model(MultiGpuMode::PrefillPeer);
        StrataTuning {
            peer_reserve_mib: Some(1500),
            ..StrataTuning::default()
        }
        .store(&mut m.extra);
        let out = run_config(&base(), &m, &[&a, &b]).expect("config");
        let args = args(&out);
        assert!(args.windows(2).any(|w| w == ["--peer-reserve-mib", "1500"]));
        assert!(args.contains(&"--peer-prefill-only"));
        assert_eq!(out["env"]["STRATA_PEER_HOT"], "0");
        assert_eq!(out["env"]["STRATA_PEER_NO_P2P"], "1");
    }

    #[test]
    fn helper_cache_keeps_one_card_and_names_the_helper_in_the_environment() {
        let (a, b) = (card(1), card(0));
        let out =
            run_config(&base(), &model(MultiGpuMode::HelperCache), &[&a, &b]).expect("config");
        assert_eq!(out["gpu"], json!(1));
        assert_eq!(out["env"]["CUDA_DEVICE_ORDER"], "PCI_BUS_ID");
        assert_eq!(out["env"]["CUDA_VISIBLE_DEVICES"], "1,0");
        let args = args(&out);
        assert!(
            args.windows(2)
                .any(|w| w == ["--expert-cache-device1", "auto"])
        );
        assert!(args.contains(&"--remote-expert-opt"));
    }

    #[test]
    fn old_peer_flags_are_replaced_not_stacked() {
        let mut b = base();
        b["args"].as_array_mut().expect("args").extend(
            [
                "--peer-device",
                "2",
                "--peer-prefill-only",
                "--layer-split",
                "1,1",
                "--peer-slots",
                "4",
            ]
            .map(Value::from),
        );
        let (x, y) = (card(1), card(0));
        let out = run_config(&b, &model(MultiGpuMode::PeerTier), &[&x, &y]).expect("config");
        let args = args(&out);
        assert_eq!(args.iter().filter(|a| **a == "--peer-device").count(), 1);
        assert!(!args.contains(&"--peer-prefill-only"));
        assert!(!args.contains(&"--layer-split"));
        assert!(!args.contains(&"--peer-slots"));
    }

    #[test]
    fn context_and_tuning_are_applied() {
        let c = card(1);
        let mut m = model(MultiGpuMode::Split);
        m.context_size = Some(16_384);
        StrataTuning {
            vision: Some(false),
            draft: Some(false),
            vram_reserve_mib: Some(1000),
            peer_reserve_mib: None,
        }
        .store(&mut m.extra);
        let out = run_config(&base(), &m, &[&c]).expect("config");
        let args = args(&out);
        assert!(args.windows(2).any(|w| w == ["--max-context", "16384"]));
        assert!(args.windows(2).any(|w| w == ["--kv-resident", "16384"]));
        assert!(args.windows(2).any(|w| w == ["--vram-reserve-mib", "1000"]));
        assert!(!args.contains(&"--vision"));
        assert!(out.get("vision").is_none());
        assert_eq!(out["mtp"], json!(false));
        assert_eq!(out["gpu"], json!(1));
    }

    #[test]
    fn a_larger_context_keeps_the_resident_window_and_is_appended_when_absent() {
        let c = card(1);
        let mut b = base();
        b["args"] = json!(["--kv-resident", "8192"]);
        let mut m = model(MultiGpuMode::Split);
        m.context_size = Some(32_768);
        let out = run_config(&b, &m, &[&c]).expect("config");
        assert_eq!(
            args(&out),
            ["--kv-resident", "8192", "--max-context", "32768"]
        );
    }

    #[test]
    fn running_twice_equals_running_once() {
        let (a, b) = (card(1), card(0));
        let mut m = model(MultiGpuMode::PrefillPeer);
        m.context_size = Some(32_768);
        StrataTuning {
            vision: Some(false),
            draft: Some(false),
            vram_reserve_mib: Some(700),
            peer_reserve_mib: Some(1000),
        }
        .store(&mut m.extra);
        let once = run_config(&base(), &m, &[&a, &b]).expect("once");
        let twice = run_config(&once, &m, &[&a, &b]).expect("twice");
        assert_eq!(once, twice);
        m.multi_gpu = MultiGpuMode::HelperCache;
        let once = run_config(&base(), &m, &[&a, &b]).expect("once");
        assert_eq!(once, run_config(&once, &m, &[&a, &b]).expect("twice"));
    }

    #[test]
    fn a_peer_mode_with_one_card_is_refused() {
        let c = card(1);
        for mode in [
            MultiGpuMode::PeerTier,
            MultiGpuMode::PrefillPeer,
            MultiGpuMode::HelperCache,
        ] {
            let e = run_config(&base(), &model(mode), &[&c]).expect_err("one card");
            assert!(matches!(e, InferError::Settings(_)), "{mode:?}");
        }
    }
}

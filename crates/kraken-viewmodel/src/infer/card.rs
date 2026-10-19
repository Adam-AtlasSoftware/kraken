//! The model card of Settings > AI: what a local model's choices look like and how editing them
//! changes the `LocalModel` record. Pure functions over the record and the cards found on this
//! computer; the GUI only draws.

use kraken_host::infer::ModelStatus;
use kraken_infer::hardware::{default_devices, usable};
use kraken_proto::infer::{
    DeviceInfo, DeviceRef, LocalEngine, LocalModel, ModelState, MultiGpuMode, TokSource,
};

/// One line of the "Run on" list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRow {
    /// The card.
    pub device: DeviceRef,
    /// Name and memory in plain words.
    pub label: String,
    /// Ticked.
    pub checked: bool,
    /// Why it cannot be used, when it cannot; the row is greyed out then.
    pub unusable: Option<String>,
}

/// One way to use several cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeOption {
    /// The setting it writes.
    pub mode: MultiGpuMode,
    /// Short name.
    pub title: &'static str,
    /// One line about what it does.
    pub help: &'static str,
}

/// The status block of the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLine {
    /// Main sentence.
    pub text: String,
    /// How to colour it.
    pub tone: Tone,
    /// Memory figures while the model loads or runs.
    pub figures: Option<String>,
    /// Smaller notes: why it was not started, memory warnings, the countdown to stopping.
    pub notes: Vec<String>,
}

/// Colour of a status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Nothing to say.
    Neutral,
    /// Working.
    Good,
    /// Needs a look.
    Warn,
    /// Failed.
    Bad,
}

const GIB: f64 = (1u64 << 30) as f64;

/// `7.4 GB`.
pub fn gb(bytes: u64) -> String {
    format!("{:.1} GB", bytes as f64 / GIB)
}

fn device_ref(d: &DeviceInfo) -> DeviceRef {
    DeviceRef {
        uuid: d.uuid.clone(),
        index: d.index,
        vendor: d.vendor,
    }
}

pub(super) fn same(a: &DeviceRef, b: &DeviceInfo) -> bool {
    if !a.uuid.is_empty() && !b.uuid.is_empty() {
        a.uuid == b.uuid
    } else {
        a.index == b.index && a.vendor == b.vendor
    }
}

/// The cards the model would run on now: its own choice, or the default selection when it has
/// none; nothing when it runs on the processor.
pub fn effective_devices(model: &LocalModel, found: &[DeviceInfo]) -> Vec<DeviceRef> {
    if model.cpu_only {
        return Vec::new();
    }
    if model.devices.is_empty() {
        return default_devices(model.engine, found, &[]);
    }
    model.devices.clone()
}

/// The "Run on" list: every card found, greyed out with the reason where the engine cannot use
/// it.
pub fn device_rows(model: &LocalModel, found: &[DeviceInfo]) -> Vec<DeviceRow> {
    let chosen = effective_devices(model, found);
    found
        .iter()
        .map(|d| {
            let unusable = usable(model.engine, d, &[]).err();
            DeviceRow {
                device: device_ref(d),
                label: format!("{} \u{b7} {} video memory", d.name, gb(d.vram_total)),
                checked: unusable.is_none() && chosen.iter().any(|c| same(c, d)),
                unusable,
            }
        })
        .collect()
}

/// Whether the model runs on the processor only, as the card shows it.
pub fn cpu_checked(model: &LocalModel, found: &[DeviceInfo]) -> bool {
    model.cpu_only || effective_devices(model, found).is_empty()
}

/// True when the engine can run on the processor alone.
pub fn cpu_allowed(model: &LocalModel) -> bool {
    model.engine == LocalEngine::Llama
}

/// Ticks or unticks one card.
pub fn set_device(model: &mut LocalModel, found: &[DeviceInfo], card: &DeviceRef, on: bool) {
    let mut chosen = effective_devices(model, found);
    chosen.retain(|c| c.uuid != card.uuid || c.index != card.index);
    if on {
        chosen.push(card.clone());
    }
    chosen.sort_by_key(|c| c.index);
    model.cpu_only = chosen.is_empty() && cpu_allowed(model);
    model.devices = chosen;
    fix_after_device_change(model);
}

/// Ticks or unticks "CPU only".
pub fn set_cpu_only(model: &mut LocalModel, found: &[DeviceInfo], on: bool) {
    if on && cpu_allowed(model) {
        model.cpu_only = true;
        model.devices.clear();
    } else {
        model.cpu_only = false;
        model.devices = default_devices(model.engine, found, &[]);
    }
    fix_after_device_change(model);
}

fn fix_after_device_change(model: &mut LocalModel) {
    model.shares = None;
    if let Some(main) = &model.main_device
        && !model.devices.iter().any(|d| d.uuid == main.uuid)
    {
        model.main_device = None;
    }
    if model.devices.len() < 2 {
        model.multi_gpu = MultiGpuMode::Split;
    }
}

/// True when the "How to use several cards" block belongs on the card: two or more cards ticked.
pub fn several_cards(model: &LocalModel, found: &[DeviceInfo]) -> bool {
    effective_devices(model, found).len() >= 2
}

/// The ways to use several cards that the model's engine offers.
pub fn mode_options(engine: LocalEngine) -> Vec<ModeOption> {
    let mut v = vec![ModeOption {
        mode: MultiGpuMode::Split,
        title: "Split the model across the cards",
        help: "One model shared by the cards. Fits models too big for one card.",
    }];
    match engine {
        LocalEngine::Strata => v.push(ModeOption {
            mode: MultiGpuMode::CopyPerCard,
            title: "Each card runs its own full copy",
            help: "Answers more requests at once. Each card must fit the whole model.",
        }),
        LocalEngine::Llama => v.push(ModeOption {
            mode: MultiGpuMode::SplitEveryLayer,
            title: "Split every layer between the cards",
            help: "Can be faster with a fast link between the cards (NVLink). Usually slower otherwise.",
        }),
    }
    v
}

/// Chooses how several cards are used.
pub fn set_mode(model: &mut LocalModel, mode: MultiGpuMode) {
    if mode_options(model.engine).iter().any(|o| o.mode == mode) {
        model.multi_gpu = mode;
    }
}

/// The share of each ticked card, in percent: the saved ones, or an even split.
pub fn shares(model: &LocalModel, found: &[DeviceInfo]) -> Vec<u8> {
    let n = effective_devices(model, found).len();
    match &model.shares {
        Some(s) if s.len() == n => s.clone(),
        _ if n == 0 => Vec::new(),
        _ => {
            let each = (100 / n) as u8;
            let mut v = vec![each; n];
            v[0] += (100 - usize::from(each) * n) as u8;
            v
        }
    }
}

/// Sets the share of the `index`th ticked card. The rest keep their proportions of what is left.
pub fn set_share(model: &mut LocalModel, found: &[DeviceInfo], index: usize, percent: u8) {
    let chosen = effective_devices(model, found);
    if index >= chosen.len() || chosen.len() < 2 {
        return;
    }
    let mut s = shares(model, found);
    let percent = percent.clamp(1, 99);
    let others: u32 = s
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != index)
        .map(|(_, v)| u32::from(*v))
        .sum::<u32>()
        .max(1);
    let left = 100 - u32::from(percent);
    let last = (0..s.len()).rev().find(|i| *i != index).unwrap_or(0);
    let mut given = 0u32;
    for i in (0..s.len()).filter(|i| *i != index) {
        let part = if i == last {
            left.saturating_sub(given)
        } else {
            left * u32::from(s[i]) / others
        };
        let part = part.clamp(1, 99);
        s[i] = part as u8;
        given += part;
    }
    s[index] = percent;
    model.devices = chosen;
    model.shares = Some(s);
}

/// Chooses the main card (`None`: the engine's choice).
pub fn set_main(model: &mut LocalModel, found: &[DeviceInfo], main: Option<&DeviceRef>) {
    let chosen = effective_devices(model, found);
    model.main_device = main.and_then(|m| chosen.iter().find(|c| c.uuid == m.uuid).cloned());
    model.devices = chosen;
}

pub(super) fn names_of(cards: &[DeviceRef], found: &[DeviceInfo]) -> String {
    if cards.is_empty() {
        return "the processor".into();
    }
    cards
        .iter()
        .map(|c| {
            found
                .iter()
                .find(|d| same(c, d))
                .map_or_else(|| format!("card {}", c.index), |d| d.name.clone())
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// How long to say a countdown: `1:42`.
pub fn clock(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

/// The status block for `status` (`None`: the daemon has not answered yet).
pub fn status_line(status: Option<&ModelStatus>, found: &[DeviceInfo]) -> StatusLine {
    let Some(st) = status else {
        return StatusLine {
            text: "Looking...".into(),
            tone: Tone::Neutral,
            figures: None,
            notes: Vec::new(),
        };
    };
    let mut notes = Vec::new();
    notes.extend(st.warnings.iter().cloned());
    if let Some(n) = &st.notice {
        notes.push(n.clone());
    }
    if let Some(s) = st.stops_in_secs {
        notes.push(format!(
            "Nothing uses it any more. It stops in {} unless something asks for it.",
            clock(s)
        ));
    }
    let cards = st
        .stats
        .as_ref()
        .map(|s| s.devices.clone())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| st.devices.clone());
    let figures = st.stats.as_ref().filter(|_| st.is_running()).map(|s| {
        let vram: u64 = s.vram_per_device.iter().map(|d| d.bytes).sum();
        let mut parts = Vec::new();
        if vram > 0 {
            parts.push(format!("Video memory {}", gb(vram)));
        }
        if s.ram_bytes > 0 {
            parts.push(format!("RAM {}", gb(s.ram_bytes)));
        }
        parts.join(" \u{b7} ")
    });
    let figures = figures.filter(|f| !f.is_empty());
    let (text, tone) = match &st.state {
        ModelState::Stopped => ("Stopped".to_string(), Tone::Neutral),
        ModelState::Stopping => ("Stopping...".to_string(), Tone::Neutral),
        ModelState::Failed { message } => (message.clone(), Tone::Bad),
        ModelState::Loading => {
            let pct = st
                .load_fraction
                .or(st.stats.as_ref().and_then(|s| s.load_fraction))
                .map(|f| format!(" {:.0}%", f.clamp(0.0, 1.0) * 100.0))
                .unwrap_or_default();
            (
                format!("Loading{pct} on {}", names_of(&cards, found)),
                Tone::Warn,
            )
        }
        ModelState::Ready => {
            let mut t = format!("Running on {}", names_of(&cards, found));
            if let Some(stats) = &st.stats
                && let Some(v) = stats.tok_s
            {
                let about = stats.tok_s_source == Some(TokSource::Approx);
                t.push_str(&format!(
                    " \u{b7} {}{:.0} words/s roughly",
                    if about { "about " } else { "" },
                    v
                ));
            }
            (t, Tone::Good)
        }
    };
    StatusLine {
        text,
        tone,
        figures,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kraken_proto::infer::{DeviceState, DeviceVram, GpuVendor, ModelStats};

    use super::*;

    fn card(index: u32, vendor: GpuVendor, name: &str, state: DeviceState) -> DeviceInfo {
        DeviceInfo {
            index,
            uuid: format!("GPU-{index}"),
            vendor,
            name: name.into(),
            vram_total: 8 << 30,
            vram_used: 0,
            state,
        }
    }

    fn two_cards() -> Vec<DeviceInfo> {
        vec![
            card(0, GpuVendor::Nvidia, "RTX 3070 Ti", DeviceState::Ok),
            card(1, GpuVendor::Nvidia, "RTX 3060", DeviceState::Ok),
        ]
    }

    fn model(engine: LocalEngine) -> LocalModel {
        LocalModel {
            id: "m".into(),
            name: "M".into(),
            engine,
            model_path: PathBuf::from("/m"),
            devices: Vec::new(),
            cpu_only: false,
            multi_gpu: MultiGpuMode::Split,
            shares: None,
            main_device: None,
            context_size: None,
            autostart: true,
            extra: None,
        }
    }

    #[test]
    fn unusable_cards_are_greyed_with_their_reason() {
        let found = vec![
            card(0, GpuVendor::Nvidia, "RTX 3070 Ti", DeviceState::Ok),
            card(
                1,
                GpuVendor::Intel,
                "Intel UHD 750",
                DeviceState::Unsupported {
                    reason: "not supported yet".into(),
                },
            ),
            card(2, GpuVendor::Amd, "RX 7600", DeviceState::Ok),
        ];
        let rows = device_rows(&model(LocalEngine::Strata), &found);
        assert!(rows[0].checked && rows[0].unusable.is_none());
        assert_eq!(rows[1].unusable.as_deref(), Some("not supported yet"));
        assert!(!rows[1].checked);
        assert!(rows[2].unusable.as_deref().unwrap().contains("NVIDIA"));
        assert!(rows[0].label.contains("8.0 GB video memory"));
    }

    #[test]
    fn the_several_card_block_needs_two_ticked_cards() {
        let found = two_cards();
        let mut m = model(LocalEngine::Llama);
        assert!(!several_cards(&m, &found), "the default is one card");
        set_device(&mut m, &found, &found_ref(&found, 1), true);
        assert!(several_cards(&m, &found));
        set_device(&mut m, &found, &found_ref(&found, 0), false);
        assert!(!several_cards(&m, &found));
    }

    fn found_ref(found: &[DeviceInfo], i: usize) -> DeviceRef {
        device_ref(&found[i])
    }

    #[test]
    fn the_modes_depend_on_the_engine() {
        let llama: Vec<_> = mode_options(LocalEngine::Llama)
            .into_iter()
            .map(|o| o.mode)
            .collect();
        assert_eq!(
            llama,
            vec![MultiGpuMode::Split, MultiGpuMode::SplitEveryLayer]
        );
        let strata: Vec<_> = mode_options(LocalEngine::Strata)
            .into_iter()
            .map(|o| o.mode)
            .collect();
        assert_eq!(strata, vec![MultiGpuMode::Split, MultiGpuMode::CopyPerCard]);
        let mut m = model(LocalEngine::Llama);
        set_mode(&mut m, MultiGpuMode::CopyPerCard);
        assert_eq!(m.multi_gpu, MultiGpuMode::Split, "not offered by llama");
        set_mode(&mut m, MultiGpuMode::SplitEveryLayer);
        assert_eq!(m.multi_gpu, MultiGpuMode::SplitEveryLayer);
    }

    #[test]
    fn cpu_only_replaces_the_cards_and_back() {
        let found = two_cards();
        let mut m = model(LocalEngine::Llama);
        set_cpu_only(&mut m, &found, true);
        assert!(m.cpu_only && m.devices.is_empty() && cpu_checked(&m, &found));
        assert!(device_rows(&m, &found).iter().all(|r| !r.checked));
        set_cpu_only(&mut m, &found, false);
        assert!(!m.cpu_only && m.devices.len() == 1);
        let mut s = model(LocalEngine::Strata);
        set_cpu_only(&mut s, &found, true);
        assert!(!s.cpu_only, "Strata cannot run on the processor");
    }

    #[test]
    fn shares_always_add_up_to_a_hundred() {
        let found = two_cards();
        let mut m = model(LocalEngine::Llama);
        set_device(&mut m, &found, &found_ref(&found, 1), true);
        assert_eq!(shares(&m, &found), vec![50, 50]);
        set_share(&mut m, &found, 0, 70);
        assert_eq!(shares(&m, &found), vec![70, 30]);
        set_share(&mut m, &found, 1, 100);
        assert_eq!(
            shares(&m, &found)
                .iter()
                .map(|v| u32::from(*v))
                .sum::<u32>(),
            100
        );
        // Unticking a card forgets the shares and a main card that is gone.
        set_main(&mut m, &found, Some(&found_ref(&found, 1)));
        assert!(m.main_device.is_some());
        set_device(&mut m, &found, &found_ref(&found, 1), false);
        assert!(m.shares.is_none() && m.main_device.is_none());
    }

    #[test]
    fn three_cards_keep_the_sum_too() {
        let mut found = two_cards();
        found.push(card(2, GpuVendor::Nvidia, "RTX 3050", DeviceState::Ok));
        let mut m = model(LocalEngine::Strata);
        for i in 1..3 {
            set_device(&mut m, &found, &found_ref(&found, i), true);
        }
        assert_eq!(
            shares(&m, &found)
                .iter()
                .map(|v| u32::from(*v))
                .sum::<u32>(),
            100
        );
        set_share(&mut m, &found, 2, 10);
        let s = shares(&m, &found);
        assert_eq!(s.iter().map(|v| u32::from(*v)).sum::<u32>(), 100, "{s:?}");
        assert_eq!(s[2], 10);
    }

    fn status(state: ModelState) -> ModelStatus {
        ModelStatus {
            id: "m".into(),
            name: "M".into(),
            engine: Some(LocalEngine::Llama),
            state,
            base_url: None,
            served_model: None,
            api_key: None,
            port: None,
            pid: None,
            load_fraction: None,
            restarts: 0,
            uptime_secs: None,
            holders: 0,
            pinned: false,
            stops_in_secs: None,
            notice: None,
            warnings: Vec::new(),
            devices: Vec::new(),
            stats: None,
            role_assigned: false,
            autostart: true,
        }
    }

    #[test]
    fn the_status_reads_like_the_mockup() {
        let found = two_cards();
        let mut st = status(ModelState::Ready);
        st.devices = vec![device_ref(&found[0])];
        st.stats = Some(ModelStats {
            model: "m".into(),
            phase: ModelState::Ready,
            load_fraction: None,
            vram_per_device: vec![DeviceVram {
                device: device_ref(&found[0]),
                bytes: 7 << 30,
            }],
            ram_bytes: 2 << 30,
            tok_s: Some(38.0),
            tok_s_source: Some(TokSource::Engine),
            devices: vec![device_ref(&found[0])],
        });
        let l = status_line(Some(&st), &found);
        assert_eq!(l.text, "Running on RTX 3070 Ti \u{b7} 38 words/s roughly");
        assert_eq!(l.tone, Tone::Good);
        assert_eq!(
            l.figures.as_deref(),
            Some("Video memory 7.0 GB \u{b7} RAM 2.0 GB")
        );
        st.stats.as_mut().unwrap().tok_s_source = Some(TokSource::Approx);
        assert!(status_line(Some(&st), &found).text.contains("about 38"));

        let mut loading = status(ModelState::Loading);
        loading.load_fraction = Some(0.62);
        loading.devices = vec![device_ref(&found[0])];
        assert_eq!(
            status_line(Some(&loading), &found).text,
            "Loading 62% on RTX 3070 Ti"
        );
    }

    #[test]
    fn stopped_failed_and_idle_models_say_so() {
        let mut st = status(ModelState::Stopped);
        st.notice = Some("It would not fit next to the other model.".into());
        let l = status_line(Some(&st), &[]);
        assert_eq!(l.text, "Stopped");
        assert_eq!(l.notes, vec!["It would not fit next to the other model."]);
        let mut idle = status(ModelState::Ready);
        idle.stops_in_secs = Some(102);
        assert!(status_line(Some(&idle), &[]).notes[0].contains("1:42"));
        let failed = status(ModelState::Failed {
            message: "The card vanished.".into(),
        });
        let l = status_line(Some(&failed), &[]);
        assert_eq!((l.text.as_str(), l.tone), ("The card vanished.", Tone::Bad));
        assert_eq!(status_line(None, &[]).text, "Looking...");
    }
}

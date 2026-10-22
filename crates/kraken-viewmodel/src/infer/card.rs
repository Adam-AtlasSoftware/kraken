//! The model card of Settings > AI: what a local model's choices look like and how editing them
//! changes the `LocalModel` record. Pure functions over the record and the cards found on this
//! computer; the GUI only draws.

use kraken_host::infer::ModelStatus;
use kraken_infer::hardware::{default_devices, usable};
use kraken_proto::infer::{
    DeviceInfo, DeviceRef, LocalEngine, LocalModel, ModelState, MultiGpuMode, StrataTuning,
    TokSource,
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
    /// Only makes sense with two or more cards ticked.
    pub needs_two_cards: bool,
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
    let one_card_ok = mode_options(model.engine)
        .iter()
        .any(|o| o.mode == model.multi_gpu && !o.needs_two_cards);
    if model.devices.len() < 2 && !one_card_ok {
        model.multi_gpu = MultiGpuMode::Split;
    }
}

/// True when the "How to use several cards" block belongs on the card: two or more cards ticked.
pub fn several_cards(model: &LocalModel, found: &[DeviceInfo]) -> bool {
    effective_devices(model, found).len() >= 2
}

/// The ways to use several cards that the model's engine offers, whatever cards are ticked.
pub fn mode_options(engine: LocalEngine) -> Vec<ModeOption> {
    let opt = |mode, title, help, needs_two_cards| ModeOption {
        mode,
        title,
        help,
        needs_two_cards,
    };
    match engine {
        LocalEngine::Llama => vec![
            opt(
                MultiGpuMode::Split,
                "Split the model across the cards",
                "One model shared by the cards. Fits models too big for one card.",
                true,
            ),
            opt(
                MultiGpuMode::SplitEveryLayer,
                "Split every layer between the cards",
                "Can be faster with a fast link between the cards (NVLink). Usually slower otherwise.",
                true,
            ),
        ],
        LocalEngine::Strata => vec![
            opt(
                MultiGpuMode::Auto,
                "Automatic (recommended)",
                "KRAKEN picks the cards and settings each time the model starts, from the free video memory.",
                false,
            ),
            opt(
                MultiGpuMode::Split,
                "One card, or split across the cards",
                "One model shared by the cards. Fits models too big for one card.",
                false,
            ),
            opt(
                MultiGpuMode::CopyPerCard,
                "Each card runs its own full copy",
                "Answers more requests at once. Each card must fit the whole model.",
                true,
            ),
            opt(
                MultiGpuMode::PeerTier,
                "Second card helps (peer tier)",
                "Answers are about a third slower. Prompts were read faster in one early test, but not clearly so once the main card had more free memory.",
                true,
            ),
            opt(
                MultiGpuMode::HelperCache,
                "Second card as helper cache",
                "Measured slower than one card when the cards are different sizes.",
                true,
            ),
            opt(
                MultiGpuMode::PrefillPeer,
                "Second card reads prompts only",
                "Prompts are read faster and answers stay at one-card speed. Needs a Strata build with prompts-only support.",
                true,
            ),
        ],
    }
}

/// The choices to draw now: those that need two cards only when two or more are ticked.
pub fn visible_modes(model: &LocalModel, found: &[DeviceInfo]) -> Vec<ModeOption> {
    let two = several_cards(model, found);
    mode_options(model.engine)
        .into_iter()
        .filter(|o| two || !o.needs_two_cards)
        .collect()
}

/// True when the "How to use several cards" block is drawn: two or more cards ticked, or a
/// Strata model, which always has Automatic to choose.
pub fn modes_shown(model: &LocalModel, found: &[DeviceInfo]) -> bool {
    several_cards(model, found) || model.engine == LocalEngine::Strata
}

/// True for the modes where a second card keeps experts, which `peer_reserve_mib` applies to.
pub fn is_peer_mode(mode: MultiGpuMode) -> bool {
    matches!(
        mode,
        MultiGpuMode::PeerTier | MultiGpuMode::HelperCache | MultiGpuMode::PrefillPeer
    )
}

/// The Strata tuning saved on the model.
pub fn strata_tuning(model: &LocalModel) -> StrataTuning {
    StrataTuning::from_extra(model.extra.as_ref())
}

/// True when the tuning block belongs on the card.
pub fn has_strata_tuning(model: &LocalModel) -> bool {
    model.engine == LocalEngine::Strata
}

/// True when "Second card keeps free" belongs on the card.
pub fn shows_peer_reserve(model: &LocalModel) -> bool {
    has_strata_tuning(model) && is_peer_mode(model.multi_gpu)
}

/// True when any card setting is set, so "Reset to automatic" has something to do.
pub fn strata_tuning_is_set(model: &LocalModel) -> bool {
    let t = strata_tuning(model);
    t.vision.is_some()
        || t.draft.is_some()
        || t.peer_reserve_mib.is_some()
        || answer_speed(model) != AnswerSpeed::Standard
}

/// How fast Strata answers, traded against how closely it follows the full model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerSpeed {
    /// Nothing stored: Strata's own settings.
    Standard,
    Faster,
    Fastest,
    Exact,
    /// Stored values that match no preset; shown as such and left alone.
    Custom,
}

/// One preset and the values it stores (`None`: left unset, Strata's own).
pub struct SpeedPreset {
    pub speed: AnswerSpeed,
    pub tail_skip: Option<u32>,
    pub spec: Option<u32>,
    pub spec_min_p_percent: Option<u32>,
}

const fn preset(
    speed: AnswerSpeed,
    tail_skip: Option<u32>,
    spec: Option<u32>,
    spec_min_p_percent: Option<u32>,
) -> SpeedPreset {
    SpeedPreset {
        speed,
        tail_skip,
        spec,
        spec_min_p_percent,
    }
}

/// The presets a person can pick. The numbers live here and nowhere else.
pub const ANSWER_SPEED_PRESETS: [SpeedPreset; 4] = [
    preset(AnswerSpeed::Standard, None, None, None),
    preset(AnswerSpeed::Faster, Some(5), Some(3), Some(65)),
    preset(AnswerSpeed::Fastest, Some(4), Some(3), Some(65)),
    preset(AnswerSpeed::Exact, Some(0), None, None),
];

impl AnswerSpeed {
    pub fn title(self) -> &'static str {
        match self {
            Self::Standard => "Standard",
            Self::Faster => "Faster",
            Self::Fastest => "Fastest",
            Self::Exact => "Exact",
            Self::Custom => "Custom",
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::Standard => "Strata's own settings.",
            Self::Faster => {
                "About 20 percent faster answers. More rarely used experts are skipped: in one test the model's top choice for the next word changed in about 4 more places per 100 than with Standard."
            }
            Self::Fastest => {
                "About 30 percent faster. Skips still more experts: in the same test the top choice changed in about 6 more places per 100 than with Standard."
            }
            Self::Exact => {
                "No experts skipped. About 18 percent slower than Standard, but closest to the full model."
            }
            Self::Custom => "Set by hand in the configuration file. Pick a preset to replace it.",
        }
    }
}

/// The preset the stored values match, or `Custom`.
pub fn answer_speed(model: &LocalModel) -> AnswerSpeed {
    let t = strata_tuning(model);
    let stored = (t.tail_skip, t.spec, t.spec_min_p_percent);
    ANSWER_SPEED_PRESETS
        .iter()
        .find(|p| (p.tail_skip, p.spec, p.spec_min_p_percent) == stored)
        .map_or(AnswerSpeed::Custom, |p| p.speed)
}

/// Applies a preset; the other tuning fields and keys of `extra` stay. `Custom` is not a preset.
pub fn set_answer_speed(model: &mut LocalModel, speed: AnswerSpeed) {
    let Some(p) = ANSWER_SPEED_PRESETS.iter().find(|p| p.speed == speed) else {
        return;
    };
    edit_tuning(model, |t| {
        t.tail_skip = p.tail_skip;
        t.spec = p.spec;
        t.spec_min_p_percent = p.spec_min_p_percent;
    });
}

fn edit_tuning(model: &mut LocalModel, f: impl FnOnce(&mut StrataTuning)) {
    if !has_strata_tuning(model) {
        return;
    }
    let mut t = strata_tuning(model);
    f(&mut t);
    t.store(&mut model.extra);
}

/// Sets "Read pictures" (`None`: automatic).
pub fn set_vision(model: &mut LocalModel, on: Option<bool>) {
    edit_tuning(model, |t| t.vision = on);
}

/// Sets "Use the draft layer" (`None`: automatic).
pub fn set_draft(model: &mut LocalModel, on: Option<bool>) {
    edit_tuning(model, |t| t.draft = on);
}

/// Sets the video memory the second card keeps free, in MiB (`None`: automatic).
pub fn set_peer_reserve(model: &mut LocalModel, mib: Option<u32>) {
    edit_tuning(model, |t| t.peer_reserve_mib = mib);
}

/// Clears the card settings and the answer speed back to automatic. Other tuning keys stay as they are.
pub fn reset_strata_tuning(model: &mut LocalModel) {
    edit_tuning(model, |t| {
        t.vision = None;
        t.draft = None;
        t.peer_reserve_mib = None;
        t.tail_skip = None;
        t.spec = None;
        t.spec_min_p_percent = None;
    });
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
        assert_eq!(
            strata,
            vec![
                MultiGpuMode::Auto,
                MultiGpuMode::Split,
                MultiGpuMode::CopyPerCard,
                MultiGpuMode::PeerTier,
                MultiGpuMode::HelperCache,
                MultiGpuMode::PrefillPeer,
            ]
        );
        let mut m = model(LocalEngine::Llama);
        set_mode(&mut m, MultiGpuMode::CopyPerCard);
        assert_eq!(m.multi_gpu, MultiGpuMode::Split, "not offered by llama");
        set_mode(&mut m, MultiGpuMode::SplitEveryLayer);
        assert_eq!(m.multi_gpu, MultiGpuMode::SplitEveryLayer);
    }

    #[test]
    fn strata_offers_automatic_on_one_card_and_the_peer_modes_on_two() {
        let found = two_cards();
        let mut m = model(LocalEngine::Strata);
        let one: Vec<_> = visible_modes(&m, &found).iter().map(|o| o.mode).collect();
        assert_eq!(one, vec![MultiGpuMode::Auto, MultiGpuMode::Split]);
        assert!(modes_shown(&m, &found));
        set_device(&mut m, &found, &found_ref(&found, 1), true);
        assert_eq!(visible_modes(&m, &found).len(), 6);
        for mode in [
            MultiGpuMode::Auto,
            MultiGpuMode::PeerTier,
            MultiGpuMode::HelperCache,
            MultiGpuMode::PrefillPeer,
            MultiGpuMode::CopyPerCard,
        ] {
            set_mode(&mut m, mode);
            assert_eq!(m.multi_gpu, mode);
        }
        set_mode(&mut m, MultiGpuMode::PrefillPeer);
        set_device(&mut m, &found, &found_ref(&found, 1), false);
        assert_eq!(
            m.multi_gpu,
            MultiGpuMode::Split,
            "a peer mode needs two cards"
        );
        set_device(&mut m, &found, &found_ref(&found, 1), true);
        set_mode(&mut m, MultiGpuMode::Auto);
        set_device(&mut m, &found, &found_ref(&found, 1), false);
        assert_eq!(
            m.multi_gpu,
            MultiGpuMode::Auto,
            "automatic works on one card"
        );

        let mut l = model(LocalEngine::Llama);
        set_device(&mut l, &found, &found_ref(&found, 1), true);
        assert_eq!(visible_modes(&l, &found).len(), 2);
        set_mode(&mut l, MultiGpuMode::Auto);
        set_mode(&mut l, MultiGpuMode::PeerTier);
        assert_eq!(l.multi_gpu, MultiGpuMode::Split);
        assert!(!modes_shown(&model(LocalEngine::Llama), &found));
    }

    #[test]
    fn every_answer_speed_preset_round_trips_and_keeps_the_rest() {
        let mut m = model(LocalEngine::Strata);
        m.extra = Some(serde_json::json!({"other": 1}));
        assert_eq!(answer_speed(&m), AnswerSpeed::Standard);
        set_vision(&mut m, Some(false));
        set_draft(&mut m, Some(true));
        set_peer_reserve(&mut m, Some(1500));
        for SpeedPreset { speed: preset, .. } in ANSWER_SPEED_PRESETS {
            set_answer_speed(&mut m, preset);
            assert_eq!(answer_speed(&m), preset);
            let t = strata_tuning(&m);
            assert_eq!(
                (t.vision, t.draft, t.peer_reserve_mib),
                (Some(false), Some(true), Some(1500))
            );
            assert_eq!(m.extra.as_ref().map(|e| e["other"].clone()), Some(1.into()));
        }
        set_answer_speed(&mut m, AnswerSpeed::Faster);
        let t = strata_tuning(&m);
        assert_eq!(
            (t.tail_skip, t.spec, t.spec_min_p_percent),
            (Some(5), Some(3), Some(65))
        );
        set_answer_speed(&mut m, AnswerSpeed::Fastest);
        assert_eq!(strata_tuning(&m).tail_skip, Some(4));
        set_answer_speed(&mut m, AnswerSpeed::Exact);
        let t = strata_tuning(&m);
        assert_eq!(
            (t.tail_skip, t.spec, t.spec_min_p_percent),
            (Some(0), None, None)
        );
        set_answer_speed(&mut m, AnswerSpeed::Standard);
        let t = strata_tuning(&m);
        assert_eq!(
            (t.tail_skip, t.spec, t.spec_min_p_percent),
            (None, None, None)
        );
    }

    #[test]
    fn unmatched_answer_speed_values_are_custom_until_a_preset_is_picked() {
        let mut m = model(LocalEngine::Strata);
        m.extra = Some(serde_json::json!({"strata": {"tail_skip": 6}}));
        assert_eq!(answer_speed(&m), AnswerSpeed::Custom);
        set_answer_speed(&mut m, AnswerSpeed::Custom);
        assert_eq!(answer_speed(&m), AnswerSpeed::Custom);
        assert_eq!(strata_tuning(&m).tail_skip, Some(6), "left untouched");
        assert!(strata_tuning_is_set(&m));
        set_answer_speed(&mut m, AnswerSpeed::Faster);
        assert_eq!(answer_speed(&m), AnswerSpeed::Faster);
    }

    #[test]
    fn reset_clears_the_answer_speed() {
        let mut m = model(LocalEngine::Strata);
        m.extra = Some(serde_json::json!({"other": 1}));
        set_answer_speed(&mut m, AnswerSpeed::Fastest);
        assert!(strata_tuning_is_set(&m));
        reset_strata_tuning(&mut m);
        assert_eq!(answer_speed(&m), AnswerSpeed::Standard);
        assert_eq!(m.extra, Some(serde_json::json!({"other": 1})));
        assert!(!strata_tuning_is_set(&m));
    }

    #[test]
    fn the_strata_tuning_round_trips_through_extra_and_resets_to_automatic() {
        let mut m = model(LocalEngine::Strata);
        m.extra = Some(serde_json::json!({"other": 1}));
        assert!(!strata_tuning_is_set(&m));
        set_vision(&mut m, Some(false));
        set_draft(&mut m, Some(true));
        set_peer_reserve(&mut m, Some(1500));
        let t = strata_tuning(&m);
        assert_eq!(
            (t.vision, t.draft, t.peer_reserve_mib),
            (Some(false), Some(true), Some(1500))
        );
        assert!(strata_tuning_is_set(&m));
        assert_eq!(m.extra.as_ref().map(|e| e["other"].clone()), Some(1.into()));
        reset_strata_tuning(&mut m);
        assert_eq!(m.extra, Some(serde_json::json!({"other": 1})));
        assert!(!strata_tuning_is_set(&m));
        let mut bare = model(LocalEngine::Strata);
        set_draft(&mut bare, Some(false));
        reset_strata_tuning(&mut bare);
        assert_eq!(
            bare.extra, None,
            "the key goes, and the empty object with it"
        );

        let mut l = model(LocalEngine::Llama);
        set_vision(&mut l, Some(true));
        assert_eq!(l.extra, None, "not a Strata model");
    }

    #[test]
    fn the_second_card_reserve_is_for_the_peer_modes() {
        let mut m = model(LocalEngine::Strata);
        assert!(!shows_peer_reserve(&m));
        m.multi_gpu = MultiGpuMode::PeerTier;
        assert!(shows_peer_reserve(&m));
        let mut l = model(LocalEngine::Llama);
        l.multi_gpu = MultiGpuMode::PeerTier;
        assert!(!shows_peer_reserve(&l));
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

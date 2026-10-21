//! Chooses how Strata uses the cards of this computer: which card is the main one, whether a
//! second card helps, and what to give up when the main card is short of video memory.
//!
//! The figures come from measurements of the Swift 1.5 IQ2_XS model on an RTX 3070 Ti (8 GiB,
//! main) with an RTX 2060 (6 GiB, second): one card read prompts at about 650 to 690 tokens per
//! second and answered at about 66; a second card as peer tier read prompts at 875 to 913 and
//! answered at about 45; a layer split did not start because the 6 GiB card had no room for its
//! own copy of the dense weights. Other models need somewhat different amounts, which is why
//! the constants below are estimates and the engine's own check still has the last word.

use kraken_proto::infer::{
    DeviceInfo, DeviceRef, DeviceState, LocalEngine, LocalModel, MultiGpuMode, StrataTuning,
};

use crate::hardware::usable;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

/// The context the engine uses when the model sets none.
pub const ENGINE_CONTEXT: u32 = 65_536;
/// Video memory the second card leaves free, so its prompt buffers fit (500 MiB crashed the
/// first prompt, 1000 MiB ran every test).
pub const PEER_RESERVE_MIB: u32 = 1000;
/// Video memory the engine keeps free on the main card. It grows when the card also drives a
/// monitor, because the engine's own advice for a card with a display is "more".
const MAIN_RESERVE_MIB: u64 = 700;
const MAIN_RESERVE_DISPLAY_MIB: u64 = 1000;
/// The least the expert cache needs on the main card (364 experts), and the least a second
/// card must have left after its reserve to be worth using.
const MIN_CACHE: u64 = 524 * MIB;
const MIN_PEER_CACHE: u64 = 3 * GIB / 2;
/// A card smaller than this cannot hold the dense weights of the main card.
const MIN_CARD: u64 = 4 * GIB;

/// What gives way, in order, when the main card is short of memory. `base` is what the model's
/// own weights, the draft layer, the head, the context and the prompt buffers take on the main
/// card. Level 0 is the engine's usual start.
struct Level {
    context: u32,
    draft: bool,
    base: u64,
}

const LEVELS: [Level; 5] = [
    Level {
        context: 65_536,
        draft: true,
        base: 5 * GIB + 100 * MIB,
    },
    Level {
        context: 32_768,
        draft: true,
        base: 5 * GIB - 140 * MIB,
    },
    Level {
        context: 16_384,
        draft: true,
        base: 5 * GIB - 250 * MIB,
    },
    Level {
        context: 65_536,
        draft: false,
        base: 4 * GIB + 280 * MIB,
    },
    Level {
        context: 32_768,
        draft: false,
        base: 4 * GIB + 60 * MIB,
    },
];

/// What [`plan`] looks at.
pub struct PlanInput<'a> {
    /// The cards found on this computer, with the memory in use right now.
    pub devices: &'a [DeviceInfo],
    /// Numbers (`DeviceInfo::index`) of the cards that have a monitor connected.
    pub display: &'a [u32],
    /// The model as saved.
    pub model: &'a LocalModel,
    /// Whether the installed engine can keep the second card out of answering
    /// ([`MultiGpuMode::PrefillPeer`]).
    pub prefill_peer: bool,
}

/// How to run, in the words of the settings, plus what to tell the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// A concrete mode, never [`MultiGpuMode::Auto`].
    pub mode: MultiGpuMode,
    /// The cards, main card first.
    pub devices: Vec<DeviceRef>,
    /// Every field filled in.
    pub tuning: StrataTuning,
    /// Context size to run with; `None` leaves the engine's own.
    pub context_size: Option<u32>,
    /// Whether the main card has room for the model at all.
    pub fits: bool,
    /// What was decided and why, in plain words.
    pub notes: Vec<String>,
    /// What the person could change to get more speed.
    pub advice: Vec<String>,
}

impl Plan {
    /// The model as it is run this time: the plan's cards, mode, context and settings. The saved
    /// model is not touched.
    pub fn apply(&self, model: &LocalModel) -> LocalModel {
        let mut m = model.clone();
        m.multi_gpu = self.mode;
        m.devices = self.devices.clone();
        m.main_device = None;
        m.shares = None;
        m.context_size = self.context_size.or(model.context_size);
        self.tuning.store(&mut m.extra);
        m
    }
}

fn dref(d: &DeviceInfo) -> DeviceRef {
    DeviceRef {
        uuid: d.uuid.clone(),
        index: d.index,
        vendor: d.vendor,
    }
}

fn free(d: &DeviceInfo) -> u64 {
    d.vram_total.saturating_sub(d.vram_used)
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

/// The first level at which `card` works as the main card, with `context` fixed when the person
/// set one and `draft` fixed when they chose it.
fn level_for(
    card: &DeviceInfo,
    display: bool,
    context: Option<u32>,
    draft: Option<bool>,
) -> Option<usize> {
    let reserve = if display {
        MAIN_RESERVE_DISPLAY_MIB
    } else {
        MAIN_RESERVE_MIB
    } * MIB;
    LEVELS.iter().position(|l| {
        (context.is_none() || l.context == ENGINE_CONTEXT)
            && draft.is_none_or(|d| d == l.draft)
            && free(card) >= l.base + reserve + MIN_CACHE
    })
}

fn chosen_cards<'a>(input: &PlanInput<'a>) -> Vec<&'a DeviceInfo> {
    let usable_card = |d: &&DeviceInfo| {
        d.state == DeviceState::Ok
            && d.vram_total >= MIN_CARD
            && usable(LocalEngine::Strata, d, &[]).is_ok()
    };
    if input.model.multi_gpu != MultiGpuMode::Auto && !input.model.devices.is_empty() {
        return input
            .model
            .devices
            .iter()
            .filter_map(|r| {
                input.devices.iter().find(|d| {
                    if r.uuid.is_empty() {
                        d.index == r.index && d.vendor == r.vendor
                    } else {
                        d.uuid == r.uuid
                    }
                })
            })
            .collect();
    }
    let mut cards: Vec<&DeviceInfo> = input.devices.iter().filter(usable_card).collect();
    cards.sort_by(|a, b| {
        b.vram_total
            .cmp(&a.vram_total)
            .then(free(b).cmp(&free(a)))
            .then(a.index.cmp(&b.index))
    });
    cards
}

/// Works out how to run `input.model` on this computer. Settings the person made win; the rest
/// follow the cards as they are right now, so moving a monitor to the other card changes the
/// next start.
pub fn plan(input: &PlanInput<'_>) -> Plan {
    let model = input.model;
    let tuning_in = StrataTuning::from_extra(model.extra.as_ref());
    let auto = model.multi_gpu == MultiGpuMode::Auto;
    let cards = chosen_cards(input);
    let on_display = |d: &DeviceInfo| input.display.contains(&d.index);
    let mut notes = Vec::new();
    let mut advice = Vec::new();

    // The main card: the one the person put first, else the largest card that works, else the
    // largest card.
    let explicit = !auto && !model.devices.is_empty();
    let level_of =
        |c: &DeviceInfo| level_for(c, on_display(c), model.context_size, tuning_in.draft);
    let main_pick = if explicit {
        cards
            .first()
            .map(|c| (*c, level_of(c).unwrap_or(LEVELS.len() - 1)))
    } else {
        cards
            .iter()
            .find_map(|c| level_of(c).map(|l| (*c, l)))
            .or_else(|| cards.first().map(|c| (*c, LEVELS.len() - 1)))
    };
    let Some((main, level)) = main_pick else {
        return Plan {
            mode: MultiGpuMode::Split,
            devices: Vec::new(),
            tuning: tuning_in,
            context_size: model.context_size,
            fits: false,
            notes: vec!["No NVIDIA card that Strata can use was found.".into()],
            advice,
        };
    };
    let fits = level_of(main).is_some();
    let lv = &LEVELS[level];

    if !fits {
        notes.push(format!(
            "{} has {} of video memory free, which is not enough even with the draft layer and \
             a short context left out.",
            main.name,
            gib(free(main))
        ));
    }
    if on_display(main) {
        notes.push(format!(
            "A monitor is connected to {}, so the desktop is using {} of its video memory and the \
             engine keeps more of it free.",
            main.name,
            gib(main.vram_used)
        ));
    }
    let context_size = if model.context_size.is_none() && lv.context != ENGINE_CONTEXT {
        notes.push(format!(
            "The context is {} tokens instead of {} to fit the free video memory.",
            lv.context, ENGINE_CONTEXT
        ));
        Some(lv.context)
    } else {
        model.context_size
    };
    let draft = tuning_in.draft.unwrap_or(lv.draft);
    if tuning_in.draft.is_none() && !lv.draft {
        notes.push(
            "The draft layer is off to save video memory; answers are slower without it.".into(),
        );
    }
    if on_display(main)
        && let Some(other) = cards
            .iter()
            .find(|c| !std::ptr::eq(**c, main) && !on_display(c))
    {
        advice.push(format!(
            "Connecting your monitors to {} instead would free the {} the desktop uses on {}.",
            other.name,
            gib(main.vram_used),
            main.name
        ));
    }

    // The second card.
    let reserve_mib = tuning_in.peer_reserve_mib.unwrap_or(PEER_RESERVE_MIB);
    let peer = cards
        .iter()
        .find(|c| {
            !std::ptr::eq(**c, main)
                && free(c) >= u64::from(reserve_mib) * MIB + MIN_PEER_CACHE
                && c.vendor == main.vendor
        })
        .copied();
    let wanted = if auto { None } else { Some(model.multi_gpu) };
    let (mode, devices) = match (wanted, peer) {
        (None, Some(p)) if input.prefill_peer && fits => {
            notes.push(format!(
                "{} helps read long prompts and stays out of answering.",
                p.name
            ));
            (MultiGpuMode::PrefillPeer, vec![dref(main), dref(p)])
        }
        (None, Some(p)) => {
            advice.push(if input.prefill_peer {
                format!(
                    "{} is not used because {} is short of memory.",
                    p.name, main.name
                )
            } else {
                format!(
                    "{} could read long prompts about 30 percent faster as a peer tier, at the \
                     cost of answering about a third slower. Choose \"Peer tier\" under Several \
                     cards to try it.",
                    p.name
                )
            });
            (MultiGpuMode::Split, vec![dref(main)])
        }
        (None, None) => (MultiGpuMode::Split, vec![dref(main)]),
        (
            Some(
                m
                @ (MultiGpuMode::PeerTier | MultiGpuMode::HelperCache | MultiGpuMode::PrefillPeer),
            ),
            Some(p),
        ) => (m, vec![dref(main), dref(p)]),
        (
            Some(MultiGpuMode::PeerTier | MultiGpuMode::HelperCache | MultiGpuMode::PrefillPeer),
            None,
        ) => {
            notes.push(format!(
                "No second card has enough free video memory, so the model runs on {} alone.",
                main.name
            ));
            (MultiGpuMode::Split, vec![dref(main)])
        }
        (Some(m), _) => (m, cards.iter().map(|c| dref(c)).collect()),
    };
    let tuning = StrataTuning {
        vision: tuning_in.vision,
        peer_reserve_mib: Some(reserve_mib),
        draft: Some(draft),
        vram_reserve_mib: Some(tuning_in.vram_reserve_mib.unwrap_or(if on_display(main) {
            MAIN_RESERVE_DISPLAY_MIB as u32
        } else {
            MAIN_RESERVE_MIB as u32
        })),
    };
    Plan {
        mode,
        devices,
        tuning,
        context_size,
        fits,
        notes,
        advice,
    }
}

#[cfg(test)]
mod tests {
    use kraken_proto::infer::GpuVendor;

    use super::*;

    fn card(index: u32, name: &str, total_gib: f64, used_gib: f64) -> DeviceInfo {
        DeviceInfo {
            index,
            uuid: format!("GPU-{index}"),
            vendor: GpuVendor::Nvidia,
            name: name.into(),
            vram_total: (total_gib * GIB as f64) as u64,
            vram_used: (used_gib * GIB as f64) as u64,
            state: DeviceState::Ok,
        }
    }

    fn model() -> LocalModel {
        LocalModel {
            id: "strata".into(),
            name: "Strata".into(),
            engine: LocalEngine::Strata,
            model_path: "/m".into(),
            devices: Vec::new(),
            cpu_only: false,
            multi_gpu: MultiGpuMode::Auto,
            shares: None,
            main_device: None,
            context_size: None,
            autostart: true,
            extra: None,
        }
    }

    /// RTX 2060 (number 0) and RTX 3070 Ti (number 1) as on the machine of the measurements.
    fn rig(used_2060: f64, used_3070: f64) -> Vec<DeviceInfo> {
        vec![
            card(0, "RTX 2060", 6.0, used_2060),
            card(1, "RTX 3070 Ti", 8.0, used_3070),
        ]
    }

    fn run(devices: &[DeviceInfo], display: &[u32], prefill_peer: bool) -> Plan {
        let m = model();
        plan(&PlanInput {
            devices,
            display,
            model: &m,
            prefill_peer,
        })
    }

    #[test]
    fn monitor_on_the_small_card_runs_the_big_card_alone_at_full_settings() {
        let p = run(&rig(0.1, 1.2), &[0], false);
        assert_eq!(p.mode, MultiGpuMode::Split);
        assert_eq!(p.devices.len(), 1);
        assert_eq!(p.devices[0].index, 1);
        assert_eq!(p.context_size, None);
        assert_eq!(p.tuning.draft, Some(true));
        assert!(p.fits);
        assert!(
            p.advice.iter().any(|a| a.contains("peer tier")),
            "the second card is offered: {:?}",
            p.advice
        );
    }

    #[test]
    fn an_engine_with_prefill_peer_uses_the_second_card_for_prompts() {
        let p = run(&rig(0.1, 1.2), &[0], true);
        assert_eq!(p.mode, MultiGpuMode::PrefillPeer);
        let order: Vec<u32> = p.devices.iter().map(|d| d.index).collect();
        assert_eq!(order, vec![1, 0], "main card first");
        assert_eq!(p.tuning.peer_reserve_mib, Some(1000));
    }

    #[test]
    fn monitor_on_the_big_card_gives_up_context_and_the_draft_layer_not_the_run() {
        let p = run(&rig(0.1, 2.4), &[1], true);
        assert!(p.fits, "{:?}", p.notes);
        assert_eq!(p.devices[0].index, 1);
        assert_eq!(p.context_size, Some(32_768));
        assert_eq!(p.tuning.draft, Some(false));
        assert_eq!(p.tuning.vram_reserve_mib, Some(1000));
        assert!(p.notes.iter().any(|n| n.contains("monitor")));
        assert!(
            p.advice
                .iter()
                .any(|a| a.contains("Connecting your monitors")),
            "{:?}",
            p.advice
        );
    }

    #[test]
    fn a_choice_the_person_made_is_kept() {
        let mut m = model();
        m.context_size = Some(65_536);
        StrataTuning {
            draft: Some(true),
            ..StrataTuning::default()
        }
        .store(&mut m.extra);
        let d = rig(0.1, 2.4);
        let p = plan(&PlanInput {
            devices: &d,
            display: &[1],
            model: &m,
            prefill_peer: false,
        });
        assert!(!p.fits, "draft layer and 64K asked for, too little memory");
        assert_eq!(p.tuning.draft, Some(true));
        assert_eq!(p.context_size, Some(65_536));
    }

    #[test]
    fn an_explicit_peer_tier_keeps_its_mode_and_orders_the_cards() {
        let mut m = model();
        m.multi_gpu = MultiGpuMode::PeerTier;
        let d = rig(0.1, 1.2);
        m.devices = vec![dref(&d[1]), dref(&d[0])];
        let p = plan(&PlanInput {
            devices: &d,
            display: &[0],
            model: &m,
            prefill_peer: false,
        });
        assert_eq!(p.mode, MultiGpuMode::PeerTier);
        assert_eq!(
            p.devices.iter().map(|x| x.index).collect::<Vec<_>>(),
            vec![1, 0]
        );
    }

    #[test]
    fn one_big_card_and_nothing_else_is_a_single_card_run() {
        let d = vec![card(0, "RTX 4090", 24.0, 0.5)];
        let p = run(&d, &[0], true);
        assert_eq!(p.mode, MultiGpuMode::Split);
        assert_eq!(p.devices.len(), 1);
        assert_eq!(p.context_size, None);
    }

    #[test]
    fn no_usable_card_is_said_plainly() {
        let p = run(&[], &[], true);
        assert!(!p.fits && p.devices.is_empty());
        assert!(p.notes[0].contains("No NVIDIA card"));
    }

    #[test]
    fn applying_a_plan_leaves_the_saved_model_alone() {
        let m = model();
        let d = rig(0.1, 2.4);
        let p = plan(&PlanInput {
            devices: &d,
            display: &[1],
            model: &m,
            prefill_peer: false,
        });
        let run = p.apply(&m);
        assert_eq!(m.multi_gpu, MultiGpuMode::Auto);
        assert_eq!(run.multi_gpu, MultiGpuMode::Split);
        assert_eq!(run.context_size, Some(32_768));
        assert_eq!(
            StrataTuning::from_extra(run.extra.as_ref()).draft,
            Some(false)
        );
    }
}

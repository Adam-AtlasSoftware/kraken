//! The model chips of the title bar: one small badge per local model that matters now (given
//! a role, loading, running or failed) and one for a server the person runs. Pure: the models
//! the service reports and the room there is go in, descriptions of what to draw come out.

use kraken_host::infer::ModelStatus;
use kraken_proto::infer::{DeviceInfo, ModelState, TokSource};

use super::card::{Tone, clock, gb, names_of, same};

/// What a chip's button does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipAction {
    /// Start serving the model.
    Start,
    /// Stop serving it.
    Stop,
}

impl ChipAction {
    /// The button's text.
    pub fn label(self) -> &'static str {
        match self {
            ChipAction::Start => "Start",
            ChipAction::Stop => "Stop",
        }
    }
}

/// Where a chip's model is in its life, for drawing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipState {
    /// Answering requests.
    Ready,
    /// Loading its weights.
    Loading,
    /// Shutting down.
    Stopping,
    /// Set up for a role but not running.
    Stopped,
    /// Could not run.
    Failed,
    /// A server the person runs.
    External,
}

/// One chip.
#[derive(Debug, Clone, PartialEq)]
pub struct Chip {
    /// The model's id; `external` for the server chip.
    pub key: String,
    /// Name shown first.
    pub name: String,
    /// Colour of the dot.
    pub tone: Tone,
    /// The state.
    pub state: ChipState,
    /// A word about the state when the figures do not say it: `loading 62%`, `stopped`.
    pub label: Option<String>,
    /// The figures, in order: cards, video memory, RAM, speed.
    pub parts: Vec<String>,
    /// How far the loading is (0 to 1): the fill behind the content.
    pub progress: Option<f32>,
    /// The button.
    pub action: Option<ChipAction>,
    /// `stops in 1:45` while nothing uses the model.
    pub countdown: Option<String>,
    /// Only the name and the dot, for lack of room.
    pub collapsed: bool,
    /// Lines of the tooltip.
    pub hover: Vec<String>,
}

const CHAR_W: f32 = 6.6;
const NAME_CHAR_W: f32 = 7.4;
const PAD: f32 = 26.0;
const BUTTON_W: f32 = 54.0;
const GAP: f32 = 6.0;
const OVERFLOW_W: f32 = 34.0;

impl Chip {
    /// A guess of the width the chip takes, in points.
    pub fn estimated_width(&self) -> f32 {
        let name = self.name.chars().count() as f32 * NAME_CHAR_W;
        if self.collapsed {
            return PAD + name;
        }
        let text: usize = self
            .label
            .iter()
            .chain(self.parts.iter())
            .chain(self.countdown.iter())
            .map(|t| t.chars().count() + 2)
            .sum();
        PAD + name + text as f32 * CHAR_W + if self.action.is_some() { BUTTON_W } else { 0.0 }
    }
}

/// What the person runs outside KRAKEN, as far as KRAKEN can tell.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalServer {
    /// `Ollama`, `vLLM`, or the address.
    pub name: String,
    /// The server's address, for the tooltip.
    pub url: String,
    /// Whether it answered the last look; `None` before the first one.
    pub reachable: Option<bool>,
    /// Words per second measured from the assistant's replies.
    pub tok_s: Option<f32>,
}

/// The chips that fit, and how many more would not.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ChipBar {
    /// Left to right.
    pub chips: Vec<Chip>,
    /// Chips left out for lack of room, even collapsed.
    pub hidden: usize,
}

impl ChipBar {
    /// A guess of the width of the whole bar, in points.
    pub fn estimated_width(&self) -> f32 {
        let chips: f32 = self.chips.iter().map(Chip::estimated_width).sum();
        chips
            + GAP * self.chips.len().saturating_sub(1) as f32
            + if self.hidden > 0 { OVERFLOW_W } else { 0.0 }
    }

    /// True when there is nothing to draw.
    pub fn is_empty(&self) -> bool {
        self.chips.is_empty() && self.hidden == 0
    }
}

/// Whether a model deserves a chip: it has a role, or something is going on with it.
pub fn shows(m: &ModelStatus) -> bool {
    m.role_assigned
        || matches!(
            m.state,
            ModelState::Loading
                | ModelState::Ready
                | ModelState::Stopping
                | ModelState::Failed { .. }
        )
}

fn speed(v: f32, source: Option<TokSource>) -> String {
    let n = format!("{:.0} tok/s", v.max(0.0));
    if source == Some(TokSource::Approx) {
        format!("about {n}")
    } else {
        n
    }
}

fn model_chip(m: &ModelStatus, found: &[DeviceInfo]) -> Chip {
    let cards = m
        .stats
        .as_ref()
        .map(|s| s.devices.clone())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| m.devices.clone());
    let mut hover = Vec::new();
    let mut parts = Vec::new();
    let mut label = None;
    let mut progress = None;
    let (state, tone, action) = match &m.state {
        ModelState::Ready => (ChipState::Ready, Tone::Good, Some(ChipAction::Stop)),
        ModelState::Loading => (ChipState::Loading, Tone::Warn, Some(ChipAction::Stop)),
        ModelState::Stopping => (ChipState::Stopping, Tone::Neutral, None),
        ModelState::Stopped => (ChipState::Stopped, Tone::Neutral, Some(ChipAction::Start)),
        ModelState::Failed { .. } => (ChipState::Failed, Tone::Bad, None),
    };

    if m.is_running() {
        if state == ChipState::Loading {
            let f = m
                .load_fraction
                .or(m.stats.as_ref().and_then(|s| s.load_fraction));
            progress = f.map(|f| f.clamp(0.0, 1.0));
            label = Some(match progress {
                Some(f) => format!("loading {:.0}%", f * 100.0),
                None => "loading".into(),
            });
            parts.push(format!("on {}", names_of(&cards, found)));
        }
        if let Some(s) = &m.stats {
            let used: u64 = s.vram_per_device.iter().map(|d| d.bytes).sum();
            if used > 0 {
                let total: u64 = cards
                    .iter()
                    .filter_map(|c| found.iter().find(|d| same(c, d)))
                    .map(|d| d.vram_total)
                    .sum();
                parts.push(if total > 0 && state == ChipState::Ready {
                    format!(
                        "VRAM {:.1}/{:.1} GB",
                        used as f64 / (1u64 << 30) as f64,
                        total as f64 / (1u64 << 30) as f64
                    )
                } else {
                    format!("VRAM {}", gb(used))
                });
            }
            if s.ram_bytes > 0 {
                parts.push(format!("RAM {}", gb(s.ram_bytes)));
            }
            if state == ChipState::Ready
                && let Some(v) = s.tok_s
            {
                parts.push(speed(v, s.tok_s_source));
            }
            for v in &s.vram_per_device {
                let name = found
                    .iter()
                    .find(|d| same(&v.device, d))
                    .map_or_else(|| format!("card {}", v.device.index), |d| d.name.clone());
                hover.push(format!("{name}: {} video memory", gb(v.bytes)));
            }
        }
    } else {
        label = Some(
            match state {
                ChipState::Failed => "failed",
                ChipState::Stopping => "stopping",
                _ => "stopped",
            }
            .into(),
        );
    }
    if let ModelState::Failed { message } = &m.state {
        hover.insert(0, message.clone());
    }
    hover.push(format!(
        "Runs on {}",
        names_of(&cards, found).replace(" and ", ", ")
    ));
    if let Some(e) = m.engine {
        let e = format!("{e:?}").to_lowercase();
        hover.push(format!("Engine: {e}"));
    }
    if let Some(p) = m.port {
        hover.push(format!("Port: {p}"));
    }
    hover.extend(m.notice.iter().cloned());
    hover.extend(m.warnings.iter().cloned());

    Chip {
        key: m.id.clone(),
        name: m.name.clone(),
        tone,
        state,
        label,
        parts,
        progress,
        action,
        countdown: m
            .stops_in_secs
            .filter(|_| m.is_running())
            .map(|s| format!("stops in {}", clock(s))),
        collapsed: false,
        hover,
    }
}

fn external_chip(e: &ExternalServer) -> Chip {
    let (tone, label) = match e.reachable {
        Some(true) => (Tone::Good, "reachable"),
        Some(false) => (Tone::Bad, "unreachable"),
        None => (Tone::Neutral, "checking"),
    };
    let mut hover = vec![
        format!("A server you run yourself: {}", e.url),
        "KRAKEN cannot start or stop it.".to_string(),
    ];
    if e.reachable == Some(false) {
        hover.push("It did not answer. Is it running?".into());
    }
    hover.push("Speed is measured from the assistant's replies.".into());
    Chip {
        key: "external".into(),
        name: e.name.clone(),
        tone,
        state: ChipState::External,
        label: Some(label.into()),
        parts: e
            .tok_s
            .filter(|_| e.reachable == Some(true))
            .map(|v| speed(v, Some(TokSource::Approx)))
            .into_iter()
            .collect(),
        progress: None,
        action: None,
        countdown: None,
        collapsed: false,
        hover,
    }
}

/// The chips for `models` (and the server the person runs, if any) that fit in `budget`
/// points: all in full if they fit; otherwise the last ones shrink to a name and a dot one by
/// one, and chips that still do not fit are counted in [`ChipBar::hidden`].
pub fn chip_bar(
    models: &[ModelStatus],
    found: &[DeviceInfo],
    external: Option<&ExternalServer>,
    budget: f32,
) -> ChipBar {
    let mut chips: Vec<Chip> = models
        .iter()
        .filter(|m| shows(m))
        .map(|m| model_chip(m, found))
        .collect();
    chips.extend(external.map(external_chip));
    let total = |c: &[Chip]| -> f32 {
        c.iter().map(Chip::estimated_width).sum::<f32>() + GAP * c.len().saturating_sub(1) as f32
    };
    for i in (0..chips.len()).rev() {
        if total(&chips) <= budget {
            break;
        }
        chips[i].collapsed = true;
    }
    let mut hidden = 0;
    while total(&chips) + if hidden > 0 { OVERFLOW_W } else { 0.0 } > budget && !chips.is_empty() {
        chips.pop();
        hidden += 1;
    }
    ChipBar { chips, hidden }
}

#[cfg(test)]
mod tests {
    use kraken_proto::infer::{DeviceRef, DeviceState, DeviceVram, GpuVendor, ModelStats};

    use super::*;
    use crate::infer::fake::stopped_status;

    fn card(i: u32, name: &str) -> DeviceInfo {
        DeviceInfo {
            index: i,
            uuid: format!("GPU-{i}"),
            vendor: GpuVendor::Nvidia,
            name: name.into(),
            vram_total: 8 << 30,
            vram_used: 0,
            state: DeviceState::Ok,
        }
    }

    fn on(i: u32) -> DeviceRef {
        DeviceRef {
            uuid: format!("GPU-{i}"),
            index: i,
            vendor: GpuVendor::Nvidia,
        }
    }

    fn running(id: &str, state: ModelState) -> ModelStatus {
        let mut m = stopped_status(id, id);
        m.state = state.clone();
        m.devices = vec![on(0)];
        m.port = Some(41234);
        m.stats = Some(ModelStats {
            model: id.into(),
            phase: state,
            load_fraction: None,
            vram_per_device: vec![DeviceVram {
                device: on(0),
                bytes: 7_400_000_000,
            }],
            ram_bytes: 41_200_000_000,
            tok_s: Some(38.0),
            tok_s_source: Some(TokSource::Engine),
            devices: vec![on(0)],
        });
        m
    }

    fn bar(models: &[ModelStatus], budget: f32) -> ChipBar {
        chip_bar(models, &[card(0, "RTX 3070 Ti")], None, budget)
    }

    #[test]
    fn a_ready_model_shows_memory_ram_speed_and_stop() {
        let b = bar(&[running("strata", ModelState::Ready)], 2000.0);
        let c = &b.chips[0];
        assert_eq!(c.state, ChipState::Ready);
        assert_eq!(c.tone, Tone::Good);
        assert_eq!(c.label, None);
        assert_eq!(c.parts, vec!["VRAM 6.9/8.0 GB", "RAM 38.4 GB", "38 tok/s"]);
        assert_eq!(c.action, Some(ChipAction::Stop));
        assert!(
            c.hover
                .iter()
                .any(|l| l == "RTX 3070 Ti: 6.9 GB video memory")
        );
        assert!(c.hover.iter().any(|l| l == "Port: 41234"));
        assert!(c.hover.iter().any(|l| l == "Engine: llama"));
    }

    #[test]
    fn a_measured_speed_says_about() {
        let mut m = running("a", ModelState::Ready);
        m.stats.as_mut().unwrap().tok_s_source = Some(TokSource::Approx);
        let b = bar(&[m], 2000.0);
        assert!(b.chips[0].parts.contains(&"about 38 tok/s".to_string()));
    }

    #[test]
    fn a_loading_model_shows_progress_cards_and_memory_but_no_speed() {
        let mut m = running("a", ModelState::Loading);
        m.load_fraction = Some(0.62);
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.state, ChipState::Loading);
        assert_eq!(c.progress, Some(0.62));
        assert_eq!(c.label.as_deref(), Some("loading 62%"));
        assert_eq!(c.parts[0], "on RTX 3070 Ti");
        assert!(c.parts.iter().any(|p| p.starts_with("VRAM 6.9 GB")));
        assert!(!c.parts.iter().any(|p| p.contains("tok/s")));
        assert_eq!(c.action, Some(ChipAction::Stop));
    }

    #[test]
    fn load_progress_may_come_from_the_stats() {
        let mut m = running("a", ModelState::Loading);
        m.stats.as_mut().unwrap().load_fraction = Some(0.5);
        assert_eq!(bar(&[m], 2000.0).chips[0].progress, Some(0.5));
        let m = running("a", ModelState::Loading);
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.progress, None);
        assert_eq!(c.label.as_deref(), Some("loading"));
    }

    #[test]
    fn a_role_model_that_is_not_running_offers_start() {
        let mut m = stopped_status("q", "Qwen");
        m.role_assigned = true;
        m.notice = Some("Not started: it would not fit.".into());
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.state, ChipState::Stopped);
        assert_eq!(c.label.as_deref(), Some("stopped"));
        assert_eq!(c.action, Some(ChipAction::Start));
        assert!(
            c.hover
                .contains(&"Not started: it would not fit.".to_string())
        );
    }

    #[test]
    fn a_model_without_a_role_that_is_stopped_has_no_chip() {
        let m = stopped_status("q", "Qwen");
        assert!(bar(&[m], 2000.0).is_empty());
    }

    #[test]
    fn a_failed_model_is_red_with_its_message_on_hover() {
        let mut m = stopped_status("q", "Qwen");
        m.state = ModelState::Failed {
            message: "The card is gone.".into(),
        };
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.tone, Tone::Bad);
        assert_eq!(c.label.as_deref(), Some("failed"));
        assert_eq!(c.hover[0], "The card is gone.");
        assert_eq!(c.action, None);
    }

    #[test]
    fn the_countdown_shows_while_nothing_holds_a_running_model() {
        let mut m = running("a", ModelState::Ready);
        m.stops_in_secs = Some(105);
        assert_eq!(
            bar(&[m], 2000.0).chips[0].countdown.as_deref(),
            Some("stops in 1:45")
        );
    }

    #[test]
    fn a_stopping_model_has_no_button() {
        let mut m = running("a", ModelState::Stopping);
        m.stats = None;
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.label.as_deref(), Some("stopping"));
        assert_eq!(c.action, None);
    }

    #[test]
    fn running_on_the_processor_says_so() {
        let mut m = running("a", ModelState::Loading);
        m.devices.clear();
        m.stats.as_mut().unwrap().devices.clear();
        m.stats.as_mut().unwrap().vram_per_device.clear();
        let c = &bar(&[m], 2000.0).chips[0];
        assert_eq!(c.parts[0], "on the processor");
        assert!(!c.parts.iter().any(|p| p.starts_with("VRAM")));
    }

    #[test]
    fn the_external_server_shows_reachability_and_a_measured_speed() {
        let e = |reachable, tok_s| ExternalServer {
            name: "Ollama".into(),
            url: "http://localhost:11434/v1".into(),
            reachable,
            tok_s,
        };
        let one = |e: &ExternalServer| chip_bar(&[], &[], Some(e), 2000.0).chips.remove(0);
        let c = one(&e(Some(true), Some(22.4)));
        assert_eq!(c.label.as_deref(), Some("reachable"));
        assert_eq!(c.parts, vec!["about 22 tok/s"]);
        assert_eq!(c.tone, Tone::Good);
        assert_eq!(c.action, None);
        let c = one(&e(Some(false), Some(22.4)));
        assert_eq!(c.label.as_deref(), Some("unreachable"));
        assert!(c.parts.is_empty(), "no speed for a server that is gone");
        assert_eq!(c.tone, Tone::Bad);
        assert_eq!(one(&e(None, None)).label.as_deref(), Some("checking"));
    }

    #[test]
    fn narrow_widths_collapse_the_last_chips_first_then_drop_them() {
        let models: Vec<_> = (0..3)
            .map(|i| running(&format!("model{i}"), ModelState::Ready))
            .collect();
        let wide = bar(&models, 5000.0);
        assert!(wide.chips.iter().all(|c| !c.collapsed));
        let full = wide.chips[0].estimated_width();

        let mid = bar(&models, full * 2.0 + 120.0);
        assert!(!mid.chips[0].collapsed);
        assert!(mid.chips[2].collapsed);
        assert_eq!(mid.hidden, 0);
        assert!(
            mid.chips[2].action.is_some(),
            "the state is kept for the tooltip"
        );

        let tiny = bar(&models, 150.0);
        assert!(tiny.chips.iter().all(|c| c.collapsed));
        assert!(tiny.hidden > 0);
        assert!(!tiny.chips.is_empty());
    }

    #[test]
    fn no_room_at_all_hides_everything() {
        let b = bar(&[running("a", ModelState::Ready)], 10.0);
        assert!(b.chips.is_empty());
        assert_eq!(b.hidden, 1);
    }
}

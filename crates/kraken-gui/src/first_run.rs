//! The first-run wizard on the wizard window: engine, assistant, keys, look, start. The flow is
//! `kraken_viewmodel::first_run`; this draws the steps, reads the engine state off the Setup
//! status hub, and saves the result to `config.toml` (`[ui]`) when the wizard ends.

use std::path::Path;

use egui::{RichText, Ui};
use kraken_host::{KrakenConfig, UiSettings};
use kraken_registry::commands::SetupState;
use kraken_viewmodel::first_run::{
    AfterFirstRun, AssistantChoice, EngineState, FirstRun, FirstRunStep, ZOOM_STEPS,
};
use kraken_viewmodel::setup_status::{SetupHub, install_command};
use kraken_viewmodel::wizard::WizardFlow;

use crate::keymap;
use crate::style::{self, medium, pal};

/// The smallest and largest text size accepted from the file.
pub const ZOOM_RANGE: (u32, u32) = (80, 160);

/// Changes `[ui]` in the config file at `path` and saves it; the rest of the file is kept.
pub fn save_ui(path: &Path, change: impl FnOnce(&mut UiSettings)) -> Result<(), String> {
    let mut cfg = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
    change(&mut cfg.ui);
    cfg.save(path).map_err(|e| e.to_string())
}

/// What the engine step shows, from the hub: the native engine's row.
pub fn engine_state(hub: Option<&SetupHub>) -> EngineState {
    let Some(hub) = hub else {
        return EngineState::Unknown;
    };
    let s = hub.state();
    if s.running_for("native").is_some() {
        return EngineState::Installing;
    }
    match s.items.iter().find(|i| i.id == "native") {
        Some(i) if i.state == SetupState::Ready => EngineState::Ready,
        Some(_) => EngineState::Missing,
        None => EngineState::Unknown,
    }
}

/// Draws the current step. `hub` is the Setup status hub when the daemon is reachable.
pub fn body(ui: &mut Ui, w: &mut FirstRun, hub: Option<&SetupHub>) {
    match w.current() {
        FirstRunStep::Engine => engine_step(ui, w, hub),
        FirstRunStep::Assistant => assistant_step(ui, w),
        FirstRunStep::Keymap => keymap_step(ui, w),
        FirstRunStep::Look => look_step(ui, w),
        FirstRunStep::Done => done_step(ui, w),
    }
}

fn engine_step(ui: &mut Ui, w: &mut FirstRun, hub: Option<&SetupHub>) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    w.engine = engine_state(hub);
    let (text, color) = match w.engine {
        EngineState::Ready => ("The native engine is ready.", s.success),
        EngineState::Installing => ("Setting up the native engine...", s.info),
        EngineState::Missing => ("The native engine is not set up yet.", s.warning),
        EngineState::Unknown => (
            "KRAKEN cannot tell yet. It looks again when it can reach its background service.",
            p.text_dim,
        ),
    };
    ui.label(medium(text, 13.5).color(color));
    let item = hub.and_then(|h| h.state().items.iter().find(|i| i.id == "native").cloned());
    if let Some(item) = &item {
        ui.add(egui::Label::new(RichText::new(&item.detail).size(12.0).color(p.text_dim)).wrap());
    }
    if let (EngineState::Missing, Some(item), Some(hub)) = (&w.engine, &item, hub) {
        ui.add_space(6.0);
        if install_command(item).is_some() {
            if style::primary_button(ui, "Set up the native engine")
                .on_hover_text(
                    "Download and compile the processor descriptions in the background. You can go on with this wizard.",
                )
                .clicked()
            {
                hub.install(item);
            }
        } else if let Some(fix) = &item.fix {
            ui.add(egui::Label::new(RichText::new(fix).size(12.0)).wrap());
        }
    }
    if let EngineState::Installing = w.engine
        && let Some(hub) = hub
        && let Some(job) = hub.state().running_for("native")
    {
        ui.add(egui::ProgressBar::new(job.fraction().unwrap_or(0.0)).desired_width(320.0));
        ui.label(RichText::new(job.line()).size(12.0).color(p.text_dim));
    }
    ui.add_space(8.0);
    ui.label(
        RichText::new(
            "You can skip this. Ghidra, if you have it installed, is used otherwise; Help > Setup status shows everything that can be installed.",
        )
        .size(12.0)
        .color(p.text_dim),
    );
}

fn assistant_step(ui: &mut Ui, w: &mut FirstRun) {
    let p = pal(ui);
    for c in AssistantChoice::ALL {
        let label = format!("{}\n{}", c.title(), c.blurb());
        let r = ui
            .add(
                egui::Button::new(RichText::new(label).color(p.text))
                    .selected(w.assistant == Some(c))
                    .min_size(egui::vec2(ui.available_width().min(660.0), 0.0)),
            )
            .on_hover_text(format!("{} {}", c.title(), c.blurb()));
        if r.clicked() {
            w.assistant = Some(c);
        }
    }
}

fn keymap_step(ui: &mut Ui, w: &mut FirstRun) {
    let p = pal(ui);
    for k in keymap::presets() {
        let label = format!("{}\n{}", k.name, k.blurb);
        let r = ui
            .add(
                egui::Button::new(RichText::new(label).color(p.text))
                    .selected(w.keymap == k.id)
                    .min_size(egui::vec2(ui.available_width().min(660.0), 0.0)),
            )
            .on_hover_text(format!("{} {}", k.name, k.blurb));
        if r.clicked() {
            w.keymap = k.id.clone();
        }
    }
    ui.add_space(6.0);
    let k = keymap::preset_or_default(Some(&w.keymap));
    ui.label(medium(format!("A few keys in {}", k.name), 13.0).color(p.text_strong));
    egui::Grid::new("kraken_first_run_keys")
        .num_columns(2)
        .spacing([18.0, 3.0])
        .show(ui, |ui| {
            use kraken_viewmodel::AppAction;
            for a in [
                AppAction::GoTo,
                AppAction::RenameCurrent,
                AppAction::Search,
                AppAction::ShowReferences,
                AppAction::OpenPalette,
            ] {
                if let Some(keys) = k.label(a) {
                    ui.monospace(keys);
                    ui.label(a.label());
                    ui.end_row();
                }
            }
        });
}

fn look_step(ui: &mut Ui, w: &mut FirstRun) {
    let p = pal(ui);
    ui.label(medium("Theme", 13.0).color(p.text_strong));
    ui.horizontal(|ui| {
        if ui
            .radio(w.dark, "Dark")
            .on_hover_text("Use the dark look")
            .clicked()
        {
            w.dark = true;
        }
        if ui
            .radio(!w.dark, "Light")
            .on_hover_text("Use the light look")
            .clicked()
        {
            w.dark = false;
        }
    });
    ui.add_space(6.0);
    ui.label(medium("Text size", 13.0).color(p.text_strong));
    ui.horizontal(|ui| {
        for z in ZOOM_STEPS {
            if ui
                .radio(w.zoom == z, format!("{z}%"))
                .on_hover_text("Make all text and controls this size")
                .clicked()
            {
                w.zoom = z;
            }
        }
    });
}

fn done_step(ui: &mut Ui, w: &mut FirstRun) {
    for (after, title, tip) in [
        (
            AfterFirstRun::Demo,
            "Open the demo project",
            "A small built-in program to try everything on",
        ),
        (
            AfterFirstRun::Tour,
            "Take the short tour",
            "A few cards that point at the main areas of the window",
        ),
        (
            AfterFirstRun::Nothing,
            "Go to the start screen",
            "Drop a program on the window or choose File > Open program",
        ),
    ] {
        if ui
            .selectable_label(w.after == after, title)
            .on_hover_text(tip)
            .clicked()
        {
            w.after = after;
        }
    }
    ui.add_space(6.0);
    ui.label(
        RichText::new("Help > First-run setup opens this wizard again.")
            .size(12.0)
            .color(pal(ui).text_dim),
    );
}

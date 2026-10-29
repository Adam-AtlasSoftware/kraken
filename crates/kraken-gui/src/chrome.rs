//! Top bar, status bar and toasts.

use egui::{
    Align, Align2, Color32, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Ui, vec2,
};
use kraken_viewmodel::{
    AnalysisPhase, AppAction, LinkState, Liveness, StageState, UiRequest, ViewModel,
};

use crate::style::{self, chip, level_color, medium, pal};

/// The bar across the top: project, history arrows, analysis, palette and theme. `identity`
/// shows the logo and the project's name (our own title bar has them already); `chips` draws
/// the model chips at the right end.
pub fn top_bar(
    ui: &mut Ui,
    vm: &mut ViewModel,
    reqs: &mut Vec<UiRequest>,
    identity: bool,
    chips: &mut dyn FnMut(&mut Ui),
) {
    let p = pal(ui);
    ui.horizontal_centered(|ui| {
        ui.add_space(2.0);
        if identity {
            ui.label(medium("KRAKEN", 16.0).color(p.accent));
        }
        if let Some(info) = &vm.project {
            ui.add_space(6.0);
            if identity {
                ui.label(medium(&info.name, 14.0).color(p.text_strong))
                    .on_hover_text(format!(
                        "{}\nProject folder: {}",
                        info.binary_path, info.project_dir
                    ));
            }
            chip(ui, &format!("{} / {}", info.format, info.arch), p.text_dim)
                .on_hover_text("File format and processor type of the program");
            if info.epoch_stale {
                chip(
                    ui,
                    "engine cache out of date",
                    style::status(style::dark(ui)).warning,
                );
            }
        }
        ui.add_space(8.0);
        ui.add_enabled_ui(vm.nav.can_back(), |ui| {
            if ui
                .button("\u{2190}")
                .on_hover_text("Go back  (Alt+Left)")
                .clicked()
            {
                reqs.extend(vm.perform(AppAction::Back));
            }
        });
        ui.add_enabled_ui(vm.nav.can_forward(), |ui| {
            if ui
                .button("\u{2192}")
                .on_hover_text("Go forward  (Alt+Right)")
                .clicked()
            {
                reqs.extend(vm.perform(AppAction::Forward));
            }
        });
        ui.add_space(8.0);
        analysis(ui, vm);
        ui.add_space(6.0);
        crate::ai_activity::top_chip(ui, vm);

        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            crate::assist::top_bar_buttons(ui, vm);
            let theme = if style::dark(ui) {
                "Light theme"
            } else {
                "Dark theme"
            };
            if ui
                .button(theme)
                .on_hover_text(
                    "Switch between the dark and light look  (your choice is remembered)",
                )
                .clicked()
            {
                reqs.push(UiRequest::ToggleTheme);
            }
            let label = RichText::new("Commands").color(p.text);
            if ui
                .add(egui::Button::new(label).min_size(vec2(0.0, 24.0)))
                .on_hover_text("Search every action by name  (Ctrl+K or Ctrl+Shift+P)")
                .clicked()
            {
                vm.open_palette();
            }
            ui.label(
                RichText::new("Ctrl+K")
                    .monospace()
                    .size(11.0)
                    .color(p.text_dim),
            );
            chips(ui);
        });
    });
}

fn analysis(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    match vm.analysis.phase {
        AnalysisPhase::Running => {
            let a = &vm.analysis;
            let s = style::status(style::dark(ui));
            let mut text = match a.stage_label() {
                Some(stage) => format!("Analyzing: {stage}"),
                None => "Analyzing".to_string(),
            };
            if let Some(counts) = a.counts_text() {
                text.push_str(&format!("  {counts}"));
            }
            let fraction = a.fraction();
            if let Some(f) = fraction {
                text.push_str(&format!("  {}%", (f * 100.0).floor()));
            }
            let bar = egui::ProgressBar::new(fraction.unwrap_or(0.0))
                .desired_width(340.0)
                .fill(p.accent.gamma_multiply(0.55))
                .text(RichText::new(text).size(12.0).color(p.text_strong))
                .animate(true);
            let mut tip = String::from(
                "KRAKEN is analyzing the program. You can keep working; edits wait until it finishes.\n",
            );
            for (label, state) in a.stage_list() {
                let mark = match state {
                    StageState::Done => "done",
                    StageState::Running => "running",
                    StageState::Waiting => "waiting",
                };
                tip.push_str(&format!("\n{label}: {mark}"));
            }
            if let Some(step) = a.step_text() {
                tip.push_str(&format!("\n\nNow: {step}"));
            } else if let Some(msg) = a
                .progress
                .as_ref()
                .map(|pr| pr.message.as_str())
                .filter(|m| !m.is_empty())
            {
                tip.push_str(&format!("\n\nNow: {msg}"));
            }
            if let Some(e) = a.elapsed_text() {
                tip.push_str(&format!("\nRunning for {e}."));
            }
            ui.add(bar).on_hover_text(tip);
            if let Some(step) = a.step_text() {
                ui.label(RichText::new(step).size(11.5).color(p.text_dim))
                    .on_hover_text("What the engine is doing inside this stage");
            }
            if let Some(e) = a.elapsed_text() {
                ui.label(RichText::new(e).monospace().size(11.0).color(p.text_dim))
                    .on_hover_text("Time since the analysis started");
            }
            match a.liveness() {
                Some(Liveness::Busy { cpu_percent }) => {
                    ui.label(
                        RichText::new(format!("engine busy {cpu_percent}% CPU"))
                            .size(11.0)
                            .color(p.text_dim),
                    )
                    .on_hover_text(
                        "The engine is working. Some steps of a large program report nothing for \
                         minutes; this shows they are still running.",
                    );
                }
                Some(Liveness::Quiet { secs }) => {
                    ui.label(
                        RichText::new(format!(
                            "no engine activity for {}",
                            kraken_viewmodel::duration_words(secs)
                        ))
                        .size(11.0)
                        .color(s.warning),
                    )
                    .on_hover_text(
                        "The engine has used no processor time and reported nothing for a while. \
                         It may be stuck or waiting; Cancel stops it, and what it found is kept.",
                    );
                }
                None => {}
            }
            if ui
                .small_button("Cancel")
                .on_hover_text("Stop the analysis. What it found so far is kept.")
                .clicked()
            {
                vm.cancel_analysis();
            }
        }
        _ => {
            let (label, tip) = match vm.analysis.phase {
                AnalysisPhase::NotStarted => (
                    "Analyze",
                    "Let KRAKEN find and name the functions in this program",
                ),
                _ => ("Re-analyze", "Run the analysis again"),
            };
            let clicked = if vm.analysis.phase == AnalysisPhase::NotStarted {
                style::primary_button(ui, label)
                    .on_hover_text(tip)
                    .clicked()
            } else {
                ui.button(label).on_hover_text(tip).clicked()
            };
            if clicked {
                vm.start_analysis();
            }
        }
    }
}

/// `No changes yet`, `1 change`, `5 changes`: the size of the edit log in plain words.
pub fn changes_text(entries: u64) -> String {
    match entries {
        0 => "No changes yet".into(),
        1 => "1 change".into(),
        n => format!("{n} changes"),
    }
}

/// The engine's name as people say it.
pub fn engine_name(kind: &str) -> &'static str {
    match kind {
        "ghidra" => "Ghidra",
        "native" => "Native",
        "dotnet" => ".NET",
        _ => "Unknown",
    }
}

/// `main at 0x401136`: the function being read, or `None`.
pub fn current_text(vm: &ViewModel) -> Option<String> {
    vm.current
        .as_ref()
        .map(|c| format!("{} at {:#x}", c.name, c.address))
}

/// The strip along the bottom.
pub fn status_bar(
    ui: &mut Ui,
    vm: &ViewModel,
    setup: Option<&kraken_viewmodel::setup_status::SetupHub>,
) {
    let p = pal(ui);
    ui.horizontal_centered(|ui| {
        ui.add_space(6.0);
        if vm.analysis.running() || vm.busy() {
            ui.spinner();
        }
        ui.label(RichText::new(vm.status_text()).size(12.0).color(p.text_dim));
        if let LinkState::Disconnected(why) = &vm.link {
            chip(
                ui,
                "reconnecting to krakend",
                style::status(style::dark(ui)).warning,
            )
            .on_hover_text(why);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if let Some(info) = &vm.project {
                if !info.engine.is_empty() {
                    let tip = match &info.engine_reason {
                        Some(why) => format!("The engine that reads this program. Why this one: {why}"),
                        None => "The engine that reads this program.".to_string(),
                    };
                    ui.label(
                        RichText::new(format!("Engine: {}", engine_name(&info.engine)))
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .on_hover_text(tip);
                    ui.separator();
                }
                if let Some(n) = vm.analysis.function_count.or(vm.functions.total) {
                    ui.label(
                        RichText::new(format!("{n} functions"))
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .on_hover_text("Functions the analysis found in the program");
                    ui.separator();
                }
                if let Some(cur) = current_text(vm) {
                    ui.label(RichText::new(cur).monospace().size(12.0).color(p.text))
                        .on_hover_text("The function you are reading, and where it starts");
                    ui.separator();
                }
                ui.label(
                    RichText::new(changes_text(info.log_entries))
                        .size(12.0)
                        .color(p.text_dim),
                )
                .on_hover_text(
                    "Renames, comments and other changes made in this project, by you or by agents. Open the History tab to review or undo them.",
                );
                if info.open_proposals > 0 {
                    chip(
                        ui,
                        &format!("{} to review", info.open_proposals),
                        style::status(style::dark(ui)).info,
                    )
                    .on_hover_text(
                        "Suggested changes waiting for your decision. Open the Proposals tab to accept or reject them.",
                    );
                }
            }
            if let Some(hub) = setup {
                crate::setup_status::status_chip(ui, hub);
            }
            crate::activity::status_chip(ui, vm);
            crate::ai_activity::status_chip(ui, vm);
        });
    });
}

/// Where toasts sit: the bottom-left corner above the status bar, over the Functions list, the
/// panel read least while something is being worked on. Returns the anchor, its offset and the
/// width, which shrinks on narrow windows.
pub fn toast_placement(screen_width: f32) -> (Align2, egui::Vec2, f32) {
    (
        Align2::LEFT_BOTTOM,
        vec2(16.0, -40.0),
        (screen_width * 0.25).clamp(240.0, 360.0),
    )
}

/// Notifications in the bottom-left corner.
pub fn toasts(ctx: &egui::Context, vm: &mut ViewModel) {
    if vm.toasts.is_empty() {
        return;
    }
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let mut dismiss = Vec::new();
    let mut act = Vec::new();
    let (anchor, offset, width) = toast_placement(ctx.content_rect().width());
    egui::Area::new(egui::Id::new("kraken_toasts"))
        .anchor(anchor, offset)
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            ui.set_width(width);
            for t in &vm.toasts {
                let color = level_color(t.level, dark);
                Frame::new()
                    .fill(p.surface)
                    .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(12, 8))
                    .shadow(egui::Shadow {
                        offset: [0, 4],
                        blur: 14,
                        spread: 0,
                        color: Color32::from_black_alpha(80),
                    })
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_top(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(vec2(4.0, 18.0), egui::Sense::hover());
                            ui.painter().rect_filled(rect, 2.0, color);
                            ui.add(
                                egui::Label::new(RichText::new(&t.text).color(p.text_strong))
                                    .wrap(),
                            );
                            ui.with_layout(Layout::right_to_left(Align::TOP), |ui| {
                                if let Some(a) = &t.action
                                    && ui
                                        .small_button(a.label())
                                        .on_hover_text("Do what this message offers")
                                        .clicked()
                                {
                                    act.push(t.id);
                                }
                                if ui
                                    .small_button("\u{00d7}")
                                    .on_hover_text("Dismiss")
                                    .clicked()
                                {
                                    dismiss.push(t.id);
                                }
                            });
                        });
                    });
                ui.add_space(6.0);
            }
        });
    for id in act {
        vm.run_toast_action(id);
    }
    for id in dismiss {
        vm.dismiss_toast(id);
    }
}

#[cfg(test)]
mod tests {
    use super::{changes_text, engine_name, toast_placement};
    use egui::Align2;

    #[test]
    fn toasts_sit_bottom_left_above_the_status_bar() {
        let (anchor, offset, width) = toast_placement(1440.0);
        assert_eq!(anchor, Align2::LEFT_BOTTOM);
        assert!(offset.x > 0.0 && offset.y < 0.0, "inset from the corner");
        assert!((240.0..=360.0).contains(&width));
        assert_eq!(toast_placement(300.0).2, 240.0);
        assert_eq!(toast_placement(4000.0).2, 360.0);
    }

    #[test]
    fn engines_have_plain_names() {
        assert_eq!(engine_name("native"), "Native");
        assert_eq!(engine_name("dotnet"), ".NET");
        assert_eq!(engine_name(""), "Unknown");
    }

    #[test]
    fn the_change_count_reads_as_words() {
        assert_eq!(changes_text(0), "No changes yet");
        assert_eq!(changes_text(1), "1 change");
        assert_eq!(changes_text(12), "12 changes");
    }
}

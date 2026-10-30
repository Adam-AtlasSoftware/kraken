//! The strip above the Decompiler with up to three suggestions of what to do next. Each is one
//! click; the small cross hides it for the rest of the session.

use egui::{Frame, Margin, RichText, Ui};
use kraken_viewmodel::ViewModel;

use crate::style::pal;

/// Draws the strip, and asks the view model for fresh suggestions when something changed.
pub fn strip(ui: &mut Ui, vm: &mut ViewModel) {
    vm.ensure_next_steps();
    let rows: Vec<(String, String, String, Option<String>)> = vm
        .tools
        .next_steps
        .visible()
        .into_iter()
        .map(|s| {
            (
                s.id.clone(),
                s.title.clone(),
                s.reason.clone(),
                s.command.clone(),
            )
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    let p = pal(ui);
    let mut run: Option<String> = None;
    let mut hide: Option<String> = None;
    Frame::new()
        .fill(p.text_dim.gamma_multiply(0.08))
        .corner_radius(4.0)
        .inner_margin(Margin::symmetric(8, 4))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Next:").size(12.0).color(p.text_dim));
                for (id, title, reason, command) in &rows {
                    let tip = match command {
                        Some(c) => format!("{reason}\n\nRuns `{c}`."),
                        None => reason.clone(),
                    };
                    if ui.button(title).on_hover_text(tip).clicked() {
                        run = Some(id.clone());
                    }
                    if ui
                        .small_button("x")
                        .on_hover_text("Hide this suggestion for now")
                        .clicked()
                    {
                        hide = Some(id.clone());
                    }
                    ui.add_space(6.0);
                }
            });
        });
    if let Some(id) = hide {
        vm.dismiss_next_step(&id);
    }
    if let Some(id) = run {
        vm.run_next_step(&id);
    }
}

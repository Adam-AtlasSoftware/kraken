//! Floating pieces of the assistant: the first-overview banner and the name-review window.

use egui::{Align, Align2, Color32, Frame, Id, Layout, Margin, RichText, Stroke, vec2};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::{
    ApplyWhich, AutoNameReview, AutoNameState, OverviewOffer, ReviewRow, RowStatus,
    confidence_label,
};

use super::chat::confidence_color;
use crate::style::{self, chip, medium};

/// The non-modal "Get an overview" banner under the top bar.
pub fn banner(ctx: &egui::Context, vm: &mut ViewModel) {
    if vm.assist.overview_offer != OverviewOffer::Offered || vm.assist.busy() {
        return;
    }
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let mut start = false;
    let mut dismiss = false;
    egui::Area::new(Id::new("kraken_overview_banner"))
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_TOP, vec2(0.0, 52.0))
        .show(ctx, |ui| {
            Frame::new()
                .fill(p.surface)
                .stroke(Stroke::new(1.0, p.accent.gamma_multiply(0.7)))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(14, 10))
                .shadow(egui::Shadow {
                    offset: [0, 6],
                    blur: 20,
                    spread: 0,
                    color: Color32::from_black_alpha(110),
                })
                .show(ui, |ui| {
                    ui.set_max_width(560.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(medium("The analysis is done.", 14.0).color(p.text_strong));
                            ui.label(
                                RichText::new(
                                    "New to this program? The assistant can tell you what it is and where to start reading.",
                                )
                                .size(12.5)
                                .color(p.text_dim),
                            );
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("Not now").clicked() {
                                dismiss = true;
                            }
                            if style::primary_button(ui, "Get an overview of this program").clicked() {
                                start = true;
                            }
                        });
                    });
                });
        });
    if start {
        vm.assist_overview();
    } else if dismiss {
        vm.assist_dismiss_offer();
    }
}

enum Act {
    Select(usize, bool),
    SelectAll(bool),
    Apply(ApplyWhich),
    Undo,
    Close,
    Stop,
}

/// The window listing suggested names: working, failed or ready for review.
pub fn autoname(ctx: &egui::Context, vm: &mut ViewModel) {
    if matches!(vm.assist.autoname, AutoNameState::Idle) {
        return;
    }
    let state = vm.assist.autoname.clone();
    let mut acts: Vec<Act> = Vec::new();
    let mut open = true;
    egui::Window::new(medium("Suggested names", 15.0))
        .id(Id::new("kraken_autoname"))
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, 10.0))
        .default_size(vec2(900.0, 440.0))
        .show(ctx, |ui| match &state {
            AutoNameState::Idle => {}
            AutoNameState::Running => {
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        "The assistant is reading functions that still have placeholder names...",
                    );
                });
                ui.add_space(6.0);
                if ui.button("Stop").clicked() {
                    acts.push(Act::Stop);
                }
            }
            AutoNameState::Failed(why) => {
                let s = style::status(style::dark(ui));
                ui.add(egui::Label::new(RichText::new(why).color(s.danger)).wrap());
                if ui.button("Close").clicked() {
                    acts.push(Act::Close);
                }
            }
            AutoNameState::Review(r) => review(ui, r, &mut acts),
        });
    if !open {
        acts.push(Act::Close);
    }
    for a in acts {
        match a {
            Act::Select(i, on) => vm.autoname_select(i, on),
            Act::SelectAll(on) => vm.autoname_select_all(on),
            Act::Apply(w) => vm.autoname_apply(w),
            Act::Undo => vm.autoname_undo(),
            Act::Stop => vm.assist_stop(),
            Act::Close => {
                if matches!(vm.assist.autoname, AutoNameState::Running) {
                    vm.assist_stop();
                }
                vm.autoname_close();
                if matches!(vm.assist.autoname, AutoNameState::Failed(_)) {
                    vm.assist.autoname = AutoNameState::Idle;
                }
            }
        }
    }
}

fn review(ui: &mut egui::Ui, r: &AutoNameReview, acts: &mut Vec<Act>) {
    let p = crate::style::pal(ui);
    let dark = style::dark(ui);
    let s = style::status(dark);
    if r.rows.is_empty() {
        ui.add_space(8.0);
        ui.label(medium("No confident suggestions", 14.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "The assistant did not find placeholder-named functions it could name from evidence. Try again after more of the program is analyzed.",
            )
            .color(p.text_dim),
        );
        if ui.button("Close").clicked() {
            acts.push(Act::Close);
        }
        return;
    }
    ui.label(
        RichText::new(
            "Nothing has changed yet. Tick the names you want, then apply them. They become your own edits, and Undo takes them back.",
        )
        .color(p.text_dim),
    );
    ui.add_space(4.0);
    let applicable = r
        .rows
        .iter()
        .filter(|row| row.selected && !matches!(row.status, RowStatus::Applied))
        .count();
    egui::ScrollArea::vertical()
        .id_salt("kraken_autoname_scroll")
        .max_height((ui.available_height() - 78.0).max(120.0))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("kraken_autoname_grid")
                .num_columns(4)
                .spacing([14.0, 8.0])
                .striped(true)
                .show(ui, |ui| {
                    for h in ["", "Rename", "How sure", "Evidence"] {
                        ui.label(RichText::new(h).size(11.5).color(p.text_dim));
                    }
                    ui.end_row();
                    for (i, row) in r.rows.iter().enumerate() {
                        row_cells(ui, i, row, acts);
                        ui.end_row();
                    }
                });
        });
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.add_enabled_ui(!r.busy, |ui| {
            if ui
                .add_enabled(
                    applicable > 0,
                    egui::Button::new(
                        RichText::new(format!("Apply selected ({applicable})")).color(if dark {
                            p.bg
                        } else {
                            Color32::WHITE
                        }),
                    )
                    .fill(p.accent)
                    .min_size(vec2(0.0, 28.0)),
                )
                .clicked()
            {
                acts.push(Act::Apply(ApplyWhich::Selected));
            }
            if ui.button("Apply all").clicked() {
                acts.push(Act::Apply(ApplyWhich::All));
            }
            if ui
                .add_enabled(r.undoable > 0, egui::Button::new("Undo"))
                .on_hover_text("Reverse the changes the last Apply made")
                .clicked()
            {
                acts.push(Act::Undo);
            }
            if ui.small_button("Select all").clicked() {
                acts.push(Act::SelectAll(true));
            }
            if ui.small_button("Select none").clicked() {
                acts.push(Act::SelectAll(false));
            }
        });
        if r.busy {
            ui.spinner();
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.button("Close").clicked() {
                acts.push(Act::Close);
            }
        });
    });
    if let Some(m) = &r.message {
        ui.label(RichText::new(m).size(12.5).color(s.success));
    }
    ui.label(RichText::new(&r.note).size(11.0).color(p.text_dim));
}

fn row_cells(ui: &mut egui::Ui, i: usize, row: &ReviewRow, acts: &mut Vec<Act>) {
    let p = crate::style::pal(ui);
    let dark = style::dark(ui);
    let s = style::status(dark);
    let mut sel = row.selected;
    let applied = matches!(row.status, RowStatus::Applied);
    ui.add_enabled_ui(!applied, |ui| {
        if ui.checkbox(&mut sel, "").changed() {
            acts.push(Act::Select(i, sel));
        }
    });
    ui.vertical(|ui| {
        ui.set_min_width(330.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(
                RichText::new(&row.old_name)
                    .monospace()
                    .size(12.5)
                    .color(p.text_dim),
            );
            if let Some(n) = &row.new_name {
                ui.label(RichText::new("\u{2192}").color(p.text_dim));
                ui.label(
                    RichText::new(n)
                        .monospace()
                        .size(12.5)
                        .strong()
                        .color(p.text_strong),
                );
            }
        });
        ui.label(
            RichText::new(format!("{:#x}", row.address))
                .monospace()
                .size(11.0)
                .color(p.address),
        );
        if let Some(c) = &row.comment {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("Comment: {c}"))
                        .italics()
                        .size(11.5)
                        .color(p.text_dim),
                )
                .wrap(),
            );
        }
        match &row.status {
            RowStatus::Pending => {}
            RowStatus::Applied => {
                ui.label(RichText::new("Applied").size(11.5).color(s.success));
            }
            RowStatus::Undone => {
                ui.label(RichText::new("Undone").size(11.5).color(p.text_dim));
            }
            RowStatus::Failed(why) => {
                ui.add(egui::Label::new(RichText::new(why).size(11.5).color(s.danger)).wrap());
            }
        }
    });
    ui.vertical(|ui| {
        ui.set_max_width(250.0);
        chip(
            ui,
            confidence_label(row.confidence),
            confidence_color(row.confidence, dark),
        )
        .on_hover_text(&row.basis);
    });
    ui.vertical(|ui| {
        ui.set_max_width(300.0);
        if row.evidence.is_empty() {
            ui.label(RichText::new("none cited").size(12.0).color(p.text_dim));
        }
        for e in row.evidence.iter().take(4) {
            ui.add(egui::Label::new(RichText::new(e).size(12.0).color(p.text)).truncate());
        }
    });
}

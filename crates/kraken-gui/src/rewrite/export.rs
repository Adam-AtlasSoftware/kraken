//! The export dialog: where to write the accepted functions, a warning before leaving the
//! project folder, progress, and the coverage of what was written.

use egui::{Align2, Key, RichText, vec2};
use kraken_gui_widgets::KrakenTheme;
use kraken_viewmodel::ViewModel;

use super::browse::{FolderField, Purpose, folder_field, open_buttons};
use crate::style::{self, medium, primary_button};

/// Draws the dialog while it is open.
pub fn dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    if !vm.rewrite.export.open {
        return;
    }
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let check = vm.rewrite_export_check();
    let running = vm.rewrite.exporting();
    let blocked = vm.rewrite.blocked_note().map(str::to_string);
    let mut dir = vm.rewrite.export.dir.clone();
    let mut name = vm.rewrite.export.name.clone();
    let mut build = vm.rewrite.export.build;
    let (mut start, mut agree, mut close) = (false, false, false);
    let state = vm.rewrite.export.clone();
    let progress = vm
        .rewrite
        .jobs
        .iter()
        .rev()
        .find(|j| j.running() && j.kind == kraken_viewmodel::rewrite::JobKind::Export)
        .cloned();
    egui::Window::new(medium("Export the rewrite", 15.0))
        .id(egui::Id::new("kraken_rewrite_export"))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .fixed_size(vec2(520.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(vm.rewrite.coverage_line())
                    .size(12.5)
                    .color(p.text),
            );
            ui.label(
                RichText::new(
                    "Only accepted functions are written: a Rust library, and a shim that exposes each one under the original name so it can stand in for the original.",
                )
                .size(12.0)
                .color(p.text_dim),
            );
            ui.add_space(6.0);
            ui.label("Folder to write to");
            folder_field(
                ui,
                vm,
                &mut dir,
                Some(&check),
                !running,
                &FolderField {
                    id: "kraken_export_dir",
                    hint: "rewrite-export",
                    purpose: Purpose::Export,
                    title: "Where should the Rust project be written?",
                    tip: "A folder name inside your project, or a full path. It must be empty, or an earlier export.",
                },
            );
            ui.add_space(4.0);
            ui.add_enabled_ui(!running, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.add(
                        egui::TextEdit::singleline(&mut name)
                            .hint_text("same as the program")
                            .desired_width(180.0),
                    )
                    .on_hover_text("The name of the Rust project. Leave it to use the program's name");
                });
                ui.add_enabled(
                    blocked.is_none(),
                    egui::Checkbox::new(&mut build, "Build it in the sandbox to check it"),
                )
                .on_hover_text(
                    "Compiles the exported project and checks that it exports exactly the accepted functions.",
                )
                .on_disabled_hover_text(blocked.clone().unwrap_or_default());
            });
            if let Some(note) = &blocked {
                ui.label(
                    RichText::new(format!("The files are still written, but not built. {note}"))
                        .size(11.5)
                        .color(p.text_dim),
                );
            }
            if state.ask_outside {
                ui.add_space(6.0);
                egui::Frame::new()
                    .fill(s.warning.gamma_multiply(0.12))
                    .stroke(egui::Stroke::new(1.0, s.warning.gamma_multiply(0.5)))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("Write outside the project?", 13.0).color(s.warning));
                        ui.label(
                            RichText::new(format!(
                                "KRAKEN will create files in {}. Nothing in that folder is deleted, but it must be empty or an earlier export.",
                                dir.trim()
                            ))
                            .size(12.0),
                        );
                        if ui.button("Yes, write there")
.on_hover_text("Write the project into this folder").clicked() {
                            agree = true;
                        }
                    });
            }
            if let Some(job) = &progress {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(
                        RichText::new(job.progress.as_ref().map_or("Exporting...", |p| p.message.as_str()))
                            .size(12.0)
                            .color(p.text_dim),
                    );
                });
            }
            if let Some(e) = &state.error {
                ui.add_space(4.0);
                ui.label(RichText::new(e).color(s.danger));
            }
            if let Some(r) = &state.result {
                ui.add_space(6.0);
                egui::Frame::new()
                    .fill(s.success.gamma_multiply(0.08))
                    .stroke(egui::Stroke::new(1.0, s.success.gamma_multiply(0.35)))
                    .corner_radius(8)
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("Written", 13.0).color(s.success));
                        ui.label(RichText::new(&r.dir).monospace().size(11.5));
                        ui.label(
                            RichText::new(format!(
                                "{} function{} in {} crate{}{}. Covers {} of {} planned functions ({} in the program).",
                                r.symbols.len(),
                                if r.symbols.len() == 1 { "" } else { "s" },
                                r.crates.len(),
                                if r.crates.len() == 1 { "" } else { "s" },
                                if r.built { ", built and checked" } else { ", not built" },
                                r.accepted,
                                r.planned,
                                r.functions_total,
                            ))
                            .size(12.0),
                        );
                        ui.label(
                            RichText::new(r.symbols.join(", ")).monospace().size(11.5).color(p.text_dim),
                        );
                        open_buttons(ui, &r.dir);
                    });
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let can = !running && vm.rewrite.counts.accepted > 0;
                ui.add_enabled_ui(can, |ui| {
                    if primary_button(ui, "Export")
.on_hover_text("Write the accepted functions as a Rust project").clicked() {
                        start = true;
                    }
                });
                if ui
                    .button(if state.result.is_some() { "Close" } else { "Cancel" })
                    .on_hover_text("Close this window. Files already written stay")
                    .clicked()
                {
                    close = true;
                }
            });
        });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        close = true;
    }
    vm.rewrite_export_set_dir(dir);
    vm.rewrite.export.name = name;
    vm.rewrite.export.build = build;
    if close {
        vm.rewrite_export_close();
    } else if agree {
        vm.rewrite_export_agree_outside();
    } else if start {
        vm.rewrite_export_start();
    }
}

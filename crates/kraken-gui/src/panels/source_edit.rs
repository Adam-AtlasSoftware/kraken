//! The Edit tab (experimental): the function's C on the left, editable; the assistant's patch
//! plan, its check and the actions on the right.

use egui::{Frame, Margin, RichText, Stroke, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{SourceEditPhase, spaced_hex, verdict_text};

use crate::style::{self, chip, empty_state, medium, pal};

fn bytes_of(hex: &str) -> Vec<u8> {
    kraken_viewmodel::navtools::parse_hex(hex).unwrap_or_default()
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(edit) = vm.tools.source_edit.clone() else {
        empty_state(
            ui,
            "Nothing being edited",
            "Open a function and press Patch function in the Decompiler. You edit its C here and \
             the assistant turns your change into a byte patch.",
            Some("Experimental: best for small changes such as a constant or a condition."),
        );
        return;
    };

    // The banner sets expectations before anything else.
    Frame::new()
        .fill(s.warning.gamma_multiply(0.14))
        .stroke(Stroke::new(1.0, s.warning.gamma_multiply(0.5)))
        .corner_radius(6)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                chip(ui, "experimental", s.warning);
                ui.label(
                    RichText::new(
                        "Editing decompiled code works best for small, local changes: a constant, \
                         a comparison, a branch. For anything larger, patch the bytes in the \
                         Listing or rewrite the function.",
                    )
                    .size(12.0)
                    .color(p.text),
                );
            });
        });
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(medium(&edit.name, 14.0).color(p.text_strong));
        ui.label(
            RichText::new(format!("{:#x}", edit.address))
                .monospace()
                .size(12.0)
                .color(p.address),
        );
        let n = edit.changed_lines().len();
        if n > 0 {
            chip(
                ui,
                &format!("{n} line{} changed", if n == 1 { "" } else { "s" }),
                s.info,
            );
        }
    });
    ui.separator();

    let mut text = edit.text.clone();
    let busy = edit.busy();
    ui.columns(2, |cols| {
        // Left: the code.
        let ui = &mut cols[0];
        ui.label(RichText::new("Your edit (C)").size(11.5).color(p.text_dim));
        egui::ScrollArea::both()
            .id_salt("kraken_source_edit_text")
            .auto_shrink([false, false])
            .max_height(ui.available_height() - 4.0)
            .show(ui, |ui| {
                // Code does not wrap: long lines scroll sideways, as in an editor.
                let color = p.text;
                let mut layouter = |ui: &Ui, buf: &dyn egui::TextBuffer, _wrap: f32| {
                    let job = egui::text::LayoutJob::simple(
                        buf.as_str().to_owned(),
                        egui::FontId::monospace(12.5),
                        color,
                        f32::INFINITY,
                    );
                    ui.fonts_mut(|f| f.layout_job(job))
                };
                ui.add_enabled(
                    !busy,
                    egui::TextEdit::multiline(&mut text)
                        .code_editor()
                        .layouter(&mut layouter)
                        .desired_width(f32::INFINITY)
                        .desired_rows(20),
                )
                .on_hover_text("Change the code; the patch is planned from what you change")
                .on_disabled_hover_text("Wait while the assistant plans the patch");
            });

        // Right: the plan.
        let ui = &mut cols[1];
        plan_column(ui, vm, &edit, busy);
    });
    if text != edit.text {
        vm.set_source_edit_text(text);
    }
}

fn plan_column(
    ui: &mut Ui,
    vm: &mut ViewModel,
    edit: &kraken_viewmodel::navtools::SourceEdit,
    busy: bool,
) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.label(RichText::new("Patch plan").size(11.5).color(p.text_dim));
    let mut plan_clicked = false;
    let mut stage = false;
    let mut verify = false;
    let mut reset = false;
    let mut discard = false;
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(
                !busy && edit.changed(),
                egui::Button::new(RichText::new("Plan patch").strong()),
            )
            .on_hover_text(
                "Ask the assistant's model for the byte patch; it is checked by \
                     decompiling the patched code again. Uses AI",
            )
            .on_disabled_hover_text(if busy {
                "Working..."
            } else {
                "Change the code first"
            })
            .clicked()
        {
            plan_clicked = true;
        }
        let can_stage = matches!(&edit.phase, SourceEditPhase::Planned(p) if !p.patches.is_empty());
        if ui
            .add_enabled(can_stage, egui::Button::new("Stage patches"))
            .on_hover_text(
                "Keep these patches in the project. Nothing on disk changes until you \
                     export",
            )
            .on_disabled_hover_text("Plan a patch first")
            .clicked()
        {
            stage = true;
        }
        let staged = matches!(edit.phase, SourceEditPhase::Staged(_));
        if ui
            .add_enabled(staged, egui::Button::new("Run original vs patched"))
            .on_hover_text("Run both in the sandboxed emulator and compare, in the Emulation tab")
            .on_disabled_hover_text("Stage the patches first")
            .clicked()
        {
            verify = true;
        }
        if ui
            .add_enabled(!busy && edit.changed(), egui::Button::new("Reset"))
            .on_hover_text("Put the decompiled code back")
            .on_disabled_hover_text(if busy {
                "Working..."
            } else {
                "The code is as decompiled"
            })
            .clicked()
        {
            reset = true;
        }
        if ui
            .button("Discard")
            .on_hover_text("Close this edit. Staged patches stay staged")
            .clicked()
        {
            discard = true;
        }
    });
    ui.add_space(4.0);
    egui::ScrollArea::vertical()
        .id_salt("kraken_source_edit_plan")
        .auto_shrink([false, false])
        .show(ui, |ui| match &edit.phase {
            SourceEditPhase::Editing => {
                let what = if edit.changed() {
                    "Press Plan patch: the assistant's model finds the smallest byte change \
                         that does what your edit says, then the patched code is decompiled \
                         again to check it."
                } else {
                    "Change the code on the left first."
                };
                ui.label(RichText::new(what).size(12.5).color(p.text));
            }
            SourceEditPhase::Planning(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Planning and checking the patch...").color(p.text));
                });
                ui.label(
                    RichText::new(
                        "This sends the decompile, your edit and the disassembly to the \
                             assistant's model. See AI Activity for the cost.",
                    )
                    .size(11.5)
                    .color(p.text_dim),
                );
            }
            SourceEditPhase::Failed(why) => {
                ui.label(RichText::new("No plan came back.").color(s.danger));
                ui.label(RichText::new(why).size(12.0).color(p.text_dim));
            }
            SourceEditPhase::Planned(plan)
            | SourceEditPhase::Staging(plan)
            | SourceEditPhase::Staged(plan) => {
                if !plan.summary.0.is_empty() {
                    ui.label(RichText::new(&plan.summary.0).size(12.5).color(p.text));
                }
                let (verdict, good) = verdict_text(plan.check.verdict);
                ui.label(RichText::new(verdict).size(12.5).strong().color(if good {
                    s.success
                } else {
                    s.warning
                }));
                if !plan.check.reason.0.is_empty() {
                    ui.label(
                        RichText::new(&plan.check.reason.0)
                            .size(12.0)
                            .color(p.text_dim),
                    );
                }
                if plan.patches.is_empty() {
                    ui.label(
                        RichText::new(
                            "No in-place byte change can do this. Try a smaller edit, or \
                                 patch the bytes by hand.",
                        )
                        .color(s.warning),
                    );
                }
                for pt in &plan.patches {
                    Frame::new()
                        .fill(p.surface)
                        .stroke(Stroke::new(1.0, p.border))
                        .corner_radius(6)
                        .inner_margin(Margin::same(6))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(format!("{:#x}", pt.address.0))
                                        .monospace()
                                        .color(p.address),
                                );
                                ui.label(
                                    RichText::new(spaced_hex(&bytes_of(&pt.original)))
                                        .monospace()
                                        .color(s.danger),
                                );
                                ui.label(RichText::new("→").color(p.text_dim));
                                ui.label(
                                    RichText::new(spaced_hex(&bytes_of(&pt.replacement)))
                                        .monospace()
                                        .color(s.success),
                                );
                            });
                            if !pt.explanation.0.is_empty() {
                                ui.label(
                                    RichText::new(&pt.explanation.0)
                                        .size(11.5)
                                        .color(p.text_dim),
                                );
                            }
                        });
                }
                for w in &plan.warnings {
                    ui.label(RichText::new(w).size(11.5).color(s.warning));
                }
                if let Some(d) = &plan.check.patched_decompile {
                    egui::CollapsingHeader::new("The patched function, decompiled again")
                        .id_salt("kraken_source_edit_patched")
                        .show(ui, |ui| {
                            ui.label(RichText::new(&d.0).monospace().size(11.5));
                        });
                }
                if matches!(edit.phase, SourceEditPhase::Staged(_)) {
                    ui.label(
                        RichText::new(
                            "Staged. Nothing on disk changes until you export a patched copy.",
                        )
                        .size(12.0)
                        .color(s.success),
                    );
                }
            }
        });
    if plan_clicked {
        vm.plan_source_edit();
    }
    if stage {
        vm.stage_source_edit();
    }
    if verify {
        vm.verify_source_edit();
    }
    if reset {
        vm.reset_source_edit();
    }
    if discard {
        vm.discard_source_edit();
    }
}

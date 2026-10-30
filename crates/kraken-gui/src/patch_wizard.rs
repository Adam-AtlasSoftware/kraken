//! Patch > Change what this code does...: the guided patch wizard. The flow lives in
//! `kraken-viewmodel` (`navtools/patch_wizard.rs`); this draws its five steps on the wizard window:
//! where, what, preview, test, save.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{CText, Draft, PatchStep, PatchWizard, WizardIntent};
use kraken_viewmodel::wizard::WizardFlow;

use crate::style::{self, medium, pal};
use crate::wizard::{self, WizardEvent};

/// Draws the wizard when it is open and acts on what the person did.
pub fn show(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(mut w) = vm.tools.patch_wizard.take() else {
        return;
    };
    let groups: Vec<String> = vm
        .tools
        .patches
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    let ev = wizard::show(ctx, "Change what this code does", &mut w, |ui, w| {
        body(ui, w, &groups)
    });
    match ev {
        WizardEvent::Cancel => {
            vm.tools.patch_wizard = Some(w);
            vm.cancel_patch_wizard();
        }
        WizardEvent::Finish | WizardEvent::None => {
            vm.tools.patch_wizard = Some(w);
            vm.drive_patch_wizard();
        }
    }
}

fn body(ui: &mut Ui, w: &mut PatchWizard, groups: &[String]) {
    match w.current() {
        PatchStep::Pick => pick_step(ui, w),
        PatchStep::Intent => intent_step(ui, w),
        PatchStep::Preview => preview_step(ui, w),
        PatchStep::Test => test_step(ui, w),
        PatchStep::Save => save_step(ui, w, groups),
    }
}

fn pick_step(ui: &mut Ui, w: &mut PatchWizard) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Address").color(p.text_dim));
        ui.add(
            egui::TextEdit::singleline(&mut w.address_text)
                .id(egui::Id::new("kraken_patch_wizard_address"))
                .font(egui::TextStyle::Monospace)
                .hint_text("0x401136")
                .desired_width(160.0),
        )
        .on_hover_text(
            "The address of the instruction to change, as 0x401136. It was filled in from your selection.",
        );
    });
    ui.add_space(6.0);
    match &w.pick {
        None => {
            ui.label(RichText::new("No instruction picked yet.").color(p.text_dim));
        }
        Some(pick) => {
            egui::Grid::new("kraken_patch_wizard_pick")
                .num_columns(2)
                .spacing([14.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Function").color(p.text_dim));
                    match &pick.function {
                        Some((a, n)) => ui.label(
                            RichText::new(format!("{n}  ({a:#x})"))
                                .monospace()
                                .color(p.text_strong),
                        ),
                        None => {
                            ui.label(RichText::new("not in a known function").color(p.text_dim))
                        }
                    };
                    ui.end_row();
                    ui.label(RichText::new("Instruction").color(p.text_dim));
                    match &pick.text {
                        Some(t) => ui.label(RichText::new(t).monospace().color(p.text_strong)),
                        None => ui.label(
                            RichText::new("(not in the Listing now; the preview will show it)")
                                .color(p.text_dim),
                        ),
                    };
                    ui.end_row();
                    if let Some(b) = &pick.bytes {
                        ui.label(RichText::new("Bytes").color(p.text_dim));
                        ui.label(RichText::new(b).monospace());
                        ui.end_row();
                    }
                });
        }
    }
}

fn intent_step(ui: &mut Ui, w: &mut PatchWizard) {
    let p = pal(ui);
    for intent in WizardIntent::ALL {
        let why = w.unavailable(intent);
        let chosen = w.intent == Some(intent);
        let label = format!("{}\n{}", intent.title(), intent.blurb());
        let r = ui.add_enabled(
            why.is_none(),
            egui::Button::new(RichText::new(label).color(if why.is_some() {
                p.text_dim
            } else {
                p.text
            }))
            .selected(chosen)
            .min_size(egui::vec2(ui.available_width().min(660.0), 0.0)),
        );
        let r = r.on_hover_text(format!("{} {}", intent.title(), intent.blurb()));
        let r = r.on_disabled_hover_text(why.unwrap_or(""));
        if r.clicked() {
            w.intent = Some(intent);
        }
    }
    ui.add_space(6.0);
    match w.intent {
        Some(i) if i.takes_value() => {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Value").color(p.text_dim));
                ui.add(
                    egui::TextEdit::singleline(&mut w.value)
                        .id(egui::Id::new("kraken_patch_wizard_value"))
                        .font(egui::TextStyle::Monospace)
                        .hint_text("0, 1, -1, 0x10")
                        .desired_width(120.0),
                )
                .on_hover_text("A number, decimal or 0x hex. Negative numbers are fine.");
            });
        }
        Some(WizardIntent::Assembly) => {
            ui.label(RichText::new("Instructions").color(p.text_dim));
            ui.add(
                egui::TextEdit::multiline(&mut w.asm)
                    .id(egui::Id::new("kraken_patch_wizard_asm"))
                    .font(egui::TextStyle::Monospace)
                    .hint_text("xor eax, eax\nret")
                    .desired_rows(3)
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text(
                "One instruction per line, in the syntax the Listing shows. They are assembled for this address.",
            );
        }
        _ => {}
    }
}

fn c_column(ui: &mut Ui, id: &str, title: &str, text: &CText) {
    let p = pal(ui);
    ui.label(RichText::new(title).size(12.0).color(p.text_dim));
    match text {
        CText::Idle => {}
        CText::Loading => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Decompiling...");
            });
        }
        CText::Failed(e) => {
            ui.add(egui::Label::new(RichText::new(e).size(12.0).color(p.text_dim)).wrap());
        }
        CText::Ready(t) => {
            egui::ScrollArea::both()
                .id_salt(id)
                .max_height(220.0)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(t).monospace().size(11.5)).extend());
                });
        }
    }
}

fn preview_step(ui: &mut Ui, w: &PatchWizard) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    match &w.draft {
        Draft::Failed(e) => {
            ui.label(RichText::new(e).color(s.warning));
            ui.label(RichText::new("Go Back and change the choice.").color(p.text_dim));
            return;
        }
        Draft::Staging | Draft::None => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Working out the patch...");
            });
            return;
        }
        Draft::Staged(_) => {}
    }
    if let Some(pv) = &w.preview {
        ui.label(medium("Instructions", 13.0).color(p.text_strong));
        ui.columns(2, |cols| {
            cols[0].label(RichText::new("Before").size(12.0).color(p.text_dim));
            for l in &pv.old_disassembly {
                cols[0].label(RichText::new(l).monospace().size(12.0));
            }
            cols[1].label(RichText::new("After").size(12.0).color(p.text_dim));
            if pv.new_disassembly.is_empty() {
                cols[1].label(
                    RichText::new(format!("bytes {}", pv.replacement))
                        .monospace()
                        .size(12.0),
                );
            }
            for l in &pv.new_disassembly {
                cols[1].label(RichText::new(l).monospace().size(12.0).color(p.text_strong));
            }
        });
        for n in &pv.notes {
            ui.label(RichText::new(n).size(12.0).color(p.text_dim));
        }
    }
    ui.add_space(6.0);
    ui.label(medium("Patch checks", 13.0).color(p.text_strong));
    match &w.lint {
        None => {
            ui.label(RichText::new("Checking...").color(p.text_dim));
        }
        Some(l) if l.is_empty() => {
            ui.label(RichText::new("Nothing to warn about.").color(s.success));
        }
        Some(l) => {
            for f in l {
                let c = if f.severity == "warning" {
                    s.warning
                } else {
                    p.text_dim
                };
                ui.add(egui::Label::new(RichText::new(&f.message).size(12.5).color(c)).wrap());
            }
        }
    }
    ui.add_space(6.0);
    ui.label(medium("Decompiled C", 13.0).color(p.text_strong));
    ui.columns(2, |cols| {
        c_column(&mut cols[0], "kraken_pw_c_before", "Before", &w.c_before);
        c_column(&mut cols[1], "kraken_pw_c_after", "After", &w.c_after);
    });
}

fn test_step(ui: &mut Ui, w: &mut PatchWizard) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.label(
        RichText::new("Skip this step if you do not want to test. Press Next to go on.")
            .color(p.text_dim),
    );
    ui.horizontal(|ui| {
        ui.label(RichText::new("Arguments").color(p.text_dim));
        ui.add(
            egui::TextEdit::singleline(&mut w.test.argv)
                .id(egui::Id::new("kraken_patch_wizard_argv"))
                .font(egui::TextStyle::Monospace)
                .hint_text("separated by spaces")
                .desired_width(320.0),
        )
        .on_hover_text("Command-line arguments both runs get after the program name.");
    });
    ui.label(RichText::new("Standard input").color(p.text_dim));
    ui.add(
        egui::TextEdit::multiline(&mut w.test.stdin)
            .id(egui::Id::new("kraken_patch_wizard_stdin"))
            .font(egui::TextStyle::Monospace)
            .desired_rows(2)
            .desired_width(f32::INFINITY),
    )
    .on_hover_text("Text both runs read from standard input.");
    ui.add_space(4.0);
    let running = w.test.running;
    let run = ui
        .add_enabled(!running, egui::Button::new("Run original and patched"))
        .on_hover_text(
            "Run the program twice in the emulator, once as it is and once with the patch, and compare.",
        )
        .on_disabled_hover_text("The test is running.");
    if run.clicked() {
        w.request_test();
    }
    if running {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Running both programs...");
        });
    }
    if let Some(e) = &w.test.error {
        ui.label(RichText::new(e).color(s.warning));
    }
    if let Some((same, first)) = &w.test.result {
        if *same {
            ui.label(
                RichText::new("Both programs behaved the same on this input.").color(s.success),
            );
        } else {
            ui.label(RichText::new("The patched program behaves differently.").color(s.warning));
            ui.add(egui::Label::new(RichText::new(first).monospace().size(12.0)).wrap());
        }
    }
}

fn save_step(ui: &mut Ui, w: &mut PatchWizard, groups: &[String]) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.horizontal(|ui| {
        ui.label(RichText::new("Patch set").color(p.text_dim));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut w.set_name)
                    .id(egui::Id::new("kraken_patch_wizard_set"))
                    .desired_width(260.0),
            )
            .on_hover_text(
                "The name of the patch set this patch goes into. A new name makes a new set.",
            );
        if r.changed() {
            w.touch_name();
        }
        if !groups.is_empty() {
            let mut picked = None;
            egui::ComboBox::from_id_salt("kraken_patch_wizard_existing")
                .selected_text("Existing sets")
                .show_ui(ui, |ui| {
                    for g in groups {
                        if ui
                            .selectable_label(false, g)
                            .on_hover_text("Put the patch into this set")
                            .clicked()
                        {
                            picked = Some(g.clone());
                        }
                    }
                })
                .response
                .on_hover_text("Choose a patch set that already exists");
            if let Some(g) = picked {
                w.set_name = g;
                w.touch_name();
            }
        }
    });
    ui.label(RichText::new("What it is for (optional)").color(p.text_dim));
    ui.add(
        egui::TextEdit::singleline(&mut w.set_note)
            .id(egui::Id::new("kraken_patch_wizard_note"))
            .desired_width(f32::INFINITY),
    )
    .on_hover_text("A line saying what this set of patches does");
    ui.add_space(6.0);
    ui.checkbox(&mut w.export_binary, "Also write a patched copy of the program")
        .on_hover_text(
            "Writes the program with this set's patches applied. The original is untouched. You are asked to approve it.",
        );
    if w.export_binary {
        if w.binary_path.is_empty() {
            w.binary_path = "patched-program".into();
        }
        ui.add(
            egui::TextEdit::singleline(&mut w.binary_path)
                .id(egui::Id::new("kraken_patch_wizard_binary"))
                .desired_width(f32::INFINITY),
        )
        .on_hover_text("Where to write the copy. A relative path lands in the project folder.");
    }
    ui.checkbox(&mut w.export_diff, "Also write a patch file to share")
        .on_hover_text(
            "Writes only this set's changes as an IPS, BPS or JSON file, chosen by the extension.",
        );
    if w.export_diff {
        if w.diff_path.is_empty() {
            w.diff_path = "changes.ips".into();
        }
        ui.add(
            egui::TextEdit::singleline(&mut w.diff_path)
                .id(egui::Id::new("kraken_patch_wizard_diff"))
                .desired_width(f32::INFINITY),
        )
        .on_hover_text(
            "Where to write the patch file; .ips, .bps, .json and others set the format.",
        );
    }
    if let Some(e) = &w.error {
        ui.add_space(4.0);
        ui.label(RichText::new(e).color(s.warning));
    }
}

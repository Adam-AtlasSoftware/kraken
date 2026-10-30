//! The Patches tab: byte patches staged on the program, the button that compares the original
//! against the patched program in the emulator (the Emulation tab shows it), and the export of a
//! patched copy.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::spaced_hex;

use super::strings::one_line;
use crate::style::{self, chip, empty_state, medium, pal};

/// Bytes shown per side before the rest is elided.
const SHOWN_BYTES: usize = 12;

fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() <= SHOWN_BYTES {
        spaced_hex(bytes)
    } else {
        format!("{} …", spaced_hex(&bytes[..SHOWN_BYTES]))
    }
}

/// The patch sets: one row each with an on/off switch, how many patches, export and remove.
fn sets(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    if vm.tools.patches.groups.is_empty() {
        return;
    }
    let groups = vm.tools.patches.groups.clone();
    let (mut switch, mut export, mut remove) = (None, None, None);
    ui.label(RichText::new("Patch sets").size(11.0).color(p.text_dim));
    egui::Grid::new("kraken_patch_sets")
        .striped(true)
        .num_columns(5)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            for g in &groups {
                let mut on = g.enabled_patches > 0;
                if ui
                    .checkbox(&mut on, RichText::new(&g.name).color(p.text_strong))
                    .on_hover_text(
                        "Switch every patch of this set on or off. Off patches stay staged but \
                         are left out of exports and emulated runs",
                    )
                    .changed()
                {
                    switch = Some((g.name.clone(), on));
                }
                let state = g.state();
                let color = match state {
                    "on" => s.success,
                    "off" => s.warning,
                    _ => s.info,
                };
                chip(
                    ui,
                    &format!(
                        "{} patch{} {state}",
                        g.patches,
                        if g.patches == 1 { "" } else { "es" }
                    ),
                    color,
                );
                ui.label(
                    RichText::new(one_line(&g.description, 70))
                        .size(12.0)
                        .color(p.text_dim),
                );
                if ui
                    .small_button("Export set...")
                    .on_hover_text("Write a copy of the program with only this set's patches")
                    .clicked()
                {
                    export = Some(g.name.clone());
                }
                if ui
                    .add_enabled(g.patches == 0, egui::Button::new("Delete").small())
                    .on_hover_text("Delete this empty set")
                    .on_disabled_hover_text("Move or remove its patches first")
                    .clicked()
                {
                    remove = Some(g.name.clone());
                }
                ui.end_row();
            }
        });
    ui.separator();
    if let Some((n, on)) = switch {
        vm.set_patch_group_enabled(&n, on);
    }
    if let Some(n) = export {
        vm.begin_patch_export_group(Some(n));
    }
    if let Some(n) = remove {
        vm.remove_patch_group(&n);
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_patches();
    let count = vm.tools.patches.items.len();
    ui.horizontal_wrapped(|ui| {
        ui.label(medium("Patch & export", 14.0).color(p.text_strong));
        if count > 0 {
            chip(ui, &format!("{count} staged"), s.warning)
                .on_hover_text("Patches waiting to be exported. The binary on disk is unchanged");
        }
        if vm.tools.patches.loading {
            ui.spinner();
        }
    });
    ui.horizontal_wrapped(|ui| {
        let row = vm.views.listing.selected_row().is_some();
        if ui
            .add_enabled(row, egui::Button::new("Patch selected instruction"))
            .on_hover_text("Replace the bytes of the instruction selected in the Listing")
            .on_disabled_hover_text("Click an instruction in the Listing first")
            .clicked()
        {
            vm.begin_patch_instruction();
        }
        let sel = vm.views.hex.selection.is_some();
        if ui
            .add_enabled(sel, egui::Button::new("Patch Hex selection"))
            .on_hover_text("Replace the bytes selected in the Hex view")
            .on_disabled_hover_text("Select bytes in the Hex view first")
            .clicked()
        {
            vm.begin_patch_bytes();
        }
        if ui
            .button("Patch file offset...")
            .on_hover_text(
                "Patch bytes by their offset in the file: headers, padding, data the program \
                 does not map, or a raw image",
            )
            .clicked()
        {
            vm.begin_patch_file_offset();
        }
        if ui
            .button("Run original vs patched...")
            .on_hover_text(
                "Run the program twice in the sandboxed emulator with the arguments and input \
                 you give, as it is and with the patches, and compare what each did",
            )
            .clicked()
        {
            vm.begin_emulate(kraken_viewmodel::navtools::EmulateMode::Compare);
        }
        if ui
            .add_enabled(count > 0, egui::Button::new("Verify..."))
            .on_hover_text(
                "Run the original and the patched program with the arguments, input and \
                 environment you give, show what differs, and keep the verdict with the patches",
            )
            .on_disabled_hover_text("Stage a patch first")
            .clicked()
        {
            vm.begin_emulate(kraken_viewmodel::navtools::EmulateMode::Verify);
        }
        if ui
            .add_enabled(
                count > 0 && !vm.tools.patches.linting,
                egui::Button::new("Check patches"),
            )
            .on_hover_text(
                "Look for patches over bytes the loader rewrites at start-up, across the end of \
                 a function, or on a signed file. Nothing is run or changed",
            )
            .on_disabled_hover_text("Stage a patch first")
            .clicked()
        {
            vm.check_patches();
        }
        if ui
            .button("New patch set...")
            .on_hover_text(
                "Make a named group for the patches of one change, so you can switch them on \
                 and off together and export them alone",
            )
            .clicked()
        {
            vm.begin_patch_group();
        }
        if ui
            .button("Export patched binary...")
            .on_hover_text(
                "Write a copy of the program with every patch that is on applied. It asks \
                 first; the original file is never touched",
            )
            .clicked()
        {
            vm.begin_patch_export();
        }
        if ui
            .button("Refresh")
            .on_hover_text("Reload the patches, including ones an agent just staged")
            .clicked()
        {
            vm.refresh_patches();
        }
    });
    if let Some(done) = &vm.tools.patches.last_export {
        ui.label(
            RichText::new(format!(
                "Last export: {} ({} patch{}, {} bytes).",
                done.output_path,
                done.applied,
                if done.applied == 1 { "" } else { "es" },
                done.bytes_written
            ))
            .size(12.0)
            .color(s.success),
        );
        if !done.sha256.is_empty() {
            ui.label(
                RichText::new(format!("SHA-256 {}", done.sha256))
                    .monospace()
                    .size(11.0),
            )
            .on_hover_text("Hash of the exported file");
        }
    }
    if let Some(e) = &vm.tools.patches.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    if let Some(l) = &vm.tools.patches.lint {
        if l.findings.is_empty() {
            ui.label(
                RichText::new(format!(
                    "Checked {} patch{}: nothing to warn about.",
                    l.checked,
                    if l.checked == 1 { "" } else { "es" }
                ))
                .size(12.0)
                .color(s.success),
            );
        }
        for f in &l.findings {
            ui.horizontal_wrapped(|ui| {
                let (label, color) = if f.severity == "warning" {
                    ("warning", s.warning)
                } else {
                    ("note", s.info)
                };
                chip(ui, label, color);
                if let Some(a) = f.address {
                    ui.label(
                        RichText::new(format!("{a:08x}"))
                            .monospace()
                            .size(12.0)
                            .color(p.address),
                    );
                }
                ui.label(RichText::new(&f.message).size(12.0).color(p.text));
            });
        }
    }
    ui.separator();
    sets(ui, vm);

    let b = &vm.tools.patches;
    if b.items.is_empty() {
        if b.loaded {
            empty_state(
                ui,
                "No patches yet",
                "A patch replaces bytes at an address, for example to skip a check. Staging one \
                 changes nothing on disk until you export a patched copy.",
                Some(
                    "Click an instruction in the Listing and press Patch bytes, or select bytes \
                     in the Hex view.",
                ),
            );
        }
        return;
    }
    let mut go = None;
    let mut remove = None;
    let mut edit = None;
    let mut assign: Option<(u64, String)> = None;
    let names: Vec<String> = b.groups.iter().map(|g| g.name.clone()).collect();
    egui::ScrollArea::vertical()
        .id_salt("kraken_patches")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("kraken_patch_rows")
                .striped(true)
                .num_columns(7)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Address", "Change", "Length", "", "Set", "By", "Note"] {
                        ui.label(RichText::new(h).size(11.0).color(p.text_dim));
                    }
                    ui.end_row();
                    for it in &b.items {
                        if it.by_offset {
                            ui.label(
                                RichText::new(format!("file+{:#x}", it.address))
                                    .monospace()
                                    .size(12.0)
                                    .color(p.address),
                            )
                            .on_hover_text(
                                "A patch by file offset: this many bytes from the start of the \
                                 file, outside the program's address space",
                            );
                        } else {
                            let addr = ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(format!("{:08x}", it.address))
                                            .monospace()
                                            .size(12.0)
                                            .color(p.address),
                                    )
                                    .frame(false),
                                )
                                .on_hover_text(match vm.functions.containing(it.address) {
                                    Some(f) => format!("Go to this address, in {}", f.name),
                                    None => "Go to this address".to_string(),
                                });
                            if addr.clicked() {
                                go = Some(it.address);
                            }
                        }
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(short_hex(&it.original))
                                    .monospace()
                                    .size(12.0)
                                    .color(s.danger),
                            );
                            ui.label(RichText::new("→").color(p.text_dim));
                            ui.label(
                                RichText::new(short_hex(&it.replacement))
                                    .monospace()
                                    .size(12.0)
                                    .color(s.success),
                            );
                        });
                        ui.label(
                            RichText::new(it.replacement.len().to_string())
                                .monospace()
                                .size(12.0),
                        );
                        ui.horizontal(|ui| {
                            if ui
                                .small_button("Edit")
                                .on_hover_text("Change the bytes or the note of this patch")
                                .clicked()
                            {
                                edit = Some((it.address, it.original.clone(), it.by_offset));
                            }
                            if ui
                                .small_button("Remove")
                                .on_hover_text(
                                    "Drop this patch. The binary on disk was never changed",
                                )
                                .clicked()
                            {
                                remove = Some((it.address, it.by_offset));
                            }
                        });
                        ui.horizontal(|ui| {
                            let shown = if it.group.is_empty() {
                                "(none)"
                            } else {
                                it.group.as_str()
                            };
                            egui::ComboBox::from_id_salt(("patch_set_of", it.address))
                                .selected_text(shown)
                                .width(110.0)
                                .show_ui(ui, |ui| {
                                    if ui
                                        .selectable_label(it.group.is_empty(), "(none)")
                                        .on_hover_text("Take this patch out of its set")
                                        .clicked()
                                        && !it.group.is_empty()
                                    {
                                        assign = Some((it.address, String::new()));
                                    }
                                    for n in &names {
                                        if ui
                                            .selectable_label(&it.group == n, n)
                                            .on_hover_text("Put this patch in this set")
                                            .clicked()
                                            && &it.group != n
                                        {
                                            assign = Some((it.address, n.clone()));
                                        }
                                    }
                                })
                                .response
                                .on_hover_text("The patch set this patch belongs to");
                            if !it.enabled {
                                chip(ui, "off", s.warning).on_hover_text(
                                    "Switched off with its set: not exported or emulated",
                                );
                            }
                            if let Some(v) = &it.verdict {
                                let (text, color) = if v.same {
                                    ("verified: no change", s.warning)
                                } else {
                                    ("verified: changes behavior", s.success)
                                };
                                chip(ui, text, color).on_hover_text(if v.same {
                                    "The last verification of exactly these patches found no \
                                     difference on the input it was given"
                                } else {
                                    v.summary.as_str()
                                });
                            }
                        });
                        if it.by_agent {
                            chip(ui, &it.who, s.info).on_hover_text("An agent staged this patch");
                        } else {
                            ui.label(RichText::new(&it.who).color(p.text_dim));
                        }
                        if it.note.is_empty() {
                            ui.label(RichText::new("(no note)").italics().color(p.text_dim));
                        } else {
                            ui.label(RichText::new(one_line(&it.note, 80)).color(p.text));
                        }
                        ui.end_row();
                    }
                });
        });
    if b.next_cursor.is_some() && !b.loading {
        vm.more_patches();
    }
    if let Some((a, group)) = assign {
        vm.assign_patch_group(a, &group);
    }
    if let Some(a) = go {
        vm.goto(a);
    }
    if let Some((a, by_offset)) = remove {
        vm.remove_patch_at(a, by_offset);
    }
    if let Some((a, original, by_offset)) = edit {
        if by_offset {
            vm.begin_patch_file_offset();
            vm.set_patch_offset_text(format!("{a:#x}"));
        } else {
            vm.begin_patch(
                a,
                Some(original),
                kraken_viewmodel::navtools::PatchOrigin::Bytes,
            );
        }
    }
}

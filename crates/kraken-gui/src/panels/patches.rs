//! The Patches tab: byte patches staged on the program, a run of the original against the
//! patched program in the emulator, and the export of a patched copy.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{RunSide, spaced_hex};

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
        let running = vm.tools.patches.running;
        if ui
            .add_enabled(!running, egui::Button::new("Run original vs patched"))
            .on_hover_text(
                "Run the program twice in the sandboxed emulator, as it is and with the patches, \
                 and compare what each did",
            )
            .on_disabled_hover_text("Running...")
            .clicked()
        {
            vm.run_patched_compare();
        }
        if running {
            ui.spinner();
        }
        if ui
            .button("Export patched binary...")
            .on_hover_text(
                "Write a copy of the program with every patch applied. It asks first; the \
                 original file is never touched",
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
    }
    if let Some(e) = &vm.tools.patches.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    run_report(ui, vm);
    ui.separator();

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
    egui::ScrollArea::vertical()
        .id_salt("kraken_patches")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("kraken_patch_rows")
                .striped(true)
                .num_columns(6)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for h in ["Address", "Change", "Length", "", "By", "Note"] {
                        ui.label(RichText::new(h).size(11.0).color(p.text_dim));
                    }
                    ui.end_row();
                    for it in &b.items {
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
                                edit = Some((it.address, it.original.clone()));
                            }
                            if ui
                                .small_button("Remove")
                                .on_hover_text(
                                    "Drop this patch. The binary on disk was never changed",
                                )
                                .clicked()
                            {
                                remove = Some(it.address);
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
    if let Some(a) = go {
        vm.goto(a);
    }
    if let Some(a) = remove {
        vm.remove_patch(a);
    }
    if let Some((a, original)) = edit {
        vm.begin_patch(
            a,
            Some(original),
            kraken_viewmodel::navtools::PatchOrigin::Bytes,
        );
    }
}

/// The last original-versus-patched run, side by side.
fn run_report(ui: &mut Ui, vm: &ViewModel) {
    let Some(run) = &vm.tools.patches.run else {
        return;
    };
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let (text, color) = if run.same() {
        (
            "Both runs behaved the same: the patches made no visible difference with no input.",
            s.warning,
        )
    } else if run.original.is_ok() && run.patched.is_ok() {
        ("The patched program behaved differently.", s.success)
    } else {
        ("A run could not finish; see below.", s.danger)
    };
    ui.label(RichText::new(text).size(12.5).color(color));
    ui.columns(2, |cols| {
        side(&mut cols[0], "Original", &run.original, p, s);
        side(&mut cols[1], "Patched", &run.patched, p, s);
    });
}

fn side(
    ui: &mut Ui,
    title: &str,
    r: &Result<RunSide, String>,
    p: kraken_gui_widgets::Palette,
    s: style::Status,
) {
    ui.label(
        RichText::new(title)
            .size(11.5)
            .strong()
            .color(p.text_strong),
    );
    match r {
        Ok(r) => {
            ui.label(RichText::new(&r.exit).monospace().size(12.0));
            let out = if r.stdout.is_empty() {
                "(no output)".to_string()
            } else {
                one_line(&r.stdout, 300)
            };
            ui.label(RichText::new(out).monospace().size(11.5).color(p.text))
                .on_hover_text("Standard output; program data, shown as text");
            if !r.stderr.is_empty() {
                ui.label(
                    RichText::new(one_line(&r.stderr, 200))
                        .monospace()
                        .size(11.5)
                        .color(s.warning),
                );
            }
            for n in r.notes.iter().take(3) {
                ui.label(RichText::new(n).size(11.0).color(p.text_dim));
            }
        }
        Err(e) => {
            ui.label(RichText::new(e).size(12.0).color(s.danger));
        }
    }
}

//! The dialogs of the navigation and editing tools: Go to, bookmark note, Retype / Edit
//! signature, Create / Delete function, the generated command form and its result window.

use egui::{Align2, Id, Key, Margin, Modifiers, RichText, vec2};
use kraken_gui_widgets::{KrakenTheme, Palette};
use kraken_viewmodel::navtools::{
    AsmState, FieldKind, FunctionDialogKind, IntentKind, PatchOrigin, ResultSegment,
    SYMBOL_CONFLICTS, SYMBOL_FORMATS, TypeMode, result_lines, spaced_hex,
};
use kraken_viewmodel::{Permission, ViewModel, humanize_command};

use crate::style::{self, Status, medium};

/// Draws whichever tool dialogs are open.
pub fn show(ctx: &egui::Context, vm: &mut ViewModel) {
    goto_dialog(ctx, vm);
    bookmark_dialog(ctx, vm);
    patch_dialog(ctx, vm);
    string_dialog(ctx, vm);
    group_dialog(ctx, vm);
    export_dialog(ctx, vm);
    import_dialog(ctx, vm);
    symbols_dialog(ctx, vm);
    intent_dialog(ctx, vm);
    crate::patch_wizard::show(ctx, vm);
    super::emulation::dialog(ctx, vm);
    super::emulation::call_dialog(ctx, vm);
    type_dialog(ctx, vm);
    local_dialog(ctx, vm);
    function_dialog(ctx, vm);
    command_form(ctx, vm);
    command_result(ctx, vm);
}

fn colors(ctx: &egui::Context) -> (Palette, Status) {
    let dark = ctx.global_style().visuals.dark_mode;
    (KrakenTheme { dark }.palette(), style::status(dark))
}

fn window(title: &str, id: &str, width: f32) -> egui::Window<'static> {
    egui::Window::new(medium(title, 15.0))
        .id(Id::new(id))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -60.0))
        .fixed_size(vec2(width, 0.0))
}

/// Enter and Escape, consumed so the workspace does not see them.
fn enter_escape(ctx: &egui::Context) -> (bool, bool) {
    ctx.input_mut(|i| {
        (
            i.consume_key(Modifiers::NONE, Key::Enter),
            i.consume_key(Modifiers::NONE, Key::Escape),
        )
    })
}

fn buttons(
    ui: &mut egui::Ui,
    label: &str,
    tip: &str,
    enabled: Result<(), String>,
    busy: bool,
    ok: &mut bool,
    cancel: &mut bool,
) {
    ui.horizontal(|ui| {
        let why = enabled.clone().err();
        let r = ui
            .add_enabled(
                why.is_none() && !busy,
                egui::Button::new(RichText::new(label).strong()),
            )
            .on_hover_text(tip);
        let r = if busy {
            r.on_disabled_hover_text("Working...")
        } else {
            r.on_disabled_hover_text(why.unwrap_or_default())
        };
        crate::panels::remember_rect(ui.ctx(), ("dialog", label), r.rect);
        if r.clicked() {
            *ok = true;
        }
        if ui
            .button("Cancel")
            .on_hover_text("Close without changing anything (Esc)")
            .clicked()
        {
            *cancel = true;
        }
        if busy {
            ui.spinner();
        }
    });
}

// ---------------------------------------------------------------- go to

fn goto_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.goto.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (up, down) = ctx.input_mut(|i| {
        (
            i.consume_key(Modifiers::NONE, Key::ArrowUp),
            i.consume_key(Modifiers::NONE, Key::ArrowDown),
        )
    });
    let (enter, esc) = enter_escape(ctx);
    let mut input = d.input.clone();
    let mut chosen = None;
    let (mut go, mut cancel) = (false, false);
    window("Go to", "kraken_goto", 460.0).show(ctx, |ui| {
        ui.label(
            RichText::new(
                "Type an address such as 0x401000, a function or symbol name, or entry / main.",
            )
            .color(p.text_dim),
        );
        ui.add_space(4.0);
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut input)
                    .id(Id::new("kraken_goto_input"))
                    .font(egui::TextStyle::Monospace)
                    .hint_text("0x401000, main, printf...")
                    .desired_width(f32::INFINITY)
                    .margin(Margin::symmetric(8, 6)),
            )
            .on_hover_text("An address, or the name of a function or symbol. Enter jumps there");
        if !r.has_focus() {
            r.request_focus();
        }
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(4.0);
        for (i, it) in d.suggestions.iter().enumerate() {
            let text = format!("{}    {:#x}    {}", it.name, it.address, it.kind.word());
            if ui
                .selectable_label(i == d.selected, RichText::new(text).monospace().size(12.5))
                .on_hover_text(format!("Go to this {}", it.kind.word()))
                .clicked()
            {
                chosen = Some(i);
            }
        }
        if d.suggestions.is_empty() && !input.trim().is_empty() {
            ui.label(
                RichText::new(
                    "No loaded name matches. Press Enter to look it up in the whole program.",
                )
                .size(12.0)
                .color(p.text_dim),
            );
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Go",
            "Jump there; Alt+Left comes back (Enter)",
            Ok(()),
            d.resolving,
            &mut go,
            &mut cancel,
        );
        ui.label(
            RichText::new("Up / Down to pick    Enter to go    Esc to close")
                .size(11.0)
                .color(p.text_dim),
        );
    });
    if esc || cancel {
        vm.close_goto();
        return;
    }
    if input != d.input {
        vm.set_goto_input(input);
    }
    if up {
        vm.move_goto_selection(-1);
    }
    if down {
        vm.move_goto_selection(1);
    }
    if let Some(i) = chosen {
        vm.choose_goto(i);
    } else if go || enter {
        vm.submit_goto();
    }
}

// ---------------------------------------------------------------- bookmark

fn bookmark_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.bookmark_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut input = d.input.clone();
    let (mut save, mut cancel) = (false, false);
    let title = if d.existing {
        "Edit bookmark"
    } else {
        "Add bookmark"
    };
    let fname = vm.functions.find(d.address).map(|f| f.name.clone());
    window(title, "kraken_bookmark", 420.0).show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Address").size(12.0).color(p.text_dim));
            ui.label(
                RichText::new(format!("{:#x}", d.address))
                    .monospace()
                    .color(p.address),
            );
            if let Some(n) = &fname {
                ui.label(RichText::new(n).monospace().color(p.text_strong));
            }
        });
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut input)
                    .id(Id::new("kraken_bookmark_input"))
                    .hint_text("A short note, e.g. parses the config file (optional)")
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text("A note to remember why this place matters. It can stay empty");
        if !r.has_focus() && !d.submitting {
            r.request_focus();
        }
        match &d.error {
            Some(e) => ui.label(RichText::new(e).color(s.danger)),
            None => ui.label(
                RichText::new(
                    "Bookmarks are saved with the project. They do not change the program.",
                )
                .size(12.0)
                .color(p.text_dim),
            ),
        };
        ui.add_space(6.0);
        buttons(
            ui,
            "Save",
            "Save the bookmark (Enter)",
            Ok(()),
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if input != d.input {
        vm.set_bookmark_input(input);
    }
    if esc || cancel {
        vm.cancel_bookmark();
    } else if save || enter {
        vm.submit_bookmark();
    }
}

// ---------------------------------------------------------------- byte patch

const ASM_ID: &str = "kraken_patch_asm";

fn patch_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.patch_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    // Enter in the instruction field starts a new line; Ctrl+Enter there assembles, and once it
    // is assembled (or anywhere else) Enter stages.
    let in_asm = ctx.memory(|m| m.has_focus(Id::new(ASM_ID)));
    let (enter, esc) = if in_asm {
        ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::COMMAND, Key::Enter),
                i.consume_key(Modifiers::NONE, Key::Escape),
            )
        })
    } else {
        enter_escape(ctx)
    };
    let mut input = d.input.clone();
    let mut note = d.note.clone();
    let mut asm = d.asm.clone();
    let mut group = d.group.clone();
    let mut offset_text = d.offset_text.clone();
    let groups: Vec<String> = vm
        .tools
        .patches
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    let (mut save, mut cancel, mut pad) = (false, false, false);
    let (mut assemble, mut pick) = (false, None);
    let focused_once = ctx.memory(|m| m.focused().is_some());
    let title = match (d.existing, d.by_offset) {
        (true, _) => "Edit byte patch",
        (false, true) => "Patch file bytes",
        (false, false) => "Patch bytes",
    };
    let fname = vm
        .functions
        .containing(d.address)
        .filter(|_| !d.by_offset)
        .map(|f| f.name.clone());
    window(title, "kraken_patch", 520.0).show(ctx, |ui| {
        ui.horizontal(|ui| {
            if d.by_offset {
                ui.label(RichText::new("File offset").size(12.0).color(p.text_dim));
                ui.add(
                    egui::TextEdit::singleline(&mut offset_text)
                        .id(Id::new("kraken_patch_offset"))
                        .font(egui::TextStyle::Monospace)
                        .hint_text("0x10")
                        .desired_width(140.0),
                )
                .on_hover_text(
                    "Where to patch, counted in bytes from the start of the file (hex with 0x, \
                     or decimal). This reaches bytes the program does not map, such as headers \
                     or padding",
                );
            } else {
                ui.label(RichText::new("Address").size(12.0).color(p.text_dim));
                ui.label(
                    RichText::new(format!("{:#x}", d.address))
                        .monospace()
                        .color(p.address),
                );
            }
            if let Some(n) = &fname {
                ui.label(
                    RichText::new(format!("in {n}"))
                        .monospace()
                        .color(p.text_strong),
                );
            }
        });
        if let PatchOrigin::Instruction(text) = &d.origin {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Instruction now")
                        .size(12.0)
                        .color(p.text_dim),
                );
                ui.label(RichText::new(text).monospace().color(p.text));
            });
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new("Bytes now").size(12.0).color(p.text_dim));
            match &d.original {
                Some(o) => ui.label(RichText::new(spaced_hex(o)).monospace().color(s.danger)),
                None => ui.label(
                    RichText::new("read when the patch is staged")
                        .italics()
                        .color(p.text_dim),
                ),
            };
        });
        ui.add_space(4.0);
        if !d.by_offset {
            ui.label(
                RichText::new("New instruction")
                    .size(12.0)
                    .color(p.text_dim),
            );
        }
        ui.horizontal(|ui| {
            if d.by_offset {
                return;
            }
            ui.add(
                egui::TextEdit::multiline(&mut asm)
                    .id(Id::new(ASM_ID))
                    .font(egui::TextStyle::Monospace)
                    .hint_text("mov eax, 0x7\nret")
                    .desired_rows(3)
                    .desired_width(ui.available_width() - 90.0),
            )
            .on_hover_text(
                "One instruction per line (or separated by ;). Press Assemble or Ctrl+Enter: \
                 they are assembled for this address, padded with NOPs to the next instruction, \
                 and their bytes go in the field below",
            );
            let busy = matches!(d.asm_state, AsmState::Busy);
            if ui
                .add_enabled(
                    !busy && !asm.trim().is_empty(),
                    egui::Button::new("Assemble"),
                )
                .on_hover_text("Turn the instruction into bytes (Enter)")
                .on_disabled_hover_text(if busy {
                    "Assembling..."
                } else {
                    "Type an instruction first"
                })
                .clicked()
            {
                assemble = true;
            }
        });
        if let Some(note) = &d.asm_note {
            ui.label(RichText::new(note).size(12.0).color(p.text_dim));
        }
        match &d.asm_state {
            AsmState::Failed(why) => {
                ui.label(RichText::new(why).size(12.0).color(s.danger));
            }
            AsmState::Done(enc) if enc.len() > 1 => {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Other encodings:")
                            .size(12.0)
                            .color(p.text_dim),
                    );
                    for (i, b) in enc.iter().enumerate().skip(1).take(5) {
                        if ui
                            .small_button(RichText::new(spaced_hex(b)).monospace())
                            .on_hover_text("Use this encoding instead")
                            .clicked()
                        {
                            pick = Some(i);
                        }
                    }
                });
            }
            _ => {}
        }
        ui.label(
            RichText::new("New bytes (hex)")
                .size(12.0)
                .color(p.text_dim),
        );
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut input)
                    .id(Id::new("kraken_patch_input"))
                    .font(egui::TextStyle::Monospace)
                    .hint_text("90 90, eb 10, b8 07 00 00 00")
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text("The bytes to put here, as hex. Spaces are ignored");
        let elsewhere = ui
            .memory(|m| m.has_focus(Id::new("kraken_patch_note")) || m.has_focus(Id::new(ASM_ID)));
        if !r.has_focus() && !d.submitting && !elsewhere && !focused_once {
            let first = if d.by_offset {
                Id::new("kraken_patch_offset")
            } else {
                Id::new(ASM_ID)
            };
            ui.memory_mut(|m| m.request_focus(first));
        }
        if let Some(n) = d.length_note() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(n).size(12.0).color(s.warning));
                if d.x86
                    && d.parsed()
                        .ok()
                        .zip(d.original.as_ref())
                        .is_some_and(|(new, old)| new.len() < old.len())
                    && ui
                        .small_button("Fill with nop")
                        .on_hover_text("Pad with 90 (x86 nop) to the original length")
                        .clicked()
                {
                    pad = true;
                }
            });
        }
        ui.add(
            egui::TextEdit::singleline(&mut note)
                .id(Id::new("kraken_patch_note"))
                .hint_text("Why, e.g. remove the startup banner (optional)")
                .desired_width(f32::INFINITY),
        )
        .on_hover_text("A note kept with the patch");
        if !groups.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Patch set").size(12.0).color(p.text_dim));
                egui::ComboBox::from_id_salt("kraken_patch_dialog_set")
                    .selected_text(if group.is_empty() { "(none)" } else { &group })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut group, String::new(), "(none)")
                            .on_hover_text("Keep this patch in no set");
                        for g in &groups {
                            ui.selectable_value(&mut group, g.clone(), g)
                                .on_hover_text("Put this patch in this set");
                        }
                    })
                    .response
                    .on_hover_text(
                        "Keep this patch in a set to switch it on and off with the others",
                    );
            });
        }
        match &d.error {
            Some(e) => ui.label(RichText::new(e).color(s.danger)),
            None => ui.label(
                RichText::new(
                    "Staging keeps the patch in the project with the bytes that were there. \
                     Nothing on disk changes until you export a patched copy.",
                )
                .size(12.0)
                .color(p.text_dim),
            ),
        };
        ui.add_space(6.0);
        buttons(
            ui,
            "Stage patch",
            "Keep this patch in the project (Enter)",
            d.check(),
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if offset_text != d.offset_text {
        vm.set_patch_offset_text(offset_text);
    }
    if input != d.input {
        vm.set_patch_input(input);
    }
    if note != d.note {
        vm.set_patch_note(note);
    }
    if group != d.group {
        vm.set_patch_dialog_group(group);
    }
    if asm != d.asm {
        vm.set_patch_asm(asm);
    }
    if let Some(i) = pick {
        vm.pick_patch_encoding(i);
    }
    if pad {
        vm.pad_patch_with_nops();
    }
    if esc || cancel {
        vm.cancel_patch();
    } else if assemble
        || (enter
            && in_asm
            && !d.asm.trim().is_empty()
            && !matches!(d.asm_state, AsmState::Done(_)))
    {
        vm.assemble_patch();
    } else if save || enter {
        vm.submit_patch();
    }
}

/// The Edit string dialog.
fn string_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    use kraken_registry::commands::PatchStringEncoding as Enc;
    let Some(d) = vm.tools.string_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut input = d.input.clone();
    let mut note = d.note.clone();
    let mut group = d.group.clone();
    let mut encoding = d.encoding;
    let groups: Vec<String> = vm
        .tools
        .patches
        .groups
        .iter()
        .map(|g| g.name.clone())
        .collect();
    let (mut save, mut cancel) = (false, false);
    let check = d.check();
    window("Edit string", "kraken_string_edit", 520.0).show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Address").size(12.0).color(p.text_dim));
            ui.label(
                RichText::new(format!("{:#x}", d.address))
                    .monospace()
                    .color(p.address),
            );
        });
        if let Some(old) = &d.old_text {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Now").size(12.0).color(p.text_dim));
                ui.label(
                    RichText::new(super::strings::one_line(old, 120))
                        .monospace()
                        .color(s.danger),
                );
            });
        }
        ui.horizontal(|ui| {
            ui.label(RichText::new("Stored as").size(12.0).color(p.text_dim));
            egui::ComboBox::from_id_salt("kraken_string_encoding")
                .selected_text(match encoding {
                    Enc::Auto => "Detect".to_string(),
                    Enc::Ascii => "ASCII".to_string(),
                    Enc::Utf8 => "UTF-8".to_string(),
                    Enc::Utf16le => "UTF-16 (little endian)".to_string(),
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut encoding, Enc::Auto, "Detect")
                        .on_hover_text("Look at the bytes in the program to decide");
                    ui.selectable_value(&mut encoding, Enc::Ascii, "ASCII")
                        .on_hover_text("One byte per character, 7-bit text only");
                    ui.selectable_value(&mut encoding, Enc::Utf8, "UTF-8")
                        .on_hover_text("UTF-8 text, one to four bytes per character");
                    ui.selectable_value(&mut encoding, Enc::Utf16le, "UTF-16 (little endian)")
                        .on_hover_text("Two bytes per character, as Windows programs store text");
                })
                .response
                .on_hover_text(
                    "How the program stores the characters. Detect looks at the bytes: UTF-16 \
                     if every other byte is zero, UTF-8 otherwise",
                );
        });
        ui.label(RichText::new("New text").size(12.0).color(p.text_dim));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut input)
                    .id(Id::new("kraken_string_input"))
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text(
                "The new text. It may be as long as the old one or shorter; the rest is filled \
                 with zero bytes",
            );
        if !r.has_focus() && !d.submitting && d.capacity.is_some() && d.error.is_none() {
            let other = ui.memory(|m| m.has_focus(Id::new("kraken_string_note")));
            if !other {
                r.request_focus();
            }
        }
        if let Some(cap) = d.capacity {
            let needed = d.needed();
            let (text, color) = match &needed {
                Ok(n) if *n <= cap => (format!("{n} of {cap} bytes"), p.text_dim),
                Ok(n) => (format!("{n} of {cap} bytes"), s.danger),
                Err(e) => (e.clone(), s.danger),
            };
            ui.label(RichText::new(text).size(12.0).color(color))
                .on_hover_text("Bytes the new text takes, against the room the old text leaves");
        }
        ui.add(
            egui::TextEdit::singleline(&mut note)
                .id(Id::new("kraken_string_note"))
                .hint_text("Why (optional)")
                .desired_width(f32::INFINITY),
        )
        .on_hover_text("A note kept with the patch");
        if !groups.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Patch set").size(12.0).color(p.text_dim));
                egui::ComboBox::from_id_salt("kraken_string_set")
                    .selected_text(if group.is_empty() { "(none)" } else { &group })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut group, String::new(), "(none)")
                            .on_hover_text("Keep this patch in no set");
                        for g in &groups {
                            ui.selectable_value(&mut group, g.clone(), g)
                                .on_hover_text("Put this patch in this set");
                        }
                    })
                    .response
                    .on_hover_text("Keep this edit in a set to switch it on and off with others");
            });
        }
        match (&d.error, &check) {
            (Some(e), _) => ui.label(RichText::new(e).color(s.danger)),
            (None, Err(e)) if !d.probing && !d.input.is_empty() => {
                ui.label(RichText::new(e).color(s.warning))
            }
            _ => ui.label(
                RichText::new(
                    "The text is written over the old string and its end is padded with zero \
                     bytes. Nothing on disk changes until you export a patched copy.",
                )
                .size(12.0)
                .color(p.text_dim),
            ),
        };
        ui.add_space(6.0);
        buttons(
            ui,
            "Stage string",
            "Keep this edit in the project (Enter)",
            check.clone(),
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if input != d.input {
        vm.set_string_input(input);
    }
    if note != d.note {
        vm.set_string_note(note);
    }
    if group != d.group {
        vm.set_string_group(group);
    }
    if encoding != d.encoding {
        vm.set_string_encoding(encoding);
    }
    if esc || cancel {
        vm.cancel_string_edit();
    } else if save || enter {
        vm.submit_string_edit();
    }
}

/// The New patch set dialog.
fn group_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.patches.group_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let (mut name, mut description) = (d.name.clone(), d.description.clone());
    let (mut save, mut cancel) = (false, false);
    window("New patch set", "kraken_patch_group", 460.0).show(ctx, |ui| {
        ui.label(
            RichText::new(
                "A patch set groups the patches of one change. Switch it off to leave it out of \
                 exports and emulated runs, or export it alone.",
            )
            .color(p.text_dim),
        );
        ui.label(RichText::new("Name").size(12.0).color(p.text_dim));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut name)
                    .id(Id::new("kraken_group_name"))
                    .hint_text("debug logging")
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text("A short name for the set");
        if !r.has_focus() && !ctx.memory(|m| m.has_focus(Id::new("kraken_group_desc"))) {
            r.request_focus();
        }
        ui.label(RichText::new("What it does").size(12.0).color(p.text_dim));
        ui.add(
            egui::TextEdit::singleline(&mut description)
                .id(Id::new("kraken_group_desc"))
                .hint_text("optional")
                .desired_width(f32::INFINITY),
        )
        .on_hover_text("A line describing the change");
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Create set",
            "Create the patch set (Enter)",
            if name.trim().is_empty() {
                Err("Give the set a name".into())
            } else {
                Ok(())
            },
            false,
            &mut save,
            &mut cancel,
        );
    });
    if name != d.name || description != d.description {
        vm.set_patch_group_text(name, description);
    }
    if esc || cancel {
        vm.cancel_patch_group();
    } else if save || enter {
        vm.submit_patch_group();
    }
}

/// The path chosen in the system save dialog, waiting for the export dialog to take it.
static EXPORT_PICK: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn browse_export(vm: &ViewModel, ctx: &egui::Context, current: &str) {
    let ctx = ctx.clone();
    let start = vm
        .project
        .as_ref()
        .map(|p| p.project_dir.clone())
        .filter(|d| std::path::Path::new(d).is_dir());
    let name = std::path::Path::new(current)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "program.patched".into());
    vm.runtime_handle().spawn(async move {
        let mut d = rfd::AsyncFileDialog::new()
            .set_title("Where should the patched binary be written?")
            .set_file_name(name);
        if let Some(s) = start {
            d = d.set_directory(s);
        }
        if let Some(h) = d.save_file().await {
            if let Ok(mut p) = EXPORT_PICK.lock() {
                *p = Some(h.path().to_string_lossy().into_owned());
            }
            ctx.request_repaint();
        }
    });
}

/// Opens the folder holding `path` in the desktop's file manager.
fn open_folder_of(path: &str) {
    if cfg!(test) {
        return;
    }
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let program = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(program)
        .arg(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

fn export_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.export_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut path = d.output_path.clone();
    let mut overwrite = d.overwrite;
    if let Some(picked) = EXPORT_PICK.lock().ok().and_then(|mut x| x.take()) {
        path = picked;
        // The system dialog already asked about replacing a file.
        overwrite = true;
    }
    let (mut save, mut cancel, mut browse) = (false, false, false);
    let n = match &d.group {
        Some(g) => vm
            .tools
            .patches
            .items
            .iter()
            .filter(|p| &p.group == g && p.enabled)
            .count(),
        None => vm.tools.patches.items.iter().filter(|p| p.enabled).count(),
    };
    if let Some(done) = &d.done {
        let mut copy = false;
        let mut folder = false;
        let title = if done.format.is_some() {
            "Patch file written"
        } else {
            "Patched binary written"
        };
        window(title, "kraken_patch_export", 540.0).show(ctx, |ui| {
            ui.label(
                RichText::new(format!(
                    "Wrote {} with {} {} ({} bytes).",
                    done.output_path,
                    match done.applied {
                        0 => "no patches".to_string(),
                        1 => "1 patch".to_string(),
                        n => format!("{n} patches"),
                    },
                    if done.format.is_some() {
                        "in it"
                    } else {
                        "applied"
                    },
                    done.bytes_written
                ))
                .color(s.success),
            );
            ui.label(RichText::new("SHA-256").size(12.0).color(p.text_dim));
            ui.add(egui::Label::new(RichText::new(&done.sha256).monospace().size(11.5)).wrap());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                folder = ui
                    .button("Open folder")
                    .on_hover_text("Show the file in your file manager")
                    .clicked();
                copy = ui
                    .button("Copy SHA-256")
                    .on_hover_text("Copy the hash to the clipboard")
                    .clicked();
                cancel = ui
                    .button("Close")
                    .on_hover_text("Close this window")
                    .clicked();
            });
        });
        if folder {
            open_folder_of(&done.output_path);
        }
        if copy {
            ctx.copy_text(done.sha256.clone());
        }
        if esc || enter || cancel {
            vm.cancel_patch_export();
        }
        return;
    }
    let title = match &d.group {
        Some(g) => format!("Export patch set {g}"),
        None => "Export patches".to_string(),
    };
    let mut format = d.format.clone();
    let binary = d.format == "binary";
    window(&title, "kraken_patch_export", 520.0).show(ctx, |ui| {
        ui.label(
            RichText::new(format!(
                "Writes {} {} (patches that are switched off are left out). Each address is \
                 mapped to its place in the file and the original bytes are checked first; if \
                 anything does not line up nothing is written. The original file is never \
                 touched.",
                if binary {
                    "a copy of the program with"
                } else {
                    "a patch file holding only"
                },
                match n {
                    0 => "no patches (an exact copy)".to_string(),
                    1 => "1 patch".to_string(),
                    n => format!("{n} patches"),
                }
            ))
            .color(p.text_dim),
        );
        ui.label(RichText::new("Format").size(12.0).color(p.text_dim));
        let shown = kraken_viewmodel::navtools::EXPORT_FORMATS
            .iter()
            .find(|(f, _)| *f == format)
            .map_or("", |(_, t)| *t);
        egui::ComboBox::from_id_salt("kraken_patch_export_format")
            .selected_text(shown)
            .width(ui.available_width().min(420.0))
            .show_ui(ui, |ui| {
                for (f, text) in kraken_viewmodel::navtools::EXPORT_FORMATS {
                    ui.selectable_value(&mut format, f.to_string(), text)
                        .on_hover_text(match f {
                            "binary" => "The whole program with the patches applied",
                            "ips" | "ips32" => {
                                "A small file of changes most patchers and emulators read"
                            }
                            "bps" => "Changes plus checksums, so it refuses the wrong file",
                            "json" => {
                                "Changes with addresses and notes; Patch > Import reads it back"
                            }
                            _ => "A text list of every changed byte, to read or paste elsewhere",
                        });
                }
            })
            .response
            .on_hover_text(
                "Write the whole patched program, or just the patches as a file to share",
            );
        ui.label(RichText::new("Write to").size(12.0).color(p.text_dim));
        ui.horizontal(|ui| {
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut path)
                        .id(Id::new("kraken_patch_export_path"))
                        .font(egui::TextStyle::Monospace)
                        .desired_width((ui.available_width() - 84.0).max(120.0)),
                )
                .on_hover_text("A file path; a relative one is placed in the project folder");
            if !r.has_focus() && !d.submitting {
                r.request_focus();
            }
            browse = ui
                .button("Browse...")
                .on_hover_text("Choose the file in a save dialog")
                .clicked();
        });
        ui.checkbox(&mut overwrite, "Replace the file if it exists")
            .on_hover_text("Without this, an existing file at that path is left alone");
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        buttons(
            ui,
            if binary {
                "Write patched binary"
            } else {
                "Write patch file"
            },
            "Write the file (Enter). You are asked to confirm first",
            if path.trim().is_empty() {
                Err("Choose where to write it".into())
            } else {
                Ok(())
            },
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if browse {
        browse_export(vm, ctx, &path);
    }
    if format != d.format {
        vm.set_export_format(&format);
    } else if path != d.output_path {
        vm.set_export_path(path);
    }
    if overwrite != d.overwrite {
        vm.set_export_overwrite(overwrite);
    }
    if esc || cancel {
        vm.cancel_patch_export();
    } else if save || enter {
        vm.submit_patch_export();
    }
}

// ---------------------------------------------------------------- import a patch file

/// The patch file chosen in the system open dialog, waiting for the import dialog to take it.
static IMPORT_PICK: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn browse_import(vm: &ViewModel, ctx: &egui::Context) {
    let ctx = ctx.clone();
    let start = vm
        .project
        .as_ref()
        .map(|p| p.project_dir.clone())
        .filter(|d| std::path::Path::new(d).is_dir());
    vm.runtime_handle().spawn(async move {
        let mut d = rfd::AsyncFileDialog::new()
            .set_title("Which patch file should be read?")
            .add_filter("Patch files", &["ips", "bps", "json"]);
        if let Some(s) = start {
            d = d.set_directory(s);
        }
        if let Some(h) = d.pick_file().await {
            if let Ok(mut p) = IMPORT_PICK.lock() {
                *p = Some(h.path().to_string_lossy().into_owned());
            }
            ctx.request_repaint();
        }
    });
}

fn import_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.import_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut path = d.path.clone();
    if let Some(picked) = IMPORT_PICK.lock().ok().and_then(|mut x| x.take()) {
        path = picked;
    }
    let (mut go, mut check, mut cancel, mut browse) = (false, false, false, false);
    window("Import patch file", "kraken_patch_import", 520.0).show(ctx, |ui| {
        ui.label(
            RichText::new(
                "Reads an IPS, BPS or KRAKEN JSON patch file made for this program and stages \
                 its changes as patches. The file is checked first: one made for a different \
                 file, or that reaches outside this one, is refused and nothing is staged. \
                 Nothing on disk changes.",
            )
            .color(p.text_dim),
        );
        ui.label(RichText::new("Patch file").size(12.0).color(p.text_dim));
        ui.horizontal(|ui| {
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut path)
                        .id(Id::new("kraken_patch_import_path"))
                        .font(egui::TextStyle::Monospace)
                        .desired_width((ui.available_width() - 84.0).max(120.0)),
                )
                .on_hover_text("A file path; a relative one is taken from the project folder");
            if !r.has_focus() && !d.submitting {
                r.request_focus();
            }
            browse = ui
                .button("Browse...")
                .on_hover_text("Choose the patch file in an open dialog")
                .clicked();
        });
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        if !d.preview.is_empty() {
            ui.label(
                RichText::new(format!(
                    "This file would stage {} patch{}:",
                    d.preview.len(),
                    if d.preview.len() == 1 { "" } else { "es" }
                ))
                .color(s.success),
            );
            egui::ScrollArea::vertical()
                .max_height(120.0)
                .show(ui, |ui| {
                    for line in &d.preview {
                        ui.label(RichText::new(line).monospace().size(11.5));
                    }
                });
        }
        ui.add_space(6.0);
        let empty = path.trim().is_empty();
        ui.horizontal(|ui| {
            check = ui
                .add_enabled(!empty && !d.submitting, egui::Button::new("Check file"))
                .on_hover_text("List the patches the file would stage, without staging them")
                .on_disabled_hover_text("Choose a patch file first")
                .clicked();
        });
        buttons(
            ui,
            "Import patches",
            "Stage the file's changes as patches (Enter)",
            if empty {
                Err("Choose a patch file first".into())
            } else {
                Ok(())
            },
            d.submitting,
            &mut go,
            &mut cancel,
        );
    });
    if browse {
        browse_import(vm, ctx);
    }
    if path != d.path {
        vm.set_import_path(path);
    }
    if esc || cancel {
        vm.cancel_patch_import();
    } else if check {
        vm.submit_patch_import(true);
    } else if go || enter {
        vm.submit_patch_import(false);
    }
}

// ---------------------------------------------------------------- one-click patches

fn spaced(hex: &str) -> String {
    hex.as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn intent_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.intent_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut value = d.value.clone();
    let mut pattern = d.pattern.clone();
    let (mut apply, mut cancel, mut preview) = (false, false, false);
    let fname = vm.functions.containing(d.address).map(|f| f.name.clone());
    window(d.kind.title(), "kraken_patch_intent", 540.0).show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Address").size(12.0).color(p.text_dim));
            ui.label(
                RichText::new(format!("{:#x}", d.address))
                    .monospace()
                    .color(p.address),
            );
            if let Some(n) = &fname {
                ui.label(
                    RichText::new(format!("in {n}"))
                        .monospace()
                        .color(p.text_strong),
                );
            }
        });
        ui.label(RichText::new(d.kind.blurb()).color(p.text_dim));
        if d.kind.takes_input() {
            ui.horizontal(|ui| {
                let (label, hint) = match d.kind {
                    IntentKind::Return => ("Return value", "0, 1, -1, 0x10"),
                    _ => ("Length in bytes", "1 to 4096"),
                };
                ui.label(RichText::new(label).size(12.0).color(p.text_dim));
                let r = ui
                    .add(
                        egui::TextEdit::singleline(&mut value)
                            .id(Id::new("kraken_intent_value"))
                            .font(egui::TextStyle::Monospace)
                            .hint_text(hint)
                            .desired_width(110.0),
                    )
                    .on_hover_text(match d.kind {
                        IntentKind::Return => "The number the function returns, decimal or 0x hex",
                        _ => "How many bytes to overwrite, from the address above",
                    });
                if d.kind == IntentKind::Fill {
                    ui.label(RichText::new("Pattern (hex)").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut pattern)
                            .id(Id::new("kraken_intent_pattern"))
                            .font(egui::TextStyle::Monospace)
                            .hint_text("90 or cc")
                            .desired_width(110.0),
                    );
                }
                if !r.has_focus() && d.preview.is_none() && !d.loading {
                    r.request_focus();
                }
                preview = ui
                    .add_enabled(!d.loading, egui::Button::new("Preview"))
                    .on_hover_text("Show the bytes this would write")
                    .on_disabled_hover_text("Working...")
                    .clicked();
            });
        }
        ui.add_space(4.0);
        if d.loading {
            ui.label(RichText::new("Working out the new bytes...").color(p.text_dim));
        }
        if let Some(pv) = &d.preview {
            egui::Grid::new("kraken_intent_preview")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Now").size(12.0).color(p.text_dim));
                    ui.label(RichText::new(spaced(&pv.original)).monospace());
                    ui.end_row();
                    ui.label(RichText::new("After").size(12.0).color(p.text_dim));
                    ui.label(
                        RichText::new(spaced(&pv.replacement))
                            .monospace()
                            .color(p.text_strong),
                    );
                    ui.end_row();
                });
            ui.add_space(2.0);
            ui.columns(2, |cols| {
                cols[0].label(
                    RichText::new("Instructions now")
                        .size(12.0)
                        .color(p.text_dim),
                );
                for l in &pv.old_disassembly {
                    cols[0].label(RichText::new(l).monospace().size(12.0));
                }
                cols[1].label(
                    RichText::new("Instructions after")
                        .size(12.0)
                        .color(p.text_dim),
                );
                if pv.new_disassembly.is_empty() {
                    cols[1].label(
                        RichText::new("(not shown: no decoder for this processor here)")
                            .size(12.0)
                            .color(p.text_dim),
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
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Apply patch",
            "Record the patch (Enter). Undo it from the History; nothing on disk changes",
            if d.preview.is_some() {
                Ok(())
            } else {
                Err("Preview the patch first".into())
            },
            d.applying || d.loading,
            &mut apply,
            &mut cancel,
        );
    });
    if value != d.value {
        vm.set_intent_value(value);
    }
    if pattern != d.pattern {
        vm.set_intent_pattern(pattern);
    }
    if esc || cancel {
        vm.cancel_intent();
    } else if preview || (enter && d.preview.is_none() && d.kind.takes_input()) {
        vm.preview_intent();
    } else if apply || (enter && d.preview.is_some()) {
        vm.apply_intent();
    }
}

// ---------------------------------------------------------------- retype / signature

fn type_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.type_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut input = d.input.clone();
    let (mut save, mut cancel) = (false, false);
    let check = d.check();
    let (title, intro, hint) = match d.mode {
        TypeMode::Signature => (
            "Edit function signature",
            "Write the function as a C prototype: the return type, the name, then the parameters.",
            "int parse(char *buf, size_t len)",
        ),
        TypeMode::Data => (
            "Retype",
            "Write the type of the data at this address, as in C.",
            "int, char *, uint8_t[16], struct config",
        ),
    };
    window(title, "kraken_type", 540.0).show(ctx, |ui| {
        ui.label(RichText::new(intro).color(p.text_dim));
        ui.horizontal(|ui| {
            ui.label(RichText::new(&d.target).monospace().color(p.text_strong));
            ui.label(
                RichText::new(format!("{:#x}", d.address))
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            );
        });
        let r = ui.add(
            egui::TextEdit::singleline(&mut input)
                .id(Id::new("kraken_type_input"))
                .font(egui::TextStyle::Monospace)
                .hint_text(hint)
                .desired_width(f32::INFINITY)
                .margin(Margin::symmetric(8, 6)),
        )
        .on_hover_text("Write it as you would in C. Enter saves it");
        if !r.has_focus() && !d.submitting {
            r.request_focus();
        }
        match (&d.error, &check) {
            (Some(e), _) => {
                ui.label(RichText::new(e).color(s.danger));
            }
            (None, Err(e)) if !d.input.trim().is_empty() => {
                ui.label(RichText::new(e).color(s.danger));
            }
            (None, Ok((_, Some(note)))) => {
                ui.label(RichText::new(note).color(s.warning));
            }
            _ => {
                ui.label(
                    RichText::new(
                        "KRAKEN knows the C types, int8_t to uint64_t, size_t, Ghidra's undefined8 and uint, and the names of your own types.",
                    )
                    .size(12.0)
                    .color(p.text_dim),
                );
            }
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Save",
            "Apply it. The change is recorded in History and can be undone (Enter)",
            check.as_ref().map(|_| ()).map_err(Clone::clone),
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if input != d.input {
        vm.set_type_input(input);
    }
    if esc || cancel {
        vm.cancel_type();
    } else if save || (enter && check.is_ok()) {
        vm.submit_type();
    }
}

// ---------------------------------------------------------------- rename / retype a variable

fn local_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.local_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let (mut name, mut ty) = (d.name.clone(), d.ty.clone());
    let (mut save, mut cancel) = (false, false);
    let check = d.check();
    window("Rename or retype variable", "kraken_local", 540.0).show(ctx, |ui| {
        ui.label(
            RichText::new(
                "Give this variable of the decompiled function a better name, a type, or both. \
                 Leave a field alone to keep it.",
            )
            .color(p.text_dim),
        );
        ui.horizontal(|ui| {
            ui.label(RichText::new(&d.old_name).monospace().color(p.text_strong));
            ui.label(
                RichText::new(&d.storage)
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            );
        });
        ui.label(RichText::new("Name").size(12.0).color(p.text_dim));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut name)
                    .id(Id::new("kraken_local_name"))
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .margin(Margin::symmetric(8, 6)),
            )
            .on_hover_text("The new name, with no spaces. Enter saves it");
        ui.label(RichText::new("Type").size(12.0).color(p.text_dim));
        let rt = ui
            .add(
                egui::TextEdit::singleline(&mut ty)
                    .id(Id::new("kraken_local_type"))
                    .font(egui::TextStyle::Monospace)
                    .hint_text("int, char *, uint8_t[16], struct config")
                    .desired_width(f32::INFINITY)
                    .margin(Margin::symmetric(8, 6)),
            )
            .on_hover_text("Write the type as you would in C. Enter saves it");
        if !r.has_focus() && !rt.has_focus() && !d.submitting {
            if d.focus_type {
                rt.request_focus();
            } else {
                r.request_focus();
            }
        }
        match (&d.error, &check) {
            (Some(e), _) => {
                ui.label(RichText::new(e).color(s.danger));
            }
            (None, Err(e)) if d.name != d.old_name || !d.ty.trim().is_empty() => {
                ui.label(RichText::new(e).color(s.danger));
            }
            _ => {
                ui.label(
                    RichText::new(
                        "A type of another size than the variable can clash with its neighbours; \
                         the decompiler then says it was not applied.",
                    )
                    .size(12.0)
                    .color(p.text_dim),
                );
            }
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Save",
            "Apply it. The change is recorded in History and can be undone (Enter)",
            check.as_ref().map(|_| ()).map_err(Clone::clone),
            d.submitting,
            &mut save,
            &mut cancel,
        );
    });
    if name != d.name || ty != d.ty {
        vm.set_local_input(name, ty);
    }
    if esc || cancel {
        vm.cancel_local();
    } else if save || (enter && check.is_ok()) {
        vm.submit_local();
    }
}

// ---------------------------------------------------------------- create / delete function

fn function_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.function_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut name = d.name.clone();
    let (mut ok, mut cancel) = (false, false);
    let (title, label, tip) = match d.kind {
        FunctionDialogKind::Create => ("Create function", "Create", "Create the function (Enter)"),
        FunctionDialogKind::Delete => (
            "Delete function?",
            "Delete",
            "Delete the function; its code stays (Enter)",
        ),
    };
    window(title, "kraken_function", 440.0).show(ctx, |ui| {
        match d.kind {
            FunctionDialogKind::Create => {
                ui.label(
                    RichText::new(format!(
                        "Mark the code at {:#x} as the start of a function. KRAKEN works out where it ends.",
                        d.address
                    ))
                    .color(p.text_dim),
                );
                let r = ui.add(
                    egui::TextEdit::singleline(&mut name)
                        .id(Id::new("kraken_function_name"))
                        .font(egui::TextStyle::Monospace)
                        .hint_text("Name (optional), e.g. handle_request")
                        .desired_width(f32::INFINITY),
                )
                .on_hover_text("A name for the new function. Leave it empty for a default name");
                if !r.has_focus() && !d.submitting {
                    r.request_focus();
                }
            }
            FunctionDialogKind::Delete => {
                ui.label(
                    RichText::new(format!(
                        "Remove the function {} at {:#x}? Its code stays; only the function goes. You can undo this from History.",
                        d.name, d.address
                    ))
                    .color(s.warning),
                );
            }
        }
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        buttons(ui, label, tip, Ok(()), d.submitting, &mut ok, &mut cancel);
    });
    if name != d.name && d.kind == FunctionDialogKind::Create {
        vm.set_function_name_input(name);
    }
    if esc || cancel {
        vm.cancel_function_dialog();
    } else if ok || enter {
        vm.submit_function_dialog();
    }
}

// ---------------------------------------------------------------- generated command form

fn command_form(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(f) = vm.tools.form.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let esc = ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape));
    let mut values: Vec<String> = f.fields.iter().map(|x| x.value.clone()).collect();
    let mut flags: Vec<bool> = f.fields.iter().map(|x| x.flag).collect();
    let (mut run, mut cancel) = (false, false);
    egui::Window::new(medium(humanize_command(&f.command), 15.0))
        .id(Id::new("kraken_command_form"))
        .collapsible(false)
        .resizable(true)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .default_width(540.0)
        .show(ctx, |ui| {
            ui.label(RichText::new(&f.summary).color(p.text_strong));
            if !f.doc.is_empty() {
                ui.label(RichText::new(&f.doc).size(12.0).color(p.text_dim));
            }
            match f.permission {
                Permission::Safe => {}
                Permission::Mutating => {
                    ui.label(
                        RichText::new("This changes the project. It is recorded in History.")
                            .size(12.0)
                            .color(s.warning),
                    );
                }
                Permission::Dangerous => {
                    ui.label(
                        RichText::new(
                            "This can change or remove work. KRAKEN asks you to allow it before it runs.",
                        )
                        .size(12.0)
                        .color(s.danger),
                    );
                }
            }
            ui.add_space(4.0);
            egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                egui::Grid::new("kraken_form_grid")
                    .num_columns(2)
                    .spacing(vec2(10.0, 6.0))
                    .show(ui, |ui| {
                        for (i, field) in f.fields.iter().enumerate() {
                            let label = if field.required {
                                format!("{} *", field.name)
                            } else {
                                field.name.clone()
                            };
                            ui.label(RichText::new(label).monospace())
                                .on_hover_text(&field.doc);
                            let tip = if field.required {
                                format!("{} (required)", field.doc)
                            } else {
                                format!("{} (optional; leave empty to skip)", field.doc)
                            };
                            match &field.kind {
                                FieldKind::Bool => {
                                    ui.checkbox(&mut flags[i], "").on_hover_text(tip);
                                }
                                FieldKind::Enum(opts) => {
                                    let shown = if values[i].is_empty() {
                                        "(not set)".to_string()
                                    } else {
                                        values[i].clone()
                                    };
                                    egui::ComboBox::from_id_salt(("kraken_form_enum", i))
                                        .selected_text(shown)
                                        .show_ui(ui, |ui| {
                                            if !field.required {
                                                ui.selectable_value(
                                                    &mut values[i],
                                                    String::new(),
                                                    "(not set)",
                                                )
                                                .on_hover_text("Leave this option out");
                                            }
                                            for (v, doc) in opts {
                                                ui.selectable_value(&mut values[i], v.clone(), v)
                                                    .on_hover_text(doc);
                                            }
                                        })
                                        .response
                                        .on_hover_text(tip);
                                }
                                kind => {
                                    let hint = match kind {
                                        FieldKind::Address => "0x401000",
                                        FieldKind::Integer => "a number",
                                        FieldKind::Json => "JSON",
                                        _ => "",
                                    };
                                    let edit = if *kind == FieldKind::Json {
                                        egui::TextEdit::multiline(&mut values[i]).desired_rows(2)
                                    } else {
                                        egui::TextEdit::singleline(&mut values[i])
                                    };
                                    ui.add(
                                        edit.id(Id::new(("kraken_form_field", i)))
                                            .hint_text(hint)
                                            .desired_width(320.0),
                                    )
                                    .on_hover_text(tip);
                                }
                            }
                            ui.end_row();
                        }
                    });
            });
            if let Some(e) = &f.error {
                ui.label(RichText::new(e).color(s.danger));
            }
            ui.add_space(6.0);
            buttons(
                ui,
                "Run",
                "Run the command and show what it returns",
                Ok(()),
                f.running,
                &mut run,
                &mut cancel,
            );
        });
    for (i, v) in values.into_iter().enumerate() {
        if f.fields.get(i).is_some_and(|x| x.value != v) {
            vm.set_form_value(i, v);
        }
    }
    for (i, b) in flags.into_iter().enumerate() {
        if f.fields.get(i).is_some_and(|x| x.flag != b) {
            vm.set_form_flag(i, b);
        }
    }
    if esc || cancel {
        vm.cancel_command_form();
    } else if run {
        vm.submit_command_form();
    }
}

fn command_result(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(r) = vm.tools.result.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let mut open = true;
    let mut go = None;
    let mut close = false;
    egui::Window::new(medium(
        format!("Result: {}", humanize_command(&r.command)),
        15.0,
    ))
    .id(Id::new("kraken_command_result"))
    .open(&mut open)
    .collapsible(true)
    .resizable(true)
    .default_size(vec2(560.0, 420.0))
    .show(ctx, |ui| {
        ui.label(
            RichText::new(format!("{} {}", r.command, r.args))
                .monospace()
                .size(11.5)
                .color(p.text_dim),
        );
        if r.failed {
            ui.label(RichText::new(&r.text).color(s.danger));
        } else {
            if r.truncated {
                ui.label(
                    RichText::new("The result is very long; the end is cut off.")
                        .size(12.0)
                        .color(s.warning),
                );
            }
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .max_height((ui.available_height() - 30.0).max(60.0))
                .show(ui, |ui| {
                    for line in result_lines(&r.text) {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 0.0;
                            for seg in line {
                                match seg {
                                    ResultSegment::Text(t) => {
                                        ui.label(RichText::new(t).monospace().size(12.0));
                                    }
                                    ResultSegment::Address(t, a) => {
                                        if ui
                                            .link(
                                                RichText::new(t)
                                                    .monospace()
                                                    .size(12.0)
                                                    .color(p.address),
                                            )
                                            .on_hover_text("Go to this address")
                                            .clicked()
                                        {
                                            go = Some(a);
                                        }
                                    }
                                }
                            }
                        });
                    }
                });
        }
        ui.horizontal(|ui| {
            if ui
                .button("Copy")
                .on_hover_text("Copy the whole result to the clipboard")
                .clicked()
            {
                ui.ctx().copy_text(r.text.clone());
            }
            if ui
                .button("Close")
                .on_hover_text("Close this window")
                .clicked()
            {
                close = true;
            }
        });
    });
    if let Some(a) = go {
        vm.goto(a);
    }
    if !open || close {
        vm.close_command_result();
    }
}

// ---------------------------------------------------------------- import symbols

static SYMBOLS_PICK: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn browse_symbols(vm: &ViewModel, ctx: &egui::Context) {
    let ctx = ctx.clone();
    let start = vm
        .project
        .as_ref()
        .map(|p| p.project_dir.clone())
        .filter(|d| std::path::Path::new(d).is_dir());
    vm.runtime_handle().spawn(async move {
        let mut d = rfd::AsyncFileDialog::new()
            .set_title("Choose a map, CSV, splat or IDA script file")
            .add_filter("Symbol files", &["map", "csv", "txt", "idc"]);
        if let Some(s) = start {
            d = d.set_directory(s);
        }
        if let Some(h) = d.pick_file().await {
            if let Ok(mut p) = SYMBOLS_PICK.lock() {
                *p = Some(h.path().to_string_lossy().into_owned());
            }
            ctx.request_repaint();
        }
    });
}

fn status_label(status: &str) -> &str {
    match status {
        "unchanged" => "same",
        "duplicate" => "repeat",
        other => other,
    }
}

fn symbols_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.symbols_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut edited = d.clone();
    if let Some(picked) = SYMBOLS_PICK.lock().ok().and_then(|mut x| x.take()) {
        edited.path = picked;
    }
    let (mut go, mut cancel, mut browse, mut preview) = (false, false, false, false);
    window("Import symbols", "kraken_import_symbols", 640.0).show(ctx, |ui| {
        ui.label(
            RichText::new(
                "Names functions and labels, and adds comments, from a GNU ld or MSVC map, a CSV \
                 (address,name,size,comment), a splat symbol_addrs.txt or an IDA script. \
                 Preview first; the import is one undoable run in History.",
            )
            .color(p.text_dim),
        );
        ui.label(RichText::new("File").size(12.0).color(p.text_dim));
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut edited.path)
                    .id(Id::new("kraken_symbols_path"))
                    .font(egui::TextStyle::Monospace)
                    .desired_width((ui.available_width() - 84.0).max(120.0)),
            )
            .on_hover_text("The symbol file; a relative path is taken from the project folder");
            browse = ui
                .button("Browse...")
                .on_hover_text("Choose the file in an open dialog")
                .clicked();
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Format").size(12.0).color(p.text_dim));
            egui::ComboBox::from_id_salt("kraken_symbols_format")
                .selected_text(SYMBOL_FORMATS[edited.format.min(SYMBOL_FORMATS.len() - 1)].1)
                .show_ui(ui, |ui| {
                    for (i, (_, label)) in SYMBOL_FORMATS.iter().enumerate() {
                        ui.selectable_value(&mut edited.format, i, *label)
                            .on_hover_text("Read the file as this format");
                    }
                })
                .response
                .on_hover_text("Detect looks at the text and picks the format");
            ui.label(RichText::new("Offset").size(12.0).color(p.text_dim));
            ui.add(
                egui::TextEdit::singleline(&mut edited.offset)
                    .id(Id::new("kraken_symbols_offset"))
                    .hint_text("0x0")
                    .font(egui::TextStyle::Monospace)
                    .desired_width(110.0),
            )
            .on_hover_text(
                "Added to every address of the file, such as 0x100000 for a position-independent \
                 program loaded at that base; a minus sign subtracts",
            );
        });
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("A different name")
                    .size(12.0)
                    .color(p.text_dim),
            );
            egui::ComboBox::from_id_salt("kraken_symbols_conflicts")
                .selected_text(SYMBOL_CONFLICTS[edited.conflicts.min(SYMBOL_CONFLICTS.len() - 1)].1)
                .show_ui(ui, |ui| {
                    for (i, (_, label)) in SYMBOL_CONFLICTS.iter().enumerate() {
                        ui.selectable_value(&mut edited.conflicts, i, *label)
                            .on_hover_text("What to do when a function already has another name");
                    }
                })
                .response
                .on_hover_text(
                    "What to do when a function already has another name than the file gives it",
                );
        });
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        if let Some(r) = &d.preview {
            ui.separator();
            ui.label(
                RichText::new(format!(
                    "{} records read as {}: {} new, {} same, {} conflicts, {} invalid, {} repeated",
                    r.records, r.format, r.new, r.unchanged, r.conflicts, r.invalid, r.duplicates
                ))
                .strong(),
            );
            for w in &r.warnings {
                ui.label(RichText::new(w).size(12.0).color(s.warning));
            }
            egui::ScrollArea::vertical()
                .id_salt("kraken_symbols_rows")
                .max_height(260.0)
                .show(ui, |ui| {
                    egui::Grid::new("kraken_symbols_grid")
                        .num_columns(4)
                        .striped(true)
                        .spacing([12.0, 3.0])
                        .show(ui, |ui| {
                            for h in ["Address", "Status", "File says", "Program has"] {
                                ui.label(RichText::new(h).size(12.0).color(p.text_dim));
                            }
                            ui.end_row();
                            for row in &r.edits {
                                ui.label(RichText::new(&row.address).monospace().size(12.0));
                                let color = match row.status.as_str() {
                                    "conflict" => s.warning,
                                    "invalid" => s.danger,
                                    _ => p.text,
                                };
                                let st = ui.label(
                                    RichText::new(status_label(&row.status))
                                        .size(12.0)
                                        .color(color),
                                );
                                if let Some(why) = &row.reason {
                                    st.on_hover_text(why.clone());
                                }
                                let says = match (&row.name, &row.text) {
                                    (Some(n), _) => n.clone(),
                                    (None, Some(t)) => format!("// {t}"),
                                    _ => String::new(),
                                };
                                ui.label(RichText::new(says).monospace().size(12.0));
                                ui.label(
                                    RichText::new(row.existing.clone().unwrap_or_default())
                                        .monospace()
                                        .size(12.0)
                                        .color(p.text_dim),
                                );
                                ui.end_row();
                            }
                        });
                    if r.edits_omitted > 0 {
                        ui.label(
                            RichText::new(format!("{} more not shown", r.edits_omitted))
                                .size(12.0)
                                .color(p.text_dim),
                        );
                    }
                });
        }
        ui.add_space(6.0);
        let ready = if edited.path.trim().is_empty() {
            Err("Choose the symbol file".to_string())
        } else {
            Ok(())
        };
        ui.horizontal(|ui| {
            let r = ui
                .add_enabled(ready.is_ok() && !d.busy, egui::Button::new("Preview"))
                .on_hover_text("Read the file and list what would change; nothing is changed yet")
                .on_disabled_hover_text(ready.clone().err().unwrap_or_else(|| "Working...".into()));
            if r.clicked() {
                preview = true;
            }
        });
        buttons(
            ui,
            "Import",
            "Apply the names and comments as one undoable run (Enter)",
            ready,
            d.busy,
            &mut go,
            &mut cancel,
        );
    });
    if browse {
        browse_symbols(vm, ctx);
    }
    if edited != d {
        let fresh = edited.clone();
        vm.edit_symbols_dialog(move |x| {
            x.path = fresh.path;
            x.format = fresh.format;
            x.conflicts = fresh.conflicts;
            x.offset = fresh.offset;
        });
    }
    if esc || cancel {
        vm.cancel_import_symbols();
    } else if preview {
        vm.preview_import_symbols();
    } else if go || enter {
        if d.preview.is_some() || go {
            vm.submit_import_symbols();
        } else {
            vm.preview_import_symbols();
        }
    }
}

//! The dialogs of the navigation and editing tools: Go to, bookmark note, Retype / Edit
//! signature, Create / Delete function, the generated command form and its result window.

use egui::{Align2, Id, Key, Margin, Modifiers, RichText, vec2};
use kraken_gui_widgets::{KrakenTheme, Palette};
use kraken_viewmodel::navtools::{
    FieldKind, FunctionDialogKind, PatchOrigin, ResultSegment, TypeMode, result_lines, spaced_hex,
};
use kraken_viewmodel::{Permission, ViewModel, humanize_command};

use crate::style::{self, Status, medium};

/// Draws whichever tool dialogs are open.
pub fn show(ctx: &egui::Context, vm: &mut ViewModel) {
    goto_dialog(ctx, vm);
    bookmark_dialog(ctx, vm);
    patch_dialog(ctx, vm);
    export_dialog(ctx, vm);
    type_dialog(ctx, vm);
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

fn patch_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.patch_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut input = d.input.clone();
    let mut note = d.note.clone();
    let (mut save, mut cancel, mut pad) = (false, false, false);
    let title = if d.existing {
        "Edit byte patch"
    } else {
        "Patch bytes"
    };
    let fname = vm.functions.containing(d.address).map(|f| f.name.clone());
    window(title, "kraken_patch", 520.0).show(ctx, |ui| {
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
        if let PatchOrigin::Instruction(text) = &d.origin {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Instruction").size(12.0).color(p.text_dim));
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
            .on_hover_text(
                "The bytes to put here, as hex. Spaces are ignored. An assembler for typing \
                 instructions is not built in yet",
            );
        if !r.has_focus()
            && !d.submitting
            && !ui.memory(|m| m.has_focus(Id::new("kraken_patch_note")))
        {
            r.request_focus();
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
                .hint_text("Why, e.g. skip the licence check (optional)")
                .desired_width(f32::INFINITY),
        )
        .on_hover_text("A note kept with the patch");
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
    if input != d.input {
        vm.set_patch_input(input);
    }
    if note != d.note {
        vm.set_patch_note(note);
    }
    if pad {
        vm.pad_patch_with_nops();
    }
    if esc || cancel {
        vm.cancel_patch();
    } else if save || enter {
        vm.submit_patch();
    }
}

fn export_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.tools.export_dialog.clone() else {
        return;
    };
    let (p, s) = colors(ctx);
    let (enter, esc) = enter_escape(ctx);
    let mut path = d.output_path.clone();
    let mut overwrite = d.overwrite;
    let (mut save, mut cancel) = (false, false);
    let n = vm.tools.patches.items.len();
    window("Export patched binary", "kraken_patch_export", 520.0).show(ctx, |ui| {
        ui.label(
            RichText::new(format!(
                "Writes a copy of the program with {} applied. Each address is mapped to its \
                 place in the file and the original bytes are checked first; if anything does \
                 not line up nothing is written. The original file is never touched.",
                match n {
                    0 => "no patches (an exact copy)".to_string(),
                    1 => "1 patch".to_string(),
                    n => format!("{n} patches"),
                }
            ))
            .color(p.text_dim),
        );
        ui.label(RichText::new("Write to").size(12.0).color(p.text_dim));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut path)
                    .id(Id::new("kraken_patch_export_path"))
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text("A file path; a relative one is placed in the project folder");
        if !r.has_focus() && !d.submitting {
            r.request_focus();
        }
        ui.checkbox(&mut overwrite, "Replace the file if it exists")
            .on_hover_text("Without this, an existing file at that path is left alone");
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        buttons(
            ui,
            "Write patched binary",
            "Write the copy (Enter). You are asked to confirm first",
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
    if path != d.output_path {
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

//! Command palette and the rename / comment dialogs.

use egui::{
    Align2, Color32, CornerRadius, Frame, Id, Key, Margin, Modifiers, RichText, Sense, Stroke, vec2,
};
use kraken_gui_widgets::KrakenTheme;
use kraken_proto::CommentKind;
use kraken_viewmodel::{ApprovalBroker, UiRequest, ViewModel};

use crate::style::{self, medium};

const PALETTE_ROWS: usize = 9;

/// The command palette. Keyboard first: type, Up/Down, Enter, Esc.
pub fn palette(ctx: &egui::Context, vm: &mut ViewModel, reqs: &mut Vec<UiRequest>) {
    if !vm.palette.open {
        return;
    }
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();

    let (esc, up, down, enter) = ctx.input_mut(|i| {
        (
            i.consume_key(Modifiers::NONE, Key::Escape),
            i.consume_key(Modifiers::NONE, Key::ArrowUp),
            i.consume_key(Modifiers::NONE, Key::ArrowDown),
            i.consume_key(Modifiers::NONE, Key::Enter),
        )
    });
    if esc {
        vm.close_palette();
        return;
    }
    if up {
        vm.palette.move_selection(-1);
    }
    if down {
        vm.palette.move_selection(1);
    }

    // Dim the window behind and close on a click outside.
    let screen = ctx.content_rect();
    let dim = egui::Area::new(Id::new("kraken_palette_dim"))
        .order(egui::Order::Middle)
        .fixed_pos(screen.min)
        .show(ctx, |ui| {
            let (rect, resp) = ui.allocate_exact_size(screen.size(), Sense::click());
            ui.painter().rect_filled(
                rect,
                0.0,
                Color32::from_black_alpha(if dark { 130 } else { 70 }),
            );
            resp
        });
    if dim.inner.clicked() {
        vm.close_palette();
        return;
    }

    let rows: Vec<(String, String, Option<&'static str>, bool)> = vm
        .palette
        .visible()
        .iter()
        .map(|i| (i.title.clone(), i.subtitle.clone(), i.shortcut, i.mutating))
        .collect();
    let selected = vm.palette.selected.min(rows.len().saturating_sub(1));
    let start = (selected + 1).saturating_sub(PALETTE_ROWS);
    let mut chosen: Option<usize> = None;
    let mut query = vm.palette.query.clone();

    egui::Area::new(Id::new("kraken_palette"))
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_TOP, vec2(0.0, 84.0))
        .show(ctx, |ui| {
            Frame::new()
                .fill(p.panel)
                .stroke(Stroke::new(1.0, p.border))
                .corner_radius(CornerRadius::same(12))
                .inner_margin(Margin::same(10))
                .shadow(egui::Shadow {
                    offset: [0, 10],
                    blur: 30,
                    spread: 0,
                    color: Color32::from_black_alpha(140),
                })
                .show(ui, |ui| {
                    ui.set_width(580.0);
                    let edit = egui::TextEdit::singleline(&mut query)
                        .id(Id::new("kraken_palette_input"))
                        .hint_text("Type a command, e.g. rename, undo, theme...")
                        .font(egui::FontId::new(15.0, egui::FontFamily::Proportional))
                        .desired_width(f32::INFINITY)
                        .margin(Margin::symmetric(10, 8));
                    let r = ui
                        .add(edit)
                        .on_hover_text("Type part of what you want to do, then press Enter");
                    r.request_focus();
                    ui.add_space(6.0);

                    if rows.is_empty() {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(format!("No command matches \"{query}\"."))
                                .color(p.text_dim),
                        );
                        ui.add_space(8.0);
                    }
                    for (i, (title, sub, shortcut, mutating)) in
                        rows.iter().enumerate().skip(start).take(PALETTE_ROWS)
                    {
                        let (rect, resp) = ui
                            .allocate_exact_size(vec2(ui.available_width(), 42.0), Sense::click());
                        if i == selected {
                            ui.painter().rect_filled(rect, 7.0, p.selection);
                            ui.painter().rect_stroke(
                                rect,
                                7.0,
                                Stroke::new(1.0, p.accent.gamma_multiply(0.6)),
                                egui::StrokeKind::Inside,
                            );
                        } else if resp.hovered() {
                            ui.painter().rect_filled(rect, 7.0, p.row_hover);
                        }
                        let tx = rect.left() + 12.0;
                        ui.painter().text(
                            egui::pos2(tx, rect.top() + 14.0),
                            Align2::LEFT_CENTER,
                            title,
                            egui::FontId::new(14.0, crate::fonts::medium()),
                            p.text_strong,
                        );
                        ui.painter().text(
                            egui::pos2(tx, rect.top() + 30.0),
                            Align2::LEFT_CENTER,
                            sub,
                            egui::FontId::new(11.5, egui::FontFamily::Proportional),
                            p.text_dim,
                        );
                        let mut right = rect.right() - 12.0;
                        if let Some(sc) = shortcut {
                            let g = ui.painter().text(
                                egui::pos2(right, rect.center().y),
                                Align2::RIGHT_CENTER,
                                sc,
                                egui::FontId::monospace(11.5),
                                p.text_dim,
                            );
                            right = g.left() - 8.0;
                        }
                        if *mutating {
                            ui.painter().text(
                                egui::pos2(right, rect.center().y),
                                Align2::RIGHT_CENTER,
                                "changes the project",
                                egui::FontId::new(11.0, egui::FontFamily::Proportional),
                                style::status(dark).warning,
                            );
                        }
                        if resp.clicked() {
                            chosen = Some(i);
                        }
                    }
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("Up / Down to move    Enter to run    Esc to close")
                            .size(11.0)
                            .color(p.text_dim),
                    );
                });
        });

    if query != vm.palette.query {
        vm.palette.set_query(query);
    }
    if let Some(i) = chosen {
        vm.palette.selected = i;
        reqs.extend(vm.activate_palette());
    } else if enter {
        reqs.extend(vm.activate_palette());
    }
}

fn dialog_window(title: &str, id: &str) -> egui::Window<'static> {
    egui::Window::new(medium(title, 15.0))
        .id(Id::new(id))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -50.0))
        .fixed_size(vec2(400.0, 0.0))
}

/// The rename dialog: validation shown live, server errors and conflicts shown plainly.
pub fn rename_dialog(ctx: &egui::Context, vm: &mut ViewModel, focus: &mut Option<u64>) {
    let Some(d) = vm.rename.clone() else {
        *focus = None;
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let mut input = d.input.clone();
    let mut submit = false;
    let mut cancel = false;
    let validation = d.validate();
    let untouched = d.input == d.old_name;

    let is_function = vm.functions.find(d.address).is_some()
        || vm.current.as_ref().is_some_and(|c| c.address == d.address);
    let (title, intro) = if is_function {
        (
            "Rename function",
            "Give this function a name that says what it does.",
        )
    } else {
        (
            "Rename / add label",
            "Name this address. The name shows wherever the address is used.",
        )
    };
    dialog_window(title, "kraken_rename").show(ctx, |ui| {
        ui.label(RichText::new(intro).color(p.text_dim));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Current name").size(12.0).color(p.text_dim));
            ui.label(RichText::new(&d.old_name).monospace().color(p.text_strong));
            ui.label(
                RichText::new(format!("{:#x}", d.address))
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            );
        });
        let edit = egui::TextEdit::singleline(&mut input)
            .id(Id::new("kraken_rename_input"))
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY)
            .margin(Margin::symmetric(8, 6));
        let out = edit.show(ui);
        out.response
            .response
            .clone()
            .on_hover_text("Type the new name. Enter saves it, Escape cancels");
        if *focus != Some(d.address) {
            *focus = Some(d.address);
            out.response.request_focus();
            let mut state = out.state.clone();
            state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::two(
                    egui::text::CCursor::new(egui::text::CharIndex(0)),
                    egui::text::CCursor::new(egui::text::CharIndex(d.input.chars().count())),
                )));
            state.store(ctx, out.response.id);
        }
        if (out.response.has_focus() || out.response.lost_focus())
            && ctx.input(|i| i.key_pressed(Key::Enter))
        {
            submit = true;
            out.response.request_focus();
        }
        ui.add_space(2.0);
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        } else if let Some(n) = &d.notice {
            ui.label(RichText::new(n).color(s.warning));
        } else if let (Err(msg), false) = (&validation, untouched) {
            ui.label(RichText::new(msg).color(s.danger));
        } else {
            ui.label(
                RichText::new("Letters, digits and underscores work best. No spaces.")
                    .size(12.0)
                    .color(p.text_dim),
            );
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_enabled_ui(validation.is_ok() && !d.submitting, |ui| {
                if style::primary_button(ui, "Rename")
                    .on_hover_text("Save the new name. You can undo it")
                    .clicked()
                {
                    submit = true;
                }
            });
            if ui
                .button("Cancel")
                .on_hover_text("Close without changing anything")
                .clicked()
            {
                cancel = true;
            }
            if d.submitting {
                ui.spinner();
            }
        });
    });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        cancel = true;
    }
    if input != d.input {
        vm.set_rename_input(input);
    }
    if cancel {
        vm.cancel_rename();
    } else if submit && validation.is_ok() {
        vm.submit_rename();
    }
}

fn kind_label(k: CommentKind) -> &'static str {
    match k {
        CommentKind::Plate => "Above the function",
        CommentKind::Pre => "Before the line",
        CommentKind::Eol => "End of line",
        CommentKind::Post => "After the line",
        CommentKind::Repeatable => "Shown at every use",
    }
}

fn kind_help(k: CommentKind) -> &'static str {
    match k {
        CommentKind::Plate => "A block of text shown above the function",
        CommentKind::Pre => "A line of text shown before this line",
        CommentKind::Eol => "A short note at the end of this line",
        CommentKind::Post => "A line of text shown after this line",
        CommentKind::Repeatable => "A note that also shows wherever this address is used",
    }
}

/// The comment dialog.
pub fn comment_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.comment.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let mut input = d.input.clone();
    let mut kind = d.kind;
    let mut submit = false;
    let mut cancel = false;
    dialog_window("Comment", "kraken_comment").show(ctx, |ui| {
        ui.label(
            RichText::new("Notes are saved with the project and shown to everyone who opens it.")
                .color(p.text_dim),
        );
        ui.add_space(4.0);
        let kinds = egui::ComboBox::from_id_salt("kraken_comment_kind")
            .selected_text(kind_label(kind))
            .show_ui(ui, |ui| {
                for k in [
                    CommentKind::Plate,
                    CommentKind::Pre,
                    CommentKind::Eol,
                    CommentKind::Post,
                    CommentKind::Repeatable,
                ] {
                    ui.selectable_value(&mut kind, k, kind_label(k))
                        .on_hover_text(kind_help(k));
                }
            });
        kinds
            .response
            .on_hover_text("Where the comment shows: above the line, beside it or below it");
        let r = ui.add(
            egui::TextEdit::multiline(&mut input)
                .desired_rows(4)
                .desired_width(f32::INFINITY)
                .hint_text("Write a note. Leave it empty and save to remove the comment."),
        );
        let r = r.on_hover_text("The note is saved with the project");
        if !r.has_focus() && !d.submitting && d.input.is_empty() && input.is_empty() {
            r.request_focus();
        }
        if let Some(e) = &d.error {
            ui.label(RichText::new(e).color(s.danger));
        }
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!d.submitting, |ui| {
                if style::primary_button(ui, "Save")
                    .on_hover_text("Save the comment. You can undo it")
                    .clicked()
                {
                    submit = true;
                }
            });
            if ui
                .button("Cancel")
                .on_hover_text("Close without changing anything")
                .clicked()
            {
                cancel = true;
            }
            if d.submitting {
                ui.spinner();
            }
        });
    });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        cancel = true;
    }
    if kind != d.kind {
        vm.set_comment_kind(kind);
    } else if input != d.input {
        vm.set_comment_input(input);
    }
    if cancel {
        vm.cancel_comment();
    } else if submit {
        vm.submit_comment();
    }
}

/// Asks whether a dangerous command may run. Nothing runs until the person says yes.
pub fn approval_dialog(ctx: &egui::Context, broker: &ApprovalBroker) {
    let Some((id, prompt)) = broker.current() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let mut answer = None;
    egui::Window::new(medium("Allow this action?", 15.0))
        .id(Id::new("kraken_approval"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -50.0))
        .fixed_size(vec2(440.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new("This can change or remove work in your project.").color(s.warning),
            );
            ui.add_space(4.0);
            ui.label(medium(&prompt.command, 14.0).color(p.text_strong));
            ui.label(RichText::new(&prompt.summary).color(p.text_dim));
            let args = serde_json::to_string_pretty(&prompt.args).unwrap_or_default();
            if args != "null" && args != "{}" {
                ui.add_space(4.0);
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .show(ui, |ui| {
                        ui.label(RichText::new(args).monospace().size(12.0).color(p.text));
                    });
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if style::primary_button(ui, "Allow")
                    .on_hover_text("Let the agent do this once")
                    .clicked()
                {
                    answer = Some(true);
                }
                if ui
                    .button("Deny")
                    .on_hover_text("Refuse. The agent cannot do this")
                    .clicked()
                {
                    answer = Some(false);
                }
            });
        });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        answer = Some(false);
    }
    if let Some(a) = answer {
        broker.respond(id, a);
    }
}

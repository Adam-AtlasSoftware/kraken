//! The History tab: every change, grouped by agent run, with a per-change Undo that previews the
//! later edits depending on it, and the dialog that asks before undoing them too.

use egui::{Align2, Key, RichText, Ui, vec2};
use kraken_gui_widgets::KrakenTheme;
use kraken_viewmodel::history::{HistoryGroup, UndoDialog, group_history, is_live};
use kraken_viewmodel::{HistoryEntry, ViewModel};

use crate::style::{self, chip, clock, empty_state, medium, pal};

/// What the person asked for in one frame; applied after the drawing borrow ends.
#[derive(Default)]
struct Acts {
    undo_entry: Option<u64>,
    undo_run: Option<String>,
    more: bool,
}

/// The History tab.
pub fn panel(ui: &mut Ui, vm: &mut ViewModel) {
    let s = style::status(style::dark(ui));
    ui.horizontal(|ui| {
        if ui
            .button("Undo my last change")
            .on_hover_text("Reverses your most recent edit. Press again to step further back.")
            .clicked()
        {
            vm.undo_last();
        }
        if ui
            .button("Refresh")
            .on_hover_text("Reload the list")
            .clicked()
        {
            vm.refresh_history();
        }
        if vm.history.loading {
            ui.spinner();
        }
    });
    if let Some(e) = &vm.history.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    if vm.history.entries.is_empty() && !vm.history.loading {
        empty_state(
            ui,
            "No changes yet",
            "Rename a function or add a comment and it will be listed here, with a way to undo it.",
            None,
        );
        return;
    }
    let groups = group_history(&vm.history.entries);
    let mut acts = Acts::default();
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for g in &groups {
                let rows = &vm.history.entries[g.first..g.first + g.len];
                if g.run_id.is_some() {
                    run_header(ui, g, &mut acts);
                    ui.indent(("run", g.first), |ui| {
                        for e in rows {
                            entry_row(ui, e, &mut acts);
                        }
                    });
                } else {
                    for e in rows {
                        entry_row(ui, e, &mut acts);
                    }
                }
            }
            if vm.history.next_cursor.is_some()
                && ui
                    .button("Load older changes")
                    .on_hover_text("Show the next older changes")
                    .clicked()
            {
                acts.more = true;
            }
        });
    if let Some(id) = acts.undo_entry {
        vm.request_undo_entry(id);
    }
    if let Some(run) = acts.undo_run {
        vm.request_undo_run(run);
    }
    if acts.more {
        vm.load_more_history();
    }
}

fn run_header(ui: &mut Ui, g: &HistoryGroup, acts: &mut Acts) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(run) = &g.run_id else { return };
    ui.horizontal(|ui| {
        chip(ui, &g.who, s.info);
        ui.label(
            medium(
                format!("{} edit{}", g.len, if g.len == 1 { "" } else { "s" }),
                12.5,
            )
            .color(p.text_strong),
        );
        ui.label(
            RichText::new(format!("run {run}"))
                .monospace()
                .size(11.5)
                .color(p.text_dim),
        );
        ui.add_enabled_ui(g.live > 0, |ui| {
            if ui
                .small_button("Undo this agent run")
                .on_hover_text(format!(
                    "Reverse every change from run {run}. Later edits that depended on them are listed first."
                ))
                .clicked()
            {
                acts.undo_run = Some(run.clone());
            }
        });
    });
}

fn entry_row(ui: &mut Ui, e: &HistoryEntry, acts: &mut Acts) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.horizontal(|ui| {
        let dim = e.undone || e.status == "rejected";
        let text = |t: String| {
            let r = RichText::new(t).size(12.5);
            if dim {
                r.color(p.text_dim).strikethrough()
            } else {
                r.color(p.text)
            }
        };
        ui.label(
            RichText::new(clock(e.ts_ms))
                .monospace()
                .size(11.5)
                .color(p.text_dim),
        );
        if e.by_agent {
            chip(ui, &e.who, s.info);
        } else {
            chip(ui, "you", p.accent);
        }
        ui.label(text(e.description.clone()));
        if e.is_undo {
            chip(ui, "undo", p.text_dim);
        }
        if e.undone {
            chip(ui, "undone", p.text_dim);
        }
        if e.sync == "engine_rejected" {
            chip(ui, "engine refused", s.danger);
        } else if e.sync == "pending" {
            chip(ui, "waiting", s.warning);
        }
        if is_live(e)
            && ui
                .small_button("Undo")
                .on_hover_text(
                    "Reverse this change. If later edits depended on it, you are asked first.",
                )
                .clicked()
        {
            acts.undo_entry = Some(e.id);
        }
    });
}

/// The undo preview: names the later edits that depended on what is being undone.
pub fn dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(d) = vm.undo.dialog.clone().filter(UndoDialog::visible) else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let mut confirm = false;
    let mut cancel = false;
    egui::Window::new(medium("Undo", 15.0))
        .id(egui::Id::new("kraken_undo_preview"))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -50.0))
        .fixed_size(vec2(480.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(&d.headline)
                    .monospace()
                    .size(12.5)
                    .color(p.text_strong),
            );
            ui.add_space(4.0);
            ui.label(RichText::new(d.summary()).color(p.text));
            if !d.dependents.is_empty() {
                ui.add_space(4.0);
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .show(ui, |ui| {
                        for dep in &d.dependents {
                            ui.horizontal(|ui| {
                                if dep.by_agent {
                                    chip(ui, &dep.who, s.info);
                                } else {
                                    chip(ui, "you", p.accent);
                                }
                                ui.label(RichText::new(&dep.description).monospace().size(12.0));
                            });
                        }
                    });
            }
            if let Some(note) = d.stale_note() {
                ui.add_space(4.0);
                ui.label(RichText::new(note).size(12.0).color(p.text_dim));
            }
            if let Some(e) = &d.error {
                ui.add_space(4.0);
                ui.label(RichText::new(e).color(s.warning));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_enabled_ui(!d.running, |ui| {
                    if style::primary_button(ui, d.confirm_label())
                        .on_hover_text("Go ahead with the undo")
                        .clicked()
                    {
                        confirm = true;
                    }
                    if ui
                        .button("Cancel")
                        .on_hover_text("Close this window without changing anything")
                        .clicked()
                    {
                        cancel = true;
                    }
                });
                if d.running {
                    ui.spinner();
                }
            });
        });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        cancel = true;
    }
    if cancel {
        vm.cancel_undo();
    } else if confirm {
        vm.confirm_undo();
    }
}

//! The Bookmarks tab: addresses you or an agent marked, with notes. Click one to go there.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;

use super::PanelState;
use super::strings::one_line;
use crate::style::{self, chip, empty_state, pal};

pub fn show(ui: &mut Ui, vm: &mut ViewModel, _st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_bookmarks();
    let here = vm.cursor_address();
    ui.horizontal(|ui| {
        let r = ui
            .add_enabled(
                here.is_some(),
                egui::Button::new("Bookmark this address  (Ctrl+D)"),
            )
            .on_hover_text("Mark the address you are looking at, with a note")
            .on_disabled_hover_text("Pick a function or an address first");
        if r.clicked()
            && let Some(a) = here
        {
            vm.begin_bookmark(a);
        }
        if ui
            .button("Refresh")
            .on_hover_text("Reload the bookmarks, including ones an agent just added")
            .clicked()
        {
            vm.refresh_bookmarks();
        }
        if vm.tools.bookmarks.loading {
            ui.spinner();
        }
    });
    let b = &vm.tools.bookmarks;
    if let Some(e) = &b.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    if b.items.is_empty() {
        if b.loaded {
            empty_state(
                ui,
                "No bookmarks yet",
                "Bookmark places you want to come back to. Agents can bookmark places for you to look at too.",
                Some("Press Ctrl+D, or right-click and choose Add bookmark."),
            );
        }
        return;
    }
    let mut go = None;
    let mut remove = None;
    let mut edit = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for it in &b.items {
                ui.horizontal(|ui| {
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
                        .on_hover_text("Go to this address");
                    if addr.clicked() {
                        go = Some(it.address);
                    }
                    if let Some(f) = vm.functions.find(it.address) {
                        ui.label(RichText::new(&f.name).monospace().size(12.0));
                    }
                    let note = if it.note.is_empty() {
                        RichText::new("(no note)").italics().color(p.text_dim)
                    } else {
                        RichText::new(one_line(&it.note, 120)).color(p.text)
                    };
                    if ui
                        .add(egui::Label::new(note).sense(egui::Sense::click()))
                        .on_hover_text("Click to go there")
                        .clicked()
                    {
                        go = Some(it.address);
                    }
                    if it.by_agent {
                        chip(ui, &it.who, s.info).on_hover_text("An agent set this bookmark");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button("Delete")
                            .on_hover_text("Remove this bookmark. The program is not changed")
                            .clicked()
                        {
                            remove = Some(it.address);
                        }
                        if ui
                            .small_button("Edit note")
                            .on_hover_text("Change the note of this bookmark")
                            .clicked()
                        {
                            edit = Some(it.address);
                        }
                    });
                });
            }
        });
    if b.next_cursor.is_some() && !b.loading {
        vm.more_bookmarks();
    }
    if let Some(a) = go {
        vm.goto(a);
    }
    if let Some(a) = remove {
        vm.remove_bookmark(a);
    }
    if let Some(a) = edit {
        vm.begin_bookmark(a);
    }
}

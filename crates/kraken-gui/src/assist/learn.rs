//! Learn mode: a top-bar switch, panel explanations and glossary hovers.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::assist::panel_help;

use crate::style::{medium, pal};

/// The Learn mode switch and the Assistant shortcut, for the right end of the top bar.
pub fn top_bar_buttons(ui: &mut Ui, vm: &mut ViewModel) {
    let on = vm.assist.learn_mode;
    if ui
        .selectable_label(on, if on { "Learn mode: on" } else { "Learn mode" })
        .on_hover_text(
            "When on, hover panel tabs, assembly instructions and technical terms for a plain-language explanation.",
        )
        .clicked()
    {
        vm.assist.learn_mode = !on;
    }
    if ui
        .button("Assistant")
        .on_hover_text("Open the AI assistant and ask questions about this program")
        .clicked()
    {
        vm.assist.show_requested = true;
    }
}

/// Lists glossary terms with their one-sentence meaning.
pub fn term_list(ui: &mut Ui, vm: &ViewModel, terms: &[&str]) {
    let p = pal(ui);
    for t in terms {
        let Some(e) = vm.assist.term(t) else {
            continue;
        };
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            ui.label(medium(&e.term, 12.5).color(p.accent));
            ui.label(RichText::new(&e.short).size(12.0).color(p.text_dim));
        });
    }
}

/// The hover text of a panel's tab: its one-line purpose, and in learn mode what it is for and
/// the terms it uses.
pub fn tab_tooltip(ui: &mut Ui, vm: &ViewModel, title: &str, purpose: &str) {
    let p = pal(ui);
    ui.set_max_width(360.0);
    ui.label(RichText::new(purpose).color(p.text));
    if !vm.assist.learn_mode {
        return;
    }
    if let Some(h) = panel_help(title) {
        ui.add_space(4.0);
        ui.separator();
        ui.label(RichText::new(h.text).size(12.5).color(p.text));
        term_list(ui, vm, h.terms);
    }
}

/// Adds the glossary hover to `resp` when learn mode is on and `mnemonic` is a known
/// instruction of the open program's architecture.
#[allow(dead_code)] // a hook for the listing and graph panels
pub fn mnemonic_hover(resp: egui::Response, vm: &ViewModel, mnemonic: &str) -> egui::Response {
    if !vm.assist.learn_mode {
        return resp;
    }
    let Some(arch) = vm.project.as_ref().map(|p| p.arch.clone()) else {
        return resp;
    };
    let Some(e) = vm.assist.mnemonic(&arch, mnemonic) else {
        return resp;
    };
    resp.on_hover_ui(|ui| {
        let p = pal(ui);
        ui.set_max_width(340.0);
        ui.label(medium(&e.term, 13.0).color(p.accent));
        ui.label(RichText::new(&e.short).color(p.text));
        if let Some(n) = &e.note {
            ui.label(RichText::new(n).size(12.0).color(p.text_dim));
        }
    })
}

/// Adds the glossary hover for an RE `term` to `resp` when learn mode is on.
#[allow(dead_code)] // a hook for panels that show technical terms
pub fn term_hover(resp: egui::Response, vm: &ViewModel, term: &str) -> egui::Response {
    if !vm.assist.learn_mode {
        return resp;
    }
    let Some(e) = vm.assist.term(term) else {
        return resp;
    };
    resp.on_hover_ui(|ui| {
        let p = pal(ui);
        ui.set_max_width(340.0);
        ui.label(medium(&e.term, 13.0).color(p.accent));
        ui.label(RichText::new(&e.short).color(p.text));
        if let Some(n) = &e.note {
            ui.label(RichText::new(n).size(12.0).color(p.text_dim));
        }
    })
}

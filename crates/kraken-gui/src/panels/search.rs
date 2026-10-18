//! The Search tab: names, strings, byte patterns and instruction text across the program.
//! Click a result to go there.

use egui::{Id, Key, RichText, Ui};
use kraken_gui_widgets::VirtualList;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::SearchKind;

use super::PanelState;
use super::strings::one_line;
use crate::style::{self, chip, empty_state, pal};

/// The id of the search box, so Ctrl+Shift+F can focus it.
pub fn input_id() -> Id {
    Id::new("kraken_search_input")
}

#[derive(Default)]
pub struct SearchUi {
    selected: Option<usize>,
}

fn kind_word(kind: &str) -> &str {
    match kind {
        "function" => "function",
        "import" => "import",
        "export" => "export",
        "string" => "string",
        "bytes" => "bytes",
        "instruction" => "code",
        other => other,
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let mut run = false;
    let mut kind = vm.tools.search.kind;
    ui.horizontal(|ui| {
        for k in SearchKind::ALL {
            ui.selectable_value(&mut kind, k, k.label())
                .on_hover_text(k.help());
        }
    });
    if kind != vm.tools.search.kind {
        vm.set_search_kind(kind);
    }
    ui.horizontal(|ui| {
        let mut query = vm.tools.search.query.clone();
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut query)
                    .id(input_id())
                    .hint_text(vm.tools.search.kind.hint())
                    .desired_width((ui.available_width() - 150.0).max(80.0)),
            )
            .on_hover_text("What to look for. Press Enter to search");
        if std::mem::take(&mut vm.tools.search.focus_requested) {
            r.request_focus();
        }
        if r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
            run = true;
        }
        if query != vm.tools.search.query {
            vm.tools.search.query = query;
        }
        let empty = vm.tools.search.query.trim().is_empty();
        if ui
            .add_enabled(!empty, egui::Button::new("Search"))
            .on_hover_text("Search the whole program (Enter)")
            .on_disabled_hover_text("Type what to look for first")
            .clicked()
        {
            run = true;
        }
        if vm.tools.search.loading {
            ui.spinner();
            if ui
                .button("Stop")
                .on_hover_text("Stop searching; what was found so far stays")
                .clicked()
            {
                vm.stop_search();
            }
        }
    });
    if run {
        st.search.selected = None;
        vm.run_search();
    }

    let sp = &vm.tools.search;
    if let Some(e) = &sp.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    let n = sp.hits.len();
    if sp.searched {
        let more = if sp.has_more() { "+" } else { "" };
        let text = if sp.loading {
            format!("Searching... {n} found so far")
        } else {
            format!("{n}{more} result{}", if n == 1 { "" } else { "s" })
        };
        let further = sp.has_more() && !sp.loading;
        let mut more_clicked = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new(text).size(11.5).color(p.text_dim));
            if further {
                more_clicked = ui
                    .small_button("Search further")
                    .on_hover_text("Each search covers part of the program at a time. This looks through the next part.")
                    .clicked();
            }
        });
        if more_clicked {
            vm.search_more();
        }
    }
    let sp = &vm.tools.search;
    if n == 0 {
        if !sp.searched {
            empty_state(
                ui,
                "Search the program",
                "Pick what to look through, type, and press Enter. Results link to where they are.",
                Some("Tip: Ctrl+Shift+F brings you here from anywhere."),
            );
        } else if !sp.loading && sp.error.is_none() {
            let hint = if sp.has_more() {
                "Nothing yet in the part searched so far. Press Search further to keep looking."
            } else {
                "Nothing matched. Check the spelling, or try another kind of search."
            };
            empty_state(ui, "No results", hint, None);
        }
        return;
    }

    let mut selected = st.search.selected.filter(|i| *i < n);
    let hits = &sp.hits;
    let resp = VirtualList::new("search_hits", n, 22.0).show(ui, &mut selected, |ui, i, sel| {
        let h = &hits[i];
        ui.add(
            egui::Label::new(
                RichText::new(format!("{:08x}", h.address))
                    .monospace()
                    .size(12.0)
                    .color(p.address),
            )
            .selectable(false),
        );
        chip(ui, kind_word(&h.kind), p.text_dim);
        let color = if sel { p.text_strong } else { p.text };
        let r = ui.add(
            egui::Label::new(
                RichText::new(one_line(&h.text, 120))
                    .monospace()
                    .size(12.5)
                    .color(color),
            )
            .selectable(false),
        );
        let mut tip = String::from("Click to go there");
        if let Some(f) = &h.function_name {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("in {f}"))
                        .size(11.5)
                        .color(p.text_dim),
                )
                .selectable(false),
            );
            tip = format!("In {f}. Click to go there");
        }
        if let Some(c) = &h.context {
            ui.add(
                egui::Label::new(RichText::new(one_line(c, 60)).size(11.5).color(p.text_dim))
                    .selectable(false),
            );
        }
        super::remember_rect(ui.ctx(), ("search_row", i), r.rect);
        r.on_hover_text(tip);
    });
    st.search.selected = selected;
    if let Some(i) = resp.clicked.or(resp.changed.then_some(selected).flatten()) {
        vm.open_search_hit(i);
    }
    if let Some(i) = selected {
        st.hot = vm.tools.search.hits.get(i).map(|h| h.address);
    }
}

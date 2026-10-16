//! The Imports and Exports tab: what the program borrows from libraries and what it offers.

use egui::{RichText, Ui};
use kraken_gui_widgets::VirtualList;
use kraken_proto::SymbolKind;
use kraken_viewmodel::{SymbolTable, ViewModel};

use super::PanelState;
use crate::style::{self, chip, empty_state, pal};

pub struct SymbolsUi {
    pub table: SymbolTable,
    pub filter: String,
    selected: Option<usize>,
}

impl Default for SymbolsUi {
    fn default() -> Self {
        SymbolsUi {
            table: SymbolTable::Imports,
            filter: String::new(),
            selected: None,
        }
    }
}

fn plain(table: SymbolTable) -> (&'static str, &'static str) {
    match table {
        SymbolTable::Imports => (
            "Imports",
            "Functions and data this program borrows from other libraries.",
        ),
        SymbolTable::Exports => (
            "Exports",
            "Functions and data this program makes available, including its entry points.",
        ),
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let table = st.symbols.table;
    vm.ensure_symbols(table);

    ui.horizontal(|ui| {
        for t in [SymbolTable::Imports, SymbolTable::Exports] {
            let (name, tip) = plain(t);
            let list = match t {
                SymbolTable::Imports => &vm.views.imports,
                SymbolTable::Exports => &vm.views.exports,
            };
            let label = if list.loaded {
                format!("{name} ({})", list.items.len())
            } else {
                name.to_string()
            };
            if ui
                .selectable_label(st.symbols.table == t, label)
                .on_hover_text(tip)
                .clicked()
            {
                st.symbols.table = t;
                st.symbols.selected = None;
                vm.set_symbols_filter(t, st.symbols.filter.clone());
            }
        }
        let edit = egui::TextEdit::singleline(&mut st.symbols.filter)
            .hint_text("Filter by name or library")
            .desired_width(f32::INFINITY);
        if ui.add(edit).changed() {
            vm.set_symbols_filter(table, st.symbols.filter.clone());
        }
    });
    let table = st.symbols.table;
    ui.label(RichText::new(plain(table).1).size(11.5).color(p.text_dim));

    let list = match table {
        SymbolTable::Imports => &vm.views.imports,
        SymbolTable::Exports => &vm.views.exports,
    };
    if let Some(err) = list.error.clone() {
        ui.label(RichText::new(err).color(s.danger));
        if ui.button("Try again").clicked() {
            vm.retry_symbols(table);
        }
        return;
    }
    if !list.loaded {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Loading...").color(p.text_dim));
        });
        return;
    }
    let visible = list.visible();
    if visible.is_empty() {
        let (title, body) = if list.filter.is_empty() {
            (
                "Nothing listed",
                "This program has none, for example because it is statically linked.",
            )
        } else if list.has_more() {
            (
                "Still searching",
                "Loading the rest of the list to check it.",
            )
        } else {
            (
                "No matches",
                "Nothing matches the filter. Clear it to see everything.",
            )
        };
        empty_state(ui, title, body, None);
        return;
    }
    let n = visible.len();
    let mut selected = st
        .symbols
        .selected
        .and_then(|row| visible.iter().position(|v| *v == row));
    let mut max_seen = 0usize;
    let items = &list.items;
    let vis = &visible;
    let resp = VirtualList::new(("symbols", table as u8), n, 22.0).show(
        ui,
        &mut selected,
        |ui, i, sel| {
            max_seen = max_seen.max(i);
            let it = &items[vis[i]];
            let addr = it
                .address
                .map_or_else(|| "        ".to_string(), |a| format!("{a:08x}"));
            ui.label(RichText::new(addr).monospace().size(12.0).color(p.address));
            let color = if sel { p.text_strong } else { p.text };
            ui.label(RichText::new(&it.name).monospace().size(12.5).color(color))
                .on_hover_text("Double-click to see what uses this");
            if let Some(l) = &it.library {
                chip(ui, l, p.text_dim);
            }
            if it.kind == SymbolKind::Data {
                chip(ui, "data", p.text_dim);
            }
        },
    );
    let row_of = |i: usize| visible.get(i).copied();
    st.symbols.selected = selected.and_then(row_of);
    let (clicked, last) = (resp.double_clicked.and_then(row_of), max_seen);
    vm.symbols_scrolled(table, last + 1);
    if let Some(row) = clicked {
        vm.open_symbol(table, row);
    }
    if let Some(row) = st.symbols.selected {
        st.hot = match table {
            SymbolTable::Imports => vm.views.imports.items.get(row),
            SymbolTable::Exports => vm.views.exports.items.get(row),
        }
        .and_then(|s| s.address);
    }
}

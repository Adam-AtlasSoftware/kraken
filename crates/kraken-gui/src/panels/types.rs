//! The Types tab: structs, unions, enums, typedefs and prototypes of the program (from its debug
//! info and KRAKEN's libc and Windows tables). Pick one to read its C declaration.

use egui::{RichText, Ui};
use kraken_gui_widgets::VirtualList;
use kraken_viewmodel::ViewModel;

use super::PanelState;
use crate::style::{self, chip, empty_state, pal};

const KINDS: [(&str, &str); 6] = [
    ("", "All kinds"),
    ("struct", "Structs"),
    ("union", "Unions"),
    ("enum", "Enums"),
    ("typedef", "Typedefs"),
    ("function", "Prototypes"),
];

#[derive(Default)]
pub struct TypesUi {
    pub filter: String,
    selected: Option<usize>,
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_types();

    ui.horizontal(|ui| {
        let edit = egui::TextEdit::singleline(&mut st.types.filter)
            .hint_text("Filter types")
            .desired_width(180.0);
        if ui
            .add(edit)
            .on_hover_text("Type part of a type name to narrow the list")
            .changed()
        {
            vm.set_types_filter(st.types.filter.clone());
        }
        let current = vm.tools.types.kind.clone();
        let label = KINDS
            .iter()
            .find(|(k, _)| *k == current)
            .map_or("All kinds", |(_, l)| *l);
        egui::ComboBox::from_id_salt("types_kind")
            .selected_text(label)
            .show_ui(ui, |ui| {
                for (k, l) in KINDS {
                    if ui
                        .selectable_label(current == k, l)
                        .on_hover_text("Show only this kind of type")
                        .clicked()
                    {
                        vm.set_types_kind(k);
                    }
                }
            })
            .response
            .on_hover_text("Show only one kind of type");
        let mut deps = vm.tools.types.dependencies;
        if ui
            .checkbox(&mut deps, "With the types it uses")
            .on_hover_text("Print the types a declaration uses before it, so the text stands alone")
            .changed()
        {
            vm.set_types_dependencies(deps);
        }
        if vm.tools.types.loading {
            ui.spinner();
        }
    });
    let t = &vm.tools.types;
    let n = t.items.len();
    let summary = if t.loading && n == 0 {
        "Loading...".to_string()
    } else {
        format!(
            "{n}{} type{}",
            if t.has_more() { "+" } else { "" },
            if n == 1 { "" } else { "s" }
        )
    };
    ui.label(RichText::new(summary).size(11.5).color(p.text_dim));

    if let Some(err) = t.error.clone() {
        ui.label(RichText::new(err).color(s.danger));
        if ui
            .button("Try again")
            .on_hover_text("Ask for the types again")
            .clicked()
        {
            vm.retry_types();
        }
        return;
    }
    if n == 0 {
        if !t.loaded {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Reading types...").color(p.text_dim));
            });
        } else if !t.filter.is_empty() || !t.kind.is_empty() {
            empty_state(
                ui,
                "No matches",
                "No type fits the filter.",
                Some("Clear the filter to see every type."),
            );
        } else {
            empty_state(
                ui,
                "No types found",
                "This program has no debug information that names types, and none were added.",
                Some("Programs built with debug info (DWARF or a PDB) list their types here."),
            );
        }
        return;
    }

    let mut picked: Option<String> = None;
    let mut max_seen = 0usize;
    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        let mut selected = st.types.selected.filter(|i| *i < n);
        let items = &vm.tools.types.items;
        let resp = VirtualList::new("types", n, 22.0).show(ui, &mut selected, |ui, i, sel| {
            max_seen = max_seen.max(i);
            let it = &items[i];
            let color = if sel { p.text_strong } else { p.text };
            ui.label(RichText::new(&it.name).monospace().size(12.5).color(color))
                .on_hover_text(&it.detail);
            chip(ui, &it.kind, p.text_dim);
            if let Some(size) = it.size {
                ui.label(
                    RichText::new(format!("{size} bytes"))
                        .size(11.5)
                        .color(p.text_dim),
                );
            }
        });
        st.types.selected = selected;
        if resp.changed
            && let Some(i) = selected
        {
            picked = items.get(i).map(|it| it.name.clone());
        }

        let ui = &mut cols[1];
        let t = &vm.tools.types;
        if let Some(e) = &t.decl_error {
            ui.label(RichText::new(e).color(s.danger));
        } else if let Some(d) = &t.decl {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&d.name).strong().color(p.text_strong));
                if ui
                    .small_button("Copy")
                    .on_hover_text("Copy the C declaration")
                    .clicked()
                {
                    ui.ctx().copy_text(d.c.clone());
                }
                if t.decl_loading {
                    ui.spinner();
                }
            });
            if !d.undefined.is_empty() {
                ui.label(
                    RichText::new(format!("Not defined here: {}", d.undefined.join(", ")))
                        .size(11.5)
                        .color(p.text_dim),
                );
            }
            egui::ScrollArea::both()
                .id_salt("type_decl")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let mut text = d.c.as_str();
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text("The C declaration. Select text to copy it");
                });
        } else if t.decl_loading {
            ui.spinner();
        } else {
            ui.label(RichText::new("Pick a type to read its declaration.").color(p.text_dim));
        }
    });
    vm.types_scrolled(max_seen + 1);
    if let Some(name) = picked {
        vm.select_type(&name);
    }
}

//! The Types tab: structs, unions, enums, typedefs and prototypes of the program (from its debug
//! info and KRAKEN's libc and Windows tables). Pick one to read its C declaration.

use egui::{Align2, Id, RichText, Ui, vec2};
use kraken_gui_widgets::VirtualList;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{FieldRow, TypeDecl};

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
    /// Field rows the edit boxes below were last filled from.
    base: Vec<FieldRow>,
    base_name: String,
    names: Vec<String>,
    types: Vec<String>,
}

/// Fills the field edit boxes from the declaration when it changed under them.
fn sync_fields(st: &mut TypesUi, d: &TypeDecl) {
    if st.base_name != d.name || st.base != d.fields {
        st.base_name = d.name.clone();
        st.base = d.fields.clone();
        st.names = d.fields.iter().map(|f| f.name.clone()).collect();
        st.types = d.fields.iter().map(|f| f.ty.clone()).collect();
    }
}

fn define_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(mut d) = vm.tools.types.define.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let (enter, esc) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter),
            i.consume_key(egui::Modifiers::NONE, egui::Key::Escape),
        )
    });
    let (mut go, mut cancel) = (enter, esc);
    egui::Window::new(RichText::new("New type").size(15.0).strong())
        .id(Id::new("kraken_type_define_dialog"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .fixed_size(vec2(520.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(
                    "Type C declarations: struct, union, enum or typedef. Fields are laid out                      for this program's architecture.",
                )
                .color(p.text_dim),
            );
            ui.add(
                egui::TextEdit::multiline(&mut d.text)
                    .id(Id::new("kraken_type_define_text"))
                    .desired_rows(10)
                    .code_editor()
                    .desired_width(f32::INFINITY),
            )
            .on_hover_text("C declarations. Ctrl+Enter defines them, Esc closes this window");
            if let Some(e) = &d.error {
                ui.label(RichText::new(e).color(s.danger));
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!d.busy, egui::Button::new("Define"))
                    .on_hover_text("Define the types. You can undo it from the History tab")
                    .on_disabled_hover_text("Waiting for the types to be defined")
                    .clicked()
                {
                    go = true;
                }
                if ui
                    .button("Cancel")
                    .on_hover_text("Close without defining anything")
                    .clicked()
                {
                    cancel = true;
                }
                if d.busy {
                    ui.spinner();
                }
            });
        });
    if cancel {
        vm.close_type_define();
        return;
    }
    if let Some(live) = vm.tools.types.define.as_mut() {
        live.text = d.text;
    }
    if go {
        vm.submit_type_define();
    }
}

fn apply_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(mut d) = vm.tools.types.apply.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let (enter, esc) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::NONE, egui::Key::Enter),
            i.consume_key(egui::Modifiers::NONE, egui::Key::Escape),
        )
    });
    let (mut go, mut cancel) = (enter, esc);
    egui::Window::new(RichText::new("Apply to address").size(15.0).strong())
        .id(Id::new("kraken_type_apply_dialog"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .fixed_size(vec2(380.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(format!(
                    "Give the data at an address the type {}.",
                    d.type_name
                ))
                .color(p.text_dim),
            );
            let r = ui
                .add(
                    egui::TextEdit::singleline(&mut d.address)
                        .id(Id::new("kraken_type_apply_address"))
                        .hint_text("0x404040")
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                )
                .on_hover_text("The address of the data, such as 0x404040");
            if !r.has_focus() && d.error.is_none() && d.address.is_empty() {
                r.request_focus();
            }
            if let Some(e) = &d.error {
                ui.label(RichText::new(e).color(s.danger));
            }
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!d.busy, egui::Button::new("Apply"))
                    .on_hover_text("Set the type at this address. You can undo it from History")
                    .on_disabled_hover_text("Waiting for the type to be applied")
                    .clicked()
                {
                    go = true;
                }
                if ui
                    .button("Cancel")
                    .on_hover_text("Close without changing anything")
                    .clicked()
                {
                    cancel = true;
                }
                if d.busy {
                    ui.spinner();
                }
            });
        });
    if cancel {
        vm.close_type_apply();
        return;
    }
    if let Some(live) = vm.tools.types.apply.as_mut() {
        live.address = d.address;
    }
    if go {
        vm.submit_type_apply();
    }
}

#[derive(Default)]
struct TypeActions {
    apply: Option<String>,
    delete: Option<String>,
    edit: Option<(String, String, Option<String>, Option<String>)>,
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_types();
    define_dialog(ui.ctx(), vm);
    apply_dialog(ui.ctx(), vm);

    ui.horizontal(|ui| {
        if ui
            .button("New type...")
            .on_hover_text("Define a struct, union, enum or typedef by typing C")
            .clicked()
        {
            vm.open_type_define();
        }
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
    if let Some(note) = &t.notice {
        ui.label(RichText::new(note).size(11.5).color(s.success));
    }

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
    let mut actions = TypeActions::default();
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
                if ui
                    .small_button("Apply to address...")
                    .on_hover_text("Give the data at an address this type")
                    .clicked()
                {
                    actions.apply = Some(d.name.clone());
                }
                if ui
                    .small_button("Delete")
                    .on_hover_text("Remove this type. You can undo it from the History tab")
                    .clicked()
                {
                    actions.delete = Some(d.name.clone());
                }
                if t.decl_loading {
                    ui.spinner();
                }
            });
            if let Some(e) = &t.edit_error {
                ui.label(RichText::new(e).color(s.danger));
            }
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
                    if !d.fields.is_empty() {
                        ui.add_space(6.0);
                        ui.label(RichText::new("Fields").strong().color(p.text_strong));
                        sync_fields(&mut st.types, d);
                        egui::Grid::new("type_fields")
                            .num_columns(3)
                            .spacing([8.0, 4.0])
                            .show(ui, |ui| {
                                for i in 0..d.fields.len() {
                                    ui.label(
                                        RichText::new(format!("+{:#x}", d.fields[i].offset))
                                            .monospace()
                                            .size(11.5)
                                            .color(p.text_dim),
                                    );
                                    let name = ui
                                        .add(
                                            egui::TextEdit::singleline(&mut st.types.names[i])
                                                .font(egui::TextStyle::Monospace)
                                                .desired_width(130.0),
                                        )
                                        .on_hover_text("Field name. Press Enter to rename it");
                                    let ty = ui
                                        .add(
                                            egui::TextEdit::singleline(&mut st.types.types[i])
                                                .font(egui::TextStyle::Monospace)
                                                .desired_width(180.0),
                                        )
                                        .on_hover_text(
                                            "Field type as C, such as int or char *. Press Enter to change it; later fields move",
                                        );
                                    if name.lost_focus() || ty.lost_focus() {
                                        let n = &st.types.names[i];
                                        let t = &st.types.types[i];
                                        let new_name = (*n != d.fields[i].name && !n.is_empty())
                                            .then(|| n.clone());
                                        let new_type = (*t != d.fields[i].ty && !t.is_empty())
                                            .then(|| t.clone());
                                        if new_name.is_some() || new_type.is_some() {
                                            actions.edit = Some((
                                                d.name.clone(),
                                                d.fields[i].name.clone(),
                                                new_name,
                                                new_type,
                                            ));
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    }
                });
        } else if t.decl_loading {
            ui.spinner();
        } else {
            ui.label(RichText::new("Pick a type to read its declaration.").color(p.text_dim));
        }
    });
    vm.types_scrolled(max_seen + 1);
    if let Some(name) = actions.apply {
        vm.open_type_apply(&name);
    }
    if let Some(name) = actions.delete {
        vm.delete_type(&name);
    }
    if let Some((ty, field, new_name, new_type)) = actions.edit {
        vm.edit_type_field(&ty, &field, new_name, new_type);
    }
    if let Some(name) = picked {
        vm.select_type(&name);
    }
}

//! The model choice of Settings > AI: a drop-down of the models known for the choice, shown by
//! name, and a switch that swaps it for a text box. Without a known list the drop-down is off and
//! the text box is the only way.

use egui::{RichText, Ui};

use crate::style::{pal, toggle_switch};

/// Whether the person types the model's name. Starts on by itself for a saved name the list does
/// not hold.
#[derive(Debug, Clone, Default)]
pub struct ModelTyping {
    /// What the state belongs to; another choice decides it anew.
    key: String,
    on: bool,
}

impl ModelTyping {
    /// Decides anew the next time the field is drawn.
    pub fn reset(&mut self) {
        self.key.clear();
    }

    fn sync(&mut self, key: &str, known: &[String], model: &str) {
        if self.key != key {
            self.key = key.to_string();
            let name = model.trim();
            self.on = !name.is_empty() && !known.iter().any(|m| m == name);
        }
    }
}

/// How the field presents a choice.
pub struct ModelField<'a> {
    /// `egui` id of the drop-down.
    pub salt: &'a str,
    /// What the typing state belongs to, such as the provider kind and address.
    pub key: &'a str,
    /// The model ids to offer; empty when they are not known.
    pub known: &'a [String],
    /// The entry that leaves the model empty, when that is allowed.
    pub empty: Option<&'a str>,
    /// Grey text of the text box.
    pub hint: &'a str,
}

fn shown(id: &str) -> String {
    kraken_agent::model_name(id).map_or_else(|| id.to_string(), str::to_string)
}

/// Draws the drop-down and the switch, with the text box under them while typing.
pub fn model_field(ui: &mut Ui, f: &ModelField<'_>, typing: &mut ModelTyping, model: &mut String) {
    typing.sync(f.key, f.known, model);
    let listed = !f.known.is_empty();
    let type_it = typing.on || !listed;
    let text = if !listed {
        "No model list for this choice".to_string()
    } else if model.trim().is_empty() {
        f.empty.unwrap_or("Pick a model").to_string()
    } else {
        shown(model.trim())
    };
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.add_enabled_ui(listed && !typing.on, |ui| {
                egui::ComboBox::from_id_salt(f.salt)
                    .selected_text(text)
                    .width(280.0)
                    .show_ui(ui, |ui| {
                        if let Some(e) = f.empty
                            && ui
                                .selectable_label(model.trim().is_empty(), e)
                                .on_hover_text("Name no model")
                                .clicked()
                        {
                            model.clear();
                        }
                        for id in f.known {
                            if ui
                                .selectable_label(model == id, shown(id))
                                .on_hover_text(id)
                                .clicked()
                            {
                                model.clone_from(id);
                            }
                        }
                    })
                    .response
                    .on_hover_text("Choose the model")
                    .on_disabled_hover_text(if listed {
                        "Turn off \"Type a name\" to choose from the list"
                    } else {
                        "KRAKEN does not know which models this one offers, so type the name"
                    });
            });
            ui.add_enabled_ui(listed, |ui| {
                let mut on = type_it;
                toggle_switch(ui, &mut on, "Type a name")
                    .on_hover_text("Type any model name instead of choosing from the list")
                    .on_disabled_hover_text("There is no list to choose from here");
                if listed {
                    typing.on = on;
                }
            });
        });
        if typing.on || !listed {
            ui.add(
                egui::TextEdit::singleline(model)
                    .hint_text(f.hint)
                    .desired_width(380.0),
            )
            .on_hover_text("The exact name of the model");
        } else if !model.trim().is_empty() {
            ui.label(
                RichText::new(model.trim())
                    .size(11.0)
                    .color(pal(ui).text_dim),
            );
        }
    });
}

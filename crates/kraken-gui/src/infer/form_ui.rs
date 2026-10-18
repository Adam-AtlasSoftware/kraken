//! Draws a generated settings form: numbers, switches, choices and file paths.

use egui::{RichText, Ui};
use kraken_viewmodel::infer::{FieldKind, SettingsForm};

use crate::style::{self, pal};

const FIELD_WIDTH: f32 = 330.0;

/// Draws every field. Returns the key of the path field whose "Browse..." button was clicked.
pub fn show(ui: &mut Ui, form: &mut SettingsForm) -> Option<String> {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let mut browse = None;
    egui::Grid::new("kraken_infer_form")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            for f in &mut form.fields {
                let label = if f.required {
                    format!("{} *", f.title)
                } else {
                    f.title.clone()
                };
                let l = ui.label(label);
                if let Some(d) = &f.description {
                    l.on_hover_text(d.clone());
                }
                let error = f.error();
                ui.vertical(|ui| {
                    match &f.kind {
                        FieldKind::Bool => {
                            let before = f.flag;
                            ui.checkbox(&mut f.flag, "").on_hover_text(
                                f.description
                                    .clone()
                                    .unwrap_or_else(|| "Switch this option on or off".into()),
                            );
                            if f.flag != before {
                                f.touched = true;
                            }
                        }
                        FieldKind::Enum(options) => {
                            egui::ComboBox::from_id_salt(("kraken_infer_enum", &f.key))
                                .selected_text(f.text.clone())
                                .width(FIELD_WIDTH)
                                .show_ui(ui, |ui| {
                                    for o in options {
                                        ui.selectable_value(&mut f.text, o.clone(), o)
                                            .on_hover_text(format!("Use {o}"));
                                    }
                                })
                                .response
                                .on_hover_text("Choose one of the allowed values");
                        }
                        FieldKind::Path => {
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut f.text)
                                        .hint_text(if f.required {
                                            "choose a file"
                                        } else {
                                            "automatic"
                                        })
                                        .desired_width(FIELD_WIDTH - 90.0),
                                )
                                .on_hover_text("The path of a file. Type it or use Browse");
                                if ui
                                    .button("Browse...")
                                    .on_hover_text("Choose the file in a dialog")
                                    .clicked()
                                {
                                    browse = Some(f.key.clone());
                                }
                            });
                        }
                        FieldKind::Integer { .. } | FieldKind::Number { .. } => {
                            ui.add(
                                egui::TextEdit::singleline(&mut f.text)
                                    .hint_text(match &f.default {
                                        Some(d) => format!("default {d}"),
                                        None => "automatic".to_string(),
                                    })
                                    .desired_width(120.0),
                            )
                            .on_hover_text("A number. Leave it empty to use the default");
                        }
                        FieldKind::Text | FieldKind::Json => {
                            ui.add(
                                egui::TextEdit::singleline(&mut f.text).desired_width(FIELD_WIDTH),
                            )
                            .on_hover_text("Type the value");
                        }
                    }
                    if let Some(e) = &error
                        && !f.text.trim().is_empty()
                    {
                        ui.label(RichText::new(e).size(11.5).color(s.danger));
                    }
                    if let Some(d) = &f.description {
                        ui.add(
                            egui::Label::new(RichText::new(d).size(11.5).color(p.text_dim)).wrap(),
                        );
                    }
                });
                ui.end_row();
            }
        });
    browse
}

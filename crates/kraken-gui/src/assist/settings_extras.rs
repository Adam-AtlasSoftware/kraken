//! Parts of Settings > AI beyond the provider form: the model picker, the thinking effort, the
//! terminal-agent permission rules.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use egui::{RichText, Ui};
use kraken_agent::{Effort, ModelList, ModelSource, ProviderConfig, ThinkingConfig};
use tokio::runtime::Handle;

use crate::style::{medium, pal};

/// State of the extra sections.
#[derive(Default)]
pub struct AiExtras {
    /// The key (`kind|url`) the model list was asked for, the list and the pending answer.
    list_for: String,
    list: Option<ModelList>,
    list_rx: Option<Receiver<ModelList>>,
}

impl AiExtras {
    /// Draws the model picker under the model text box: the provider's models (or the
    /// well-known ones when it cannot be reached) in a drop-down that fills the box. The box
    /// itself stays for a custom name.
    pub fn model_picker(
        &mut self,
        ui: &mut Ui,
        rt: &Handle,
        key: &str,
        cfg: Option<ProviderConfig>,
        keyring: Option<std::sync::Arc<dyn kraken_agent::Keyring>>,
        model: &mut String,
    ) {
        if let Some(rx) = &self.list_rx
            && let Ok(l) = rx.try_recv()
        {
            self.list = Some(l);
            self.list_rx = None;
        }
        if self.list_for != key {
            self.list_for = key.to_string();
            self.list = None;
            self.list_rx = None;
        }
        let p = pal(ui);
        ui.horizontal(|ui| {
            let loading = self.list_rx.is_some();
            let text = if loading {
                "Looking up models..."
            } else {
                "Pick a model"
            };
            ui.add_enabled_ui(self.list.is_some(), |ui| {
                egui::ComboBox::from_id_salt("kraken_model_picker")
                    .selected_text(text)
                    .width(240.0)
                    .show_ui(ui, |ui| {
                        if let Some(l) = &self.list {
                            for id in &l.ids {
                                if ui
                                    .selectable_label(model == id, id)
                                    .on_hover_text("Use this model")
                                    .clicked()
                                {
                                    *model = id.clone();
                                }
                            }
                        }
                    })
                    .response
                    .on_hover_text(
                        "Models the provider offers, or well-known ones when it cannot be reached. You can also type any model name above",
                    );
            });
            let can = cfg.is_some() && !loading;
            if ui
                .add_enabled(can, egui::Button::new("Look up models").small())
                .on_hover_text("Ask the provider which models it offers")
                .on_disabled_hover_text("Fill in the provider settings first, or wait for the running lookup")
                .clicked()
                && let Some(cfg) = cfg
            {
                let (tx, rx) = channel();
                self.list_rx = Some(rx);
                let ctx = ui.ctx().clone();
                rt.spawn(async move {
                    let list = kraken_agent::model_choices(
                        &cfg,
                        &kraken_agent::LayeredSecrets { keyring },
                    )
                    .await;
                    let _ = tx.send(list);
                    ctx.request_repaint();
                });
            }
            if loading {
                ui.spinner();
            }
            if let Some(l) = &self.list
                && l.source == ModelSource::BuiltIn
                && let Some(n) = &l.note
            {
                ui.label(RichText::new(n).size(11.5).color(p.text_dim));
            }
        });
    }

    /// The thinking effort of the provider `key`.
    pub fn thinking(
        &mut self,
        ui: &mut Ui,
        key: &str,
        config_path: Option<&PathBuf>,
    ) -> Option<String> {
        let current = ThinkingConfig::load(config_path.map(PathBuf::as_path))
            .0
            .get(key)
            .copied();
        let mut error = None;
        ui.horizontal(|ui| {
            ui.label("Thinking effort");
            let label = current.map_or("Provider default", Effort::as_str);
            egui::ComboBox::from_id_salt("kraken_thinking")
                .selected_text(label)
                .show_ui(ui, |ui| {
                    let mut pick: Option<Option<Effort>> = None;
                    if ui
                        .selectable_label(current.is_none(), "Provider default")
                        .on_hover_text("Send no thinking setting; the model decides")
                        .clicked()
                    {
                        pick = Some(None);
                    }
                    for e in Effort::ALL {
                        if ui
                            .selectable_label(current == Some(e), e.as_str())
                            .on_hover_text("Use this thinking effort")
                            .clicked()
                        {
                            pick = Some(Some(e));
                        }
                    }
                    if let (Some(choice), Some(path)) = (pick, config_path)
                        && let Err(e) = kraken_assist::save_thinking(path, key, choice)
                    {
                        error = Some(e);
                    }
                })
                .response
                .on_hover_text(
                    "How hard the model thinks before it answers: off, low, medium or high. Sent as the provider's own setting (a thinking budget, or reasoning effort). Terminal agents get it where they support it. More thinking is slower and costs more",
                );
        });
        error
    }

    /// The `[permissions]` rules of terminal agents, read-only.
    pub fn permissions(&self, ui: &mut Ui, config_path: Option<&PathBuf>) {
        let p = pal(ui);
        let rules = kraken_assist::PermissionRules::load(config_path.map(PathBuf::as_path));
        let list = |v: &[String]| {
            if v.is_empty() {
                "none".to_string()
            } else {
                v.join(", ")
            }
        };
        ui.label(medium("Terminal agent permissions", 13.0).color(p.text_strong));
        ui.label(
            RichText::new(format!(
                "Unlisted tools: {:?}. Always allowed: {}. Always refused: {}. The permission card in the Assistant tab adds to the allowed list ('Always for this tool'); edit [permissions] in config.toml to change the rest. The rewrite pipeline refuses every request.",
                rules.default,
                list(&rules.allow),
                list(&rules.deny),
            ))
            .size(11.5)
            .color(p.text_dim),
        );
    }
}

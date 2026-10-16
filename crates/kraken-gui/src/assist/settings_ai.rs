//! The "AI" section of the Settings window: which model the assistant talks to.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};

use egui::{RichText, Ui};
use kraken_agent::ChatProvider;
use kraken_viewmodel::assist::{
    ProviderBadge, ProviderDraft, ProviderKind, ProviderStore, badge_of, test_connection,
};
use tokio::runtime::Handle;

use crate::style::{self, chip, medium, pal};

/// A change the app should pass on to the assistant.
pub enum Change {
    /// Use this model from now on.
    Use(Arc<dyn ChatProvider>, ProviderBadge),
    /// There is no model any more.
    Clear,
    /// The settings were saved but cannot be used yet.
    Problem(String),
}

/// State of the AI settings form.
pub struct AiSettings {
    draft: ProviderDraft,
    store: ProviderStore,
    loaded: bool,
    configured: bool,
    status: Option<Result<String, String>>,
    test: Option<Receiver<Result<String, String>>>,
    change: Option<Change>,
}

impl Default for AiSettings {
    fn default() -> Self {
        AiSettings {
            draft: ProviderDraft::preset(ProviderKind::Ollama),
            store: ProviderStore::default(),
            loaded: false,
            configured: false,
            status: None,
            test: None,
            change: None,
        }
    }
}

impl AiSettings {
    /// Forget the form so it reloads from the file the next time it is drawn.
    pub fn reset(&mut self) {
        self.loaded = false;
        self.status = None;
        self.test = None;
    }

    /// Starts the form from the standard settings of `kind`.
    pub fn preset(&mut self, kind: ProviderKind) {
        self.draft = ProviderDraft::preset(kind);
        self.loaded = true;
        self.status = None;
    }

    /// The change made since the last call, if any.
    pub fn take_change(&mut self) -> Option<Change> {
        self.change.take()
    }

    /// Passes on a change made elsewhere in Settings (the local-model section) and reloads the
    /// form from the file next time.
    pub(crate) fn push_change(&mut self, change: Change) {
        self.change = Some(change);
        self.reset();
    }

    /// True while a connection test runs.
    pub fn testing(&self) -> bool {
        self.test.is_some()
    }

    fn load(&mut self, config_path: Option<&PathBuf>) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        self.store = ProviderStore::new(config_path.cloned());
        match self.store.load() {
            Ok(Some(cfg)) => {
                self.draft = ProviderDraft::from_config(&cfg);
                self.configured = true;
            }
            Ok(None) => {
                self.draft = ProviderDraft::preset(ProviderKind::Ollama);
                self.configured = false;
            }
            Err(e) => {
                self.configured = false;
                self.status = Some(Err(format!("The saved AI settings could not be read: {e}")));
            }
        }
    }

    fn drain(&mut self) {
        if let Some(rx) = &self.test
            && let Ok(r) = rx.try_recv()
        {
            self.status = Some(r);
            self.test = None;
        }
    }

    /// Saves the form to `config_path` and starts using it.
    pub(crate) fn save(&mut self, config_path: Option<&PathBuf>) {
        self.store = ProviderStore::new(config_path.cloned());
        match self.store.save(&self.draft) {
            Ok(out) => {
                let mut msg = String::from("Saved.");
                for n in &out.notes {
                    msg.push(' ');
                    msg.push_str(n);
                }
                self.configured = true;
                self.draft = ProviderDraft::from_config(&out.config);
                match self.store.build(&out.config) {
                    Ok(p) => {
                        self.change = Some(Change::Use(p, badge_of(&out.config)));
                        msg.push_str(" The assistant uses it now.");
                        self.status = Some(Ok(msg));
                    }
                    Err(e) => {
                        self.change = Some(Change::Problem(e.clone()));
                        self.status = Some(Err(format!("{msg} But it cannot be used yet: {e}")));
                    }
                }
            }
            Err(e) => self.status = Some(Err(e)),
        }
    }

    fn start_test(&mut self, rt: &Handle, ctx: &egui::Context) {
        let provider = match self.store.build_unsaved(&self.draft) {
            Ok(p) => p,
            Err(e) => {
                self.status = Some(Err(e));
                return;
            }
        };
        let (tx, rx) = channel();
        self.test = Some(rx);
        self.status = None;
        let ctx = ctx.clone();
        rt.spawn(async move {
            let r = test_connection(provider).await.map(|t| {
                format!(
                    "Connected. {} answered \"{}\" in {} ms.",
                    t.model, t.reply, t.millis
                )
            });
            let _ = tx.send(r);
            ctx.request_repaint();
        });
    }

    /// Draws the section.
    pub fn show(&mut self, ui: &mut Ui, rt: &Handle, config_path: Option<&PathBuf>) {
        self.load(config_path);
        self.drain();
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("AI assistant", 14.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "The assistant explains code and suggests names using an AI model. Pick where that model runs.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
        ui.add_space(4.0);

        let kind = self.draft.kind;
        egui::Grid::new("kraken_settings_ai")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Provider");
                let mut picked = kind;
                egui::ComboBox::from_id_salt("kraken_ai_kind")
                    .selected_text(kind.label())
                    .width(300.0)
                    .show_ui(ui, |ui| {
                        for k in ProviderKind::ALL {
                            ui.selectable_value(&mut picked, k, k.label());
                        }
                    });
                if picked != kind {
                    self.draft.switch_kind(picked);
                    self.status = None;
                }
                ui.end_row();

                if self.draft.kind.needs_url() {
                    ui.label("Server address");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.draft.base_url)
                            .hint_text("http://localhost:11434/v1")
                            .desired_width(380.0),
                    );
                    ui.end_row();
                }
                ui.label("Model");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.model)
                        .hint_text(match self.draft.kind {
                            ProviderKind::Ollama => "for example qwen3:14b (see `ollama list`)",
                            ProviderKind::LmStudio => "the model id shown in LM Studio",
                            _ => "model name",
                        })
                        .desired_width(380.0),
                );
                ui.end_row();

                let optional = !self.draft.kind.needs_key();
                ui.label(if optional {
                    "API key (optional)"
                } else {
                    "API key"
                });
                let stored = self.draft.uses_secrets_file();
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.draft.key_env)
                                .hint_text(
                                    "name of an environment variable, e.g. ANTHROPIC_API_KEY",
                                )
                                .desired_width(380.0),
                        );
                    });
                    ui.add(
                        egui::TextEdit::singleline(&mut self.draft.key_paste)
                            .password(true)
                            .hint_text(if stored {
                                "a key is stored; paste a new one to replace it"
                            } else {
                                "or paste the key itself"
                            })
                            .desired_width(380.0),
                    );
                });
                ui.end_row();
            });
        ui.add_space(2.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(self.draft.kind.help())
                    .size(12.0)
                    .color(p.text_dim),
            );
            if self.draft.kind.needs_url()
                && !kraken_viewmodel::assist::is_local_url(&self.draft.base_url)
            {
                chip(ui, "not on this computer", s.warning);
            }
        });
        ui.label(
            RichText::new(
                "Keys are never written to config.toml. An environment variable is read when KRAKEN starts. A pasted key goes into a separate file (secrets.toml, next to config.toml) that only you can read.",
            )
            .size(11.5)
            .color(p.text_dim),
        );
        let env = self.draft.key_env.trim();
        if !env.is_empty()
            && env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && std::env::var_os(env).is_none_or(|v| v.is_empty())
            && self.draft.key_paste.is_empty()
        {
            ui.label(
                RichText::new(format!(
                    "{env} is not set in the environment KRAKEN was started from, so the key will not be found until it is."
                ))
                .size(11.5)
                .color(s.warning),
            );
        }
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let can_save = self.store.config_path.is_some() || config_path.is_some();
            ui.add_enabled_ui(can_save, |ui| {
                if style::primary_button(ui, "Save and use").clicked() {
                    self.save(config_path);
                }
            });
            ui.add_enabled_ui(!self.testing(), |ui| {
                if ui
                    .button("Test connection")
                    .on_hover_text("Sends one tiny request to check the address, model and key.")
                    .clicked()
                {
                    self.store = ProviderStore::new(config_path.cloned());
                    self.start_test(rt, ui.ctx());
                }
            });
            ui.add_enabled_ui(self.configured, |ui| {
                if ui
                    .button("Remove")
                    .on_hover_text("Stop using an AI model")
                    .clicked()
                {
                    match self.store.clear() {
                        Ok(()) => {
                            self.configured = false;
                            self.change = Some(Change::Clear);
                            self.status = Some(Ok(
                                "Removed. The assistant is off until you pick a model.".into(),
                            ));
                        }
                        Err(e) => self.status = Some(Err(e)),
                    }
                }
            });
            if self.testing() {
                ui.spinner();
                ui.label(RichText::new("Asking the model...").color(p.text_dim));
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(150));
            }
        });
        match &self.status {
            Some(Ok(t)) => {
                ui.add(egui::Label::new(RichText::new(t).size(12.0).color(s.success)).wrap());
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            None => {}
        }
    }

    /// The form's current choice (for tests).
    #[cfg(test)]
    pub fn draft(&self) -> &ProviderDraft {
        &self.draft
    }

    /// Edits the form (for tests).
    #[cfg(test)]
    #[cfg_attr(not(unix), allow(dead_code))] // its only caller is a Unix-only test
    pub fn draft_mut(&mut self) -> &mut ProviderDraft {
        &mut self.draft
    }
}

//! The "AI" section of the Settings window: what answers the assistant. One picker lists model
//! APIs (local and cloud) and terminal agents (Claude Code, Codex, Gemini CLI) with their
//! availability; either kind works the same way in the Assistant tab and in `kraken explain`.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use egui::{RichText, Ui};
use kraken_viewmodel::agents::{AgentTestState, AgentsHub, Availability};
use kraken_viewmodel::assist::{
    BackendChoice, ProviderBadge, ProviderDraft, ProviderKind, ProviderStore, test_connection,
};
use tokio::runtime::Handle;

use super::agents_ui::{SetupAct, availability_chip, notice_card, setup_card};
use crate::style::{self, chip, medium, pal};

/// A change the app should pass on to the assistant.
pub enum Change {
    /// Use this backend from now on.
    Use(BackendChoice, ProviderBadge),
    /// There is no backend any more.
    Clear,
    /// The settings were saved but cannot be used yet.
    Problem(String),
}

/// What the picker was used for this frame.
enum Pick {
    Api(ProviderKind),
    Agent(String),
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
    hub: Option<AgentsHub>,
    agents_dirty: bool,
    rewrite: super::settings_cost::RewriteForm,
    limits: super::settings_cost::LimitsForm,
    policy_dirty: bool,
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
            hub: None,
            agents_dirty: false,
            rewrite: super::settings_cost::RewriteForm::default(),
            limits: super::settings_cost::LimitsForm::default(),
            policy_dirty: false,
        }
    }
}

impl AiSettings {
    /// Uses `hub` for the terminal agents the picker lists.
    pub fn set_hub(&mut self, hub: AgentsHub) {
        self.hub = Some(hub);
        self.agents_dirty = true;
    }

    /// The terminal agents hub, once there is one.
    pub fn hub_mut(&mut self) -> Option<&mut AgentsHub> {
        self.hub.as_mut()
    }

    /// True once after the rewrite model, the limits or the assistant's model were saved, so
    /// the app can reload the open project's AI settings.
    pub fn take_policy_dirty(&mut self) -> bool {
        std::mem::take(&mut self.policy_dirty)
    }

    /// The rewriting form (for tests).
    #[cfg(test)]
    pub fn rewrite_form(&mut self) -> &mut super::settings_cost::RewriteForm {
        &mut self.rewrite
    }

    /// True once when the agents' configuration or notice changed, so the app can tell the
    /// open project's assistant.
    pub fn take_agents_dirty(&mut self) -> bool {
        std::mem::take(&mut self.agents_dirty)
    }

    /// Takes in what the agents' background tasks reported. Call once per frame.
    pub fn poll(&mut self) {
        if let Some(h) = self.hub.as_mut() {
            h.poll();
        }
    }

    /// The person read the one-time notice (from the settings or from the Assistant tab).
    pub fn acknowledge_agents(&mut self) {
        if let Some(h) = self.hub.as_mut() {
            h.acknowledge();
            self.agents_dirty = true;
        }
    }

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
        self.test.is_some() || self.hub.as_ref().is_some_and(|h| h.test.running())
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
                self.policy_dirty = true;
                self.draft = ProviderDraft::from_config(&out.config);
                match self.store.choice(&out.config) {
                    Ok(choice) => {
                        let mut badge = self.store.badge(&out.config);
                        if self.draft.kind.is_agent()
                            && let Some(row) =
                                self.hub.as_ref().and_then(|h| h.row(&self.draft.agent))
                        {
                            badge.service = row.name.clone();
                        }
                        self.change = Some(Change::Use(choice, badge));
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
        if self.draft.kind.is_agent() {
            self.start_agent_test();
            return;
        }
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

    fn start_agent_test(&mut self) {
        let model = self.draft.model.trim().to_string();
        let args: Vec<String> = self
            .draft
            .agent_args
            .split_whitespace()
            .map(str::to_string)
            .collect();
        self.status = None;
        if let Some(h) = self.hub.as_mut() {
            h.test_agent(
                self.draft.agent.trim(),
                (!model.is_empty()).then_some(model.as_str()),
                &args,
            );
        }
    }

    /// The text on the picker for the current choice.
    fn picked_label(&self) -> String {
        if self.draft.kind.is_agent() {
            self.hub
                .as_ref()
                .and_then(|h| h.row(&self.draft.agent))
                .map_or_else(|| self.draft.agent.clone(), |r| r.name.clone())
        } else {
            self.draft.kind.label().to_string()
        }
    }

    /// Draws the section.
    pub fn show(&mut self, ui: &mut Ui, rt: &Handle, config_path: Option<&PathBuf>) {
        self.load(config_path);
        self.drain();
        if self.hub.is_none() {
            self.hub = Some(AgentsHub::new(rt.clone(), None));
            self.agents_dirty = true;
        }
        if let Some(h) = self.hub.as_mut() {
            h.ensure_loaded();
        }
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("AI assistant", 14.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "The assistant explains code and suggests names. Pick what answers it: an AI model (on your computer or in the cloud) or a terminal agent such as Claude Code. Both work the same way in the Assistant tab.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
        ui.add_space(4.0);

        let mut pick: Option<Pick> = None;
        ui.horizontal(|ui| {
            ui.label("Assistant");
            let combo = egui::ComboBox::from_id_salt("kraken_ai_kind")
                .selected_text(self.picked_label())
                .width(320.0)
                .show_ui(ui, |ui| {
                    ui.label(RichText::new("AI models").size(11.5).color(p.text_dim));
                    for k in ProviderKind::ALL {
                        let on = !self.draft.kind.is_agent() && self.draft.kind == k;
                        if ui
                            .selectable_label(on, k.label())
                            .on_hover_text(k.help())
                            .clicked()
                        {
                            pick = Some(Pick::Api(k));
                        }
                    }
                    ui.separator();
                    ui.label(
                        RichText::new("Terminal agents")
                            .size(11.5)
                            .color(p.text_dim),
                    );
                    if let Some(h) = &self.hub {
                        for row in &h.rows {
                            let on = self.draft.kind.is_agent() && self.draft.agent == row.id;
                            let text =
                                format!("{}  \u{2014}  {}", row.name, row.availability.label());
                            if ui
                                .selectable_label(on, text)
                                .on_hover_text(format!("Use {} as the assistant", row.name))
                                .clicked()
                            {
                                pick = Some(Pick::Agent(row.id.clone()));
                            }
                        }
                        if !h.loaded {
                            ui.label(RichText::new("Looking for agents...").color(p.text_dim));
                        }
                    }
                });
            combo.response.on_hover_text(
                "Choose what answers: an AI service, a local model or a terminal agent",
            );
        });
        match pick {
            Some(Pick::Api(k)) => {
                self.draft.switch_kind(k);
                self.status = None;
            }
            Some(Pick::Agent(id)) if !(self.draft.kind.is_agent() && self.draft.agent == id) => {
                self.draft = ProviderDraft::for_agent(&id);
                self.status = None;
            }
            Some(Pick::Agent(_)) | None => {}
        }
        ui.add_space(2.0);

        if self.draft.kind.is_agent() {
            self.agent_form(ui, &p, &s);
        } else {
            self.api_form(ui, &p, &s);
        }

        ui.add_space(4.0);
        let agent = self.draft.kind.is_agent();
        let agent_ready = agent
            && self.hub.as_ref().is_some_and(|h| {
                h.notice.acknowledged
                    && h.row(&self.draft.agent)
                        .is_some_and(kraken_viewmodel::agents::AgentRow::is_ready)
            });
        ui.horizontal(|ui| {
            let can_save = (self.store.config_path.is_some() || config_path.is_some())
                && (!agent || agent_ready);
            ui.add_enabled_ui(can_save, |ui| {
                if style::primary_button(ui, "Save and use")
.on_hover_text("Save these settings and use this assistant from now on").clicked() {
                    self.save(config_path);
                }
            });
            let can_test = !self.testing() && (!agent || agent_ready);
            ui.add_enabled_ui(can_test, |ui| {
                if ui
                    .button(if agent { "Test agent" } else { "Test connection" })
                    .on_hover_text(if agent {
                        "Starts the agent without KRAKEN's tools and asks it for one word, to check the install and the sign-in."
                    } else {
                        "Sends one tiny request to check the address, model and key."
                    })
                    .clicked()
                {
                    self.store = ProviderStore::new(config_path.cloned());
                    self.start_test(rt, ui.ctx());
                }
            });
            ui.add_enabled_ui(self.configured, |ui| {
                if ui
                    .button("Remove")
                    .on_hover_text("Stop using an AI model or agent")
                    .clicked()
                {
                    match self.store.clear() {
                        Ok(()) => {
                            self.configured = false;
                            self.change = Some(Change::Clear);
                            self.status = Some(Ok(
                                "Removed. The assistant is off until you pick one.".into(),
                            ));
                        }
                        Err(e) => self.status = Some(Err(e)),
                    }
                }
            });
            if self.testing() {
                ui.spinner();
                ui.label(
                    RichText::new(if agent {
                        "Asking the agent..."
                    } else {
                        "Asking the model..."
                    })
                    .color(p.text_dim),
                );
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(150));
            }
        });
        if agent && !agent_ready {
            ui.label(
                RichText::new(
                    "Read the note and set the agent up first; then you can test it and use it.",
                )
                .size(11.5)
                .color(p.text_dim),
            );
        }
        match &self.status {
            Some(Ok(t)) => {
                ui.add(egui::Label::new(RichText::new(t).size(12.0).color(s.success)).wrap());
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            None => {}
        }
        ui.separator();
        if self.rewrite.show(ui, config_path) {
            self.policy_dirty = true;
        }
        ui.separator();
        if self.limits.show(ui, config_path) {
            self.policy_dirty = true;
        }
        if agent && let Some(h) = &self.hub {
            match &h.test {
                AgentTestState::Passed { agent_id, message } if *agent_id == self.draft.agent => {
                    ui.add(
                        egui::Label::new(RichText::new(message).size(12.0).color(s.success)).wrap(),
                    );
                }
                AgentTestState::Failed { agent_id, message } if *agent_id == self.draft.agent => {
                    ui.add(
                        egui::Label::new(RichText::new(message).size(12.0).color(s.danger)).wrap(),
                    );
                }
                _ => {}
            }
        }
    }

    /// The fields of a model API.
    fn api_form(&mut self, ui: &mut Ui, p: &kraken_gui_widgets::Palette, s: &style::Status) {
        egui::Grid::new("kraken_settings_ai")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                if self.draft.kind.needs_url() {
                    ui.label("Server address");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.draft.base_url)
                            .hint_text("http://localhost:11434/v1")
                            .desired_width(380.0),
                    )
                    .on_hover_text("The address of the server that runs the model");
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
                )
                .on_hover_text("The name of the model to ask");
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
                        )
                        .on_hover_text(
                            "KRAKEN reads the key from this environment variable when it starts",
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
                    )
                    .on_hover_text(
                        "Paste the key here. It is saved in a file only you can read, never in the main settings file",
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
    }

    /// The fields of a terminal agent: availability, Set up, the one-time notice, model and
    /// extra arguments.
    fn agent_form(&mut self, ui: &mut Ui, p: &kraken_gui_widgets::Palette, s: &style::Status) {
        let Some(hub) = self.hub.as_mut() else {
            return;
        };
        ui.add(
            egui::Label::new(
                RichText::new(self.draft.kind.help())
                    .size(12.0)
                    .color(p.text_dim),
            )
            .wrap(),
        );
        ui.add_space(4.0);
        if let Some(note) = &hub.platform_note {
            ui.add(egui::Label::new(RichText::new(note).size(12.0).color(s.warning)).wrap());
        }
        if let Some(err) = &hub.catalogue_error {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "Your agents.toml could not be read, so only the built-in agents are listed. {err}"
                    ))
                    .size(12.0)
                    .color(s.warning),
                )
                .wrap(),
            );
        }
        if let Some(err) = &hub.error {
            ui.add(egui::Label::new(RichText::new(err).size(12.0).color(s.danger)).wrap());
        }

        let mut setup_request: Option<String> = None;
        let mut refresh = false;
        match hub.row(&self.draft.agent).cloned() {
            Some(row) => {
                ui.horizontal(|ui| {
                    availability_chip(ui, &row.availability, s);
                    if !row.builtin {
                        chip(ui, "custom", p.text_dim);
                    }
                    if matches!(row.availability, Availability::NeedsSetup { .. })
                        && ui
                            .add_enabled(!hub.setup.running(), egui::Button::new("Set up..."))
                            .on_hover_text("Shows what would be downloaded and asks first")
                            .on_disabled_hover_text("A setup is already running")
                            .clicked()
                    {
                        setup_request = Some(row.id.clone());
                    }
                    if ui
                        .add_enabled(!hub.loading, egui::Button::new("Check again").small())
                        .on_hover_text("Look again at what is installed")
                        .on_disabled_hover_text("Already looking")
                        .clicked()
                    {
                        refresh = true;
                    }
                });
                let detail = match row.availability {
                    Availability::Ready { .. } => format!("Found: {}", row.availability.detail()),
                    _ => row.availability.detail().to_string(),
                };
                ui.add(egui::Label::new(RichText::new(detail).size(12.0).color(p.text)).wrap());
            }
            None if hub.loaded => {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "There is no agent called `{}` (see agents.toml).",
                            self.draft.agent
                        ))
                        .color(s.warning),
                    )
                    .wrap(),
                );
            }
            None => {}
        }
        ui.add_space(4.0);

        match setup_card(ui, p, s, &hub.setup) {
            Some(SetupAct::Confirm) => hub.confirm_setup(),
            Some(SetupAct::Dismiss) => hub.dismiss_setup(),
            None => {}
        }
        if let Some(id) = setup_request {
            hub.request_setup(&id);
        }
        if refresh {
            hub.refresh();
        }

        if !hub.notice.acknowledged {
            if notice_card(ui, p, s, "I understand") {
                hub.acknowledge();
                self.agents_dirty = true;
            }
            ui.add_space(4.0);
        } else if let Some(e) = &hub.notice.save_error {
            ui.add(egui::Label::new(RichText::new(e).size(11.5).color(s.warning)).wrap());
        }

        egui::Grid::new("kraken_settings_agent")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Model (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.model)
                        .hint_text("leave empty to let the agent choose")
                        .desired_width(380.0),
                )
                .on_hover_text(
                    "Ask the agent for this model. Leave it empty for the agent's own choice",
                );
                ui.end_row();
                ui.label("Extra arguments (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.agent_args)
                        .hint_text("passed to the agent as they are, separated by spaces")
                        .desired_width(380.0),
                )
                .on_hover_text("Extra command-line arguments for the agent program");
                ui.end_row();
            });
        ui.label(
            RichText::new(
                "Agents sign in by themselves (for example `claude` or `codex login` in a terminal); KRAKEN never gives them its own settings or keys. The terminal command `kraken agents setup <id>` does the same Set up.",
            )
            .size(11.5)
            .color(p.text_dim),
        );
    }

    /// The terminal agents hub (for tests).
    #[cfg(all(test, unix))]
    pub fn hub(&self) -> Option<&AgentsHub> {
        self.hub.as_ref()
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

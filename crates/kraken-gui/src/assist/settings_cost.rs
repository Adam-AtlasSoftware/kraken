//! Settings > AI, the parts about cost: the model the Rust rewrite uses ("Rewriting", the
//! `[rewrite]` table) and the limits on AI work (`[ai_limits]`).

use std::path::{Path, PathBuf};

use egui::{RichText, Ui};
use kraken_agent::{ProviderConfig, SecretRef};
use kraken_assist::{AiLimits, AiPolicy, load_rewrite_config, save_rewrite_config};
use kraken_proto::money;

use crate::style::{self, medium, pal};

/// What the rewrite's own model is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RewriteKind {
    /// Anthropic's API.
    #[default]
    Anthropic,
    /// OpenAI's API.
    OpenAi,
    /// Google's Gemini API.
    Gemini,
    /// A model server on this computer (Ollama, LM Studio, llama-server).
    Local,
    /// A terminal agent (Claude Code, Codex, Gemini CLI).
    Agent,
}

impl RewriteKind {
    /// Every kind, in the picker's order.
    pub const ALL: [RewriteKind; 5] = [
        RewriteKind::Anthropic,
        RewriteKind::OpenAi,
        RewriteKind::Gemini,
        RewriteKind::Local,
        RewriteKind::Agent,
    ];

    /// The picker's text.
    pub fn label(self) -> &'static str {
        match self {
            RewriteKind::Anthropic => "Anthropic API (cloud)",
            RewriteKind::OpenAi => "OpenAI API (cloud)",
            RewriteKind::Gemini => "Gemini API (cloud)",
            RewriteKind::Local => "Local model (free)",
            RewriteKind::Agent => "Terminal agent (its subscription)",
        }
    }

    fn default_model(self) -> &'static str {
        match self {
            RewriteKind::Anthropic => kraken_agent::provider::anthropic::DEFAULT_MODEL,
            RewriteKind::OpenAi => "gpt-4.1",
            RewriteKind::Gemini => kraken_agent::provider::gemini::DEFAULT_MODEL,
            RewriteKind::Local => "qwen3:14b",
            RewriteKind::Agent => "",
        }
    }

    fn default_key(self) -> &'static str {
        match self {
            RewriteKind::Anthropic => "ANTHROPIC_API_KEY",
            RewriteKind::OpenAi => "OPENAI_API_KEY",
            RewriteKind::Gemini => "GEMINI_API_KEY",
            _ => "",
        }
    }
}

/// The "Rewriting" form.
#[derive(Debug, Clone, Default)]
pub struct RewriteForm {
    /// The rewrite has its own model (`[rewrite]`); off means it uses the assistant's.
    pub own: bool,
    /// Which kind.
    pub kind: RewriteKind,
    /// The model name.
    pub model: String,
    /// The environment variable holding the key (cloud APIs).
    pub key_env: String,
    /// The server address (local model).
    pub base_url: String,
    /// The agent id (terminal agent).
    pub agent: String,
    loaded: bool,
    status: Option<Result<String, String>>,
}

impl RewriteForm {
    /// The form for `cfg` (the `[rewrite]` table), or "use the assistant's model" for `None`.
    pub fn from_config(cfg: Option<&ProviderConfig>) -> Self {
        let mut f = RewriteForm {
            loaded: true,
            ..RewriteForm::default()
        };
        let Some(cfg) = cfg else {
            f.switch(RewriteKind::Anthropic);
            return f;
        };
        f.own = true;
        let env_of = |k: &SecretRef| match k {
            SecretRef::Env(v) => v.clone(),
            SecretRef::Keyring { .. } => String::new(),
        };
        match cfg {
            ProviderConfig::Anthropic { model, api_key, .. } => {
                f.kind = RewriteKind::Anthropic;
                f.model = model.clone().unwrap_or_default();
                f.key_env = env_of(api_key);
            }
            ProviderConfig::Gemini { model, api_key, .. } => {
                f.kind = RewriteKind::Gemini;
                f.model = model.clone().unwrap_or_default();
                f.key_env = env_of(api_key);
            }
            ProviderConfig::OpenaiCompatible {
                base_url,
                model,
                api_key,
                ..
            } => {
                f.kind = if kraken_assist::is_local_url(base_url) {
                    RewriteKind::Local
                } else {
                    RewriteKind::OpenAi
                };
                f.base_url = base_url.clone();
                f.model = model.clone();
                f.key_env = api_key.as_ref().map(env_of).unwrap_or_default();
            }
            ProviderConfig::TerminalAgent { agent, model, .. } => {
                f.kind = RewriteKind::Agent;
                f.agent = agent.clone();
                f.model = model.clone().unwrap_or_default();
            }
            ProviderConfig::Replay { .. } => f.own = false,
        }
        f
    }

    /// Switches the kind and fills its usual values.
    pub fn switch(&mut self, kind: RewriteKind) {
        self.kind = kind;
        self.model = kind.default_model().to_string();
        self.key_env = kind.default_key().to_string();
        self.base_url = match kind {
            RewriteKind::Local => "http://localhost:11434/v1".into(),
            RewriteKind::OpenAi => "https://api.openai.com/v1".into(),
            _ => String::new(),
        };
        if kind == RewriteKind::Agent && self.agent.is_empty() {
            self.agent = "claude".into();
        }
    }

    /// The `[rewrite]` table the form describes; `Ok(None)` is "use the assistant's model".
    pub fn config(&self) -> Result<Option<ProviderConfig>, String> {
        if !self.own {
            return Ok(None);
        }
        let model = self.model.trim().to_string();
        let key = self.key_env.trim().to_string();
        let key_ref = || -> Result<SecretRef, String> {
            if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(
                    "Name the environment variable that holds the API key (letters, digits and underscores)."
                        .into(),
                );
            }
            Ok(SecretRef::Env(key.clone()))
        };
        Ok(Some(match self.kind {
            RewriteKind::Anthropic => ProviderConfig::Anthropic {
                model: (!model.is_empty()).then_some(model),
                api_key: key_ref()?,
                base_url: None,
                max_tokens: None,
                context_window: None,
            },
            RewriteKind::Gemini => ProviderConfig::Gemini {
                model: (!model.is_empty()).then_some(model),
                api_key: key_ref()?,
                base_url: None,
                context_window: None,
            },
            RewriteKind::OpenAi | RewriteKind::Local => {
                let url = self.base_url.trim().trim_end_matches('/').to_string();
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err("The server address must start with http:// or https://.".into());
                }
                if model.is_empty() {
                    return Err("Enter the model name.".into());
                }
                ProviderConfig::OpenaiCompatible {
                    base_url: url,
                    model,
                    api_key: if key.is_empty() {
                        None
                    } else {
                        Some(key_ref()?)
                    },
                    supports_tools: true,
                    context_window: None,
                }
            }
            RewriteKind::Agent => {
                let agent = self.agent.trim().to_string();
                if agent.is_empty() {
                    return Err("Name the terminal agent (claude, codex or gemini).".into());
                }
                ProviderConfig::TerminalAgent {
                    agent,
                    model: (!model.is_empty()).then_some(model),
                    args: Vec::new(),
                }
            }
        }))
    }

    /// Writes the form to the config file at `path`.
    pub fn save(&mut self, path: &Path) -> Result<(), String> {
        let cfg = self.config()?;
        save_rewrite_config(path, cfg.as_ref())
    }

    fn load(&mut self, path: Option<&Path>) {
        if self.loaded {
            return;
        }
        match load_rewrite_config(path) {
            Ok(c) => *self = RewriteForm::from_config(c.as_ref()),
            Err(e) => {
                *self = RewriteForm::from_config(None);
                self.status = Some(Err(format!("The [rewrite] table could not be read: {e}")));
            }
        }
    }

    /// Draws the section; true when the file was saved.
    pub fn show(&mut self, ui: &mut Ui, config_path: Option<&PathBuf>) -> bool {
        self.load(config_path.map(PathBuf::as_path));
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        let mut saved = false;
        ui.label(medium("Rewriting", 14.0).color(p.text_strong));
        ui.add(
            egui::Label::new(
                RichText::new(
                    "The Rust rewrite asks a model for every translation, test fix and repair. A whole program can take about 60 requests, so you may want a cheaper or a local model for it.",
                )
                .size(12.0)
                .color(p.text_dim),
            )
            .wrap(),
        );
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.own, false, "Use the assistant's model")
                .on_hover_text("The rewrite uses the model chosen above for the assistant");
            ui.radio_value(&mut self.own, true, "Use its own model")
                .on_hover_text(
                    "Choose a separate model for the rewrite (the [rewrite] table of config.toml)",
                );
        });
        if self.own {
            let mut pick = None;
            egui::ComboBox::from_id_salt("kraken_rewrite_kind")
                .selected_text(self.kind.label())
                .width(300.0)
                .show_ui(ui, |ui| {
                    for k in RewriteKind::ALL {
                        if ui
                            .selectable_label(self.kind == k, k.label())
                            .on_hover_text(match k {
                                RewriteKind::Local => "Free and private: the model runs on this computer",
                                RewriteKind::Agent => "Claude Code, Codex or Gemini CLI, billed by its own subscription",
                                _ => "Billed per token by the provider",
                            })
                            .clicked()
                        {
                            pick = Some(k);
                        }
                    }
                })
                .response
                .on_hover_text("Where the rewrite's model runs");
            if let Some(k) = pick.filter(|k| *k != self.kind) {
                self.switch(k);
            }
            egui::Grid::new("kraken_rewrite_model")
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    if matches!(self.kind, RewriteKind::OpenAi | RewriteKind::Local) {
                        ui.label("Server address");
                        ui.add(egui::TextEdit::singleline(&mut self.base_url).desired_width(320.0))
                            .on_hover_text("The address of the server that runs the model");
                        ui.end_row();
                    }
                    if self.kind == RewriteKind::Agent {
                        ui.label("Agent");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.agent)
                                .hint_text("claude, codex or gemini")
                                .desired_width(320.0),
                        )
                        .on_hover_text("Which terminal agent; set it up in the assistant section first");
                        ui.end_row();
                    }
                    ui.label(if self.kind == RewriteKind::Agent {
                        "Model (optional)"
                    } else {
                        "Model"
                    });
                    ui.add(egui::TextEdit::singleline(&mut self.model).desired_width(320.0))
                        .on_hover_text("The name of the model the rewrite asks");
                    ui.end_row();
                    if !matches!(self.kind, RewriteKind::Agent) {
                        ui.label(if self.kind == RewriteKind::Local {
                            "Key variable (optional)"
                        } else {
                            "Key variable"
                        });
                        ui.add(
                            egui::TextEdit::singleline(&mut self.key_env)
                                .hint_text("e.g. ANTHROPIC_API_KEY")
                                .desired_width(320.0),
                        )
                        .on_hover_text(
                            "The environment variable that holds the API key. The key itself is never written to config.toml",
                        );
                        ui.end_row();
                    }
                });
        }
        let can_save = config_path.is_some();
        if ui
            .add_enabled(can_save, egui::Button::new("Save rewriting model"))
            .on_hover_text("Write this choice to config.toml. Rewrite jobs use it from their next model call, also in the background engine")
            .on_disabled_hover_text("There is no settings file to save to (HOME is not set)")
            .clicked()
            && let Some(path) = config_path
        {
            match self.save(path) {
                Ok(()) => {
                    self.status = Some(Ok("Saved. The next rewrite run uses it.".into()));
                    saved = true;
                }
                Err(e) => self.status = Some(Err(e)),
            }
        }
        match &self.status {
            Some(Ok(t)) => {
                ui.label(RichText::new(t).size(12.0).color(s.success));
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            None => {}
        }
        let policy = AiPolicy::load(config_path.map(PathBuf::as_path));
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "Which model each feature uses now: {}",
                    policy.models_line()
                ))
                .size(11.5)
                .color(p.text_dim),
            )
            .wrap(),
        );
        saved
    }
}

/// The "Limits" form: text boxes, empty meaning off.
#[derive(Debug, Clone, Default)]
pub struct LimitsForm {
    /// Most model calls per run.
    pub max_calls: String,
    /// Most estimated cost per run, dollars.
    pub max_cost: String,
    /// Daily budget, dollars.
    pub daily: String,
    /// Do not ask below this many dollars.
    pub skip_under: String,
    loaded: bool,
    status: Option<Result<String, String>>,
}

fn text_of<T: ToString>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_default()
}

impl LimitsForm {
    /// The form for `l`.
    pub fn from_limits(l: &AiLimits) -> Self {
        LimitsForm {
            max_calls: text_of(l.max_calls_per_run),
            max_cost: text_of(l.max_cost_per_run),
            daily: text_of(l.daily_budget),
            skip_under: text_of(l.skip_confirm_under),
            loaded: true,
            status: None,
        }
    }

    /// The limits the form describes.
    pub fn limits(&self) -> Result<AiLimits, String> {
        fn num(s: &str, what: &str) -> Result<Option<f64>, String> {
            let t = s.trim().trim_start_matches('$');
            if t.is_empty() {
                return Ok(None);
            }
            t.parse::<f64>()
                .ok()
                .filter(|v| *v >= 0.0 && v.is_finite())
                .map(Some)
                .ok_or_else(|| {
                    format!("{what} must be a number of dollars, such as 2.50, or empty.")
                })
        }
        let calls = match self.max_calls.trim() {
            "" => None,
            t => Some(t.parse::<u64>().ok().filter(|n| *n > 0).ok_or_else(|| {
                "Most calls per run must be a whole number above 0, or empty.".to_string()
            })?),
        };
        Ok(AiLimits {
            max_calls_per_run: calls,
            max_cost_per_run: num(&self.max_cost, "Most cost per run")?,
            daily_budget: num(&self.daily, "The daily budget")?,
            skip_confirm_under: num(&self.skip_under, "The ask-first threshold")?,
        })
    }

    /// Draws the section; true when the file was saved.
    pub fn show(&mut self, ui: &mut Ui, config_path: Option<&PathBuf>) -> bool {
        if !self.loaded {
            *self = LimitsForm::from_limits(&AiLimits::load(config_path.map(PathBuf::as_path)));
        }
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        let mut saved = false;
        ui.label(medium("Limits on AI work", 14.0).color(p.text_strong));
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Cloud models are billed per token. KRAKEN shows an estimate before AI work starts and keeps a running total, but the estimate uses list prices and your provider's bill is what counts. Leave a box empty for no limit.",
                )
                .size(12.0)
                .color(p.text_dim),
            )
            .wrap(),
        );
        egui::Grid::new("kraken_ai_limits")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Most calls per run");
                ui.add(egui::TextEdit::singleline(&mut self.max_calls).hint_text("no limit").desired_width(120.0))
                    .on_hover_text("A run stops cleanly after this many model calls and keeps what it finished");
                ui.end_row();
                ui.label("Most cost per run ($)");
                ui.add(egui::TextEdit::singleline(&mut self.max_cost).hint_text("no limit").desired_width(120.0))
                    .on_hover_text("A run stops cleanly once its estimated cost reaches this, and keeps what it finished");
                ui.end_row();
                ui.label("Daily budget ($)");
                ui.add(egui::TextEdit::singleline(&mut self.daily).hint_text("no budget").desired_width(120.0))
                    .on_hover_text("No new AI work starts once today's estimated total (all projects, UTC day) reaches this");
                ui.end_row();
                ui.label("Do not ask below ($)");
                ui.add(egui::TextEdit::singleline(&mut self.skip_under).hint_text("always ask").desired_width(120.0))
                    .on_hover_text("AI work estimated below this starts without the question. Free local models never ask");
                ui.end_row();
            });
        if let Some(d) = kraken_model::DailyLedger::standard() {
            let today = d.today();
            ui.label(
                RichText::new(format!("Today so far, all projects: {}.", today.line()))
                    .size(11.5)
                    .color(p.text_dim),
            );
        }
        let can_save = config_path.is_some();
        if ui
            .add_enabled(can_save, egui::Button::new("Save limits"))
            .on_hover_text(
                "Write these limits to config.toml ([ai_limits]); new runs use them at once",
            )
            .on_disabled_hover_text("There is no settings file to save to (HOME is not set)")
            .clicked()
            && let Some(path) = config_path
        {
            match self.limits().and_then(|l| l.save(path)) {
                Ok(()) => {
                    let msg = match self.limits().ok().and_then(|l| l.daily_budget) {
                        Some(b) => format!("Saved. Daily budget: {}.", money(b)),
                        None => "Saved.".to_string(),
                    };
                    self.status = Some(Ok(msg));
                    saved = true;
                }
                Err(e) => self.status = Some(Err(e)),
            }
        }
        match &self.status {
            Some(Ok(t)) => {
                ui.label(RichText::new(t).size(12.0).color(s.success));
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            None => {}
        }
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Prices come from a built-in table of list prices (estimates). To correct one or add your model, add it to the [pricing] table of config.toml, for example: \"my-model\" = { input = 0.5, output = 1.5 } (dollars per million tokens).",
                )
                .size(11.5)
                .color(p.text_dim),
            )
            .wrap(),
        );
        saved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rewrite_form_round_trips_and_validates() {
        let mut f = RewriteForm::from_config(None);
        assert!(!f.own);
        assert_eq!(f.config().unwrap(), None);
        f.own = true;
        f.switch(RewriteKind::Local);
        f.model = "qwen3:14b".into();
        let cfg = f.config().unwrap().unwrap();
        assert_eq!(
            kraken_assist::provider_kind_of(&cfg),
            kraken_proto::AiProviderKind::Local
        );
        let back = RewriteForm::from_config(Some(&cfg));
        assert_eq!(back.kind, RewriteKind::Local);
        f.switch(RewriteKind::Anthropic);
        f.key_env = "sk-ant-123 nope".into();
        assert!(f.config().is_err());
    }

    #[test]
    fn the_limits_form_reads_empty_as_off() {
        let mut f = LimitsForm::from_limits(&AiLimits::default());
        assert_eq!(f.limits().unwrap(), AiLimits::default());
        f.daily = "$2.50".into();
        f.max_calls = "100".into();
        let l = f.limits().unwrap();
        assert_eq!(l.daily_budget, Some(2.5));
        assert_eq!(l.max_calls_per_run, Some(100));
        f.max_cost = "lots".into();
        assert!(f.limits().is_err());
    }

    #[test]
    fn settings_write_the_rewrite_table_and_the_limits() {
        let dir = crate::testutil::tempdir();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[provider]\nkind = \"openai_compatible\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"qwen3\"\n",
        )
        .expect("config");
        let mut settings = crate::assist::settings_ai::AiSettings::default();
        let form = settings.rewrite_form();
        form.own = true;
        form.switch(RewriteKind::Anthropic);
        form.model = "claude-haiku-4-5".into();
        form.save(&path).expect("save");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("[rewrite]"), "{text}");
        assert!(text.contains("ANTHROPIC_API_KEY"), "{text}");
        assert!(
            text.contains("[provider]"),
            "the assistant's table stays: {text}"
        );
        let p = AiPolicy::load(Some(&path));
        let rw = p.rewrite.expect("rewrite model");
        assert_eq!(rw.source, kraken_assist::ModelSource::Rewrite);
        assert_eq!(rw.model, "claude-haiku-4-5");
        assert_eq!(
            p.assistant.expect("assistant").kind,
            kraken_proto::AiProviderKind::Local
        );

        // Back to the assistant's model: the table goes.
        form.own = false;
        form.save(&path).expect("save");
        assert!(
            !std::fs::read_to_string(&path)
                .expect("read")
                .contains("[rewrite]")
        );

        let limits = LimitsForm {
            daily: "3".into(),
            skip_under: "0.05".into(),
            ..LimitsForm::default()
        };
        limits.limits().expect("limits").save(&path).expect("save");
        let l = AiLimits::load(Some(&path));
        assert_eq!(l.daily_budget, Some(3.0));
        assert_eq!(l.skip_confirm_under, Some(0.05));
    }
}

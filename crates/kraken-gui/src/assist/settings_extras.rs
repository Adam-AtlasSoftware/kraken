//! Parts of Settings > AI beyond the provider form: the model picker, the thinking effort, the
//! terminal-agent permission rules and the local-model recommendation with its Set up button.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};

use egui::{RichText, Ui};
use kraken_agent::{Effort, ModelList, ModelSource, ProviderConfig, ThinkingConfig};
use kraken_registry::commands::{
    LocalFeature, LocalModelBackend, LocalModelRecommendOut, LocalModelSetupOut, LocalSetupPlan,
    recommend_view, recommendation_now,
};
use tokio::runtime::Handle;

use crate::style::{self, chip, medium, pal};

/// What the local-model block is doing.
enum Local {
    Idle,
    Detecting(Receiver<LocalModelRecommendOut>),
    Ready(Box<LocalModelRecommendOut>),
    Confirming(Box<LocalModelRecommendOut>),
    Installing(Receiver<Result<LocalModelSetupOut, String>>),
    Done(Result<LocalModelSetupOut, String>),
}

/// State of the extra sections.
pub struct AiExtras {
    /// The key (`kind|url`) the model list was asked for, the list and the pending answer.
    list_for: String,
    list: Option<ModelList>,
    list_rx: Option<Receiver<ModelList>>,
    local: Local,
}

impl Default for AiExtras {
    fn default() -> Self {
        AiExtras {
            list_for: String::new(),
            list: None,
            list_rx: None,
            local: Local::Idle,
        }
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1u64 << 30) as f64)
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

    /// The local-model recommendation and its Set up button. `assistant_is_local` only changes
    /// the wording of the result.
    pub fn local_model(&mut self, ui: &mut Ui, rt: &Handle, ctx: &egui::Context) {
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        // Finish background work.
        match &self.local {
            Local::Detecting(rx) => {
                if let Ok(r) = rx.try_recv() {
                    self.local = Local::Ready(Box::new(r));
                }
            }
            Local::Installing(rx) => {
                if let Ok(r) = rx.try_recv() {
                    self.local = Local::Done(r);
                }
            }
            _ => {}
        }
        ui.label(medium("Run a model on this computer", 13.0).color(p.text_strong));
        match &self.local {
            Local::Idle => {
                ui.label(
                    RichText::new(
                        "KRAKEN can look at your graphics card, memory and disk and suggest an engine and a model that fit.",
                    )
                    .size(11.5)
                    .color(p.text_dim),
                );
                if ui
                    .button("Check this computer")
                    .on_hover_text(
                        "Reads your hardware (nvidia-smi, rocm-smi, /sys). Downloads nothing",
                    )
                    .clicked()
                {
                    let (tx, rx) = channel();
                    self.local = Local::Detecting(rx);
                    let ctx = ctx.clone();
                    rt.spawn_blocking(move || {
                        let (hw, rec, _) = recommendation_now();
                        let _ = tx.send(recommend_view(&hw, &rec));
                        ctx.request_repaint();
                    });
                }
            }
            Local::Detecting(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Looking at your hardware...");
                });
                ctx.request_repaint_after(std::time::Duration::from_millis(200));
            }
            Local::Ready(r) | Local::Confirming(r) => {
                let r = r.clone();
                let hw = format!(
                    "{} | {:.0} GiB RAM | {:.0} GiB free disk | {} cores",
                    if r.gpus.is_empty() {
                        "no GPU".to_string()
                    } else {
                        r.gpus
                            .iter()
                            .map(|g| match g.vram_gib {
                                Some(v) => format!("{} ({v} GiB)", g.name),
                                None => g.name.clone(),
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    r.ram_gib,
                    r.free_disk_gib,
                    r.cpu_cores
                );
                ui.label(RichText::new(hw).size(12.0).color(p.text));
                ui.horizontal(|ui| {
                    chip(ui, &r.engine_label, s.info);
                    if let Some(m) = &r.model {
                        chip(
                            ui,
                            &format!("{} {} ({})", m.name, m.quant, gib(m.size_bytes)),
                            s.success,
                        );
                    } else {
                        chip(ui, "no model fits", s.warning);
                    }
                });
                for line in &r.reasons {
                    ui.add(
                        egui::Label::new(RichText::new(line).size(11.5).color(p.text_dim)).wrap(),
                    );
                }
                if let Some(m) = &r.model {
                    ui.horizontal(|ui| {
                        if style::primary_button(ui, "Set up...")
                            .on_hover_text("Shows the download size and disk use and asks first")
                            .clicked()
                        {
                            self.local = Local::Confirming(r.clone());
                        }
                        if ui
                            .button("Check again")
                            .on_hover_text("Look at the hardware again")
                            .clicked()
                        {
                            self.local = Local::Idle;
                        }
                    });
                    if matches!(self.local, Local::Confirming(_)) {
                        let mut go = false;
                        let mut cancel = false;
                        egui::Window::new("Set up a local model")
                            .collapsible(false)
                            .resizable(false)
                            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                            .show(ctx, |ui| {
                                ui.label(format!(
                                    "Download {} {} with {}.",
                                    m.name, m.quant, r.engine_label
                                ));
                                ui.label(format!("Download size: {}", gib(r.download_bytes)));
                                ui.label(format!("Disk use: {}", gib(r.disk_bytes)));
                                ui.label(
                                    RichText::new(
                                        "The file is checked against a SHA-256 pinned in KRAKEN and deleted if it differs. The assistant is pointed at the model afterwards.",
                                    )
                                    .size(11.5)
                                    .color(p.text_dim),
                                );
                                ui.horizontal(|ui| {
                                    if style::primary_button(ui, "Download and set up")
                                        .on_hover_text("Download, verify the SHA-256 and configure")
                                        .clicked()
                                    {
                                        go = true;
                                    }
                                    if ui
                                        .button("Cancel")
                                        .on_hover_text("Download nothing")
                                        .clicked()
                                    {
                                        cancel = true;
                                    }
                                });
                            });
                        if cancel {
                            self.local = Local::Ready(r.clone());
                        }
                        if go {
                            self.start_setup(rt, ctx);
                        }
                    }
                } else if ui
                    .button("Check again")
                    .on_hover_text("Look at the hardware again")
                    .clicked()
                {
                    self.local = Local::Idle;
                }
            }
            Local::Installing(_) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Downloading and checking the model. This can take a while...");
                });
                ctx.request_repaint_after(std::time::Duration::from_millis(300));
            }
            Local::Done(Ok(o)) => {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "Done. {} is at {} (SHA-256 verified). {}",
                            o.model_id, o.path, o.note
                        ))
                        .size(12.0)
                        .color(s.success),
                    )
                    .wrap(),
                );
                if ui
                    .button("Check again")
                    .on_hover_text("Look at the hardware again")
                    .clicked()
                {
                    self.local = Local::Idle;
                }
            }
            Local::Done(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
                if ui
                    .button("Check again")
                    .on_hover_text("Look at the hardware again")
                    .clicked()
                {
                    self.local = Local::Idle;
                }
            }
        }
    }

    fn start_setup(&mut self, rt: &Handle, ctx: &egui::Context) {
        let (tx, rx) = channel();
        self.local = Local::Installing(rx);
        let ctx = ctx.clone();
        rt.spawn(async move {
            let result = async {
                let (_, rec, models_dir) = tokio::task::spawn_blocking(recommendation_now)
                    .await
                    .map_err(|e| e.to_string())?;
                let model = rec.model.clone().ok_or("no model fits this computer")?;
                let backend =
                    kraken_host::local_models::LocalModels::system().map_err(|e| e.message)?;
                backend
                    .setup(LocalSetupPlan {
                        engine: rec.engine,
                        model,
                        models_dir,
                        assign: vec![LocalFeature::Assistant],
                    })
                    .await
                    .map_err(|e| e.message)
            }
            .await;
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
}

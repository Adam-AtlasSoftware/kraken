//! Parts of Settings > AI beyond the provider form: the model picker, the thinking effort, the
//! terminal-agent permission rules and the local-model recommendation with its Set up button.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};

use egui::{RichText, Ui};
use kraken_agent::{Effort, ModelList, ModelSource, ProviderConfig, ThinkingConfig};
use kraken_infer::{EngineChoice, GpuApi, ModelEntry};
use kraken_registry::commands::{
    LocalFeature, LocalModelBackend, LocalModelRecommendOut, LocalModelSetupOut, LocalSetupPlan,
    SetupProgress, StrataPlan, recommend_view, recommendation_now, strata_downloads, strata_now,
    strata_view,
};
use tokio::runtime::Handle;

use crate::style::{self, chip, medium, pal};

/// What the local-model block is doing.
enum Local {
    Idle,
    Detecting(Receiver<LocalModelRecommendOut>),
    Ready(Box<LocalModelRecommendOut>),
    Confirming(Box<LocalModelRecommendOut>),
    Installing(
        Receiver<Result<LocalModelSetupOut, String>>,
        Arc<Mutex<SetupProgress>>,
    ),
    Done(Result<LocalModelSetupOut, String>),
}

/// State of the extra sections.
pub struct AiExtras {
    /// The key (`kind|url`) the model list was asked for, the list and the pending answer.
    list_for: String,
    list: Option<ModelList>,
    list_rx: Option<Receiver<ModelList>>,
    local: Local,
    /// The engine chosen in the local-model block: llama-server (the recommendation) or Strata.
    strata: bool,
    /// The Strata model picked in the list (the recommended one when empty).
    strata_model: String,
}

impl Default for AiExtras {
    fn default() -> Self {
        AiExtras {
            list_for: String::new(),
            list: None,
            list_rx: None,
            local: Local::Idle,
            strata: false,
            strata_model: String::new(),
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
            Local::Installing(rx, _) => {
                if let Ok(r) = rx.try_recv() {
                    self.local = Local::Done(r);
                }
            }
            _ => {}
        }
        ui.label(medium("Run a model on this computer", 13.0).color(p.text_strong));
        if matches!(self.local, Local::Idle | Local::Ready(_)) {
            let before = self.strata;
            ui.horizontal(|ui| {
                ui.label("Engine");
                ui.selectable_value(&mut self.strata, false, "llama-server (recommended)")
                    .on_hover_text("Small models that fit in video memory");
                ui.selectable_value(&mut self.strata, true, "Strata").on_hover_text(
                    "Big mixture-of-experts models on a small GPU by keeping the experts in system RAM",
                );
            });
            if before != self.strata {
                self.local = Local::Idle;
                self.strata_model.clear();
            }
        }
        match &self.local {
            Local::Idle => {
                ui.label(
                    RichText::new(
                        "KRAKEN can look at your graphics card, memory and disk and suggest an engine and a model that fit.",
                    )
                    .size(11.5)
                    .color(p.text_dim),
                );
                let label = if self.strata {
                    "Evaluate this system"
                } else {
                    "Check this computer"
                };
                if ui
                    .button(label)
                    .on_hover_text(
                        "Reads your hardware (GPU and video memory, RAM, disk, CUDA). Downloads nothing",
                    )
                    .clicked()
                {
                    let (tx, rx) = channel();
                    self.local = Local::Detecting(rx);
                    let ctx = ctx.clone();
                    let strata = self.strata;
                    rt.spawn_blocking(move || {
                        let view = if strata {
                            let (hw, a, m, _) = strata_now();
                            strata_view(&hw, &a, &m)
                        } else {
                            let (hw, rec, _) = recommendation_now();
                            recommend_view(&hw, &rec)
                        };
                        let _ = tx.send(view);
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
                if let Some(sv) = &r.strata {
                    for m in &sv.missing {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("Missing: {} -- {}", m.what, m.how_to_fix))
                                    .size(11.5)
                                    .color(s.danger),
                            )
                            .wrap(),
                        );
                    }
                    if self.strata_model.is_empty() {
                        self.strata_model = sv.recommended.clone().unwrap_or_default();
                    }
                    for c in &sv.candidates {
                        ui.horizontal(|ui| {
                            ui.radio_value(
                                &mut self.strata_model,
                                c.id.clone(),
                                format!("{} {} ({})", c.name, c.quant, gib(c.download_bytes)),
                            )
                            .on_hover_text("Download and set up this model");
                            let (txt, col) = match c.fit.as_str() {
                                "fits" => ("fits", s.success),
                                "below_minimum" => ("below Strata's minimum", s.warning),
                                _ => ("not enough disk", s.danger),
                            };
                            chip(ui, txt, col);
                        });
                        ui.add(
                            egui::Label::new(RichText::new(&c.speed).size(11.0).color(p.text_dim))
                                .wrap(),
                        );
                        for w in &c.warnings {
                            ui.add(
                                egui::Label::new(RichText::new(w).size(11.0).color(s.warning))
                                    .wrap(),
                            );
                        }
                    }
                }
                let blocked = r.strata.as_ref().is_some_and(|sv| !sv.missing.is_empty());
                if blocked {
                    if ui
                        .button("Check again")
                        .on_hover_text(
                            "Look at the hardware again after installing what is missing",
                        )
                        .clicked()
                    {
                        self.local = Local::Idle;
                    }
                } else if let Some(m) = &r.model {
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
                                let chosen = r
                                    .strata
                                    .as_ref()
                                    .and_then(|sv| {
                                        sv.candidates.iter().find(|c| c.id == self.strata_model)
                                    })
                                    .cloned();
                                if let Some(c) = &chosen {
                                    ui.label(format!(
                                        "Download {} {} with Strata. Every download:",
                                        c.name, c.quant
                                    ));
                                    let mut total = 0;
                                    for d in &c.downloads {
                                        total += d.size_bytes;
                                        ui.label(format!("  {} - {}", d.name, gib(d.size_bytes)));
                                    }
                                    ui.label(format!("Download size: {}", gib(total)));
                                    ui.label(format!(
                                        "Disk use: {} (files, Python environment and build) under the KRAKEN data folder, engines/strata",
                                    gib(c.disk_bytes)));
                                    for w in &c.warnings {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(w).size(11.5).color(s.warning),
                                            )
                                            .wrap(),
                                        );
                                    }
                                } else {
                                    ui.label(format!(
                                        "Download {} {} with {}.",
                                        m.name, m.quant, r.engine_label
                                    ));
                                    ui.label(format!("Download size: {}", gib(r.download_bytes)));
                                    ui.label(format!("Disk use: {}", gib(r.disk_bytes)));
                                }
                                ui.label(
                                    RichText::new(
                                        "Every file is checked against a SHA-256 pinned in KRAKEN and deleted if it differs. Nothing is installed outside the KRAKEN data folder and nothing needs sudo. The assistant is pointed at the model afterwards.",
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
            Local::Installing(_, progress) => {
                let pr = progress.lock().map(|p| p.clone()).unwrap_or_default();
                ui.add(
                    egui::ProgressBar::new(pr.fraction())
                        .show_percentage()
                        .text(if pr.label.is_empty() {
                            "Starting...".to_string()
                        } else {
                            format!("Step {} of {}: {}", pr.step, pr.steps, pr.label)
                        }),
                );
                if pr.total > 0 {
                    ui.label(
                        RichText::new(format!("{} of {}", gib(pr.done), gib(pr.total)))
                            .size(11.5)
                            .color(p.text_dim),
                    );
                }
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
        let progress = Arc::new(Mutex::new(SetupProgress::default()));
        self.local = Local::Installing(rx, progress.clone());
        let ctx = ctx.clone();
        let (strata, pick) = (self.strata, self.strata_model.clone());
        rt.spawn(async move {
            let result = async {
                let backend =
                    kraken_host::local_models::LocalModels::system().map_err(|e| e.message)?;
                let plan = if strata {
                    let (_, a, m, models_dir) = tokio::task::spawn_blocking(strata_now)
                        .await
                        .map_err(|e| e.to_string())?;
                    if let Some(x) = a.missing.first() {
                        return Err(format!("{} -- {}", x.what, x.how_to_fix));
                    }
                    let c = a
                        .candidates
                        .iter()
                        .find(|c| c.model.id == pick)
                        .ok_or("pick a Strata model first")?;
                    let _ = strata_downloads(&m, &c.model);
                    let first = c.model.files.first().cloned();
                    LocalSetupPlan {
                        engine: EngineChoice {
                            id: "strata".into(),
                            gpu_api: GpuApi::Cuda,
                            label: "Strata".into(),
                        },
                        model: ModelEntry {
                            id: c.model.id.clone(),
                            name: c.model.name.clone(),
                            params_b: 0,
                            quant: c.model.quant.clone(),
                            file: first.as_ref().map(|f| f.name.clone()).unwrap_or_default(),
                            url: first.as_ref().map(|f| f.url.clone()).unwrap_or_default(),
                            size: c.download_bytes,
                            sha256: first.map(|f| f.sha256).unwrap_or_default(),
                            license: c.model.license.clone(),
                        },
                        models_dir,
                        assign: vec![LocalFeature::Assistant],
                        strata: Some(StrataPlan {
                            model: c.model.clone(),
                            manifest: m,
                        }),
                        progress: Some(progress),
                    }
                } else {
                    let (_, rec, models_dir) = tokio::task::spawn_blocking(recommendation_now)
                        .await
                        .map_err(|e| e.to_string())?;
                    let model = rec.model.clone().ok_or("no model fits this computer")?;
                    LocalSetupPlan {
                        engine: rec.engine,
                        model,
                        models_dir,
                        assign: vec![LocalFeature::Assistant],
                        strata: None,
                        progress: None,
                    }
                };
                backend.setup(plan).await.map_err(|e| e.message)
            }
            .await;
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
}

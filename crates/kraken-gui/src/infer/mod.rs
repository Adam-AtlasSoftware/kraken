//! "Run a model on this computer": the local-inference section of Settings → AI (decisions 21,
//! 30, 69).
//!
//! The state and logic are `kraken_viewmodel::infer::InferPanel`; this module draws them. The
//! model runs in `krakend` (it outlives the window) or, with `--no-daemon`, in this process.

mod form_ui;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Instant;

use egui::{RichText, Ui};
use kraken_host::infer::InferManager;
use kraken_viewmodel::DaemonClientBackend;
use kraken_viewmodel::assist::{ProviderStore, badge_of};
use kraken_viewmodel::infer::{DaemonInfer, HintLevel, InferApi, InferPanel};
use tokio::runtime::Handle;

use crate::assist::{AiSettings, Change};
use crate::services::Mode;
use crate::style::{self, chip, medium, pal};

/// Which service the panel is bound to, so a new daemon connection rebinds it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    Daemon(usize),
    Local,
    Fixed,
}

/// Result of the last "Use for the assistant".
type Notice = Result<String, String>;

/// State of the section.
#[derive(Default)]
pub struct InferSettings {
    panel: Option<InferPanel>,
    binding: Option<Binding>,
    local: Option<Arc<InferManager>>,
    pick: Option<Receiver<PathBuf>>,
    notice: Option<Notice>,
    asked_to_start: bool,
}

impl InferSettings {
    /// A section bound to a given service (tests).
    #[cfg(test)]
    pub fn with_service(api: Arc<dyn InferApi>, rt: Handle) -> Self {
        let mut panel = InferPanel::new(api, rt);
        panel.refresh();
        InferSettings {
            panel: Some(panel),
            binding: Some(Binding::Fixed),
            ..Default::default()
        }
    }

    /// The panel's state (tests).
    #[cfg(test)]
    pub fn panel_mut(&mut self) -> Option<&mut InferPanel> {
        self.panel.as_mut()
    }

    /// The last result of "Use for the assistant" (tests).
    #[cfg(test)]
    pub fn notice(&self) -> Option<&Notice> {
        self.notice.as_ref()
    }

    /// Stops a model this process owns (`--no-daemon` runs); a daemon's model outlives the window.
    pub fn shutdown(&self, rt: &Handle) {
        if let Some(m) = &self.local {
            let m = m.clone();
            rt.block_on(async move { m.shutdown().await });
        }
    }

    fn bind(
        &mut self,
        ctx: &egui::Context,
        rt: &Handle,
        mode: Mode,
        backend: Option<&Arc<DaemonClientBackend>>,
    ) -> bool {
        let want = match mode {
            Mode::Daemon => match backend {
                Some(b) => Binding::Daemon(Arc::as_ptr(b) as usize),
                None => return self.panel.is_some(),
            },
            Mode::NoDaemon => Binding::Local,
        };
        if self.binding == Some(want) && self.panel.is_some() {
            return true;
        }
        if self.binding == Some(Binding::Fixed) && self.panel.is_some() {
            return true;
        }
        let api: Arc<dyn InferApi> = match want {
            Binding::Daemon(_) => match backend {
                Some(b) => Arc::new(DaemonInfer(b.clone())),
                None => return false,
            },
            Binding::Local => self
                .local
                .get_or_insert_with(|| Arc::new(InferManager::from_env()))
                .clone(),
            Binding::Fixed => return self.panel.is_some(),
        };
        let c = ctx.clone();
        let mut panel =
            InferPanel::new(api, rt.clone()).with_repaint(Arc::new(move || c.request_repaint()));
        panel.refresh();
        self.panel = Some(panel);
        self.binding = Some(want);
        true
    }

    /// Draws the section. Passes a chosen model on to `ai` so the assistant switches to it.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        rt: &Handle,
        mode: Mode,
        backend: Option<&Arc<DaemonClientBackend>>,
        config_path: Option<&PathBuf>,
        ai: &mut AiSettings,
    ) {
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("Run a model on this computer", 14.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "Runs a language model on your own computer with llama.cpp or another engine. \
                 Nothing leaves your machine. You choose the model file; KRAKEN never downloads models.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
        ui.add_space(4.0);
        if !self.bind(ui.ctx(), rt, mode, backend) {
            ui.label(RichText::new("Connecting to krakend...").color(p.text_dim));
            return;
        }
        if let Some(rx) = &self.pick
            && let Ok(path) = rx.try_recv()
        {
            if let Some(panel) = self.panel.as_mut() {
                panel.set_model_path(&path);
            }
            self.pick = None;
        }
        let ctx = ui.ctx().clone();
        let Some(panel) = self.panel.as_mut() else {
            return;
        };
        panel.poll();
        panel.tick(Instant::now());
        ctx.request_repaint_after(panel.next_tick_in());

        if !panel.loaded() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Looking for engines...").color(p.text_dim));
            });
            if let Some(e) = &panel.error {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
                if ui.button("Try again").clicked() {
                    panel.error = None;
                    panel.refresh();
                }
            }
            return;
        }
        if panel.backends().is_empty() {
            ui.label(
                RichText::new(
                    "No engine can run on this computer. See docs/local-models.md for how to add one.",
                )
                .color(s.warning),
            );
            return;
        }

        let running = panel.is_running() || panel.is_busy();
        let mut pick_for: Option<String> = None;
        ui.add_enabled_ui(!running, |ui| {
            // Engine picker.
            ui.horizontal(|ui| {
                ui.label("Engine");
                let current = panel
                    .selected_backend()
                    .map(|b| b.display_name.clone())
                    .unwrap_or_default();
                let mut chosen = panel.selected.clone();
                egui::ComboBox::from_id_salt("kraken_infer_engine")
                    .selected_text(current)
                    .width(300.0)
                    .show_ui(ui, |ui| {
                        for b in panel.backends() {
                            ui.selectable_value(
                                &mut chosen,
                                Some(b.id.clone()),
                                b.display_name.clone(),
                            );
                        }
                    });
                if chosen != panel.selected
                    && let Some(id) = chosen
                {
                    panel.select(&id);
                }
                if let Some(b) = panel.selected_backend() {
                    chip(
                        ui,
                        if b.builtin {
                            "built in"
                        } else {
                            "from manifest"
                        },
                        p.text_dim,
                    );
                    if b.capabilities.supports_moe_offload {
                        chip(ui, "big models on small GPUs", s.info).on_hover_text(
                            "Can keep a mixture-of-experts model's expert weights in system RAM.",
                        );
                    }
                }
            });
            if let Some(l) = &panel.listing {
                for w in &l.warnings {
                    ui.add(egui::Label::new(RichText::new(w).size(12.0).color(s.warning)).wrap());
                }
            }
            if let Some(h) = panel.install_hint() {
                ui.add(egui::Label::new(RichText::new(h).size(12.0).color(s.warning)).wrap());
            }
            ui.add_space(2.0);
            pick_for = form_ui::show(ui, &mut panel.form);
        });
        if let Some(key) = pick_for {
            let (tx, rx) = channel();
            self.pick = Some(rx);
            let c = ctx.clone();
            let start_dir = panel
                .form
                .field(&key)
                .map(|f| f.text.trim().to_string())
                .and_then(|t| PathBuf::from(t).parent().map(PathBuf::from))
                .filter(|d| d.is_dir());
            rt.spawn(async move {
                let mut d = rfd::AsyncFileDialog::new().set_title("Choose a model file (GGUF)");
                if let Some(dir) = start_dir {
                    d = d.set_directory(dir);
                }
                if let Some(h) = d.pick_file().await {
                    let _ = tx.send(h.path().to_path_buf());
                    c.request_repaint();
                }
            });
        }

        if let Some(h) = panel.memory_hint() {
            let color = match h.level {
                HintLevel::Info => p.text_dim,
                HintLevel::Warn => s.warning,
                HintLevel::Bad => s.danger,
            };
            ui.add(egui::Label::new(RichText::new(h.text).size(12.0).color(color)).wrap());
        }
        ui.add_space(4.0);

        // Start, stop, use.
        let mut use_it = false;
        ui.horizontal(|ui| {
            ui.add_enabled_ui(panel.can_start(), |ui| {
                if style::primary_button(ui, "Start").clicked() {
                    panel.start();
                    self.asked_to_start = true;
                    self.notice = None;
                }
            });
            ui.add_enabled_ui(panel.is_running() && !panel.is_busy(), |ui| {
                if ui.button("Stop").clicked() {
                    panel.stop();
                }
            });
            ui.add_enabled_ui(panel.is_ready(), |ui| {
                if ui
                    .button("Use for the assistant")
                    .on_hover_text(
                        "Saves this model as the assistant's provider (an OpenAI-compatible server on this computer).",
                    )
                    .clicked()
                {
                    use_it = true;
                }
            });
        });
        if panel.is_running() || panel.is_busy() || self.asked_to_start {
            ui.horizontal(|ui| {
                if panel.is_busy() || matches!(panel.status.phase.as_str(), "starting" | "loading")
                {
                    ui.spinner();
                }
                ui.label(
                    RichText::new(panel.phase_text()).color(if panel.is_ready() {
                        s.success
                    } else {
                        p.text
                    }),
                );
            });
            if let Some(f) = panel.progress() {
                ui.add(egui::ProgressBar::new(f).desired_width(380.0));
            }
        }
        for w in &panel.warnings {
            ui.add(egui::Label::new(RichText::new(w).size(12.0).color(s.warning)).wrap());
        }
        if let Some(e) = &panel.error {
            ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
        }
        match &self.notice {
            Some(Ok(t)) => {
                ui.add(egui::Label::new(RichText::new(t).size(12.0).color(s.success)).wrap());
            }
            Some(Err(e)) => {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            None => {}
        }
        if panel.is_ready() {
            ui.label(
                RichText::new(
                    "Tip: the address changes each time unless you set a Port, so \"Use for the assistant\" after every start.",
                )
                .size(11.5)
                .color(p.text_dim),
            );
        }

        // Log viewer.
        let was_open = panel.show_logs;
        let header = egui::CollapsingHeader::new("Model log")
            .id_salt("kraken_infer_log")
            .open(if panel.show_logs { Some(true) } else { None })
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .max_height(180.0)
                    .stick_to_bottom(true)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        if panel.logs.is_empty() {
                            ui.label(RichText::new("Nothing yet.").color(p.text_dim));
                        }
                        for l in &panel.logs {
                            let color = if l.stream == "stderr" {
                                s.warning
                            } else {
                                p.text_dim
                            };
                            ui.label(RichText::new(&l.text).monospace().size(11.5).color(color));
                        }
                    });
            });
        if header.header_response.clicked() {
            panel.show_logs = !was_open;
        }

        if use_it {
            self.use_for_assistant(config_path, ai);
        }
    }

    fn use_for_assistant(&mut self, config_path: Option<&PathBuf>, ai: &mut AiSettings) {
        let Some(panel) = self.panel.as_ref() else {
            return;
        };
        let Some(cfg) = panel.provider_config() else {
            self.notice = Some(Err("Wait until the model has finished loading.".into()));
            return;
        };
        let Some(path) = config_path else {
            self.notice = Some(Err(
                "There is no settings folder to save to (HOME is not set).".into(),
            ));
            return;
        };
        let store = ProviderStore::new(Some(path.clone()));
        if let Err(e) = store.write_config(path, &cfg) {
            self.notice = Some(Err(e));
            return;
        }
        match store.build(&cfg) {
            Ok(provider) => {
                ai.push_change(Change::Use(provider, badge_of(&cfg)));
                self.notice = Some(Ok("Saved. The assistant uses this model now.".into()));
            }
            Err(e) => {
                ai.push_change(Change::Problem(e.clone()));
                self.notice = Some(Err(format!("Saved, but it cannot be used yet: {e}")));
            }
        }
    }
}

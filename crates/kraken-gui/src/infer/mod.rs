//! The model card of Settings > AI: the models KRAKEN serves on this computer, one card each
//! (state, Start serving / Stop, "Serve automatically", the cards to run on, several-card
//! options, Remove).
//!
//! The logic is in `kraken_viewmodel::infer` (`card`, `ServingHub`, `LocalModelStore`); this
//! module draws it and owns the window's link to the serving service: the daemon connection of
//! this window, or, with `--no-daemon`, a manager in this process that stops its models on exit.
//! The window's lifetime holds the models marked "serve automatically".

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use egui::{RichText, Ui};
use kraken_host::infer::{Holder, InferManager, ModelStatus, ServingApi, StartOptions};
use kraken_proto::infer::{DeviceInfo, LocalModel, MultiGpuMode};
use kraken_viewmodel::DaemonClientBackend;
use kraken_viewmodel::infer::card::{self, Tone};
use kraken_viewmodel::infer::chips::{self, ChipAction, ChipBar};
use kraken_viewmodel::infer::external::ExternalWatch;
use kraken_viewmodel::infer::{BackendServing, LocalModelStore, ServingHub};
use tokio::runtime::Handle;

pub mod setup_dialog;

use crate::services::Mode;
use crate::style::{self, medium, pal};

/// Which service the hub is bound to, so a new daemon connection rebinds it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    Daemon(usize),
    Local,
    Fixed,
}

/// State of the cards.
#[derive(Default)]
pub struct InferSettings {
    hub: Option<ServingHub>,
    binding: Option<Binding>,
    manager: Option<Arc<InferManager>>,
    models: Vec<LocalModel>,
    models_loaded: bool,
    models_error: Option<String>,
    confirm_remove: Option<String>,
    removed: Option<String>,
    save_error: Option<String>,
    external: Option<ExternalWatch>,
    /// Chips were drawn last frame: keep the hub polling for them.
    chips_shown: bool,
}

impl InferSettings {
    /// Cards bound to a given service (tests, screenshots).
    pub fn with_service(api: Arc<dyn ServingApi>, rt: Handle) -> Self {
        InferSettings {
            hub: Some(ServingHub::new(api, rt)),
            binding: Some(Binding::Fixed),
            ..Default::default()
        }
    }

    /// Looks at the configuration again the next time a card is drawn.
    pub fn reload(&mut self) {
        self.models_loaded = false;
        self.reload_external();
    }

    /// The assistant's server may have changed: look at the configuration again.
    pub fn reload_external(&mut self) {
        if let Some(w) = self.external.as_mut() {
            w.reload();
        }
    }

    /// The window's view of the local models, for the title bar chips.
    pub fn hub(&self) -> Option<&ServingHub> {
        self.hub.as_ref()
    }

    /// The chips that fit in `budget` points, and keeps the hub polling while any is shown.
    pub fn chip_bar(&mut self, budget: f32) -> ChipBar {
        let (models, found) = self
            .hub
            .as_ref()
            .map_or_else(Default::default, |h| (h.models(), h.devices()));
        let external = self.external.as_ref().and_then(ExternalWatch::server);
        let bar = chips::chip_bar(&models, &found, external.as_ref(), budget);
        self.chips_shown = !bar.is_empty();
        bar
    }

    /// Does what a chip's button asks.
    pub fn chip_action(&mut self, key: &str, action: ChipAction) {
        if let Some(h) = self.hub.as_mut() {
            match action {
                ChipAction::Start => h.start(key, StartOptions::default()),
                ChipAction::Stop => h.stop(key),
            }
        }
    }

    fn ensure_models(&mut self, config_path: Option<&PathBuf>) {
        if self.models_loaded {
            return;
        }
        self.models_loaded = true;
        match LocalModelStore::new(config_path.cloned()).load() {
            Ok(m) => {
                self.models = m;
                self.models_error = None;
            }
            Err(e) => {
                self.models_error = Some(format!("The saved model list could not be read: {e}"));
            }
        }
    }

    /// The models set up, for the pickers.
    pub fn models(&mut self, config_path: Option<&PathBuf>) -> &[LocalModel] {
        self.ensure_models(config_path);
        &self.models
    }

    /// True once after "Set up a model on this computer..." was chosen.
    pub fn take_setup_request(&mut self) -> bool {
        self.hub
            .as_mut()
            .is_some_and(ServingHub::take_setup_request)
    }

    /// The service that runs the models (the guided setup starts the new model through it).
    pub fn serving(&self) -> Option<Arc<dyn ServingApi>> {
        self.hub.as_ref().map(ServingHub::api)
    }

    /// Asks for the guided setup (the picker's last entry).
    pub fn request_setup(&mut self) {
        if let Some(h) = self.hub.as_mut() {
            h.request_setup();
        }
    }

    /// The model removed since the last call, so a form that used it can let go of it.
    pub fn take_removed(&mut self) -> Option<String> {
        self.removed.take()
    }

    /// Stops the models this process runs (`--no-daemon`); a daemon's holds end with this
    /// window's connection.
    pub fn shutdown(&self, rt: &Handle) {
        if let Some(m) = &self.manager {
            let m = m.clone();
            kraken_assist::set_serving(None);
            rt.block_on(async move { m.shutdown().await });
        }
    }

    /// Binds to the serving service (once, or again after a reconnect), refreshes the models
    /// and lets the window hold the ones marked "serve automatically". Call every frame; with
    /// nothing to show it only listens when `watch` is true or a model is set up.
    pub fn frame(
        &mut self,
        ctx: &egui::Context,
        rt: &Handle,
        mode: Mode,
        backend: Option<&Arc<DaemonClientBackend>>,
        config_path: Option<&PathBuf>,
        watch: bool,
    ) {
        self.ensure_models(config_path);
        let w = self.external.get_or_insert_with(|| {
            let c = ctx.clone();
            ExternalWatch::new(rt.clone(), config_path.cloned())
                .with_repaint(Arc::new(move || c.request_repaint()))
        });
        let next = w.poll(Instant::now());
        if w.server().is_some() {
            ctx.request_repaint_after(next.max(std::time::Duration::from_millis(50)));
        }
        if !self.bind(ctx, rt, mode, backend) {
            return;
        }
        let unknown = self.hub.as_ref().is_some_and(|h| !h.loaded());
        if !(watch || self.chips_shown || unknown || !self.models.is_empty()) {
            return;
        }
        if let Some(h) = self.hub.as_mut() {
            let next = h.poll(Instant::now());
            ctx.request_repaint_after(next.max(std::time::Duration::from_millis(50)));
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
                None => return self.hub.is_some(),
            },
            Mode::NoDaemon => Binding::Local,
        };
        if self.binding == Some(Binding::Fixed)
            || (self.binding == Some(want) && self.hub.is_some())
        {
            return self.hub.is_some();
        }
        let c = ctx.clone();
        let repaint: Arc<dyn Fn() + Send + Sync> = Arc::new(move || c.request_repaint());
        let hub = match want {
            Binding::Daemon(_) => {
                let Some(b) = backend else { return false };
                let api: Arc<dyn ServingApi> = Arc::new(BackendServing(b.clone()));
                kraken_assist::set_serving(Some(api.clone()));
                ServingHub::new(api, rt.clone())
            }
            Binding::Local => {
                let m = self
                    .manager
                    .get_or_insert_with(|| Arc::new(InferManager::from_env()))
                    .clone();
                let held: Arc<dyn ServingApi> = Arc::new(m.holder(Holder::Owner));
                kraken_assist::set_serving(Some(held.clone()));
                ServingHub::new(held, rt.clone()).with_manager(m)
            }
            Binding::Fixed => return self.hub.is_some(),
        };
        self.hub = Some(hub.with_repaint(repaint));
        self.binding = Some(want);
        true
    }

    /// The "Not enough memory" question, when a start was refused. Call every frame.
    pub fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(hub) = self.hub.as_mut() else {
            return;
        };
        let Some(q) = hub.fit_prompt() else {
            return;
        };
        let mut answer = None;
        let mut cancel = false;
        egui::Window::new(medium("Not enough memory", 14.0))
            .id(egui::Id::new("kraken_fit_prompt"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.add(egui::Label::new(&q.message).wrap());
                ui.add_space(6.0);
                for o in &q.options {
                    if ui.button(o.label()).on_hover_text(o.help()).clicked() {
                        answer = Some(o.clone());
                    }
                }
                ui.add_space(4.0);
                if ui
                    .button("Cancel")
                    .on_hover_text("Do not start the model")
                    .clicked()
                {
                    cancel = true;
                }
            });
        if let Some(o) = answer {
            hub.answer_fit(&o);
        } else if cancel
            || ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            hub.cancel_fit();
        }
    }

    /// Draws the card of the model `id`. `scope` keeps the widget ids apart when two cards
    /// of the same model are on screen (assistant and rewriting).
    pub fn card(&mut self, ui: &mut Ui, scope: &str, id: &str, config_path: Option<&PathBuf>) {
        self.ensure_models(config_path);
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        if let Some(e) = &self.models_error {
            ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
        }
        let Some(idx) = self.models.iter().position(|m| m.id == id) else {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "The model `{id}` is not set up on this computer (any more). Pick another one, or set one up."
                    ))
                    .color(s.warning),
                )
                .wrap(),
            );
            return;
        };
        let Some(hub) = self.hub.as_mut() else {
            ui.label(RichText::new("Connecting to krakend...").color(p.text_dim));
            return;
        };
        let found = hub.devices();
        let status = hub.status(id);
        let busy = hub.busy(id);
        let mut model = self.models[idx].clone();
        let before = model.clone();
        let mut start = false;
        let mut stop = false;
        let mut remove = false;
        let mut start_over = false;

        ui.push_id((scope, id), |ui| {
            status_block(ui, &p, &s, status.as_ref(), &found, busy, &mut start, &mut stop);
            if let Some(e) = hub.error() {
                ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
            }
            ui.add_space(4.0);
            ui.checkbox(&mut model.autostart, "Serve automatically when KRAKEN opens")
                .on_hover_text(
                    "KRAKEN starts this model when it opens and stops it when it closes",
                );
            ui.label(
                RichText::new("Unchecked: it only starts when you press Start serving.")
                    .size(11.5)
                    .color(p.text_dim),
            );
            ui.add_space(4.0);
            run_on(ui, &p, &mut model, &found);
            if card::several_cards(&model, &found) {
                several(ui, &p, &mut model);
            }
            advanced(ui, &p, &mut model, &found);
            if model != before && status.as_ref().is_some_and(ModelStatus::is_running) {
                start_over = true;
            }
            if start_over {
                ui.label(
                    RichText::new("Stop and start the model again to use these choices.")
                        .size(11.5)
                        .color(s.warning),
                );
            }
            ui.add_space(4.0);
            if self.confirm_remove.as_deref() == Some(id) {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(
                            "Remove it from KRAKEN? It stops serving. The downloaded files stay on your disk.",
                        )
                        .size(12.0),
                    );
                    if ui
                        .button("Remove")
                        .on_hover_text("Remove this model from the list")
                        .clicked()
                    {
                        remove = true;
                    }
                    if ui
                        .button("Keep it")
                        .on_hover_text("Keep the model")
                        .clicked()
                    {
                        self.confirm_remove = None;
                    }
                });
            } else if ui
                .button("Remove this model")
                .on_hover_text("Take this model out of the list. The downloaded files stay on your disk")
                .clicked()
            {
                self.confirm_remove = Some(id.to_string());
            }
        });

        if start {
            hub.start(id, StartOptions::default());
        }
        if stop {
            hub.stop(id);
        }
        if remove {
            if status.as_ref().is_some_and(ModelStatus::is_running) {
                hub.stop(id);
            }
            match LocalModelStore::new(config_path.cloned()).remove(id) {
                Ok(()) => {
                    self.confirm_remove = None;
                    self.removed = Some(id.to_string());
                    self.models.remove(idx);
                    self.save_error = None;
                }
                Err(e) => self.save_error = Some(e),
            }
            hub.refresh();
        } else if model != before {
            match LocalModelStore::new(config_path.cloned()).update(&model) {
                Ok(()) => {
                    self.models[idx] = model;
                    self.save_error = None;
                }
                Err(e) => self.save_error = Some(e),
            }
            hub.refresh();
        }
        if let Some(e) = &self.save_error {
            ui.add(egui::Label::new(RichText::new(e).size(12.0).color(s.danger)).wrap());
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn status_block(
    ui: &mut Ui,
    p: &kraken_gui_widgets::Palette,
    s: &style::Status,
    status: Option<&ModelStatus>,
    found: &[DeviceInfo],
    busy: bool,
    start: &mut bool,
    stop: &mut bool,
) {
    let line = card::status_line(status, found);
    let color = match line.tone {
        Tone::Neutral => p.text,
        Tone::Good => s.success,
        Tone::Warn => s.warning,
        Tone::Bad => s.danger,
    };
    let running = status.is_some_and(ModelStatus::is_running);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Status").color(p.text_dim));
        if busy || matches!(line.tone, Tone::Warn) {
            ui.spinner();
        }
        ui.label(RichText::new(&line.text).color(color));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if running {
                if ui
                    .add_enabled(!busy, egui::Button::new("Stop serving"))
                    .on_hover_text("Stop the model and free its memory")
                    .on_disabled_hover_text(
                        "Wait until the model has finished starting or stopping",
                    )
                    .clicked()
                {
                    *stop = true;
                }
            } else if ui
                .add_enabled(
                    status.is_some() && !busy,
                    egui::Button::new("Start serving"),
                )
                .on_hover_text("Start the model now and keep it running until you stop it")
                .on_disabled_hover_text("Waiting for krakend, or the model is starting or stopping")
                .clicked()
            {
                *start = true;
            }
        });
    });
    if let Some(f) = &line.figures {
        ui.label(RichText::new(f).size(12.0).color(p.text_dim));
    }
    for n in &line.notes {
        ui.add(egui::Label::new(RichText::new(n).size(11.5).color(s.warning)).wrap());
    }
}

pub(crate) fn run_on(
    ui: &mut Ui,
    p: &kraken_gui_widgets::Palette,
    model: &mut LocalModel,
    found: &[DeviceInfo],
) {
    ui.label(medium("Run on", 13.0).color(p.text_strong));
    for row in card::device_rows(model, found) {
        let mut on = row.checked;
        ui.horizontal(|ui| {
            let r = ui.add_enabled(
                row.unusable.is_none(),
                egui::Checkbox::new(&mut on, &row.label),
            );
            match &row.unusable {
                Some(why) => {
                    r.on_disabled_hover_text(why.clone());
                    ui.label(
                        RichText::new(format!("\u{b7} {why}"))
                            .size(11.5)
                            .color(p.text_dim),
                    );
                }
                None => {
                    r.on_hover_text("Run the model on this card");
                }
            }
        });
        if on != row.checked {
            card::set_device(model, found, &row.device, on);
        }
    }
    if card::cpu_allowed(model) {
        let mut cpu = card::cpu_checked(model, found);
        let before = cpu;
        ui.checkbox(&mut cpu, "CPU only (much slower)")
            .on_hover_text("Run on the processor and the computer's memory, without a card");
        if cpu != before {
            card::set_cpu_only(model, found, cpu);
        }
    }
    ui.add(
        egui::Label::new(
            RichText::new(
                "KRAKEN found these on this computer. Video memory (VRAM) is the memory on the graphics card. The model runs fastest when it fits there.",
            )
            .size(11.5)
            .color(p.text_dim),
        )
        .wrap(),
    );
}

pub(crate) fn several(ui: &mut Ui, p: &kraken_gui_widgets::Palette, model: &mut LocalModel) {
    ui.add_space(4.0);
    ui.label(medium("How to use several cards", 13.0).color(p.text_strong));
    for o in card::mode_options(model.engine) {
        let mut mode: MultiGpuMode = model.multi_gpu;
        ui.radio_value(&mut mode, o.mode, o.title)
            .on_hover_text(o.help);
        ui.label(RichText::new(o.help).size(11.5).color(p.text_dim));
        if mode != model.multi_gpu {
            card::set_mode(model, mode);
        }
    }
}

fn advanced(
    ui: &mut Ui,
    p: &kraken_gui_widgets::Palette,
    model: &mut LocalModel,
    found: &[DeviceInfo],
) {
    let chosen = card::effective_devices(model, found);
    if chosen.len() < 2 {
        return;
    }
    egui::CollapsingHeader::new("Advanced: share per card, main card")
        .id_salt("kraken_card_advanced")
        .show(ui, |ui| {
            let names: Vec<String> = chosen
                .iter()
                .map(|c| {
                    found
                        .iter()
                        .find(|d| d.index == c.index && d.uuid == c.uuid)
                        .map_or_else(|| format!("card {}", c.index), |d| d.name.clone())
                })
                .collect();
            ui.label(
                RichText::new("How much of the model each card holds (percent).")
                    .size(11.5)
                    .color(p.text_dim),
            );
            let mut shares = card::shares(model, found);
            for (i, name) in names.iter().enumerate() {
                let before = shares[i];
                ui.horizontal(|ui| {
                    ui.label(name);
                    ui.add(egui::Slider::new(&mut shares[i], 1..=99).suffix("%"))
                        .on_hover_text("Share of the model on this card");
                });
                if shares[i] != before {
                    card::set_share(model, found, i, shares[i]);
                }
            }
            ui.label(RichText::new("Main card").size(12.0).color(p.text_dim));
            let mut main = model.main_device.as_ref().and_then(|m| {
                chosen
                    .iter()
                    .position(|c| c.uuid == m.uuid && c.index == m.index)
            });
            let before = main;
            ui.horizontal(|ui| {
                ui.radio_value(&mut main, None, "Let the engine choose")
                    .on_hover_text("The engine picks the main card");
                for (i, name) in names.iter().enumerate() {
                    ui.radio_value(&mut main, Some(i), name)
                        .on_hover_text("Keep the small shared parts of the model on this card");
                }
            });
            if main != before {
                card::set_main(model, found, main.map(|i| &chosen[i]));
            }
        });
}

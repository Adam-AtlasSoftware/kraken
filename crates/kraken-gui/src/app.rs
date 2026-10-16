//! The eframe application: owns the view-model and draws the welcome screen or the workspace.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Frame, Key, Margin, Modifiers, Ui, ViewportCommand};
use egui_dock::DockState;
use kraken_gui_widgets::KrakenTheme;
use kraken_registry::EngineFactory;
use kraken_viewmodel::demo::demo_project;
use kraken_viewmodel::{AnalysisPhase, Connection, InProcessBackend, Load, UiRequest, ViewModel};
use tokio::runtime::Runtime;

use crate::args::{Options, Scene};
use crate::welcome::{self, Choice, Welcome, default_project_dir};
use crate::workspace::{self, Tab, UiState};
use crate::{chrome, overlays};

const SCREENSHOT_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ShotStage {
    Loading,
    Selecting,
    Editing,
    Settling,
    Waiting,
}

struct Shot {
    scene: Scene,
    path: PathBuf,
    stage: ShotStage,
    settle: u32,
    started: Instant,
}

pub struct KrakenApp {
    rt: Arc<Runtime>,
    factory: Option<Arc<dyn EngineFactory>>,
    vm: Option<ViewModel>,
    welcome: Welcome,
    dock: DockState<Tab>,
    state: UiState,
    theme: KrakenTheme,
    applied: Option<KrakenTheme>,
    rename_focus: Option<u64>,
    auto_analyze: bool,
    shot: Option<Shot>,
}

impl KrakenApp {
    pub fn new(
        ctx: &egui::Context,
        rt: Arc<Runtime>,
        factory: Option<Arc<dyn EngineFactory>>,
        opts: &Options,
    ) -> Self {
        let mut app = KrakenApp {
            rt,
            factory,
            vm: None,
            welcome: Welcome::default(),
            dock: workspace::initial_dock(),
            state: UiState::default(),
            theme: if opts.light {
                KrakenTheme::LIGHT
            } else {
                KrakenTheme::DARK
            },
            applied: None,
            rename_focus: None,
            auto_analyze: false,
            shot: opts.screenshot.clone().map(|path| Shot {
                scene: opts.scene,
                path,
                stage: if opts.scene == Scene::Welcome {
                    ShotStage::Settling
                } else {
                    ShotStage::Loading
                },
                settle: 0,
                started: Instant::now(),
            }),
        };
        if opts.demo {
            app.start_demo(ctx);
        }
        app
    }

    /// The view-model, if a project is open or opening.
    #[cfg(test)]
    pub fn view_model(&self) -> Option<&ViewModel> {
        self.vm.as_ref()
    }

    #[cfg(test)]
    pub fn view_model_mut(&mut self) -> Option<&mut ViewModel> {
        self.vm.as_mut()
    }

    #[cfg(test)]
    pub fn theme(&self) -> KrakenTheme {
        self.theme
    }

    #[cfg(test)]
    pub fn welcome_error(&self) -> Option<&str> {
        self.welcome.error.as_deref()
    }

    #[cfg(test)]
    pub fn pending_nav(&mut self) -> &mut UiState {
        &mut self.state
    }

    fn new_vm(
        &mut self,
        backend: Arc<dyn kraken_viewmodel::Backend>,
        ctx: &egui::Context,
    ) -> ViewModel {
        let mut vm = ViewModel::new(backend, self.rt.handle().clone());
        let ctx = ctx.clone();
        vm.set_repaint(Arc::new(move || ctx.request_repaint()));
        vm
    }

    pub fn start_demo(&mut self, ctx: &egui::Context) {
        match demo_project() {
            Ok(d) => {
                let mut vm = self.new_vm(d.backend, ctx);
                vm.create_project(
                    d.binary.to_string_lossy().into_owned(),
                    d.project_dir.to_string_lossy().into_owned(),
                );
                self.vm = Some(vm);
                self.auto_analyze = true;
                self.welcome.error = None;
                self.welcome.busy = Some("Opening the demo project...".into());
            }
            Err(e) => self.welcome.error = Some(format!("Could not set up the demo: {e}")),
        }
    }

    pub(crate) fn start_real(&mut self, choice: Choice, ctx: &egui::Context) {
        let Some(factory) = self.factory.clone() else {
            self.welcome.error = Some(
                "The analysis engine is not connected in this build yet, so real programs cannot be opened. The demo project works today."
                    .into(),
            );
            return;
        };
        let backend = Arc::new(InProcessBackend::new(factory));
        let mut vm = self.new_vm(backend, ctx);
        match choice {
            Choice::OpenProject(dir) => vm.open_project(dir),
            Choice::NewProject(bin) => {
                let dir = default_project_dir(&bin);
                vm.create_project(bin, dir);
            }
            Choice::Demo => return,
        }
        self.vm = Some(vm);
        self.welcome.error = None;
        self.welcome.busy = Some("Opening...".into());
    }

    fn step_vm(&mut self, ctx: &egui::Context) {
        let Some(vm) = self.vm.as_mut() else {
            return;
        };
        if vm.poll() {
            ctx.request_repaint();
        }
        match vm.connection.clone() {
            Connection::Failed(msg) => {
                self.welcome.error = Some(msg);
                self.welcome.busy = None;
                self.vm = None;
            }
            Connection::Opening(msg) => self.welcome.busy = Some(msg),
            Connection::Open => {
                self.welcome.busy = None;
                if self.auto_analyze {
                    self.auto_analyze = false;
                    vm.start_analysis();
                }
                self.state.flush_pending_nav(vm, ctx);
            }
            Connection::NoProject => {}
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context, reqs: &mut Vec<UiRequest>) {
        let Some(vm) = self
            .vm
            .as_mut()
            .filter(|v| v.connection == Connection::Open)
        else {
            return;
        };
        let (palette_a, palette_b, back, fwd, filter) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::P),
                i.consume_key(Modifiers::COMMAND, Key::K),
                i.consume_key(Modifiers::ALT, Key::ArrowLeft),
                i.consume_key(Modifiers::ALT, Key::ArrowRight),
                i.consume_key(Modifiers::COMMAND, Key::L),
            )
        });
        if palette_a || palette_b {
            if vm.palette.open {
                vm.close_palette();
            } else {
                vm.open_palette();
            }
        }
        if vm.palette.open {
            return;
        }
        if back {
            vm.go_back();
        }
        if fwd {
            vm.go_forward();
        }
        if filter {
            reqs.push(UiRequest::FocusFunctionFilter);
        }
    }

    pub(crate) fn handle(&mut self, r: UiRequest, ctx: &egui::Context) {
        match r {
            UiRequest::ToggleTheme => self.theme.dark = !self.theme.dark,
            UiRequest::FocusFunctionFilter => self.state.focus_filter = true,
            UiRequest::ShowHistory => self.state.bring_to_front = Some(Tab::History),
            UiRequest::ShowProposals => self.state.bring_to_front = Some(Tab::Proposals),
            UiRequest::OpenProject | UiRequest::NewProject => {
                self.vm = None;
                self.welcome.error = None;
                self.welcome.busy = None;
            }
            UiRequest::OpenDemo => self.start_demo(ctx),
        }
    }

    /// Draws one frame. Separate from `eframe::App::ui` so tests can drive it headlessly.
    pub fn frame(&mut self, ui: &mut Ui) {
        let ctx = ui.ctx().clone();
        if self.applied != Some(self.theme) {
            self.theme.apply(&ctx);
            self.applied = Some(self.theme);
        }
        self.step_vm(&ctx);
        let mut reqs: Vec<UiRequest> = Vec::new();
        self.shortcuts(&ctx, &mut reqs);
        let pal = self.theme.palette();

        let open = self
            .vm
            .as_ref()
            .is_some_and(|v| v.connection == Connection::Open);
        if let Some(vm) = self.vm.as_mut().filter(|_| open) {
            egui::Panel::top("kraken_top")
                .frame(
                    Frame::new()
                        .fill(pal.bg)
                        .inner_margin(Margin::symmetric(14, 6)),
                )
                .exact_size(44.0)
                .show(ui, |ui| chrome::top_bar(ui, vm, &mut reqs));
            egui::Panel::bottom("kraken_status")
                .frame(
                    Frame::new()
                        .fill(pal.bg)
                        .inner_margin(Margin::symmetric(14, 4)),
                )
                .exact_size(28.0)
                .show(ui, |ui| chrome::status_bar(ui, vm));
            egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.bg).inner_margin(6))
                .show(ui, |ui| {
                    workspace::show(ui, &mut self.dock, vm, &mut self.state)
                });
            overlays::palette(&ctx, vm, &mut reqs);
            overlays::rename_dialog(&ctx, vm, &mut self.rename_focus);
            overlays::comment_dialog(&ctx, vm);
            chrome::toasts(&ctx, vm);
            if !vm.toasts.is_empty() {
                ctx.request_repaint_after(Duration::from_millis(400));
            }
        } else {
            let choice = egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.bg).inner_margin(24))
                .show(ui, |ui| {
                    welcome::show(ui, &mut self.welcome, self.rt.handle())
                })
                .inner;
            match choice {
                Some(Choice::Demo) => self.start_demo(&ctx),
                Some(c) => self.start_real(c, &ctx),
                None => {}
            }
        }
        for r in reqs {
            self.handle(r, &ctx);
        }
        self.drive_screenshot(&ctx);
    }

    fn drive_screenshot(&mut self, ctx: &egui::Context) {
        let Some(shot) = self.shot.as_mut() else {
            return;
        };
        ctx.request_repaint();
        if shot.started.elapsed() > SCREENSHOT_TIMEOUT {
            eprintln!("kraken-gui: screenshot timed out in stage {:?}", shot.stage);
            std::process::exit(1);
        }
        let image = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = image {
            let rgba: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
            let [w, h] = img.size;
            if let Some(dir) = shot.path.parent().filter(|d| !d.as_os_str().is_empty()) {
                let _ = std::fs::create_dir_all(dir);
            }
            match image::save_buffer(
                &shot.path,
                &rgba,
                w as u32,
                h as u32,
                image::ColorType::Rgba8,
            ) {
                Ok(()) => println!("screenshot saved: {} ({w}x{h})", shot.path.display()),
                Err(e) => {
                    eprintln!("kraken-gui: could not save the screenshot: {e}");
                    std::process::exit(1);
                }
            }
            ctx.send_viewport_cmd(ViewportCommand::Close);
            return;
        }
        if shot.stage == ShotStage::Settling && shot.scene == Scene::Welcome {
            shot.settle += 1;
            if shot.settle > 6 {
                ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
                shot.stage = ShotStage::Waiting;
            }
            return;
        }
        let Some(vm) = self.vm.as_mut() else {
            return;
        };
        match shot.stage {
            ShotStage::Loading => {
                if vm.connection == Connection::Open
                    && vm.analysis.phase == AnalysisPhase::Complete
                    && !vm.busy()
                    && let Some(main) = vm.functions.items.iter().find(|f| f.name == "main")
                {
                    let addr = main.address;
                    self.state.initial_highlight = Some("helper".into());
                    vm.select_function(addr);
                    shot.stage = ShotStage::Selecting;
                }
            }
            ShotStage::Selecting => {
                let ready = vm
                    .current
                    .as_ref()
                    .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)));
                if ready && !vm.busy() {
                    // One real edit so the History tab has something to show.
                    vm.begin_rename(0x401340, Some("FUN_00401340"));
                    vm.set_rename_input("fatal_out_of_memory");
                    vm.submit_rename();
                    shot.stage = ShotStage::Editing;
                }
            }
            ShotStage::Editing => {
                if vm.rename.as_ref().is_some_and(|r| r.error.is_some()) {
                    vm.cancel_rename();
                }
                if vm.rename.is_none() && !vm.busy() {
                    shot.stage = ShotStage::Settling;
                }
            }
            ShotStage::Settling => {
                shot.settle += 1;
                if shot.settle == 12 {
                    // Keep only the newest notification so the picture stays readable.
                    let ids: Vec<u64> = vm.toasts.iter().rev().skip(1).map(|t| t.id).collect();
                    for id in ids {
                        vm.dismiss_toast(id);
                    }
                    match shot.scene {
                        Scene::Palette => {
                            vm.open_palette();
                            vm.palette.set_query("ren");
                        }
                        Scene::Rename => vm.begin_rename_current(),
                        _ => {}
                    }
                }
                if shot.settle > 18 && !vm.busy() {
                    ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
                    shot.stage = ShotStage::Waiting;
                }
            }
            ShotStage::Waiting => {}
        }
    }
}

impl eframe::App for KrakenApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}

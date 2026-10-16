//! The eframe application: owns the view-model and draws the welcome screen or the workspace.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant};

use egui::{Frame, Key, Margin, Modifiers, Ui, ViewportCommand};
use egui_dock::DockState;
use kraken_gui_widgets::KrakenTheme;
use kraken_host::ManagedFactory;
use kraken_viewmodel::demo::demo_project;
use kraken_viewmodel::{
    AnalysisPhase, ApprovalBroker, Backend, BackendOptions, Connection, DaemonClientBackend,
    InProcessBackend, Load, UiRequest, ViewModel,
};
use tokio::runtime::Runtime;

use crate::agents;
use crate::args::{Options, Scene};
use crate::assist::{self, AssistRequest, AssistSetup, Change};
use crate::recent::{self, Prefs};
use crate::services::{Mode, Services};
use crate::settings::{Settings, SettingsAction, SettingsEnv};
use crate::welcome::{self, Choice, Welcome, WelcomeAction};
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

/// The connection to `krakend`, made when a real project is first needed.
enum Slot {
    Idle,
    Connecting(Receiver<Result<Arc<DaemonClientBackend>, String>>),
    Ready(Arc<DaemonClientBackend>),
    Failed(String),
}

struct Shot {
    /// A real project opened with `--open-project` instead of the demo.
    real: bool,
    scene: Scene,
    path: PathBuf,
    stage: ShotStage,
    settle: u32,
    started: Instant,
}

pub struct KrakenApp {
    rt: Arc<Runtime>,
    services: Services,
    slot: Slot,
    /// What to do once the daemon connection is up.
    pending: Option<Choice>,
    approvals: ApprovalBroker,
    /// The AI model in use, kept across projects.
    assist: AssistSetup,
    settings: Settings,
    prefs: Prefs,
    /// The open project is the demo (not worth remembering).
    is_demo: bool,
    /// The open project was added to the recent list.
    recorded: bool,
    vm: Option<ViewModel>,
    welcome: Welcome,
    dock: DockState<Tab>,
    state: UiState,
    theme: KrakenTheme,
    applied: Option<KrakenTheme>,
    rename_focus: Option<u64>,
    auto_analyze: bool,
    /// Function a screenshot selects instead of `main`.
    function: Option<String>,
    shot: Option<Shot>,
}

impl KrakenApp {
    pub fn new(ctx: &egui::Context, rt: Arc<Runtime>, services: Services, opts: &Options) -> Self {
        let prefs = Prefs::load(services.prefs_file.clone());
        let dark = if opts.light {
            false
        } else {
            prefs.dark().unwrap_or(true)
        };
        let approvals = ApprovalBroker::new();
        {
            let ctx = ctx.clone();
            approvals.set_repaint(Arc::new(move || ctx.request_repaint()));
        }
        let mut app = KrakenApp {
            rt,
            slot: Slot::Idle,
            pending: None,
            approvals,
            assist: AssistSetup::load(services.config_path.clone()),
            settings: Settings::default(),
            prefs,
            is_demo: false,
            recorded: false,
            vm: None,
            welcome: Welcome::new(services.cfg.clone()),
            services,
            dock: agents::with_agents_tab(assist::with_assistant_tab(workspace::initial_dock())),
            state: UiState::default(),
            theme: if dark {
                KrakenTheme::DARK
            } else {
                KrakenTheme::LIGHT
            },
            applied: None,
            rename_focus: None,
            auto_analyze: false,
            function: opts.function.clone(),
            shot: opts.screenshot.clone().map(|path| Shot {
                real: opts.open_project.is_some(),
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
        if opts.screenshot.is_some()
            && let Some((p, b)) = assist::provider_for(opts.scene)
        {
            app.assist.set(p, b);
        }
        if opts.demo {
            app.start_demo(ctx);
        } else if let Some(dir) = &opts.open_project {
            app.start_real(Choice::OpenProject(dir.to_string_lossy().into_owned()), ctx);
            // Screenshot runs analyze a project that has not been analyzed yet.
            app.auto_analyze = opts.screenshot.is_some();
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
    pub fn dock(&self) -> &DockState<Tab> {
        &self.dock
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

    #[cfg(test)]
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    #[cfg(test)]
    pub fn prefs(&self) -> &Prefs {
        &self.prefs
    }

    #[cfg(test)]
    pub fn assist_setup(&self) -> &AssistSetup {
        &self.assist
    }

    #[cfg(test)]
    pub fn approvals(&self) -> &ApprovalBroker {
        &self.approvals
    }

    fn new_vm(
        &mut self,
        backend: Arc<dyn kraken_viewmodel::Backend>,
        ctx: &egui::Context,
    ) -> ViewModel {
        let mut vm = ViewModel::new(backend, self.rt.handle().clone());
        let ctx = ctx.clone();
        vm.set_repaint(Arc::new(move || ctx.request_repaint()));
        self.assist.apply(&mut vm);
        if self.shot.as_ref().is_some_and(|s| s.scene == Scene::Agents) {
            // The scripted agent of the screenshot, with the warning counted as read.
            if let Some(cfg) = agents::scene_config() {
                vm.agents_configure(cfg);
            }
            vm.agents.notice.acknowledged = true;
        } else if let Some(cfg) = self.services.agents.clone() {
            vm.agents_configure(cfg);
        }
        vm
    }

    pub fn start_demo(&mut self, ctx: &egui::Context) {
        match demo_project() {
            Ok(d) => {
                let mut vm = self.new_vm(d.backend, ctx);
                // The demo's engine lives in this process, so an agent cannot join it.
                vm.agents_set_daemon(false);
                vm.create_project(
                    d.binary.to_string_lossy().into_owned(),
                    d.project_dir.to_string_lossy().into_owned(),
                );
                self.vm = Some(vm);
                self.auto_analyze = true;
                self.is_demo = true;
                self.recorded = false;
                self.welcome.error = None;
                self.welcome.busy = Some("Opening the demo project...".into());
            }
            Err(e) => self.welcome.error = Some(format!("Could not set up the demo: {e}")),
        }
    }

    /// Opens or creates a real project through the daemon (or in-process with `--no-daemon`).
    pub(crate) fn start_real(&mut self, choice: Choice, ctx: &egui::Context) {
        self.welcome.error = None;
        match self.services.mode {
            Mode::NoDaemon => {
                let Some(factory) = self.services.ghidra.clone() else {
                    self.welcome.error = Some("The in-process engine is not available.".into());
                    return;
                };
                let backend = InProcessBackend::new(factory);
                backend.set_approver(Arc::new(self.approvals.clone()));
                self.launch(choice, Arc::new(backend), ctx);
            }
            Mode::Daemon => {
                if let Slot::Failed(_) = self.slot {
                    self.slot = Slot::Idle;
                }
                if let Slot::Ready(b) = &self.slot {
                    let backend = b.clone();
                    self.launch(choice, backend, ctx);
                } else {
                    self.pending = Some(choice);
                    self.connect_daemon(ctx);
                    self.welcome.busy = Some("Starting the analysis engine...".into());
                }
            }
        }
    }

    fn connect_daemon(&mut self, ctx: &egui::Context) {
        if matches!(self.slot, Slot::Connecting(_) | Slot::Ready(_)) {
            return;
        }
        let (tx, rx) = channel();
        let connector = self.services.connector();
        let ctx = ctx.clone();
        self.rt.spawn(async move {
            let r = DaemonClientBackend::connect(connector, BackendOptions::default())
                .await
                .map(Arc::new);
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.slot = Slot::Connecting(rx);
    }

    fn poll_daemon(&mut self, ctx: &egui::Context) {
        let Slot::Connecting(rx) = &self.slot else {
            return;
        };
        let outcome = match rx.try_recv() {
            Ok(r) => r,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("the connection attempt was dropped".into()),
        };
        match outcome {
            Ok(backend) => {
                backend.set_approver(Arc::new(self.approvals.clone()));
                self.slot = Slot::Ready(backend.clone());
                if let Some(choice) = self.pending.take() {
                    self.launch(choice, backend, ctx);
                }
            }
            Err(e) => {
                self.slot = Slot::Failed(e.clone());
                if self.pending.take().is_some() {
                    self.welcome.busy = None;
                    self.welcome.error = Some(format!(
                        "Could not reach the analysis engine (krakend): {e}. Run `kraken daemon start` to see why, or start the GUI with --no-daemon."
                    ));
                }
            }
        }
    }

    fn launch(&mut self, choice: Choice, backend: Arc<dyn Backend>, ctx: &egui::Context) {
        let mut vm = self.new_vm(backend, ctx);
        match choice {
            Choice::OpenProject(dir) => vm.open_project(dir),
            Choice::NewProject {
                binary,
                project_dir,
            } => {
                vm.create_project(binary, project_dir);
                self.auto_analyze = true;
            }
            Choice::Demo => return,
        }
        self.vm = Some(vm);
        self.is_demo = false;
        self.recorded = false;
        self.welcome.error = None;
        self.welcome.busy = Some("Opening...".into());
    }

    fn step_vm(&mut self, ctx: &egui::Context) {
        self.poll_daemon(ctx);
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
                    if vm.analysis.phase == AnalysisPhase::NotStarted {
                        vm.start_analysis();
                    }
                }
                if !self.recorded
                    && !self.is_demo
                    && let Some(info) = &vm.project
                {
                    self.recorded = true;
                    self.prefs
                        .touch(&info.project_dir, &info.name, recent::now_ms());
                }
                self.state.flush_pending_nav(vm, ctx);
            }
            Connection::NoProject => {}
        }
    }

    fn shortcuts(&mut self, ctx: &egui::Context, reqs: &mut Vec<UiRequest>) {
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Comma)) {
            self.settings.toggle();
        }
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
            UiRequest::OpenSettings => self.settings.show_window(),
        }
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let backend = match &self.slot {
            Slot::Ready(b) => Some(b),
            _ => None,
        };
        let env = SettingsEnv {
            rt: self.rt.handle(),
            mode: self.services.mode,
            dark: self.theme.dark,
            config_path: self.services.config_path.as_ref(),
            backend,
            connecting: matches!(self.slot, Slot::Connecting(_)),
            connect_error: match &self.slot {
                Slot::Failed(e) => Some(e.as_str()),
                _ => None,
            },
        };
        for a in self.settings.show(ctx, &env) {
            match a {
                SettingsAction::SetDark(dark) => {
                    self.theme.dark = dark;
                    self.prefs.set_dark(dark);
                }
                SettingsAction::ConnectDaemon => self.connect_daemon(ctx),
            }
        }
        if let Some(change) = self.settings.ai.take_change() {
            match change {
                Change::Use(p, b) => self.assist.set(p, b),
                Change::Clear => self.assist.clear(),
                Change::Problem(why) => self.assist.set_problem(why),
            }
            if let Some(vm) = self.vm.as_mut() {
                self.assist.apply(vm);
            }
        }
    }

    /// Runs what the assistant panels asked for: one-click presets and opening the AI settings.
    fn assist_requests(&mut self) {
        for r in std::mem::take(&mut self.state.assist.requests) {
            match r {
                AssistRequest::UsePreset(kind) => {
                    if let Err(e) = self.assist.use_preset(kind) {
                        self.assist.set_problem(e);
                    }
                }
                AssistRequest::OpenSettings(kind) => {
                    self.settings.show_window();
                    if let Some(k) = kind {
                        self.settings.ai.preset(k);
                    }
                }
            }
            if let Some(vm) = self.vm.as_mut() {
                self.assist.apply(vm);
            }
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
            crate::history::dialog(&ctx, vm);
            chrome::toasts(&ctx, vm);
            assist::overlays(&ctx, vm, &mut self.state.assist);
            if !vm.toasts.is_empty() || vm.link != kraken_viewmodel::LinkState::Connected {
                ctx.request_repaint_after(Duration::from_millis(400));
            }
        } else {
            let actions = egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.bg).inner_margin(24))
                .show(ui, |ui| {
                    welcome::show(
                        ui,
                        &mut self.welcome,
                        self.rt.handle(),
                        self.prefs.items(),
                        recent::now_ms(),
                    )
                })
                .inner;
            for a in actions {
                match a {
                    WelcomeAction::Choose(Choice::Demo) => self.start_demo(&ctx),
                    WelcomeAction::Choose(c) => self.start_real(c, &ctx),
                    WelcomeAction::Forget(path) => self.prefs.remove(&path),
                    WelcomeAction::Settings => self.settings.show_window(),
                }
            }
        }
        for r in reqs {
            self.handle(r, &ctx);
        }
        self.assist_requests();
        self.settings_window(&ctx);
        overlays::approval_dialog(&ctx, &self.approvals);
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
                {
                    let wanted = self.function.as_deref().unwrap_or("main");
                    let pick = vm
                        .functions
                        .items
                        .iter()
                        .find(|f| f.name == wanted)
                        .or_else(|| vm.functions.items.first().filter(|_| shot.real))
                        .map(|f| f.address);
                    if let Some(addr) = pick {
                        if !shot.real {
                            self.state.initial_highlight = Some("helper".into());
                        }
                        vm.select_function(addr);
                        shot.stage = ShotStage::Selecting;
                    }
                }
            }
            ShotStage::Selecting => {
                let ready = vm
                    .current
                    .as_ref()
                    .is_some_and(|c| matches!(c.decompiled, Load::Ready(_)));
                if ready && !vm.busy() {
                    // One real edit so the History tab has something to show.
                    if shot.real {
                        let target = vm
                            .functions
                            .items
                            .iter()
                            .find(|f| f.name.starts_with("FUN_") && Some(f.address) != vm.selected)
                            .map(|f| (f.address, f.name.clone()));
                        if let Some((addr, name)) = target {
                            vm.begin_rename(addr, Some(&name));
                            vm.set_rename_input("dispatch_command");
                            vm.submit_rename();
                            shot.stage = ShotStage::Editing;
                        } else {
                            shot.stage = ShotStage::Settling;
                        }
                    } else if matches!(shot.scene, Scene::AutoName | Scene::Agents) {
                        // Leave the placeholder names alone so there is something to suggest.
                        shot.stage = ShotStage::Settling;
                    } else {
                        vm.begin_rename(0x401340, Some("FUN_00401340"));
                        vm.set_rename_input("fatal_out_of_memory");
                        vm.submit_rename();
                        shot.stage = ShotStage::Editing;
                    }
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
                    let keep = usize::from(!matches!(
                        shot.scene,
                        Scene::Assistant | Scene::Explain | Scene::AutoName | Scene::Agents
                    ));
                    let ids: Vec<u64> = vm.toasts.iter().rev().skip(keep).map(|t| t.id).collect();
                    for id in ids {
                        vm.dismiss_toast(id);
                    }
                    match shot.scene {
                        Scene::Palette => {
                            vm.open_palette();
                            vm.palette.set_query("ren");
                        }
                        Scene::Rename => vm.begin_rename_current(),
                        Scene::Graph => self.dock = workspace::graph_dock(),
                        Scene::Assistant => {
                            self.dock = agents::scene_dock(Tab::Assistant);
                            vm.assist_send(assist::CHAT_QUESTION);
                        }
                        Scene::Explain => {
                            self.dock = agents::scene_dock(Tab::Assistant);
                            vm.assist_explain_function(0x4011a0);
                        }
                        Scene::AutoName => vm.assist_auto_name(10),
                        Scene::Agents => {
                            self.dock = agents::scene_dock(Tab::Agents);
                            self.state.bring_to_front = Some(Tab::Agents);
                        }
                        _ => {}
                    }
                    vm.assist_dismiss_offer();
                }
                if shot.scene == Scene::Agents && shot.settle > 12 {
                    vm.agents_ensure_loaded();
                    if vm.agents.loaded && vm.agents.session.is_none() && vm.agents.error.is_none()
                    {
                        vm.agents_start("demo");
                    }
                }
                if shot.scene == Scene::Agents
                    && shot.settle > 12
                    && vm.agents.session.as_ref().is_some_and(|s| {
                        s.phase == kraken_viewmodel::agents::SessionPhase::Ready
                            && s.items.is_empty()
                    })
                {
                    vm.agents_send(agents::SCENE_PROMPT);
                }
                let views_ready = match shot.scene {
                    Scene::Agents => vm
                        .agents
                        .session
                        .as_ref()
                        .is_some_and(|s| s.waiting_permissions() == 1),
                    Scene::Graph => vm.views.graph.data.is_some(),
                    Scene::Main => vm.views.listing.loaded && !vm.views.listing.loading,
                    _ => true,
                };
                if shot.settle > 18 && !vm.busy() && !vm.assist.busy() && views_ready {
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

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.stop_in_process_engine();
    }
}

impl KrakenApp {
    /// Ends the sidecar of a `--no-daemon` run; a daemon outlives the window by design.
    fn stop_in_process_engine(&mut self) {
        self.settings.infer.shutdown(self.rt.handle());
        if let Some(f) = self.services.ghidra.clone() {
            self.vm = None;
            self.rt.block_on(f.shutdown());
        }
    }
}

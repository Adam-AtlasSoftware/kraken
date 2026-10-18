//! The eframe application: owns the view-model and draws the welcome screen or the workspace.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::time::{Duration, Instant};

use egui::{Frame, Key, Margin, Modifiers, Ui, ViewportCommand};
use egui_dock::DockState;
use kraken_gui_widgets::KrakenTheme;
use kraken_host::ManagedFactory;
use kraken_viewmodel::agents::{AgentEnv, AgentsHub};
use kraken_viewmodel::demo::demo_project;
use kraken_viewmodel::{
    AnalysisPhase, AppAction, ApprovalBroker, Backend, BackendOptions, Connection,
    DaemonClientBackend, InProcessBackend, Load, UiRequest, ViewModel,
};
use tokio::runtime::Runtime;

use crate::args::{Options, Scene};
use crate::assist::{self, AssistRequest, AssistSetup, Change};
use crate::help::{self, HelpDo, HelpEnv, HelpUi};
use crate::import::{ImportAction, ImportDialog, Picked, Picker, is_project_dir};
use crate::menu::{self, MenuCmd, MenuEnv};
use crate::recent::{self, Prefs};
use crate::services::{Mode, Services};
use crate::settings::{Settings, SettingsAction, SettingsEnv};
use crate::tour::{self, Spot, Tour, TourEvent};
use crate::welcome::{self, Choice, Welcome, WelcomeAction};
use crate::workspace::{self, Tab, UiState};
use crate::{chrome, overlays};

const SCREENSHOT_TIMEOUT: Duration = Duration::from_secs(45);

/// A step that stops a running job, waiting for the person to agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Pending {
    /// Open or create another project.
    Open(Choice),
    /// Close the project.
    Close,
    /// Close the window.
    Quit,
}

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
    /// Hidden tutorial-screenshot controls from the environment (see `ShotTweaks`).
    tweaks: ShotTweaks,
}

/// Hidden environment switches for documentation screenshots of a real project:
/// `KRAKEN_GUI_SHOT_TAB=<tab title>` brings that tab to the front, `KRAKEN_GUI_SHOT_LAYOUT=graph`
/// uses the graph layout, `KRAKEN_GUI_SHOT_EDIT=1` makes one scripted rename (so History has an
/// entry; without it a real project is not changed) and
/// `KRAKEN_GUI_SHOT_STRINGS_FILTER=<text>` types into the Strings filter.
#[derive(Default)]
struct ShotTweaks {
    tab: Option<Tab>,
    graph_layout: bool,
    edit: bool,
    strings_filter: Option<String>,
}

impl ShotTweaks {
    fn from_env() -> Self {
        let tab = std::env::var("KRAKEN_GUI_SHOT_TAB").ok().and_then(|name| {
            [
                Tab::Functions,
                Tab::Decompiler,
                Tab::Hex,
                Tab::Listing,
                Tab::Graph,
                Tab::Xrefs,
                Tab::Strings,
                Tab::Symbols,
                Tab::History,
                Tab::Proposals,
            ]
            .into_iter()
            .find(|t| t.title().eq_ignore_ascii_case(&name))
        });
        ShotTweaks {
            tab,
            graph_layout: std::env::var("KRAKEN_GUI_SHOT_LAYOUT").is_ok_and(|v| v == "graph"),
            edit: std::env::var_os("KRAKEN_GUI_SHOT_EDIT").is_some(),
            strings_filter: std::env::var("KRAKEN_GUI_SHOT_STRINGS_FILTER").ok(),
        }
    }
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
    /// The import dialog, when open.
    import: Option<ImportDialog>,
    /// File dialogs opened from the menus and shortcuts.
    picker: Picker,
    /// A step waiting for the person to agree to stop a running job.
    confirm: Option<Pending>,
    /// The shortcut cheat sheet is showing.
    shortcuts_open: bool,
    /// The help window.
    help: HelpUi,
    /// The first-run tour.
    tour: Tour,
    /// The tour step whose panel was last brought to the front.
    tour_fronted: Option<usize>,
    /// Analysis finished with this many functions: the next-steps notice is showing.
    next_steps: Option<u64>,
    /// The analysis was seen running, so its end shows the next-steps notice.
    saw_running: bool,
    /// The last address handed to the browser.
    opened_url: Option<String>,
    /// Keep the File menu open (the menu screenshot).
    file_menu_open: bool,
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
            dock: assist::with_assistant_tab(workspace::initial_dock()),
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
            import: None,
            picker: Picker::default(),
            confirm: None,
            shortcuts_open: false,
            help: HelpUi::default(),
            tour: Tour::default(),
            tour_fronted: None,
            next_steps: None,
            saw_running: false,
            opened_url: None,
            file_menu_open: false,
            shot: opts.screenshot.clone().map(|path| Shot {
                real: opts.open_project.is_some(),
                scene: opts.scene,
                path,
                stage: if matches!(opts.scene, Scene::Welcome | Scene::Import) {
                    ShotStage::Settling
                } else {
                    ShotStage::Loading
                },
                settle: 0,
                started: Instant::now(),
                tweaks: ShotTweaks::from_env(),
            }),
        };
        // The terminal agents the settings list; they need no open project.
        let mut hub = AgentsHub::new(app.rt.handle().clone(), None);
        {
            let ctx = ctx.clone();
            hub.set_repaint(Arc::new(move || ctx.request_repaint()));
        }
        if opts.screenshot.is_some() && opts.scene == Scene::AssistantAgent {
            // The scripted agent of the screenshot, with the note counted as read.
            if let Some(cfg) = assist::scene_config() {
                hub.configure(cfg);
            }
            hub.notice.acknowledged = true;
            let (choice, badge) = assist::scene_backend();
            app.assist.set_choice(choice, badge);
        } else if let Some(cfg) = app.services.agents.clone() {
            hub.configure(cfg);
        }
        app.settings.ai.set_hub(hub);
        if app.services.first_run_tour
            && app.prefs.persistent()
            && !app.prefs.tour_done()
            && opts.screenshot.is_none()
            && !opts.demo
        {
            app.tour.start();
        }
        if opts.screenshot.is_some()
            && let Some((p, b)) = assist::provider_for(opts.scene)
        {
            app.assist.set(p, b);
        }
        if opts.screenshot.is_some() && opts.scene == Scene::Loading {
            app.start_loading_demo(ctx, Duration::from_secs(20));
        } else if opts.demo {
            app.start_demo(ctx);
        } else if let Some(dir) = &opts.open_project {
            app.start_real(Choice::OpenProject(dir.to_string_lossy().into_owned()), ctx);
            // Screenshot runs analyze a project that has not been analyzed yet.
            app.auto_analyze = opts.screenshot.is_some();
        } else if opts.screenshot.is_some() && opts.scene == Scene::Import {
            let binary = opts.path.clone().or_else(scene_binary);
            match binary {
                Some(b) => app.start_import(b.to_string_lossy().into_owned(), ctx),
                None => app.welcome.error = Some("No program to show in the import dialog.".into()),
            }
        } else if let Some(path) = &opts.path {
            app.open_path(path, ctx);
        }
        app
    }

    /// Opens what `path` names: a project folder is opened, a file goes to the import dialog.
    pub(crate) fn open_path(&mut self, path: &Path, ctx: &egui::Context) {
        if path.is_dir() {
            if is_project_dir(path) {
                self.request(
                    Pending::Open(Choice::OpenProject(path.to_string_lossy().into_owned())),
                    ctx,
                );
            } else {
                self.problem(format!(
                    "{} is a folder but not a KRAKEN project (it has no meta.json). Drop a program to import it, or a project folder to open it.",
                    path.display()
                ));
            }
        } else if path.exists() {
            self.start_import(path.to_string_lossy().into_owned(), ctx);
        } else {
            self.problem(format!("{} does not exist.", path.display()));
        }
    }

    /// Shows `msg` where the person is looking: a toast in a project, else on the welcome screen.
    fn problem(&mut self, msg: String) {
        match self
            .vm
            .as_mut()
            .filter(|v| v.connection == Connection::Open)
        {
            Some(vm) => vm.toast(kraken_viewmodel::ToastLevel::Warning, msg),
            None => self.welcome.error = Some(msg),
        }
    }

    /// Opens the import dialog for `binary` and starts probing it.
    pub(crate) fn start_import(&mut self, binary: String, ctx: &egui::Context) {
        let mut cfg = self.services.cfg.clone();
        cfg.engine = Some(self.welcome.engine);
        self.import = Some(ImportDialog::start(&cfg, &binary, self.rt.handle(), ctx));
    }

    /// True while a job would be stopped by closing or switching the project.
    fn job_running(&self) -> bool {
        self.vm
            .as_ref()
            .is_some_and(|v| v.connection == Connection::Open && v.analysis.running())
    }

    /// Runs `step` now, or asks first when it would stop a running job.
    pub(crate) fn request(&mut self, step: Pending, ctx: &egui::Context) {
        if self.job_running() {
            self.confirm = Some(step);
        } else {
            self.run_pending(step, ctx);
        }
    }

    fn run_pending(&mut self, step: Pending, ctx: &egui::Context) {
        match step {
            Pending::Open(Choice::Demo) => self.start_demo(ctx),
            Pending::Open(c) => self.start_real(c, ctx),
            Pending::Close => self.close_project(),
            Pending::Quit => ctx.send_viewport_cmd(ViewportCommand::Close),
        }
    }

    /// Releases the open project (unless `keep` names its folder) before another one opens.
    fn release_current(&mut self, keep: Option<&str>) {
        let Some(vm) = self.vm.as_mut() else {
            return;
        };
        let same = keep.is_some_and(|k| {
            vm.project
                .as_ref()
                .is_some_and(|p| Path::new(&p.project_dir) == Path::new(k))
        });
        if !same {
            vm.close_project();
        }
    }

    /// Closes the project and returns to the welcome screen.
    pub(crate) fn close_project(&mut self) {
        self.release_current(None);
        self.vm = None;
        self.is_demo = false;
        self.auto_analyze = false;
        self.saw_running = false;
        self.next_steps = None;
        self.state = UiState::default();
        self.welcome.busy = None;
        self.welcome.error = None;
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

    /// Replaces the dock layout (benchmarks).
    #[cfg(test)]
    pub(crate) fn set_dock(&mut self, dock: DockState<Tab>) {
        self.dock = dock;
    }

    /// Makes `tab` the visible one of its group on the next frame (benchmarks).
    #[cfg(test)]
    pub(crate) fn bring_to_front(&mut self, tab: Tab) {
        self.state.bring_to_front = Some(tab);
    }

    #[cfg(test)]
    pub fn automate_open(&self) -> bool {
        self.state.assist.automate.open
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

    #[cfg(all(test, unix))]
    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
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

    #[cfg(test)]
    pub fn import_dialog(&self) -> Option<&ImportDialog> {
        self.import.as_ref()
    }

    #[cfg(test)]
    pub fn confirming(&self) -> Option<&Pending> {
        self.confirm.as_ref()
    }

    /// The page the help window shows, when it is open.
    #[cfg(test)]
    pub fn help_topic(&self) -> Option<help::Topic> {
        self.help.is_open().then(|| self.help.topic())
    }

    /// Hides the notices that float over the window, so a screenshot shows one thing.
    #[cfg(test)]
    pub fn hide_notices(&mut self) {
        self.next_steps = None;
        if let Some(vm) = self.vm.as_mut() {
            vm.assist_dismiss_offer();
            let ids: Vec<u64> = vm.toasts.iter().map(|t| t.id).collect();
            for id in ids {
                vm.dismiss_toast(id);
            }
        }
    }

    /// Starts the tour at step `n` (documentation screenshots).
    #[cfg(test)]
    pub fn start_tour_at(&mut self, n: usize) {
        self.tour.start_at(n);
    }

    /// Whether the tour is showing, and its step.
    #[cfg(test)]
    pub fn tour_step(&self) -> Option<usize> {
        self.tour.is_active().then(|| self.tour.step())
    }

    #[cfg(test)]
    pub fn shortcuts_open(&self) -> bool {
        self.shortcuts_open
    }

    #[cfg(test)]
    pub fn next_steps(&self) -> Option<u64> {
        self.next_steps
    }

    #[cfg(test)]
    pub fn opened_url(&self) -> Option<&str> {
        self.opened_url.as_deref()
    }

    #[cfg(test)]
    pub fn picker(&self) -> &Picker {
        &self.picker
    }

    fn new_vm(
        &mut self,
        backend: Arc<dyn kraken_viewmodel::Backend>,
        ctx: &egui::Context,
    ) -> ViewModel {
        let mut vm = ViewModel::new(backend, self.rt.handle().clone());
        let ctx = ctx.clone();
        vm.set_repaint(Arc::new(move || ctx.request_repaint()));
        let agents = self.agent_env();
        self.assist.apply(&mut vm, agents);
        vm
    }

    /// The loading-screen screenshot: the demo opening slowly, as a big program would.
    pub(crate) fn start_loading_demo(&mut self, ctx: &egui::Context, open_time: Duration) {
        match kraken_viewmodel::demo::demo_project_loading(open_time, 14_963) {
            Ok(d) => {
                self.is_demo = true;
                let mut vm = self.new_vm(d.backend, ctx);
                vm.create_project(
                    d.binary.to_string_lossy().into_owned(),
                    d.project_dir.to_string_lossy().into_owned(),
                );
                self.vm = Some(vm);
                self.welcome.busy = Some("Opening...".into());
            }
            Err(e) => self.welcome.error = Some(format!("Could not set up the demo: {e}")),
        }
    }

    pub fn start_demo(&mut self, ctx: &egui::Context) {
        self.release_current(None);
        match demo_project() {
            Ok(d) => {
                // The demo's engine lives in this process, so an agent cannot join it (see
                // `agent_env`).
                self.is_demo = true;
                let mut vm = self.new_vm(d.backend, ctx);
                vm.create_project(
                    d.binary.to_string_lossy().into_owned(),
                    d.project_dir.to_string_lossy().into_owned(),
                );
                self.vm = Some(vm);
                self.auto_analyze = true;
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
        let keep = match &choice {
            Choice::OpenProject(dir) => Some(dir.clone()),
            _ => None,
        };
        self.release_current(keep.as_deref());
        self.is_demo = false;
        self.next_steps = None;
        let mut vm = self.new_vm(backend, ctx);
        match choice {
            Choice::OpenProject(dir) => vm.open_project(dir),
            Choice::NewProject {
                binary,
                project_dir,
                engine,
                analyze,
            } => {
                vm.create_project_with(binary, project_dir, Some(engine));
                self.auto_analyze = analyze;
            }
            Choice::Demo => return,
        }
        self.vm = Some(vm);
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
                crate::activity::apply_requests(ctx, vm, &mut self.state);
                if self.auto_analyze {
                    self.auto_analyze = false;
                    if vm.analysis.phase == AnalysisPhase::NotStarted {
                        vm.start_analysis();
                        self.saw_running = true;
                    }
                }
                match vm.analysis.phase {
                    AnalysisPhase::Running => self.saw_running = true,
                    AnalysisPhase::Complete if self.saw_running && !vm.busy() => {
                        self.saw_running = false;
                        if self.shot.is_none() {
                            let n = vm
                                .analysis
                                .function_count
                                .or(vm.functions.total)
                                .unwrap_or(vm.functions.items.len() as u64);
                            self.next_steps = Some(n);
                        }
                    }
                    AnalysisPhase::Failed | AnalysisPhase::Cancelled => self.saw_running = false,
                    _ => {}
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
            Connection::NoProject => {
                // the open was cancelled: back to the welcome screen
                if vm.loading.is_none() && self.welcome.busy.is_some() {
                    self.vm = None;
                    self.welcome.busy = None;
                    self.auto_analyze = false;
                }
            }
        }
    }

    /// The project that is opening, once it has taken long enough to show the loading screen.
    fn loading_shown(&self) -> bool {
        self.vm.as_ref().is_some_and(|v| {
            matches!(v.connection, Connection::Opening(_))
                && v.loading
                    .as_ref()
                    .is_some_and(|l| l.started.elapsed() >= crate::loading::SHOW_AFTER)
        })
    }

    fn shortcuts(&mut self, ctx: &egui::Context, reqs: &mut Vec<UiRequest>) {
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::Comma)) {
            self.settings.toggle();
        }
        let (open_project, open_binary, close, quit, cheat, help) = ctx.input_mut(|i| {
            // The shifted chord first: a plain Ctrl+O pattern also matches it.
            let open_project = i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::O);
            (
                open_project,
                i.consume_key(Modifiers::COMMAND, Key::O),
                i.consume_key(Modifiers::COMMAND, Key::W),
                i.consume_key(Modifiers::COMMAND, Key::Q),
                i.consume_key(Modifiers::COMMAND, Key::Slash),
                i.consume_key(Modifiers::NONE, Key::F1),
            )
        });
        for (pressed, action) in [
            (open_project, AppAction::OpenProject),
            (open_binary, AppAction::NewProject),
            (close, AppAction::CloseProject),
            (quit, AppAction::Quit),
            (cheat, AppAction::ShowShortcuts),
            (help, AppAction::ShowHelp),
        ] {
            if pressed {
                reqs.extend(self.action_request(action));
            }
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

    /// What `a` asks of the window: the view-model decides while a project is open, the window
    /// itself on the welcome screen (where only actions without a project make sense).
    pub(crate) fn action_request(&mut self, a: AppAction) -> Option<UiRequest> {
        if let Some(vm) = self
            .vm
            .as_mut()
            .filter(|v| v.connection == Connection::Open)
        {
            return vm.perform(a);
        }
        match a {
            AppAction::ToggleTheme => Some(UiRequest::ToggleTheme),
            AppAction::OpenProject => Some(UiRequest::OpenProject),
            AppAction::NewProject => Some(UiRequest::NewProject),
            AppAction::OpenDemo => Some(UiRequest::OpenDemo),
            AppAction::OpenSettings => Some(UiRequest::OpenSettings),
            AppAction::ClearRecent => Some(UiRequest::ClearRecent),
            AppAction::Quit => Some(UiRequest::Quit),
            AppAction::ShowShortcuts => Some(UiRequest::ShowShortcuts),
            AppAction::OpenDocs => Some(UiRequest::OpenDocs),
            AppAction::ShowHelp => Some(UiRequest::ShowHelp),
            AppAction::TakeTour => Some(UiRequest::TakeTour),
            _ => None,
        }
    }

    /// Runs `a` as a menu click or shortcut does.
    pub(crate) fn dispatch(&mut self, a: AppAction, ctx: &egui::Context) {
        if let Some(r) = self.action_request(a) {
            self.handle(r, ctx);
        }
    }

    pub(crate) fn handle(&mut self, r: UiRequest, ctx: &egui::Context) {
        match r {
            UiRequest::ToggleTheme => self.theme.dark = !self.theme.dark,
            UiRequest::FocusFunctionFilter => self.state.focus_filter = true,
            UiRequest::ShowHistory => self.state.bring_to_front = Some(Tab::History),
            UiRequest::ShowProposals => self.state.bring_to_front = Some(Tab::Proposals),
            UiRequest::OpenProject => {
                let start = kraken_host::projects_root(&self.services.cfg).ok();
                self.picker.project(self.rt.handle(), ctx, start);
            }
            UiRequest::NewProject => self.picker.binary(self.rt.handle(), ctx),
            UiRequest::OpenDemo => self.request(Pending::Open(Choice::Demo), ctx),
            UiRequest::OpenSettings => self.settings.show_window(),
            UiRequest::CloseProject => self.request(Pending::Close, ctx),
            UiRequest::ClearRecent => self.prefs.clear(),
            UiRequest::Quit => self.request(Pending::Quit, ctx),
            UiRequest::ShowShortcuts => self.shortcuts_open = true,
            UiRequest::OpenDocs => {
                let url = docs_url();
                if let Err(e) = open_in_browser(&url) {
                    self.problem(format!(
                        "Could not open the user guide ({e}). It is at {url}"
                    ));
                }
                self.opened_url = Some(url);
            }
            UiRequest::OpenAutomate => self.state.assist.automate.show(),
            UiRequest::ShowHelp => {
                let open = self
                    .vm
                    .as_ref()
                    .is_some_and(|v| v.connection == Connection::Open);
                let tab = if open { self.focused_tab() } else { None };
                self.help.show_topic(help::topic_for_tab(tab));
            }
            UiRequest::TakeTour => self.tour.start(),
        }
    }

    fn take_picks(&mut self, ctx: &egui::Context) {
        for p in self.picker.drain() {
            match p {
                Picked::Binary(b) => self.start_import(b, ctx),
                Picked::Project(dir) => self.open_path(Path::new(&dir), ctx),
                Picked::Location(_) => {}
            }
        }
    }

    fn menu_bar(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        let recents = self.prefs.items().to_vec();
        let vm = self
            .vm
            .as_ref()
            .filter(|v| v.connection == Connection::Open);
        let env = MenuEnv {
            project: vm.is_some(),
            analyzing: vm.is_some_and(|v| v.analysis.running()),
            can_back: vm.is_some_and(|v| v.nav.can_back()),
            can_forward: vm.is_some_and(|v| v.nav.can_forward()),
            has_function: vm.is_some_and(|v| v.current.is_some()),
            learn_mode: vm.is_some_and(|v| v.assist.learn_mode),
            dark: self.theme.dark,
            recents: &recents,
            open_file: self.file_menu_open,
        };
        let pal = self.theme.palette();
        let bar = egui::Panel::top("kraken_menu")
            .frame(
                Frame::new()
                    .fill(pal.panel)
                    .inner_margin(Margin::symmetric(8, 2)),
            )
            .show(ui, |ui| menu::bar(ui, &env));
        tour::note_spot(ctx, Spot::Menu, bar.response.rect);
        let cmds = bar.inner;
        for c in cmds {
            match c {
                MenuCmd::Action(a) => self.dispatch(a, ctx),
                MenuCmd::ShowTab(tab) => {
                    if self.dock.find_tab(&tab).is_none() {
                        self.dock.push_to_focused_leaf(tab);
                    }
                    self.state.bring_to_front = Some(tab);
                }
                MenuCmd::OpenRecent(path) => {
                    self.request(Pending::Open(Choice::OpenProject(path)), ctx)
                }
            }
        }
    }

    /// The import dialog, the stop-the-job question, the cheat sheet and file drops.
    fn dialogs(&mut self, ctx: &egui::Context) {
        self.take_picks(ctx);
        if let Some(d) = self.import.as_mut() {
            match d.show(ctx, self.rt.handle()) {
                Some(ImportAction::Import(c)) => {
                    self.import = None;
                    self.request(Pending::Open(c), ctx);
                }
                Some(ImportAction::Cancel) => self.import = None,
                None => {}
            }
        }
        if let Some(step) = self.confirm.clone() {
            match confirm_dialog(ctx, &step) {
                Some(true) => {
                    self.confirm = None;
                    if let Some(vm) = self.vm.as_mut() {
                        vm.cancel_analysis();
                    }
                    self.run_pending(step, ctx);
                }
                Some(false) => self.confirm = None,
                None => {}
            }
        }
        menu::shortcuts_window(ctx, &mut self.shortcuts_open);
        self.help_window(ctx);
        let (hovering, dropped) = ctx.input(|i| {
            (
                !i.raw.hovered_files.is_empty(),
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .collect::<Vec<_>>(),
            )
        });
        if hovering {
            drop_overlay(ctx);
        }
        if let Some(path) = dropped.first() {
            self.open_path(path, ctx);
        }
        if let Some(n) = self.next_steps
            && let Some(vm) = self
                .vm
                .as_ref()
                .filter(|v| v.connection == Connection::Open)
        {
            let has_main = vm.functions.items.iter().any(|f| f.name == "main");
            match next_steps(ctx, n, has_main) {
                Some(NextStep::Run(a)) => {
                    self.next_steps = None;
                    self.dispatch(a, ctx);
                }
                Some(NextStep::Dismiss) => self.next_steps = None,
                None => {}
            }
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
                SettingsAction::DefaultEngine(engine) => self.welcome.engine = engine,
            }
        }
        if let Some(change) = self.settings.ai.take_change() {
            match change {
                Change::Use(choice, b) => self.assist.set_choice(choice, b),
                Change::Clear => self.assist.clear(),
                Change::Problem(why) => self.assist.set_problem(why),
            }
            let agents = self.agent_env();
            if let Some(vm) = self.vm.as_mut() {
                self.assist.apply(vm, agents);
            }
        } else if self.settings.ai.take_agents_dirty() {
            let agents = self.agent_env();
            if let Some(vm) = self.vm.as_mut() {
                AssistSetup::sync_agents(vm, agents);
            }
        }
    }

    /// Where terminal agents are found and whether the note about them was read.
    fn agent_env(&mut self) -> Option<AgentEnv> {
        let demo = self.is_demo;
        let mut env = self.settings.ai.hub_mut().and_then(AgentsHub::env)?;
        if demo {
            // The demo's engine lives in this process, so an agent cannot join it.
            env.config.use_daemon = false;
        }
        Some(env)
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
                AssistRequest::AcknowledgeAgents => self.settings.ai.acknowledge_agents(),
            }
            let agents = self.agent_env();
            if let Some(vm) = self.vm.as_mut() {
                self.assist.apply(vm, agents);
            }
        }
    }

    /// The tab in front in the dock pane that was clicked last, if any was.
    fn focused_tab(&self) -> Option<Tab> {
        let path = self.dock.focused_leaf()?;
        let leaf = self.dock[path.surface][path.node].get_leaf()?;
        leaf.tabs.get(leaf.active.0).copied()
    }

    /// Makes the pane holding `tab` the focused one (tests).
    #[cfg(test)]
    pub(crate) fn focus_tab(&mut self, tab: Tab) {
        if let Some(path) = self.dock.find_tab(&tab) {
            self.dock.set_focused_node_and_surface(path.node_path());
            let _ = self.dock.set_active_tab(path);
        }
    }

    /// The help window, and what its "Do it" buttons ask for.
    fn help_window(&mut self, ctx: &egui::Context) {
        if !self.help.is_open() {
            return;
        }
        let vm = self
            .vm
            .as_ref()
            .filter(|v| v.connection == Connection::Open);
        let menu_env = MenuEnv {
            project: vm.is_some(),
            analyzing: vm.is_some_and(|v| v.analysis.running()),
            can_back: vm.is_some_and(|v| v.nav.can_back()),
            can_forward: vm.is_some_and(|v| v.nav.can_forward()),
            has_function: vm.is_some_and(|v| v.current.is_some()),
            learn_mode: vm.is_some_and(|v| v.assist.learn_mode),
            dark: self.theme.dark,
            recents: &[],
            open_file: false,
        };
        let env = HelpEnv {
            menu: &menu_env,
            vm,
        };
        match self.help.window(ctx, &env) {
            Some(HelpDo::Action(a)) => self.dispatch(a, ctx),
            Some(HelpDo::ShowTab(tab)) => {
                if self.dock.find_tab(&tab).is_none() {
                    self.dock.push_to_focused_leaf(tab);
                }
                self.state.bring_to_front = Some(tab);
            }
            None => {}
        }
    }

    /// The first-run tour: brings the panel of the current step forward and draws the card.
    fn tour_card(&mut self, ctx: &egui::Context, project: bool) {
        if !self.tour.is_active() {
            return;
        }
        if project
            && self.tour_fronted != Some(self.tour.step())
            && let Some(name) = self.tour.panel()
        {
            self.tour_fronted = Some(self.tour.step());
            if let Some(tab) = menu::VIEW_TABS.into_iter().find(|t| t.title() == name) {
                self.state.bring_to_front = Some(tab);
            }
        }
        if self.tour.show(ctx, project) == Some(TourEvent::Ended) {
            self.tour_fronted = None;
            self.prefs.set_tour_done();
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

        self.menu_bar(ui, &ctx);
        // Before the panels, so the dialogs see Escape before any panel takes it.
        self.dialogs(&ctx);
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
            if let Some(tab) = self.state.help_request.take() {
                self.help.show_topic(help::Topic::Panel(tab));
            }
            overlays::palette(&ctx, vm, &mut reqs);
            overlays::rename_dialog(&ctx, vm, &mut self.rename_focus);
            overlays::comment_dialog(&ctx, vm);
            crate::history::dialog(&ctx, vm);
            crate::rewrite::export_dialog(&ctx, vm);
            crate::rewrite::wizard_window(&ctx, vm, &mut self.state.bring_to_front);
            chrome::toasts(&ctx, vm);
            assist::overlays(&ctx, vm, &mut self.state.assist);
            if !vm.toasts.is_empty() || vm.link != kraken_viewmodel::LinkState::Connected {
                ctx.request_repaint_after(Duration::from_millis(400));
            }
        } else if self.loading_shown() {
            let cancel = egui::CentralPanel::default()
                .frame(Frame::new().fill(pal.bg).inner_margin(24))
                .show(ui, |ui| {
                    let loading = self.vm.as_ref().and_then(|v| v.loading.as_ref());
                    loading.is_some_and(|l| crate::loading::show(ui, l, Instant::now()))
                })
                .inner;
            if cancel && let Some(vm) = self.vm.as_mut() {
                vm.cancel_open();
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
                    WelcomeAction::Choose(c) => self.request(Pending::Open(c), &ctx),
                    WelcomeAction::Import(binary) => self.start_import(binary, &ctx),
                    WelcomeAction::Forget(path) => self.prefs.remove(&path),
                    WelcomeAction::Settings => self.settings.show_window(),
                    WelcomeAction::Help => self.help.show_topic(help::Topic::Start),
                    WelcomeAction::Tour => self.tour.start(),
                }
            }
        }
        for r in reqs {
            self.handle(r, &ctx);
        }
        self.settings.ai.poll();
        self.tour_card(&ctx, open);
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
        if shot.stage == ShotStage::Settling && shot.scene == Scene::Import {
            if self.import.as_ref().is_some_and(|d| d.probed().is_some()) {
                shot.settle += 1;
                if shot.settle > 6 {
                    ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
                    shot.stage = ShotStage::Waiting;
                }
            }
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
        if shot.scene == Scene::Loading {
            // halfway through finding functions, with the screen up
            let mid = self
                .vm
                .as_ref()
                .and_then(|v| v.loading.as_ref())
                .is_some_and(|l| {
                    l.stage() == kraken_proto::OpenStage::Functions
                        && l.fraction().is_some_and(|f| f >= 0.4)
                });
            if mid && shot.stage == ShotStage::Loading {
                shot.stage = ShotStage::Settling;
            }
            if shot.stage == ShotStage::Settling {
                shot.settle += 1;
                if shot.settle > 6 {
                    ctx.send_viewport_cmd(ViewportCommand::Screenshot(egui::UserData::default()));
                    shot.stage = ShotStage::Waiting;
                }
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
                    if shot.real && !shot.tweaks.edit {
                        shot.stage = ShotStage::Settling;
                    } else if shot.real {
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
                    } else if matches!(
                        shot.scene,
                        Scene::AutoName
                            | Scene::AssistantAgent
                            | Scene::Rewrite
                            | Scene::RewriteProgram
                            | Scene::RewriteWizard
                    ) {
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
                        Scene::Assistant
                            | Scene::Explain
                            | Scene::AutoName
                            | Scene::AssistantAgent
                            | Scene::Rewrite
                            | Scene::RewriteWizard
                    ));
                    let ids: Vec<u64> = vm.toasts.iter().rev().skip(keep).map(|t| t.id).collect();
                    for id in ids {
                        vm.dismiss_toast(id);
                    }
                    match shot.scene {
                        Scene::Menu => self.file_menu_open = true,
                        Scene::Help => self.help.show_topic(help::Topic::Start),
                        Scene::Tour => self.tour.start_at(3),
                        Scene::Palette => {
                            vm.open_palette();
                            vm.palette.set_query("ren");
                        }
                        Scene::Rename => vm.begin_rename_current(),
                        Scene::Graph => self.dock = workspace::graph_dock(),
                        Scene::Assistant => {
                            self.dock = assist::scene_dock();
                            vm.assist_send(assist::CHAT_QUESTION);
                        }
                        Scene::Explain => {
                            self.dock = assist::scene_dock();
                            vm.assist_explain_function(0x4011a0);
                        }
                        Scene::AutoName => vm.assist_auto_name(10),
                        Scene::AssistantAgent => {
                            self.dock = assist::scene_dock();
                            self.state.bring_to_front = Some(Tab::Assistant);
                            vm.assist_send(assist::SCENE_PROMPT);
                        }
                        Scene::Rewrite => {
                            self.dock = crate::rewrite::scene_dock();
                            // The demo's pipeline is scripted, so it runs on any computer.
                            vm.rewrite.availability =
                                kraken_viewmodel::rewrite::Availability::Unknown;
                            vm.rewrite_ensure_loaded();
                            vm.rewrite_select(crate::rewrite::SCENE_FUNCTION);
                        }
                        Scene::RewriteWizard => {
                            vm.rewrite.availability =
                                kraken_viewmodel::rewrite::Availability::Unknown;
                            vm.rewrite_ensure_loaded();
                            vm.rewrite_wizard_open();
                            vm.rewrite.wizard.scope = kraken_viewmodel::rewrite::WizardScope::Plan;
                            vm.rewrite.wizard.step = kraken_viewmodel::rewrite::WizardStep::Review;
                        }
                        Scene::RewriteProgram => {
                            self.dock = crate::rewrite::scene_dock();
                            vm.rewrite.availability =
                                kraken_viewmodel::rewrite::Availability::Unknown;
                            self.state.rewrite.section = crate::rewrite::Section::Program;
                            self.state.rewrite.program.repairs_open = true;
                            vm.rewrite_program_refresh(None);
                        }
                        _ => {}
                    }
                    if shot.tweaks.graph_layout && shot.scene == Scene::Main {
                        self.dock = workspace::graph_dock();
                    }
                    if let Some(text) = shot.tweaks.strings_filter.clone() {
                        self.state.panels.strings.filter = text.clone();
                        vm.set_strings_filter(text);
                    }
                    if let Some(tab) = shot.tweaks.tab {
                        self.state.bring_to_front = Some(tab);
                    }
                    vm.assist_dismiss_offer();
                }
                let views_ready = match shot.scene {
                    Scene::Rewrite => {
                        vm.rewrite.loaded
                            && vm.rewrite.selected_detail().is_some_and(|d| {
                                d.c.is_some() && !d.loading && !d.versions().is_empty()
                            })
                    }
                    Scene::RewriteProgram => vm.rewrite.program.detail.is_some(),
                    Scene::RewriteWizard => vm.rewrite.loaded && !vm.rewrite.rows.is_empty(),
                    Scene::AssistantAgent => vm
                        .assist
                        .items
                        .iter()
                        .filter(|i| {
                            matches!(
                                i,
                                kraken_viewmodel::assist::ChatItem::Permission(c)
                                    if c.state == kraken_viewmodel::assist::PermissionState::Waiting
                            )
                        })
                        .count()
                        == 1,
                    Scene::Graph => vm.views.graph.data.is_some(),
                    Scene::Main => vm.views.listing.loaded && !vm.views.listing.loading,
                    _ => true,
                };
                // The agent scene ends with the agent waiting for an answer, so a busy run is fine.
                let assist_quiet = !vm.assist.busy() || shot.scene == Scene::AssistantAgent;
                if shot.settle > 18 && !vm.busy() && assist_quiet && views_ready {
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

/// A program to show in the import screenshot when none was given: the corpus of a source
/// checkout.
fn scene_binary() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/pie_list-O0");
    p.is_file().then_some(p)
}

/// The user guide: the built book or the `docs` folder of a checkout or an install next to the
/// executable, else the documentation on GitHub.
pub(crate) fn docs_url() -> String {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf));
    let local = exe_dir
        .iter()
        .flat_map(|d| {
            [
                d.join("docs"),
                d.join("../docs"),
                d.join("../../docs"),
                d.join("../share/kraken/docs"),
            ]
        })
        .find(|d| d.join("SUMMARY.md").is_file() || d.join("index.html").is_file())
        .and_then(|d| d.canonicalize().ok());
    match local {
        Some(dir) => {
            let page = [dir.join("book/index.html"), dir.join("index.html")]
                .into_iter()
                .find(|p| p.is_file())
                .unwrap_or(dir);
            format!("file://{}", page.display())
        }
        None => "https://github.com/Adam-AtlasSoftware/kraken/tree/main/docs".into(),
    }
}

/// Opens `url` with the desktop's handler. Tests never start a browser.
fn open_in_browser(url: &str) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }
    let mut cmd = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        let mut c = std::process::Command::new("explorer");
        c.arg(url);
        return c.spawn().map(|_| ()).map_err(|e| e.to_string());
    } else {
        std::process::Command::new("xdg-open")
    };
    cmd.arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Asks whether to stop the running job for `step`: `Some(true)` go on, `Some(false)` keep
/// working.
fn confirm_dialog(ctx: &egui::Context, step: &Pending) -> Option<bool> {
    let mut answer = None;
    let what = match step {
        Pending::Open(_) => "open another project",
        Pending::Close => "close the project",
        Pending::Quit => "quit",
    };
    let modal = egui::Modal::new(egui::Id::new("kraken_confirm_job")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.heading("The analysis is still running");
        ui.label(format!(
            "To {what}, KRAKEN stops the analysis. What it found so far is kept, and you can run it again later."
        ));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .button("Stop it and continue")
                .on_hover_text("Cancel the analysis and go on")
                .clicked()
            {
                answer = Some(true);
            }
            if ui
                .button("Keep working")
                .on_hover_text("Let the analysis finish and stay here")
                .clicked()
            {
                answer = Some(false);
            }
        });
    });
    if answer.is_none() && modal.should_close() {
        answer = Some(false);
    }
    answer
}

/// The overlay while files are dragged over the window.
fn drop_overlay(ctx: &egui::Context) {
    let rect = ctx.content_rect();
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::new("kraken_drop"),
    ));
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    painter.rect_filled(rect, 0.0, egui::Color32::from_black_alpha(170));
    painter.rect_stroke(
        rect.shrink(18.0),
        12.0,
        egui::Stroke::new(2.0, p.accent),
        egui::StrokeKind::Inside,
    );
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        DROP_TEXT,
        egui::FontId::proportional(20.0),
        egui::Color32::WHITE,
    );
}

/// What the drop overlay says.
pub(crate) const DROP_TEXT: &str =
    "Drop a program to import it, or a KRAKEN project folder to open it";

enum NextStep {
    Run(AppAction),
    Dismiss,
}

/// The notice after analysis: what was found and where to go next.
fn next_steps(ctx: &egui::Context, functions: u64, has_main: bool) -> Option<NextStep> {
    let dark = ctx.global_style().visuals.dark_mode;
    let p = KrakenTheme { dark }.palette();
    let mut out = None;
    egui::Area::new(egui::Id::new("kraken_next_steps"))
        .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -40.0])
        .order(egui::Order::Foreground)
        .show(ctx, |ui| {
            Frame::new()
                .fill(p.surface)
                .stroke(egui::Stroke::new(1.0, p.accent.gamma_multiply(0.6)))
                .corner_radius(8)
                .inner_margin(Margin::symmetric(14, 10))
                .show(ui, |ui| {
                    ui.set_max_width(380.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "Analysis finished: {functions} functions found."
                            ))
                            .strong()
                            .color(p.text_strong),
                        );
                        if ui
                            .small_button("\u{00d7}")
                            .on_hover_text("Dismiss")
                            .clicked()
                        {
                            out = Some(NextStep::Dismiss);
                        }
                    });
                    ui.label(egui::RichText::new("What next?").color(p.text_dim));
                    ui.horizontal_wrapped(|ui| {
                        let open = if has_main {
                            "Open main"
                        } else {
                            "Open the entry point"
                        };
                        if ui
                            .button(open)
                            .on_hover_text(AppAction::GoToMain.hint())
                            .clicked()
                        {
                            out = Some(NextStep::Run(AppAction::GoToMain));
                        }
                        if ui
                            .button(AppAction::ExplainProgram.label())
                            .on_hover_text(AppAction::ExplainProgram.hint())
                            .clicked()
                        {
                            out = Some(NextStep::Run(AppAction::ExplainProgram));
                        }
                        if ui
                            .button("Rewrite to Rust")
                            .on_hover_text(AppAction::RewriteWizard.hint())
                            .clicked()
                        {
                            out = Some(NextStep::Run(AppAction::RewriteWizard));
                        }
                    });
                });
        });
    out
}

//! The settings window (Ctrl+,): engine paths, theme, daemon status and first-time setup.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use egui::{Align2, Id, RichText, Ui, vec2};
use kraken_host::KrakenConfig;
use kraken_host::provision::{HttpsFetcher, Layout, Progress, SetupOptions, pinned, setup};
use kraken_viewmodel::DaemonClientBackend;
use serde_json::Value;
use tokio::runtime::Handle;

use crate::services::Mode;
use crate::style::{self, medium, pal};

const STATUS_REFRESH: Duration = Duration::from_secs(3);

/// What the settings window asks the app to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsAction {
    /// The default engine for new projects was saved.
    DefaultEngine(kraken_registry::EngineChoice),
    /// Switch to the dark (`true`) or light theme.
    SetDark(bool),
    /// Connect to the daemon now (it was not needed until now).
    ConnectDaemon,
}

enum SetupMsg {
    Progress(String, Option<f32>),
    Done(Result<String, String>),
}

enum StatusMsg {
    Status(Result<Value, String>),
    Restarted(Result<(), String>),
}

#[derive(Default)]
enum SetupState {
    #[default]
    Idle,
    Running(String, Option<f32>),
    Done(String),
    Failed(String),
}

/// Text fields of the engine section.
#[derive(Default, Clone, PartialEq, Eq)]
struct Draft {
    /// Engine for new projects.
    engine: kraken_registry::EngineChoice,
    ghidra_home: String,
    java_home: String,
    max_heap_mb: String,
}

/// State of the settings window.
pub struct Settings {
    /// Whether the window is showing.
    pub open: bool,
    draft: Draft,
    /// The AI section.
    pub ai: crate::assist::AiSettings,
    /// The local-model section.
    pub infer: crate::infer::InferSettings,
    loaded_from: Option<PathBuf>,
    note: Option<Result<String, String>>,
    status: Option<Result<Value, String>>,
    status_asked: Option<Instant>,
    status_in_flight: bool,
    restarting: bool,
    setup: SetupState,
    setup_tx: Sender<SetupMsg>,
    setup_rx: Receiver<SetupMsg>,
    status_tx: Sender<StatusMsg>,
    status_rx: Receiver<StatusMsg>,
}

impl Default for Settings {
    fn default() -> Self {
        let (setup_tx, setup_rx) = channel();
        let (status_tx, status_rx) = channel();
        Settings {
            open: false,
            draft: Draft::default(),
            ai: crate::assist::AiSettings::default(),
            infer: crate::infer::InferSettings::default(),
            loaded_from: None,
            note: None,
            status: None,
            status_asked: None,
            status_in_flight: false,
            restarting: false,
            setup: SetupState::Idle,
            setup_tx,
            setup_rx,
            status_tx,
            status_rx,
        }
    }
}

/// What the window needs from the app each frame.
pub struct SettingsEnv<'a> {
    pub rt: &'a Handle,
    pub mode: Mode,
    pub dark: bool,
    pub config_path: Option<&'a PathBuf>,
    pub backend: Option<&'a Arc<DaemonClientBackend>>,
    pub connecting: bool,
    pub connect_error: Option<&'a str>,
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

/// Text and fraction for a provisioning step.
pub fn describe_progress(p: &Progress) -> (String, Option<f32>) {
    match p {
        Progress::Downloading {
            name, done, total, ..
        } => match total {
            Some(t) if *t > 0 => (
                format!(
                    "Downloading {name}: {:.0} of {:.0} MiB",
                    mib(*done),
                    mib(*t)
                ),
                Some((*done as f32 / *t as f32).clamp(0.0, 1.0)),
            ),
            _ => (format!("Downloading {name}: {:.0} MiB", mib(*done)), None),
        },
        Progress::Verifying { name } => (format!("Checking the {name} download"), None),
        Progress::Extracting { name } => (format!("Unpacking {name}"), None),
        Progress::BuildingExtension => ("Building the Ghidra extension".into(), None),
        Progress::InstallingBundledExtension => {
            ("Installing the bundled Ghidra extension".into(), None)
        }
        Progress::Skipped { name } => (format!("{name} is already installed"), None),
    }
}

/// One line about the sandbox of an engine from its `diagnostics.confinement` object, and
/// whether the engine is properly confined.
pub fn confinement_summary(v: &Value) -> (String, bool) {
    if !v
        .get("filesystem")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return ("not confined".into(), false);
    }
    let abi = v.get("landlock_abi").and_then(Value::as_u64).unwrap_or(0);
    let mut parts = vec!["filesystem".to_string()];
    for (key, label) in [
        ("tcp_denied", "tcp denied"),
        ("scoped", "scoped"),
        ("unix_connect_denied", "no unix connect"),
        ("sockets_denied", "no new sockets"),
        ("network_namespace", "no network"),
        ("parent_death_signal", "dies with daemon"),
    ] {
        if v.get(key).and_then(Value::as_bool).unwrap_or(false) {
            parts.push(label.to_string());
        }
    }
    (format!("Landlock ABI {abi}: {}", parts.join(", ")), true)
}

fn duration_text(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
    }
}

impl Settings {
    /// Opens the window and reloads the fields from the config file.
    pub fn show_window(&mut self) {
        self.open = true;
        self.loaded_from = None;
        self.note = None;
        self.ai.reset();
    }

    /// Opens or closes the window.
    pub fn toggle(&mut self) {
        if self.open {
            self.open = false;
        } else {
            self.show_window();
        }
    }

    /// The last daemon status, if any (for tests).
    #[cfg(test)]
    pub fn status(&self) -> Option<&Result<Value, String>> {
        self.status.as_ref()
    }

    fn load_draft(&mut self, path: Option<&PathBuf>) {
        if self.loaded_from.is_some() {
            return;
        }
        self.loaded_from = Some(path.cloned().unwrap_or_default());
        let cfg = path
            .map(|p| KrakenConfig::from_file(p).unwrap_or_default())
            .unwrap_or_default();
        let show = |p: &Option<PathBuf>| {
            p.as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        self.draft = Draft {
            engine: cfg.engine.unwrap_or_default(),
            ghidra_home: show(&cfg.ghidra_home),
            java_home: show(&cfg.java_home),
            max_heap_mb: cfg.max_heap_mb.map(|m| m.to_string()).unwrap_or_default(),
        };
    }

    /// Writes the three engine fields into the config file, keeping everything else in it.
    fn save(&self, path: &Path) -> Result<String, String> {
        let mut cfg = KrakenConfig::from_file(path).map_err(|e| e.to_string())?;
        let opt = |s: &str| {
            let t = s.trim();
            (!t.is_empty()).then(|| PathBuf::from(t))
        };
        cfg.engine = Some(self.draft.engine);
        cfg.ghidra_home = opt(&self.draft.ghidra_home);
        cfg.java_home = opt(&self.draft.java_home);
        let heap = self.draft.max_heap_mb.trim();
        cfg.max_heap_mb = if heap.is_empty() {
            None
        } else {
            Some(
                heap.parse::<u64>()
                    .ok()
                    .filter(|m| (256..=262_144).contains(m))
                    .ok_or("The memory limit must be a number of MiB between 256 and 262144.")?,
            )
        };
        for (what, p) in [("Ghidra", &cfg.ghidra_home), ("JDK", &cfg.java_home)] {
            if let Some(p) = p
                && !p.is_dir()
            {
                return Err(format!("The {what} folder {} does not exist.", p.display()));
            }
        }
        cfg.save(path).map_err(|e| e.to_string())?;
        Ok("Saved. New engines use these settings; restart the background engine to apply them to running projects."
            .into())
    }

    fn drain(&mut self) {
        while let Ok(m) = self.setup_rx.try_recv() {
            match m {
                SetupMsg::Progress(t, f) => self.setup = SetupState::Running(t, f),
                SetupMsg::Done(Ok(t)) => self.setup = SetupState::Done(t),
                SetupMsg::Done(Err(e)) => self.setup = SetupState::Failed(e),
            }
        }
        while let Ok(m) = self.status_rx.try_recv() {
            match m {
                StatusMsg::Status(s) => {
                    self.status_in_flight = false;
                    self.status = Some(s);
                }
                StatusMsg::Restarted(r) => {
                    self.restarting = false;
                    self.status = None;
                    self.status_asked = None;
                    self.note = Some(match r {
                        Ok(()) => Ok(
                            "The background engine was told to stop. It starts again on the next action."
                                .into(),
                        ),
                        Err(e) => Err(e),
                    });
                }
            }
        }
    }

    fn refresh_status(&mut self, env: &SettingsEnv<'_>, ctx: &egui::Context, force: bool) {
        let Some(backend) = env.backend else {
            return;
        };
        let due = self
            .status_asked
            .is_none_or(|t| t.elapsed() >= STATUS_REFRESH);
        if self.status_in_flight || !(force || due) {
            return;
        }
        self.status_asked = Some(Instant::now());
        self.status_in_flight = true;
        let (b, tx, ctx) = (backend.clone(), self.status_tx.clone(), ctx.clone());
        env.rt.spawn(async move {
            let r = b.status().await.map_err(|e| e.message);
            let _ = tx.send(StatusMsg::Status(r));
            ctx.request_repaint();
        });
    }

    fn start_setup(&mut self, rt: &Handle, ctx: &egui::Context) {
        self.setup = SetupState::Running("Starting...".into(), None);
        let (tx, ctx) = (self.setup_tx.clone(), ctx.clone());
        rt.spawn(async move {
            let result = async {
                let specs = pinned().map_err(|e| e.to_string())?;
                let layout = Layout::from_env()
                    .ok_or("Cannot place the runtime: neither XDG_DATA_HOME nor HOME is set.")?;
                let fetcher = HttpsFetcher::new().map_err(|e| e.to_string())?;
                let (ptx, pctx) = (tx.clone(), ctx.clone());
                let mut last = Instant::now() - Duration::from_secs(1);
                let mut report = move |p: Progress| {
                    // Downloads report per chunk; the window needs a few updates a second.
                    let download = matches!(p, Progress::Downloading { .. });
                    if download && last.elapsed() < Duration::from_millis(150) {
                        return;
                    }
                    last = Instant::now();
                    let (text, frac) = describe_progress(&p);
                    let _ = ptx.send(SetupMsg::Progress(text, frac));
                    pctx.request_repaint();
                };
                setup(
                    &layout,
                    &fetcher,
                    &specs,
                    &SetupOptions::with_bundled(false),
                    &mut report,
                )
                .await
                .map_err(|e| e.to_string())?;
                Ok::<String, String>(
                    "Ghidra and the JDK are installed. KRAKEN finds them on its own.".into(),
                )
            }
            .await;
            let _ = tx.send(SetupMsg::Done(result));
            ctx.request_repaint();
        });
    }

    /// Draws the window when open. Returns what the app should do.
    pub fn show(&mut self, ctx: &egui::Context, env: &SettingsEnv<'_>) -> Vec<SettingsAction> {
        self.drain();
        let mut actions = Vec::new();
        if !self.open {
            return actions;
        }
        self.load_draft(env.config_path);
        if env.mode == Mode::Daemon {
            if env.backend.is_some() {
                self.refresh_status(env, ctx, false);
                ctx.request_repaint_after(STATUS_REFRESH);
            } else if !env.connecting && env.connect_error.is_none() {
                actions.push(SettingsAction::ConnectDaemon);
            }
        }
        if matches!(self.setup, SetupState::Running(..)) {
            ctx.request_repaint_after(Duration::from_millis(200));
        }

        let dark = env.dark;
        let mut open = true;
        egui::Window::new(medium("Settings", 15.0))
            .id(Id::new("kraken_settings"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .anchor(Align2::CENTER_CENTER, vec2(0.0, -20.0))
            .default_size(vec2(560.0, 560.0))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.appearance(ui, dark, &mut actions);
                        ui.separator();
                        self.ai.show(ui, env.rt, env.config_path);
                        ui.separator();
                        self.infer.show(
                            ui,
                            env.rt,
                            env.mode,
                            env.backend,
                            env.config_path,
                            &mut self.ai,
                        );
                        ui.separator();
                        self.engine(ui, env, &mut actions);
                        ui.separator();
                        self.setup_section(ui, env, ctx);
                        ui.separator();
                        self.daemon_section(ui, env, ctx);
                    });
            });
        if !open || ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.open = false;
        }
        actions
    }

    fn appearance(&mut self, ui: &mut Ui, dark: bool, actions: &mut Vec<SettingsAction>) {
        let p = pal(ui);
        ui.label(medium("Appearance", 14.0).color(p.text_strong));
        ui.horizontal(|ui| {
            if ui.radio(dark, "Dark").clicked() && !dark {
                actions.push(SettingsAction::SetDark(true));
            }
            if ui.radio(!dark, "Light").clicked() && dark {
                actions.push(SettingsAction::SetDark(false));
            }
        });
    }

    fn engine(&mut self, ui: &mut Ui, env: &SettingsEnv<'_>, actions: &mut Vec<SettingsAction>) {
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("Analysis engine", 14.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "Engine for new projects. Each project keeps the engine it was made with.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
        ui.horizontal(|ui| crate::welcome::engine_choice(ui, &mut self.draft.engine));
        ui.label(
            RichText::new(crate::welcome::engine_help(self.draft.engine))
                .size(12.0)
                .color(p.text_dim),
        );
        if std::env::var_os("KRAKEN_ENGINE").is_some_and(|v| !v.is_empty()) {
            ui.label(
                RichText::new("KRAKEN_ENGINE is set and overrides the engine for projects made from the command line.")
                    .size(12.0)
                    .color(s.warning),
            );
        }
        ui.add_space(4.0);
        ui.label(
            RichText::new("Where Ghidra and Java live. Leave a field empty to use the copy installed by setup or the one your environment names.")
                .size(12.0)
                .color(p.text_dim),
        );
        egui::Grid::new("kraken_settings_engine")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Ghidra folder");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.ghidra_home)
                        .hint_text("automatic")
                        .desired_width(380.0),
                );
                ui.end_row();
                ui.label("Java (JDK) folder");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.java_home)
                        .hint_text("automatic")
                        .desired_width(380.0),
                );
                ui.end_row();
                ui.label("Memory limit (MiB)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.max_heap_mb)
                        .hint_text("default")
                        .desired_width(120.0),
                );
                ui.end_row();
            });
        for (var, what) in [
            ("KRAKEN_GHIDRA_HOME", "Ghidra folder"),
            ("KRAKEN_JAVA_HOME", "Java folder"),
            ("KRAKEN_MAX_HEAP_MB", "memory limit"),
        ] {
            if std::env::var_os(var).is_some_and(|v| !v.is_empty()) {
                ui.label(
                    RichText::new(format!("{var} is set and overrides the {what}."))
                        .size(12.0)
                        .color(s.warning),
                );
            }
        }
        ui.horizontal(|ui| {
            ui.add_enabled_ui(env.config_path.is_some(), |ui| {
                if style::primary_button(ui, "Save").clicked()
                    && let Some(path) = env.config_path
                {
                    self.note = Some(self.save(path));
                    if matches!(self.note, Some(Ok(_))) {
                        actions.push(SettingsAction::DefaultEngine(self.draft.engine));
                    }
                }
            });
            if let Some(path) = env.config_path {
                ui.label(
                    RichText::new(path.display().to_string())
                        .size(11.0)
                        .color(p.text_dim),
                );
            }
        });
        match &self.note {
            Some(Ok(t)) => {
                ui.label(RichText::new(t).size(12.0).color(s.success));
            }
            Some(Err(e)) => {
                ui.label(RichText::new(e).size(12.0).color(s.danger));
            }
            None => {}
        }
    }

    fn setup_section(&mut self, ui: &mut Ui, env: &SettingsEnv<'_>, ctx: &egui::Context) {
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("First-time setup", 14.0).color(p.text_strong));
        let installed = Layout::from_env().map(|l| l.provisioned());
        let line = match &installed {
            Some(i) if i.is_complete() => "Ghidra, Java and the engine extension are installed.",
            Some(_) => "Ghidra and Java are not installed yet (about 750 MB).",
            None => "Cannot place the runtime: HOME is not set.",
        };
        ui.label(RichText::new(line).color(p.text_dim));
        let running = matches!(self.setup, SetupState::Running(..));
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                if ui.button("Run setup (download Ghidra + JDK)").clicked() {
                    self.start_setup(env.rt, ctx);
                }
            });
        });
        match &self.setup {
            SetupState::Idle => {}
            SetupState::Running(text, frac) => {
                let bar = match frac {
                    Some(f) => egui::ProgressBar::new(*f).text(text.clone()),
                    None => egui::ProgressBar::new(0.0).animate(true).text(text.clone()),
                };
                ui.add(bar.desired_width(ui.available_width().min(460.0)));
            }
            SetupState::Done(t) => {
                ui.label(RichText::new(t).size(12.0).color(s.success));
            }
            SetupState::Failed(e) => {
                ui.label(RichText::new(e).size(12.0).color(s.danger));
            }
        }
    }

    fn daemon_section(&mut self, ui: &mut Ui, env: &SettingsEnv<'_>, ctx: &egui::Context) {
        let p = pal(ui);
        let s = style::status(style::dark(ui));
        ui.label(medium("Background engine (krakend)", 14.0).color(p.text_strong));
        if env.mode == Mode::NoDaemon {
            ui.label(
                RichText::new("Running without krakend (--no-daemon): the engine lives inside this window, and agents cannot share the project.")
                    .color(p.text_dim),
            );
            return;
        }
        let Some(_backend) = env.backend else {
            if env.connecting {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Connecting to krakend...");
                });
            } else if let Some(e) = env.connect_error {
                ui.label(RichText::new(e).color(s.danger));
            }
            return;
        };
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh_status(env, ctx, true);
            }
            ui.add_enabled_ui(!self.restarting, |ui| {
                if ui
                    .button("Restart")
                    .on_hover_text(
                        "Stop krakend; it starts again with the saved settings on the next action",
                    )
                    .clicked()
                    && let Some(b) = env.backend
                {
                    self.restarting = true;
                    let (b, tx, ctx) = (b.clone(), self.status_tx.clone(), ctx.clone());
                    env.rt.spawn(async move {
                        let r = b.shutdown_daemon().await.map_err(|e| e.message);
                        let _ = tx.send(StatusMsg::Restarted(r));
                        ctx.request_repaint();
                    });
                }
            });
        });
        match &self.status {
            None => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Asking krakend...");
                });
            }
            Some(Err(e)) => {
                ui.label(RichText::new(e).color(s.danger));
            }
            Some(Ok(v)) => {
                let st = v.clone();
                status_view(ui, &st);
            }
        }
    }
}

fn status_view(ui: &mut Ui, v: &Value) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let d = &v["daemon"];
    let num = |x: &Value| x.as_u64().unwrap_or(0);
    ui.label(format!(
        "krakend {} running (pid {}), up {}, {} connected client(s), {} running job(s)",
        d["build"].as_str().unwrap_or("?"),
        num(&d["pid"]),
        duration_text(num(&d["uptime_secs"])),
        num(&d["clients"]),
        num(&d["running_jobs"]),
    ));
    if let Some(dir) = d["runtime_dir"].as_str() {
        ui.label(RichText::new(dir).size(11.0).color(p.text_dim));
    }
    ui.add_space(4.0);
    ui.label(medium("Open projects", 13.0).color(p.text_strong));
    let sessions = v["sessions"].as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        ui.label(RichText::new("None right now.").color(p.text_dim));
    }
    for sess in &sessions {
        let phase = sess["analysis"]["phase"].as_str().unwrap_or("not open");
        ui.label(format!(
            "{}  -  analysis {phase}, {} pending edit(s), {} proposal(s), idle {}",
            sess["project_dir"].as_str().unwrap_or("?"),
            num(&sess["pending_entries"]),
            num(&sess["open_proposals"]),
            duration_text(num(&sess["idle_secs"])),
        ));
    }
    ui.add_space(4.0);
    ui.label(medium("Engines", 13.0).color(p.text_strong));
    let engines = v["engines"].as_array().cloned().unwrap_or_default();
    if engines.is_empty() {
        ui.label(RichText::new("No engine is running.").color(p.text_dim));
    }
    for e in &engines {
        let diag = &e["diagnostics"];
        let state = diag["state"].as_str().unwrap_or("?");
        let mut text = format!("{}: {state}", e["engine_dir"].as_str().unwrap_or("?"));
        if let Some(pid) = diag["pid"].as_u64() {
            text.push_str(&format!(", pid {pid}"));
        }
        if let Some(g) = diag["ghidra_version"].as_str() {
            text.push_str(&format!(", Ghidra {g}"));
        }
        if let Some(h) = diag["heap_mb"].as_u64() {
            text.push_str(&format!(", {h} MiB heap"));
        }
        let restarts = num(&diag["restarts"]);
        if restarts > 0 {
            text.push_str(&format!(", restarted {restarts}x"));
        }
        ui.label(text);
        if diag["confinement"].is_object() {
            let (line, ok) = confinement_summary(&diag["confinement"]);
            ui.label(
                RichText::new(format!("Sandbox: {line}"))
                    .size(12.0)
                    .color(if ok { s.success } else { s.warning }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn progress_text_is_plain() {
        let (t, f) = describe_progress(&Progress::Downloading {
            name: "ghidra".into(),
            done: 50 << 20,
            total: Some(200 << 20),
            resumed_from: 0,
        });
        assert_eq!(t, "Downloading ghidra: 50 of 200 MiB");
        assert_eq!(f, Some(0.25));
        let (t, f) = describe_progress(&Progress::BuildingExtension);
        assert!(t.contains("extension") && f.is_none());
        let (t, _) = describe_progress(&Progress::Skipped { name: "jdk".into() });
        assert!(t.contains("already"));
    }

    #[test]
    fn confinement_is_summarised_and_flagged() {
        let (line, ok) = confinement_summary(&json!({
            "filesystem": true, "landlock_abi": 6, "tcp_denied": true, "scoped": true,
            "network_namespace": true, "parent_death_signal": true
        }));
        assert!(ok);
        assert!(
            line.starts_with("Landlock ABI 6: filesystem, tcp denied"),
            "{line}"
        );
        let (line, ok) = confinement_summary(&json!({"filesystem": false}));
        assert!(!ok && line == "not confined");
    }

    #[test]
    fn saving_keeps_other_keys_and_validates() {
        let tmp = crate::testutil::tempdir();
        let path = tmp.path().join("cfg/config.toml");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "per_run_cap = 9\n").unwrap();
        let ghidra = tmp.path().join("ghidra");
        std::fs::create_dir_all(&ghidra).unwrap();

        let mut s = Settings {
            draft: Draft {
                ghidra_home: ghidra.to_string_lossy().into_owned(),
                java_home: String::new(),
                max_heap_mb: "4096".into(),
                engine: kraken_registry::EngineChoice::Auto,
            },
            ..Settings::default()
        };
        s.save(&path).unwrap();
        let cfg = KrakenConfig::from_file(&path).unwrap();
        assert_eq!(cfg.per_run_cap, Some(9), "other keys survive");
        assert_eq!(cfg.max_heap_mb, Some(4096));
        assert_eq!(cfg.engine, Some(kraken_registry::EngineChoice::Auto));
        assert_eq!(cfg.ghidra_home, Some(ghidra));

        s.draft.max_heap_mb = "lots".into();
        assert!(s.save(&path).unwrap_err().contains("MiB"));
        s.draft.max_heap_mb = String::new();
        s.draft.java_home = "/definitely/not/here".into();
        assert!(s.save(&path).unwrap_err().contains("does not exist"));
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration_text(5), "5 s");
        assert_eq!(duration_text(125), "2 min");
        assert_eq!(duration_text(7500), "2 h 5 min");
    }
}

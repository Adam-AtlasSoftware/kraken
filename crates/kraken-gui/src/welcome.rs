//! The screen shown when no project is open.

use std::path::Path;

use egui::{Align, Layout, RichText, Ui, vec2};
use kraken_host::KrakenConfig;
use kraken_registry::EngineChoice;
use kraken_viewmodel::RawLoad;
use tokio::runtime::Handle;

use crate::import::{Picked, Picker};
use crate::recent::{self, RecentProject};
use crate::style::{self, card, medium, pal};

/// What the person picked on the welcome screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// The built-in demo.
    Demo,
    /// An existing project folder.
    OpenProject(String),
    /// A binary to start a project from, the folder the project goes in, the engine, and
    /// whether to analyze it right away.
    NewProject {
        binary: String,
        project_dir: String,
        engine: EngineChoice,
        analyze: bool,
        /// Open the file as a raw image (firmware, a ROM) with these options.
        raw: Option<RawLoad>,
        /// The program's separate debug file, already checked against it.
        debug_file: Option<String>,
    },
}

/// Something the welcome screen asks the app for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WelcomeAction {
    /// Open or create a project.
    Choose(Choice),
    /// Show the import dialog for this program.
    Import(String),
    /// Remove a project from the recent list.
    Forget(String),
    /// Show the settings window.
    Settings,
    /// Show the help window.
    Help,
    /// Start the guided tour.
    Tour,
}

pub struct Welcome {
    pub open_path: String,
    pub binary_path: String,
    /// Engine for a new project when the import dialog has no recommendation; starts as the
    /// default from the settings.
    pub engine: EngineChoice,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// A warning that is not a failure (the runtime directory fell back to a shorter one).
    pub notice: Option<String>,
    /// Set while a project is being opened.
    pub busy: Option<String>,
    cfg: KrakenConfig,
    picker: Picker,
}

impl Default for Welcome {
    fn default() -> Self {
        Self::new(KrakenConfig::default())
    }
}

/// The folder of a new project made from `binary`: `<projects root>/<program name>`, made
/// unique when that folder is already in use. Next to the binary when no root can be found.
pub fn default_project_dir(cfg: &KrakenConfig, binary: &str) -> String {
    let stem = Path::new(binary)
        .file_name()
        .map_or_else(|| "project".into(), |n| n.to_string_lossy().into_owned());
    let Ok(base) = kraken_host::default_project_dir(cfg, &stem) else {
        return format!("{binary}.kraken");
    };
    let mut candidate = base.clone();
    let mut n = 2;
    while candidate.exists() {
        let mut name = base.file_name().unwrap_or_default().to_os_string();
        name.push(format!("-{n}"));
        candidate = base.with_file_name(name);
        n += 1;
    }
    candidate.to_string_lossy().into_owned()
}

/// The label of an engine choice.
pub fn engine_label(e: EngineChoice) -> &'static str {
    match e {
        EngineChoice::Ghidra => "Ghidra",
        EngineChoice::Native => "Native",
        EngineChoice::Auto => "Automatic",
    }
}

/// One sentence on what an engine choice means.
pub fn engine_help(e: EngineChoice) -> &'static str {
    match e {
        EngineChoice::Ghidra => "Ghidra with Java: every format, and renames and comments.",
        EngineChoice::Native => {
            "No Java, fast start. ELF and Windows PE programs, libraries and raw firmware images for x86, ARM, AArch64 and RISC-V. Needs `kraken setup --native` once."
        }
        EngineChoice::Auto => "Native when it is installed and can open the program, else Ghidra.",
    }
}

/// The three engines as radio buttons.
pub fn engine_choice(ui: &mut Ui, engine: &mut EngineChoice) {
    for e in [
        EngineChoice::Ghidra,
        EngineChoice::Native,
        EngineChoice::Auto,
    ] {
        ui.radio_value(engine, e, engine_label(e))
            .on_hover_text(engine_help(e));
    }
}

/// Why `dir` cannot hold a project, if so.
pub fn project_dir_problem(dir: &str) -> Option<String> {
    let dir = dir.trim();
    if dir.is_empty() {
        return Some("Choose a folder for the project.".into());
    }
    if Path::new(dir).is_file() {
        return Some("That is a file, not a folder.".into());
    }
    if let Ok(mut entries) = std::fs::read_dir(dir)
        && entries.next().is_some()
    {
        return Some("That folder is not empty. Choose a new folder.".into());
    }
    kraken_host::check_ghidra_safe(Path::new(dir))
        .err()
        .map(|e| e.message)
}

impl Welcome {
    pub fn new(cfg: KrakenConfig) -> Self {
        Welcome {
            open_path: String::new(),
            binary_path: String::new(),
            engine: cfg.engine.unwrap_or_default(),
            error: None,
            notice: None,
            busy: None,
            cfg,
            picker: Picker::default(),
        }
    }

    /// Takes the answers of file dialogs; a chosen program goes straight to the import dialog.
    fn drain_picks(&mut self, actions: &mut Vec<WelcomeAction>) {
        for p in self.picker.drain() {
            match p {
                Picked::Project(f) => self.open_path = f,
                Picked::Binary(b) => {
                    self.binary_path = b.clone();
                    actions.push(WelcomeAction::Import(b));
                }
                Picked::Location(_) | Picked::DebugFile(_) | Picked::DebugFolder(_) => {}
            }
        }
    }
}

const DEMO_HINT: &str = "Open a small built-in program to try KRAKEN";

/// The "Try the demo" card; the main button when the person is new.
fn demo_card(ui: &mut Ui, busy: bool, primary: bool, actions: &mut Vec<WelcomeAction>) {
    let p = pal(ui);
    card().fill(p.surface).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(medium("Try the demo", 16.0).color(p.text_strong));
        ui.label(
            RichText::new(
                "A small built-in program, ready to explore. No files needed. Start here if you are new.",
            )
            .color(p.text_dim),
        );
        ui.add_space(6.0);
        ui.add_enabled_ui(!busy, |ui| {
            let clicked = if primary {
                style::primary_button(ui, "Open demo project")
                    .on_hover_text(DEMO_HINT)
                    .clicked()
            } else {
                ui.button("Open demo project")
                    .on_hover_text(DEMO_HINT)
                    .on_disabled_hover_text("Wait for the current job to finish")
                    .clicked()
            };
            if clicked {
                actions.push(WelcomeAction::Choose(Choice::Demo));
            }
        });
    });
}

pub fn show(
    ui: &mut Ui,
    w: &mut Welcome,
    rt: &Handle,
    recents: &[RecentProject],
    now_ms: u64,
) -> Vec<WelcomeAction> {
    let mut actions = Vec::new();
    w.drain_picks(&mut actions);
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let ctx = ui.ctx().clone();
    let busy = w.busy.is_some();
    // Nothing opened before: point a newcomer at the demo first.
    let first_run = recents.is_empty();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                ui.add_space((ui.available_height() * 0.06).clamp(12.0, 56.0));
                ui.label(medium("KRAKEN", 44.0).color(p.accent));
                ui.label(
                    RichText::new("Take a program apart and understand it. With a helping hand.")
                        .size(15.0)
                        .color(p.text_dim),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "A project holds one program and everything you learn about it: names, comments and notes.",
                    )
                    .size(12.5)
                    .color(p.text_dim),
                );
                ui.add_space(18.0);

                ui.scope(|ui| {
                    ui.set_width(600.0_f32.min(ui.available_width()));
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    if let Some(msg) = &w.busy {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(RichText::new(msg).color(p.text));
                        });
                        ui.add_space(8.0);
                    }
                    if let Some(n) = &w.notice {
                        card().fill(s.warning.gamma_multiply(0.14)).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(n).color(s.warning));
                        });
                        ui.add_space(10.0);
                    }
                    if let Some(e) = &w.error {
                        card().fill(s.danger.gamma_multiply(0.14)).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(e).color(s.danger));
                        });
                        ui.add_space(10.0);
                    }

                    if first_run {
                        demo_card(ui, busy, true, &mut actions);
                        ui.add_space(10.0);
                    }
                    card().fill(p.surface).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("New project from a program", 16.0).color(p.text_strong));
                        ui.label(
                            RichText::new("Pick an executable or library (ELF, PE, Mach-O or .NET). KRAKEN looks at it first and tells you what it found. You can also drop a file on this window.")
                                .color(p.text_dim),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut w.binary_path)
                                    .hint_text("Path to the program")
                                    .desired_width(ui.available_width() - 178.0),
                            )
                            .on_hover_text("Type or paste the path of the program, or use Browse");
                            if ui
                                .add_enabled(!busy, egui::Button::new("Browse..."))
                                .on_hover_text("Choose a program to import  (Ctrl+O)")
                                .on_disabled_hover_text("Wait until the project that is opening is ready.")
                                .clicked()
                            {
                                w.picker.binary(rt, &ctx);
                            }
                            let have_binary = !w.binary_path.trim().is_empty();
                            ui.add_enabled_ui(!busy && have_binary, |ui| {
                                if style::primary_button(ui, "Import...")
                                    .on_hover_text("Look at the program and choose how to import it")
                                    .on_disabled_hover_text(if busy {
                                        "Wait until the project that is opening is ready."
                                    } else {
                                        "Choose a program first."
                                    })
                                    .clicked()
                                {
                                    actions.push(WelcomeAction::Import(
                                        w.binary_path.trim().to_string(),
                                    ));
                                }
                            });
                        });
                    });
                    ui.add_space(10.0);

                    card().fill(p.surface).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("Open a project", 16.0).color(p.text_strong));
                        ui.label(RichText::new("Continue where you left off.").color(p.text_dim));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut w.open_path)
                                    .hint_text("Path to the project folder")
                                    .desired_width(ui.available_width() - 178.0),
                            )
                            .on_hover_text("The folder of a KRAKEN project. Type it or use Browse");
                            if ui
                                .button("Browse...")
                                .on_hover_text("Choose a KRAKEN project folder  (Ctrl+Shift+O)")
                                .clicked()
                            {
                                let start = kraken_host::projects_root(&w.cfg).ok();
                                w.picker.project(rt, &ctx, start);
                            }
                            ui.add_enabled_ui(!busy && !w.open_path.trim().is_empty(), |ui| {
                                if ui
                                    .button("Open")
                                    .on_hover_text("Open this project folder")
                                    .on_disabled_hover_text("Type or choose a project folder first.")
                                    .clicked()
                                {
                                    actions.push(WelcomeAction::Choose(Choice::OpenProject(
                                        w.open_path.trim().to_string(),
                                    )));
                                }
                            });
                        });
                        if !recents.is_empty() {
                            ui.add_space(8.0);
                            ui.label(RichText::new("Recent projects").size(12.0).color(p.text_dim));
                            for r in recents {
                                ui.horizontal(|ui| {
                                    let open = ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(medium(&r.name, 14.0).color(p.accent))
                                                .frame(false),
                                        )
                                        .on_hover_text(&r.path)
                                        .on_disabled_hover_text("Wait for the current job to finish");
                                    if open.clicked() {
                                        actions.push(WelcomeAction::Choose(Choice::OpenProject(
                                            r.path.clone(),
                                        )));
                                    }
                                    ui.label(
                                        RichText::new(recent::ago(now_ms, r.opened_ms))
                                            .size(11.0)
                                            .color(p.text_dim),
                                    );
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if ui
                                            .small_button("\u{00d7}")
                                            .on_hover_text("Remove from this list")
                                            .clicked()
                                        {
                                            actions.push(WelcomeAction::Forget(r.path.clone()));
                                        }
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&r.path).size(11.0).color(p.text_dim),
                                            )
                                            .truncate(),
                                        );
                                    });
                                });
                            }
                        }
                    });
                    ui.add_space(10.0);

                    if !first_run {
                        demo_card(ui, busy, false, &mut actions);
                        ui.add_space(10.0);
                    }
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Press Ctrl+K once a project is open to search every action by name.")
                                .size(12.5)
                                .color(p.text_dim),
                        );
                        if ui
                            .small_button("Settings (Ctrl+,)")
                            .on_hover_text("Engine paths, theme, daemon status and setup")
                            .clicked()
                        {
                            actions.push(WelcomeAction::Settings);
                        }
                        if ui
                            .small_button("Help (F1)")
                            .on_hover_text("Read how KRAKEN works: the first steps, every panel, shortcuts and the glossary")
                            .clicked()
                        {
                            actions.push(WelcomeAction::Help);
                        }
                        if ui
                            .small_button("Take the tour")
                            .on_hover_text("Walk through the main areas of the window, one step at a time")
                            .clicked()
                        {
                            actions.push(WelcomeAction::Tour);
                        }
                    });
                    });
                });
                ui.allocate_space(vec2(0.0, 20.0));
            });
        });
    actions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_in(root: &Path) -> KrakenConfig {
        KrakenConfig {
            projects_root: Some(root.to_path_buf()),
            ..Default::default()
        }
    }

    #[test]
    fn new_projects_default_to_the_projects_root_and_stay_unique() {
        let tmp = crate::testutil::tempdir();
        let cfg = cfg_in(tmp.path());
        let first = default_project_dir(&cfg, "/bin/ls");
        assert_eq!(Path::new(&first), tmp.path().join("ls"));
        std::fs::create_dir_all(&first).unwrap();
        std::fs::write(Path::new(&first).join("x"), b"1").unwrap();
        let second = default_project_dir(&cfg, "/other/ls");
        assert_eq!(Path::new(&second), tmp.path().join("ls-2"));
    }

    #[test]
    fn project_folder_problems_are_explained() {
        let tmp = crate::testutil::tempdir();
        assert!(project_dir_problem("").is_some());
        assert!(project_dir_problem(&tmp.path().join("new").to_string_lossy()).is_none());
        std::fs::write(tmp.path().join("f"), b"x").unwrap();
        assert!(
            project_dir_problem(&tmp.path().join("f").to_string_lossy())
                .unwrap()
                .contains("file")
        );
        assert!(
            project_dir_problem(&tmp.path().to_string_lossy())
                .unwrap()
                .contains("not empty")
        );
        assert!(project_dir_problem("/home/u/.hidden/proj").is_some());
    }
}

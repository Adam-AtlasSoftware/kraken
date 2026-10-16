//! The screen shown when no project is open.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};

use egui::{Align, Layout, RichText, Ui, vec2};
use kraken_host::KrakenConfig;
use tokio::runtime::Handle;

use crate::recent::{self, RecentProject};
use crate::style::{self, card, medium, pal};

/// What the person picked on the welcome screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// The built-in demo.
    Demo,
    /// An existing project folder.
    OpenProject(String),
    /// A binary to start a project from, and the folder the project goes in.
    NewProject { binary: String, project_dir: String },
}

/// Something the welcome screen asks the app for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WelcomeAction {
    /// Open or create a project.
    Choose(Choice),
    /// Remove a project from the recent list.
    Forget(String),
    /// Show the settings window.
    Settings,
}

enum Picked {
    Folder(String),
    Binary(String),
    ProjectFolder(String),
}

pub struct Welcome {
    pub open_path: String,
    pub binary_path: String,
    /// Folder of the project a new binary gets.
    pub project_dir: String,
    /// The person typed or chose the folder, so a new binary no longer overwrites it.
    dir_edited: bool,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// Set while a project is being opened.
    pub busy: Option<String>,
    cfg: KrakenConfig,
    tx: Sender<Picked>,
    rx: Receiver<Picked>,
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
        let (tx, rx) = channel();
        Welcome {
            open_path: String::new(),
            binary_path: String::new(),
            project_dir: String::new(),
            dir_edited: false,
            error: None,
            busy: None,
            cfg,
            tx,
            rx,
        }
    }

    fn pick(&self, rt: &Handle, ctx: &egui::Context, what: PickWhat) {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let start: Option<PathBuf> = match what {
            PickWhat::ProjectFolder => kraken_host::projects_root(&self.cfg).ok().map(|root| {
                // The dialog cannot open a folder that does not exist yet.
                if root.is_dir() {
                    root
                } else {
                    root.parent().map(Path::to_path_buf).unwrap_or(root)
                }
            }),
            _ => None,
        };
        rt.spawn(async move {
            let msg = match what {
                PickWhat::OpenFolder => rfd::AsyncFileDialog::new()
                    .set_title("Open a KRAKEN project folder")
                    .pick_folder()
                    .await
                    .map(|h| Picked::Folder(h.path().to_string_lossy().into_owned())),
                PickWhat::Binary => rfd::AsyncFileDialog::new()
                    .set_title("Choose a program to analyze")
                    .pick_file()
                    .await
                    .map(|h| Picked::Binary(h.path().to_string_lossy().into_owned())),
                PickWhat::ProjectFolder => {
                    let mut d =
                        rfd::AsyncFileDialog::new().set_title("Where should the project be saved?");
                    if let Some(s) = &start {
                        d = d.set_directory(s);
                    }
                    d.pick_folder()
                        .await
                        .map(|h| Picked::ProjectFolder(h.path().to_string_lossy().into_owned()))
                }
            };
            if let Some(m) = msg {
                let _ = tx.send(m);
                ctx.request_repaint();
            }
        });
    }

    /// Uses `binary` for a new project and suggests a folder for it.
    pub fn set_binary(&mut self, binary: String) {
        if !self.dir_edited || self.project_dir.trim().is_empty() {
            self.project_dir = default_project_dir(&self.cfg, &binary);
            self.dir_edited = false;
        }
        self.binary_path = binary;
    }

    fn drain_picks(&mut self) {
        while let Ok(p) = self.rx.try_recv() {
            match p {
                Picked::Folder(f) => self.open_path = f,
                Picked::Binary(b) => self.set_binary(b),
                Picked::ProjectFolder(dir) => {
                    // A chosen existing folder holds the project in a sub-folder named for the
                    // program, unless it is empty.
                    let chosen = Path::new(&dir);
                    let empty = std::fs::read_dir(chosen).is_ok_and(|mut e| e.next().is_none());
                    self.project_dir = if empty || self.binary_path.trim().is_empty() {
                        dir
                    } else {
                        let name = Path::new(self.binary_path.trim())
                            .file_name()
                            .map_or_else(|| "project".into(), |n| n.to_string_lossy().into_owned());
                        chosen.join(name).to_string_lossy().into_owned()
                    };
                    self.dir_edited = true;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum PickWhat {
    OpenFolder,
    Binary,
    ProjectFolder,
}

pub fn show(
    ui: &mut Ui,
    w: &mut Welcome,
    rt: &Handle,
    recents: &[RecentProject],
    now_ms: u64,
) -> Vec<WelcomeAction> {
    w.drain_picks();
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let ctx = ui.ctx().clone();
    let mut actions = Vec::new();
    let busy = w.busy.is_some();

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
                    if let Some(e) = &w.error {
                        card().fill(s.danger.gamma_multiply(0.14)).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.label(RichText::new(e).color(s.danger));
                        });
                        ui.add_space(10.0);
                    }

                    card().fill(p.surface).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("New project from a program", 16.0).color(p.text_strong));
                        ui.label(
                            RichText::new("Pick an executable (ELF, PE or Mach-O). KRAKEN loads it and finds the functions.")
                                .color(p.text_dim),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut w.binary_path)
                                    .hint_text("Path to the program")
                                    .desired_width(ui.available_width() - 90.0),
                            );
                            if ui.button("Browse...").clicked() {
                                w.pick(rt, &ctx, PickWhat::Binary);
                            }
                        });
                        ui.add_space(4.0);
                        ui.label(RichText::new("Save the project in").size(12.0).color(p.text_dim));
                        ui.horizontal(|ui| {
                            let r = ui.add(
                                egui::TextEdit::singleline(&mut w.project_dir)
                                    .hint_text("Folder for the project")
                                    .desired_width(ui.available_width() - 90.0),
                            );
                            if r.changed() {
                                w.dir_edited = true;
                            }
                            if ui.button("Choose...").clicked() {
                                w.pick(rt, &ctx, PickWhat::ProjectFolder);
                            }
                        });
                        let have_binary = !w.binary_path.trim().is_empty();
                        let problem = have_binary.then(|| project_dir_problem(&w.project_dir)).flatten();
                        if let Some(msg) = &problem {
                            ui.label(RichText::new(msg).size(12.0).color(s.warning));
                        }
                        ui.add_space(4.0);
                        ui.add_enabled_ui(!busy && have_binary && problem.is_none(), |ui| {
                            if style::primary_button(ui, "Create project and analyze").clicked() {
                                actions.push(WelcomeAction::Choose(Choice::NewProject {
                                    binary: w.binary_path.trim().to_string(),
                                    project_dir: w.project_dir.trim().to_string(),
                                }));
                            }
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
                            );
                            if ui.button("Browse...").clicked() {
                                w.pick(rt, &ctx, PickWhat::OpenFolder);
                            }
                            ui.add_enabled_ui(!busy && !w.open_path.trim().is_empty(), |ui| {
                                if ui.button("Open").clicked() {
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
                                        .on_hover_text(&r.path);
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
                            if ui.button("Open demo project").clicked() {
                                actions.push(WelcomeAction::Choose(Choice::Demo));
                            }
                        });
                    });
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Press Ctrl+K once a project is open to search every action by name.")
                                .size(12.5)
                                .color(p.text_dim),
                        );
                        if ui.small_button("Settings (Ctrl+,)").clicked() {
                            actions.push(WelcomeAction::Settings);
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
    fn picking_a_binary_suggests_a_folder_until_the_person_chooses_one() {
        let tmp = crate::testutil::tempdir();
        let mut w = Welcome::new(cfg_in(tmp.path()));
        w.set_binary("/x/prog_a".into());
        assert_eq!(Path::new(&w.project_dir), tmp.path().join("prog_a"));
        w.set_binary("/x/prog_b".into());
        assert_eq!(Path::new(&w.project_dir), tmp.path().join("prog_b"));
        w.project_dir = "/mine".into();
        w.dir_edited = true;
        w.set_binary("/x/prog_c".into());
        assert_eq!(w.project_dir, "/mine", "a chosen folder is kept");
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

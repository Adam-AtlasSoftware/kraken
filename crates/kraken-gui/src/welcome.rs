//! The screen shown when no project is open.

use std::sync::mpsc::{Receiver, Sender, channel};

use egui::{Align, Layout, RichText, Ui, vec2};
use tokio::runtime::Handle;

use crate::style::{self, card, medium, pal};

/// What the person picked on the welcome screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    /// The built-in demo.
    Demo,
    /// An existing project folder.
    OpenProject(String),
    /// A binary to start a project from.
    NewProject(String),
}

enum Picked {
    Folder(String),
    Binary(String),
}

pub struct Welcome {
    pub open_path: String,
    pub binary_path: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// Set while a project is being opened.
    pub busy: Option<String>,
    tx: Sender<Picked>,
    rx: Receiver<Picked>,
}

impl Default for Welcome {
    fn default() -> Self {
        let (tx, rx) = channel();
        Welcome {
            open_path: String::new(),
            binary_path: String::new(),
            error: None,
            busy: None,
            tx,
            rx,
        }
    }
}

/// The project folder used for a new project made from `binary`: next to the binary.
pub fn default_project_dir(binary: &str) -> String {
    format!("{binary}.kraken")
}

impl Welcome {
    fn pick(&self, rt: &Handle, ctx: &egui::Context, folder: bool) {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        rt.spawn(async move {
            let msg = if folder {
                rfd::AsyncFileDialog::new()
                    .set_title("Open a KRAKEN project folder")
                    .pick_folder()
                    .await
                    .map(|h| Picked::Folder(h.path().to_string_lossy().into_owned()))
            } else {
                rfd::AsyncFileDialog::new()
                    .set_title("Choose a program to analyze")
                    .pick_file()
                    .await
                    .map(|h| Picked::Binary(h.path().to_string_lossy().into_owned()))
            };
            if let Some(m) = msg {
                let _ = tx.send(m);
                ctx.request_repaint();
            }
        });
    }

    fn drain_picks(&mut self) {
        while let Ok(p) = self.rx.try_recv() {
            match p {
                Picked::Folder(f) => self.open_path = f,
                Picked::Binary(b) => self.binary_path = b,
            }
        }
    }
}

pub fn show(ui: &mut Ui, w: &mut Welcome, rt: &Handle) -> Option<Choice> {
    w.drain_picks();
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let ctx = ui.ctx().clone();
    let mut choice = None;
    let busy = w.busy.is_some();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.with_layout(Layout::top_down(Align::Center), |ui| {
                ui.add_space((ui.available_height() * 0.08).clamp(16.0, 70.0));
                ui.label(medium("KRAKEN", 44.0).color(p.accent));
                ui.label(
                    RichText::new("Take a program apart and understand it. With a helping hand.")
                        .size(15.0)
                        .color(p.text_dim),
                );
                ui.add_space(22.0);

                ui.scope(|ui| {
                    ui.set_width(580.0_f32.min(ui.available_width()));
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
                        ui.label(medium("Try the demo", 16.0).color(p.text_strong));
                        ui.label(
                            RichText::new(
                                "A small built-in program, ready to explore. No files needed. Start here if you are new.",
                            )
                            .color(p.text_dim),
                        );
                        ui.add_space(6.0);
                        ui.add_enabled_ui(!busy, |ui| {
                            if style::primary_button(ui, "Open demo project").clicked() {
                                choice = Some(Choice::Demo);
                            }
                        });
                    });
                    ui.add_space(10.0);

                    card().fill(p.surface).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("New project from a program", 16.0).color(p.text_strong));
                        ui.label(
                            RichText::new("Pick an executable (ELF, PE or Mach-O) to analyze.")
                                .color(p.text_dim),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut w.binary_path)
                                    .hint_text("Path to the program")
                                    .desired_width(ui.available_width() - 214.0),
                            );
                            if ui.button("Browse...").clicked() {
                                w.pick(rt, &ctx, false);
                            }
                            ui.add_enabled_ui(!busy && !w.binary_path.trim().is_empty(), |ui| {
                                if ui.button("Create project").clicked() {
                                    choice = Some(Choice::NewProject(w.binary_path.trim().to_string()));
                                }
                            });
                        });
                        if !w.binary_path.trim().is_empty() {
                            ui.label(
                                RichText::new(format!(
                                    "The project will be saved in {}",
                                    default_project_dir(w.binary_path.trim())
                                ))
                                .size(12.0)
                                .color(p.text_dim),
                            );
                        }
                    });
                    ui.add_space(10.0);

                    card().fill(p.surface).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.label(medium("Open a project", 16.0).color(p.text_strong));
                        ui.label(
                            RichText::new("Continue where you left off.").color(p.text_dim),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut w.open_path)
                                    .hint_text("Path to the project folder")
                                    .desired_width(ui.available_width() - 178.0),
                            );
                            if ui.button("Browse...").clicked() {
                                w.pick(rt, &ctx, true);
                            }
                            ui.add_enabled_ui(!busy && !w.open_path.trim().is_empty(), |ui| {
                                if ui.button("Open").clicked() {
                                    choice = Some(Choice::OpenProject(w.open_path.trim().to_string()));
                                }
                            });
                        });
                    });
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(
                            "Once a project is open, press Ctrl+K to search every action by name.",
                        )
                        .size(12.5)
                        .color(p.text_dim),
                    );
                    });
                });
                ui.allocate_space(vec2(0.0, 20.0));
            });
        });
    choice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_dir_sits_next_to_the_binary() {
        assert_eq!(default_project_dir("/tmp/a.out"), "/tmp/a.out.kraken");
    }
}

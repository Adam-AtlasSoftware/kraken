//! The list of agents, with what each needs and the Set up flow.

use egui::{Align, Frame, Layout, Margin, RichText, Stroke, Ui};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::agents::{AgentRow, Availability, SetupPlan, SetupProgress, SetupState};

use crate::style::{self, chip, medium, pal};

enum Act {
    Start(String),
    Setup(String),
    Refresh,
    Confirm,
    Dismiss,
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let mut acts: Vec<Act> = Vec::new();
    egui::ScrollArea::vertical()
        .id_salt("kraken_agents_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add_space(6.0);
            ui.label(medium("Terminal agents", 16.0).color(p.text_strong));
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "Coding agents that run on your computer, like Claude Code, Codex and Gemini CLI. \
                         KRAKEN connects them to this project's tools, so they can read the program and \
                         suggest or make changes that show up here and can be undone.",
                    )
                    .size(12.5)
                    .color(p.text_dim),
                )
                .wrap(),
            );
            ui.add_space(8.0);

            if let Some(note) = &vm.agents.platform_note {
                note_box(ui, &p, s.warning, note);
            }
            if let Some(err) = &vm.agents.catalogue_error {
                note_box(
                    ui,
                    &p,
                    s.warning,
                    &format!("Your agents.toml could not be read, so only the built-in agents are listed. {err}"),
                );
            }
            if let Some(err) = &vm.agents.error {
                note_box(ui, &p, s.danger, err);
            }

            setup_card(ui, vm, &p, &s, &mut acts);

            if !vm.agents.loaded {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Looking for agents...").color(p.text_dim));
                });
            }
            let busy_setup = vm.agents.setup.running();
            for row in &vm.agents.rows {
                agent_card(ui, row, &p, &s, busy_setup, &mut acts);
                ui.add_space(4.0);
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!vm.agents.loading, egui::Button::new("Check again").small())
                    .on_hover_text("Look again at what is installed")
                    .clicked()
                {
                    acts.push(Act::Refresh);
                }
            });
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "The first time you start an agent, KRAKEN explains what it can and cannot protect you from. \
                         Agents sign in by themselves; KRAKEN never gives them its own settings or keys.",
                    )
                    .size(11.5)
                    .color(p.text_dim),
                )
                .wrap(),
            );
        });
    for a in acts {
        match a {
            Act::Start(id) => vm.agents_start(&id),
            Act::Setup(id) => vm.agents_request_setup(&id),
            Act::Refresh => vm.agents_refresh(),
            Act::Confirm => vm.agents_confirm_setup(),
            Act::Dismiss => vm.agents_dismiss_setup(),
        }
    }
}

fn note_box(ui: &mut Ui, p: &Palette, color: egui::Color32, text: &str) {
    Frame::new()
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.text)).wrap());
        });
    ui.add_space(6.0);
}

fn agent_card(
    ui: &mut Ui,
    row: &AgentRow,
    p: &Palette,
    s: &style::Status,
    busy_setup: bool,
    acts: &mut Vec<Act>,
) {
    style::card().fill(p.surface).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(medium(&row.name, 14.0).color(p.text_strong));
            let (label, color) = match &row.availability {
                Availability::Ready { .. } => (row.availability.label(), s.success),
                Availability::NeedsSetup { .. } => (row.availability.label(), s.info),
                Availability::NotFound { .. } => (row.availability.label(), s.warning),
                Availability::Unsupported { .. } => (row.availability.label(), s.danger),
            };
            chip(ui, label, color);
            if !row.builtin {
                chip(ui, "custom", p.text_dim);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let act = match &row.availability {
                    Availability::Ready { .. } => style::primary_button(ui, "Start")
                        .on_hover_text("Start this agent on the open project")
                        .clicked()
                        .then(|| Act::Start(row.id.clone())),
                    Availability::NeedsSetup { .. } => ui
                        .add_enabled(!busy_setup, egui::Button::new("Set up..."))
                        .on_hover_text("Shows what would be downloaded and asks first")
                        .clicked()
                        .then(|| Act::Setup(row.id.clone())),
                    _ => None,
                };
                acts.extend(act);
            });
        });
        let summary = row.summary.replace('`', "");
        ui.add(egui::Label::new(RichText::new(summary).size(12.5).color(p.text)).wrap());
        let detail_color = match row.availability {
            Availability::Ready { .. } => p.text_dim,
            _ => p.text,
        };
        let prefix = match row.availability {
            Availability::Ready { .. } => "Found: ",
            _ => "",
        };
        ui.add(
            egui::Label::new(
                RichText::new(format!("{prefix}{}", row.availability.detail()))
                    .size(12.0)
                    .color(detail_color),
            )
            .wrap(),
        );
    });
}

fn setup_card(ui: &mut Ui, vm: &ViewModel, p: &Palette, s: &style::Status, acts: &mut Vec<Act>) {
    match &vm.agents.setup {
        SetupState::Idle => {}
        SetupState::Confirm(plan) => confirm_card(ui, p, s, plan, acts),
        SetupState::Running(progress) => running_card(ui, p, progress),
        SetupState::Failed { message, .. } => {
            Frame::new()
                .stroke(Stroke::new(1.0, s.danger.gamma_multiply(0.6)))
                .corner_radius(8)
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(medium("Setup did not finish", 13.5).color(s.danger));
                    ui.add(
                        egui::Label::new(RichText::new(message).size(12.5).color(p.text)).wrap(),
                    );
                    ui.add_space(4.0);
                    if ui.button("Close").clicked() {
                        acts.push(Act::Dismiss);
                    }
                });
            ui.add_space(6.0);
        }
        SetupState::Done { agent_name, .. } => {
            Frame::new()
                .stroke(Stroke::new(1.0, s.success.gamma_multiply(0.6)))
                .corner_radius(8)
                .inner_margin(Margin::same(10))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(medium(format!("{agent_name} is ready"), 13.5).color(s.success));
                    ui.label(
                        RichText::new("Press Start to run it on this project.")
                            .size(12.5)
                            .color(p.text),
                    );
                    if ui.button("Close").clicked() {
                        acts.push(Act::Dismiss);
                    }
                });
            ui.add_space(6.0);
        }
    }
}

fn confirm_card(
    ui: &mut Ui,
    p: &Palette,
    s: &style::Status,
    plan: &SetupPlan,
    acts: &mut Vec<Act>,
) {
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, s.info.gamma_multiply(0.7)))
        .corner_radius(8)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(medium(format!("Set up {}", plan.agent_name), 14.0).color(p.text_strong));
            ui.add_space(2.0);
            ui.label(
                RichText::new("This will download:")
                    .size(12.5)
                    .color(p.text),
            );
            for d in &plan.downloads {
                ui.add(
                    egui::Label::new(
                        RichText::new(format!("\u{2022} {d}"))
                            .size(12.5)
                            .color(p.text),
                    )
                    .wrap(),
                );
            }
            ui.add_space(2.0);
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "Everything goes into {} and nothing is installed system-wide.",
                        plan.into_dir
                    ))
                    .size(12.0)
                    .color(p.text_dim),
                )
                .wrap(),
            );
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if style::primary_button(ui, "Download and install").clicked() {
                    acts.push(Act::Confirm);
                }
                if ui.button("Cancel").clicked() {
                    acts.push(Act::Dismiss);
                }
            });
        });
    ui.add_space(6.0);
}

fn running_card(ui: &mut Ui, p: &Palette, progress: &SetupProgress) {
    Frame::new()
        .fill(p.surface)
        .corner_radius(8)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                medium(format!("Setting up {}", progress.agent_name), 14.0).color(p.text_strong),
            );
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(&progress.step).color(p.text));
            });
            if let Some(f) = progress.fraction {
                ui.add(egui::ProgressBar::new(f).show_percentage());
            }
            ui.label(
                RichText::new("This can take a minute. You can keep working meanwhile.")
                    .size(11.5)
                    .color(p.text_dim),
            );
        });
    ui.add_space(6.0);
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(200));
}

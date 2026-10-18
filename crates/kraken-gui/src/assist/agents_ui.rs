//! Pieces for terminal agents shared by the AI settings and the Assistant tab: the one-time
//! notice, the setup consent and progress cards, and the availability chip.

use egui::{Frame, Margin, RichText, Stroke, Ui};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::agents::{
    Availability, SetupPlan, SetupProgress, SetupState, WARNING_TEXT, WARNING_TITLE,
};

use crate::style::{self, chip, medium};

/// What a click on one of the cards asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAct {
    /// Download and install.
    Confirm,
    /// Close the card without doing anything.
    Dismiss,
}

/// The chip that says whether an agent can run here.
pub fn availability_chip(ui: &mut Ui, a: &Availability, s: &style::Status) {
    let color = match a {
        Availability::Ready { .. } => s.success,
        Availability::NeedsSetup { .. } => s.info,
        Availability::NotFound { .. } => s.warning,
        Availability::Unsupported { .. } => s.danger,
    };
    chip(ui, a.label(), color);
}

/// The one-time "agents work outside KRAKEN's safety net" notice (decision 50: warn only).
/// Returns true when "I understand" was pressed.
pub fn notice_card(ui: &mut Ui, p: &Palette, s: &style::Status, button: &str) -> bool {
    let mut understood = false;
    Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, s.warning.gamma_multiply(0.7)))
        .corner_radius(10)
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.add(egui::Label::new(medium(WARNING_TITLE, 15.0).color(s.warning)).wrap());
            ui.add_space(4.0);
            for para in WARNING_TEXT.split("\n\n") {
                ui.add(egui::Label::new(RichText::new(para).size(12.5).color(p.text)).wrap());
                ui.add_space(4.0);
            }
            ui.horizontal(|ui| {
                if style::primary_button(ui, button)
                    .on_hover_text("Close this message")
                    .clicked()
                {
                    understood = true;
                }
            });
            ui.label(
                RichText::new("KRAKEN shows this once.")
                    .size(11.5)
                    .color(p.text_dim),
            );
        });
    understood
}

/// The setup consent, progress, failure and success cards. Returns what was clicked.
pub fn setup_card(
    ui: &mut Ui,
    p: &Palette,
    s: &style::Status,
    state: &SetupState,
) -> Option<SetupAct> {
    match state {
        SetupState::Idle => None,
        SetupState::Confirm(plan) => confirm_card(ui, p, s, plan),
        SetupState::Running(progress) => {
            running_card(ui, p, progress);
            None
        }
        SetupState::Failed { message, .. } => {
            result_card(ui, p, s.danger, "Setup did not finish", message, "Close")
        }
        SetupState::Done { agent_name, .. } => result_card(
            ui,
            p,
            s.success,
            &format!("{agent_name} is ready"),
            "Test it, then save it as the assistant.",
            "Close",
        ),
    }
}

fn result_card(
    ui: &mut Ui,
    p: &Palette,
    color: egui::Color32,
    title: &str,
    body: &str,
    button: &str,
) -> Option<SetupAct> {
    let mut act = None;
    Frame::new()
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.6)))
        .corner_radius(8)
        .inner_margin(Margin::same(10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(medium(title, 13.5).color(color));
            ui.add(egui::Label::new(RichText::new(body).size(12.5).color(p.text)).wrap());
            ui.add_space(4.0);
            if ui
                .button(button)
                .on_hover_text("Close this message")
                .clicked()
            {
                act = Some(SetupAct::Dismiss);
            }
        });
    ui.add_space(6.0);
    act
}

fn confirm_card(ui: &mut Ui, p: &Palette, s: &style::Status, plan: &SetupPlan) -> Option<SetupAct> {
    let mut act = None;
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
                if style::primary_button(ui, "Download and install")
                    .on_hover_text("Download and install what is listed above")
                    .clicked()
                {
                    act = Some(SetupAct::Confirm);
                }
                if ui
                    .button("Cancel")
                    .on_hover_text("Do not download anything")
                    .clicked()
                {
                    act = Some(SetupAct::Dismiss);
                }
            });
        });
    ui.add_space(6.0);
    act
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

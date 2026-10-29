//! The Setup status window (Help > Setup status) and the status-bar chip for the install jobs
//! that run in the daemon. What they show and do is `kraken_viewmodel::setup_status`.

use egui::{RichText, ScrollArea, Ui};
use kraken_registry::commands::{SetupItem, SetupState};
use kraken_viewmodel::setup_status::{SetupHub, SetupJob, install_command};

use crate::style::{self, chip, medium, pal};

fn state_chip(ui: &mut Ui, state: SetupState) {
    let s = style::status(style::dark(ui));
    let (text, color) = match state {
        SetupState::Ready => ("Ready", s.success),
        SetupState::Missing => ("Not installed", s.warning),
        SetupState::Partial => ("Incomplete", s.warning),
        SetupState::Unavailable => ("Not available here", s.info),
    };
    chip(ui, text, color);
}

fn job_row(ui: &mut Ui, hub: &SetupHub, job: &SetupJob) {
    ui.horizontal(|ui| {
        match job.fraction() {
            Some(f) => {
                ui.add(egui::ProgressBar::new(f).desired_width(220.0));
            }
            None => {
                ui.spinner();
            }
        }
        ui.add(egui::Label::new(RichText::new(job.line()).size(12.0)).truncate());
        let label = if job.cancelling {
            "Cancelling..."
        } else {
            "Cancel"
        };
        if ui
            .add_enabled(!job.cancelling, egui::Button::new(label))
            .on_hover_text("Stop this install; a partial download is kept and resumed next time")
            .on_disabled_hover_text("Cancel was already asked; the install is stopping")
            .clicked()
        {
            hub.cancel(&job.job_id);
        }
    });
}

fn item_card(ui: &mut Ui, hub: &SetupHub, item: &SetupItem, job: Option<SetupJob>) {
    let p = pal(ui);
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.label(medium(&item.name, 14.0).color(p.text_strong));
            state_chip(ui, item.state);
        });
        ui.label(RichText::new(&item.purpose).size(12.0).color(p.text_dim));
        ui.add(egui::Label::new(RichText::new(&item.detail).size(12.0)).wrap());
        if let Some(fix) = &item.fix {
            ui.add(egui::Label::new(RichText::new(fix).size(12.0).color(p.text_dim)).wrap());
        }
        if let Some(job) = job {
            job_row(ui, hub, &job);
        } else if item.state != SetupState::Ready
            && install_command(item).is_some()
            && style::primary_button(ui, "Install")
                .on_hover_text(
                    "Download and install it in the background; you can keep working and cancel it",
                )
                .clicked()
        {
            hub.install(item);
        }
    });
    ui.add_space(4.0);
}

/// Draws the Setup status window when it is open.
pub fn show(ctx: &egui::Context, hub: &SetupHub) {
    if !hub.state().open {
        return;
    }
    if hub.state().active().is_some() {
        ctx.request_repaint_after(std::time::Duration::from_millis(400));
    }
    let mut open = true;
    egui::Window::new(medium("Setup status", 15.0))
        .id(egui::Id::new("kraken_setup_status"))
        .open(&mut open)
        .default_size([640.0, 560.0])
        .resizable(true)
        .collapsible(false)
        .show(ctx, |ui| {
            let p = pal(ui);
            let (ready, not_ready) = hub.state().counts();
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{ready} ready, {not_ready} not ready"))
                        .color(p.text_dim),
                );
                if ui
                    .button("Refresh")
                    .on_hover_text("Look at this computer again")
                    .clicked()
                {
                    hub.refresh();
                }
            });
            let message = hub.state().message.clone();
            if let Some((text, error)) = message {
                let st = style::status(style::dark(ui));
                let color = if error { st.danger } else { st.success };
                ui.add(egui::Label::new(RichText::new(text).color(color)).wrap());
            }
            ui.separator();
            let (items, loaded) = {
                let s = hub.state();
                (s.items.clone(), s.loaded)
            };
            if items.is_empty() {
                ui.label(if loaded {
                    "Nothing to show."
                } else {
                    "Looking at this computer..."
                });
                return;
            }
            ScrollArea::vertical()
                .id_salt("setup_status_items")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for item in &items {
                        let job = hub.state().running_for(&item.id).cloned();
                        item_card(ui, hub, item, job);
                    }
                });
        });
    if !open {
        hub.state().open = false;
    }
}

/// The chip in the status bar while an install job runs; clicking it opens the window.
pub fn status_chip(ui: &mut Ui, hub: &SetupHub) {
    let Some(job) = hub.state().active().cloned() else {
        return;
    };
    let color = style::status(style::dark(ui)).info;
    let text = match job.fraction() {
        Some(f) => format!("Setup: {}%", (f * 100.0).round() as u32),
        None => "Setup: working".to_string(),
    };
    let resp = chip(ui, &text, color)
        .interact(egui::Sense::click())
        .on_hover_text(format!("{} (click for details)", job.line()));
    if resp.clicked() {
        hub.state().open = true;
    }
}

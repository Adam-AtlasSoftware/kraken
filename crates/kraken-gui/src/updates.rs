//! The update strip under the menu bar, the Updates window (Help > Check for updates...) and the
//! About window (ADR 0015). The state lives in `kraken_viewmodel::update`.

use egui::{Frame, Margin, RichText, Ui};
use kraken_registry::commands::UpdateStatusOut;
use kraken_viewmodel::update::{StripAction, UpdateHub};

use crate::style::{self, medium, pal};

/// What the person asked for that the app carries out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateEvent {
    /// Stop the daemon when it is idle and start the new program.
    Restart,
    /// Put this text on the clipboard.
    Copy(String),
    /// Open this page in the browser.
    Open(String),
    /// Turn the daily check on or off in `config.toml`.
    SetChecks(bool),
}

fn progress_line(ui: &mut Ui, hub: &UpdateHub) -> bool {
    let Some(p) = hub.state().applying.clone() else {
        return false;
    };
    ui.horizontal(|ui| {
        ui.spinner();
        let text = if p.message.is_empty() {
            "Updating...".to_string()
        } else {
            format!("Updating: {}", p.message)
        };
        ui.label(RichText::new(text).size(12.5));
        if p.total > 0 {
            let f = (p.done as f32 / p.total as f32).clamp(0.0, 1.0);
            ui.add(
                egui::ProgressBar::new(f)
                    .desired_width(180.0)
                    .show_percentage(),
            );
        }
    });
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(300));
    true
}

fn restart_row(ui: &mut Ui, hub: &UpdateHub, out: &mut Option<UpdateEvent>) -> bool {
    let Some(done) = hub.state().applied.clone() else {
        return false;
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(&done.message).size(12.5));
        if style::primary_button(ui, "Restart now")
            .on_hover_text(
                "Close KRAKEN and start the new version; your projects are saved as you work",
            )
            .clicked()
        {
            *out = Some(UpdateEvent::Restart);
        }
    });
    true
}

/// The buttons for an available update; shared by the strip and the window.
fn offer(ui: &mut Ui, hub: &UpdateHub, out: &mut Option<UpdateEvent>, strip: bool) {
    let Some(view) = hub.state().strip_ignoring_dismissal() else {
        return;
    };
    if let Some(url) = &view.notes_url
        && ui
            .button("What's new")
            .on_hover_text("Open the release notes in your browser")
            .clicked()
    {
        *out = Some(UpdateEvent::Open(url.clone()));
    }
    match &view.action {
        StripAction::UpdateNow => {
            if style::primary_button(ui, "Update now")
                .on_hover_text(
                    "Download the new version, check its signature and install it; the current one is kept so you can go back",
                )
                .clicked()
            {
                hub.apply();
            }
        }
        StripAction::CopyCommand(c) => {
            if ui
                .button("Copy command")
                .on_hover_text(format!("Copy `{c}` to run it in a terminal"))
                .clicked()
            {
                *out = Some(UpdateEvent::Copy(c.clone()));
            }
        }
        StripAction::Download(url) => {
            if ui
                .button("Download")
                .on_hover_text("Open the release page in your browser")
                .clicked()
            {
                *out = Some(UpdateEvent::Open(url.clone()));
            }
        }
    }
    if ui
        .button("Skip this version")
        .on_hover_text(format!("Do not tell about {} again", view.version))
        .clicked()
    {
        hub.skip(&view.version);
    }
    if strip
        && ui
            .button("Later")
            .on_hover_text("Hide this until KRAKEN starts again")
            .clicked()
    {
        hub.later();
    }
}

/// The strip under the menu bar: an available update, the install's progress, or Restart now.
pub fn strip(ui: &mut Ui, hub: &UpdateHub) -> Option<UpdateEvent> {
    let (applying, applied, view) = {
        let s = hub.state();
        (s.applying.is_some(), s.applied.is_some(), s.strip())
    };
    if !applying && !applied && view.is_none() {
        return None;
    }
    let mut out = None;
    let p = pal(ui);
    egui::Panel::top("kraken_update_strip")
        .frame(
            Frame::new()
                .fill(style::status(style::dark(ui)).info.gamma_multiply(0.12))
                .inner_margin(Margin::symmetric(14, 5)),
        )
        .show(ui, |ui| {
            if progress_line(ui, hub) || restart_row(ui, hub, &mut out) {
                return;
            }
            if let Some(v) = &view {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&v.text).size(12.5).color(p.text));
                    offer(ui, hub, &mut out, true);
                });
            }
        });
    out
}

fn when(secs: Option<u64>) -> String {
    let Some(t) = secs else {
        return "never".into();
    };
    let ago = kraken_host::update::state::now_secs().saturating_sub(t);
    match ago {
        0..120 => "just now".into(),
        120..7200 => format!("{} minutes ago", ago / 60),
        7200..172_800 => format!("{} hours ago", ago / 3600),
        _ => format!("{} days ago", ago / 86_400),
    }
}

fn facts(ui: &mut Ui, s: &UpdateStatusOut, system: bool) {
    egui::Grid::new(if system {
        "kraken_about_facts"
    } else {
        "kraken_update_facts"
    })
    .num_columns(2)
    .spacing([14.0, 4.0])
    .show(ui, |ui| {
        let mut row = |k: &str, v: String| {
            ui.label(RichText::new(k).color(pal(ui).text_dim));
            ui.label(v);
            ui.end_row();
        };
        row("Version", s.version.clone());
        row("Installed as", s.install.label.clone());
        row("Build", format!("{} ({})", s.target, s.build_channel));
        if system {
            row("Computer", format!("{}, {}", s.system.os, s.system.arch));
            row("C library", s.system.libc.clone());
            row("Session", s.system.session.clone());
        } else {
            row("Channel", s.channel.clone());
            row("Last check", when(s.last_check));
            if let Some(l) = &s.latest {
                row("Newest release", l.clone());
            }
        }
    });
}

/// The Updates window and the About window, when open.
pub fn windows(ctx: &egui::Context, hub: &UpdateHub) -> Option<UpdateEvent> {
    let mut out = None;
    let (dialog, about) = {
        let s = hub.state();
        (s.dialog_open, s.about_open)
    };
    if dialog {
        let mut open = true;
        egui::Window::new(medium("Updates", 15.0))
            .id(egui::Id::new("kraken_updates"))
            .open(&mut open)
            .default_width(520.0)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                let status = hub.state().status.clone();
                let Some(s) = status else {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Looking at this install...");
                    });
                    return;
                };
                facts(ui, &s, false);
                ui.add_space(6.0);
                let mut on = s.checks_enabled;
                let r = ui
                    .add_enabled(
                        s.checks_disabled_by.as_deref().is_none_or(|b| b == "updates.check = false"),
                        egui::Checkbox::new(&mut on, "Check for a new version once a day"),
                    )
                    .on_hover_text(
                        "Sends one request to GitHub with only KRAKEN's version; nothing about your files",
                    )
                    .on_disabled_hover_text(format!(
                        "Turned off by {}",
                        s.checks_disabled_by.clone().unwrap_or_default()
                    ));
                if r.changed() {
                    out = Some(UpdateEvent::SetChecks(on));
                }
                if let Some(b) = &s.install.self_update_blocked {
                    ui.label(RichText::new(format!("KRAKEN cannot update itself here: {b}")).size(12.0));
                }
                let message = hub.state().message.clone();
                if let Some((text, error)) = message {
                    let st = style::status(style::dark(ui));
                    ui.add(
                        egui::Label::new(
                            RichText::new(text).color(if error { st.danger } else { st.success }),
                        )
                        .wrap(),
                    );
                } else {
                    ui.add(egui::Label::new(RichText::new(&s.summary).size(12.5)).wrap());
                }
                ui.add_space(4.0);
                if progress_line(ui, hub) || restart_row(ui, hub, &mut out) {
                    return;
                }
                ui.horizontal_wrapped(|ui| {
                    let checking = hub.state().checking;
                    if ui
                        .add_enabled(!checking, egui::Button::new("Check now"))
                        .on_hover_text("Ask GitHub for the newest release now")
                        .on_disabled_hover_text("A check is running")
                        .clicked()
                    {
                        hub.check_now();
                    }
                    if checking {
                        ui.spinner();
                    }
                    offer(ui, hub, &mut out, false);
                });
            });
        if !open {
            hub.state().dialog_open = false;
        }
    }
    if about {
        let mut open = true;
        egui::Window::new(medium("About KRAKEN", 15.0))
            .id(egui::Id::new("kraken_about"))
            .open(&mut open)
            .default_width(480.0)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new("AI-assisted reverse engineering workbench. GPL-3.0-or-later.")
                        .color(pal(ui).text_dim),
                );
                ui.add_space(4.0);
                let status = hub.state().status.clone();
                match status {
                    Some(s) => facts(ui, &s, true),
                    None => {
                        ui.label(format!("Version {}", env!("CARGO_PKG_VERSION")));
                    }
                }
                ui.add_space(6.0);
                if ui
                    .button("Check for updates...")
                    .on_hover_text("Open the Updates window")
                    .clicked()
                {
                    hub.open_dialog();
                }
            });
        if !open {
            hub.state().about_open = false;
        }
    }
    out
}

/// Restart now: stops the daemon when no job runs (so the next one starts with the new program)
/// and starts the installed `kraken-gui`. The window closes when this succeeds.
pub async fn restart(daemon: bool) -> Result<(), String> {
    use kraken_host::daemon::{DaemonClient, wait_until_stopped};
    if daemon
        && let Ok(dir) = kraken_ipc::RuntimeDir::resolve()
        && let Ok(Some(c)) = DaemonClient::connect_running(
            &dir,
            kraken_ipc::ClientKind::Gui,
            env!("CARGO_PKG_VERSION"),
        )
        .await
    {
        let running = c
            .status()
            .await
            .ok()
            .and_then(|v| v["daemon"]["running_jobs"].as_u64())
            .unwrap_or(0);
        if running > 0 {
            return Err(
                "A job is still running in KRAKEN's background service. Restart when it is done."
                    .into(),
            );
        }
        c.shutdown().await.map_err(|e| e.message)?;
        wait_until_stopped(&dir, std::time::Duration::from_secs(10)).await;
    }
    let program = kraken_host::update::restart_program("kraken-gui");
    std::process::Command::new(&program)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start {}: {e}", program.display()))
}

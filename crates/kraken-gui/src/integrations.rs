//! The Integrations window (Tools > Emulators and tools) and the "Run in emulator" dialog.
//! What they list and do is `kraken_viewmodel::integrations`; this draws it.

use egui::{Align, Layout, RichText, ScrollArea, Ui};
use kraken_registry::commands::{IntegrationSource, IntegrationStatus, IntegrationView};
use kraken_viewmodel::integrations::{IntegrationsHub, RunWhat};

use crate::style::{self, chip, medium, pal, primary_button};

const LIST_WIDTH: f32 = 270.0;

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1 << 20) as f64)
}

fn status_chip(ui: &mut Ui, r: &IntegrationView) {
    let s = style::status(style::dark(ui));
    let (text, color) = match (r.status, r.source) {
        (IntegrationStatus::Ready, Some(IntegrationSource::Downloaded)) => {
            ("Installed by KRAKEN", s.success)
        }
        (IntegrationStatus::Ready, Some(IntegrationSource::UserPath)) => ("Your path", s.success),
        (IntegrationStatus::Ready, _) => ("Found on this computer", s.success),
        (IntegrationStatus::NotInstalled, _) => ("Not installed", s.info),
        (IntegrationStatus::ManualOnly, _) => ("Use your own copy", s.warning),
        (IntegrationStatus::Installing, _) => ("Installing...", s.info),
    };
    chip(ui, text, color);
}

/// Draws the Integrations window when it is open.
pub fn show(ctx: &egui::Context, hub: &IntegrationsHub) {
    if !hub.state().open {
        return;
    }
    if hub.state().due() {
        hub.refresh();
    }
    if hub.state().installing() {
        ctx.request_repaint_after(std::time::Duration::from_millis(400));
    }
    let mut open = true;
    egui::Window::new(medium("Emulators and tools", 15.0))
        .id(egui::Id::new("kraken_integrations"))
        .open(&mut open)
        .default_size([860.0, 640.0])
        .resizable(true)
        .collapsible(false)
        .show(ctx, |ui| {
            let p = pal(ui);
            ui.label(
                RichText::new(
                    "Nothing here ships with KRAKEN. Install downloads the program from its own \
                     project's release page and checks its hash; Use existing points KRAKEN at a \
                     copy you already have.",
                )
                .color(p.text_dim),
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let mut s = hub.state();
                ui.add(
                    egui::TextEdit::singleline(&mut s.filter)
                        .hint_text("Filter by name or system")
                        .desired_width(220.0),
                )
                .on_hover_text("Type part of a name or a system, such as PlayStation");
                drop(s);
                if ui
                    .button("Refresh")
                    .on_hover_text("Look again for installed copies")
                    .clicked()
                {
                    hub.refresh();
                }
                let s = hub.state();
                let ready = s.ready().len();
                ui.label(
                    RichText::new(format!("{ready} of {} ready", s.rows.len())).color(p.text_dim),
                );
            });
            let message = hub.state().message.clone();
            if let Some((text, error)) = message {
                let st = style::status(style::dark(ui));
                let color = if error { st.danger } else { st.success };
                ui.add(egui::Label::new(RichText::new(text).color(color)).wrap());
            }
            ui.separator();
            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    egui::vec2(LIST_WIDTH, ui.available_height().max(380.0)),
                    Layout::top_down(Align::Min),
                    |ui| list(ui, hub),
                );
                ui.separator();
                ui.vertical(|ui| detail(ui, hub));
            });
        });
    if !open {
        hub.state().open = false;
    }
}

fn list(ui: &mut Ui, hub: &IntegrationsHub) {
    let rows: Vec<IntegrationView> = hub.state().visible().into_iter().cloned().collect();
    let selected = hub.state().selected.clone();
    if rows.is_empty() {
        let loaded = hub.state().loaded;
        ui.label(if loaded {
            "Nothing matches the filter."
        } else {
            "Reading the catalogue..."
        });
        return;
    }
    ScrollArea::vertical()
        .id_salt("integrations_list")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(LIST_WIDTH - 12.0);
            for r in &rows {
                let on = selected.as_deref() == Some(r.id.as_str());
                let resp = ui
                    .scope(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(medium(&r.name, 13.0));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                status_chip(ui, r)
                            });
                        });
                        ui.label(
                            RichText::new(r.platforms.join(", "))
                                .size(11.0)
                                .color(pal(ui).text_dim),
                        );
                    })
                    .response;
                let click = ui
                    .interact(resp.rect, ui.id().with(&r.id), egui::Sense::click())
                    .on_hover_text("Show details");
                if on {
                    ui.painter().rect_stroke(
                        resp.rect.expand(3.0),
                        4.0,
                        egui::Stroke::new(1.0, pal(ui).accent),
                        egui::StrokeKind::Outside,
                    );
                }
                if click.clicked() {
                    hub.select(&r.id);
                }
                ui.add_space(6.0);
            }
        });
}

fn detail(ui: &mut Ui, hub: &IntegrationsHub) {
    let row = {
        let s = hub.state();
        s.selected.as_deref().and_then(|id| s.row(id)).cloned()
    };
    let Some(r) = row else {
        ui.label("Pick an emulator on the left.");
        return;
    };
    let p = pal(ui);
    let busy = hub.state().busy.iter().any(|b| b == &r.id);
    ScrollArea::vertical()
        .id_salt("integrations_detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(medium(&r.name, 17.0).color(p.text_strong));
                status_chip(ui, &r);
                if r.user_supplied {
                    chip(
                        ui,
                        "your manifest, not reviewed",
                        style::status(style::dark(ui)).warning,
                    );
                }
            });
            ui.label(RichText::new(&r.summary).color(p.text_dim));
            if !r.homepage.is_empty() {
                ui.hyperlink_to(&r.homepage, &r.homepage);
            }
            ui.add_space(6.0);
            if !r.notice.is_empty() {
                ui.add_space(6.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(medium("Read before installing", 12.0));
                    ui.add(egui::Label::new(RichText::new(&r.notice)).wrap());
                });
            }
            ui.add_space(8.0);
            actions(ui, hub, &r, busy);
            ui.add_space(8.0);
            ui.separator();
            egui::Grid::new("integration_facts")
                .num_columns(2)
                .spacing([12.0, 3.0])
                .show(ui, |ui| {
                    let mut fact = |k: &str, v: String| {
                        ui.label(RichText::new(k).color(p.text_dim));
                        ui.add(egui::Label::new(v).wrap());
                        ui.end_row();
                    };
                    fact("Runs", r.platforms.join(", "));
                    if !r.formats.is_empty() {
                        fact("Opens", r.formats.join(", "));
                    }
                    fact("Licence", r.license.clone());
                    if let Some(v) = &r.version {
                        fact("Version", v.clone());
                    }
                    if let Some(path) = &r.path {
                        fact("Program", path.clone());
                    }
                    if r.disk_bytes > 0 {
                        fact("Disk use", mib(r.disk_bytes));
                    }
                    fact("Command", r.argv.join(" "));
                    if r.debuggable {
                        fact("Debugging", "has a GDB stub".into());
                    }
                });
        });
}

fn actions(ui: &mut Ui, hub: &IntegrationsHub, r: &IntegrationView, busy: bool) {
    let st = style::status(style::dark(ui));
    if let Some(pr) = &r.progress {
        let frac = if pr.total > 0 {
            pr.done as f32 / pr.total as f32
        } else {
            0.0
        };
        let text = match pr.phase.as_str() {
            "downloading" => format!("Downloading {} of {}", mib(pr.done), mib(pr.total)),
            "verifying" => "Checking the hash".to_string(),
            _ => "Unpacking".to_string(),
        };
        ui.add(
            egui::ProgressBar::new(frac)
                .text(text)
                .animate(pr.total == 0),
        );
        return;
    }
    if busy {
        ui.add(egui::Spinner::new());
        return;
    }
    match r.status {
        IntegrationStatus::NotInstalled => {
            let mut accepted = hub.state().accepted;
            if r.contains_key_material {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "This download embeds key material. You are asking KRAKEN to fetch it \
                             from upstream, nobody else.",
                        )
                        .color(st.warning),
                    )
                    .wrap(),
                );
            }
            ui.checkbox(
                &mut accepted,
                format!("I have read the {} licence and the notice", r.license),
            )
            .on_hover_text("Install stays off until you confirm");
            hub.state().accepted = accepted;
            ui.horizontal(|ui| {
                let label = format!(
                    "Install {} ({})",
                    r.pinned_version.clone().unwrap_or_default(),
                    mib(r.download_bytes)
                );
                let resp = ui
                    .add_enabled_ui(accepted, |ui| primary_button(ui, &label))
                    .inner;
                let resp = resp.on_hover_text(
                    "Download upstream's release over HTTPS, check its SHA-256 and unpack it \
                     under KRAKEN's data folder",
                );
                if resp.clicked() {
                    hub.install(&r.id);
                }
            });
            use_existing(ui, hub, r);
        }
        IntegrationStatus::ManualOnly => {
            ui.label(
                RichText::new(
                    "Upstream publishes no download for this platform that KRAKEN can check. \
                     Install it yourself, then point KRAKEN at it.",
                )
                .color(pal(ui).text_dim),
            );
            use_existing(ui, hub, r);
        }
        IntegrationStatus::Ready => {
            ui.horizontal(|ui| {
                if r.source == Some(IntegrationSource::System) {
                    ui.label(RichText::new("KRAKEN uses the copy it found.").color(st.success));
                }
                let label = match r.source {
                    Some(IntegrationSource::Downloaded) => "Remove",
                    Some(IntegrationSource::UserPath) => "Forget this path",
                    _ => "",
                };
                if !label.is_empty()
                    && ui
                        .button(label)
                        .on_hover_text(
                            "Delete what KRAKEN installed; your own copies are never touched",
                        )
                        .clicked()
                {
                    hub.remove(&r.id);
                }
            });
            use_existing(ui, hub, r);
        }
        IntegrationStatus::Installing => {}
    }
}

fn use_existing(ui: &mut Ui, hub: &IntegrationsHub, r: &IntegrationView) {
    ui.add_space(6.0);
    ui.label(medium("Use existing", 12.0));
    ui.horizontal(|ui| {
        let mut text = hub.state().path_input.clone();
        let changed = ui
            .add(
                egui::TextEdit::singleline(&mut text)
                    .hint_text("/path/to/the/program")
                    .desired_width(300.0),
            )
            .on_hover_text("The full path of an emulator or tool you already have")
            .changed();
        if changed {
            hub.state().path_input = text.clone();
        }
        if ui
            .add_enabled(
                !text.trim().is_empty(),
                egui::Button::new("Use this program"),
            )
            .on_hover_text("An executable file: a binary, an AppImage or a wrapper script")
            .on_disabled_hover_text("Type the path of the program first")
            .clicked()
        {
            hub.use_path(&r.id, text.trim());
        }
    });
}

/// The "Run in emulator" dialog.
pub fn run_dialog(ctx: &egui::Context, hub: &IntegrationsHub) {
    let Some(dialog) = hub.state().run.clone() else {
        return;
    };
    let ready: Vec<IntegrationView> = hub.state().ready().into_iter().cloned().collect();
    let mut open = true;
    let mut dialog = dialog;
    let mut start = false;
    let mut show_window = false;
    egui::Window::new(medium("Run in emulator", 15.0))
        .id(egui::Id::new("kraken_run_in_emulator"))
        .open(&mut open)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.set_width(460.0);
            let p = pal(ui);
            if ready.is_empty() {
                ui.label("No emulator is ready yet. Install one or point KRAKEN at yours.");
                if primary_button(ui, "Open emulators and tools")
                    .on_hover_text("Install one or point KRAKEN at yours")
                    .clicked()
                {
                    show_window = true;
                }
                return;
            }
            ui.label(
                RichText::new(
                    "This starts the real emulator on this computer, not KRAKEN's confined \
                     interpreter. KRAKEN asks before it runs.",
                )
                .color(p.text_dim),
            );
            ui.add_space(4.0);
            let name_of = |id: &Option<String>| {
                id.as_deref()
                    .and_then(|i| ready.iter().find(|r| r.id == i))
                    .map_or_else(|| "Choose...".to_string(), |r| r.name.clone())
            };
            egui::ComboBox::from_label("Emulator")
                .selected_text(name_of(&dialog.emulator))
                .show_ui(ui, |ui| {
                    for r in &ready {
                        ui.selectable_value(
                            &mut dialog.emulator,
                            Some(r.id.clone()),
                            format!("{}  ({})", r.name, r.platforms.join(", ")),
                        )
                        .on_hover_text(&r.summary);
                    }
                })
                .response
                .on_hover_text("Which installed emulator runs the program");
            ui.radio_value(&mut dialog.what, RunWhat::Original, "The original program")
                .on_hover_text("Run the file the project was made from");
            ui.radio_value(
                &mut dialog.what,
                RunWhat::Patched,
                "A copy with my patches applied",
            )
            .on_hover_text(
                "Write a copy with your byte patches and run that; the original is untouched",
            );
            let debuggable = dialog
                .emulator
                .as_deref()
                .and_then(|i| ready.iter().find(|r| r.id == i))
                .is_some_and(|r| r.debuggable);
            ui.add_enabled(
                debuggable,
                egui::Checkbox::new(&mut dialog.debug, "Wait for a GDB debugger"),
            )
            .on_disabled_hover_text("This emulator's manifest has no GDB stub flags");
            if !debuggable {
                dialog.debug = false;
            }
            ui.add_space(6.0);
            let running = hub.state().running;
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        dialog.emulator.is_some() && !running,
                        egui::Button::new("Run"),
                    )
                    .on_hover_text("Start the emulator; KRAKEN asks first")
                    .on_disabled_hover_text("Choose an emulator first")
                    .clicked()
                {
                    start = true;
                }
                if running {
                    ui.add(egui::Spinner::new());
                }
            });
            if let Some((text, true)) = hub.state().message.clone() {
                ui.add(
                    egui::Label::new(
                        RichText::new(text).color(style::status(style::dark(ui)).danger),
                    )
                    .wrap(),
                );
            }
            if let Some(out) = hub.state().last_run.clone() {
                ui.separator();
                let line = if out.exited {
                    match out.exit_code {
                        Some(c) => format!("{} ended with code {c}", out.emulator),
                        None => format!("{} ended", out.emulator),
                    }
                } else {
                    format!("{} is running (pid {})", out.emulator, out.pid)
                };
                ui.label(medium(line, 12.0).color(p.text_strong));
                if let Some(g) = &out.gdb {
                    ui.label(format!("GDB stub: target remote {g}"));
                }
                for n in &out.notes {
                    ui.label(RichText::new(n).color(p.text_dim));
                }
                let text = out.output.0.clone();
                if !text.trim().is_empty() {
                    ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                        ui.add(egui::Label::new(RichText::new(text).monospace().size(11.0)).wrap());
                    });
                }
                ui.label(
                    RichText::new(format!("Log: {}", out.log))
                        .size(11.0)
                        .color(p.text_dim),
                );
            }
        });
    if open {
        hub.state().run = Some(dialog);
    } else {
        hub.state().run = None;
    }
    if start {
        hub.run_dialog_start();
    }
    if show_window {
        hub.state().run = None;
        hub.open();
    }
}

//! The screen shown while a project is created or opened: the stages, a progress bar, the
//! counts, the time and a Cancel button.

use std::time::{Duration, Instant};

use egui::{Align, Color32, CornerRadius, Layout, RichText, Sense, Stroke, Ui, vec2};
use kraken_proto::OpenStage;
use kraken_viewmodel::{LoadingState, clock};

use crate::style::{self, card, medium, pal};

/// An open that ends sooner than this never shows the screen (no flash for small programs).
pub const SHOW_AFTER: Duration = Duration::from_millis(300);

/// What a stage does, for its hover text.
fn stage_help(stage: OpenStage) -> &'static str {
    match stage {
        OpenStage::Prepare => {
            "KRAKEN checks that the file is a program it can read and computes its fingerprint."
        }
        OpenStage::StartEngine => {
            "The engine is the part of KRAKEN that reads machine code. It runs in its own protected process."
        }
        OpenStage::ReadFile => "The file is read and its parts are placed in memory.",
        OpenStage::Symbols => {
            "Names from the symbol table and the debug information, when the program has them."
        }
        OpenStage::Functions => {
            "KRAKEN follows the code from every known starting point to find where each function \
             begins and ends. This is the slow part of a first open."
        }
        OpenStage::Types => "Known library functions get their types and parameter names.",
        OpenStage::Replay => "Your renames, comments and other changes are applied again.",
        OpenStage::Ready => "The project opens.",
    }
}

/// `about 3 minutes left`, rounded the way people say it.
fn left_text(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..=44 => "less than a minute left".into(),
        45..=89 => "about a minute left".into(),
        90..=3599 => format!("about {} minutes left", s.div_ceil(60)),
        _ => format!("about {} hours left", s.div_ceil(3600)),
    }
}

/// A bar for a share that is not known: a block that moves back and forth.
fn indeterminate_bar(ui: &mut Ui, width: f32, color: Color32, track: Color32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(width, 10.0), Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(5), track);
    let t = ui.input(|i| i.time) as f32;
    let block = rect.width() * 0.25;
    let span = rect.width() - block;
    // a triangle wave: 0 to 1 and back every 2.4 s
    let phase = (t / 1.2) % 2.0;
    let x = if phase < 1.0 { phase } else { 2.0 - phase };
    let left = rect.left() + span * x;
    let moving = egui::Rect::from_min_size(egui::pos2(left, rect.top()), vec2(block, 10.0));
    painter.rect_filled(moving, CornerRadius::same(5), color);
    ui.ctx().request_repaint_after(Duration::from_millis(30));
    resp
}

/// One row of the stage list: a marker (done, now, later) and the name.
fn stage_row(ui: &mut Ui, stage: OpenStage, current: OpenStage, accent: Color32, dim: Color32) {
    let done = stage < current || current == OpenStage::Ready;
    let now = stage == current && current != OpenStage::Ready;
    let resp = ui
        .horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(vec2(16.0, 18.0), Sense::hover());
            let c = rect.center();
            if now {
                ui.put(rect, egui::Spinner::new().size(13.0).color(accent));
            } else if done {
                ui.painter().circle_filled(c, 5.0, accent);
            } else {
                ui.painter().circle_stroke(c, 4.5, Stroke::new(1.2, dim));
            }
            let text = RichText::new(stage.label()).size(13.5);
            let text = if now {
                text.color(accent).strong()
            } else if done {
                text.color(ui.visuals().text_color())
            } else {
                text.color(dim)
            };
            ui.label(text);
        })
        .response;
    resp.on_hover_text(stage_help(stage));
}

/// Draws the loading screen. Returns true when Cancel was clicked.
pub fn show(ui: &mut Ui, loading: &LoadingState, now: Instant) -> bool {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let mut cancel = false;
    let current = loading.stage();
    ui.ctx().request_repaint_after(Duration::from_millis(250));
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        ui.add_space((ui.available_height() * 0.08).clamp(12.0, 64.0));
        let verb = if loading.creating {
            "Opening"
        } else {
            "Reopening"
        };
        ui.label(medium(format!("{verb} {}", loading.program), 24.0).color(p.text_strong));
        ui.add_space(4.0);
        let subtitle = if loading.from_cache() {
            "Reading the results saved by the last open. This is much faster than the first time."
        } else {
            "The first open of a big program is slow: KRAKEN looks at every function once and \
             saves what it finds. The next open takes seconds."
        };
        ui.label(RichText::new(subtitle).size(12.5).color(p.text_dim));
        ui.add_space(18.0);
        ui.scope(|ui| {
            ui.set_width(560.0_f32.min(ui.available_width()));
            card().fill(p.surface).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.with_layout(Layout::top_down(Align::Min), |ui| {
                    for stage in loading.stages() {
                        stage_row(ui, stage, current, p.accent, p.text_dim);
                    }
                    ui.add_space(12.0);
                    let width = ui.available_width();
                    match loading.fraction() {
                        Some(f) => {
                            ui.add(
                                egui::ProgressBar::new(f)
                                    .desired_width(width)
                                    .fill(p.accent.gamma_multiply(0.75))
                                    .text(
                                        RichText::new(format!("{}%", (f * 100.0).floor()))
                                            .color(p.text_strong),
                                    ),
                            )
                            .on_hover_text(
                                "How much of the work is done. It never goes back; the slow part \
                                 is finding functions.",
                            );
                        }
                        None => {
                            indeterminate_bar(ui, width, p.accent, p.surface_hover).on_hover_text(
                                "This step cannot tell how far it is. It is still working.",
                            );
                        }
                    }
                    ui.add_space(8.0);
                    if let Some(counts) = loading.counts_text() {
                        ui.label(RichText::new(counts).size(14.0).color(p.text_strong))
                            .on_hover_text(
                                "Functions found so far, and the places still waiting to be \
                                 looked at. The second number grows and shrinks as new \
                                 functions turn up.",
                            );
                    }
                    let msg = loading.message();
                    // the counts line already says what a "N functions found" message says
                    let repeats =
                        loading.counts_text().is_some() && msg.contains("functions found");
                    if !msg.is_empty() && !repeats {
                        ui.label(RichText::new(msg).size(12.0).color(p.text_dim));
                    }
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        let mut time = format!("Elapsed {}", clock(loading.elapsed(now)));
                        if let Some(left) = loading.estimate(now) {
                            time.push_str(&format!(" · {}", left_text(left)));
                        }
                        ui.label(RichText::new(time).size(12.0).color(p.text_dim))
                            .on_hover_text(
                                "Time since the open started. A rough estimate of the time left \
                                 appears once the slow part has run for a while.",
                            );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let label = if loading.cancelling {
                                "Stopping..."
                            } else {
                                "Cancel"
                            };
                            let resp = ui
                                .add_enabled(!loading.cancelling, egui::Button::new(label))
                                .on_hover_text(
                                    "Stop opening this program. Nothing is changed, and nothing \
                                     stays open.",
                                )
                                .on_disabled_hover_text(
                                    "Already stopping: the engine is finishing its current step.",
                                );
                            cancel = resp.clicked();
                        });
                    });
                    if loading.cancelling {
                        ui.label(
                            RichText::new("Stopping the engine...")
                                .size(12.0)
                                .color(s.warning),
                        );
                    }
                });
            });
        });
    });
    cancel
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_left_is_rounded_as_people_say_it() {
        assert_eq!(
            left_text(Duration::from_secs(10)),
            "less than a minute left"
        );
        assert_eq!(left_text(Duration::from_secs(60)), "about a minute left");
        assert_eq!(left_text(Duration::from_secs(150)), "about 3 minutes left");
        assert_eq!(left_text(Duration::from_secs(7200)), "about 2 hours left");
    }
}

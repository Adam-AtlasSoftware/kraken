//! Small shared look-and-feel helpers on top of the widgets crate's theme.

use egui::{Align, Color32, CornerRadius, Frame, Layout, Margin, RichText, Stroke, Ui};
use kraken_gui_widgets::{KrakenTheme, Palette};
use kraken_viewmodel::ToastLevel;

use crate::fonts;

/// Colours for statuses, chosen to sit next to the teal theme in both modes.
#[derive(Clone, Copy)]
pub struct Status {
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub info: Color32,
}

pub fn status(dark: bool) -> Status {
    if dark {
        Status {
            success: Color32::from_rgb(0x5f, 0xd7, 0x9e),
            warning: Color32::from_rgb(0xf0, 0xc9, 0x87),
            danger: Color32::from_rgb(0xf2, 0x7c, 0x7c),
            info: Color32::from_rgb(0x6c, 0xc6, 0xf0),
        }
    } else {
        Status {
            success: Color32::from_rgb(0x1d, 0x8a, 0x63),
            warning: Color32::from_rgb(0xb2, 0x71, 0x08),
            danger: Color32::from_rgb(0xc2, 0x3a, 0x3a),
            info: Color32::from_rgb(0x0b, 0x72, 0xa8),
        }
    }
}

pub fn level_color(level: ToastLevel, dark: bool) -> Color32 {
    let s = status(dark);
    match level {
        ToastLevel::Info => s.info,
        ToastLevel::Success => s.success,
        ToastLevel::Warning => s.warning,
        ToastLevel::Error => s.danger,
    }
}

pub fn pal(ui: &Ui) -> Palette {
    KrakenTheme::from_ctx(ui.ctx()).palette()
}

pub fn dark(ui: &Ui) -> bool {
    KrakenTheme::from_ctx(ui.ctx()).dark
}

/// Medium-weight proportional text.
pub fn medium(text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text.into()).font(egui::FontId::new(size, fonts::medium()))
}

/// A small rounded label such as `partial` or `agent`.
pub fn chip(ui: &mut Ui, text: &str, color: Color32) -> egui::Response {
    Frame::new()
        .fill(color.gamma_multiply(0.16))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.45)))
        .corner_radius(CornerRadius::same(9))
        .inner_margin(Margin::symmetric(7, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(text).size(11.0).color(color));
        })
        .response
}

/// Centered friendly text for a panel with nothing to show yet.
pub fn empty_state(ui: &mut Ui, title: &str, body: &str, hint: Option<&str>) {
    let p = pal(ui);
    ui.with_layout(Layout::top_down(Align::Center), |ui| {
        ui.add_space((ui.available_height() * 0.28).clamp(12.0, 140.0));
        ui.label(medium(title, 16.0).color(p.text_strong));
        ui.add_space(2.0);
        ui.scope(|ui| {
            ui.set_max_width(ui.available_width().min(420.0));
            ui.label(RichText::new(body).color(p.text_dim));
        });
        if let Some(h) = hint {
            ui.add_space(8.0);
            ui.scope(|ui| {
                ui.set_max_width(ui.available_width().min(420.0));
                ui.label(RichText::new(h).size(12.0).color(p.accent));
            });
        }
    });
}

/// A raised card surface.
pub fn card() -> Frame {
    Frame::new()
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
}

/// Accent-filled primary button.
pub fn primary_button(ui: &mut Ui, text: &str) -> egui::Response {
    let p = pal(ui);
    let label = RichText::new(text).color(if dark(ui) { p.bg } else { Color32::WHITE });
    ui.add(
        egui::Button::new(label)
            .fill(p.accent)
            .stroke(Stroke::NONE)
            .min_size(egui::vec2(0.0, 28.0)),
    )
}

/// `HH:MM:SS` (UTC) of a millisecond Unix timestamp.
pub fn clock(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000).rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_formats_utc_time_of_day() {
        assert_eq!(clock(0), "00:00:00");
        assert_eq!(clock(1_700_000_000_000), "22:13:20");
        assert_eq!(clock(-1000), "23:59:59");
    }

    #[test]
    fn status_colours_differ_per_mode() {
        assert_ne!(status(true).danger, status(false).danger);
    }
}

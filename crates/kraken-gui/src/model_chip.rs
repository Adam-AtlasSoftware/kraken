//! Draws the model chips (`kraken_viewmodel::infer::chips`): in the custom title bar, or at the
//! right of the in-window top bar when the system draws the title bar. The figures and what to
//! show are decided there; this only paints them.

use egui::{
    Align, Color32, CornerRadius, Frame, Layout, Margin, Rect, RichText, Shape, Stroke, Ui,
    UiBuilder, pos2, vec2,
};
use kraken_viewmodel::infer::card::Tone;
use kraken_viewmodel::infer::chips::{Chip, ChipAction, ChipBar, ChipState};

use crate::style::{self, medium, pal};

/// What a press on a chip's button asks for.
pub type ChipClick = (String, ChipAction);

fn tone_color(ui: &Ui, tone: Tone) -> Color32 {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    match tone {
        Tone::Neutral => p.text_dim,
        Tone::Good => s.success,
        Tone::Warn => s.warning,
        Tone::Bad => s.danger,
    }
}

fn one(ui: &mut Ui, chip: &Chip, busy: bool) -> Option<ChipClick> {
    let p = pal(ui);
    let color = tone_color(ui, chip.tone);
    let mut clicked = None;
    let frame = Frame::new()
        .fill(p.surface)
        .stroke(Stroke::new(1.0, p.border))
        .corner_radius(CornerRadius::same(11))
        .inner_margin(Margin::symmetric(8, 2));
    let mut prepared = frame.begin(ui);
    let fill = prepared.content_ui.painter().add(Shape::Noop);
    {
        let ui = &mut prepared.content_ui;
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
            let (dot, _) = ui.allocate_exact_size(vec2(8.0, 8.0), egui::Sense::hover());
            ui.painter().circle_filled(dot.center(), 4.0, color);
            ui.label(medium(&chip.name, 12.0).color(p.text_strong));
            if !chip.collapsed {
                if let Some(l) = &chip.label {
                    ui.label(RichText::new(l).size(12.0).color(color));
                }
                for part in &chip.parts {
                    ui.label(RichText::new(part).size(12.0).color(p.text));
                }
                if let Some(c) = &chip.countdown {
                    ui.label(RichText::new(c).size(12.0).color(p.text_dim));
                }
                if let Some(a) = chip.action {
                    let b = ui.add_enabled(
                        !busy,
                        egui::Button::new(RichText::new(a.label()).size(11.0))
                            .small()
                            .min_size(vec2(0.0, 18.0)),
                    );
                    let tip = match a {
                        ChipAction::Start => "Start serving this model",
                        ChipAction::Stop => "Stop serving this model",
                    };
                    if b.on_hover_text(tip)
                        .on_disabled_hover_text("Working on it.")
                        .clicked()
                    {
                        clicked = Some((chip.key.clone(), a));
                    }
                }
            }
        });
    }
    if let Some(f) = chip.progress.filter(|_| chip.state == ChipState::Loading) {
        let r = prepared.content_ui.min_rect().expand2(vec2(8.0, 2.0));
        let mut done = r;
        done.set_width(r.width() * f.clamp(0.0, 1.0));
        prepared.content_ui.painter().set(
            fill,
            Shape::rect_filled(done, CornerRadius::same(11), color.gamma_multiply(0.28)),
        );
    }
    let response = prepared.end(ui);
    response.on_hover_ui(|ui| {
        ui.set_max_width(360.0);
        ui.label(medium(&chip.name, 13.0));
        for line in &chip.hover {
            ui.add(egui::Label::new(RichText::new(line).size(12.0)).wrap());
        }
        if chip.collapsed {
            if let Some(l) = &chip.label {
                ui.label(RichText::new(l).size(12.0));
            }
            for part in &chip.parts {
                ui.label(RichText::new(part).size(12.0));
            }
        }
    });
    clicked
}

/// Draws the chips, the first one leftmost, against the right end of the room left in `ui`
/// (for the title bar: the strip given to them; for the top bar: what its buttons leave).
/// Returns the button the person pressed. `busy` says whether a start or stop of a model is on
/// its way.
pub fn show(ui: &mut Ui, bar: &ChipBar, busy: impl Fn(&str) -> bool) -> Option<ChipClick> {
    let p = pal(ui);
    let ctx = ui.ctx().clone();
    let room = ui.available_rect_before_wrap();
    // The width the chips took last time puts them flush right; the first frame guesses.
    let id = egui::Id::new("kraken_chip_strip_width");
    let known: f32 = ctx
        .data(|d| d.get_temp(id))
        .unwrap_or_else(|| bar.estimated_width());
    let width = known.min(room.width());
    let rect = Rect::from_min_max(pos2(room.right() - width, room.top()), room.right_bottom());
    let (clicked, used) = ui
        .scope_builder(
            UiBuilder::new()
                .max_rect(rect)
                .layout(Layout::left_to_right(Align::Center)),
            |ui| {
                let mut clicked = None;
                ui.spacing_mut().item_spacing.x = 6.0;
                for chip in &bar.chips {
                    let hit = one(ui, chip, busy(&chip.key));
                    clicked = clicked.or(hit);
                }
                if bar.hidden > 0 {
                    ui.label(
                        RichText::new(format!("+{}", bar.hidden))
                            .size(12.0)
                            .color(p.text_dim),
                    )
                    .on_hover_text("More local models; make the window wider to see them.");
                }
                (clicked, ui.min_rect().width())
            },
        )
        .inner;
    if (used - known).abs() > 1.0 {
        ctx.data_mut(|d| d.insert_temp(id, used));
        ctx.request_discard("the model chips changed width");
        ctx.request_repaint();
    }
    clicked
}

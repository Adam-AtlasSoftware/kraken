//! KRAKEN's own title bar (window decorations off): logo, project, the menus, the model
//! chips and minimise / maximise / close; dragging the empty bar moves the window, a double
//! click maximises it, and thin invisible zones along the edges resize it.
//!
//! Whether to use it is [`is_custom`]: the setting `[local_serving] titlebar`, and for
//! `auto` the desktop (KDE, GNOME and Windows get this bar; other window managers keep the
//! system's, which they draw and tile better).

use egui::{
    Align, Color32, Context, CursorIcon, Id, Layout, Rect, ResizeDirection, Sense, Stroke, Ui,
    UiBuilder, ViewportCommand, WidgetInfo, WidgetType, pos2, vec2,
};
use kraken_host::TitlebarMode;

use crate::menu::MenuCmd;
use crate::style::{self, medium, pal};

/// Width the three window buttons take, with their gaps.
const BUTTONS_W: f32 = 3.0 * 36.0 + 8.0;
/// Room between the menus and the chips.
const GAP: f32 = 14.0;
/// Width the menus are given before they have been measured.
const MENUS_GUESS: f32 = 640.0;

/// Whether the window draws its own title bar. `desktop` is `XDG_CURRENT_DESKTOP`.
pub fn is_custom(mode: TitlebarMode, desktop: Option<&str>, windows: bool) -> bool {
    match mode {
        TitlebarMode::Custom => true,
        TitlebarMode::System => false,
        TitlebarMode::Auto => {
            windows
                || desktop.is_some_and(|d| {
                    let d = d.to_ascii_lowercase();
                    d.split(':')
                        .any(|e| e.contains("kde") || e.contains("gnome"))
                })
        }
    }
}

/// [`is_custom`] for this computer.
pub fn custom_here(mode: TitlebarMode) -> bool {
    is_custom(
        mode,
        std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref(),
        cfg!(windows),
    )
}

/// The sensitive strip along the window's edge, in points: 5 of them, and never less than 4
/// real pixels on a small scale factor.
pub fn edge_margin(pixels_per_point: f32) -> f32 {
    5.0_f32.max(4.0 / pixels_per_point.max(0.1))
}

/// The eight zones that start a resize: four edges (without the corners) and four square
/// corners twice the edge's width.
pub fn resize_zones(screen: Rect, m: f32) -> [(Rect, ResizeDirection); 8] {
    let c = 2.0 * m;
    let (l, r, t, b) = (screen.min.x, screen.max.x, screen.min.y, screen.max.y);
    let rect = |x0: f32, y0: f32, x1: f32, y1: f32| Rect::from_min_max(pos2(x0, y0), pos2(x1, y1));
    [
        (rect(l + c, t, r - c, t + m), ResizeDirection::North),
        (rect(l + c, b - m, r - c, b), ResizeDirection::South),
        (rect(l, t + c, l + m, b - c), ResizeDirection::West),
        (rect(r - m, t + c, r, b - c), ResizeDirection::East),
        (rect(l, t, l + c, t + c), ResizeDirection::NorthWest),
        (rect(r - c, t, r, t + c), ResizeDirection::NorthEast),
        (rect(l, b - c, l + c, b), ResizeDirection::SouthWest),
        (rect(r - c, b - c, r, b), ResizeDirection::SouthEast),
    ]
}

/// The direction a press at `p` would resize in, if it is in a zone.
#[cfg(test)]
pub fn resize_zone(p: egui::Pos2, screen: Rect, m: f32) -> Option<ResizeDirection> {
    resize_zones(screen, m)
        .into_iter()
        .find(|(r, _)| r.contains(p))
        .map(|(_, d)| d)
}

/// The mouse pointer over a zone.
pub fn cursor_for(d: ResizeDirection) -> CursorIcon {
    match d {
        ResizeDirection::North | ResizeDirection::South => CursorIcon::ResizeVertical,
        ResizeDirection::East | ResizeDirection::West => CursorIcon::ResizeHorizontal,
        ResizeDirection::NorthWest | ResizeDirection::SouthEast => CursorIcon::ResizeNwSe,
        ResizeDirection::NorthEast | ResizeDirection::SouthWest => CursorIcon::ResizeNeSw,
    }
}

fn floating(ctx: &Context) -> bool {
    ctx.input(|i| {
        let v = i.viewport();
        v.maximized != Some(true) && v.fullscreen != Some(true)
    })
}

/// The invisible edge zones. Call once per frame while the custom bar is in use; nothing
/// while the window is maximised or full screen.
pub fn resize_handles(ctx: &Context) {
    if !floating(ctx) {
        return;
    }
    let m = edge_margin(ctx.pixels_per_point());
    for (i, (rect, dir)) in resize_zones(ctx.content_rect(), m).into_iter().enumerate() {
        egui::Area::new(Id::new(("kraken_resize_zone", i)))
            .order(egui::Order::Foreground)
            .fixed_pos(rect.min)
            .constrain(false)
            .show(ctx, |ui| {
                let (_, r) = ui.allocate_exact_size(rect.size(), Sense::click_and_drag());
                if r.hovered() {
                    ctx.set_cursor_icon(cursor_for(dir));
                    if ctx.input(|i| i.pointer.primary_pressed()) {
                        ctx.send_viewport_cmd(ViewportCommand::BeginResize(dir));
                    }
                }
            });
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Caption {
    Minimize,
    Maximize,
    Close,
}

fn caption_button(ui: &mut Ui, kind: Caption, maximized: bool) -> egui::Response {
    let (label, tip) = match kind {
        Caption::Minimize => ("Minimize window", "Minimize"),
        Caption::Maximize if maximized => ("Restore window", "Restore the window's size"),
        Caption::Maximize => ("Maximize window", "Maximize"),
        Caption::Close => ("Close window", "Close KRAKEN"),
    };
    let (rect, r) = ui.allocate_exact_size(vec2(36.0, 26.0), Sense::click());
    r.widget_info(|| WidgetInfo::labeled(WidgetType::Button, true, label));
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    if r.hovered() {
        let fill = if kind == Caption::Close {
            s.danger.gamma_multiply(0.85)
        } else {
            p.surface_hover
        };
        ui.painter().rect_filled(rect, 5.0, fill);
    }
    let color = if r.hovered() && kind == Caption::Close {
        Color32::WHITE
    } else {
        p.text
    };
    let stroke = Stroke::new(1.3, color);
    let c = rect.center();
    let d = 5.0;
    let painter = ui.painter();
    match kind {
        Caption::Minimize => {
            painter.line_segment([c + vec2(-d, 2.0), c + vec2(d, 2.0)], stroke);
        }
        Caption::Maximize if maximized => {
            let back = Rect::from_center_size(c + vec2(1.5, -1.5), vec2(7.0, 7.0));
            let front = Rect::from_center_size(c + vec2(-1.0, 1.0), vec2(7.0, 7.0));
            painter.rect_stroke(back, 1.0, stroke, egui::StrokeKind::Middle);
            painter.rect_filled(front.expand(0.5), 0.0, ui.visuals().panel_fill);
            painter.rect_stroke(front, 1.0, stroke, egui::StrokeKind::Middle);
        }
        Caption::Maximize => {
            painter.rect_stroke(
                Rect::from_center_size(c, vec2(2.0 * d, 2.0 * d)),
                1.0,
                stroke,
                egui::StrokeKind::Middle,
            );
        }
        Caption::Close => {
            painter.line_segment([c + vec2(-d, -d), c + vec2(d, d)], stroke);
            painter.line_segment([c + vec2(-d, d), c + vec2(d, -d)], stroke);
        }
    }
    r.on_hover_text(tip)
}

/// What the custom bar draws between the logo and the window buttons.
pub struct BarParts<M, C> {
    /// The open project's name, if one is open.
    pub project: Option<String>,
    /// The menus: returns what was clicked and the x position where they end.
    pub menus: M,
    /// The chips, given the width there is for them.
    pub chips: C,
}

/// Draws the bar into `ui` (the panel's inside) and returns the menu clicks.
pub fn custom_bar<M, C>(ui: &mut Ui, parts: BarParts<M, C>) -> Vec<MenuCmd>
where
    M: FnOnce(&mut Ui) -> (Vec<MenuCmd>, f32),
    C: FnOnce(&mut Ui, f32),
{
    let ctx = ui.ctx().clone();
    let row = ui.max_rect();
    let maximized = ctx.input(|i| i.viewport().maximized == Some(true));
    // Under everything else, so the menus and chips win their own clicks.
    let drag = ui.interact(
        row,
        Id::new("kraken_titlebar_drag"),
        Sense::click_and_drag(),
    );
    if drag.drag_started_by(egui::PointerButton::Primary) {
        ctx.send_viewport_cmd(ViewportCommand::StartDrag);
    }
    if drag.double_clicked() {
        ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
    }

    let p = pal(ui);
    let width_id = Id::new("kraken_titlebar_menus");
    let known: f32 = ctx.data(|d| d.get_temp(width_id)).unwrap_or(MENUS_GUESS);
    let left_end = (row.min.x + known + 8.0).min(row.max.x - BUTTONS_W);
    let left = Rect::from_min_max(row.min, pos2(left_end, row.max.y));
    let centered = Layout::left_to_right(Align::Center);
    let (cmds, menus_end) = ui
        .scope_builder(UiBuilder::new().max_rect(left).layout(centered), |ui| {
            ui.add_space(2.0);
            ui.label(medium("KRAKEN", 16.0).color(p.accent));
            if let Some(name) = &parts.project {
                ui.add_space(4.0);
                ui.label(medium(name, 14.0).color(p.text_strong));
            }
            ui.add_space(10.0);
            (parts.menus)(ui)
        })
        .inner;
    let used = (menus_end - row.min.x).max(0.0);
    if (used - known).abs() > 1.0 && used > 0.0 {
        ctx.data_mut(|d| d.insert_temp(width_id, used));
        ctx.request_discard("the menus changed width");
        ctx.request_repaint();
    }

    let buttons = Rect::from_min_max(pos2(row.max.x - BUTTONS_W, row.min.y), row.max);
    let chips_from = (row.min.x + used + GAP).min(buttons.min.x);
    let chips = Rect::from_min_max(
        pos2(chips_from, row.min.y),
        pos2(buttons.min.x - 8.0, row.max.y),
    );
    let right_to_left = Layout::right_to_left(Align::Center);
    ui.scope_builder(
        UiBuilder::new().max_rect(chips).layout(right_to_left),
        |ui| {
            (parts.chips)(ui, chips.width());
        },
    );
    ui.scope_builder(UiBuilder::new().max_rect(buttons).layout(centered), |ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.add_space(4.0);
        if caption_button(ui, Caption::Minimize, maximized).clicked() {
            ctx.send_viewport_cmd(ViewportCommand::Minimized(true));
        }
        if caption_button(ui, Caption::Maximize, maximized).clicked() {
            ctx.send_viewport_cmd(ViewportCommand::Maximized(!maximized));
        }
        if caption_button(ui, Caption::Close, maximized).clicked() {
            ctx.send_viewport_cmd(ViewportCommand::Close);
        }
    });
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_picks_the_bar_by_desktop() {
        let auto = |d: Option<&str>, w| is_custom(TitlebarMode::Auto, d, w);
        assert!(auto(Some("KDE"), false));
        assert!(auto(Some("GNOME"), false));
        assert!(auto(Some("ubuntu:GNOME"), false));
        assert!(auto(Some("gnome-classic:gnome"), false));
        assert!(auto(Some("X-Cinnamon"), true), "Windows always");
        assert!(auto(None, true));
        for d in ["Hyprland", "sway", "i3", "XFCE", "COSMIC", "X-Cinnamon", ""] {
            assert!(!auto(Some(d), false), "{d}");
        }
        assert!(!auto(None, false), "macOS and unknown desktops");
    }

    #[test]
    fn the_setting_overrides_the_desktop() {
        assert!(is_custom(TitlebarMode::Custom, Some("Hyprland"), false));
        assert!(!is_custom(TitlebarMode::System, Some("KDE"), true));
    }

    #[test]
    fn the_edge_is_five_points_and_grows_on_small_scales() {
        assert_eq!(edge_margin(1.0), 5.0);
        assert_eq!(edge_margin(2.0), 5.0);
        assert_eq!(edge_margin(0.5), 8.0);
    }

    #[test]
    fn zones_give_the_right_direction_with_the_matching_cursor() {
        let screen = Rect::from_min_max(pos2(0.0, 0.0), pos2(1000.0, 600.0));
        let at = |x: f32, y: f32| resize_zone(pos2(x, y), screen, 5.0);
        assert_eq!(at(500.0, 1.0), Some(ResizeDirection::North));
        assert_eq!(at(500.0, 599.0), Some(ResizeDirection::South));
        assert_eq!(at(1.0, 300.0), Some(ResizeDirection::West));
        assert_eq!(at(999.0, 300.0), Some(ResizeDirection::East));
        assert_eq!(at(2.0, 2.0), Some(ResizeDirection::NorthWest));
        assert_eq!(at(998.0, 2.0), Some(ResizeDirection::NorthEast));
        assert_eq!(at(2.0, 598.0), Some(ResizeDirection::SouthWest));
        assert_eq!(at(998.0, 598.0), Some(ResizeDirection::SouthEast));
        assert_eq!(
            at(9.0, 9.0),
            Some(ResizeDirection::NorthWest),
            "corners are bigger"
        );
        assert_eq!(at(500.0, 300.0), None, "the middle is the app's");
        assert_eq!(at(500.0, 7.0), None);
        assert_eq!(
            cursor_for(ResizeDirection::North),
            CursorIcon::ResizeVertical
        );
        assert_eq!(
            cursor_for(ResizeDirection::West),
            CursorIcon::ResizeHorizontal
        );
        assert_eq!(
            cursor_for(ResizeDirection::NorthWest),
            CursorIcon::ResizeNwSe
        );
        assert_eq!(
            cursor_for(ResizeDirection::SouthWest),
            CursorIcon::ResizeNeSw
        );
    }

    #[test]
    fn zones_do_not_overlap() {
        let screen = Rect::from_min_max(pos2(0.0, 0.0), pos2(400.0, 300.0));
        let z = resize_zones(screen, 5.0);
        for (i, (a, _)) in z.iter().enumerate() {
            for (b, _) in z.iter().skip(i + 1) {
                assert!(!a.intersects(*b) || a.intersect(*b).area() == 0.0);
            }
        }
    }
}

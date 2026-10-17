//! KRAKEN colour theme: a calm blue-teal dark theme and a matching light theme.

use egui::{
    Color32, Context, CornerRadius, FontFamily, FontId, Margin, Shadow, Stroke, TextStyle, Vec2,
};
use kraken_proto::TokenKind;

const fn rgb(hex: u32) -> Color32 {
    Color32::from_rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

/// Every colour the widgets use, resolved for one theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub surface: Color32,
    pub surface_hover: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_strong: Color32,
    pub text_dim: Color32,
    pub accent: Color32,
    pub selection: Color32,
    pub row_hover: Color32,
    pub row_stripe: Color32,
    pub highlight: Color32,
    pub address: Color32,
    pub hex_byte: Color32,
    pub hex_zero: Color32,
    pub ascii: Color32,
    pub gutter: Color32,
}

/// Syntax colours per [`TokenKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenStyle {
    keyword: Color32,
    variable: Color32,
    function: Color32,
    type_: Color32,
    field: Color32,
    constant: Color32,
    comment: Color32,
    op: Color32,
    other: Color32,
}

impl TokenStyle {
    /// Colour for a token kind.
    pub fn color(&self, kind: TokenKind) -> Color32 {
        match kind {
            TokenKind::Keyword => self.keyword,
            TokenKind::Variable => self.variable,
            TokenKind::Function => self.function,
            TokenKind::Type => self.type_,
            TokenKind::Field => self.field,
            TokenKind::Constant => self.constant,
            TokenKind::Comment => self.comment,
            TokenKind::Op => self.op,
            TokenKind::Other => self.other,
        }
    }

    /// Comments are drawn in italics.
    pub fn italic(&self, kind: TokenKind) -> bool {
        kind == TokenKind::Comment
    }

    /// Style for the given theme.
    pub fn for_theme(theme: &KrakenTheme) -> Self {
        if theme.dark {
            Self {
                keyword: rgb(0xb8a1f2),
                variable: rgb(0xd5e3ea),
                function: rgb(0x6cc6f0),
                type_: rgb(0xf0c987),
                field: rgb(0x8fd6b4),
                constant: rgb(0xf29c7c),
                comment: rgb(0x607d8b),
                op: rgb(0x8fa8b5),
                other: rgb(0xb4c6cf),
            }
        } else {
            Self {
                keyword: rgb(0x7048c4),
                variable: rgb(0x23343d),
                function: rgb(0x0b72a8),
                type_: rgb(0x9a6408),
                field: rgb(0x1d8a63),
                constant: rgb(0xc2501f),
                comment: rgb(0x7f929c),
                op: rgb(0x5d7480),
                other: rgb(0x40545e),
            }
        }
    }
}

/// The KRAKEN theme. `apply` installs it on an egui context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KrakenTheme {
    pub dark: bool,
}

impl KrakenTheme {
    pub const DARK: Self = Self { dark: true };
    pub const LIGHT: Self = Self { dark: false };

    /// Monospace font size used by the code widgets.
    pub const MONO_SIZE: f32 = 13.0;

    /// Theme matching the context's current dark/light mode.
    pub fn from_ctx(ctx: &Context) -> Self {
        Self {
            dark: ctx.global_style().visuals.dark_mode,
        }
    }

    pub fn palette(&self) -> Palette {
        if self.dark {
            Palette {
                bg: rgb(0x0b1820),
                panel: rgb(0x0f2029),
                surface: rgb(0x16303b),
                surface_hover: rgb(0x1d3b48),
                border: rgb(0x23424f),
                text: rgb(0xc9d9e0),
                text_strong: rgb(0xeaf3f6),
                text_dim: rgb(0x6f8b98),
                accent: rgb(0x34d3bd),
                selection: Color32::from_rgba_unmultiplied(0x34, 0xd3, 0xbd, 56),
                row_hover: Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 10),
                row_stripe: Color32::from_rgba_unmultiplied(0xff, 0xff, 0xff, 5),
                highlight: Color32::from_rgba_unmultiplied(0xf0, 0xc9, 0x87, 56),
                address: rgb(0x5fa3b8),
                hex_byte: rgb(0xc3d4db),
                hex_zero: rgb(0x436270),
                ascii: rgb(0x8fd6b4),
                gutter: rgb(0x4f6c79),
            }
        } else {
            Palette {
                bg: rgb(0xf4f8f9),
                panel: rgb(0xeaf1f3),
                surface: rgb(0xdde9ed),
                surface_hover: rgb(0xcfe1e7),
                border: rgb(0xc3d5dc),
                text: rgb(0x2b3e47),
                text_strong: rgb(0x0e1c22),
                text_dim: rgb(0x4a5f68),
                accent: rgb(0x0b8577),
                selection: Color32::from_rgba_unmultiplied(0x0b, 0x85, 0x77, 52),
                row_hover: Color32::from_rgba_unmultiplied(0x00, 0x30, 0x40, 14),
                row_stripe: Color32::from_rgba_unmultiplied(0x00, 0x30, 0x40, 8),
                highlight: Color32::from_rgba_unmultiplied(0xe0, 0x9a, 0x10, 62),
                address: rgb(0x1f6f88),
                hex_byte: rgb(0x2b3e47),
                hex_zero: rgb(0xa5b8c0),
                ascii: rgb(0x187a56),
                gutter: rgb(0x7a8e97),
            }
        }
    }

    pub fn token_style(&self) -> TokenStyle {
        TokenStyle::for_theme(self)
    }

    /// Monospace font used by the code widgets.
    pub fn mono_font() -> FontId {
        FontId::new(Self::MONO_SIZE, FontFamily::Monospace)
    }

    /// Installs visuals, spacing, rounding and font sizes on `ctx`.
    pub fn apply(&self, ctx: &Context) {
        let p = self.palette();
        let theme = if self.dark {
            egui::Theme::Dark
        } else {
            egui::Theme::Light
        };
        ctx.set_theme(theme);
        let dark = self.dark;
        ctx.all_styles_mut(move |style| {
            if style.visuals.dark_mode != dark {
                return;
            }
            let v = &mut style.visuals;
            v.panel_fill = p.panel;
            v.window_fill = p.panel;
            v.extreme_bg_color = p.bg;
            v.faint_bg_color = p.row_stripe;
            v.code_bg_color = p.surface;
            v.hyperlink_color = p.accent;
            v.override_text_color = None;
            v.window_stroke = Stroke::new(1.0, p.border);
            v.window_corner_radius = CornerRadius::same(10);
            v.menu_corner_radius = CornerRadius::same(8);
            v.window_shadow = Shadow {
                offset: [0, 8],
                blur: 24,
                spread: 0,
                color: Color32::from_black_alpha(if dark { 110 } else { 40 }),
            };
            v.popup_shadow = v.window_shadow;
            v.selection.bg_fill = p.selection;
            v.selection.stroke = Stroke::new(1.0, p.accent);

            let radius = CornerRadius::same(6);
            let w = &mut v.widgets;
            w.noninteractive.bg_fill = p.panel;
            w.noninteractive.weak_bg_fill = p.panel;
            w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
            w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
            w.inactive.bg_fill = p.surface;
            w.inactive.weak_bg_fill = p.surface;
            w.inactive.bg_stroke = Stroke::NONE;
            w.inactive.fg_stroke = Stroke::new(1.0, p.text);
            w.hovered.bg_fill = p.surface_hover;
            w.hovered.weak_bg_fill = p.surface_hover;
            w.hovered.bg_stroke = Stroke::new(1.0, p.accent);
            w.hovered.fg_stroke = Stroke::new(1.5, p.text_strong);
            w.active.bg_fill = p.surface_hover;
            w.active.weak_bg_fill = p.surface_hover;
            w.active.bg_stroke = Stroke::new(1.0, p.accent);
            w.active.fg_stroke = Stroke::new(1.5, p.text_strong);
            w.open.bg_fill = p.surface;
            w.open.weak_bg_fill = p.surface;
            w.open.bg_stroke = Stroke::new(1.0, p.border);
            w.open.fg_stroke = Stroke::new(1.0, p.text);
            for ws in [
                &mut w.noninteractive,
                &mut w.inactive,
                &mut w.hovered,
                &mut w.active,
                &mut w.open,
            ] {
                ws.corner_radius = radius;
            }

            style.spacing.item_spacing = Vec2::new(8.0, 6.0);
            style.spacing.button_padding = Vec2::new(10.0, 4.0);
            style.spacing.interact_size.y = 24.0;
            style.spacing.window_margin = Margin::same(12);
            style.spacing.menu_margin = Margin::same(8);
            style.spacing.scroll.bar_width = 8.0;
            style.spacing.scroll.floating = true;

            let sizes = [
                (
                    TextStyle::Heading,
                    FontId::new(18.0, FontFamily::Proportional),
                ),
                (TextStyle::Body, FontId::new(13.5, FontFamily::Proportional)),
                (
                    TextStyle::Button,
                    FontId::new(13.5, FontFamily::Proportional),
                ),
                (
                    TextStyle::Small,
                    FontId::new(11.0, FontFamily::Proportional),
                ),
                (TextStyle::Monospace, Self::mono_font()),
            ];
            for (ts, font) in sizes {
                style.text_styles.insert(ts, font);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_a_distinct_colour_except_other() {
        let s = KrakenTheme::DARK.token_style();
        let kinds = [
            TokenKind::Keyword,
            TokenKind::Variable,
            TokenKind::Function,
            TokenKind::Type,
            TokenKind::Field,
            TokenKind::Constant,
            TokenKind::Comment,
            TokenKind::Op,
        ];
        for (i, a) in kinds.iter().enumerate() {
            for b in &kinds[i + 1..] {
                assert_ne!(s.color(*a), s.color(*b), "{a:?} vs {b:?}");
            }
        }
    }

    fn luminance(c: Color32) -> f32 {
        let lin = |v: u8| {
            let v = f32::from(v) / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(c.r()) + 0.7152 * lin(c.g()) + 0.0722 * lin(c.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (x, y) = (luminance(a), luminance(b));
        (x.max(y) + 0.05) / (x.min(y) + 0.05)
    }

    #[test]
    fn dim_captions_stay_readable_in_the_light_theme() {
        let p = KrakenTheme::LIGHT.palette();
        for (name, bg) in [
            ("bg", p.bg),
            ("panel", p.panel),
            ("surface", p.surface),
            ("surface_hover", p.surface_hover),
        ] {
            let c = contrast(p.text_dim, bg);
            assert!(c >= 4.5, "text_dim on {name} is {c:.2}:1");
        }
    }

    #[test]
    fn light_and_dark_differ() {
        assert_ne!(KrakenTheme::DARK.palette(), KrakenTheme::LIGHT.palette());
    }
}

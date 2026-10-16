//! Disassembly-style listing: address, bytes, mnemonic, operands, comment.

use egui::text::{LayoutJob, TextFormat};
use egui::{Align2, Id, Pos2, Ui};
use kraken_proto::TokenKind;

use crate::theme::KrakenTheme;
use crate::virtual_list::{VirtualList, VirtualListResponse};

/// One coloured piece of an operand list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandToken {
    pub text: String,
    pub kind: TokenKind,
    /// Address the token refers to; such tokens are underlined on hover and can be clicked.
    pub target: Option<u64>,
}

impl OperandToken {
    pub fn new(text: impl Into<String>, kind: TokenKind) -> Self {
        Self {
            text: text.into(),
            kind,
            target: None,
        }
    }

    /// A token that jumps to `target` when clicked.
    pub fn with_target(mut self, target: u64) -> Self {
        self.target = Some(target);
        self
    }
}

/// One listing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingRow {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub mnemonic_kind: TokenKind,
    pub operands: Vec<OperandToken>,
    pub comment: Option<String>,
}

/// Lazy provider of listing rows.
pub trait ListingSource {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn row(&self, index: usize) -> ListingRow;
}

/// `"48 89 e5"`, truncated with an ellipsis after `max` bytes.
pub fn format_bytes(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    for (i, b) in bytes.iter().take(max).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    if bytes.len() > max {
        s.push_str(" ..");
    }
    s
}

/// What happened in a [`ListingView::show_with_targets`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ListingResponse {
    /// Row selection and clicks, as for any [`VirtualList`].
    pub list: VirtualListResponse,
    /// A token with a target was clicked: the row and the target address.
    pub target_clicked: Option<(usize, u64)>,
    /// The row and target of the token under the pointer.
    pub target_hovered: Option<(usize, u64)>,
    /// The row under the pointer.
    pub row_hovered: Option<usize>,
}

pub struct ListingView<'a> {
    source: &'a dyn ListingSource,
    id: Id,
    address_digits: usize,
    scroll_to: Option<usize>,
}

impl<'a> ListingView<'a> {
    pub fn new(source: &'a dyn ListingSource) -> Self {
        Self {
            source,
            id: Id::new("kraken_listing_view"),
            address_digits: 8,
            scroll_to: None,
        }
    }

    pub fn id_salt(mut self, salt: impl std::hash::Hash + std::fmt::Debug) -> Self {
        self.id = Id::new("kraken_widget").with(salt);
        self
    }

    pub fn address_digits(mut self, digits: usize) -> Self {
        self.address_digits = digits;
        self
    }

    /// Scrolls the given row into view this frame.
    pub fn scroll_to(mut self, row: usize) -> Self {
        self.scroll_to = Some(row);
        self
    }

    pub fn show(self, ui: &mut Ui, selected: &mut Option<usize>) -> VirtualListResponse {
        self.show_with_targets(ui, selected).list
    }

    pub fn show_with_targets(self, ui: &mut Ui, selected: &mut Option<usize>) -> ListingResponse {
        let theme = KrakenTheme::from_ctx(ui.ctx());
        let pal = theme.palette();
        let style = theme.token_style();
        let font = KrakenTheme::mono_font();
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let row_h = ui.fonts_mut(|f| f.row_height(&font)) + 5.0;
        let addr_w = (self.address_digits as f32 + 2.0) * cw;
        let bytes_w = 22.0 * cw;
        let digits = self.address_digits;

        let (pointer, pressed) = ui.input(|i| (i.pointer.hover_pos(), i.pointer.primary_clicked()));
        let mut out = ListingResponse::default();
        let mut list = VirtualList::new(self.id, self.source.len(), row_h);
        if let Some(r) = self.scroll_to {
            list = list.scroll_to(r);
        }
        out.list = list.show(ui, selected, |ui, index, _| {
            let row = self.source.row(index);
            let rect = ui.max_rect();
            let painter = ui.painter_at(rect);
            let mid = rect.center().y;
            let mut x = rect.left();
            painter.text(
                Pos2::new(x, mid),
                Align2::LEFT_CENTER,
                format!("{:0digits$x}", row.address),
                font.clone(),
                pal.address,
            );
            x += addr_w;
            painter.text(
                Pos2::new(x, mid),
                Align2::LEFT_CENTER,
                format_bytes(&row.bytes, 6),
                font.clone(),
                pal.text_dim,
            );
            x += bytes_w;
            let mut job = LayoutJob::default();
            let mnem = TextFormat::simple(font.clone(), style.color(row.mnemonic_kind));
            job.append(&row.mnemonic, 0.0, mnem);
            let pad = row.mnemonic.chars().count().min(8);
            job.append(
                &" ".repeat(9 - pad),
                0.0,
                TextFormat::simple(font.clone(), pal.text),
            );
            let mut col = 9.0_f32.max(row.mnemonic.chars().count() as f32 + 1.0);
            let hovering_row = pointer.is_some_and(|p| rect.contains(p));
            if hovering_row {
                out.row_hovered = Some(index);
            }
            for t in &row.operands {
                job.append(
                    &t.text,
                    0.0,
                    TextFormat::simple(font.clone(), style.color(t.kind)),
                );
                let width = t.text.chars().count() as f32;
                if let Some(target) = t.target
                    && let Some(p) = pointer.filter(|_| hovering_row)
                {
                    let left = x + col * cw;
                    let span = egui::Rect::from_min_max(
                        Pos2::new(left, rect.top()),
                        Pos2::new(left + width * cw, rect.bottom()),
                    );
                    if span.contains(p) {
                        let y = mid + row_h / 2.0 - 3.0;
                        painter.line_segment(
                            [Pos2::new(span.left(), y), Pos2::new(span.right(), y)],
                            egui::Stroke::new(1.0, style.color(t.kind)),
                        );
                        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                        out.target_hovered = Some((index, target));
                        if pressed {
                            out.target_clicked = Some((index, target));
                        }
                    }
                }
                col += width;
            }
            if let Some(c) = &row.comment {
                let mut fmt = TextFormat::simple(font.clone(), style.color(TokenKind::Comment));
                fmt.italics = true;
                job.append("   ; ", 0.0, fmt.clone());
                job.append(c, 0.0, fmt);
            }
            let galley = painter.layout_job(job);
            painter.galley(Pos2::new(x, mid - galley.size().y / 2.0), galley, pal.text);
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_format_and_truncate() {
        assert_eq!(format_bytes(&[0x48, 0x89, 0xe5], 8), "48 89 e5");
        assert_eq!(format_bytes(&[1, 2, 3], 2), "01 02 ..");
        assert_eq!(format_bytes(&[], 4), "");
    }
}

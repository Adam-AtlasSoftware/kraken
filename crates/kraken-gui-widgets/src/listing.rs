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
}

impl OperandToken {
    pub fn new(text: impl Into<String>, kind: TokenKind) -> Self {
        Self {
            text: text.into(),
            kind,
        }
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

pub struct ListingView<'a> {
    source: &'a dyn ListingSource,
    id: Id,
    address_digits: usize,
}

impl<'a> ListingView<'a> {
    pub fn new(source: &'a dyn ListingSource) -> Self {
        Self {
            source,
            id: Id::new("kraken_listing_view"),
            address_digits: 8,
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

    pub fn show(self, ui: &mut Ui, selected: &mut Option<usize>) -> VirtualListResponse {
        let theme = KrakenTheme::from_ctx(ui.ctx());
        let pal = theme.palette();
        let style = theme.token_style();
        let font = KrakenTheme::mono_font();
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let row_h = ui.fonts_mut(|f| f.row_height(&font)) + 5.0;
        let addr_w = (self.address_digits as f32 + 2.0) * cw;
        let bytes_w = 19.0 * cw;
        let digits = self.address_digits;

        VirtualList::new(self.id, self.source.len(), row_h).show(ui, selected, |ui, index, _| {
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
                pal.hex_zero.gamma_multiply(1.5),
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
            for t in &row.operands {
                job.append(
                    &t.text,
                    0.0,
                    TextFormat::simple(font.clone(), style.color(t.kind)),
                );
            }
            if let Some(c) = &row.comment {
                let mut fmt = TextFormat::simple(font.clone(), style.color(TokenKind::Comment));
                fmt.italics = true;
                job.append("   ; ", 0.0, fmt.clone());
                job.append(c, 0.0, fmt);
            }
            let galley = painter.layout_job(job);
            painter.galley(Pos2::new(x, mid - galley.size().y / 2.0), galley, pal.text);
        })
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

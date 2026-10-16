//! Virtualised hex dump with drag selection and highlighted ranges.

use std::ops::Range;

use egui::text::{LayoutJob, TextFormat};
use egui::{Align2, Color32, Id, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2};

use crate::theme::KrakenTheme;

/// Bytes per hex row.
pub const BYTES_PER_ROW: usize = 16;

/// What is known about one byte of a [`ByteSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ByteState {
    /// A real value.
    #[default]
    Ready,
    /// Memory without contents (like `.bss`); drawn greyed out.
    Uninitialized,
    /// Not loaded yet; drawn as a placeholder.
    Pending,
    /// Nothing is mapped here or the read failed.
    Unmapped,
}

/// Random-access byte provider, so huge or lazily loaded data need not be in memory.
pub trait ByteSource {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Fills `buf` from `offset`; returns the number of bytes written (short at the end).
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize;
    /// Whether the byte at `offset` is a real value; sources that are always complete keep the
    /// default.
    fn state(&self, _offset: u64) -> ByteState {
        ByteState::Ready
    }
}

impl ByteSource for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        let Ok(start) = usize::try_from(offset) else {
            return 0;
        };
        let Some(src) = <[u8]>::get(self, start..) else {
            return 0;
        };
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        n
    }
}

impl ByteSource for Vec<u8> {
    fn len(&self) -> u64 {
        Vec::len(self) as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        self.as_slice().read(offset, buf)
    }
}

/// Sized wrapper so a borrowed slice can be passed as `&dyn ByteSource`.
pub struct SliceSource<'a>(pub &'a [u8]);

impl ByteSource for SliceSource<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }
    fn read(&self, offset: u64, buf: &mut [u8]) -> usize {
        self.0.read(offset, buf)
    }
}

/// Text of one hex row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexRowText {
    pub address: String,
    /// Two hex digits per byte (no separators), at most 16 entries.
    pub bytes: Vec<String>,
    pub ascii: String,
}

/// Number of hex digits needed for addresses up to `max_addr`.
pub fn address_digits(max_addr: u64) -> usize {
    if max_addr > u32::MAX as u64 { 16 } else { 8 }
}

/// Formats row `row` (0-based) of data at `base`.
pub fn format_row(base: u64, row: u64, data: &[u8], digits: usize) -> HexRowText {
    let addr = base.wrapping_add(row * BYTES_PER_ROW as u64);
    HexRowText {
        address: format!("{addr:0digits$x}"),
        bytes: data.iter().map(|b| format!("{b:02x}")).collect(),
        ascii: data
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect(),
    }
}

/// Character column (in monospace cells, relative to the hex column start) of byte `i`.
pub fn hex_col(i: usize) -> usize {
    i * 3 + i / 8
}

/// Inverse of [`hex_col`]: the byte index under a cell column, if any.
pub fn byte_at_hex_col(col: isize) -> Option<usize> {
    if col < 0 {
        return None;
    }
    let col = col as usize;
    let group = col / 25; // 8 bytes * 3 + 1 spacer
    let in_group = col % 25;
    let b = (in_group / 3).min(7);
    let i = group * 8 + b;
    (i < BYTES_PER_ROW).then_some(i)
}

/// A drag selection; `anchor` is where it started, `cursor` where it is now (both inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionState {
    pub anchor: u64,
    pub cursor: u64,
}

impl SelectionState {
    /// Half-open byte range covered.
    pub fn range(&self) -> Range<u64> {
        self.anchor.min(self.cursor)..self.anchor.max(self.cursor) + 1
    }
}

/// Maps a (row, byte column) cell to an absolute offset, clamped to `len`.
pub fn offset_for_cell(row: u64, col: usize, len: u64) -> Option<u64> {
    if len == 0 {
        return None;
    }
    Some((row * BYTES_PER_ROW as u64 + col as u64).min(len - 1))
}

/// Result of showing a [`HexView`]. Offsets are relative to the start of the data, not `base`.
pub struct HexViewResponse {
    pub response: Response,
    pub selection: Option<Range<u64>>,
    pub hovered: Option<u64>,
}

pub struct HexView<'a> {
    source: &'a dyn ByteSource,
    base: u64,
    id: Id,
    highlights: &'a [(Range<u64>, Color32)],
    scroll_to: Option<u64>,
}

impl<'a> HexView<'a> {
    pub fn new(source: &'a dyn ByteSource, base: u64) -> Self {
        Self {
            source,
            base,
            id: Id::new("kraken_hex_view"),
            highlights: &[],
            scroll_to: None,
        }
    }

    /// Scrolls so the row holding `offset` (relative to the data start) is near the top this frame.
    pub fn scroll_to(mut self, offset: u64) -> Self {
        self.scroll_to = Some(offset);
        self
    }

    pub fn id_salt(mut self, salt: impl std::hash::Hash + std::fmt::Debug) -> Self {
        self.id = Id::new("kraken_widget").with(salt);
        self
    }

    /// Highlighted byte ranges (relative to the data start) with their background colours.
    pub fn highlights(mut self, h: &'a [(Range<u64>, Color32)]) -> Self {
        self.highlights = h;
        self
    }

    pub fn show(self, ui: &mut Ui) -> HexViewResponse {
        let theme = KrakenTheme::from_ctx(ui.ctx());
        let pal = theme.palette();
        let font = KrakenTheme::mono_font();
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let row_h = ui.fonts_mut(|f| f.row_height(&font)) + 3.0;
        let len = self.source.len();
        let rows = len.div_ceil(BYTES_PER_ROW as u64) as usize;
        let digits = address_digits(self.base.saturating_add(len));
        let id = ui.make_persistent_id(self.id);

        let pad = 10.0;
        let hex_x = pad + (digits as f32 + 2.0) * cw;
        let ascii_x = hex_x + (hex_col(BYTES_PER_ROW) as f32 + 1.0) * cw + 8.0;
        let total_w = ascii_x + (BYTES_PER_ROW as f32 + 1.0) * cw + pad;

        let mut sel: Option<SelectionState> = ui.data(|d| d.get_temp(id.with("sel"))).flatten();
        let mut dragging: bool = ui.data(|d| d.get_temp(id.with("drag"))).unwrap_or(false);
        let mut hovered = None;

        // Column header.
        let (hdr, _) =
            ui.allocate_exact_size(Vec2::new(ui.available_width(), row_h), Sense::hover());
        let p = ui.painter_at(hdr);
        p.rect_filled(hdr, 0.0, pal.surface);
        let head_y = hdr.center().y;
        p.text(
            Pos2::new(hdr.left() + pad, head_y),
            Align2::LEFT_CENTER,
            "OFFSET",
            font.clone(),
            pal.text_dim,
        );
        for i in 0..BYTES_PER_ROW {
            p.text(
                Pos2::new(hdr.left() + hex_x + hex_col(i) as f32 * cw, head_y),
                Align2::LEFT_CENTER,
                format!("{i:02x}"),
                font.clone(),
                pal.text_dim,
            );
        }
        p.text(
            Pos2::new(hdr.left() + ascii_x, head_y),
            Align2::LEFT_CENTER,
            "ASCII",
            font.clone(),
            pal.text_dim,
        );

        let mut response = None;
        let mut area = egui::ScrollArea::both()
            .id_salt(id.with("scroll"))
            .auto_shrink([false, false]);
        if let Some(off) = self.scroll_to {
            let row = off / BYTES_PER_ROW as u64;
            area = area.vertical_scroll_offset((row as f32 * row_h - 2.0 * row_h).max(0.0));
        }
        let spacing_y = ui.spacing().item_spacing.y;
        // The rows are laid out without spacing, so the scroll area must count them that way too.
        ui.spacing_mut().item_spacing.y = 0.0;
        area.show_rows(ui, row_h, rows, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let width = total_w.max(ui.available_width());
            let (rect, resp) = ui.allocate_exact_size(
                Vec2::new(width, row_h * range.len() as f32),
                Sense::click_and_drag(),
            );
            let painter = ui.painter_at(rect);
            let mut buf = [0u8; BYTES_PER_ROW];
            let cur = sel.map(|s| s.range());

            let cell = |pos: Pos2| -> Option<u64> {
                let row = range.start as f32 + ((pos.y - rect.top()) / row_h).floor();
                let row = (row.max(0.0) as u64).min(rows.saturating_sub(1) as u64);
                let x = pos.x - rect.left();
                let col =
                    if x >= ascii_x - 4.0 {
                        let c = ((x - ascii_x) / cw).floor();
                        (c >= 0.0).then_some((c as usize).min(BYTES_PER_ROW - 1))
                    } else {
                        byte_at_hex_col(((x - hex_x) / cw).floor() as isize)
                            .or(Some(if x < hex_x { 0 } else { BYTES_PER_ROW - 1 }))
                    }?;
                offset_for_cell(row, col, len)
            };

            if let Some(pos) = resp.hover_pos() {
                hovered = cell(pos);
            }
            if resp.is_pointer_button_down_on() {
                if let Some(pos) = resp.interact_pointer_pos().and_then(cell) {
                    if !dragging {
                        dragging = true;
                        sel = Some(SelectionState {
                            anchor: pos,
                            cursor: pos,
                        });
                    } else if let Some(s) = sel.as_mut() {
                        s.cursor = pos;
                    }
                }
            } else {
                dragging = false;
            }

            let cur = if dragging {
                sel.map(|s| s.range())
            } else {
                cur
            };
            for (k, row) in range.clone().enumerate() {
                let y = rect.top() + k as f32 * row_h;
                let start = row as u64 * BYTES_PER_ROW as u64;
                let n = self.source.read(start, &mut buf);
                let data = &buf[..n];
                let mut text = format_row(self.base, row as u64, data, digits);
                let mut states = [ByteState::Ready; BYTES_PER_ROW];
                for (i, st) in states.iter_mut().enumerate().take(n) {
                    *st = self.source.state(start + i as u64);
                    match *st {
                        ByteState::Ready | ByteState::Uninitialized => {}
                        ByteState::Pending => {
                            text.bytes[i] = "..".into();
                            text.ascii.replace_range(i..=i, " ");
                        }
                        ByteState::Unmapped => {
                            text.bytes[i] = "??".into();
                            text.ascii.replace_range(i..=i, " ");
                        }
                    }
                }
                if row % 2 == 1 {
                    painter.rect_filled(
                        Rect::from_min_size(Pos2::new(rect.left(), y), Vec2::new(width, row_h)),
                        0.0,
                        pal.row_stripe,
                    );
                }
                // Backgrounds for highlights and selection.
                for (i, state) in states.iter().enumerate().take(n) {
                    let off = start + i as u64;
                    let mut fill = None;
                    for (r, c) in self.highlights {
                        if r.contains(&off) {
                            fill = Some(*c);
                        }
                    }
                    let selected = cur.as_ref().is_some_and(|r| r.contains(&off));
                    let hx = rect.left() + hex_x + hex_col(i) as f32 * cw;
                    let ax = rect.left() + ascii_x + i as f32 * cw;
                    let grey = *state == ByteState::Uninitialized;
                    let rects = [
                        Rect::from_min_size(
                            Pos2::new(hx - 1.5, y),
                            Vec2::new(cw * 2.0 + 3.0, row_h),
                        ),
                        Rect::from_min_size(Pos2::new(ax, y), Vec2::new(cw, row_h)),
                    ];
                    for r in rects {
                        if grey {
                            painter.rect_filled(r, 2.0, pal.text_dim.gamma_multiply(0.12));
                        }
                        if let Some(c) = fill {
                            painter.rect_filled(r, 2.0, c);
                        }
                        if selected {
                            painter.rect_filled(r, 2.0, pal.selection);
                            painter.rect_stroke(
                                r,
                                2.0,
                                Stroke::new(1.0, pal.accent.gamma_multiply(0.55)),
                                egui::StrokeKind::Inside,
                            );
                        }
                    }
                }
                let mid = y + row_h / 2.0;
                painter.text(
                    Pos2::new(rect.left() + pad, mid),
                    Align2::LEFT_CENTER,
                    &text.address,
                    font.clone(),
                    pal.address,
                );
                let mut hex = LayoutJob::default();
                for (i, b) in text.bytes.iter().enumerate() {
                    let color = match states[i] {
                        ByteState::Ready if data[i] != 0 => pal.hex_byte,
                        ByteState::Ready => pal.hex_zero,
                        ByteState::Uninitialized => pal.hex_zero.gamma_multiply(0.6),
                        ByteState::Pending | ByteState::Unmapped => {
                            pal.hex_zero.gamma_multiply(0.8)
                        }
                    };
                    let sep = if i % 8 == 7 && i + 1 < BYTES_PER_ROW {
                        "  "
                    } else {
                        " "
                    };
                    let fmt = TextFormat::simple(font.clone(), color);
                    hex.append(b, 0.0, fmt.clone());
                    hex.append(sep, 0.0, fmt);
                }
                let g = painter.layout_job(hex);
                painter.galley(
                    Pos2::new(rect.left() + hex_x, mid - g.size().y / 2.0),
                    g,
                    pal.hex_byte,
                );
                let mut asc = LayoutJob::default();
                for (ch, &b) in text.ascii.chars().zip(data) {
                    let color = if ch == '.' && b != b'.' || ch == ' ' {
                        pal.hex_zero
                    } else {
                        pal.ascii
                    };
                    asc.append(
                        &ch.to_string(),
                        0.0,
                        TextFormat::simple(font.clone(), color),
                    );
                }
                let g = painter.layout_job(asc);
                painter.galley(
                    Pos2::new(rect.left() + ascii_x, mid - g.size().y / 2.0),
                    g,
                    pal.ascii,
                );
            }
            response = Some(resp);
        });
        ui.spacing_mut().item_spacing.y = spacing_y;

        ui.data_mut(|d| {
            d.insert_temp(id.with("sel"), sel);
            d.insert_temp(id.with("drag"), dragging);
        });
        let response = response.unwrap_or_else(|| ui.allocate_response(Vec2::ZERO, Sense::hover()));
        HexViewResponse {
            response,
            selection: sel.map(|s| s.range()),
            hovered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_full_and_partial_rows() {
        let data: Vec<u8> = (0x41..0x51).collect();
        let r = format_row(0x1000, 2, &data, 8);
        assert_eq!(r.address, "00001020");
        assert_eq!(r.bytes.len(), 16);
        assert_eq!(r.bytes[0], "41");
        assert_eq!(r.ascii, "ABCDEFGHIJKLMNOP");
        let r = format_row(0, 0, &[0, 0x7f, b' ', 0xff], 16);
        assert_eq!(r.address, "0000000000000000");
        assert_eq!(r.ascii, ".. .");
        assert_eq!(r.bytes, ["00", "7f", "20", "ff"]);
    }

    #[test]
    fn address_width() {
        assert_eq!(address_digits(0xffff_ffff), 8);
        assert_eq!(address_digits(0x1_0000_0000), 16);
    }

    #[test]
    fn column_mapping_round_trips() {
        for i in 0..BYTES_PER_ROW {
            assert_eq!(byte_at_hex_col(hex_col(i) as isize), Some(i));
            assert_eq!(byte_at_hex_col(hex_col(i) as isize + 1), Some(i));
        }
        assert_eq!(byte_at_hex_col(-1), None);
        assert_eq!(byte_at_hex_col(60), None);
    }

    #[test]
    fn selection_range_is_normalised_and_inclusive() {
        let s = SelectionState {
            anchor: 10,
            cursor: 4,
        };
        assert_eq!(s.range(), 4..11);
        let s = SelectionState {
            anchor: 4,
            cursor: 4,
        };
        assert_eq!(s.range(), 4..5);
    }

    #[test]
    fn cell_offsets_clamp_to_len() {
        assert_eq!(offset_for_cell(0, 3, 100), Some(3));
        assert_eq!(offset_for_cell(6, 15, 100), Some(99));
        assert_eq!(offset_for_cell(0, 0, 0), None);
    }

    #[test]
    fn slice_source_reads() {
        let d = [1u8, 2, 3, 4, 5];
        let mut b = [0u8; 4];
        assert_eq!(SliceSource(&d).read(3, &mut b), 2);
        assert_eq!(&b[..2], &[4, 5]);
        assert_eq!(SliceSource(&d).read(9, &mut b), 0);
    }
}

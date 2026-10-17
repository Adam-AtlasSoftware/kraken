//! Syntax-coloured, clickable decompiler text with line numbers.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::ops::Range;
use std::sync::Arc;

use egui::epaint::text::CharIndex;
use egui::epaint::text::cursor::CCursor;
use egui::text::{LayoutJob, TextFormat};
use egui::{Align2, CursorIcon, Id, Pos2, Rect, Response, Sense, Stroke, Ui, Vec2};
use kraken_proto::{DecompileResult, Locator, Token};

use crate::theme::KrakenTheme;

/// A run of one line, either covered by a token or plain text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Byte range inside the whole text.
    pub bytes: Range<usize>,
    /// Char range inside the line.
    pub chars: Range<usize>,
    /// Index into `DecompileResult::tokens`.
    pub token: Option<usize>,
}

/// Byte offset of the start of every line (always at least one entry).
pub fn line_starts(text: &str) -> Vec<usize> {
    let mut v = vec![0];
    v.extend(text.match_indices('\n').map(|(i, _)| i + 1));
    v
}

/// Line index containing byte `offset`.
pub fn line_of_offset(starts: &[usize], offset: usize) -> usize {
    starts.partition_point(|&s| s <= offset).saturating_sub(1)
}

/// Content range of `line` (without the trailing newline).
pub fn line_range(text: &str, starts: &[usize], line: usize) -> Range<usize> {
    let s = starts[line];
    let e = starts.get(line + 1).map_or(text.len(), |n| n - 1);
    s..e.max(s)
}

/// Splits one line into token-covered and plain segments. Overlapping or out-of-order tokens
/// are skipped rather than trusted.
pub fn line_segments(text: &str, tokens: &[Token], line: Range<usize>) -> Vec<Segment> {
    let mut segs = Vec::new();
    let mut pos = line.start;
    let first = tokens.partition_point(|t| (t.end as usize) <= line.start);
    let char_of = |b: usize| text[line.start..b].chars().count();
    let push = |segs: &mut Vec<Segment>, r: Range<usize>, token: Option<usize>| {
        if r.start < r.end {
            segs.push(Segment {
                chars: char_of(r.start)..char_of(r.end),
                bytes: r,
                token,
            });
        }
    };
    for (i, t) in tokens.iter().enumerate().skip(first) {
        let (s, e) = (t.start as usize, t.end as usize);
        if s >= line.end {
            break;
        }
        let s = s.max(line.start);
        let e = e.min(line.end);
        if s < pos || s > e || !text.is_char_boundary(s) || !text.is_char_boundary(e) {
            continue;
        }
        push(&mut segs, pos..s, None);
        push(&mut segs, s..e, Some(i));
        pos = e;
    }
    push(&mut segs, pos..line.end, None);
    segs
}

/// Segment containing char index `c` of a line.
pub fn segment_at_char(segs: &[Segment], c: usize) -> Option<&Segment> {
    let i = segs.partition_point(|s| s.chars.end <= c);
    segs.get(i).filter(|s| s.chars.start <= c)
}

/// Whether a token is interactive.
pub fn is_clickable(t: &Token) -> bool {
    t.target.is_some() || t.symbol.is_some()
}

/// Content hash of a result, used as the layout cache identity.
pub fn content_hash(r: &DecompileResult) -> u64 {
    let mut h = DefaultHasher::new();
    r.text.hash(&mut h);
    for t in &r.tokens {
        (t.start, t.end, t.kind).hash(&mut h);
    }
    h.finish()
}

/// Width of the "line continues" mark drawn at the right edge of a clipped line.
const CLIP_CUE_W: f32 = 16.0;

/// True when a line of `chars` monospace characters drawn from `text_x` reaches past `visible_right`.
pub fn line_is_clipped(chars: usize, char_w: f32, text_x: f32, visible_right: f32) -> bool {
    text_x + chars as f32 * char_w > visible_right
}

/// Cache identity of a prepared layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LayoutKey {
    pub content: u64,
    pub dark: bool,
    pub font_bits: u32,
}

struct PreparedLine {
    job: Arc<LayoutJob>,
    segments: Vec<Segment>,
}

struct Prepared {
    key: LayoutKey,
    lines: Vec<PreparedLine>,
    max_chars: usize,
}

fn prepare(r: &DecompileResult, key: LayoutKey, theme: &KrakenTheme) -> Prepared {
    let style = theme.token_style();
    let font = KrakenTheme::mono_font();
    let starts = line_starts(&r.text);
    let mut max_chars = 0;
    let lines = (0..starts.len())
        .map(|l| {
            let range = line_range(&r.text, &starts, l);
            let segments = line_segments(&r.text, &r.tokens, range.clone());
            let mut job = LayoutJob::default();
            job.wrap.max_width = f32::INFINITY;
            for seg in &segments {
                let (color, italic) = match seg.token {
                    Some(i) => (
                        style.color(r.tokens[i].kind),
                        style.italic(r.tokens[i].kind),
                    ),
                    None => (style.color(kraken_proto::TokenKind::Other), false),
                };
                let mut fmt = TextFormat::simple(font.clone(), color);
                fmt.italics = italic;
                job.append(&r.text[seg.bytes.clone()], 0.0, fmt);
            }
            max_chars = max_chars.max(r.text[range].chars().count());
            PreparedLine {
                job: Arc::new(job),
                segments,
            }
        })
        .collect();
    Prepared {
        key,
        lines,
        max_chars,
    }
}

/// A token click.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenClick {
    pub index: usize,
    pub target: Option<Locator>,
    pub symbol: Option<String>,
}

pub struct TokenTextResponse {
    pub response: Response,
    pub clicked: Option<TokenClick>,
    /// Token under the pointer, if any.
    pub hovered: Option<usize>,
    /// Symbol currently highlighted everywhere.
    pub highlighted_symbol: Option<String>,
}

/// Renders a [`DecompileResult`].
pub struct TokenText<'a> {
    result: &'a DecompileResult,
    id: Id,
    cache_id: Option<u64>,
    scroll_to_line: Option<usize>,
    initial_highlight: Option<String>,
}

impl<'a> TokenText<'a> {
    pub fn new(result: &'a DecompileResult) -> Self {
        Self {
            result,
            id: Id::new("kraken_token_text"),
            cache_id: None,
            scroll_to_line: None,
            initial_highlight: None,
        }
    }

    /// Symbol highlighted until the user clicks somewhere (state is kept per widget id).
    pub fn initial_highlight(mut self, symbol: impl Into<String>) -> Self {
        self.initial_highlight = Some(symbol.into());
        self
    }

    pub fn id_salt(mut self, salt: impl std::hash::Hash + std::fmt::Debug) -> Self {
        self.id = Id::new("kraken_widget").with(salt);
        self
    }

    /// Caller-supplied identity of the result (e.g. a revision number). When set, the text is
    /// not re-hashed every frame.
    pub fn cache_id(mut self, id: u64) -> Self {
        self.cache_id = Some(id);
        self
    }

    pub fn scroll_to_line(mut self, line: usize) -> Self {
        self.scroll_to_line = Some(line);
        self
    }

    pub fn show(self, ui: &mut Ui) -> TokenTextResponse {
        let theme = KrakenTheme::from_ctx(ui.ctx());
        let pal = theme.palette();
        let id = ui.make_persistent_id(self.id);
        let font = KrakenTheme::mono_font();
        let cw = ui.fonts_mut(|f| f.glyph_width(&font, '0'));
        let row_h = ui.fonts_mut(|f| f.row_height(&font)) + 3.0;

        let key = LayoutKey {
            content: self.cache_id.unwrap_or_else(|| content_hash(self.result)),
            dark: theme.dark,
            font_bits: font.size.to_bits(),
        };
        let prepared: Arc<Prepared> = match ui.data(|d| d.get_temp::<Arc<Prepared>>(id)) {
            Some(p) if p.key == key => p,
            _ => {
                let p = Arc::new(prepare(self.result, key, &theme));
                ui.data_mut(|d| d.insert_temp(id, p.clone()));
                p
            }
        };

        let stored: Option<Option<String>> = ui.data(|d| d.get_temp(id.with("hl")));
        let mut highlight = stored.unwrap_or_else(|| self.initial_highlight.clone());
        let mut clicked = None;
        let mut hovered = None;
        let n = prepared.lines.len();
        let digits = n.to_string().len().max(3);
        let gutter_w = digits as f32 * cw + 18.0;
        let text_x = gutter_w + 10.0;
        let content_w = text_x + prepared.max_chars as f32 * cw + 24.0;

        let mut area = egui::ScrollArea::both()
            .id_salt(id.with("scroll"))
            .auto_shrink([false, false]);
        if let Some(l) = self.scroll_to_line {
            area = area.vertical_scroll_offset((l as f32 * row_h - 2.0 * row_h).max(0.0));
        }
        let spacing_y = ui.spacing().item_spacing.y;
        // The rows are laid out without spacing, so the scroll area must count them that way too.
        ui.spacing_mut().item_spacing.y = 0.0;
        let out = area.show_rows(ui, row_h, n, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let width = content_w.max(ui.available_width());
            for l in range {
                let (rect, resp) = ui.allocate_exact_size(Vec2::new(width, row_h), Sense::click());
                let painter = ui.painter_at(rect);
                let line = &prepared.lines[l];
                painter.rect_filled(
                    Rect::from_min_size(rect.min, Vec2::new(gutter_w, row_h)),
                    0.0,
                    pal.panel,
                );
                painter.text(
                    Pos2::new(rect.left() + gutter_w - 8.0, rect.center().y),
                    Align2::RIGHT_CENTER,
                    l + 1,
                    font.clone(),
                    pal.gutter,
                );
                let galley = painter.layout_job((*line.job).clone());
                let origin = Pos2::new(
                    rect.left() + text_x,
                    rect.center().y - galley.size().y / 2.0,
                );

                let seg_rect = |seg: &Segment| {
                    let a = galley.pos_from_cursor(CCursor::new(CharIndex(seg.chars.start)));
                    let b = galley.pos_from_cursor(CCursor::new(CharIndex(seg.chars.end)));
                    Rect::from_min_max(
                        Pos2::new(origin.x + a.left(), rect.top() + 1.0),
                        Pos2::new(origin.x + b.left(), rect.bottom() - 1.0),
                    )
                };

                let hover_seg = resp.hover_pos().filter(|p| p.x >= origin.x).and_then(|p| {
                    let c = galley.cursor_from_pos(p - origin).index.0;
                    let seg = segment_at_char(&line.segments, c)?;
                    // cursor_from_pos snaps to the nearest gap; reject clicks past the text end.
                    let r = seg_rect(seg);
                    (p.x >= r.left() && p.x <= r.right()).then_some(seg)
                });
                let hover_tok = hover_seg
                    .and_then(|s| s.token)
                    .filter(|&i| is_clickable(&self.result.tokens[i]));

                if resp.hovered() && hover_tok.is_none() {
                    painter.rect_filled(rect, 0.0, pal.row_hover);
                }
                if let Some(sym) = &highlight {
                    for seg in &line.segments {
                        let Some(i) = seg.token else { continue };
                        if self.result.tokens[i].symbol.as_deref() == Some(sym.as_str()) {
                            painter.rect_filled(seg_rect(seg), 3.0, pal.highlight);
                        }
                    }
                }
                painter.galley(origin, galley.clone(), pal.text);
                let visible_right = ui.clip_rect().right();
                if line_is_clipped(line.job.text.chars().count(), cw, origin.x, visible_right) {
                    // A cue that the line goes on past the edge; scrolling sideways reveals it.
                    let tab = Rect::from_min_max(
                        Pos2::new(visible_right - CLIP_CUE_W, rect.top() + 1.0),
                        Pos2::new(visible_right, rect.bottom() - 1.0),
                    );
                    let cue = ui.painter_at(tab.intersect(rect));
                    cue.rect_filled(tab, 0.0, pal.panel);
                    cue.text(
                        tab.center(),
                        Align2::CENTER_CENTER,
                        "\u{2026}",
                        font.clone(),
                        pal.accent,
                    );
                }

                if let Some(i) = hover_tok {
                    let seg = hover_seg.expect("hover token implies segment");
                    let r = seg_rect(seg);
                    let color = theme.token_style().color(self.result.tokens[i].kind);
                    painter.line_segment(
                        [
                            Pos2::new(r.left(), r.bottom() - 2.0),
                            Pos2::new(r.right(), r.bottom() - 2.0),
                        ],
                        Stroke::new(1.0, color),
                    );
                    ui.ctx().set_cursor_icon(CursorIcon::PointingHand);
                    hovered = Some(i);
                    if resp.clicked() {
                        let t = &self.result.tokens[i];
                        highlight = t.symbol.clone();
                        clicked = Some(TokenClick {
                            index: i,
                            target: t.target.clone(),
                            symbol: t.symbol.clone(),
                        });
                    }
                    let t = &self.result.tokens[i];
                    resp.on_hover_ui_at_pointer(|ui| token_tooltip(ui, t, &theme));
                } else if resp.clicked() {
                    highlight = None;
                }
            }
        });
        ui.spacing_mut().item_spacing.y = spacing_y;
        ui.data_mut(|d| d.insert_temp(id.with("hl"), highlight.clone()));
        let response = ui.interact(out.inner_rect, id.with("outer"), Sense::hover());
        TokenTextResponse {
            response,
            clicked,
            hovered,
            highlighted_symbol: highlight,
        }
    }
}

fn token_tooltip(ui: &mut Ui, t: &Token, theme: &KrakenTheme) {
    let pal = theme.palette();
    let color = theme.token_style().color(t.kind);
    if let Some(sym) = &t.symbol {
        ui.label(egui::RichText::new(sym).monospace().strong().color(color));
    }
    ui.label(
        egui::RichText::new(format!("{:?}", t.kind).to_lowercase())
            .small()
            .color(pal.text_dim),
    );
    let place = match &t.target {
        Some(Locator::Native { space, offset }) => Some(format!("{space}:{offset}")),
        Some(Locator::Managed { token, .. }) => Some(format!("token:{token:#010x}")),
        _ => None,
    };
    if let Some(place) = place {
        ui.label(egui::RichText::new(place).monospace().color(pal.address));
    }
    if let Some(vn) = &t.varnode {
        ui.label(egui::RichText::new(vn).monospace().color(pal.text_dim));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{Completeness, TokenKind};

    fn tok(start: u32, end: u32, kind: TokenKind, sym: Option<&str>) -> Token {
        Token {
            start,
            end,
            kind,
            target: None,
            symbol: sym.map(str::to_string),
            varnode: None,
        }
    }

    fn result(text: &str, tokens: Vec<Token>) -> DecompileResult {
        DecompileResult {
            function: Locator::ram(0x1000),
            language: "c".into(),
            text: text.into(),
            tokens,
            warnings: vec![],
            completeness: Completeness::Complete,
        }
    }

    #[test]
    fn long_lines_are_flagged_as_clipped() {
        assert!(line_is_clipped(200, 7.0, 40.0, 800.0));
        assert!(!line_is_clipped(20, 7.0, 40.0, 800.0));
        // Exactly filling the width is not clipped.
        assert!(!line_is_clipped(100, 7.0, 40.0, 740.0));
        assert!(line_is_clipped(101, 7.0, 40.0, 740.0));
    }

    #[test]
    fn line_mapping() {
        let text = "int a;\nreturn a;\n\nend";
        let starts = line_starts(text);
        assert_eq!(starts, vec![0, 7, 17, 18]);
        assert_eq!(line_of_offset(&starts, 0), 0);
        assert_eq!(line_of_offset(&starts, 6), 0);
        assert_eq!(line_of_offset(&starts, 7), 1);
        assert_eq!(line_of_offset(&starts, 18), 3);
        assert_eq!(line_range(text, &starts, 0), 0..6);
        assert_eq!(line_range(text, &starts, 2), 17..17);
        assert_eq!(line_range(text, &starts, 3), 18..21);
    }

    #[test]
    fn segments_cover_the_line_and_map_tokens() {
        let text = "int a;\nreturn a;";
        let tokens = vec![
            tok(0, 3, TokenKind::Type, Some("int")),
            tok(4, 5, TokenKind::Variable, Some("a")),
            tok(7, 13, TokenKind::Keyword, None),
            tok(14, 15, TokenKind::Variable, Some("a")),
        ];
        let l0 = line_segments(text, &tokens, 0..6);
        let got: Vec<_> = l0.iter().map(|s| (s.bytes.clone(), s.token)).collect();
        assert_eq!(
            got,
            vec![(0..3, Some(0)), (3..4, None), (4..5, Some(1)), (5..6, None)]
        );
        let l1 = line_segments(text, &tokens, 7..16);
        assert_eq!(l1[0].token, Some(2));
        assert_eq!(l1[0].chars, 0..6);
        assert_eq!(segment_at_char(&l1, 7).and_then(|s| s.token), Some(3));
        assert_eq!(segment_at_char(&l1, 6).and_then(|s| s.token), None);
        assert!(segment_at_char(&l1, 99).is_none());
    }

    #[test]
    fn multi_line_token_is_split_per_line() {
        let text = "/* a\nb */ x";
        let tokens = vec![tok(0, 9, TokenKind::Comment, None)];
        let l0 = line_segments(text, &tokens, 0..4);
        let l1 = line_segments(text, &tokens, 5..text.len());
        assert_eq!(l0.len(), 1);
        assert_eq!(l0[0].token, Some(0));
        assert_eq!(l1[0].bytes, 5..9);
        assert_eq!(l1[1].token, None);
    }

    #[test]
    fn bad_tokens_are_ignored() {
        let text = "héllo world";
        // 2..3 splits the two-byte 'é'; second token overlaps the first.
        let tokens = vec![
            tok(2, 3, TokenKind::Other, None),
            tok(0, 6, TokenKind::Variable, None),
            tok(3, 5, TokenKind::Variable, None),
        ];
        let segs = line_segments(text, &tokens, 0..text.len());
        let covered: usize = segs.iter().map(|s| s.bytes.len()).sum();
        assert_eq!(covered, text.len());
    }

    #[test]
    fn layout_key_tracks_content_theme_and_font() {
        let a = result("x", vec![tok(0, 1, TokenKind::Variable, None)]);
        let mut b = a.clone();
        assert_eq!(content_hash(&a), content_hash(&b));
        b.tokens[0].kind = TokenKind::Constant;
        assert_ne!(content_hash(&a), content_hash(&b));
        let k = |content, dark, font_bits| LayoutKey {
            content,
            dark,
            font_bits,
        };
        assert_eq!(k(1, true, 13), k(1, true, 13));
        assert_ne!(k(1, true, 13), k(1, false, 13));
        assert_ne!(k(1, true, 13), k(1, true, 14));
        assert_ne!(k(1, true, 13), k(2, true, 13));
    }

    #[test]
    fn prepare_builds_one_line_per_text_line() {
        let r = result("a\nbb\n", vec![tok(0, 1, TokenKind::Variable, Some("a"))]);
        let key = LayoutKey {
            content: content_hash(&r),
            dark: true,
            font_bits: 0,
        };
        let p = prepare(&r, key, &KrakenTheme::DARK);
        assert_eq!(p.lines.len(), 3);
        assert_eq!(p.max_chars, 2);
        assert_eq!(p.key, key);
    }
}

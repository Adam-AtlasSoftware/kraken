//! Assistant text: paragraphs, `code` spans and addresses that jump to the function.

use egui::{RichText, Sense, Ui};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;

/// A piece of assistant text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg<'a> {
    /// Ordinary words.
    Text(&'a str),
    /// Text between backticks.
    Code(&'a str),
    /// A hex address such as `0x401000`.
    Addr(&'a str, u64),
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Splits `s` into plain text, code spans and addresses (`0x` and at least three hex digits,
/// not glued to a longer word).
pub fn segments(s: &str) -> Vec<Seg<'_>> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut plain_from = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'`'
            && let Some(len) = s[i + 1..].find('`')
            && len > 0
        {
            if plain_from < i {
                out.push(Seg::Text(&s[plain_from..i]));
            }
            out.push(Seg::Code(&s[i + 1..i + 1 + len]));
            i += len + 2;
            plain_from = i;
            continue;
        }
        if bytes[i] == b'0'
            && bytes.get(i + 1) == Some(&b'x')
            && (i == 0 || !is_word_byte(bytes[i - 1]))
        {
            let digits = bytes[i + 2..]
                .iter()
                .take_while(|b| b.is_ascii_hexdigit())
                .count();
            let end = i + 2 + digits;
            let glued = bytes.get(end).is_some_and(|b| is_word_byte(*b));
            if (3..=16).contains(&digits)
                && !glued
                && let Ok(v) = u64::from_str_radix(&s[i + 2..end], 16)
            {
                if plain_from < i {
                    out.push(Seg::Text(&s[plain_from..i]));
                }
                out.push(Seg::Addr(&s[i..end], v));
                i = end;
                plain_from = i;
                continue;
            }
        }
        i += 1;
    }
    if plain_from < s.len() {
        out.push(Seg::Text(&s[plain_from..]));
    }
    out
}

/// One line of flowing text with clickable addresses. Clicking an address stores it in `goto`.
pub fn line(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    text: &str,
    size: f32,
    goto: &mut Option<u64>,
) {
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        for seg in segments(text) {
            match seg {
                Seg::Text(t) => {
                    ui.label(RichText::new(t).size(size).color(p.text));
                }
                Seg::Code(c) => {
                    ui.label(
                        RichText::new(c)
                            .monospace()
                            .size(size - 0.5)
                            .color(p.text_strong),
                    );
                }
                Seg::Addr(raw, addr) => {
                    address_link(ui, vm, p, raw, addr, size, goto);
                }
            }
        }
    });
}

/// A clickable address.
pub fn address_link(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    shown: &str,
    addr: u64,
    size: f32,
    goto: &mut Option<u64>,
) -> egui::Response {
    let known = vm.functions.find(addr).map(|f| f.name.clone());
    let r = ui
        .add(
            egui::Label::new(
                RichText::new(shown)
                    .monospace()
                    .size(size - 0.5)
                    .color(p.address)
                    .underline(),
            )
            .sense(Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let r = match known {
        Some(name) => r.on_hover_text(format!("Open {name} at {addr:#x}")),
        None => r.on_hover_text(format!("Go to {addr:#x}")),
    };
    if r.clicked() {
        *goto = Some(addr);
    }
    r
}

/// How a run of text looks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Style {
    pub bold: bool,
    pub italic: bool,
    pub strike: bool,
    pub code: bool,
}

/// A run of text inside a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inline {
    pub text: String,
    pub style: Style,
    /// Where it leads, for a link.
    pub link: Option<String>,
}

/// A block of Markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Heading(u8, Vec<Inline>),
    Para(Vec<Inline>),
    Code(String),
    List {
        /// The first number, for a numbered list.
        start: Option<u64>,
        items: Vec<Vec<Block>>,
    },
    Quote(Vec<Block>),
    Rule,
    Table {
        head: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
}

/// Reads Markdown. Half-written text, as it streams in, is simply what it is so far.
pub fn parse(text: &str) -> Vec<Block> {
    use pulldown_cmark::{Options, Parser};
    let opts = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut events = Parser::new_ext(text, opts);
    blocks(&mut events, None)
}

type Events<'a, 'b> = &'b mut pulldown_cmark::Parser<'a>;

/// Reads blocks until the end tag `until`.
fn blocks(ev: Events<'_, '_>, until: Option<pulldown_cmark::TagEnd>) -> Vec<Block> {
    use pulldown_cmark::{Event, Tag, TagEnd};
    let mut out = Vec::new();
    // A tight list item holds its text without a paragraph around it.
    let mut loose: Vec<Inline> = Vec::new();
    let mut style = Style::default();
    let mut link: Option<String> = None;
    let flush = |loose: &mut Vec<Inline>, out: &mut Vec<Block>| {
        if !loose.is_empty() {
            out.push(Block::Para(std::mem::take(loose)));
        }
    };
    while let Some(e) = ev.next() {
        match e {
            Event::End(end) if Some(end) == until => break,
            Event::Start(Tag::Paragraph) => {
                flush(&mut loose, &mut out);
                out.push(Block::Para(inlines(ev, TagEnd::Paragraph)));
            }
            Event::Start(Tag::Heading { level, .. }) => {
                flush(&mut loose, &mut out);
                out.push(Block::Heading(
                    level as u8,
                    inlines(ev, TagEnd::Heading(level)),
                ));
            }
            Event::Start(Tag::CodeBlock(_)) => {
                flush(&mut loose, &mut out);
                let mut code = String::new();
                for e in ev.by_ref() {
                    match e {
                        Event::Text(t) => code.push_str(&t),
                        Event::End(TagEnd::CodeBlock) => break,
                        _ => {}
                    }
                }
                out.push(Block::Code(code.trim_end().to_string()));
            }
            Event::Start(Tag::List(start)) => {
                flush(&mut loose, &mut out);
                let end = TagEnd::List(start.is_some());
                let mut items = Vec::new();
                while let Some(e) = ev.next() {
                    match e {
                        Event::Start(Tag::Item) => items.push(blocks(ev, Some(TagEnd::Item))),
                        Event::End(t) if t == end => break,
                        _ => {}
                    }
                }
                out.push(Block::List { start, items });
            }
            Event::Start(Tag::BlockQuote(kind)) => {
                flush(&mut loose, &mut out);
                out.push(Block::Quote(blocks(ev, Some(TagEnd::BlockQuote(kind)))));
            }
            Event::Start(Tag::Table(_)) => {
                flush(&mut loose, &mut out);
                out.push(table(ev));
            }
            Event::Rule => {
                flush(&mut loose, &mut out);
                out.push(Block::Rule);
            }
            // Inline content directly in a block: the tight list item.
            Event::Start(Tag::Strong) => style.bold = true,
            Event::End(TagEnd::Strong) => style.bold = false,
            Event::Start(Tag::Emphasis) => style.italic = true,
            Event::End(TagEnd::Emphasis) => style.italic = false,
            Event::Start(Tag::Strikethrough) => style.strike = true,
            Event::End(TagEnd::Strikethrough) => style.strike = false,
            Event::Start(Tag::Link { dest_url, .. }) => link = Some(dest_url.to_string()),
            Event::End(TagEnd::Link) => link = None,
            other => push_inline(&other, style, link.as_deref(), &mut loose),
        }
    }
    flush(&mut loose, &mut out);
    out
}

/// One piece of inline text; a line break becomes a space, as a paragraph reads.
fn push_inline(
    e: &pulldown_cmark::Event<'_>,
    style: Style,
    link: Option<&str>,
    out: &mut Vec<Inline>,
) {
    use pulldown_cmark::Event;
    let mut add = |text: &str, style: Style| {
        out.push(Inline {
            text: text.to_string(),
            style,
            link: link.map(str::to_string),
        });
    };
    match e {
        Event::Text(t) | Event::Html(t) | Event::InlineHtml(t) => add(t, style),
        Event::Code(t) => add(
            t,
            Style {
                code: true,
                ..style
            },
        ),
        Event::SoftBreak => add(" ", style),
        Event::HardBreak => add("\n", style),
        _ => {}
    }
}

/// Reads inline text up to the end tag `until`.
fn inlines(ev: Events<'_, '_>, until: pulldown_cmark::TagEnd) -> Vec<Inline> {
    use pulldown_cmark::{Event, Tag, TagEnd};
    let mut out = Vec::new();
    let mut style = Style::default();
    let mut link: Option<String> = None;
    for e in ev.by_ref() {
        match e {
            Event::End(end) if end == until => break,
            Event::Start(Tag::Strong) => style.bold = true,
            Event::End(TagEnd::Strong) => style.bold = false,
            Event::Start(Tag::Emphasis) => style.italic = true,
            Event::End(TagEnd::Emphasis) => style.italic = false,
            Event::Start(Tag::Strikethrough) => style.strike = true,
            Event::End(TagEnd::Strikethrough) => style.strike = false,
            Event::Start(Tag::Link { dest_url, .. }) => link = Some(dest_url.to_string()),
            Event::End(TagEnd::Link) => link = None,
            other => push_inline(&other, style, link.as_deref(), &mut out),
        }
    }
    out
}

fn table(ev: Events<'_, '_>) -> Block {
    use pulldown_cmark::{Event, Tag, TagEnd};
    let mut head = Vec::new();
    let mut rows: Vec<Vec<Vec<Inline>>> = Vec::new();
    let mut in_head = false;
    while let Some(e) = ev.next() {
        match e {
            Event::Start(Tag::TableHead) => in_head = true,
            Event::End(TagEnd::TableHead) => in_head = false,
            Event::Start(Tag::TableRow) => rows.push(Vec::new()),
            Event::Start(Tag::TableCell) => {
                let cell = inlines(ev, TagEnd::TableCell);
                if in_head {
                    head.push(cell);
                } else if let Some(r) = rows.last_mut() {
                    r.push(cell);
                }
            }
            Event::End(TagEnd::Table) => break,
            _ => {}
        }
    }
    Block::Table { head, rows }
}

/// The parsed form of `text`, kept between frames: a long chat would otherwise be read again
/// sixty times a second.
fn parsed(text: &str) -> std::sync::Arc<Vec<Block>> {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::hash::{DefaultHasher, Hash, Hasher};
    use std::sync::Arc;
    thread_local! {
        static CACHE: RefCell<HashMap<u64, Arc<Vec<Block>>>> = RefCell::new(HashMap::new());
    }
    let mut h = DefaultHasher::new();
    text.hash(&mut h);
    let key = h.finish();
    CACHE.with_borrow_mut(|c| {
        if c.len() > 2048 {
            c.clear();
        }
        c.entry(key)
            .or_insert_with(|| Arc::new(parse(text)))
            .clone()
    })
}

/// Text in Markdown, with clickable addresses.
pub fn paragraphs(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    text: &str,
    size: f32,
    goto: &mut Option<u64>,
) {
    draw_blocks(ui, vm, p, &parsed(text.trim()), size, goto);
}

fn draw_blocks(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    blocks: &[Block],
    size: f32,
    goto: &mut Option<u64>,
) {
    for (n, b) in blocks.iter().enumerate() {
        if n > 0 {
            ui.add_space(5.0);
        }
        match b {
            Block::Heading(level, text) => {
                let grow = match level {
                    1 => 5.0,
                    2 => 3.0,
                    3 => 1.5,
                    _ => 0.5,
                };
                if n > 0 {
                    ui.add_space(3.0);
                }
                let bold = Style {
                    bold: true,
                    ..Style::default()
                };
                inline_line(ui, vm, p, text, bold, size + grow, goto);
            }
            Block::Para(text) => inline_line(ui, vm, p, text, Style::default(), size, goto),
            Block::Code(code) => code_block(ui, p, code, size),
            Block::List { start, items } => {
                for (i, item) in items.iter().enumerate() {
                    let mark = start
                        .map_or_else(|| "\u{2022}".to_string(), |s| format!("{}.", s + i as u64));
                    ui.horizontal_top(|ui| {
                        ui.spacing_mut().item_spacing.x = 5.0;
                        ui.label(RichText::new(mark).size(size).color(p.text_dim));
                        ui.vertical(|ui| draw_blocks(ui, vm, p, item, size, goto));
                    });
                }
            }
            Block::Quote(inner) => {
                egui::Frame::new()
                    .stroke(egui::Stroke::NONE)
                    .inner_margin(egui::Margin {
                        left: 10,
                        ..egui::Margin::ZERO
                    })
                    .show(ui, |ui| {
                        let r = ui.scope(|ui| draw_blocks(ui, vm, p, inner, size, goto));
                        let rect = r.response.rect;
                        ui.painter().vline(
                            rect.left() - 7.0,
                            rect.y_range(),
                            egui::Stroke::new(2.0, p.border),
                        );
                    });
            }
            Block::Rule => {
                ui.separator();
            }
            Block::Table { head, rows } => {
                let id = ui.next_auto_id();
                egui::ScrollArea::horizontal()
                    .id_salt(id)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        egui::Grid::new(id.with("grid"))
                            .striped(true)
                            .spacing([14.0, 4.0])
                            .show(ui, |ui| {
                                let bold = Style {
                                    bold: true,
                                    ..Style::default()
                                };
                                for cell in head {
                                    inline_cell(ui, vm, p, cell, bold, size, goto);
                                }
                                ui.end_row();
                                for row in rows {
                                    for cell in row {
                                        inline_cell(ui, vm, p, cell, Style::default(), size, goto);
                                    }
                                    ui.end_row();
                                }
                            });
                    });
            }
        }
    }
}

fn code_block(ui: &mut Ui, p: &Palette, code: &str, size: f32) {
    egui::Frame::new()
        .fill(p.bg)
        .stroke(egui::Stroke::new(1.0, p.border))
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(8, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                if ui
                    .small_button("Copy")
                    .on_hover_text("Copy this code")
                    .clicked()
                {
                    ui.ctx().copy_text(code.to_string());
                }
                ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(code)
                                .monospace()
                                .size(size - 1.0)
                                .color(p.text_strong),
                        )
                        .wrap(),
                    );
                });
            });
        });
}

fn styled(t: &str, s: Style, size: f32, p: &Palette) -> RichText {
    let mut r = RichText::new(t).size(if s.code { size - 0.5 } else { size });
    if s.code {
        r = r.monospace();
    }
    r = r.color(if s.bold || s.code {
        p.text_strong
    } else {
        p.text
    });
    if s.bold && !s.code {
        r = r.family(crate::fonts::medium());
    }
    if s.italic {
        r = r.italics();
    }
    if s.strike {
        r = r.strikethrough();
    }
    r
}

/// A paragraph's runs in flowing text. A web link opens only for `http` and `https`.
fn inline_line(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    runs: &[Inline],
    base: Style,
    size: f32,
    goto: &mut Option<u64>,
) {
    ui.horizontal_wrapped(|ui| inline_runs(ui, vm, p, runs, base, size, goto));
}

/// A table cell: one line, since a grid gives wrapped text next to no width.
fn inline_cell(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    runs: &[Inline],
    base: Style,
    size: f32,
    goto: &mut Option<u64>,
) {
    ui.horizontal(|ui| {
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
        inline_runs(ui, vm, p, runs, base, size, goto);
    });
}

fn inline_runs(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    runs: &[Inline],
    base: Style,
    size: f32,
    goto: &mut Option<u64>,
) {
    ui.spacing_mut().item_spacing.x = 0.0;
    {
        for run in runs {
            let s = Style {
                bold: run.style.bold || base.bold,
                italic: run.style.italic || base.italic,
                strike: run.style.strike || base.strike,
                code: run.style.code,
            };
            if let Some(url) = &run.link {
                if url.starts_with("https://") || url.starts_with("http://") {
                    let text = styled(&run.text, s, size, p).color(p.address).underline();
                    ui.hyperlink_to(text, url).on_hover_text(url);
                } else {
                    ui.label(styled(&run.text, s, size, p));
                }
                continue;
            }
            // An address is a link wherever it stands, in `code` or not.
            for seg in segments(&run.text) {
                match seg {
                    Seg::Text(t) | Seg::Code(t) => {
                        ui.label(styled(t, s, size, p));
                    }
                    Seg::Addr(raw, addr) => {
                        address_link(ui, vm, p, raw, addr, size, goto);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_and_code_spans_are_found() {
        let segs = segments("See 0x401000 and `process_packet` (0x4011a0).");
        assert!(segs.contains(&Seg::Addr("0x401000", 0x401000)));
        assert!(segs.contains(&Seg::Code("process_packet")));
        assert!(segs.contains(&Seg::Addr("0x4011a0", 0x4011a0)));
        let rebuilt: String = segs
            .iter()
            .map(|s| match s {
                Seg::Text(t) | Seg::Code(t) | Seg::Addr(t, _) => *t,
            })
            .collect();
        assert!(rebuilt.contains("See ") && rebuilt.contains(" and "));
    }

    #[test]
    fn markdown_reads_as_blocks_and_styles() {
        let b = parse(
            "# Title\n\nSome **bold** and *slanted* and `code`.\n\n1. one\n2. two\n\n- a\n- b\n\n```c\nint x;\n```\n\n> said\n\n---\n",
        );
        assert!(matches!(&b[0], Block::Heading(1, t) if t[0].text == "Title"));
        let Block::Para(p) = &b[1] else {
            panic!("{b:?}")
        };
        assert!(p.iter().any(|i| i.text == "bold" && i.style.bold));
        assert!(p.iter().any(|i| i.text == "slanted" && i.style.italic));
        assert!(p.iter().any(|i| i.text == "code" && i.style.code));
        assert!(matches!(&b[2], Block::List { start: Some(1), items } if items.len() == 2));
        assert!(matches!(&b[3], Block::List { start: None, items } if items.len() == 2));
        assert!(matches!(&b[4], Block::Code(c) if c == "int x;"));
        assert!(matches!(&b[5], Block::Quote(_)));
        assert!(matches!(&b[6], Block::Rule));
    }

    #[test]
    fn styles_in_a_tight_list_item_are_kept() {
        let b = parse("- **Key:** value\n- plain\n");
        let Block::List { items, .. } = &b[0] else {
            panic!("{b:?}")
        };
        let Block::Para(p) = &items[0][0] else {
            panic!("{b:?}")
        };
        assert!(p[0].style.bold && p[0].text == "Key:", "{p:?}");
        assert!(!p[1].style.bold, "{p:?}");
    }

    #[test]
    fn tables_links_and_half_written_text() {
        let b = parse("| a | b |\n|---|---|\n| 1 | 2 |\n");
        assert!(
            matches!(&b[0], Block::Table { head, rows } if head.len() == 2 && rows[0].len() == 2)
        );
        let b = parse("- see [it](https://example.com)\n");
        let Block::List { items, .. } = &b[0] else {
            panic!("{b:?}")
        };
        let Block::Para(p) = &items[0][0] else {
            panic!("{b:?}")
        };
        assert_eq!(p[1].link.as_deref(), Some("https://example.com"), "{p:?}");
        let b = parse("[site](https://example.com)");
        let Block::Para(p) = &b[0] else {
            panic!("{b:?}")
        };
        assert_eq!(p[0].link.as_deref(), Some("https://example.com"));
        assert!(!parse("**unfinished\n\n```\ncode").is_empty());
        assert!(parse("").is_empty());
    }

    #[test]
    fn near_misses_stay_text() {
        for s in ["0x12", "foo0x401000", "0x401000zz", "price 0xZZZZ", "a ` b"] {
            assert!(
                segments(s).iter().all(|g| !matches!(g, Seg::Addr(..))),
                "{s}"
            );
        }
        assert_eq!(segments(""), Vec::<Seg>::new());
        assert_eq!(segments("plain"), vec![Seg::Text("plain")]);
    }
}

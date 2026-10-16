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

/// Several paragraphs: blank lines separate them, lines starting with `- ` are bullets.
pub fn paragraphs(
    ui: &mut Ui,
    vm: &ViewModel,
    p: &Palette,
    text: &str,
    size: f32,
    goto: &mut Option<u64>,
) {
    for (n, para) in text.trim().split("\n\n").enumerate() {
        if n > 0 {
            ui.add_space(4.0);
        }
        for l in para.lines() {
            let trimmed = l.trim_start();
            if let Some(rest) = trimmed
                .strip_prefix("- ")
                .or_else(|| trimmed.strip_prefix("* "))
            {
                line(ui, vm, p, &format!("\u{2022} {rest}"), size, goto);
            } else {
                line(ui, vm, p, l, size, goto);
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

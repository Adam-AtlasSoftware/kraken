//! The Strings tab: text found in the program. Double-click one to see what uses it.

use egui::{RichText, Ui};
use kraken_gui_widgets::VirtualList;
use kraken_proto::StringEncoding;
use kraken_viewmodel::ViewModel;

use super::PanelState;
use crate::style::{self, chip, empty_state, pal};

#[derive(Default)]
pub struct StringsUi {
    pub filter: String,
    selected: Option<usize>,
}

/// One line of text for a list: control characters shown visibly, long text clipped.
pub fn one_line(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .take(max)
        .map(|c| match c {
            '\n' => '\u{21b5}',
            '\t' => '\u{2192}',
            c if c.is_control() => '\u{fffd}',
            c => c,
        })
        .collect();
    if s.chars().count() > max {
        out.push_str("...");
    }
    out
}

/// Plain name of an encoding, for the chip next to a string.
pub fn encoding_label(e: StringEncoding) -> Option<&'static str> {
    match e {
        StringEncoding::Ascii => None,
        StringEncoding::Utf8 => Some("utf-8"),
        StringEncoding::Utf16 => Some("utf-16"),
        StringEncoding::Utf32 => Some("utf-32"),
        StringEncoding::Other => Some("other"),
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_strings();

    let edit = egui::TextEdit::singleline(&mut st.strings.filter)
        .hint_text("Filter strings")
        .desired_width(f32::INFINITY);
    if ui
        .add(edit)
        .on_hover_text("Type part of a string to narrow the list")
        .changed()
    {
        vm.set_strings_filter(st.strings.filter.clone());
    }
    let list = &vm.views.strings;
    let n = list.items.len();
    let summary = if list.loading && n == 0 {
        "Loading...".to_string()
    } else if !list.filter.is_empty() {
        format!(
            "{n}{} match{}",
            if list.has_more() { "+" } else { "" },
            if n == 1 { "" } else { "es" }
        )
    } else if let Some(t) = list.total {
        format!("{n} of {t} strings")
    } else {
        format!(
            "{n}{} string{}",
            if list.has_more() { "+" } else { "" },
            if n == 1 { "" } else { "s" }
        )
    };
    let selected_now = st
        .strings
        .selected
        .and_then(|i| list.items.get(i))
        .map(|it| it.address);
    let mut edit_string = None;
    ui.horizontal(|ui| {
        ui.label(RichText::new(summary).size(11.5).color(p.text_dim));
        if ui
            .add_enabled(
                selected_now.is_some(),
                egui::Button::new("Edit string...").small(),
            )
            .on_hover_text(
                "Change the text of the selected string in the program: same length or \
                 shorter, padded with zero bytes. Nothing on disk changes until you export",
            )
            .on_disabled_hover_text("Select a string first")
            .clicked()
        {
            edit_string = selected_now;
        }
    });

    if let Some(err) = list.error.clone() {
        ui.label(RichText::new(err).color(s.danger));
        if ui
            .button("Try again")
            .on_hover_text("Ask for it again")
            .clicked()
        {
            vm.retry_strings();
        }
        return;
    }
    if n == 0 {
        if !list.loaded {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new("Searching for strings...").color(p.text_dim));
            });
        } else if !list.filter.is_empty() {
            empty_state(
                ui,
                "No matches",
                &format!("No string contains \"{}\".", list.filter),
                Some("Clear the filter to see everything."),
            );
        } else {
            empty_state(
                ui,
                "No strings found",
                "KRAKEN did not find readable text in this program.",
                None,
            );
        }
        return;
    }

    let mut selected = st.strings.selected.filter(|i| *i < n);
    let mut max_seen = 0usize;
    let items = &list.items;
    let resp = VirtualList::new("strings", n, 22.0).show(ui, &mut selected, |ui, i, sel| {
        max_seen = max_seen.max(i);
        let it = &items[i];
        ui.label(
            RichText::new(format!("{:08x}", it.address))
                .monospace()
                .size(12.0)
                .color(p.address),
        );
        let color = if sel { p.text_strong } else { p.text };
        ui.label(
            RichText::new(one_line(&it.value, 160))
                .monospace()
                .size(12.5)
                .color(color),
        )
        .on_hover_text("Double-click to see what uses this string")
        .context_menu(|ui| {
            if ui
                .button("Edit string...")
                .on_hover_text("Change this string in the program (same length or shorter)")
                .clicked()
            {
                edit_string = Some(it.address);
                ui.close();
            }
        });
        if let Some(e) = encoding_label(it.encoding) {
            chip(ui, e, p.text_dim);
        }
    });
    st.strings.selected = selected;
    vm.strings_scrolled(max_seen + 1);
    if let Some(a) = edit_string {
        vm.begin_string_edit(a);
    }
    if let Some(i) = resp.double_clicked {
        vm.open_string(i);
    }
    if let Some(i) = selected {
        st.hot = vm.views.strings.items.get(i).map(|it| it.address);
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn text_is_one_visible_line() {
        assert_eq!(one_line("a\nb\tc", 20), "a\u{21b5}b\u{2192}c");
        assert_eq!(one_line("abcdef", 3), "abc...");
        assert_eq!(one_line("x\u{7}y", 5), "x\u{fffd}y");
    }
}

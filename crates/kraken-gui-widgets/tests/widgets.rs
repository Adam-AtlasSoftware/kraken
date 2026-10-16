//! egui_kittest smoke tests: the widgets lay out and respond without panicking.

use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;
use kraken_gui_widgets::{HexView, KrakenTheme, TokenText, VirtualList};
use kraken_proto::{Completeness, DecompileResult, Locator, Token, TokenKind};

fn result() -> DecompileResult {
    let text = "int main(void)\n{\n  return helper(1);\n}\n";
    let at = |needle: &str| text.find(needle).map_or(0, |p| p as u32);
    let tok = |s: &str, kind, sym: Option<&str>, target: Option<Locator>| Token {
        start: at(s),
        end: at(s) + s.len() as u32,
        kind,
        target,
        symbol: sym.map(str::to_string),
        varnode: None,
    };
    DecompileResult {
        function: Locator::ram(0x1000),
        language: "c".into(),
        text: text.into(),
        tokens: vec![
            tok("int", TokenKind::Type, Some("int"), None),
            tok("main", TokenKind::Function, Some("main"), None),
            tok(
                "helper",
                TokenKind::Function,
                Some("helper"),
                Some(Locator::ram(0x2000)),
            ),
        ],
        warnings: vec![],
        completeness: Completeness::Complete,
    }
}

#[test]
fn token_text_renders_both_themes() {
    for theme in [KrakenTheme::DARK, KrakenTheme::LIGHT] {
        let r = result();
        let mut h = Harness::new_ui(move |ui| {
            theme.apply(ui.ctx());
            TokenText::new(&r).show(ui);
        });
        h.run();
        h.run();
    }
}

#[test]
fn virtual_list_handles_huge_len_and_selection() {
    let mut selected = Some(0usize);
    let mut h = Harness::new_ui_state(
        |ui, selected: &mut Option<usize>| {
            KrakenTheme::DARK.apply(ui.ctx());
            VirtualList::new("l", 1_000_000, 20.0).show(ui, selected, |ui, i, _| {
                ui.label(format!("row {i}"));
            });
        },
        selected,
    );
    h.run();
    assert!(h.query_by_label("row 0").is_some());
    assert!(h.query_by_label("row 999999").is_none());
    selected = *h.state();
    assert_eq!(selected, Some(0));
}

#[test]
fn hex_view_renders_empty_and_small_sources() {
    let small: Vec<u8> = (0..40).collect();
    let empty: Vec<u8> = Vec::new();
    for data in [small, empty] {
        let mut h = Harness::new_ui(move |ui| {
            KrakenTheme::DARK.apply(ui.ctx());
            HexView::new(&data, 0x1000).show(ui);
        });
        h.run();
    }
}

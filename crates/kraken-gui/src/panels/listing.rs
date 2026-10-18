//! The Listing tab: machine instructions of the current function, one per line.

use std::cell::Cell;

use egui::{RichText, Ui};
use kraken_gui_widgets::{ListingRow, ListingSource, ListingView, OperandToken};
use kraken_proto::TokenKind;
use kraken_viewmodel::{ListingRowItem, ViewModel, mnemonic_kind, operand_kind};

use super::PanelState;
use crate::style::{self, empty_state, medium, pal};
use crate::workspace::Tab;

/// A line of the display: an instruction, or a label above one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// A name defined at the next instruction.
    Label {
        /// Index of the instruction the label belongs to.
        row: usize,
        /// The name.
        text: String,
    },
    /// An instruction by row index.
    Insn(usize),
}

/// The lines for `rows`: each label gets a line of its own above its instruction.
pub fn lines_for(rows: &[ListingRowItem]) -> Vec<Line> {
    let mut out = Vec::with_capacity(rows.len());
    for (i, r) in rows.iter().enumerate() {
        for l in &r.labels {
            out.push(Line::Label {
                row: i,
                text: l.clone(),
            });
        }
        out.push(Line::Insn(i));
    }
    out
}

/// Cached display lines, rebuilt when the rows change.
#[derive(Default)]
pub struct ListingUi {
    key: Option<(Option<u64>, u64)>,
    lines: Vec<Line>,
    /// Display line of each instruction row.
    insn_line: Vec<usize>,
}

impl ListingUi {
    fn refresh(&mut self, function: Option<u64>, revision: u64, rows: &[ListingRowItem]) {
        if self.key == Some((function, revision)) {
            return;
        }
        self.lines = lines_for(rows);
        self.insn_line = vec![0; rows.len()];
        for (li, l) in self.lines.iter().enumerate() {
            if let Line::Insn(i) = l {
                self.insn_line[*i] = li;
            }
        }
        self.key = Some((function, revision));
    }
}

struct Source<'a> {
    rows: &'a [ListingRowItem],
    lines: &'a [Line],
    max_seen: Cell<usize>,
}

impl ListingSource for Source<'_> {
    fn len(&self) -> usize {
        self.lines.len()
    }

    fn row(&self, index: usize) -> ListingRow {
        self.max_seen.set(self.max_seen.get().max(index));
        match &self.lines[index] {
            Line::Label { row, text } => ListingRow {
                address: self.rows[*row].address,
                bytes: Vec::new(),
                mnemonic: format!("{text}:"),
                mnemonic_kind: TokenKind::Function,
                operands: Vec::new(),
                comment: None,
            },
            Line::Insn(i) => {
                let r = &self.rows[*i];
                ListingRow {
                    address: r.address,
                    bytes: r.bytes.clone(),
                    mnemonic: r.mnemonic.clone(),
                    mnemonic_kind: mnemonic_kind(r.flow),
                    operands: r
                        .operands
                        .iter()
                        .map(|o| {
                            let t = OperandToken::new(o.text.clone(), operand_kind(o.kind));
                            match o.target {
                                Some(a) => t.with_target(a),
                                None => t,
                            }
                        })
                        .collect(),
                    comment: r.comment.clone(),
                }
            }
        }
    }
}

pub fn show(
    ui: &mut Ui,
    vm: &mut ViewModel,
    st: &mut PanelState,
    assist: &mut crate::assist::AssistUi,
) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    st.front = Some(Tab::Listing);
    let Some(cur) = vm.current.as_ref() else {
        empty_state(
            ui,
            "No instructions to show yet",
            "Pick a function and its machine instructions appear here, one per line.",
            Some("Tip: click an address, name or number in a call to jump there."),
        );
        return;
    };
    let name = cur.name.clone();
    vm.ensure_listing();

    ui.horizontal(|ui| {
        ui.label(medium(&name, 14.0).color(p.text_strong));
        let l = &vm.views.listing;
        if l.loading {
            ui.spinner();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("Graph  (Space)")
                .on_hover_text("See the same code as boxes joined by arrows")
                .clicked()
            {
                st.swap_requested = true;
            }
            if ui
                .button("Who refers here  (X)")
                .on_hover_text("List everything that points at the selected instruction")
                .clicked()
            {
                let at = vm.views.listing.selected_row().map(|r| r.address);
                match at {
                    Some(a) => vm.show_references(a, None),
                    None => vm.references_to_cursor(),
                }
            }
        });
    });

    if let Some(err) = vm.views.listing.error.clone() {
        ui.label(RichText::new("The instructions could not be listed.").color(s.danger));
        ui.label(RichText::new(err).color(p.text_dim));
        if ui
            .button("Try again")
            .on_hover_text("Ask for it again")
            .clicked()
        {
            vm.retry_listing();
        }
        return;
    }
    if !vm.views.listing.loaded {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Reading instructions...").color(p.text_dim));
        });
        return;
    }
    if vm.views.listing.rows.is_empty() {
        empty_state(
            ui,
            "No instructions here",
            "This function has no code of its own, for example an import placeholder.",
            None,
        );
        return;
    }

    let l = &vm.views.listing;
    st.listing.refresh(l.function, l.revision, &l.rows);
    let scroll = vm
        .views
        .listing
        .take_scroll()
        .and_then(|i| st.listing.insn_line.get(i).copied());
    let l = &vm.views.listing;
    let mut selected = l
        .selected
        .and_then(|i| st.listing.insn_line.get(i).copied());
    let src = Source {
        rows: &l.rows,
        lines: &st.listing.lines,
        max_seen: Cell::new(0),
    };
    let digits = if l
        .rows
        .last()
        .is_some_and(|r| r.address > u64::from(u32::MAX))
    {
        16
    } else {
        8
    };
    let mut view = ListingView::new(&src)
        .id_salt("listing")
        .address_digits(digits);
    if let Some(i) = scroll {
        view = view.scroll_to(i);
    }
    let out = view.show_with_targets(ui, &mut selected);
    let visible_end = src.max_seen.get() + 1;
    let lines = &st.listing.lines;

    let row_of_line = |li: usize| match lines.get(li) {
        Some(Line::Insn(i) | Line::Label { row: i, .. }) => Some(*i),
        None => None,
    };
    if let Some(li) = out.row_hovered
        && let Some(i) = row_of_line(li)
    {
        let row = &vm.views.listing.rows[i];
        st.hot = Some(row.address);
        let ops: String = row.operands.iter().map(|o| o.text.as_str()).collect();
        let text = format!("{} {ops}", row.mnemonic);
        crate::assist::capture_instruction_at(
            ui,
            ui.max_rect(),
            row.address,
            &text,
            vm.views.listing.function,
            assist,
        );
    }
    if let Some((_, target)) = out.target_hovered {
        st.hot = Some(target);
    }
    let clicked_row = out.list.clicked.and_then(row_of_line);
    let jump = out.target_clicked.map(|(_, t)| t);
    vm.listing_scrolled(visible_end);
    if let Some(i) = clicked_row {
        vm.select_listing_row(i);
    } else if out.list.changed
        && let Some(i) = selected.and_then(row_of_line)
    {
        vm.select_listing_row(i);
    }
    if let Some(t) = jump {
        vm.goto(t);
    }
}

#[cfg(test)]
mod unit {
    use super::*;
    use kraken_proto::FlowKind;

    fn row(addr: u64, labels: &[&str]) -> ListingRowItem {
        ListingRowItem {
            address: addr,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: Vec::new(),
            comment: None,
            labels: labels.iter().map(|s| s.to_string()).collect(),
            flow: FlowKind::Fallthrough,
        }
    }

    #[test]
    fn labels_get_their_own_line_above_the_instruction() {
        let rows = [
            row(0x10, &["entry", "_start"]),
            row(0x11, &[]),
            row(0x12, &["loop"]),
        ];
        let lines = lines_for(&rows);
        assert_eq!(lines.len(), 6);
        assert_eq!(
            lines[0],
            Line::Label {
                row: 0,
                text: "entry".into()
            }
        );
        assert_eq!(lines[2], Line::Insn(0));
        assert_eq!(lines[3], Line::Insn(1));
        assert_eq!(
            lines[4],
            Line::Label {
                row: 2,
                text: "loop".into()
            }
        );

        let mut ui = ListingUi::default();
        ui.refresh(Some(1), 1, &rows);
        assert_eq!(ui.insn_line, vec![2, 3, 5]);
        // Same key: not rebuilt.
        ui.insn_line = vec![9];
        ui.refresh(Some(1), 1, &rows);
        assert_eq!(ui.insn_line, vec![9]);
        ui.refresh(Some(1), 2, &rows);
        assert_eq!(ui.insn_line.len(), 3);
    }
}

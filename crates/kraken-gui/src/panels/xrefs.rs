//! The Xrefs tab: who calls this function, what it calls, and who refers to any address.

use egui::{RichText, Ui};
use kraken_gui_widgets::VirtualList;
use kraken_viewmodel::{ViewModel, XrefItem, XrefList, XrefWhich};

use super::{PanelState, describe, xref_tab_label};
use crate::style::{self, chip, empty_state, pal};

/// Which list is showing, and which "references to" address was last switched to.
pub struct XrefsUi {
    pub tab: XrefWhich,
    seen_refs: Option<u64>,
    selected: Option<usize>,
}

impl Default for XrefsUi {
    fn default() -> Self {
        XrefsUi {
            tab: XrefWhich::Callers,
            seen_refs: None,
            selected: None,
        }
    }
}

/// The text of one row: where the reference is and what it does.
pub fn row_text(which: XrefWhich, x: &XrefItem, vm: &ViewModel) -> (String, String) {
    match which {
        XrefWhich::Callers | XrefWhich::References => {
            let place = match &x.from_function {
                Some(f) => format!("{} +{:#x}", f.name, x.from.saturating_sub(f.address)),
                None => describe(vm, x.from),
            };
            (place, format!("{:#x}", x.from))
        }
        XrefWhich::Callees => {
            let target = match &x.to_function {
                Some(f) => f.name.clone(),
                None => describe(vm, x.to),
            };
            (target, format!("{:#x}", x.to))
        }
    }
}

pub fn show(ui: &mut Ui, vm: &mut ViewModel, st: &mut PanelState) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    vm.ensure_xrefs();

    // A fresh "references to" request switches to its tab.
    let refs_addr = vm.views.xrefs.references.as_ref().map(|r| r.address);
    if refs_addr != st.xrefs.seen_refs {
        st.xrefs.seen_refs = refs_addr;
        if refs_addr.is_some() {
            st.xrefs.tab = XrefWhich::References;
            st.xrefs.selected = None;
        }
    }
    if st.xrefs.tab == XrefWhich::References && refs_addr.is_none() {
        st.xrefs.tab = XrefWhich::Callers;
    }

    ui.horizontal(|ui| {
        for which in [
            XrefWhich::Callers,
            XrefWhich::Callees,
            XrefWhich::References,
        ] {
            if which == XrefWhich::References && refs_addr.is_none() {
                continue;
            }
            let n = vm.views.xrefs.list(which).map_or(0, |l| l.items.len());
            let more = vm.views.xrefs.list(which).is_some_and(XrefList::has_more);
            let label = format!(
                "{} ({n}{})",
                xref_tab_label(which),
                if more { "+" } else { "" }
            );
            if ui.selectable_label(st.xrefs.tab == which, label).clicked() {
                st.xrefs.tab = which;
                st.xrefs.selected = None;
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .button("Who refers here  (X)")
                .on_hover_text("List everything that points at the address you are looking at")
                .clicked()
            {
                vm.references_to_cursor();
            }
        });
    });
    let which = st.xrefs.tab;
    let heading = match which {
        XrefWhich::Callers => vm
            .current
            .as_ref()
            .map(|c| format!("Places that call {}", c.name)),
        XrefWhich::Callees => vm
            .current
            .as_ref()
            .map(|c| format!("Functions that {} calls", c.name)),
        XrefWhich::References => vm
            .views
            .xrefs
            .references
            .as_ref()
            .map(|r| format!("Places that refer to {}", r.label)),
    };
    let Some(heading) = heading else {
        empty_state(
            ui,
            "No references to show yet",
            "Pick a function to see who calls it and what it calls.",
            Some("Tip: press X over any address, name or byte to see what refers to it."),
        );
        return;
    };
    ui.label(RichText::new(heading).size(12.5).color(p.text_dim));

    let Some(list) = vm.views.xrefs.list(which) else {
        return;
    };
    if let Some(err) = list.error.clone() {
        ui.label(RichText::new(err).color(s.danger));
        return;
    }
    if !list.loaded {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(RichText::new("Looking...").color(p.text_dim));
        });
        return;
    }
    if list.items.is_empty() {
        let (title, body) = match which {
            XrefWhich::Callers => (
                "Nothing calls this function",
                "It may be an entry point, or only be reached through a pointer.",
            ),
            XrefWhich::Callees => (
                "This function calls nothing",
                "It makes no calls that KRAKEN could follow.",
            ),
            XrefWhich::References => (
                "Nothing refers to this address",
                "No code or data in the analyzed program points at it.",
            ),
        };
        empty_state(ui, title, body, None);
        return;
    }

    let n = list.items.len();
    let has_more = list.has_more();
    let mut max_seen = 0usize;
    let mut selected = st.xrefs.selected.filter(|i| *i < n);
    let items: Vec<(String, String, &'static str)> = list
        .items
        .iter()
        .map(|x| {
            let (a, b) = row_text(which, x, vm);
            (a, b, x.kind_label())
        })
        .collect();
    let resp =
        VirtualList::new(("xrefs", which as u8), n, 22.0).show(ui, &mut selected, |ui, i, sel| {
            max_seen = max_seen.max(i);
            let (place, addr, kind) = &items[i];
            chip(ui, kind, p.text_dim);
            let color = if sel { p.text_strong } else { p.text };
            ui.label(RichText::new(place).monospace().size(12.5).color(color));
            ui.label(RichText::new(addr).monospace().size(11.5).color(p.address));
        });
    st.xrefs.selected = selected;
    if let Some(i) = resp.clicked {
        vm.open_xref(which, i);
    }
    if has_more && max_seen + 20 >= n {
        vm.more_xrefs(which);
    }
}

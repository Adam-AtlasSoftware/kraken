//! The program views: listing, hex, graph, cross-references, strings, imports and exports.
//! Each panel draws state that lives in `ViewModel::views` and sends clicks back to it.

pub mod graph;
pub mod hex;
pub mod listing;
pub mod strings;
pub mod symbols;
pub mod xrefs;

#[cfg(test)]
mod tests;

use egui::{Context, Key, Modifiers};
use egui_dock::DockState;
use kraken_viewmodel::{Reveal, ViewModel, XrefWhich};

use crate::workspace::Tab;

/// GUI-only state of the program views.
#[derive(Default)]
pub struct PanelState {
    pub listing: listing::ListingUi,
    pub graph: graph::GraphUi,
    pub strings: strings::StringsUi,
    pub symbols: symbols::SymbolsUi,
    pub xrefs: xrefs::XrefsUi,
    /// Address under the pointer in the panel the person is working in; `X` asks about it.
    pub hot: Option<u64>,
    /// The listing or graph that was drawn last frame, so Space knows which one to swap out.
    pub front: Option<Tab>,
    /// Space was pressed: show the other one next.
    pub swap_requested: bool,
}

impl PanelState {
    /// The tab a navigation wants in front.
    pub fn tab_for(reveal: Reveal) -> Tab {
        match reveal {
            Reveal::Decompiler => Tab::Decompiler,
            Reveal::Listing => Tab::Listing,
            Reveal::Graph => Tab::Graph,
            Reveal::Hex => Tab::Hex,
            Reveal::Xrefs => Tab::Xrefs,
        }
    }
}

/// Which tab Space switches to, given which of listing and graph was in front.
pub fn space_target(front: Option<Tab>) -> Tab {
    if front == Some(Tab::Listing) {
        Tab::Graph
    } else {
        Tab::Listing
    }
}

/// Window-wide keys of the program views: Space swaps listing and graph (like IDA), X lists the
/// references to the address under the pointer. Also carries out the navigations the view-model
/// asked to show.
pub fn global_keys(
    ctx: &Context,
    dock: &mut DockState<Tab>,
    vm: &mut ViewModel,
    st: &mut PanelState,
) {
    let typing = ctx.egui_wants_keyboard_input();
    let (space, x) = if typing {
        (false, false)
    } else {
        ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, Key::Space),
                i.consume_key(Modifiers::NONE, Key::X),
            )
        })
    };
    let front = st.front.take();
    let mut bring: Option<Tab> = None;
    if space || st.swap_requested {
        st.swap_requested = false;
        bring = Some(space_target(front));
    }
    if x {
        let addr = st
            .hot
            .or(vm.views.cursor)
            .or(vm.current.as_ref().map(|c| c.address));
        match addr {
            Some(a) => vm.show_references(a, None),
            None => vm.references_to_cursor(),
        }
    }
    st.hot = None;
    if let Some(r) = vm.views.take_reveal() {
        bring = Some(PanelState::tab_for(r));
    }
    if let Some(tab) = bring
        && let Some(path) = dock.find_tab(&tab)
    {
        let _ = dock.set_active_tab(path);
    }
}

/// `0x401000` with a function name when the view-model knows one.
pub fn describe(vm: &ViewModel, addr: u64) -> String {
    match vm.functions.find(addr) {
        Some(f) => format!("{} ({addr:#x})", f.name),
        None => format!("{addr:#x}"),
    }
}

/// Label of an xref list tab.
pub fn xref_tab_label(which: XrefWhich) -> &'static str {
    match which {
        XrefWhich::Callers => "Callers",
        XrefWhich::Callees => "Calls",
        XrefWhich::References => "References",
    }
}

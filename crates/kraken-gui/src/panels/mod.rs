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
    switch_tab_by_key(ctx, dock);
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

/// Where Ctrl+Tab / Ctrl+Shift+Tab lands from tab `cur` among `len` tabs, wrapping around.
pub fn cycled(len: usize, cur: usize, backwards: bool) -> usize {
    if len == 0 {
        0
    } else if backwards {
        (cur + len - 1) % len
    } else {
        (cur + 1) % len
    }
}

const NUMBER_KEYS: [Key; 9] = [
    Key::Num1,
    Key::Num2,
    Key::Num3,
    Key::Num4,
    Key::Num5,
    Key::Num6,
    Key::Num7,
    Key::Num8,
    Key::Num9,
];

/// The pane the tab keys act on: the focused one, or before anything was clicked the pane that
/// holds the most tabs.
pub fn target_pane(dock: &DockState<Tab>) -> Option<egui_dock::NodePath> {
    dock.focused_leaf().or_else(|| {
        let mut count: std::collections::BTreeMap<(usize, usize), (usize, egui_dock::NodePath)> =
            std::collections::BTreeMap::new();
        for (p, _) in dock.iter_all_tabs() {
            let n = p.node_path();
            count.entry((p.surface.0, n.node.0)).or_insert((0, n)).0 += 1;
        }
        count.into_values().max_by_key(|(n, _)| *n).map(|(_, p)| p)
    })
}

/// Ctrl+Tab and Ctrl+Shift+Tab step through the tabs of the focused dock pane; Ctrl+1 to Ctrl+9
/// jump to the nth one.
fn switch_tab_by_key(ctx: &Context, dock: &mut DockState<Tab>) {
    let (next, prev, nth) = ctx.input_mut(|i| {
        // The shifted chord first: a plain Ctrl+Tab pattern also matches it.
        let prev = i.consume_key(Modifiers::COMMAND | Modifiers::SHIFT, Key::Tab);
        let next = i.consume_key(Modifiers::COMMAND, Key::Tab);
        let nth = NUMBER_KEYS
            .iter()
            .position(|k| i.consume_key(Modifiers::COMMAND, *k));
        (next, prev, nth)
    });
    if !(next || prev || nth.is_some()) {
        return;
    }
    let Some(node) = target_pane(dock) else {
        return;
    };
    let tabs: Vec<_> = dock
        .iter_all_tabs()
        .filter(|(p, _)| p.node_path() == node)
        .map(|(p, t)| (p, *t))
        .collect();
    let active = dock.find_active_focused().map(|(_, t)| *t);
    let cur = active
        .and_then(|a| tabs.iter().position(|(_, t)| *t == a))
        .unwrap_or(0);
    let target = match nth {
        Some(n) if n < tabs.len() => n,
        Some(_) => return,
        None => cycled(tabs.len(), cur, prev),
    };
    if let Some((path, _)) = tabs.get(target) {
        let _ = dock.set_active_tab(*path);
        dock.set_focused_node_and_surface(node);
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

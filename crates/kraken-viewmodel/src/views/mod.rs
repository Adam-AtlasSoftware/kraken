//! State and logic of the program views: listing, hex, graph, cross-references, strings,
//! imports and exports. Each view loads lazily through the data commands (`disassemble`,
//! `read_bytes`, `cfg`, `xrefs`, `strings`, ...) and navigation keeps them in step.
//!
//! The GUI calls the `ensure_*` methods while it draws a view; they load what is missing and do
//! nothing when the data is already there.

pub mod bytes;
mod decomp;
pub mod graph;
pub mod hex;
pub mod listing;
pub mod lists;
pub mod nav;
pub mod patched;
pub mod xrefs;

mod wire;

#[cfg(test)]
mod tests;

pub use bytes::{ByteCache, ByteState};
pub use graph::{GraphBlock, GraphData, GraphEdgeKind, GraphState};
pub use hex::{HexState, MemoryBlockItem, MemoryMap};
pub use listing::{
    ListingOperand, ListingRowItem, ListingState, RowPatch, mnemonic_kind, operand_kind,
};
pub use lists::{PagedList, StringItem, SymbolItem, SymbolTable};
pub use patched::PatchedDecompile;
pub use xrefs::{FnRef, ReferencesTo, XrefItem, XrefList, XrefWhich, XrefsPanel};

/// Which view the GUI should bring to the front after a navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reveal {
    /// The decompiler.
    Decompiler,
    /// The instruction listing.
    Listing,
    /// The control-flow graph.
    Graph,
    /// The hex dump.
    Hex,
    /// The cross-reference lists.
    Xrefs,
}

/// All program-view state.
#[derive(Default)]
pub struct ProgramViews {
    next_seq: u64,
    pub(crate) bytes_gen: u64,
    /// Function the listing, graph and cross-references describe.
    pub function: Option<u64>,
    /// The address last navigated to or selected in a view.
    pub cursor: Option<u64>,
    /// A view the GUI should bring forward; take it with [`ProgramViews::take_reveal`].
    pub reveal: Option<Reveal>,
    /// The memory map behind the hex view's block list.
    pub memory: MemoryMap,
    /// Hex view position and highlight.
    pub hex: HexState,
    /// Lazily loaded program bytes.
    pub bytes: ByteCache,
    /// Disassembly of the current function.
    pub listing: ListingState,
    /// Control-flow graph of the current function.
    pub graph: GraphState,
    /// Callers, callees and "references to" lists.
    pub xrefs: XrefsPanel,
    /// Strings found in the program.
    pub strings: PagedList<StringItem>,
    /// Imported symbols.
    pub imports: PagedList<SymbolItem>,
    /// Exported symbols.
    pub exports: PagedList<SymbolItem>,
    pub(crate) place_req: u64,
    /// Show the program as the byte patches would leave it (the Patched side of the toggle).
    pub patched: bool,
    /// The patched decompile of the current function, when asked for.
    pub patched_decompile: patched::PatchedDecompile,
}

impl ProgramViews {
    /// A fresh request token. Tokens never repeat, even across [`reset`](Self::reset), so late
    /// answers to old requests are recognised and dropped.
    pub(crate) fn next_seq(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Forgets everything (a new project was opened).
    pub(crate) fn reset(&mut self) {
        let seq = self.next_seq + 1;
        let page = self.listing.page_size;
        *self = ProgramViews {
            next_seq: seq,
            bytes_gen: seq,
            ..ProgramViews::default()
        };
        self.listing.page_size = page;
    }

    /// Takes the pending request to bring a view forward.
    pub fn take_reveal(&mut self) -> Option<Reveal> {
        self.reveal.take()
    }
}

impl crate::ViewModel {
    /// Called whenever the current function is (re)requested: a new function clears the
    /// function-scoped views, a refresh of the same one marks them out of date.
    pub(crate) fn views_on_request(&mut self, addr: u64) {
        if self.views.function == Some(addr) {
            let v = &mut self.views;
            v.listing.stale = true;
            v.graph.stale = true;
            v.xrefs.stale = true;
            v.patched_decompile = Default::default();
            return;
        }
        let size = self.functions.find(addr).and_then(|f| f.size).unwrap_or(64);
        let v = &mut self.views;
        let page_size = v.listing.page_size;
        v.function = Some(addr);
        v.cursor = Some(addr);
        v.listing = ListingState {
            page_size,
            ..ListingState::default()
        };
        v.graph = GraphState::default();
        v.patched_decompile = Default::default();
        v.xrefs.function = None;
        v.xrefs.callers = XrefList::default();
        v.xrefs.callees = XrefList::default();
        v.xrefs.stale = false;
        self.hex_follow(addr, size);
    }

    /// The function's real size arrived: use it for the hex highlight.
    pub(crate) fn views_detail(&mut self, addr: u64, size: Option<u64>) {
        let Some(size) = size.filter(|s| *s > 0) else {
            return;
        };
        let h = &mut self.views.hex.highlight;
        if h.as_ref().is_some_and(|r| r.start == addr) {
            *h = Some(addr..addr.saturating_add(size));
            self.views.bytes.want_range(addr, size.min(65536));
            self.service_bytes();
        }
    }

    /// A project was opened: fetch what the views always need.
    pub(crate) fn views_project_opened(&mut self) {
        self.refresh_memory_map();
    }
}
pub(crate) use decomp::{server_tokens, target_locator};
pub(crate) use wire::TokenWire;

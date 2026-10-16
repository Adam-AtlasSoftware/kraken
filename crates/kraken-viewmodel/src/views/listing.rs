//! The instruction listing of the current function, paged with `disassemble`.

use kraken_proto::{FlowKind, OperandKind, Page, TokenKind};
use serde_json::{Value, json};

use super::wire::{InsnWire, OperandWire};
use crate::errors::plain_error;
use crate::vm::{ViewModel, hex, parse};

/// Instructions requested per page.
pub const LISTING_PAGE: u32 = 200;

/// One piece of an instruction's operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingOperand {
    /// Text to show: a register, number, symbol name or punctuation.
    pub text: String,
    /// What the piece is.
    pub kind: OperandKind,
    /// Address the piece refers to (jump targets, called functions, globals).
    pub target: Option<u64>,
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingRowItem {
    /// Address of the instruction.
    pub address: u64,
    /// Its bytes.
    pub bytes: Vec<u8>,
    /// Mnemonic such as `mov`.
    pub mnemonic: String,
    /// Operand pieces, to be drawn back to back.
    pub operands: Vec<ListingOperand>,
    /// Comment at the address.
    pub comment: Option<String>,
    /// Labels defined at the address.
    pub labels: Vec<String>,
    /// Control flow out of the instruction.
    pub flow: FlowKind,
}

impl ListingRowItem {
    /// True when any operand points at `addr`.
    pub fn refers_to(&self, addr: u64) -> bool {
        self.operands.iter().any(|o| o.target == Some(addr))
    }

    /// First operand that points somewhere, if any.
    pub fn first_target(&self) -> Option<u64> {
        self.operands.iter().find_map(|o| o.target)
    }
}

/// Color class of a mnemonic.
pub fn mnemonic_kind(flow: FlowKind) -> TokenKind {
    match flow {
        FlowKind::Call => TokenKind::Function,
        FlowKind::Jump | FlowKind::ConditionalJump | FlowKind::Indirect | FlowKind::Return => {
            TokenKind::Keyword
        }
        FlowKind::Other => TokenKind::Keyword,
        FlowKind::Fallthrough => TokenKind::Type,
    }
}

/// Color class of an operand piece.
pub fn operand_kind(kind: OperandKind) -> TokenKind {
    match kind {
        OperandKind::Register => TokenKind::Variable,
        OperandKind::Immediate | OperandKind::Address => TokenKind::Constant,
        OperandKind::Symbol => TokenKind::Function,
        OperandKind::Other => TokenKind::Op,
    }
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

fn operand(o: OperandWire) -> ListingOperand {
    let text = match (&o.symbol, o.kind) {
        (Some(s), OperandKind::Symbol) if !s.0.is_empty() => s.0.clone(),
        _ => o.text,
    };
    let text = if o.kind == OperandKind::Register {
        text.to_lowercase()
    } else {
        text
    };
    ListingOperand {
        text,
        kind: o.kind,
        target: o.target.map(|t| t.0),
    }
}

fn row(w: InsnWire) -> ListingRowItem {
    ListingRowItem {
        address: w.address.0,
        bytes: unhex(&w.bytes),
        mnemonic: w.mnemonic.to_lowercase(),
        operands: w.operands.into_iter().map(operand).collect(),
        comment: w.comment.map(|c| c.0),
        labels: w.labels.into_iter().map(|l| l.0).collect(),
        flow: w.flow,
    }
}

/// The paged listing.
#[derive(Debug, Clone)]
pub struct ListingState {
    /// Function the rows belong to.
    pub function: Option<u64>,
    /// Rows loaded so far, in address order.
    pub rows: Vec<ListingRowItem>,
    /// Cursor of the next page; `None` once everything is loaded.
    pub next_cursor: Option<String>,
    /// A page request is in flight.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// The function changed under the rows (an edit); reload when next drawn.
    pub stale: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// Selected row.
    pub selected: Option<usize>,
    /// Row to scroll into view next frame; take it with [`ListingState::take_scroll`].
    pub scroll_to: Option<usize>,
    /// Address to select as soon as its row is loaded.
    pub pending_focus: Option<u64>,
    /// Keep loading pages until the whole function is in (the graph needs every row).
    pub want_all: bool,
    /// Bumped whenever the rows change; use as a render cache key.
    pub revision: u64,
    /// Instructions per request.
    pub page_size: u32,
    pub(crate) req: u64,
}

impl Default for ListingState {
    fn default() -> Self {
        ListingState {
            function: None,
            rows: Vec::new(),
            next_cursor: None,
            loading: false,
            loaded: false,
            stale: false,
            error: None,
            selected: None,
            scroll_to: None,
            pending_focus: None,
            want_all: false,
            revision: 0,
            page_size: LISTING_PAGE,
            req: 0,
        }
    }
}

impl ListingState {
    /// True when more pages can be fetched.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Row index of the instruction at `addr`.
    pub fn index_of(&self, addr: u64) -> Option<usize> {
        let i = self.rows.partition_point(|r| r.address < addr);
        (self.rows.get(i)?.address == addr).then_some(i)
    }

    /// Row index of the instruction that covers `addr` (the last row at or before it).
    pub fn row_covering(&self, addr: u64) -> Option<usize> {
        let i = self.rows.partition_point(|r| r.address <= addr);
        let row = self.rows.get(i.checked_sub(1)?)?;
        (addr < row.address + row.bytes.len().max(1) as u64).then_some(i - 1)
    }

    /// The selected row.
    pub fn selected_row(&self) -> Option<&ListingRowItem> {
        self.rows.get(self.selected?)
    }

    /// Takes the pending scroll target.
    pub fn take_scroll(&mut self) -> Option<usize> {
        self.scroll_to.take()
    }
}

impl ViewModel {
    /// Loads the listing of the current function when it is missing or out of date.
    pub fn ensure_listing(&mut self) {
        let Some(addr) = self.current.as_ref().map(|c| c.address) else {
            return;
        };
        let l = &self.views.listing;
        let fresh = l.function == Some(addr) && !l.stale;
        if fresh && (l.loaded || l.loading || l.error.is_some()) {
            if l.want_all && l.has_more() && !l.loading {
                self.fetch_listing(false);
            }
            return;
        }
        self.fetch_listing(true);
    }

    /// Loads the next page when the rows on screen get near the end of what is loaded.
    /// `visible_end` is one past the last row on screen.
    pub fn listing_scrolled(&mut self, visible_end: usize) {
        let l = &self.views.listing;
        if l.has_more() && !l.loading && visible_end + 40 >= l.rows.len() {
            self.fetch_listing(false);
        }
    }

    /// Retries after a failed load.
    pub fn retry_listing(&mut self) {
        self.views.listing.error = None;
        self.fetch_listing(true);
    }

    fn fetch_listing(&mut self, reset: bool) {
        let Some(addr) = self.current.as_ref().map(|c| c.address) else {
            return;
        };
        let req = self.views.next_seq();
        let l = &mut self.views.listing;
        let mut args = json!({ "function": hex(addr), "max_instructions": l.page_size });
        if reset {
            l.function = Some(addr);
            l.next_cursor = None;
            l.stale = false;
        } else if l.loading || l.next_cursor.is_none() {
            return;
        } else if let Some(c) = &l.next_cursor {
            args["cursor"] = Value::String(c.clone());
        }
        l.req = req;
        l.loading = true;
        l.error = None;
        self.call("disassemble", args, move |vm, res| {
            if vm.views.listing.req != req {
                return;
            }
            vm.views.listing.loading = false;
            match res.and_then(parse::<Page<InsnWire>>) {
                Ok(page) => vm.apply_listing_page(reset, page),
                Err(e) => vm.views.listing.error = Some(plain_error(&e)),
            }
        });
    }

    fn apply_listing_page(&mut self, reset: bool, page: Page<InsnWire>) {
        let revision = self.views.next_seq();
        let l = &mut self.views.listing;
        let rows: Vec<ListingRowItem> = page.items.into_iter().map(row).collect();
        if reset {
            l.rows = rows;
        } else {
            l.rows.extend(rows);
        }
        l.next_cursor = page.next_cursor;
        l.loaded = true;
        l.revision = revision;
        if reset && l.pending_focus.is_none() {
            let sel = self.views.cursor.and_then(|a| l.row_covering(a));
            l.selected = sel;
        }
        self.resolve_pending_focus();
        let l = &self.views.listing;
        if l.want_all && l.has_more() {
            self.fetch_listing(false);
        }
        self.rebuild_graph();
    }

    fn resolve_pending_focus(&mut self) {
        let l = &mut self.views.listing;
        let Some(addr) = l.pending_focus else { return };
        if let Some(i) = l.row_covering(addr) {
            l.pending_focus = None;
            l.selected = Some(i);
            l.scroll_to = Some(i);
            self.views.cursor = Some(addr);
        } else if l.has_more() {
            if !l.loading {
                self.fetch_listing(false);
            }
        } else if l.loaded {
            l.pending_focus = None;
        }
    }

    /// Selects row `index` and makes its address the cursor.
    pub fn select_listing_row(&mut self, index: usize) {
        let l = &mut self.views.listing;
        let Some(addr) = l.rows.get(index).map(|r| r.address) else {
            return;
        };
        l.selected = Some(index);
        self.views.cursor = Some(addr);
        self.views.graph.selected = self.views.graph.block_containing(addr);
    }

    /// Selects the row at `addr` and scrolls to it, loading more pages if it is further down.
    pub fn listing_focus(&mut self, addr: u64) {
        let l = &mut self.views.listing;
        l.pending_focus = Some(addr);
        if l.loaded {
            self.resolve_pending_focus();
        }
    }

    /// Highlights the listing row a decompiler token points at: the instruction at `target`, or
    /// else the first instruction that refers to it (a call to that function, say). False when
    /// no loaded row matches.
    pub fn sync_listing_to(&mut self, target: u64) -> bool {
        let l = &mut self.views.listing;
        let hit = l
            .index_of(target)
            .or_else(|| l.rows.iter().position(|r| r.refers_to(target)));
        let Some(i) = hit else { return false };
        l.selected = Some(i);
        l.scroll_to = Some(i);
        let addr = l.rows[i].address;
        self.views.cursor = Some(addr);
        self.views.graph.selected = self.views.graph.block_containing(addr);
        true
    }
}

//! Navigation to any address: a function, a spot inside one, or data. Every navigation goes
//! through the back/forward history.

use kraken_proto::ErrorCode;
use serde_json::json;

use super::Reveal;
use super::wire::CfgWire;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// Where an address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    /// The entry of a function.
    Entry(u64),
    /// Inside the body of the function with this entry.
    Inside(u64),
    /// Not known to be in a function yet.
    Unknown,
}

impl ViewModel {
    /// Works out where `addr` is from what is already loaded.
    pub fn place_of(&self, addr: u64) -> Place {
        if self.functions.find(addr).is_some() {
            return Place::Entry(addr);
        }
        if let Some(cur) = &self.current {
            let size = cur.detail.as_ref().and_then(|d| d.size).unwrap_or(0);
            let in_listing = self.views.listing.function == Some(cur.address)
                && self.views.listing.row_covering(addr).is_some();
            if in_listing || (cur.address..cur.address.saturating_add(size)).contains(&addr) {
                return Place::Inside(cur.address);
            }
        }
        if self.functions.filter.is_empty() {
            let items = &self.functions.items;
            let i = items.partition_point(|f| f.address <= addr);
            if let Some(f) = i.checked_sub(1).and_then(|i| items.get(i))
                && let Some(size) = f.size
                && addr < f.address.saturating_add(size)
            {
                return Place::Inside(f.address);
            }
        }
        Place::Unknown
    }

    /// Shows the place at `addr`: a function in the decompiler, a spot inside one in the listing,
    /// data in the hex view. Does not touch the history.
    pub(crate) fn show_place(&mut self, addr: u64) {
        match self.place_of(addr) {
            Place::Entry(entry) => {
                self.show_function(entry);
                self.focus_address(entry);
            }
            Place::Inside(entry) => {
                if self.current.as_ref().map(|c| c.address) != Some(entry) {
                    self.show_function(entry);
                }
                self.focus_address(addr);
            }
            Place::Unknown => self.resolve_place(addr),
        }
    }

    /// Asks the engine which function holds `addr` (the `cfg` command names it).
    fn resolve_place(&mut self, addr: u64) {
        let req = self.views.next_seq();
        self.views.place_req = req;
        self.call("cfg", json!({ "function": hex(addr) }), move |vm, res| {
            if vm.views.place_req != req {
                return;
            }
            match res.and_then(parse::<CfgWire>) {
                Ok(w) => {
                    let entry = w.function.0;
                    if vm.current.as_ref().map(|c| c.address) != Some(entry) {
                        vm.show_function(entry);
                    }
                    vm.focus_address(addr);
                }
                // An engine that cannot tell is treated as before: the address is a function.
                Err(e) if e.code == ErrorCode::Unsupported => {
                    vm.show_function(addr);
                    vm.focus_address(addr);
                }
                Err(_) => vm.show_data(addr),
            }
        });
    }

    /// Points the listing, graph and hex view at `addr` (inside the current function).
    pub(crate) fn focus_address(&mut self, addr: u64) {
        self.views.cursor = Some(addr);
        self.listing_focus(addr);
        self.views.graph.selected = self.views.graph.block_containing(addr);
        let v = &mut self.views;
        if let Some(i) = v.memory.block_index_of(addr) {
            v.hex.block = Some(i);
        }
        v.hex.scroll_to = Some(addr);
    }

    /// Shows data at `addr` in the hex view.
    fn show_data(&mut self, addr: u64) {
        self.views.cursor = Some(addr);
        if self.hex_goto(addr) {
            self.views.reveal = Some(Reveal::Hex);
        } else {
            self.toast(
                ToastLevel::Info,
                format!("Nothing is mapped at {addr:#x}, so there is nothing to show."),
            );
        }
    }

    /// Goes to `addr` (a function, a spot in one, or data) and records it in the history.
    pub fn goto(&mut self, addr: u64) {
        self.navigate_to(addr);
    }

    /// Like [`goto`](Self::goto), then asks the GUI to bring `view` forward.
    pub fn goto_revealing(&mut self, addr: u64, view: Reveal) {
        self.navigate_to(addr);
        self.views.reveal = Some(view);
    }

    /// Lists the references to `addr`: the address under the cursor, else the current function.
    pub fn references_to_cursor(&mut self) {
        let addr = self
            .views
            .cursor
            .or(self.current.as_ref().map(|c| c.address));
        if let Some(a) = addr {
            self.show_references(a, None);
        } else {
            self.toast(
                ToastLevel::Info,
                "Pick a function or an address first, then ask who refers to it.",
            );
        }
    }
}

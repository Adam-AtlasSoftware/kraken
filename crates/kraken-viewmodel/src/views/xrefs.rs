//! Cross-references: callers and callees of the current function, and "references to" any address.

use kraken_proto::{Page, XrefKind};
use serde_json::{Value, json};

use super::Reveal;
use super::wire::{FnRefWire, XrefWire};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// References requested per page.
pub const XREF_PAGE: u32 = 100;

/// A function named by its entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnRef {
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
}

impl From<FnRefWire> for FnRef {
    fn from(w: FnRefWire) -> Self {
        FnRef {
            address: w.address.0,
            name: w.name.0,
        }
    }
}

/// One cross-reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XrefItem {
    /// Where the reference is.
    pub from: u64,
    /// What it points at.
    pub to: u64,
    /// What it does.
    pub kind: XrefKind,
    /// Function holding `from`.
    pub from_function: Option<FnRef>,
    /// Function starting at `to`.
    pub to_function: Option<FnRef>,
}

impl XrefItem {
    /// Plain-language name of the kind.
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            XrefKind::Call => "call",
            XrefKind::Jump => "jump",
            XrefKind::Read => "reads",
            XrefKind::Write => "writes",
            XrefKind::Data => "data",
            XrefKind::Fallthrough => "falls into",
            XrefKind::Other => "other",
        }
    }
}

/// A paged list of references.
#[derive(Debug, Clone, Default)]
pub struct XrefList {
    /// Rows loaded so far, ordered by source address.
    pub items: Vec<XrefItem>,
    /// Cursor of the next page.
    pub next_cursor: Option<String>,
    /// A request is in flight.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// Total when the engine knows it.
    pub total: Option<u64>,
    pub(crate) req: u64,
}

impl XrefList {
    /// True when more pages can be fetched.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// "References to" an address.
#[derive(Debug, Clone, Default)]
pub struct ReferencesTo {
    /// The address (or function entry) looked at.
    pub address: u64,
    /// What it is, for the heading (a function or string, say).
    pub label: String,
    /// The references.
    pub list: XrefList,
    /// Go to the first referencing function once the list arrives.
    pub go_first: bool,
}

/// Which list of the panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefWhich {
    /// Call sites that call the current function.
    Callers,
    /// Calls the current function makes.
    Callees,
    /// References to a chosen address.
    References,
}

/// The Xrefs panel.
#[derive(Debug, Clone, Default)]
pub struct XrefsPanel {
    /// Function the callers and callees belong to.
    pub function: Option<u64>,
    /// Call sites of the function.
    pub callers: XrefList,
    /// Calls the function makes.
    pub callees: XrefList,
    /// "References to" a chosen address.
    pub references: Option<ReferencesTo>,
    /// Reload callers and callees when next drawn.
    pub stale: bool,
}

impl XrefsPanel {
    fn list_mut(&mut self, which: XrefWhich) -> Option<&mut XrefList> {
        match which {
            XrefWhich::Callers => Some(&mut self.callers),
            XrefWhich::Callees => Some(&mut self.callees),
            XrefWhich::References => self.references.as_mut().map(|r| &mut r.list),
        }
    }

    /// The list for `which`.
    pub fn list(&self, which: XrefWhich) -> Option<&XrefList> {
        match which {
            XrefWhich::Callers => Some(&self.callers),
            XrefWhich::Callees => Some(&self.callees),
            XrefWhich::References => self.references.as_ref().map(|r| &r.list),
        }
    }
}

fn item(w: XrefWire) -> XrefItem {
    XrefItem {
        from: w.from.0,
        to: w.to.0,
        kind: w.kind,
        from_function: w.from_function.map(FnRef::from),
        to_function: w.to_function.map(FnRef::from),
    }
}

impl ViewModel {
    /// Loads callers and callees of the current function when missing or out of date.
    pub fn ensure_xrefs(&mut self) {
        let Some(addr) = self.current.as_ref().map(|c| c.address) else {
            return;
        };
        let x = &mut self.views.xrefs;
        if x.function == Some(addr) && !x.stale {
            return;
        }
        x.function = Some(addr);
        x.stale = false;
        self.fetch_xrefs(XrefWhich::Callers, true);
        self.fetch_xrefs(XrefWhich::Callees, true);
    }

    /// Loads the next page of a list.
    pub fn more_xrefs(&mut self, which: XrefWhich) {
        self.fetch_xrefs(which, false);
    }

    /// Shows who references `address`. `label` names it for the heading.
    pub fn show_references(&mut self, address: u64, label: Option<String>) {
        self.open_references(address, label, false);
    }

    /// Like [`show_references`](Self::show_references), then goes to the first function that
    /// references the address once the list arrives (a double-click on a string or import).
    pub fn show_references_and_go(&mut self, address: u64, label: Option<String>) {
        self.open_references(address, label, true);
    }

    fn open_references(&mut self, address: u64, label: Option<String>, go_first: bool) {
        let label = label
            .or_else(|| self.functions.find(address).map(|f| f.name.clone()))
            .unwrap_or_else(|| hex(address));
        self.views.xrefs.references = Some(ReferencesTo {
            address,
            label,
            list: XrefList::default(),
            go_first,
        });
        self.views.reveal = Some(Reveal::Xrefs);
        self.fetch_xrefs(XrefWhich::References, true);
    }

    fn fetch_xrefs(&mut self, which: XrefWhich, reset: bool) {
        let target = match which {
            XrefWhich::Callers | XrefWhich::Callees => self.views.xrefs.function,
            XrefWhich::References => self.views.xrefs.references.as_ref().map(|r| r.address),
        };
        let Some(addr) = target else { return };
        let req = self.views.next_seq();
        let Some(list) = self.views.xrefs.list_mut(which) else {
            return;
        };
        let mut args = json!({ "address": hex(addr), "limit": XREF_PAGE });
        if which == XrefWhich::References {
            args["direction"] = json!("to");
        }
        if reset {
            list.next_cursor = None;
        } else if list.loading || list.next_cursor.is_none() {
            return;
        } else if let Some(c) = &list.next_cursor {
            args["cursor"] = Value::String(c.clone());
        }
        list.req = req;
        list.loading = true;
        list.error = None;
        let command = match which {
            XrefWhich::Callers => "callers",
            XrefWhich::Callees => "callees",
            XrefWhich::References => "xrefs",
        };
        self.call(command, args, move |vm, res| {
            let Some(list) = vm.views.xrefs.list_mut(which).filter(|l| l.req == req) else {
                return;
            };
            list.loading = false;
            match res.and_then(parse::<Page<XrefWire>>) {
                Ok(page) => {
                    let rows: Vec<XrefItem> = page.items.into_iter().map(item).collect();
                    if reset {
                        list.items = rows;
                    } else {
                        list.items.extend(rows);
                    }
                    list.next_cursor = page.next_cursor;
                    list.total = page.total;
                    list.loaded = true;
                    if which == XrefWhich::References {
                        vm.references_arrived();
                    }
                }
                Err(e) => list.error = Some(plain_error(&e)),
            }
        });
    }

    fn references_arrived(&mut self) {
        let Some(r) = self.views.xrefs.references.as_mut().filter(|r| r.go_first) else {
            return;
        };
        r.go_first = false;
        let label = r.label.clone();
        let first = r
            .list
            .items
            .iter()
            .find(|x| x.from_function.is_some())
            .or(r.list.items.first())
            .map(|x| x.from);
        match first {
            Some(from) => self.navigate_to(from),
            None => self.toast(
                ToastLevel::Info,
                format!("Nothing in the analyzed code refers to {label}."),
            ),
        }
    }

    /// Goes to the code a reference row names: the call site for callers and references, the
    /// called function for callees.
    pub fn open_xref(&mut self, which: XrefWhich, index: usize) {
        let Some(x) = self
            .views
            .xrefs
            .list(which)
            .and_then(|l| l.items.get(index))
        else {
            return;
        };
        let target = match which {
            XrefWhich::Callees => x.to,
            XrefWhich::Callers | XrefWhich::References => x.from,
        };
        self.navigate_to(target);
    }
}

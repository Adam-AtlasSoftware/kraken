//! The Strings, Imports and Exports lists: paged, filterable, and linked to cross-references.

use kraken_proto::{Page, StringEncoding, SymbolKind};
use serde_json::{Value, json};

use super::wire::{StringWire, SymbolWire};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::ViewModel;

/// Rows requested per page.
pub const LIST_PAGE: u32 = 200;
/// Shortest string listed.
pub const MIN_STRING_LEN: u32 = 4;

/// A paged list with a filter.
#[derive(Debug, Clone)]
pub struct PagedList<T> {
    /// Rows loaded so far.
    pub items: Vec<T>,
    /// Cursor of the next page; `None` once everything is loaded.
    pub next_cursor: Option<String>,
    /// A request is in flight.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    /// Total when the engine knows it.
    pub total: Option<u64>,
    /// The filter text. For strings the engine applies it; for imports and exports the view
    /// applies it to the rows loaded.
    pub filter: String,
    pub(crate) req: u64,
}

impl<T> Default for PagedList<T> {
    fn default() -> Self {
        PagedList {
            items: Vec::new(),
            next_cursor: None,
            loading: false,
            loaded: false,
            error: None,
            total: None,
            filter: String::new(),
            req: 0,
        }
    }
}

impl<T> PagedList<T> {
    /// True when more pages can be fetched.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

/// A string found in the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringItem {
    /// Address of its first byte.
    pub address: u64,
    /// Its text.
    pub value: String,
    /// The text was cut for display.
    pub truncated: bool,
    /// How it is stored.
    pub encoding: StringEncoding,
    /// Length in bytes.
    pub length: u32,
}

/// An imported or exported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolItem {
    /// Name.
    pub name: String,
    /// Stub address (imports) or definition (exports), if known.
    pub address: Option<u64>,
    /// Library an import comes from.
    pub library: Option<String>,
    /// What it names.
    pub kind: SymbolKind,
}

impl SymbolItem {
    fn matches(&self, needle: &str) -> bool {
        let n = needle.to_lowercase();
        self.name.to_lowercase().contains(&n)
            || self
                .library
                .as_deref()
                .is_some_and(|l| l.to_lowercase().contains(&n))
    }
}

/// Which symbol list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolTable {
    /// Functions and data the program takes from libraries.
    Imports,
    /// Functions and data the program offers.
    Exports,
}

impl SymbolTable {
    fn command(self) -> &'static str {
        match self {
            SymbolTable::Imports => "imports",
            SymbolTable::Exports => "exports",
        }
    }
}

impl PagedList<SymbolItem> {
    /// Indexes of the rows that match the filter.
    pub fn visible(&self) -> Vec<usize> {
        if self.filter.is_empty() {
            return (0..self.items.len()).collect();
        }
        self.items
            .iter()
            .enumerate()
            .filter(|(_, s)| s.matches(&self.filter))
            .map(|(i, _)| i)
            .collect()
    }
}

fn string_item(w: StringWire) -> StringItem {
    StringItem {
        address: w.address.0,
        value: w.value.0,
        truncated: w.truncated,
        encoding: w.encoding,
        length: w.length,
    }
}

fn symbol_item(w: SymbolWire) -> SymbolItem {
    SymbolItem {
        name: w.name.0,
        address: w.address.map(|a| a.0),
        library: w.library.map(|l| l.0),
        kind: w.kind,
    }
}

impl ViewModel {
    fn symbols(&self, table: SymbolTable) -> &PagedList<SymbolItem> {
        match table {
            SymbolTable::Imports => &self.views.imports,
            SymbolTable::Exports => &self.views.exports,
        }
    }

    fn symbols_mut(&mut self, table: SymbolTable) -> &mut PagedList<SymbolItem> {
        match table {
            SymbolTable::Imports => &mut self.views.imports,
            SymbolTable::Exports => &mut self.views.exports,
        }
    }

    // ---------------------------------------------------------------- strings

    /// Loads the first page of strings when nothing was requested yet.
    pub fn ensure_strings(&mut self) {
        let s = &self.views.strings;
        if !s.loaded && !s.loading && s.error.is_none() {
            self.fetch_strings(true);
        }
    }

    /// Sets the text filter (matched case-insensitively by the engine) and reloads.
    pub fn set_strings_filter(&mut self, filter: impl Into<String>) {
        let filter = filter.into();
        if filter == self.views.strings.filter {
            return;
        }
        self.views.strings.filter = filter;
        self.views.strings.error = None;
        self.fetch_strings(true);
    }

    /// Loads the next page when the rows on screen get near the end.
    pub fn strings_scrolled(&mut self, visible_end: usize) {
        let s = &self.views.strings;
        if s.has_more() && !s.loading && visible_end + 30 >= s.items.len() {
            self.fetch_strings(false);
        }
    }

    /// Retries after a failed load.
    pub fn retry_strings(&mut self) {
        self.views.strings.error = None;
        self.fetch_strings(true);
    }

    fn fetch_strings(&mut self, reset: bool) {
        let req = self.views.next_seq();
        let s = &mut self.views.strings;
        let mut args = json!({ "limit": LIST_PAGE, "min_len": MIN_STRING_LEN });
        if !s.filter.is_empty() {
            args["filter"] = Value::String(s.filter.clone());
        }
        if reset {
            s.next_cursor = None;
        } else if s.loading || s.next_cursor.is_none() {
            return;
        } else if let Some(c) = &s.next_cursor {
            args["cursor"] = Value::String(c.clone());
        }
        s.req = req;
        s.loading = true;
        s.error = None;
        self.call("strings", args, move |vm, res| {
            let s = &mut vm.views.strings;
            if s.req != req {
                return;
            }
            s.loading = false;
            match res.and_then(crate::vm::parse::<Page<StringWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(string_item);
                    if reset {
                        s.items = rows.collect();
                    } else {
                        s.items.extend(rows);
                    }
                    s.next_cursor = page.next_cursor;
                    s.total = page.total;
                    s.loaded = true;
                }
                Err(e) => s.error = Some(plain_error(&e)),
            }
        });
    }

    /// Shows who references string `index` and goes to the first function that does.
    pub fn open_string(&mut self, index: usize) {
        let Some(s) = self.views.strings.items.get(index) else {
            return;
        };
        let (address, label) = (s.address, format!("the string \"{}\"", clip(&s.value, 40)));
        self.show_references_and_go(address, Some(label));
    }

    // ---------------------------------------------------------------- imports and exports

    /// Loads the first page of a symbol list when nothing was requested yet. With a filter set it
    /// keeps loading pages until the list is complete, so the filter sees every symbol.
    pub fn ensure_symbols(&mut self, table: SymbolTable) {
        let l = self.symbols(table);
        let first = !l.loaded && !l.loading && l.error.is_none();
        let more = l.loaded && l.has_more() && !l.loading && !l.filter.is_empty();
        if first {
            self.fetch_symbols(table, true);
        } else if more {
            self.fetch_symbols(table, false);
        }
    }

    /// Sets the filter (names and libraries, case-insensitive, applied to loaded rows).
    pub fn set_symbols_filter(&mut self, table: SymbolTable, filter: impl Into<String>) {
        self.symbols_mut(table).filter = filter.into();
    }

    /// Loads the next page when the rows on screen get near the end.
    pub fn symbols_scrolled(&mut self, table: SymbolTable, visible_end: usize) {
        let l = self.symbols(table);
        if l.has_more() && !l.loading && visible_end + 30 >= l.items.len() {
            self.fetch_symbols(table, false);
        }
    }

    /// Retries after a failed load.
    pub fn retry_symbols(&mut self, table: SymbolTable) {
        self.symbols_mut(table).error = None;
        self.fetch_symbols(table, true);
    }

    fn fetch_symbols(&mut self, table: SymbolTable, reset: bool) {
        let req = self.views.next_seq();
        let l = self.symbols_mut(table);
        let mut args = json!({ "limit": LIST_PAGE });
        if reset {
            l.next_cursor = None;
        } else if l.loading || l.next_cursor.is_none() {
            return;
        } else if let Some(c) = &l.next_cursor {
            args["cursor"] = Value::String(c.clone());
        }
        l.req = req;
        l.loading = true;
        l.error = None;
        self.call(table.command(), args, move |vm, res| {
            let l = vm.symbols_mut(table);
            if l.req != req {
                return;
            }
            l.loading = false;
            match res.and_then(crate::vm::parse::<Page<SymbolWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(symbol_item);
                    if reset {
                        l.items = rows.collect();
                    } else {
                        l.items.extend(rows);
                    }
                    l.next_cursor = page.next_cursor;
                    l.total = page.total;
                    l.loaded = true;
                }
                Err(e) => l.error = Some(plain_error(&e)),
            }
        });
    }

    /// Shows who references symbol `index` of a table and goes to the first function that does.
    pub fn open_symbol(&mut self, table: SymbolTable, index: usize) {
        let Some(s) = self.symbols(table).items.get(index) else {
            return;
        };
        let name = s.name.clone();
        match (s.address, table) {
            (Some(address), _) => self.show_references_and_go(address, Some(name)),
            (None, _) => self.toast(
                ToastLevel::Info,
                format!("{name} has no address in this program, so nothing can refer to it."),
            ),
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let head: String = s.chars().take(max).collect();
        format!("{head}...")
    }
}

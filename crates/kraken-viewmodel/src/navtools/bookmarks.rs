//! The Bookmarks tab and the bookmark note dialog.

use kraken_proto::{Hex64, Page, Untrusted};
use serde::Deserialize;
use serde_json::json;

use super::NavTab;
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// Longest note, in characters (matches the registry).
pub const MAX_NOTE: usize = 1000;

/// One bookmark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkItem {
    /// The marked address.
    pub address: u64,
    /// The note, possibly empty.
    pub note: String,
    /// True when an agent set it.
    pub by_agent: bool,
    /// "you" or the agent id.
    pub who: String,
}

/// State of the Bookmarks tab.
#[derive(Debug, Clone, Default)]
pub struct BookmarksPanel {
    /// Bookmarks loaded so far, by address.
    pub items: Vec<BookmarkItem>,
    /// Where the next page starts.
    pub next_cursor: Option<String>,
    /// A call is running.
    pub loading: bool,
    /// The first page arrived.
    pub loaded: bool,
    /// Why the last load failed.
    pub error: Option<String>,
    generation: u64,
}

/// The dialog that asks for a bookmark's note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookmarkDialog {
    /// Address to bookmark.
    pub address: u64,
    /// The note typed so far.
    pub input: String,
    /// A bookmark already exists here (saving replaces its note).
    pub existing: bool,
    /// Why saving failed.
    pub error: Option<String>,
    /// The call is running.
    pub submitting: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct BookmarkWire {
    address: Hex64,
    note: Untrusted<String>,
    author_kind: String,
    author_id: String,
}

impl ViewModel {
    /// Loads the bookmarks once.
    pub fn ensure_bookmarks(&mut self) {
        let b = &self.tools.bookmarks;
        if !b.loaded && !b.loading && b.error.is_none() {
            self.refresh_bookmarks();
        }
    }

    /// Reloads the bookmarks from the first page.
    pub fn refresh_bookmarks(&mut self) {
        self.tools.bookmarks.generation += 1;
        self.tools.bookmarks.next_cursor = None;
        self.fetch_bookmarks(true);
    }

    /// Loads the next page of bookmarks.
    pub fn more_bookmarks(&mut self) {
        let b = &self.tools.bookmarks;
        if !b.loading && b.next_cursor.is_some() {
            self.fetch_bookmarks(false);
        }
    }

    fn fetch_bookmarks(&mut self, reset: bool) {
        let b = &mut self.tools.bookmarks;
        b.loading = true;
        b.error = None;
        let generation = b.generation;
        let mut args = json!({"limit": 200});
        if !reset && let Some(c) = &b.next_cursor {
            args["cursor"] = json!(c);
        }
        self.call("bookmark_list", args, move |vm, res| {
            let b = &mut vm.tools.bookmarks;
            if b.generation != generation {
                return;
            }
            b.loading = false;
            match res.and_then(parse::<Page<BookmarkWire>>) {
                Ok(page) => {
                    let rows = page.items.into_iter().map(|w| BookmarkItem {
                        address: w.address.0,
                        note: w.note.0,
                        by_agent: w.author_kind != "user",
                        who: if w.author_kind == "user" {
                            "you".into()
                        } else {
                            w.author_id
                        },
                    });
                    if reset {
                        b.items = rows.collect();
                    } else {
                        b.items.extend(rows);
                    }
                    b.loaded = true;
                    b.next_cursor = page.next_cursor;
                }
                Err(e) => b.error = Some(plain_error(&e)),
            }
        });
    }

    /// The bookmark at `addr`, when loaded.
    pub fn bookmark_at(&self, addr: u64) -> Option<&BookmarkItem> {
        self.tools
            .bookmarks
            .items
            .iter()
            .find(|b| b.address == addr)
    }

    /// Opens the note dialog for a bookmark at `addr` (prefilled when one exists).
    pub fn begin_bookmark(&mut self, addr: u64) {
        let existing = self.bookmark_at(addr).cloned();
        self.tools.bookmark_dialog = Some(BookmarkDialog {
            address: addr,
            input: existing
                .as_ref()
                .map(|b| b.note.clone())
                .unwrap_or_default(),
            existing: existing.is_some(),
            error: None,
            submitting: false,
        });
    }

    /// Opens the note dialog for the address at the cursor.
    pub fn begin_bookmark_here(&mut self) {
        match self.cursor_address() {
            Some(a) => self.begin_bookmark(a),
            None => self.toast(
                ToastLevel::Info,
                "Pick a function or an address first, then bookmark it.",
            ),
        }
    }

    /// Updates the note being typed.
    pub fn set_bookmark_input(&mut self, text: impl Into<String>) {
        if let Some(d) = self.tools.bookmark_dialog.as_mut() {
            d.input = text.into();
            d.error = None;
        }
    }

    /// Closes the note dialog without saving.
    pub fn cancel_bookmark(&mut self) {
        self.tools.bookmark_dialog = None;
    }

    /// Saves the bookmark.
    pub fn submit_bookmark(&mut self) {
        let Some(d) = self
            .tools
            .bookmark_dialog
            .as_mut()
            .filter(|d| !d.submitting)
        else {
            return;
        };
        if d.input.chars().count() > MAX_NOTE {
            d.error = Some(format!("A note can be at most {MAX_NOTE} characters."));
            return;
        }
        d.submitting = true;
        let addr = d.address;
        let args = json!({"address": hex(addr), "note": d.input.trim()});
        self.call("bookmark_add", args, move |vm, res| match res {
            Ok(_) => {
                vm.tools.bookmark_dialog = None;
                vm.toast(ToastLevel::Success, format!("Bookmarked {}.", hex(addr)));
                vm.refresh_bookmarks();
            }
            Err(e) => {
                if let Some(d) = vm.tools.bookmark_dialog.as_mut() {
                    d.submitting = false;
                    d.error = Some(plain_error(&e));
                }
            }
        });
    }

    /// Removes the bookmark at `addr`.
    pub fn remove_bookmark(&mut self, addr: u64) {
        self.call(
            "bookmark_remove",
            json!({"address": hex(addr)}),
            move |vm, res| match res {
                Ok(_) => {
                    vm.toast(
                        ToastLevel::Info,
                        format!("Removed the bookmark at {}.", hex(addr)),
                    );
                    vm.refresh_bookmarks();
                }
                Err(e) => vm.toast_error(&e),
            },
        );
    }

    /// Shows the Bookmarks tab.
    pub fn show_bookmarks(&mut self) {
        self.ensure_bookmarks();
        self.tools.request_tab(NavTab::Bookmarks);
    }
}

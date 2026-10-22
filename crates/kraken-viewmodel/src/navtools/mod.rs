//! Navigation and editing tools on par with Ghidra and IDA: Go to, Search, Bookmarks, Patches, the
//! Retype / Edit signature / Create and Delete function dialogs, and the generated forms that let
//! the command palette run every registry command.

mod bookmarks;
pub mod ctype;
mod edits;
mod form;
mod patches;
mod search;
mod source_edit;

#[cfg(test)]
mod tests;

pub use bookmarks::{BookmarkDialog, BookmarkItem, BookmarksPanel};
pub use edits::{FunctionDialog, FunctionDialogKind, TypeDialog, TypeMode};
pub use form::{
    CommandForm, CommandResult, FieldKind, FormField, ResultSegment, fields_for_schema,
    result_lines,
};
pub use patches::{
    ExportDialog, ExportDone, MAX_PATCH_BYTES, PatchDialog, PatchItem, PatchOrigin, PatchesPanel,
    RunCompare, RunSide, parse_hex, spaced_hex,
};
pub use search::{SearchHitItem, SearchKind, SearchPanel};
pub use source_edit::{SourceEdit, SourceEditPhase, verdict_text};

use kraken_proto::Page;
use serde_json::json;

use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex, parse};

/// Most suggestions the Go to dialog lists.
pub const GOTO_SUGGESTIONS: usize = 12;

/// A tab the tools want in front; the GUI takes it with [`NavTools::take_tab`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavTab {
    /// The Search tab.
    Search,
    /// The Bookmarks tab.
    Bookmarks,
    /// The History tab.
    History,
    /// The Rewrite tab.
    Rewrite,
    /// The Patches tab.
    Patches,
    /// The Edit tab (patching from edited decompiled code).
    Edit,
}

/// What a Go to suggestion is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotoKind {
    /// A function.
    Function,
    /// An imported symbol.
    Import,
    /// An exported symbol or entry point.
    Export,
    /// A bookmark.
    Bookmark,
}

impl GotoKind {
    /// One word for the suggestion row.
    pub fn word(self) -> &'static str {
        match self {
            GotoKind::Function => "function",
            GotoKind::Import => "import",
            GotoKind::Export => "export",
            GotoKind::Bookmark => "bookmark",
        }
    }
}

/// One completion in the Go to dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotoItem {
    /// The name shown.
    pub name: String,
    /// Where it goes.
    pub address: u64,
    /// What it is.
    pub kind: GotoKind,
}

/// The Go to dialog.
#[derive(Debug, Clone, Default)]
pub struct GotoDialog {
    /// What the person typed.
    pub input: String,
    /// Why the last attempt failed.
    pub error: Option<String>,
    /// Completions, best first.
    pub suggestions: Vec<GotoItem>,
    /// Highlighted completion.
    pub selected: usize,
    /// A lookup in the engine is running.
    pub resolving: bool,
    /// Names the engine found for the current input (beyond what is loaded).
    remote: Vec<GotoItem>,
    seq: u64,
}

/// All state of the navigation and editing tools.
#[derive(Debug, Default)]
pub struct NavTools {
    /// The Go to dialog, when open.
    pub goto: Option<GotoDialog>,
    /// The Search tab.
    pub search: SearchPanel,
    /// The Bookmarks tab.
    pub bookmarks: BookmarksPanel,
    /// The bookmark note dialog, when open.
    pub bookmark_dialog: Option<BookmarkDialog>,
    /// The Patches tab.
    pub patches: PatchesPanel,
    /// The dialog that stages a byte patch, when open.
    pub patch_dialog: Option<PatchDialog>,
    /// The dialog that exports the patched binary, when open.
    pub export_dialog: Option<ExportDialog>,
    /// The Edit tab's function, when one is being edited.
    pub source_edit: Option<SourceEdit>,
    /// The Retype / Edit signature dialog, when open.
    pub type_dialog: Option<TypeDialog>,
    /// The Create / Delete function dialog, when open.
    pub function_dialog: Option<FunctionDialog>,
    /// The generated form of a registry command, when open.
    pub form: Option<CommandForm>,
    /// The result window of the last command run from a form.
    pub result: Option<CommandResult>,
    show_tab: Option<NavTab>,
    seq: u64,
}

impl NavTools {
    /// Takes the request to bring a tab forward.
    pub fn take_tab(&mut self) -> Option<NavTab> {
        self.show_tab.take()
    }

    /// Asks the GUI to bring `tab` forward.
    pub fn request_tab(&mut self, tab: NavTab) {
        self.show_tab = Some(tab);
    }

    pub(crate) fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// True while any of the tools' dialogs is open (single-letter keys are then off).
    pub fn dialog_open(&self) -> bool {
        self.goto.is_some()
            || self.bookmark_dialog.is_some()
            || self.patch_dialog.is_some()
            || self.export_dialog.is_some()
            || self.type_dialog.is_some()
            || self.function_dialog.is_some()
            || self.form.is_some()
    }
}

/// Reads `0x401000`, `401000`, `401000h` as an address.
pub fn parse_address(text: &str) -> Option<u64> {
    let t = text.trim();
    let (digits, explicit) = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))
    {
        (h, true)
    } else if let Some(h) = t.strip_suffix('h').or_else(|| t.strip_suffix('H')) {
        (h, true)
    } else {
        (t, false)
    };
    if digits.is_empty() || digits.len() > 16 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // A bare word such as `add` or `face` is more likely a name than an address.
    if !explicit && !digits.chars().any(|c| c.is_ascii_digit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

const ENTRY_NAMES: &[&str] = &[
    "entry",
    "_start",
    "start",
    "_entry",
    "mainCRTStartup",
    "WinMainCRTStartup",
];

impl ViewModel {
    /// The address the tools act on: the cursor in the views, else the function being read.
    pub fn cursor_address(&self) -> Option<u64> {
        self.views
            .cursor
            .or(self.current.as_ref().map(|c| c.address))
    }

    // ---------------------------------------------------------------- go to

    /// Opens the Go to dialog.
    pub fn open_goto(&mut self) {
        self.ensure_symbols_for_goto();
        self.ensure_bookmarks();
        self.tools.goto = Some(GotoDialog {
            suggestions: self.goto_local("", &[]),
            ..GotoDialog::default()
        });
    }

    /// Closes the Go to dialog.
    pub fn close_goto(&mut self) {
        self.tools.goto = None;
    }

    fn ensure_symbols_for_goto(&mut self) {
        self.ensure_symbols(crate::views::SymbolTable::Imports);
        self.ensure_symbols(crate::views::SymbolTable::Exports);
    }

    /// Updates the typed text and the completions.
    pub fn set_goto_input(&mut self, text: impl Into<String>) {
        let text = text.into();
        let Some(d) = self.tools.goto.as_mut() else {
            return;
        };
        if d.input == text {
            return;
        }
        d.input = text.clone();
        d.error = None;
        d.selected = 0;
        d.remote.clear();
        let remote = d.remote.clone();
        let local = self.goto_local(&text, &remote);
        if let Some(d) = self.tools.goto.as_mut() {
            d.suggestions = local;
        }
        let q = text.trim().to_string();
        if q.chars().count() >= 2 && parse_address(&q).is_none() {
            let seq = self.tools.next_seq();
            if let Some(d) = self.tools.goto.as_mut() {
                d.seq = seq;
            }
            self.call(
                "search",
                json!({"query": q, "kind": "names", "limit": 40}),
                move |vm, res| {
                    let Ok(page) = res.and_then(parse::<Page<search::HitWire>>) else {
                        return;
                    };
                    let Some(d) = vm.tools.goto.as_ref().filter(|d| d.seq == seq) else {
                        return;
                    };
                    let input = d.input.clone();
                    let remote: Vec<GotoItem> = page
                        .items
                        .into_iter()
                        .filter_map(search::goto_item)
                        .collect();
                    let merged = vm.goto_local(&input, &remote);
                    if let Some(d) = vm.tools.goto.as_mut() {
                        d.remote = remote;
                        d.suggestions = merged;
                    }
                },
            );
        }
    }

    /// Moves the highlighted completion.
    pub fn move_goto_selection(&mut self, delta: isize) {
        if let Some(d) = self.tools.goto.as_mut() {
            let n = d.suggestions.len();
            if n > 0 {
                d.selected = (d.selected as isize + delta).rem_euclid(n as isize) as usize;
            }
        }
    }

    /// Names known on this side (functions, imports, exports, bookmarks, plus `remote`) that
    /// match `q`, best first.
    fn goto_local(&self, q: &str, remote: &[GotoItem]) -> Vec<GotoItem> {
        let q = q.trim();
        let mut pool: Vec<GotoItem> = Vec::new();
        pool.extend(self.functions.items.iter().map(|f| GotoItem {
            name: f.name.clone(),
            address: f.address,
            kind: GotoKind::Function,
        }));
        for (list, kind) in [
            (&self.views.imports.items, GotoKind::Import),
            (&self.views.exports.items, GotoKind::Export),
        ] {
            pool.extend(list.iter().filter_map(|s| {
                Some(GotoItem {
                    name: s.name.clone(),
                    address: s.address?,
                    kind,
                })
            }));
        }
        pool.extend(self.tools.bookmarks.items.iter().map(|b| GotoItem {
            name: if b.note.is_empty() {
                hex(b.address)
            } else {
                b.note.clone()
            },
            address: b.address,
            kind: GotoKind::Bookmark,
        }));
        pool.extend(remote.iter().cloned());
        let mut scored: Vec<(i32, usize, GotoItem)> = pool
            .into_iter()
            .enumerate()
            .filter_map(|(i, it)| {
                if q.is_empty() {
                    return Some((0, i, it));
                }
                let exact = it.name.eq_ignore_ascii_case(q);
                crate::fuzzy::score(q, &it.name).map(|s| (s + i32::from(exact) * 1000, i, it))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut out: Vec<GotoItem> = Vec::new();
        for (_, _, it) in scored {
            if !out
                .iter()
                .any(|o| o.address == it.address && o.name == it.name)
            {
                out.push(it);
            }
            if out.len() >= GOTO_SUGGESTIONS {
                break;
            }
        }
        out
    }

    fn exact_name(&self, name: &str) -> Option<u64> {
        let known = self
            .functions
            .items
            .iter()
            .map(|f| (f.name.as_str(), Some(f.address)))
            .chain(
                self.views
                    .exports
                    .items
                    .iter()
                    .chain(self.views.imports.items.iter())
                    .map(|s| (s.name.as_str(), s.address)),
            )
            .chain(
                self.tools
                    .goto
                    .iter()
                    .flat_map(|d| d.remote.iter())
                    .map(|r| (r.name.as_str(), Some(r.address))),
            );
        let mut loose = None;
        for (n, a) in known {
            let Some(a) = a else { continue };
            if n == name {
                return Some(a);
            }
            if loose.is_none() && n.eq_ignore_ascii_case(name) {
                loose = Some(a);
            }
        }
        loose
    }

    /// Jumps to what the dialog names: a name, `entry`, `main` or an address. A name the GUI has
    /// not loaded is looked up in the engine first.
    pub fn submit_goto(&mut self) {
        let Some(d) = self.tools.goto.as_ref() else {
            return;
        };
        let input = d.input.trim().to_string();
        let picked = d.suggestions.get(d.selected).cloned();
        let moved = d.selected > 0;
        if input.is_empty() {
            match picked {
                Some(p) => self.goto_chosen(p.address),
                None => self.goto_error("Type an address such as 0x401000, or a name."),
            }
            return;
        }
        if moved && let Some(p) = picked {
            self.goto_chosen(p.address);
            return;
        }
        let names: Vec<&str> = match input.to_ascii_lowercase().as_str() {
            "entry" | "entry point" => ENTRY_NAMES.to_vec(),
            _ => vec![input.as_str()],
        };
        if let Some(a) = names.iter().find_map(|n| self.exact_name(n)) {
            self.goto_chosen(a);
            return;
        }
        if let Some(a) = parse_address(&input) {
            self.goto_chosen(a);
            return;
        }
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        self.goto_lookup(input, names, picked.map(|p| p.address));
    }

    /// Asks the engine for `wanted` names; jumps to an exact match, else to `fallback`.
    fn goto_lookup(&mut self, input: String, wanted: Vec<String>, fallback: Option<u64>) {
        let query = if wanted.len() > 1 {
            "start"
        } else {
            input.as_str()
        }
        .to_string();
        let seq = self.tools.next_seq();
        if let Some(d) = self.tools.goto.as_mut() {
            d.resolving = true;
            d.seq = seq;
        }
        self.call(
            "search",
            json!({"query": query, "kind": "names", "limit": 200}),
            move |vm, res| {
                if vm.tools.goto.as_ref().is_none_or(|d| d.seq != seq) {
                    return;
                }
                if let Some(d) = vm.tools.goto.as_mut() {
                    d.resolving = false;
                }
                let hits = match res.and_then(parse::<Page<search::HitWire>>) {
                    Ok(p) => p.items,
                    Err(e) => {
                        vm.goto_error(crate::errors::plain_error(&e));
                        return;
                    }
                };
                let found = wanted.iter().find_map(|w| {
                    hits.iter()
                        .find(|h| h.text.0 == *w)
                        .or_else(|| hits.iter().find(|h| h.text.0.eq_ignore_ascii_case(w)))
                        .map(|h| h.address.0)
                });
                match found.or(fallback) {
                    Some(a) => vm.goto_chosen(a),
                    None => vm.goto_error(format!(
                        "Nothing is called \"{input}\". Try part of the name, or an address such as 0x401000."
                    )),
                }
            },
        );
    }

    fn goto_error(&mut self, msg: impl Into<String>) {
        if let Some(d) = self.tools.goto.as_mut() {
            d.error = Some(msg.into());
            d.resolving = false;
        }
    }

    /// Jumps to completion `i`.
    pub fn choose_goto(&mut self, i: usize) {
        let addr = self
            .tools
            .goto
            .as_ref()
            .and_then(|d| d.suggestions.get(i))
            .map(|s| s.address);
        if let Some(a) = addr {
            self.goto_chosen(a);
        }
    }

    fn goto_chosen(&mut self, addr: u64) {
        self.tools.goto = None;
        self.goto(addr);
    }

    // ---------------------------------------------------------------- undo with a toast

    /// Undoes the person's last change and says what it was, with a link to the history.
    pub fn undo_last_described(&mut self) {
        let known: Vec<(u64, String, String)> = self
            .history
            .entries
            .iter()
            .map(|e| (e.id, e.op.clone(), e.description.clone()))
            .collect();
        self.call("undo", json!({}), move |vm, res| {
            let ids: Vec<u64> = res
                .as_ref()
                .ok()
                .and_then(|v| v.get("undone_entry_ids"))
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();
            let what = known
                .iter()
                .find(|(id, _, _)| ids.first() == Some(id))
                .map(|(_, op, d)| describe_change(op, d))
                .unwrap_or_else(|| "your last change".to_string());
            let before = vm.toasts.last().map(|t| t.id);
            vm.undo_done(res, &what);
            // The success toast gets a way to the history.
            if let Some(t) = vm
                .toasts
                .iter_mut()
                .rev()
                .find(|t| Some(t.id) != before && t.level == ToastLevel::Success)
                && t.text.starts_with("Undid")
                && t.action.is_none()
            {
                t.action = Some(crate::state::ToastAction::OpenHistory);
            }
        });
    }
}

/// "the rename of FUN_1 to parse" and friends, from a history row.
fn describe_change(op: &str, description: &str) -> String {
    let words: Vec<&str> = description.split_whitespace().collect();
    match (op, words.as_slice()) {
        ("rename", [_, _, old, "->", new, ..]) => format!("the rename of {old} to {new}"),
        ("set_comment", [_, addr, ..]) => format!("the comment at {addr}"),
        ("set_type", [_, addr, ..]) => format!("the type change at {addr}"),
        ("create_function", [_, addr, ..]) => format!("the new function at {addr}"),
        ("delete_function", [_, addr, ..]) => format!("the deletion of the function at {addr}"),
        (_, [_, addr, ..]) => format!("the {} at {addr}", op.replace('_', " ")),
        _ => format!("your last change ({})", op.replace('_', " ")),
    }
}

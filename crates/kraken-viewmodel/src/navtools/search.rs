//! The Search tab, over the registry's `search` command.

use kraken_proto::{Hex64, Page, Untrusted};
use serde::Deserialize;
use serde_json::json;

use super::{GotoItem, GotoKind, NavTab};
use crate::errors::plain_error;
use crate::views::Reveal;
use crate::vm::{ViewModel, parse};

/// Hits asked for per call.
pub const SEARCH_PAGE: u32 = 100;
/// Calls a search keeps making on its own while it has found fewer than a page of hits.
pub const AUTO_CONTINUE: u32 = 12;

/// What the Search tab looks through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SearchKind {
    /// Function, import and export names.
    #[default]
    Names,
    /// Strings in memory.
    Strings,
    /// A hex byte pattern.
    Bytes,
    /// Instruction text.
    Instructions,
}

impl SearchKind {
    /// Every kind, in the order the tab offers them.
    pub const ALL: [SearchKind; 4] = [
        SearchKind::Names,
        SearchKind::Strings,
        SearchKind::Bytes,
        SearchKind::Instructions,
    ];

    /// The `kind` argument of `search`.
    pub fn wire(self) -> &'static str {
        match self {
            SearchKind::Names => "names",
            SearchKind::Strings => "strings",
            SearchKind::Bytes => "bytes",
            SearchKind::Instructions => "instructions",
        }
    }

    /// Button text.
    pub fn label(self) -> &'static str {
        match self {
            SearchKind::Names => "Names",
            SearchKind::Strings => "Strings",
            SearchKind::Bytes => "Bytes",
            SearchKind::Instructions => "Instructions",
        }
    }

    /// One sentence for the button's tooltip.
    pub fn help(self) -> &'static str {
        match self {
            SearchKind::Names => "Function, import and export names that contain the text",
            SearchKind::Strings => "Text stored inside the program that contains the words",
            SearchKind::Bytes => "Raw bytes in hex, such as 48 8b ?? 05. Each ?? matches any byte",
            SearchKind::Instructions => {
                "Machine instructions whose text contains this, such as xor eax or call"
            }
        }
    }

    /// Example for the empty search box.
    pub fn hint(self) -> &'static str {
        match self {
            SearchKind::Names => "Part of a name, e.g. parse",
            SearchKind::Strings => "Words to find, e.g. password",
            SearchKind::Bytes => "Hex bytes, e.g. 48 8b ?? 05",
            SearchKind::Instructions => "Instruction text, e.g. xor eax",
        }
    }
}

/// One result row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHitItem {
    /// `function`, `import`, `export`, `string`, `bytes` or `instruction`.
    pub kind: String,
    /// Where it is.
    pub address: u64,
    /// What matched.
    pub text: String,
    /// More about it (signature, library, bytes after the match).
    pub context: Option<String>,
    /// Entry of the function it is in.
    pub function: Option<u64>,
    /// Name of that function.
    pub function_name: Option<String>,
}

/// State of the Search tab.
#[derive(Debug, Clone, Default)]
pub struct SearchPanel {
    /// The search box.
    pub query: String,
    /// What to search.
    pub kind: SearchKind,
    /// Results so far.
    pub hits: Vec<SearchHitItem>,
    /// Where the next call resumes; `None` once everything was searched.
    pub next_cursor: Option<String>,
    /// A call is running.
    pub loading: bool,
    /// Why the last call failed.
    pub error: Option<String>,
    /// A search was started (so an empty result means "nothing found").
    pub searched: bool,
    /// The query and kind the results belong to.
    pub ran: Option<(String, SearchKind)>,
    /// The GUI should put the cursor in the search box.
    pub focus_requested: bool,
    generation: u64,
    auto_left: u32,
}

impl SearchPanel {
    /// True when more can be searched.
    pub fn has_more(&self) -> bool {
        self.next_cursor.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HitWire {
    pub kind: String,
    pub address: Hex64,
    pub text: Untrusted<String>,
    #[serde(default)]
    pub context: Option<Untrusted<String>>,
    #[serde(default)]
    pub function: Option<Hex64>,
    #[serde(default)]
    pub function_name: Option<Untrusted<String>>,
}

pub(crate) fn goto_item(h: HitWire) -> Option<GotoItem> {
    let kind = match h.kind.as_str() {
        "function" => GotoKind::Function,
        "import" => GotoKind::Import,
        "export" => GotoKind::Export,
        _ => return None,
    };
    Some(GotoItem {
        name: h.text.0,
        address: h.address.0,
        kind,
    })
}

impl ViewModel {
    /// Shows the Search tab with the cursor in its box.
    pub fn open_search(&mut self) {
        self.tools.search.focus_requested = true;
        self.tools.request_tab(NavTab::Search);
    }

    /// Changes what the Search tab looks through; a finished search runs again.
    pub fn set_search_kind(&mut self, kind: SearchKind) {
        let s = &mut self.tools.search;
        if s.kind == kind {
            return;
        }
        s.kind = kind;
        if s.searched && !s.query.trim().is_empty() {
            self.run_search();
        }
    }

    /// Starts a new search with the query and kind of the tab.
    pub fn run_search(&mut self) {
        let s = &mut self.tools.search;
        s.generation += 1;
        s.hits.clear();
        s.next_cursor = None;
        s.error = None;
        let q = s.query.trim().to_string();
        if q.is_empty() {
            s.searched = false;
            s.loading = false;
            s.error = Some("Type something to search for.".into());
            return;
        }
        s.searched = true;
        s.ran = Some((q, s.kind));
        s.auto_left = AUTO_CONTINUE;
        self.fetch_search();
    }

    /// Searches further from where the last call stopped.
    pub fn search_more(&mut self) {
        let s = &mut self.tools.search;
        if s.loading || s.next_cursor.is_none() {
            return;
        }
        s.auto_left = AUTO_CONTINUE;
        self.fetch_search();
    }

    /// Stops a running search; what was found stays.
    pub fn stop_search(&mut self) {
        let s = &mut self.tools.search;
        s.generation += 1;
        s.loading = false;
    }

    fn fetch_search(&mut self) {
        let s = &mut self.tools.search;
        let Some((q, kind)) = s.ran.clone() else {
            return;
        };
        s.loading = true;
        let generation = s.generation;
        let mut args = json!({"query": q, "kind": kind.wire(), "limit": SEARCH_PAGE});
        if let Some(c) = &s.next_cursor {
            args["cursor"] = json!(c);
        }
        self.call("search", args, move |vm, res| {
            let s = &mut vm.tools.search;
            if s.generation != generation {
                return;
            }
            s.loading = false;
            match res.and_then(parse::<Page<HitWire>>) {
                Ok(page) => {
                    s.hits.extend(page.items.into_iter().map(|h| SearchHitItem {
                        kind: h.kind,
                        address: h.address.0,
                        text: h.text.0,
                        context: h.context.map(|c| c.0),
                        function: h.function.map(|f| f.0),
                        function_name: h.function_name.map(|n| n.0),
                    }));
                    s.next_cursor = page.next_cursor;
                    // Each call scans a bounded amount; keep going while the page is not full.
                    if s.next_cursor.is_some()
                        && s.hits.len() < SEARCH_PAGE as usize
                        && s.auto_left > 0
                    {
                        s.auto_left -= 1;
                        vm.fetch_search();
                    }
                }
                Err(e) => s.error = Some(plain_error(&e)),
            }
        });
    }

    /// Goes to result `i`: a function opens in the decompiler, an instruction in the listing,
    /// data in the hex view.
    pub fn open_search_hit(&mut self, i: usize) {
        let Some(h) = self.tools.search.hits.get(i).cloned() else {
            return;
        };
        match h.kind.as_str() {
            "instruction" => self.goto_revealing(h.address, Reveal::Listing),
            "function" | "export" => self.goto_revealing(h.address, Reveal::Decompiler),
            _ => self.goto(h.address),
        }
    }
}

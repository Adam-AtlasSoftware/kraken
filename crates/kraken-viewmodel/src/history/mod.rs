//! Dependency-aware undo in the History tab (decisions 28, 49, 58, 74): the preview dialog
//! ("Undoing this also undoes 3 later edits that depended on it: ..."), undoing a whole agent run
//! (also with the edits that depended on it), run grouping and the stale-function markers.
//!
//! State lives on [`UndoFlow`] (`vm.undo`); the window only draws it and calls the methods below.

use std::collections::{BTreeMap, BTreeSet};

use kraken_proto::{ErrorCode, Hex64, ProtoError};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::errors::plain_error;
use crate::state::{HistoryEntry, ToastLevel};
use crate::vm::{ViewModel, parse, who};
use crate::wire::HistoryWire;

#[cfg(test)]
mod tests;

/// Most entries of one run previewed (and undone one by one) when the run has dependents.
const RUN_PREVIEW_CAP: usize = 40;
/// Edits named in the dialog's sentence before "and N more".
const NAMED_IN_SUMMARY: usize = 4;

/// What the dialog is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoTarget {
    /// One log entry.
    Entry(u64),
    /// Every live edit of an agent run.
    Run(String),
}

/// A later edit that depended on what is being undone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependentItem {
    /// Entry id.
    pub id: u64,
    /// "you" or the agent's id.
    pub who: String,
    /// True for agent edits.
    pub by_agent: bool,
    /// Operation such as `rename`.
    pub op: String,
    /// One-line description.
    pub description: String,
    /// Agent run it belongs to.
    pub run_id: Option<String>,
    /// Address edited.
    pub address: Option<u64>,
    /// The entity keys it read that the undone edit (or another dependent) wrote.
    pub keys: Vec<String>,
}

/// The undo preview dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoDialog {
    /// What is being undone.
    pub target: UndoTarget,
    /// One line naming it.
    pub headline: String,
    /// Later edits that depended on it, oldest first.
    pub dependents: Vec<DependentItem>,
    /// Functions whose derived data will be marked stale.
    pub stale_functions: Vec<u64>,
    /// The preview is still loading.
    pub loading: bool,
    /// The undo itself is running.
    pub running: bool,
    /// Why something went wrong, plain language.
    pub error: Option<String>,
    /// The person has something to read before confirming; otherwise the undo runs at once.
    pub review: bool,
}

impl UndoDialog {
    /// The dialog should be drawn.
    pub fn visible(&self) -> bool {
        !self.loading && self.review
    }

    /// The sentence at the top of the dialog.
    pub fn summary(&self) -> String {
        let n = self.dependents.len();
        let what = match &self.target {
            UndoTarget::Entry(_) => "this",
            UndoTarget::Run(_) => "this run",
        };
        if n == 0 {
            return format!("Undoing {what} changes nothing else.");
        }
        let named: Vec<String> = self
            .dependents
            .iter()
            .take(NAMED_IN_SUMMARY)
            .map(|d| format!("{} ({})", d.description, d.who))
            .collect();
        let mut list = named.join("; ");
        if n > NAMED_IN_SUMMARY {
            list.push_str(&format!("; and {} more", n - NAMED_IN_SUMMARY));
        }
        format!(
            "Undoing {what} also undoes {n} later edit{} that depended on it: {list}",
            if n == 1 { "" } else { "s" }
        )
    }

    /// Note about derived data, when a type or signature edit is involved.
    pub fn stale_note(&self) -> Option<String> {
        if self.stale_functions.is_empty() {
            return None;
        }
        let list: Vec<String> = self
            .stale_functions
            .iter()
            .take(6)
            .map(|a| format!("{a:#x}"))
            .collect();
        Some(format!(
            "The decompiler output of {} is re-read; anything derived from the old type may be stale until you refresh it.",
            list.join(", ")
        ))
    }

    /// Label of the confirm button.
    pub fn confirm_label(&self) -> &'static str {
        if self.dependents.is_empty() {
            "Undo"
        } else {
            "Undo all"
        }
    }
}

/// A run of consecutive history rows from the same agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryGroup {
    /// The run, when the rows belong to one.
    pub run_id: Option<String>,
    /// Who made the first row.
    pub who: String,
    /// True for agent edits.
    pub by_agent: bool,
    /// Index of the first row in `vm.history.entries`.
    pub first: usize,
    /// Number of rows.
    pub len: usize,
    /// Rows that can still be undone (applied, not undone, not themselves undos).
    pub live: usize,
}

/// Groups consecutive rows of the same agent run; every other row is a group of one.
pub fn group_history(entries: &[HistoryEntry]) -> Vec<HistoryGroup> {
    let mut out: Vec<HistoryGroup> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let live = usize::from(is_live(e));
        let run = e.run_id.as_ref().filter(|_| e.by_agent);
        if let Some(g) = out.last_mut()
            && run.is_some()
            && g.run_id.as_ref() == run
            && g.by_agent
        {
            g.len += 1;
            g.live += live;
            continue;
        }
        out.push(HistoryGroup {
            run_id: run.cloned(),
            who: e.who.clone(),
            by_agent: e.by_agent,
            first: i,
            len: 1,
            live,
        });
    }
    out
}

/// An entry that undo can still act on.
pub fn is_live(e: &HistoryEntry) -> bool {
    e.status == "applied" && !e.undone && !e.is_undo
}

#[derive(Default)]
struct RunPreview {
    run: String,
    ids: Vec<u64>,
    waiting: usize,
    deps: BTreeMap<u64, DependentItem>,
    stale: BTreeSet<u64>,
    failed: Option<String>,
}

/// State of dependency-aware undo and of the stale markers.
#[derive(Default)]
pub struct UndoFlow {
    /// The dialog, while a preview is loading, being reviewed or running.
    pub dialog: Option<UndoDialog>,
    /// Functions whose derived data is stale after an undo.
    pub stale: BTreeSet<u64>,
    seq: u64,
    epoch: u64,
    cleared: BTreeMap<u64, u64>,
    run: Option<RunPreview>,
    queue: Vec<u64>,
    queue_done: usize,
}

impl UndoFlow {
    pub(crate) fn note_stale(&mut self, addrs: &[Hex64]) {
        self.stale.extend(addrs.iter().map(|a| a.0));
    }
}

#[derive(Deserialize)]
struct DependentWire {
    entry: HistoryWire,
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct PreviewWire {
    #[serde(default)]
    dependents: Vec<DependentWire>,
    #[serde(default)]
    stale_functions: Vec<Hex64>,
}

#[derive(Deserialize)]
struct TaintedItemWire {
    address: Hex64,
}

#[derive(Deserialize)]
struct TaintedWire {
    #[serde(default)]
    items: Vec<TaintedItemWire>,
}

fn dependent_item(d: DependentWire) -> DependentItem {
    DependentItem {
        id: d.entry.id,
        who: who(&d.entry.author),
        by_agent: d.entry.author.kind != "user",
        op: d.entry.op,
        description: d.entry.description.0,
        run_id: d.entry.run_id,
        address: d.entry.address.map(|a| a.0),
        keys: d.keys,
    }
}

fn has_dependents(e: &ProtoError) -> bool {
    e.code == ErrorCode::InvalidArgument
        && e.details
            .as_ref()
            .is_some_and(|d| d["reason"] == "has_dependents")
}

impl ViewModel {
    /// Starts undoing log entry `id`: loads the preview, then either asks the person to review
    /// the dependents or undoes it at once when nothing else is affected.
    pub fn request_undo_entry(&mut self, id: u64) {
        self.undo.seq += 1;
        let seq = self.undo.seq;
        self.undo.run = None;
        let headline = self
            .history
            .entries
            .iter()
            .find(|e| e.id == id)
            .map_or_else(|| format!("edit {id}"), |e| e.description.clone());
        self.undo.dialog = Some(UndoDialog {
            target: UndoTarget::Entry(id),
            headline,
            dependents: Vec::new(),
            stale_functions: Vec::new(),
            loading: true,
            running: false,
            error: None,
            review: false,
        });
        self.call("undo_preview", json!({ "entry_id": id }), move |vm, res| {
            if vm.undo.seq != seq {
                return;
            }
            match res.and_then(parse::<PreviewWire>) {
                Ok(p) => vm.preview_ready(
                    p.dependents.into_iter().map(dependent_item).collect(),
                    p.stale_functions.iter().map(|a| a.0).collect(),
                ),
                Err(e) => {
                    vm.undo.dialog = None;
                    vm.toast_error(&e);
                }
            }
        });
    }

    fn preview_ready(&mut self, dependents: Vec<DependentItem>, stale: Vec<u64>) {
        let Some(d) = self.undo.dialog.as_mut() else {
            return;
        };
        d.loading = false;
        d.review = !dependents.is_empty() || !stale.is_empty();
        d.dependents = dependents;
        d.stale_functions = stale;
        if !d.review {
            self.confirm_undo();
        }
    }

    /// Starts undoing every live edit of agent run `run_id`. Edits that depended on the run's
    /// edits are listed first; without any, the whole run is undone at once.
    pub fn request_undo_run(&mut self, run_id: impl Into<String>) {
        let run = run_id.into();
        let ids: Vec<u64> = self
            .history
            .entries
            .iter()
            .filter(|e| is_live(e) && e.run_id.as_deref() == Some(run.as_str()))
            .map(|e| e.id)
            .take(RUN_PREVIEW_CAP)
            .collect();
        if ids.is_empty() {
            self.toast(ToastLevel::Info, "There was nothing to undo.");
            return;
        }
        self.undo.seq += 1;
        let seq = self.undo.seq;
        self.undo.dialog = Some(UndoDialog {
            target: UndoTarget::Run(run.clone()),
            headline: format!("{} edit(s) of run {run}", ids.len()),
            dependents: Vec::new(),
            stale_functions: Vec::new(),
            loading: true,
            running: false,
            error: None,
            review: false,
        });
        self.undo.run = Some(RunPreview {
            run,
            ids: ids.clone(),
            waiting: ids.len(),
            ..RunPreview::default()
        });
        for id in ids {
            self.call("undo_preview", json!({ "entry_id": id }), move |vm, res| {
                if vm.undo.seq != seq {
                    return;
                }
                vm.run_preview_part(res);
            });
        }
    }

    fn run_preview_part(&mut self, res: Result<Value, ProtoError>) {
        let Some(rp) = self.undo.run.as_mut() else {
            return;
        };
        rp.waiting = rp.waiting.saturating_sub(1);
        match res.and_then(parse::<PreviewWire>) {
            Ok(p) => {
                for d in p.dependents {
                    let item = dependent_item(d);
                    rp.deps.entry(item.id).or_insert(item);
                }
                rp.stale.extend(p.stale_functions.iter().map(|a| a.0));
            }
            Err(e) => rp.failed = Some(plain_error(&e)),
        }
        if rp.waiting > 0 {
            return;
        }
        let Some(rp) = self.undo.run.take() else {
            return;
        };
        if let Some(msg) = rp.failed {
            self.undo.dialog = None;
            self.toast(ToastLevel::Error, msg);
            return;
        }
        let outside: Vec<DependentItem> = rp
            .deps
            .into_values()
            .filter(|d| !rp.ids.contains(&d.id))
            .collect();
        let dialog_run = rp.run.clone();
        let Some(d) = self.undo.dialog.as_mut() else {
            return;
        };
        d.loading = false;
        d.review = !outside.is_empty() || !rp.stale.is_empty();
        d.dependents = outside;
        d.stale_functions = rp.stale.into_iter().collect();
        self.undo.run = Some(RunPreview {
            run: dialog_run,
            ids: rp.ids,
            ..RunPreview::default()
        });
        if !self.undo.dialog.as_ref().is_some_and(|d| d.review) {
            self.confirm_undo();
        }
    }

    /// The person confirmed the dialog ("Undo all").
    pub fn confirm_undo(&mut self) {
        let Some(d) = self.undo.dialog.as_mut() else {
            return;
        };
        if d.running {
            return;
        }
        d.running = true;
        d.error = None;
        let target = d.target.clone();
        let cascade = !d.dependents.is_empty();
        let seq = self.undo.seq;
        match target {
            UndoTarget::Entry(id) => {
                let what = if cascade {
                    "that change and what depended on it"
                } else {
                    "that change"
                };
                self.call(
                    "undo_entry",
                    json!({ "entry_id": id, "cascade": cascade }),
                    move |vm, res| {
                        if vm.undo.seq != seq {
                            return;
                        }
                        match res {
                            Err(e) if has_dependents(&e) => vm.dependents_changed(id),
                            res => {
                                vm.undo.dialog = None;
                                vm.undo_done(res, what);
                            }
                        }
                    },
                );
            }
            UndoTarget::Run(run) => {
                if !cascade {
                    self.undo.dialog = None;
                    self.undo_run(run);
                    return;
                }
                self.undo.queue = self
                    .undo
                    .run
                    .as_ref()
                    .map(|r| r.ids.clone())
                    .unwrap_or_default();
                // A stack: the newest id is popped first.
                self.undo.queue.sort_unstable();
                self.undo.queue_done = 0;
                self.undo_queue_step(seq);
            }
        }
    }

    /// More edits depend on the entry than the dialog showed: show the new list.
    fn dependents_changed(&mut self, id: u64) {
        if let Some(d) = self.undo.dialog.as_mut() {
            d.running = false;
            d.error =
                Some("More edits depend on this now. Review the list and confirm again.".into());
        }
        self.undo.seq += 1;
        let seq = self.undo.seq;
        self.call("undo_preview", json!({ "entry_id": id }), move |vm, res| {
            if vm.undo.seq != seq {
                return;
            }
            if let Ok(p) = res.and_then(parse::<PreviewWire>)
                && let Some(d) = vm.undo.dialog.as_mut()
            {
                d.dependents = p.dependents.into_iter().map(dependent_item).collect();
                d.stale_functions = p.stale_functions.iter().map(|a| a.0).collect();
                d.review = true;
            }
        });
    }

    /// Undoes the run's edits one by one, newest first, each with its dependents.
    fn undo_queue_step(&mut self, seq: u64) {
        let Some(id) = self.undo.queue.pop() else {
            let n = self.undo.queue_done;
            self.undo.dialog = None;
            self.undo.run = None;
            self.toast(
                ToastLevel::Success,
                format!(
                    "Undid {n} change{} from the run.",
                    if n == 1 { "" } else { "s" }
                ),
            );
            self.refresh_after_edit();
            return;
        };
        self.call(
            "undo_entry",
            json!({ "entry_id": id, "cascade": true }),
            move |vm, res| {
                if vm.undo.seq != seq {
                    return;
                }
                match res.and_then(parse::<crate::wire::UndoWire>) {
                    Ok(u) => {
                        vm.undo.note_stale(&u.tainted);
                        vm.undo.queue_done += u.undone_entry_ids.len();
                    }
                    // Already undone together with an older edit's dependents.
                    Err(e) if e.code == ErrorCode::InvalidArgument && !has_dependents(&e) => {}
                    Err(e) => {
                        vm.undo.queue.clear();
                        vm.undo.dialog = None;
                        vm.toast_error(&e);
                        vm.refresh_after_edit();
                        return;
                    }
                }
                vm.undo_queue_step(seq);
            },
        );
    }

    /// The person closed the dialog without undoing anything.
    pub fn cancel_undo(&mut self) {
        if self.undo.dialog.as_ref().is_some_and(|d| d.running) {
            return;
        }
        self.undo.seq += 1;
        self.undo.dialog = None;
        self.undo.run = None;
    }

    /// Reloads the list of functions whose derived data is stale. A backend without the command
    /// simply has none.
    pub fn refresh_tainted(&mut self) {
        self.undo.epoch += 1;
        let issued = self.undo.epoch;
        self.call("tainted_list", json!({}), move |vm, res| {
            let Ok(t) = res.and_then(parse::<TaintedWire>) else {
                return;
            };
            let cleared = &vm.undo.cleared;
            vm.undo.stale = t
                .items
                .iter()
                .map(|i| i.address.0)
                .filter(|a| cleared.get(a).is_none_or(|c| *c < issued))
                .collect();
        });
    }

    /// The function at `addr` was decompiled again: its derived data is fresh, so the stale
    /// marker goes away.
    pub(crate) fn note_decompiled(&mut self, addr: u64) {
        if !self.undo.stale.remove(&addr) {
            return;
        }
        self.undo.epoch += 1;
        let at = self.undo.epoch;
        self.undo.cleared.insert(addr, at);
        self.call(
            "tainted_clear",
            json!({ "address": format!("{addr:#x}") }),
            |_, _| {},
        );
    }

    /// The derived data of the function at `addr` is stale after an undo.
    pub fn is_stale(&self, addr: u64) -> bool {
        self.undo.stale.contains(&addr)
    }
}

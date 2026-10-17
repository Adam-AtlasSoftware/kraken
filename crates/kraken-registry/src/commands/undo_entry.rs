//! Dependency-aware undo: `undo_entry`, `undo_preview`, `tainted_list`, `tainted_clear`
//! (decisions 28, 49, 58, 74).

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use kraken_engine::{Cap, SharedEngine};
use kraken_model::{Author, AuthorKind, EntryId, TaintedKey, UndoPlan, UndoPolicy, key_address};
use kraken_proto::{ErrorCode, Hex64, Locator, ProtoError, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::edit::{UndoOut, finish_undo};
use super::rebuild::{DriftEntry, drift_against_log};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{Project, Session};
use crate::views::{HistoryEntryView, locator_parts};

/// Most functions re-read after one undo.
const REFRESH_CAP: usize = 64;

/// Arguments of `undo_entry`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoEntryArgs {
    /// The log entry to undo (see `history`).
    pub entry_id: u64,
    /// Also undo later edits that depend on it. Without this, an entry with dependents is
    /// refused and the error lists them.
    #[serde(default)]
    pub cascade: bool,
}

/// Arguments of `undo_preview`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoPreviewArgs {
    /// The log entry to preview undoing.
    pub entry_id: u64,
}

/// A later edit that depends on the entry being undone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DependentView {
    /// The dependent edit (author, run, command and target address are in it).
    pub entry: HistoryEntryView,
    /// The entity keys it read that were written by the entry or by another dependent.
    pub keys: Vec<String>,
}

/// What `undo_entry` would undo.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UndoPreview {
    /// The entry the caller asked about.
    pub entry: HistoryEntryView,
    /// Later edits depending on it, transitively, oldest first.
    pub dependents: Vec<DependentView>,
    /// Entry ids in the order they would be undone: dependents newest first, then the entry.
    pub undo_order: Vec<u64>,
    /// Functions whose derived data (decompiler output) would be marked stale.
    pub stale_functions: Vec<Hex64>,
}

/// Functions whose derived data is stale because a type or signature edit was undone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaintedFunction {
    /// Function (or item) address.
    pub address: Hex64,
    /// The entity keys marked stale there.
    pub keys: Vec<String>,
    /// The compensating entry that caused the marker.
    pub entry_id: u64,
    /// Why.
    pub reason: String,
    /// When it was marked, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

/// Result of `tainted_list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaintedListOut {
    /// Stale functions, by address.
    pub items: Vec<TaintedFunction>,
}

/// Arguments of `tainted_clear`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaintedClearArgs {
    /// Address whose stale markers to clear after its derived data was refreshed.
    pub address: Hex64,
}

/// Result of `tainted_clear`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaintedClearOut {
    /// Markers removed.
    pub cleared: u64,
}

fn dependent_views(plan: &UndoPlan) -> Vec<DependentView> {
    plan.dependents
        .iter()
        .map(|d| DependentView {
            entry: HistoryEntryView::from(&d.entry),
            keys: d.via_keys.clone(),
        })
        .collect()
}

fn addresses(keys: &[String]) -> Vec<Hex64> {
    let set: BTreeSet<u64> = keys.iter().filter_map(|k| key_address(k)).collect();
    set.into_iter().map(Hex64).collect()
}

fn preview_of(plan: &UndoPlan) -> UndoPreview {
    UndoPreview {
        entry: HistoryEntryView::from(&plan.entry),
        dependents: dependent_views(plan),
        undo_order: plan.order.iter().map(|i| i.0).collect(),
        stale_functions: addresses(&plan.tainted_keys),
    }
}

fn group_tainted(rows: Vec<TaintedKey>) -> Vec<TaintedFunction> {
    let mut by_addr: BTreeMap<u64, TaintedFunction> = BTreeMap::new();
    for r in rows {
        let Some(addr) = key_address(&r.key) else {
            continue;
        };
        let e = by_addr.entry(addr).or_insert_with(|| TaintedFunction {
            address: Hex64(addr),
            keys: Vec::new(),
            entry_id: r.entry_id.0,
            reason: sanitize(&r.reason),
            ts_ms: r.ts_ms,
        });
        e.keys.push(r.key);
        if r.entry_id.0 > e.entry_id {
            e.entry_id = r.entry_id.0;
            e.ts_ms = r.ts_ms;
        }
    }
    by_addr.into_values().collect()
}

/// Functions marked stale by the compensating entries `ids`: re-reads each one through the
/// decompiler (refreshing the engine's cache) and compares the engine with the log. Best effort;
/// nothing here fails the undo.
pub(crate) async fn refresh_after_undo(
    ctx: &CallContext,
    project: &Project,
    ids: &[EntryId],
) -> (Vec<Hex64>, Vec<DriftEntry>) {
    let wanted: BTreeSet<EntryId> = ids.iter().copied().collect();
    let rows = project
        .with_store(|st| st.tainted())
        .await
        .unwrap_or_default();
    let keys: Vec<String> = rows
        .into_iter()
        .filter(|r| wanted.contains(&r.entry_id))
        .map(|r| r.key)
        .collect();
    let tainted = addresses(&keys);
    if tainted.is_empty() {
        return (tainted, Vec::new());
    }
    let engine = project.engine();
    let state = project
        .with_store(|st| st.current_state())
        .await
        .unwrap_or_default();
    let found = reread(&engine, ctx, &tainted).await;
    let drift = drift_against_log(&found, &state);
    (tainted, drift)
}

async fn reread(
    engine: &SharedEngine,
    ctx: &CallContext,
    addrs: &[Hex64],
) -> BTreeMap<(String, u64), kraken_proto::FunctionSummary> {
    let mut out = BTreeMap::new();
    for a in addrs.iter().take(REFRESH_CAP) {
        let loc = Locator::ram(a.0);
        if let Some(d) = engine.decompiler() {
            let _ = d.decompile(&loc, &ctx.cancel).await;
        }
        if let Some(l) = engine.function_lister()
            && let Ok(f) = l.get_function(&loc, &ctx.cancel).await
        {
            let (space, off) = locator_parts(&f.locator);
            out.insert((space, off.0), f);
        }
    }
    out
}

/// An agent may only undo its own edits; people may undo anyone's.
fn check_authority(ctx: &CallContext, plan: &UndoPlan) -> Result<(), ProtoError> {
    if ctx.author.kind == AuthorKind::User {
        return Ok(());
    }
    let foreign: Vec<u64> = plan
        .dependents
        .iter()
        .map(|d| &d.entry)
        .chain([&plan.entry])
        .filter(|e| e.author != ctx.author)
        .map(|e| e.id.0)
        .collect();
    if foreign.is_empty() {
        return Ok(());
    }
    Err(ProtoError::new(
        ErrorCode::RejectedHumanPriority,
        "agents can only undo their own edits",
    )
    .with_details(json!({ "entry_ids": foreign })))
}

fn has_dependents(plan: &UndoPlan) -> ProtoError {
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!(
            "entry {} has {} later edit(s) that depend on it; pass `cascade: true` to undo them \
             too",
            plan.entry.id.0,
            plan.dependents.len()
        ),
    )
    .with_details(json!({
        "reason": "has_dependents",
        "entry_id": plan.entry.id.0,
        "dependents": dependent_views(plan),
    }))
}

/// Undoes one log entry, optionally with the later edits that depend on it.
pub struct UndoEntry;

#[async_trait]
impl Command for UndoEntry {
    type Args = UndoEntryArgs;
    type Output = UndoOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "undo_entry",
            "Undo any log entry, with the later edits that depend on it",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Reverses one edit from `history`, however old. If later edits build on it the call \
             is refused and lists them; pass `cascade: true` to undo those first. Agents can \
             only undo their own edits. Check with `undo_preview` first.\n\
             Example: undo_entry {\"entry_id\": 12, \"cascade\": false}",
        )
        .details(
            "Undoes the entry with a compensating log entry. A later edit depends on it when \
             its read-set names a key the entry wrote (transitively). Without `cascade` an entry \
             with dependents is refused with `invalid_argument` and `details.dependents` \
             (entry, author, command, keys); with it the dependents are undone first, newest \
             first. After undoing a type or signature edit the affected functions are \
             re-decompiled, `drift` reports where the engine disagrees with the log, and \
             `tainted` lists the functions whose derived data is marked stale.",
        )
        .needs(&[Cap::Mutator])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: UndoEntryArgs,
    ) -> Result<UndoOut, ProtoError> {
        let project = s.project()?;
        let _write = project.write_lock.lock().await;
        let id = EntryId(args.entry_id);
        let plan = project.with_store(move |st| st.undo_plan(id)).await?;
        check_authority(ctx, &plan)?;
        if !args.cascade && !plan.dependents.is_empty() {
            return Err(has_dependents(&plan));
        }
        let by: Author = ctx.author.clone();
        let ids = project
            .with_store(move |st| st.undo_with_dependents(id, UndoPolicy::Cascade, &by))
            .await?;
        finish_undo(ctx, &project, ids).await
    }
}

/// Shows what undoing an entry would do.
pub struct UndoPreviewCommand;

#[async_trait]
impl Command for UndoPreviewCommand {
    type Args = UndoPreviewArgs;
    type Output = UndoPreview;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "undo_preview",
            "Show what undoing a log entry would also undo",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Dry run of `undo_entry`: lists the later edits that depend on the entry, the order \
             they would be undone in and the functions that would become stale. Changes \
             nothing. Fails for an entry that is not an applied, not yet undone edit.\n\
             Example: undo_preview {\"entry_id\": 12}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: UndoPreviewArgs,
    ) -> Result<UndoPreview, ProtoError> {
        let project = s.project()?;
        let id = EntryId(args.entry_id);
        let plan = project.with_store(move |st| st.undo_plan(id)).await?;
        Ok(preview_of(&plan))
    }
}

/// Lists functions whose derived data is stale.
pub struct TaintedList;

#[async_trait]
impl Command for TaintedList {
    type Args = super::NoArgs;
    type Output = TaintedListOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "tainted_list",
            "List functions whose derived data is stale after an undo",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Functions whose decompile or explanation may be out of date because a type or \
             signature edit was undone. Re-read them (`decompile`), then `tainted_clear`.\n\
             Example: tainted_list {}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<TaintedListOut, ProtoError> {
        let project = s.project()?;
        let rows = project.with_store(|st| st.tainted()).await?;
        Ok(TaintedListOut {
            items: group_tainted(rows),
        })
    }
}

/// Clears the stale marker of a refreshed function.
pub struct TaintedClear;

#[async_trait]
impl Command for TaintedClear {
    type Args = TaintedClearArgs;
    type Output = TaintedClearOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "tainted_clear",
            "Clear the stale marker of a function after refreshing it",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Marks a function from `tainted_list` as up to date, after you re-read its \
             decompile. Not an annotation edit; it is not logged.\n\
             Example: tainted_clear {\"address\": \"0x401136\"}",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: TaintedClearArgs,
    ) -> Result<TaintedClearOut, ProtoError> {
        let project = s.project()?;
        let _write = project.write_lock.lock().await;
        let n = project
            .with_store(move |st| st.clear_tainted_at(args.address.0))
            .await?;
        Ok(TaintedClearOut { cleared: n as u64 })
    }
}

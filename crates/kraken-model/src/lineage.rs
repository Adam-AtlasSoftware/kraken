//! Dependency-aware undo (decisions 28, 49, 58, 74).
//!
//! Every edit records a read-set: the entity keys (and the versions) it was based on. A later
//! applied edit *depends on* an earlier one when its read-set names a key the earlier one wrote;
//! dependence is transitive through the keys the dependents wrote. Undoing an edit that others
//! depend on either refuses (listing them) or cascades: the dependents are undone first, newest
//! first, then the edit itself. Undoing a type or signature edit marks the affected keys
//! *tainted*: what was derived from them (decompiler output, explanations) is stale, not
//! reversed, until a caller clears the marker after refreshing.

use std::collections::{BTreeMap, BTreeSet};

use kraken_proto::{ErrorCode, LogOp, LogStatus, ProtoError, Provenance, VersionedLogOp};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::keys::{op_key, op_kind_name};
use crate::state::invert_op;
use crate::store::{
    Disposition, Store, bump_version, db, from_json, get_entry, insert_entry, is_undone, kind_str,
    now_ms,
};
use crate::{Author, AuthorKind, EntryDraft, EntryId, LogEntryView};

type Result<T> = std::result::Result<T, ProtoError>;

pub(crate) const MIGRATION: &str = "CREATE TABLE tainted (
        key TEXT PRIMARY KEY,
        entry_id INTEGER NOT NULL REFERENCES entries(id),
        reason TEXT NOT NULL,
        ts INTEGER NOT NULL
    );";

/// What to do when the entry to undo has later edits depending on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoPolicy {
    /// Undo the dependents too, newest first.
    Cascade,
    /// Fail with `invalid_argument` and list the dependents in the error details.
    Refuse,
}

/// A later edit that depends on the entry being undone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependent {
    /// The dependent entry.
    pub entry: LogEntryView,
    /// The keys it read that were written by the entry or by one of the other dependents.
    pub via_keys: Vec<String>,
}

/// What undoing an entry would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoPlan {
    /// The entry the caller wants undone.
    pub entry: LogEntryView,
    /// Later edits depending on it, transitively, oldest first.
    pub dependents: Vec<Dependent>,
    /// Entries in the order they would be undone: dependents newest first, then `entry`.
    pub order: Vec<EntryId>,
    /// Keys that would be marked tainted.
    pub tainted_keys: Vec<String>,
}

/// A key whose derived data is stale because a type or signature edit was undone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedKey {
    /// The entity key.
    pub key: String,
    /// The compensating entry that caused the marker.
    pub entry_id: EntryId,
    /// Why it is stale.
    pub reason: String,
    /// When it was marked, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

/// The address inside an entity key such as `native:ram:0x401000:type`.
pub fn key_address(key: &str) -> Option<u64> {
    let rest = key.strip_prefix("native:")?;
    let (_, rest) = rest.split_once(':')?;
    let hex = rest.split(':').next()?.strip_prefix("0x")?;
    u64::from_str_radix(hex, 16).ok()
}

fn is_type_edit(op: &LogOp) -> bool {
    matches!(
        op,
        LogOp::SetType { .. } | LogOp::SetCallingConvention { .. }
    )
}

fn not_original(id: EntryId) -> ProtoError {
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!("entry {} is not an applied original entry", id.0),
    )
}

/// Later applied, not-yet-undone original entries that depend on `root`, with the keys they
/// depend on. One pass in id order suffices because a dependent is always later than its source.
fn dependents_of(conn: &Connection, root: &LogEntryView) -> Result<Vec<(EntryId, Vec<String>)>> {
    let mut written: BTreeSet<String> = BTreeSet::from([op_key(&root.op.op)?]);
    let mut stmt = conn
        .prepare_cached(
            "SELECT e.id, e.keys, e.read_set FROM entries e
             WHERE e.id > ?1 AND e.status = 'applied' AND e.undoes_entry_id IS NULL
               AND NOT EXISTS (SELECT 1 FROM entries u
                               WHERE u.undoes_entry_id = e.id AND u.status = 'applied')
             ORDER BY e.id",
        )
        .map_err(db)?;
    let rows = stmt
        .query_map([root.id.0 as i64], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    let mut out = Vec::new();
    for (id, keys, read_set) in rows {
        let read: BTreeMap<String, u64> = from_json(&read_set)?;
        let via: Vec<String> = read
            .keys()
            .filter(|k| written.contains(*k))
            .cloned()
            .collect();
        if via.is_empty() {
            continue;
        }
        written.extend(from_json::<Vec<String>>(&keys)?);
        out.push((EntryId(id as u64), via));
    }
    Ok(out)
}

fn plan(conn: &Connection, id: EntryId) -> Result<UndoPlan> {
    let entry = get_entry(conn, id)?;
    if entry.status != LogStatus::Applied || entry.undoes_entry_id.is_some() {
        return Err(not_original(id));
    }
    if is_undone(conn, id.0 as i64)? {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("entry {} is already undone", id.0),
        ));
    }
    let mut dependents = Vec::new();
    for (dep, via_keys) in dependents_of(conn, &entry)? {
        dependents.push(Dependent {
            entry: get_entry(conn, dep)?,
            via_keys,
        });
    }
    let mut order: Vec<EntryId> = dependents.iter().rev().map(|d| d.entry.id).collect();
    order.push(id);
    let mut tainted_keys = BTreeSet::new();
    if is_type_edit(&entry.op.op) {
        tainted_keys.insert(op_key(&entry.op.op)?);
        for d in &dependents {
            tainted_keys.insert(op_key(&d.entry.op.op)?);
        }
    } else {
        for e in dependents.iter().map(|d| &d.entry) {
            if is_type_edit(&e.op.op) {
                tainted_keys.insert(op_key(&e.op.op)?);
            }
        }
    }
    Ok(UndoPlan {
        entry,
        dependents,
        order,
        tainted_keys: tainted_keys.into_iter().collect(),
    })
}

/// Appends compensating entries for `ids` (in the given order) and marks type/signature keys
/// tainted. With `taint_all`, every key the batch writes is tainted when the batch undoes a type
/// edit (the cascade of a type edit: its dependents were derived from it).
pub(crate) fn compensate(
    conn: &Connection,
    ids: &[i64],
    by: &Author,
    taint_all: bool,
) -> Result<Vec<EntryId>> {
    let mut out = Vec::with_capacity(ids.len());
    let mut type_undone = false;
    let mut written: Vec<(String, bool, EntryId)> = Vec::new();
    for &id in ids {
        let orig = get_entry(conn, EntryId(id as u64))?;
        if orig.status != LogStatus::Applied || orig.undoes_entry_id.is_some() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("entry {id} is not an applied original entry"),
            ));
        }
        if is_undone(conn, id)? {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("entry {id} is already undone"),
            ));
        }
        let comp = invert_op(&orig.op.op);
        let key = op_key(&comp)?;
        let draft = EntryDraft {
            op: VersionedLogOp::new(comp),
            author: by.clone(),
            run_id: orig.run_id.clone(),
            provenance: match by.kind {
                AuthorKind::User => Provenance::User,
                AuthorKind::Agent => Provenance::Agent,
            },
            read_set: BTreeMap::new(),
        };
        let new_id = insert_entry(
            conn,
            &draft,
            &key,
            Disposition {
                status: "applied",
                reason: None,
                undoes: Some(orig.id),
            },
        )?;
        bump_version(conn, &key, by.kind)?;
        let typed = is_type_edit(&orig.op.op);
        type_undone |= typed;
        written.push((key, typed, new_id));
        out.push(new_id);
    }
    for (key, typed, entry) in &written {
        if *typed || (taint_all && type_undone) {
            mark_tainted(conn, key, *entry)?;
        }
    }
    Ok(out)
}

fn mark_tainted(conn: &Connection, key: &str, entry: EntryId) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO tainted(key, entry_id, reason, ts) VALUES (?1, ?2, ?3, ?4)",
        params![
            key,
            entry.0 as i64,
            "a type or signature edit was undone; derived data is stale",
            now_ms()
        ],
    )
    .map_err(db)?;
    Ok(())
}

fn has_dependents_error(plan: &UndoPlan) -> ProtoError {
    let list: Vec<_> = plan
        .dependents
        .iter()
        .map(|d| {
            json!({
                "entry_id": d.entry.id.0,
                "op": op_kind_name(&d.entry.op.op),
                "author": { "kind": kind_str(d.entry.author.kind), "id": d.entry.author.id },
                "run_id": d.entry.run_id.as_ref().map(|r| r.0.as_str()),
                "keys": d.via_keys,
            })
        })
        .collect();
    ProtoError::new(
        ErrorCode::InvalidArgument,
        format!(
            "entry {} has {} later edit(s) that depend on it; undo them too or cancel",
            plan.entry.id.0,
            plan.dependents.len()
        ),
    )
    .with_details(json!({
        "reason": "has_dependents",
        "entry_id": plan.entry.id.0,
        "dependents": list,
    }))
}

impl Store {
    /// Later applied, not-yet-undone edits that depend on `id` (their read-set names a key the
    /// entry wrote, or a key one of the dependents wrote), oldest first.
    pub fn lineage(&self, id: EntryId) -> Result<Vec<Dependent>> {
        Ok(plan(&self.conn, id)?.dependents)
    }

    /// What undoing `id` would do, without changing anything.
    pub fn undo_plan(&self, id: EntryId) -> Result<UndoPlan> {
        plan(&self.conn, id)
    }

    /// Undoes any applied original entry, not just the newest. With [`UndoPolicy::Refuse`] and
    /// dependents the call fails with `invalid_argument` and `details.dependents`; with
    /// [`UndoPolicy::Cascade`] the dependents are undone first (newest first), then the entry,
    /// all in one transaction. Returns the compensating entries in creation order. Undoing a
    /// type or signature edit marks the keys it and its dependents wrote as tainted.
    pub fn undo_with_dependents(
        &mut self,
        id: EntryId,
        policy: UndoPolicy,
        by: &Author,
    ) -> Result<Vec<EntryId>> {
        let tx = self.conn.transaction().map_err(db)?;
        let p = plan(&tx, id)?;
        if policy == UndoPolicy::Refuse && !p.dependents.is_empty() {
            return Err(has_dependents_error(&p));
        }
        let ids: Vec<i64> = p.order.iter().map(|i| i.0 as i64).collect();
        let out = compensate(&tx, &ids, by, true)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }

    /// Keys whose derived data is stale.
    pub fn tainted(&self) -> Result<Vec<TaintedKey>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, entry_id, reason, ts FROM tainted ORDER BY key")
            .map_err(db)?;
        stmt.query_map([], |r| {
            Ok(TaintedKey {
                key: r.get(0)?,
                entry_id: EntryId(r.get::<_, i64>(1)? as u64),
                reason: r.get(2)?,
                ts_ms: r.get(3)?,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)
    }

    /// Clears the markers of every key at `address` (the derived data was refreshed). Returns
    /// how many keys were cleared.
    pub fn clear_tainted_at(&mut self, address: u64) -> Result<usize> {
        let keys = self.tainted()?;
        let mut n = 0;
        for k in keys.iter().filter(|k| key_address(&k.key) == Some(address)) {
            n += self
                .conn
                .execute("DELETE FROM tainted WHERE key = ?1", [&k.key])
                .map_err(db)?;
        }
        Ok(n)
    }
}

//! SQLite-backed store: migrations, append with validation, sync, undo, materialisation, history.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use kraken_proto::VersionedLogOp;
use kraken_proto::{ErrorCode, LogStatus, Page, PageRequest, ProtoError, SyncState};
use rusqlite::{Connection, OptionalExtension, ToSql, params};
use serde_json::json;

use crate::keys::op_key;
use crate::state::{AnnotationState, apply_op};
use crate::{
    Author, AuthorKind, EntryDraft, EntryId, HistoryFilter, LogEntryView, RunId, Watermark,
};

type Result<T> = std::result::Result<T, ProtoError>;

const MIGRATIONS: &[&str] = &[
    "CREATE TABLE entries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        op TEXT NOT NULL,
        keys TEXT NOT NULL,
        author_kind TEXT NOT NULL,
        author_id TEXT NOT NULL,
        run_id TEXT,
        provenance TEXT NOT NULL,
        read_set TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('applied','rejected','orphaned')),
        reason TEXT,
        sync TEXT NOT NULL CHECK (sync IN ('pending','pushed','engine_rejected')),
        sync_reason TEXT,
        undoes_entry_id INTEGER REFERENCES entries(id),
        ts INTEGER NOT NULL
    );
    CREATE INDEX entries_run ON entries(run_id);
    CREATE INDEX entries_undoes ON entries(undoes_entry_id);
    CREATE INDEX entries_sync ON entries(sync, status);
    CREATE TABLE runs (
        run_id TEXT PRIMARY KEY,
        author_id TEXT NOT NULL,
        started_ts INTEGER NOT NULL
    );
    CREATE TABLE entity_versions (
        key TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        last_author_kind TEXT NOT NULL CHECK (last_author_kind IN ('user','agent'))
    );
    CREATE TABLE push_watermark (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        last_pushed_entry_id INTEGER NOT NULL,
        engine_checkpoint TEXT NOT NULL
    );
    CREATE TABLE snapshots (
        entry_id INTEGER PRIMARY KEY,
        state TEXT NOT NULL,
        ts INTEGER NOT NULL
    );",
    crate::proposals::MIGRATION,
    crate::lineage::MIGRATION,
    crate::bookmarks::MIGRATION,
    crate::ai_usage::MIGRATION,
    crate::patches::MIGRATION,
];

/// Number of schema migrations this build knows; the version of a fully migrated database.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

const ENTRY_COLS: &str = "e.id, e.op, e.author_kind, e.author_id, e.run_id, e.provenance, \
    e.read_set, e.status, e.reason, e.sync, e.sync_reason, e.undoes_entry_id, e.ts, \
    (SELECT MIN(u.id) FROM entries u WHERE u.undoes_entry_id = e.id AND u.status = 'applied')";

pub(crate) fn db(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, format!("database error: {e}"))
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn kind_str(k: AuthorKind) -> &'static str {
    match k {
        AuthorKind::User => "user",
        AuthorKind::Agent => "agent",
    }
}

pub(crate) fn parse_kind(s: &str) -> Result<AuthorKind> {
    match s {
        "user" => Ok(AuthorKind::User),
        "agent" => Ok(AuthorKind::Agent),
        other => Err(db(format!("bad author kind {other:?}"))),
    }
}

pub(crate) fn to_json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(db)
}

pub(crate) fn from_json<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(db)
}

struct RawEntry {
    id: i64,
    op: String,
    author_kind: String,
    author_id: String,
    run_id: Option<String>,
    provenance: String,
    read_set: String,
    status: String,
    reason: Option<String>,
    sync: String,
    sync_reason: Option<String>,
    undoes: Option<i64>,
    ts: i64,
    undone_by: Option<i64>,
}

impl RawEntry {
    fn read(r: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(RawEntry {
            id: r.get(0)?,
            op: r.get(1)?,
            author_kind: r.get(2)?,
            author_id: r.get(3)?,
            run_id: r.get(4)?,
            provenance: r.get(5)?,
            read_set: r.get(6)?,
            status: r.get(7)?,
            reason: r.get(8)?,
            sync: r.get(9)?,
            sync_reason: r.get(10)?,
            undoes: r.get(11)?,
            ts: r.get(12)?,
            undone_by: r.get(13)?,
        })
    }

    fn into_view(self) -> Result<LogEntryView> {
        let status = match self.status.as_str() {
            "applied" => LogStatus::Applied,
            "rejected" => LogStatus::Rejected {
                reason: self.reason.unwrap_or_default(),
            },
            "orphaned" => LogStatus::Orphaned,
            other => return Err(db(format!("bad status {other:?}"))),
        };
        let sync = match self.sync.as_str() {
            "pending" => SyncState::Pending,
            "pushed" => SyncState::Pushed,
            "engine_rejected" => SyncState::EngineRejected {
                reason: self.sync_reason.unwrap_or_default(),
            },
            other => return Err(db(format!("bad sync state {other:?}"))),
        };
        Ok(LogEntryView {
            id: EntryId(self.id as u64),
            op: from_json(&self.op)?,
            author: Author {
                kind: parse_kind(&self.author_kind)?,
                id: self.author_id,
            },
            run_id: self.run_id.map(RunId),
            provenance: from_json(&self.provenance)?,
            read_set: from_json(&self.read_set)?,
            status,
            sync,
            undoes_entry_id: self.undoes.map(|i| EntryId(i as u64)),
            undone_by: self.undone_by.map(|i| EntryId(i as u64)),
            ts_ms: self.ts,
        })
    }
}

pub(crate) fn query_entries(
    conn: &Connection,
    tail: &str,
    args: &[&dyn ToSql],
) -> Result<Vec<LogEntryView>> {
    let sql = format!("SELECT {ENTRY_COLS} FROM entries e {tail}");
    let mut stmt = conn.prepare_cached(&sql).map_err(db)?;
    let rows = stmt
        .query_map(args, RawEntry::read)
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    rows.into_iter().map(RawEntry::into_view).collect()
}

pub(crate) fn get_entry(conn: &Connection, id: EntryId) -> Result<LogEntryView> {
    let id = id.0 as i64;
    query_entries(conn, "WHERE e.id = ?1", &[&id])?
        .pop()
        .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no log entry {id}")))
}

fn version_info(conn: &Connection, key: &str) -> Result<(u64, Option<AuthorKind>)> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT version, last_author_kind FROM entity_versions WHERE key = ?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    match row {
        None => Ok((0, None)),
        Some((v, k)) => Ok((v as u64, Some(parse_kind(&k)?))),
    }
}

pub(crate) fn bump_version(conn: &Connection, key: &str, kind: AuthorKind) -> Result<()> {
    conn.execute(
        "INSERT INTO entity_versions(key, version, last_author_kind) VALUES (?1, 1, ?2)
         ON CONFLICT(key) DO UPDATE SET version = version + 1,
            last_author_kind = excluded.last_author_kind",
        params![key, kind_str(kind)],
    )
    .map_err(db)?;
    Ok(())
}

fn ensure_run(conn: &Connection, draft: &EntryDraft) -> Result<()> {
    if let Some(run) = &draft.run_id {
        conn.execute(
            "INSERT OR IGNORE INTO runs(run_id, author_id, started_ts) VALUES (?1, ?2, ?3)",
            params![run.0, draft.author.id, now_ms()],
        )
        .map_err(db)?;
    }
    Ok(())
}

pub(crate) struct Disposition<'a> {
    pub(crate) status: &'a str,
    pub(crate) reason: Option<&'a str>,
    pub(crate) undoes: Option<EntryId>,
}

pub(crate) fn insert_entry(
    conn: &Connection,
    draft: &EntryDraft,
    key: &str,
    disp: Disposition<'_>,
) -> Result<EntryId> {
    ensure_run(conn, draft)?;
    conn.execute(
        "INSERT INTO entries(op, keys, author_kind, author_id, run_id, provenance, read_set,
            status, reason, sync, undoes_entry_id, ts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', ?10, ?11)",
        params![
            to_json(&draft.op)?,
            to_json(&[key])?,
            kind_str(draft.author.kind),
            draft.author.id,
            draft.run_id.as_ref().map(|r| r.0.as_str()),
            to_json(&draft.provenance)?,
            to_json(&draft.read_set)?,
            disp.status,
            disp.reason,
            disp.undoes.map(|i| i.0 as i64),
            now_ms(),
        ],
    )
    .map_err(db)?;
    let id = EntryId(conn.last_insert_rowid() as u64);
    if disp.status == "applied" {
        crate::patches::apply_patch_op(conn, &draft.op.op, &draft.author)?;
    }
    Ok(id)
}

fn validate(conn: &Connection, draft: &EntryDraft, key: &str) -> Result<Option<ProtoError>> {
    if draft.author.kind == AuthorKind::Agent {
        let (version, last) = version_info(conn, key)?;
        let read = draft.read_set.get(key).copied().unwrap_or(0);
        if last == Some(AuthorKind::User) && version > read {
            return Ok(Some(
                ProtoError::new(
                    ErrorCode::RejectedHumanPriority,
                    format!("{key} was edited by a user after the agent last read it"),
                )
                .with_details(json!({ "keys": [key], "read": read, "current": version })),
            ));
        }
    }
    let mut stale = Vec::new();
    for (k, expected) in &draft.read_set {
        let (actual, _) = version_info(conn, k)?;
        if actual != *expected {
            stale.push(json!({ "key": k, "expected": expected, "actual": actual }));
        }
    }
    if stale.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        ProtoError::new(
            ErrorCode::ConflictStaleRead,
            format!("{} entities changed since they were read", stale.len()),
        )
        .with_details(json!({ "stale_keys": stale })),
    ))
}

fn fold_applied(conn: &Connection, after: i64, state: &mut AnnotationState) -> Result<()> {
    let mut stmt = conn
        .prepare_cached("SELECT op FROM entries WHERE id > ?1 AND status = 'applied' ORDER BY id")
        .map_err(db)?;
    let ops = stmt
        .query_map([after], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    for json in ops {
        let op: VersionedLogOp = from_json(&json)?;
        op.check_version()?;
        apply_op(state, &op.op);
    }
    Ok(())
}

fn latest_snapshot(conn: &Connection) -> Result<(i64, AnnotationState)> {
    let row: Option<(i64, String)> = conn
        .query_row(
            "SELECT entry_id, state FROM snapshots ORDER BY entry_id DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db)?;
    match row {
        None => Ok((0, AnnotationState::new())),
        Some((id, json)) => Ok((id, from_json(&json)?)),
    }
}

pub(crate) fn is_undone(conn: &Connection, id: i64) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE undoes_entry_id = ?1 AND status = 'applied')",
        [id],
        |r| r.get(0),
    )
    .map_err(db)
}

/// Handle to one project database.
pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// Opens (creating if needed) the database at `path` and runs pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Store> {
        let conn = Connection::open(path).map_err(db)?;
        Self::init(conn)
    }

    /// Opens a private in-memory database; used by tests.
    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(mut conn: Connection) -> Result<Store> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
            .map_err(db)?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")
            .map_err(db)?;
        Self::migrate(&mut conn)?;
        let mut store = Store { conn };
        store.backfill_patch_entries()?;
        Ok(store)
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        let tx = conn.transaction().map_err(db)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            .map_err(db)?;
        let current: u32 = tx
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        if current > SCHEMA_VERSION {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "project database schema {current} is newer than supported {SCHEMA_VERSION}"
                ),
            ));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current as usize) {
            tx.execute_batch(sql).map_err(db)?;
            tx.execute(
                "INSERT INTO schema_version(version) VALUES (?1)",
                [i as u32 + 1],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    /// The migration version this database is at.
    pub fn schema_version(&self) -> Result<u32> {
        self.conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            )
            .map_err(db)
    }

    /// Appends an edit. In one transaction: an agent writing an entity last written by a user
    /// after the version it read is refused with `rejected_human_priority` (decision 34); any
    /// read-set version mismatch is refused with `conflict_stale_read`, listing `stale_keys` in
    /// the details (decision 58); otherwise the entry is stored as applied with sync pending and
    /// the written entity's version is bumped. Refused attempts are stored with status rejected
    /// for audit and the error's details carry `rejected_entry_id`.
    pub fn append(&mut self, draft: EntryDraft) -> Result<EntryId> {
        draft.op.check_version()?;
        let key = op_key(&draft.op.op)?;
        let tx = self.conn.transaction().map_err(db)?;
        if let Some(err) = validate(&tx, &draft, &key)? {
            let id = insert_entry(
                &tx,
                &draft,
                &key,
                Disposition {
                    status: "rejected",
                    reason: Some(&err.message),
                    undoes: None,
                },
            )?;
            tx.commit().map_err(db)?;
            let mut details = err.details.clone().unwrap_or_else(|| json!({}));
            details["rejected_entry_id"] = json!(id.0);
            return Err(err.with_details(details));
        }
        let id = insert_entry(
            &tx,
            &draft,
            &key,
            Disposition {
                status: "applied",
                reason: None,
                undoes: None,
            },
        )?;
        bump_version(&tx, &key, draft.author.kind)?;
        tx.commit().map_err(db)?;
        Ok(id)
    }

    /// Checks `draft` exactly as [`Store::append`] would, without storing anything: an agent
    /// writing an entity a user changed after the agent read it gets `rejected_human_priority`,
    /// any stale read-set version gets `conflict_stale_read`.
    pub fn validate_draft(&self, draft: &EntryDraft) -> Result<()> {
        draft.op.check_version()?;
        let key = op_key(&draft.op.op)?;
        match validate(&self.conn, draft, &key)? {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    /// Current version of an entity key; 0 if never written.
    pub fn entity_version(&self, key: &str) -> Result<u64> {
        Ok(version_info(&self.conn, key)?.0)
    }

    /// All entity versions.
    pub fn entity_versions(&self) -> Result<BTreeMap<String, u64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, version FROM entity_versions")
            .map_err(db)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<BTreeMap<_, _>>>()
            .map_err(db)?;
        Ok(rows)
    }

    /// One entry by id.
    pub fn get_entry(&self, id: EntryId) -> Result<LogEntryView> {
        get_entry(&self.conn, id)
    }

    /// Number of applied, non-compensating agent entries in a run (for the per-run cap, decision 29).
    pub fn count_applied_agent_entries(&self, run: &RunId) -> Result<u64> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM entries WHERE run_id = ?1 AND author_kind = 'agent'
                 AND status = 'applied' AND undoes_entry_id IS NULL",
                [&run.0],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
            .map_err(db)
    }

    /// Applied entries not yet pushed, oldest first.
    pub fn pending_entries(&self) -> Result<Vec<LogEntryView>> {
        query_entries(
            &self.conn,
            "WHERE e.status = 'applied' AND e.sync = 'pending' ORDER BY e.id",
            &[],
        )
    }

    /// Applied entries the engine accepted, oldest first: what an engine must hold to agree with
    /// the log.
    pub fn pushed_entries(&self) -> Result<Vec<LogEntryView>> {
        query_entries(
            &self.conn,
            "WHERE e.status = 'applied' AND e.sync = 'pushed' ORDER BY e.id",
            &[],
        )
    }

    /// Ids of the applied entries that are no longer pending (pushed or refused by the engine).
    pub fn settled_entry_ids(&self) -> Result<Vec<EntryId>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM entries WHERE status = 'applied' AND sync != 'pending' ORDER BY id",
            )
            .map_err(db)?;
        stmt.query_map([], |r| r.get::<_, i64>(0))
            .map_err(db)?
            .map(|r| r.map(|id| EntryId(id as u64)).map_err(db))
            .collect()
    }

    /// Ids of the applied entries the engine accepted, oldest first.
    pub fn pushed_entry_ids(&self) -> Result<Vec<EntryId>> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT id FROM entries WHERE status = 'applied' AND sync = 'pushed' ORDER BY id",
            )
            .map_err(db)?;
        stmt.query_map([], |r| r.get::<_, i64>(0))
            .map_err(db)?
            .map(|r| r.map(|id| EntryId(id as u64)).map_err(db))
            .collect()
    }

    /// Marks an applied entry as pushed to the engine; idempotent.
    pub fn mark_pushed(&mut self, id: EntryId) -> Result<()> {
        self.set_sync(id, "pushed", None)
    }

    /// Marks an applied entry as refused by the engine.
    pub fn mark_engine_rejected(&mut self, id: EntryId, reason: &str) -> Result<()> {
        self.set_sync(id, "engine_rejected", Some(reason))
    }

    fn set_sync(&mut self, id: EntryId, sync: &str, reason: Option<&str>) -> Result<()> {
        let n = self
            .conn
            .execute(
                "UPDATE entries SET sync = ?2, sync_reason = ?3 WHERE id = ?1 AND status = 'applied'",
                params![id.0 as i64, sync, reason],
            )
            .map_err(db)?;
        if n == 0 {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no applied log entry {}", id.0),
            ));
        }
        Ok(())
    }

    /// The saved push watermark, if any.
    pub fn watermark(&self) -> Result<Option<Watermark>> {
        self.conn
            .query_row(
                "SELECT last_pushed_entry_id, engine_checkpoint FROM push_watermark WHERE id = 1",
                [],
                |r| {
                    Ok(Watermark {
                        last_pushed_entry_id: EntryId(r.get::<_, i64>(0)? as u64),
                        engine_checkpoint: r.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(db)
    }

    /// Saves the push watermark (the last pushed entry and the engine checkpoint saved with it).
    pub fn set_watermark(&mut self, last_pushed: EntryId, engine_checkpoint: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO push_watermark(id, last_pushed_entry_id, engine_checkpoint)
                 VALUES (1, ?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET last_pushed_entry_id = excluded.last_pushed_entry_id,
                    engine_checkpoint = excluded.engine_checkpoint",
                params![last_pushed.0 as i64, engine_checkpoint],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Undoes `author`'s most recent applied, not-yet-undone, non-compensating entry.
    /// Returns the compensating entry id; `not_found` if there is nothing to undo.
    pub fn undo_last(&mut self, author: &Author) -> Result<EntryId> {
        let id: Option<i64> = self
            .conn
            .query_row(
                "SELECT e.id FROM entries e
                 WHERE e.status = 'applied' AND e.undoes_entry_id IS NULL
                   AND e.author_kind = ?1 AND e.author_id = ?2
                   AND NOT EXISTS (SELECT 1 FROM entries u
                                   WHERE u.undoes_entry_id = e.id AND u.status = 'applied')
                 ORDER BY e.id DESC LIMIT 1",
                params![kind_str(author.kind), author.id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        let id = id.ok_or_else(|| ProtoError::new(ErrorCode::NotFound, "nothing to undo"))?;
        self.undo_ids(&[id], author)?
            .pop()
            .ok_or_else(|| db("undo produced no entry"))
    }

    /// Undoes one specific entry on behalf of `by`; `invalid_argument` if it is not an applied
    /// original entry or was already undone.
    pub fn undo_entry(&mut self, id: EntryId, by: &Author) -> Result<EntryId> {
        self.undo_ids(&[id.0 as i64], by)?
            .pop()
            .ok_or_else(|| db("undo produced no entry"))
    }

    /// Undoes every applied, not-yet-undone entry of a run, newest first, in one transaction.
    /// Compensating entries are authored by `by`. Returns their ids in creation order; empty when
    /// everything was already undone, `not_found` for an unknown run.
    pub fn undo_run(&mut self, run: &RunId, by: &Author) -> Result<Vec<EntryId>> {
        let known: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE run_id = ?1)",
                [&run.0],
                |r| r.get(0),
            )
            .map_err(db)?;
        if !known {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("unknown run {}", run.0),
            ));
        }
        let mut stmt = self
            .conn
            .prepare(
                "SELECT e.id FROM entries e
                 WHERE e.run_id = ?1 AND e.status = 'applied' AND e.undoes_entry_id IS NULL
                   AND NOT EXISTS (SELECT 1 FROM entries u
                                   WHERE u.undoes_entry_id = e.id AND u.status = 'applied')
                 ORDER BY e.id DESC",
            )
            .map_err(db)?;
        let ids = stmt
            .query_map([&run.0], |r| r.get::<_, i64>(0))
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        drop(stmt);
        self.undo_ids(&ids, by)
    }

    fn undo_ids(&mut self, ids: &[i64], by: &Author) -> Result<Vec<EntryId>> {
        let tx = self.conn.transaction().map_err(db)?;
        let out = crate::lineage::compensate(&tx, ids, by, false)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }

    /// Current annotation state: the latest snapshot plus the applied entries after it.
    pub fn current_state(&self) -> Result<AnnotationState> {
        let (after, mut state) = latest_snapshot(&self.conn)?;
        fold_applied(&self.conn, after, &mut state)?;
        Ok(state)
    }

    /// Current annotation state replayed from the empty state, ignoring snapshots.
    pub fn replay_full(&self) -> Result<AnnotationState> {
        let mut state = AnnotationState::new();
        fold_applied(&self.conn, 0, &mut state)?;
        Ok(state)
    }

    /// Stores the current state as a snapshot at the newest entry id and returns that id;
    /// `None` when the log is empty.
    pub fn create_snapshot(&mut self) -> Result<Option<EntryId>> {
        let last: Option<i64> = self
            .conn
            .query_row("SELECT MAX(id) FROM entries", [], |r| r.get(0))
            .map_err(db)?;
        let Some(last) = last else { return Ok(None) };
        let state = self.current_state()?;
        self.conn
            .execute(
                "INSERT OR REPLACE INTO snapshots(entry_id, state, ts) VALUES (?1, ?2, ?3)",
                params![last, to_json(&state)?, now_ms()],
            )
            .map_err(db)?;
        Ok(Some(EntryId(last as u64)))
    }

    /// Entries newest first, optionally filtered. The cursor is the id of the last entry on the
    /// previous page.
    pub fn history(
        &self,
        page: &PageRequest,
        filter: &HistoryFilter,
    ) -> Result<Page<LogEntryView>> {
        let limit = page.effective_limit();
        let before: Option<i64> = match &page.cursor {
            None => None,
            Some(c) => Some(c.parse().map_err(|_| {
                ProtoError::new(ErrorCode::InvalidArgument, "malformed history cursor")
            })?),
        };
        let run = filter.run_id.as_ref().map(|r| r.0.clone());
        let kind = filter.author.as_ref().map(|a| kind_str(a.kind));
        let author_id = filter.author.as_ref().map(|a| a.id.clone());
        let cond = "(?1 IS NULL OR e.run_id = ?1) AND (?2 IS NULL OR e.author_kind = ?2)
                    AND (?3 IS NULL OR e.author_id = ?3)";
        let total: i64 = self
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM entries e WHERE {cond}"),
                params![run, kind, author_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let mut items = query_entries(
            &self.conn,
            &format!("WHERE {cond} AND (?4 IS NULL OR e.id < ?4) ORDER BY e.id DESC LIMIT ?5"),
            &[&run, &kind, &author_id, &before, &(limit as i64 + 1)],
        )?;
        let next_cursor = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items.last().map(|e| e.id.0.to_string())
        } else {
            None
        };
        Ok(Page {
            items,
            next_cursor,
            total: Some(total as u64),
        })
    }
}

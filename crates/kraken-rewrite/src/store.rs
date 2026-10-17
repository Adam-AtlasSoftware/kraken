//! `<project>/rewrite.sqlite`: everything the rewrite pipeline produces, in a file owned by this
//! crate and separate from the project database (`project.kraken.sqlite`), so the edit log's
//! schema and this one change independently (ADR 0013).
//!
//! Tables (see [`MIGRATIONS`]): `units` (one row per function: status, newest and accepted
//! version), `unit_versions` (one row per translation: code, ABI, provenance, oracle),
//! `test_cases` (the oracle's expected results), `verdicts` (counts and counterexamples),
//! `unit_events` (status transitions), `specs`, and the stored plan (`plan_meta`,
//! `plan_entries`). Versions are append-only; accepting moves a pointer.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use kraken_registry::commands::{PlanFlag, RewriteMode, UnitStatus};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::abi::Signature;
use crate::difftest::{CaseRecord, Counterexample, Verdict};
use crate::error::RewriteError;
use crate::unit::{
    CalleeRef, FunctionAnchor, OracleInfo, Provenance, RewriteUnit, RunSummary, UNIT_SCHEMA,
};

/// File name inside the project directory.
pub const DB_FILE: &str = "rewrite.sqlite";

/// Schema migrations, applied in order; the index plus one is the version number.
pub const MIGRATIONS: &[&str] = &[
    // 1: units, versions, cases, verdicts, events.
    "CREATE TABLE units (
        program_sha256   TEXT NOT NULL,
        address          TEXT NOT NULL,
        name             TEXT NOT NULL,
        mode             TEXT NOT NULL,
        status           TEXT NOT NULL,
        current_version  INTEGER NOT NULL,
        accepted_version INTEGER,
        created_at       INTEGER NOT NULL,
        updated_at       INTEGER NOT NULL,
        PRIMARY KEY (program_sha256, address)
     );
     CREATE TABLE unit_versions (
        id                    TEXT PRIMARY KEY,
        program_sha256        TEXT NOT NULL,
        address               TEXT NOT NULL,
        name                  TEXT NOT NULL,
        space                 TEXT NOT NULL,
        version               INTEGER NOT NULL,
        mode                  TEXT NOT NULL,
        status                TEXT NOT NULL,
        source_decompile_hash TEXT NOT NULL,
        callees_json          TEXT NOT NULL,
        rust_code             TEXT NOT NULL,
        rust_code_hash        TEXT NOT NULL,
        signature_json        TEXT NOT NULL,
        rust_prototype        TEXT NOT NULL,
        oracle_json           TEXT NOT NULL,
        author                TEXT NOT NULL,
        provider              TEXT,
        model                 TEXT,
        task                  TEXT NOT NULL,
        prompt_hash           TEXT NOT NULL,
        created_at            INTEGER NOT NULL,
        UNIQUE (program_sha256, address, version),
        FOREIGN KEY (program_sha256, address) REFERENCES units (program_sha256, address)
     );
     CREATE TABLE test_cases (
        version_id TEXT NOT NULL REFERENCES unit_versions (id),
        ordinal    INTEGER NOT NULL,
        case_json  TEXT NOT NULL,
        PRIMARY KEY (version_id, ordinal)
     );
     CREATE TABLE verdicts (
        version_id             TEXT PRIMARY KEY REFERENCES unit_versions (id),
        verdict                TEXT NOT NULL,
        detail                 TEXT,
        seed                   INTEGER NOT NULL,
        cases_run              INTEGER NOT NULL,
        passed                 INTEGER NOT NULL,
        skipped                INTEGER NOT NULL,
        sandbox                TEXT NOT NULL,
        counterexamples_json   TEXT NOT NULL,
        created_at             INTEGER NOT NULL
     );
     CREATE TABLE unit_events (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        program_sha256 TEXT NOT NULL,
        address        TEXT NOT NULL,
        version        INTEGER NOT NULL,
        from_status    TEXT,
        to_status      TEXT NOT NULL,
        actor          TEXT NOT NULL,
        note           TEXT,
        at             INTEGER NOT NULL
     );",
    // 2: specs and the stored plan; versions remember the spec they were made from.
    "ALTER TABLE unit_versions ADD COLUMN spec_id INTEGER;
     CREATE TABLE specs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        program_sha256 TEXT NOT NULL,
        scope          TEXT NOT NULL,
        address        TEXT,
        markdown       TEXT NOT NULL,
        citations_json TEXT NOT NULL,
        facts          INTEGER NOT NULL,
        functions      INTEGER NOT NULL,
        source_hash    TEXT NOT NULL,
        provider       TEXT NOT NULL,
        model          TEXT NOT NULL,
        prompt_hash    TEXT NOT NULL,
        created_at     INTEGER NOT NULL
     );
     CREATE INDEX specs_by_function ON specs (program_sha256, scope, address, id);
     CREATE TABLE plan_meta (
        program_sha256    TEXT PRIMARY KEY,
        created_at        INTEGER NOT NULL,
        functions_total   INTEGER NOT NULL,
        functions_planned INTEGER NOT NULL,
        skipped_imports   INTEGER NOT NULL,
        skipped_runtime   INTEGER NOT NULL,
        groups            INTEGER NOT NULL,
        truncated         INTEGER NOT NULL
     );
     CREATE TABLE plan_entries (
        program_sha256   TEXT NOT NULL,
        position         INTEGER NOT NULL,
        address          TEXT NOT NULL,
        name             TEXT NOT NULL,
        grp              INTEGER NOT NULL,
        group_size       INTEGER NOT NULL,
        callees_json     TEXT NOT NULL,
        imports_json     TEXT NOT NULL,
        needs_stubs_json TEXT NOT NULL,
        flags_json       TEXT NOT NULL,
        PRIMARY KEY (program_sha256, position)
     );",
];

/// The newest schema version.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

fn db(e: rusqlite::Error) -> RewriteError {
    RewriteError::Store(e.to_string())
}

fn js(e: serde_json::Error) -> RewriteError {
    RewriteError::Store(format!("stored JSON: {e}"))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn mode_of(s: &str) -> RewriteMode {
    if s == "spec" {
        RewriteMode::Spec
    } else {
        RewriteMode::Incremental
    }
}

fn status_of(s: &str) -> Result<UnitStatus, RewriteError> {
    UnitStatus::parse(s).ok_or_else(|| RewriteError::Store(format!("unknown status `{s}`")))
}

fn verdict_parts(v: &Verdict) -> (&'static str, Option<&str>) {
    match v {
        Verdict::Pass => ("pass", None),
        Verdict::Fail => ("fail", None),
        Verdict::Rejected { reason } => ("rejected", Some(reason)),
        Verdict::Inconclusive { reason } => ("inconclusive", Some(reason)),
    }
}

fn verdict_from(kind: &str, detail: Option<String>) -> Result<Verdict, RewriteError> {
    Ok(match kind {
        "pass" => Verdict::Pass,
        "fail" => Verdict::Fail,
        "rejected" => Verdict::Rejected {
            reason: detail.unwrap_or_default(),
        },
        "inconclusive" => Verdict::Inconclusive {
            reason: detail.unwrap_or_default(),
        },
        other => return Err(RewriteError::Store(format!("unknown verdict `{other}`"))),
    })
}

/// One row of the per-function table with the newest version's verdict, for listings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitSummary {
    /// Id of the newest version (`ru-...`).
    pub unit: String,
    /// Entry address, `0x...`.
    pub address: String,
    /// Name when the newest version was made.
    pub name: String,
    /// Mode of the newest version.
    pub mode: RewriteMode,
    /// Status of the function (accepted when a version is accepted).
    pub status: UnitStatus,
    /// Newest version.
    pub version: u32,
    /// Accepted version.
    pub accepted_version: Option<u32>,
    /// Verdict kind of the newest version.
    pub verdict: Option<String>,
    /// Cases run on both sides.
    pub cases_run: u32,
    /// Cases that agreed.
    pub passed: u32,
    /// Counterexamples stored.
    pub counterexamples: u32,
    /// Provider of the newest version.
    pub provider: Option<String>,
    /// Model of the newest version.
    pub model: Option<String>,
}

/// A stored behavioural spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSpec {
    /// Row id.
    pub id: u64,
    /// `function` or `program`.
    pub scope: String,
    /// The function (`0x...`), for `function`.
    pub address: Option<String>,
    /// The Markdown.
    pub markdown: String,
    /// Cited addresses.
    pub citations: Vec<u64>,
    /// Cited facts.
    pub facts: u32,
    /// Functions it was written from.
    pub functions: u32,
    /// SHA-256 of the decompile text it was written from.
    pub source_hash: String,
    /// Provider id.
    pub provider: String,
    /// Model.
    pub model: String,
    /// SHA-256 of the prompt.
    pub prompt_hash: String,
}

/// A spec about to be stored.
#[derive(Debug, Clone)]
pub struct NewSpec {
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// The spec (the id is assigned by the store).
    pub spec: StoredSpec,
}

/// One function of a stored plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedFunction {
    /// Position in the rewrite order.
    pub order: u32,
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Group (strongly connected component) number.
    pub group: u32,
    /// Functions in the group.
    pub group_size: u32,
    /// Internal callees.
    pub callees: Vec<u64>,
    /// Imports called directly.
    pub imports: Vec<String>,
    /// Imports without an oracle stub, directly or through callees.
    pub needs_stubs: Vec<String>,
    /// Flags.
    pub flags: Vec<PlanFlag>,
}

/// A plan with its counters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPlan {
    /// Functions the engine listed.
    pub functions_total: u64,
    /// Import thunks left out.
    pub skipped_imports: u64,
    /// Runtime glue left out.
    pub skipped_runtime: u64,
    /// Groups.
    pub groups: u32,
    /// True when the function cap cut the program short.
    pub truncated: bool,
    /// The functions, in rewrite order.
    pub entries: Vec<PlannedFunction>,
}

/// A handle to one project's `rewrite.sqlite`.
pub struct RewriteStore {
    conn: Mutex<Connection>,
    path: Option<PathBuf>,
}

impl std::fmt::Debug for RewriteStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RewriteStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl RewriteStore {
    /// Opens (creating if needed) the store of a project directory and migrates it.
    pub fn in_project(project_dir: &Path) -> Result<RewriteStore, RewriteError> {
        Self::open(project_dir.join(DB_FILE))
    }

    /// Opens (creating if needed) the database at `path` and runs pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<RewriteStore, RewriteError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path).map_err(db)?;
        Self::init(conn, Some(path))
    }

    /// A private in-memory store, for tests.
    pub fn open_in_memory() -> Result<RewriteStore, RewriteError> {
        Self::init(Connection::open_in_memory().map_err(db)?, None)
    }

    fn init(mut conn: Connection, path: Option<PathBuf>) -> Result<RewriteStore, RewriteError> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(db)?;
        if path.is_some() {
            conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0))
                .map_err(db)?;
        }
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;")
            .map_err(db)?;
        migrate(&mut conn, MIGRATIONS)?;
        Ok(RewriteStore {
            conn: Mutex::new(conn),
            path,
        })
    }

    fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The database file, if it is not in memory.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The migration version the database is at.
    pub fn schema_version(&self) -> Result<u32, RewriteError> {
        current_version(&self.conn())
    }

    /// Stores `unit` as the next version for its function and returns it with that version.
    /// The function's row is created or updated; its status follows the newest version unless a
    /// version is accepted. Older versions stay.
    pub fn put_unit(&self, mut unit: RewriteUnit) -> Result<RewriteUnit, RewriteError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(db)?;
        let prog = unit.anchor.program_sha256.clone();
        let addr = unit.anchor.address.clone();
        let previous: Option<(u32, Option<u32>, String)> = tx
            .query_row(
                "SELECT current_version, accepted_version, status FROM units
                 WHERE program_sha256 = ?1 AND address = ?2",
                params![prog, addr],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        unit.version = previous.as_ref().map_or(0, |p| p.0) + 1;
        let at = now();
        let accepted = previous.as_ref().and_then(|p| p.1);
        let fn_status = if accepted.is_some() {
            UnitStatus::Accepted
        } else {
            unit.status
        };
        if previous.is_some() {
            tx.execute(
                "UPDATE units SET name = ?3, mode = ?4, status = ?5, current_version = ?6,
                        updated_at = ?7
                 WHERE program_sha256 = ?1 AND address = ?2",
                params![
                    prog,
                    addr,
                    unit.anchor.name,
                    unit.mode.as_str(),
                    fn_status.as_str(),
                    unit.version,
                    at
                ],
            )
            .map_err(db)?;
        } else {
            tx.execute(
                "INSERT INTO units (program_sha256, address, name, mode, status, current_version,
                                    created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
                params![
                    prog,
                    addr,
                    unit.anchor.name,
                    unit.mode.as_str(),
                    fn_status.as_str(),
                    unit.version,
                    at
                ],
            )
            .map_err(db)?;
        }
        // The id names the exact (anchor, source, code); a repeat of the same translation is a
        // new version with a suffix, so ids stay unique.
        let same: u32 = tx
            .query_row(
                "SELECT COUNT(*) FROM unit_versions WHERE id = ?1 OR id LIKE ?1 || '.%'",
                params![unit.id],
                |r| r.get(0),
            )
            .map_err(db)?;
        if same > 0 {
            unit.id = format!("{}.{}", unit.id, same + 1);
        }
        tx.execute(
            "INSERT INTO unit_versions (id, program_sha256, address, name, space, version, mode,
                    status, source_decompile_hash, callees_json, rust_code, rust_code_hash,
                    signature_json, rust_prototype, oracle_json, author, provider, model, task,
                    prompt_hash, created_at, spec_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                     ?18, ?19, ?20, ?21, ?22)",
            params![
                unit.id,
                prog,
                addr,
                unit.anchor.name,
                unit.anchor.space,
                unit.version,
                unit.mode.as_str(),
                unit.status.as_str(),
                unit.source_decompile_hash,
                serde_json::to_string(&unit.callees).map_err(js)?,
                unit.rust_code,
                unit.rust_code_hash,
                serde_json::to_string(&unit.signature).map_err(js)?,
                unit.rust_prototype,
                serde_json::to_string(&unit.oracle).map_err(js)?,
                unit.provenance.author,
                unit.provenance.provider,
                unit.provenance.model,
                unit.provenance.task,
                unit.provenance.prompt_hash,
                at,
                unit.spec_id.map(|v| v as i64),
            ],
        )
        .map_err(db)?;
        for (i, case) in unit.test_cases.iter().enumerate() {
            tx.execute(
                "INSERT INTO test_cases (version_id, ordinal, case_json) VALUES (?1, ?2, ?3)",
                params![unit.id, i as i64, serde_json::to_string(case).map_err(js)?],
            )
            .map_err(db)?;
        }
        let (kind, detail) = verdict_parts(&unit.verdict);
        tx.execute(
            "INSERT INTO verdicts (version_id, verdict, detail, seed, cases_run, passed, skipped,
                    sandbox, counterexamples_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                unit.id,
                kind,
                detail,
                unit.summary.seed as i64,
                unit.summary.cases_run as i64,
                unit.summary.passed as i64,
                unit.summary.skipped as i64,
                unit.summary.sandbox,
                serde_json::to_string(&unit.counterexamples).map_err(js)?,
                at
            ],
        )
        .map_err(db)?;
        event(
            &tx,
            &prog,
            &addr,
            unit.version,
            previous.as_ref().map(|p| p.2.as_str()),
            unit.status,
            &unit.provenance.author,
            Some(kind),
        )?;
        tx.commit().map_err(db)?;
        Ok(unit)
    }

    /// The unit version with this id.
    pub fn get(&self, id: &str) -> Result<Option<RewriteUnit>, RewriteError> {
        let conn = self.conn();
        read_unit(&conn, "WHERE v.id = ?1", params![id])
    }

    /// The newest version for the function at `address` (`0x...`).
    pub fn latest(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Option<RewriteUnit>, RewriteError> {
        let conn = self.conn();
        read_unit(
            &conn,
            "WHERE v.program_sha256 = ?1 AND v.address = ?2 ORDER BY v.version DESC LIMIT 1",
            params![program_sha256, address],
        )
    }

    /// The accepted version for the function, if any.
    pub fn accepted(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Option<RewriteUnit>, RewriteError> {
        let conn = self.conn();
        read_unit(
            &conn,
            "WHERE v.program_sha256 = ?1 AND v.address = ?2 AND v.status = 'accepted' LIMIT 1",
            params![program_sha256, address],
        )
    }

    /// Every version of the function, oldest first.
    pub fn versions(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Vec<RewriteUnit>, RewriteError> {
        let conn = self.conn();
        read_units(
            &conn,
            "WHERE v.program_sha256 = ?1 AND v.address = ?2 ORDER BY v.version",
            params![program_sha256, address],
        )
    }

    /// Every accepted unit of the program, by address.
    pub fn accepted_units(&self, program_sha256: &str) -> Result<Vec<RewriteUnit>, RewriteError> {
        let conn = self.conn();
        let mut units = read_units(
            &conn,
            "WHERE v.program_sha256 = ?1 AND v.status = 'accepted'",
            params![program_sha256],
        )?;
        units.sort_by_key(|u| {
            u64::from_str_radix(u.anchor.address.trim_start_matches("0x"), 16).unwrap_or(0)
        });
        Ok(units)
    }

    /// Accepts the version `id` (which must be `verified`). The previously accepted version of
    /// the function goes back to `verified`. Returns the unit and the replaced version number.
    pub fn accept(
        &self,
        id: &str,
        actor: &str,
    ) -> Result<(RewriteUnit, Option<u32>), RewriteError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(db)?;
        let row: Option<(String, String, u32, String)> = tx
            .query_row(
                "SELECT program_sha256, address, version, status FROM unit_versions WHERE id = ?1",
                params![id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(db)?;
        let Some((prog, addr, version, status)) = row else {
            return Err(RewriteError::Store(format!("no rewrite unit `{id}`")));
        };
        let replaced: Option<u32> = tx
            .query_row(
                "SELECT accepted_version FROM units WHERE program_sha256 = ?1 AND address = ?2",
                params![prog, addr],
                |r| r.get(0),
            )
            .map_err(db)?;
        if status == "accepted" {
            return Err(RewriteError::Store(format!(
                "unit `{id}` is already accepted"
            )));
        }
        if status != "verified" {
            return Err(RewriteError::Store(format!(
                "unit `{id}` is {status}; only a verified unit can be accepted"
            )));
        }
        if let Some(old) = replaced {
            tx.execute(
                "UPDATE unit_versions SET status = 'verified'
                 WHERE program_sha256 = ?1 AND address = ?2 AND version = ?3",
                params![prog, addr, old],
            )
            .map_err(db)?;
            event(
                &tx,
                &prog,
                &addr,
                old,
                Some("accepted"),
                UnitStatus::Verified,
                actor,
                Some("replaced by a newer acceptance"),
            )?;
        }
        tx.execute(
            "UPDATE unit_versions SET status = 'accepted' WHERE id = ?1",
            params![id],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE units SET status = 'accepted', accepted_version = ?3, updated_at = ?4
             WHERE program_sha256 = ?1 AND address = ?2",
            params![prog, addr, version, now()],
        )
        .map_err(db)?;
        event(
            &tx,
            &prog,
            &addr,
            version,
            Some("verified"),
            UnitStatus::Accepted,
            actor,
            None,
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        let unit = self
            .get(id)?
            .ok_or_else(|| RewriteError::Store("accepted unit vanished".into()))?;
        Ok((unit, replaced))
    }

    /// When each stored version of the function was written: (version id, seconds since the
    /// Unix epoch), oldest first.
    pub fn created_times(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Vec<(String, i64)>, RewriteError> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT id, created_at FROM unit_versions
                 WHERE program_sha256 = ?1 AND address = ?2 ORDER BY version",
            )
            .map_err(db)?;
        st.query_map(params![program_sha256, address], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)
    }

    /// Status transitions of a function, oldest first: (version, from, to, actor, note).
    #[allow(clippy::type_complexity)]
    pub fn events(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Vec<(u32, Option<String>, String, String, Option<String>)>, RewriteError> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT version, from_status, to_status, actor, note FROM unit_events
                 WHERE program_sha256 = ?1 AND address = ?2 ORDER BY id",
            )
            .map_err(db)?;
        let rows = st
            .query_map(params![program_sha256, address], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        Ok(rows)
    }

    /// One summary per function that has a unit, by address.
    pub fn summaries(&self, program_sha256: &str) -> Result<Vec<UnitSummary>, RewriteError> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT u.address, u.name, u.mode, u.status, u.current_version, u.accepted_version,
                        d.verdict, d.cases_run, d.passed, d.counterexamples_json,
                        v.provider, v.model, v.id
                 FROM units u
                 JOIN unit_versions v ON v.program_sha256 = u.program_sha256
                      AND v.address = u.address AND v.version = u.current_version
                 JOIN verdicts d ON d.version_id = v.id
                 WHERE u.program_sha256 = ?1",
            )
            .map_err(db)?;
        let mut rows = st
            .query_map(params![program_sha256], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, u32>(4)?,
                    r.get::<_, Option<u32>>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, u32>(7)?,
                    r.get::<_, u32>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, String>(12)?,
                ))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?
            .into_iter()
            .map(
                |(
                    address,
                    name,
                    mode,
                    status,
                    version,
                    accepted_version,
                    verdict,
                    cases_run,
                    passed,
                    cx,
                    provider,
                    model,
                    unit,
                )| {
                    let counterexamples = serde_json::from_str::<Vec<serde_json::Value>>(&cx)
                        .map_or(0, |v| u32::try_from(v.len()).unwrap_or(u32::MAX));
                    Ok(UnitSummary {
                        unit,
                        address,
                        name,
                        mode: mode_of(&mode),
                        status: status_of(&status)?,
                        version,
                        accepted_version,
                        verdict: Some(verdict),
                        cases_run,
                        passed,
                        counterexamples,
                        provider,
                        model,
                    })
                },
            )
            .collect::<Result<Vec<_>, RewriteError>>()?;
        rows.sort_by_key(|u| {
            u64::from_str_radix(u.address.trim_start_matches("0x"), 16).unwrap_or(0)
        });
        Ok(rows)
    }

    /// Stores a spec and returns its id.
    pub fn put_spec(&self, new: NewSpec) -> Result<u64, RewriteError> {
        let conn = self.conn();
        let s = &new.spec;
        conn.execute(
            "INSERT INTO specs (program_sha256, scope, address, markdown, citations_json, facts,
                    functions, source_hash, provider, model, prompt_hash, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                new.program_sha256,
                s.scope,
                s.address,
                s.markdown,
                serde_json::to_string(&s.citations).map_err(js)?,
                s.facts,
                s.functions,
                s.source_hash,
                s.provider,
                s.model,
                s.prompt_hash,
                now()
            ],
        )
        .map_err(db)?;
        u64::try_from(conn.last_insert_rowid())
            .map_err(|_| RewriteError::Store("bad spec row id".into()))
    }

    /// The newest spec for a function (`Some(address)`) or for the program (`None`).
    pub fn latest_spec(
        &self,
        program_sha256: &str,
        address: Option<&str>,
    ) -> Result<Option<StoredSpec>, RewriteError> {
        let conn = self.conn();
        let sql = "SELECT id, scope, address, markdown, citations_json, facts, functions,
                          source_hash, provider, model, prompt_hash FROM specs
                   WHERE program_sha256 = ?1 AND scope = ?2 AND address IS ?3
                   ORDER BY id DESC LIMIT 1";
        let scope = if address.is_some() {
            "function"
        } else {
            "program"
        };
        let row = conn
            .query_row(sql, params![program_sha256, scope, address], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, u32>(5)?,
                    r.get::<_, u32>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                ))
            })
            .optional()
            .map_err(db)?;
        row.map(
            |(
                id,
                scope,
                address,
                markdown,
                cit,
                facts,
                functions,
                source_hash,
                provider,
                model,
                prompt_hash,
            )| {
                Ok(StoredSpec {
                    id: id as u64,
                    scope,
                    address,
                    markdown,
                    citations: serde_json::from_str(&cit).map_err(js)?,
                    facts,
                    functions,
                    source_hash,
                    provider,
                    model,
                    prompt_hash,
                })
            },
        )
        .transpose()
    }

    /// A spec by id.
    pub fn spec(&self, id: u64) -> Result<Option<StoredSpec>, RewriteError> {
        let conn = self.conn();
        let row = conn
            .query_row(
                "SELECT scope, address, markdown, citations_json, facts, functions, source_hash,
                        provider, model, prompt_hash FROM specs WHERE id = ?1",
                params![id as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, u32>(4)?,
                        r.get::<_, u32>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                        r.get::<_, String>(8)?,
                        r.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        row.map(
            |(
                scope,
                address,
                markdown,
                cit,
                facts,
                functions,
                source_hash,
                provider,
                model,
                prompt_hash,
            )| {
                Ok(StoredSpec {
                    id,
                    scope,
                    address,
                    markdown,
                    citations: serde_json::from_str(&cit).map_err(js)?,
                    facts,
                    functions,
                    source_hash,
                    provider,
                    model,
                    prompt_hash,
                })
            },
        )
        .transpose()
    }

    /// Replaces the stored plan of the program.
    pub fn save_plan(&self, program_sha256: &str, plan: &StoredPlan) -> Result<(), RewriteError> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(db)?;
        tx.execute(
            "DELETE FROM plan_entries WHERE program_sha256 = ?1",
            params![program_sha256],
        )
        .map_err(db)?;
        tx.execute(
            "INSERT OR REPLACE INTO plan_meta (program_sha256, created_at, functions_total,
                    functions_planned, skipped_imports, skipped_runtime, groups, truncated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                program_sha256,
                now(),
                plan.functions_total as i64,
                plan.entries.len() as i64,
                plan.skipped_imports as i64,
                plan.skipped_runtime as i64,
                plan.groups,
                plan.truncated
            ],
        )
        .map_err(db)?;
        for e in &plan.entries {
            tx.execute(
                "INSERT INTO plan_entries (program_sha256, position, address, name, grp,
                        group_size, callees_json, imports_json, needs_stubs_json, flags_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    program_sha256,
                    e.order,
                    format!("{:#x}", e.address),
                    e.name,
                    e.group,
                    e.group_size,
                    serde_json::to_string(&e.callees).map_err(js)?,
                    serde_json::to_string(&e.imports).map_err(js)?,
                    serde_json::to_string(&e.needs_stubs).map_err(js)?,
                    serde_json::to_string(&e.flags).map_err(js)?,
                ],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    /// The stored plan, if any.
    pub fn plan(&self, program_sha256: &str) -> Result<Option<StoredPlan>, RewriteError> {
        let conn = self.conn();
        let meta = conn
            .query_row(
                "SELECT functions_total, skipped_imports, skipped_runtime, groups, truncated
                 FROM plan_meta WHERE program_sha256 = ?1",
                params![program_sha256],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, u32>(3)?,
                        r.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(db)?;
        let Some((total, imports, runtime, groups, truncated)) = meta else {
            return Ok(None);
        };
        let mut st = conn
            .prepare(
                "SELECT position, address, name, grp, group_size, callees_json, imports_json,
                        needs_stubs_json, flags_json FROM plan_entries
                 WHERE program_sha256 = ?1 ORDER BY position",
            )
            .map_err(db)?;
        let raw = st
            .query_map(params![program_sha256], |r| {
                Ok((
                    r.get::<_, u32>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, u32>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                ))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        let mut entries = Vec::with_capacity(raw.len());
        for (order, addr, name, group, group_size, callees, imports, stubs, flags) in raw {
            entries.push(PlannedFunction {
                order,
                address: u64::from_str_radix(addr.trim_start_matches("0x"), 16)
                    .map_err(|e| RewriteError::Store(format!("plan address: {e}")))?,
                name,
                group,
                group_size,
                callees: serde_json::from_str(&callees).map_err(js)?,
                imports: serde_json::from_str(&imports).map_err(js)?,
                needs_stubs: serde_json::from_str(&stubs).map_err(js)?,
                flags: serde_json::from_str(&flags).map_err(js)?,
            });
        }
        Ok(Some(StoredPlan {
            functions_total: u64::try_from(total).unwrap_or(0),
            skipped_imports: u64::try_from(imports).unwrap_or(0),
            skipped_runtime: u64::try_from(runtime).unwrap_or(0),
            groups,
            truncated,
            entries,
        }))
    }
}

#[allow(clippy::too_many_arguments)]
fn event(
    tx: &rusqlite::Transaction<'_>,
    prog: &str,
    addr: &str,
    version: u32,
    from: Option<&str>,
    to: UnitStatus,
    actor: &str,
    note: Option<&str>,
) -> Result<(), RewriteError> {
    tx.execute(
        "INSERT INTO unit_events (program_sha256, address, version, from_status, to_status, actor,
                note, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![prog, addr, version, from, to.as_str(), actor, note, now()],
    )
    .map_err(db)?;
    Ok(())
}

fn current_version(conn: &Connection) -> Result<u32, RewriteError> {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |r| r.get(0),
    )
    .map_err(db)
}

/// Applies the migrations after the database's current version, in one transaction. A database
/// from a newer build is refused rather than half understood.
pub fn migrate(conn: &mut Connection, migrations: &[&str]) -> Result<(), RewriteError> {
    let tx = conn.transaction().map_err(db)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        .map_err(db)?;
    let current = current_version(&tx)?;
    let latest = u32::try_from(migrations.len()).unwrap_or(u32::MAX);
    if current > latest {
        return Err(RewriteError::Store(format!(
            "rewrite database schema {current} is newer than this build supports ({latest})"
        )));
    }
    for (i, sql) in migrations.iter().enumerate().skip(current as usize) {
        tx.execute_batch(sql).map_err(db)?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![i as u32 + 1],
        )
        .map_err(db)?;
    }
    tx.commit().map_err(db)
}

const UNIT_SELECT: &str = "SELECT v.id, v.program_sha256, v.address, v.name, v.space, v.version,
        v.mode, v.status, v.source_decompile_hash, v.callees_json, v.rust_code, v.rust_code_hash,
        v.signature_json, v.rust_prototype, v.oracle_json, v.author, v.provider, v.model, v.task,
        v.prompt_hash, v.spec_id,
        d.verdict, d.detail, d.seed, d.cases_run, d.passed, d.skipped, d.sandbox,
        d.counterexamples_json
     FROM unit_versions v JOIN verdicts d ON d.version_id = v.id ";

type Raw = (
    String,
    String,
    String,
    String,
    String,
    u32,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    String,
    Option<i64>,
    String,
    Option<String>,
    i64,
    u32,
    u32,
    u32,
    String,
    String,
);

fn raw_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
        r.get(15)?,
        r.get(16)?,
        r.get(17)?,
        r.get(18)?,
        r.get(19)?,
        r.get::<_, Option<i64>>(20)?,
        r.get(21)?,
        r.get(22)?,
        r.get(23)?,
        r.get(24)?,
        r.get(25)?,
        r.get(26)?,
        r.get(27)?,
        r.get(28)?,
    ))
}

fn read_units(
    conn: &Connection,
    tail: &str,
    p: impl rusqlite::Params,
) -> Result<Vec<RewriteUnit>, RewriteError> {
    let mut st = conn.prepare(&format!("{UNIT_SELECT}{tail}")).map_err(db)?;
    let raws = st
        .query_map(p, raw_row)
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    let mut out = Vec::with_capacity(raws.len());
    for raw in raws {
        out.push(build_unit(conn, raw)?);
    }
    Ok(out)
}

fn read_unit(
    conn: &Connection,
    tail: &str,
    p: impl rusqlite::Params,
) -> Result<Option<RewriteUnit>, RewriteError> {
    Ok(read_units(conn, tail, p)?.into_iter().next())
}

fn build_unit(conn: &Connection, raw: Raw) -> Result<RewriteUnit, RewriteError> {
    let (
        id,
        program_sha256,
        address,
        name,
        space,
        version,
        mode,
        status,
        source_decompile_hash,
        callees,
        rust_code,
        rust_code_hash,
        signature,
        rust_prototype,
        oracle,
        author,
        provider,
        model,
        task,
        prompt_hash,
        spec_id,
        verdict,
        detail,
        seed,
        cases_run,
        passed,
        skipped,
        sandbox,
        counterexamples,
    ) = raw;
    let mut st = conn
        .prepare("SELECT case_json FROM test_cases WHERE version_id = ?1 ORDER BY ordinal")
        .map_err(db)?;
    let cases = st
        .query_map(params![id], |r| r.get::<_, String>(0))
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    let test_cases = cases
        .iter()
        .map(|c| serde_json::from_str::<CaseRecord>(c).map_err(js))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RewriteUnit {
        schema: UNIT_SCHEMA,
        id,
        version,
        mode: mode_of(&mode),
        status: status_of(&status)?,
        spec_id: spec_id.map(|v| v as u64),
        anchor: FunctionAnchor {
            program_sha256,
            space,
            address,
            name,
        },
        source_decompile_hash,
        callees: serde_json::from_str::<Vec<CalleeRef>>(&callees).map_err(js)?,
        rust_code,
        rust_code_hash,
        signature: serde_json::from_str::<Signature>(&signature).map_err(js)?,
        rust_prototype,
        provenance: Provenance {
            author,
            provider,
            model,
            task,
            prompt_hash,
        },
        oracle: serde_json::from_str::<OracleInfo>(&oracle).map_err(js)?,
        test_cases,
        summary: RunSummary {
            seed: seed as u64,
            cases_run: cases_run as usize,
            passed: passed as usize,
            skipped: skipped as usize,
            sandbox,
        },
        counterexamples: serde_json::from_str::<Vec<Counterexample>>(&counterexamples)
            .map_err(js)?,
        verdict: verdict_from(&verdict, detail)?,
    })
}

//! `<project>/rewrite.sqlite`: everything the rewrite pipeline produces, in a file owned by this
//! crate and separate from the project database (`project.kraken.sqlite`), so the edit log's
//! schema and this one change independently (ADR 0013).
//!
//! Tables (see [`MIGRATIONS`]): `units` (one row per function: status, newest and accepted
//! version), `unit_versions` (one row per translation: code, ABI, provenance, oracle),
//! `test_cases` (the oracle's expected results), `verdicts` (counts and counterexamples),
//! `unit_events` (status transitions), `specs`, and the stored plan (`plan_meta`,
//! `plan_entries`). Versions are append-only; accepting moves a pointer.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use kraken_registry::commands::{
    PlanFlag, ProgramRunSummary, RewriteMode, RewriteProgramResult, UnitStatus,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::abi::{Arg, Signature};
use crate::difftest::{CaseRecord, Counterexample, Verdict};
use crate::error::RewriteError;
use kraken_registry::commands::RewriteHints;

use crate::unit::{
    CalleeRef, Coverage, FunctionAnchor, OracleInfo, Provenance, RepairLink, RewriteUnit,
    RunSummary, UNIT_SCHEMA,
};

/// The hints of a function as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHints {
    /// The hints.
    pub hints: RewriteHints,
    /// Who set them last.
    pub updated_by: String,
    /// True when an agent set them (their text goes into the prompt as data).
    pub by_agent: bool,
}

/// A model reply of the translation cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedReply {
    /// The reply text.
    pub text: String,
    /// Provider id that wrote it.
    pub provider: String,
    /// Model that wrote it.
    pub model: String,
}

/// What the translation cache holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheSummary {
    /// Replies stored.
    pub entries: u64,
    /// Bytes of reply text.
    pub bytes: u64,
    /// Times a stored reply was used instead of a model call.
    pub hits: u64,
    /// Seconds since the epoch of the oldest reply (0 when empty).
    pub oldest: u64,
}

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
    // 3: repair runs and staleness. A version made by a repair run remembers its attempt number
    // and the failed version it answers; the newest decompile hash seen per function is kept so
    // a version can be marked stale when it differs from the hash the version was made from.
    "CREATE TABLE unit_repairs (
        version_id TEXT PRIMARY KEY REFERENCES unit_versions (id),
        attempt    INTEGER NOT NULL,
        repair_of  INTEGER,
        feedback   TEXT
     );
     CREATE TABLE observed_hashes (
        program_sha256  TEXT NOT NULL,
        address         TEXT NOT NULL,
        decompile_hash  TEXT NOT NULL,
        observed_at     INTEGER NOT NULL,
        PRIMARY KEY (program_sha256, address)
     );",
    // 4: whole-program rewrites. One row per `rewrite_program` run; the result (function table,
    // crate location, program verdict with its per-case evidence) is kept as JSON because it is
    // written once and read whole.
    "CREATE TABLE program_runs (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        program_sha256 TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        entry          TEXT NOT NULL,
        verdict        TEXT NOT NULL,
        cases_run      INTEGER NOT NULL,
        passed         INTEGER NOT NULL,
        crate_dir      TEXT NOT NULL,
        crate_sha256   TEXT NOT NULL,
        result_json    TEXT NOT NULL
     );
     CREATE INDEX program_runs_by_program ON program_runs (program_sha256, id);",
    // 5: human control. Cases a person added are marked (`origin`), a replay keeps what the
    // cases reach (`coverage_json`).
    "ALTER TABLE test_cases ADD COLUMN origin TEXT NOT NULL DEFAULT 'oracle';
     ALTER TABLE test_cases ADD COLUMN note TEXT;
     ALTER TABLE verdicts ADD COLUMN coverage_json TEXT;",
    // 6: hints that steer the translation of a function (JSON of `RewriteHints`), with who set
    // them last.
    "CREATE TABLE unit_hints (
        program_sha256 TEXT NOT NULL,
        address        TEXT NOT NULL,
        hints_json     TEXT NOT NULL,
        updated_by     TEXT NOT NULL,
        by_agent       INTEGER NOT NULL,
        updated_at     INTEGER NOT NULL,
        PRIMARY KEY (program_sha256, address)
     );",
    // 7: model replies by a fingerprint of the prompt, the model and the hints.
    "CREATE TABLE translation_cache (
        key        TEXT PRIMARY KEY,
        provider   TEXT NOT NULL,
        model      TEXT NOT NULL,
        reply      TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        hits       INTEGER NOT NULL DEFAULT 0
     );",
    // 8: inputs harvested from runs of the real program, per function. `split` is `train` (the
    // repair loop may see it) or `held_out` (only the separate check does).
    "CREATE TABLE harvested_cases (
        program_sha256 TEXT NOT NULL,
        address        TEXT NOT NULL,
        ordinal        INTEGER NOT NULL,
        split          TEXT NOT NULL,
        case_json      TEXT NOT NULL,
        run_label      TEXT NOT NULL,
        created_at     INTEGER NOT NULL,
        PRIMARY KEY (program_sha256, address, ordinal)
     );",
];

/// Which part of a function's harvested cases to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarvestSplit {
    /// Cases the translation and repair may be tested with.
    Train,
    /// Cases kept back for the separate check.
    HeldOut,
}

impl HarvestSplit {
    fn as_str(self) -> &'static str {
        match self {
            HarvestSplit::Train => "train",
            HarvestSplit::HeldOut => "held_out",
        }
    }
}

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
    /// Why the relevant version (accepted, else newest) is stale, if it is.
    pub stale: Option<String>,
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
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
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
        if let Some(r) = &unit.repair {
            tx.execute(
                "INSERT INTO unit_repairs (version_id, attempt, repair_of, feedback)
                 VALUES (?1, ?2, ?3, ?4)",
                params![unit.id, r.attempt, r.repair_of, r.feedback],
            )
            .map_err(db)?;
        }
        // The version was made from the live decompile of these functions.
        let mut seen = vec![(addr.clone(), unit.source_decompile_hash.clone())];
        seen.extend(
            unit.callees
                .iter()
                .map(|c| (c.address.clone(), c.decompile_hash.clone())),
        );
        observe_in(&tx, &prog, &seen)?;
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
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
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

    /// Marks a version as rejected by `actor`: it becomes `failed` (it stays in the history and
    /// is never exported). An accepted version must be unaccepted first.
    pub fn reject(
        &self,
        id: &str,
        actor: &str,
        reason: Option<&str>,
    ) -> Result<RewriteUnit, RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let (prog, addr, version, status) = version_row(&tx, id)?;
        match status.as_str() {
            "accepted" => {
                return Err(RewriteError::Store(format!(
                    "unit `{id}` is accepted; unaccept it before rejecting it"
                )));
            }
            "failed" => {
                return Err(RewriteError::Store(format!(
                    "unit `{id}` is already failed"
                )));
            }
            _ => {}
        }
        tx.execute(
            "UPDATE unit_versions SET status = 'failed' WHERE id = ?1",
            params![id],
        )
        .map_err(db)?;
        refresh_function_status(&tx, &prog, &addr)?;
        let note = match reason {
            Some(r) if !r.trim().is_empty() => format!("rejected: {}", r.trim()),
            _ => "rejected".to_string(),
        };
        event(
            &tx,
            &prog,
            &addr,
            version,
            Some(&status),
            UnitStatus::Failed,
            actor,
            Some(&note),
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        self.get(id)?
            .ok_or_else(|| RewriteError::Store("rejected unit vanished".into()))
    }

    /// Takes the acceptance back: the version is `verified` again and the function has no
    /// accepted version.
    pub fn unaccept(&self, id: &str, actor: &str) -> Result<RewriteUnit, RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let (prog, addr, version, status) = version_row(&tx, id)?;
        if status != "accepted" {
            return Err(RewriteError::Store(format!(
                "unit `{id}` is {status}, not accepted"
            )));
        }
        tx.execute(
            "UPDATE unit_versions SET status = 'verified' WHERE id = ?1",
            params![id],
        )
        .map_err(db)?;
        tx.execute(
            "UPDATE units SET accepted_version = NULL WHERE program_sha256 = ?1 AND address = ?2",
            params![prog, addr],
        )
        .map_err(db)?;
        refresh_function_status(&tx, &prog, &addr)?;
        event(
            &tx,
            &prog,
            &addr,
            version,
            Some("accepted"),
            UnitStatus::Verified,
            actor,
            Some("unaccepted"),
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        self.get(id)?
            .ok_or_else(|| RewriteError::Store("unaccepted unit vanished".into()))
    }

    /// Adds cases a person chose to a version (kept after the generated ones).
    pub fn add_cases(
        &self,
        id: &str,
        cases: &[CaseRecord],
        note: Option<&str>,
    ) -> Result<(), RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        version_row(&tx, id)?;
        let next: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(ordinal) + 1, 0) FROM test_cases WHERE version_id = ?1",
                params![id],
                |r| r.get(0),
            )
            .map_err(db)?;
        for (i, case) in cases.iter().enumerate() {
            tx.execute(
                "INSERT INTO test_cases (version_id, ordinal, case_json, origin, note)
                 VALUES (?1, ?2, ?3, 'user', ?4)",
                params![
                    id,
                    next + i as i64,
                    serde_json::to_string(case).map_err(js)?,
                    note
                ],
            )
            .map_err(db)?;
        }
        tx.commit().map_err(db)
    }

    /// Stores the outcome of replaying every case of a version: the verdict and counts, the
    /// counterexamples and the coverage. A disagreeing replay turns the version `failed` (an
    /// accepted one is unaccepted, with an event saying why); a passing replay does not promote
    /// a version.
    pub fn record_replay(
        &self,
        id: &str,
        replay: &Replay,
        actor: &str,
    ) -> Result<RewriteUnit, RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let (prog, addr, version, status) = version_row(&tx, id)?;
        let (kind, detail) = verdict_parts(&replay.verdict);
        tx.execute(
            "UPDATE verdicts SET verdict = ?2, detail = ?3, cases_run = ?4, passed = ?5,
                    skipped = ?6, counterexamples_json = ?7, coverage_json = ?8
             WHERE version_id = ?1",
            params![
                id,
                kind,
                detail,
                replay.cases_run as i64,
                replay.passed as i64,
                replay.skipped as i64,
                serde_json::to_string(&replay.counterexamples).map_err(js)?,
                replay
                    .coverage
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(js)?,
            ],
        )
        .map_err(db)?;
        let demoted = matches!(replay.verdict, Verdict::Fail | Verdict::Rejected { .. })
            && matches!(status.as_str(), "accepted" | "verified" | "translated");
        if demoted {
            if status == "accepted" {
                tx.execute(
                    "UPDATE units SET accepted_version = NULL
                     WHERE program_sha256 = ?1 AND address = ?2",
                    params![prog, addr],
                )
                .map_err(db)?;
            }
            tx.execute(
                "UPDATE unit_versions SET status = 'failed' WHERE id = ?1",
                params![id],
            )
            .map_err(db)?;
            refresh_function_status(&tx, &prog, &addr)?;
        }
        let to = if demoted {
            UnitStatus::Failed
        } else {
            UnitStatus::parse(&status).unwrap_or(UnitStatus::Translated)
        };
        event(
            &tx,
            &prog,
            &addr,
            version,
            Some(&status),
            to,
            actor,
            Some(&format!("replayed {} case(s): {kind}", replay.cases_run)),
        )?;
        tx.commit().map_err(db)?;
        drop(conn);
        self.get(id)?
            .ok_or_else(|| RewriteError::Store("replayed unit vanished".into()))
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
                        stale: None,
                    })
                },
            )
            .collect::<Result<Vec<_>, RewriteError>>()?;
        let stale = stale_reasons_in(&conn, program_sha256)?;
        for r in &mut rows {
            r.stale = stale.get(&r.address).cloned();
        }
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

    /// Stores the hints of a function, replacing the earlier ones; empty hints delete the row.
    pub fn put_hints(
        &self,
        program_sha256: &str,
        address: &str,
        hints: &RewriteHints,
        actor: &str,
        by_agent: bool,
    ) -> Result<(), RewriteError> {
        let conn = self.conn();
        if hints.is_empty() {
            conn.execute(
                "DELETE FROM unit_hints WHERE program_sha256 = ?1 AND address = ?2",
                params![program_sha256, address],
            )
            .map_err(db)?;
            return Ok(());
        }
        conn.execute(
            "INSERT OR REPLACE INTO unit_hints
                (program_sha256, address, hints_json, updated_by, by_agent, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                program_sha256,
                address,
                serde_json::to_string(hints).map_err(js)?,
                actor,
                by_agent,
                now()
            ],
        )
        .map_err(db)?;
        Ok(())
    }

    /// The hints of a function, with who set them and whether that was an agent.
    pub fn hints(
        &self,
        program_sha256: &str,
        address: &str,
    ) -> Result<Option<StoredHints>, RewriteError> {
        let conn = self.conn();
        let row: Option<(String, String, bool)> = conn
            .query_row(
                "SELECT hints_json, updated_by, by_agent FROM unit_hints
                 WHERE program_sha256 = ?1 AND address = ?2",
                params![program_sha256, address],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(json, updated_by, by_agent)| {
            Ok(StoredHints {
                hints: serde_json::from_str(&json).map_err(js)?,
                updated_by,
                by_agent,
            })
        })
        .transpose()
    }

    /// The cached model reply under `key`, counting the hit.
    pub fn cache_get(&self, key: &str) -> Result<Option<CachedReply>, RewriteError> {
        let conn = self.conn();
        let row: Option<CachedReply> = conn
            .query_row(
                "SELECT reply, provider, model FROM translation_cache WHERE key = ?1",
                params![key],
                |r| {
                    Ok(CachedReply {
                        text: r.get(0)?,
                        provider: r.get(1)?,
                        model: r.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(db)?;
        if row.is_some() {
            conn.execute(
                "UPDATE translation_cache SET hits = hits + 1 WHERE key = ?1",
                params![key],
            )
            .map_err(db)?;
        }
        Ok(row)
    }

    /// Caches a model reply under `key`, replacing an earlier one.
    pub fn cache_put(&self, key: &str, reply: &CachedReply) -> Result<(), RewriteError> {
        self.conn()
            .execute(
                "INSERT OR REPLACE INTO translation_cache
                    (key, provider, model, reply, created_at, hits)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![key, reply.provider, reply.model, reply.text, now()],
            )
            .map_err(db)?;
        Ok(())
    }

    /// Drops the reply under `key` (a translation that failed its test is asked for again).
    pub fn cache_forget(&self, key: &str) -> Result<(), RewriteError> {
        self.conn()
            .execute("DELETE FROM translation_cache WHERE key = ?1", params![key])
            .map_err(db)?;
        Ok(())
    }

    /// Adds harvested cases of a function (those already stored are skipped). The case at
    /// position `n` of the function's whole list is held out when `n % stride == stride - 1`
    /// (`stride` 0 holds none out), so a case keeps its split when more are added later.
    /// Returns how many were added to `train` and to `held_out`.
    pub fn add_harvest(
        &self,
        sha: &str,
        address: &str,
        run_label: &str,
        cases: &[Vec<Arg>],
        stride: u32,
    ) -> Result<(usize, usize), RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let mut have: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        {
            let mut q = tx
                .prepare(
                    "SELECT case_json FROM harvested_cases
                     WHERE program_sha256 = ?1 AND address = ?2",
                )
                .map_err(db)?;
            let rows = q
                .query_map(params![sha, address], |r| r.get::<_, String>(0))
                .map_err(db)?;
            for r in rows {
                have.insert(r.map_err(db)?);
            }
        }
        let mut next = i64::try_from(have.len()).unwrap_or(0);
        let (mut train, mut held) = (0, 0);
        for case in cases {
            let json = serde_json::to_string(case).map_err(js)?;
            if !have.insert(json.clone()) {
                continue;
            }
            let held_out = stride > 0 && next % i64::from(stride) == i64::from(stride) - 1;
            tx.execute(
                "INSERT INTO harvested_cases
                    (program_sha256, address, ordinal, split, case_json, run_label, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    sha,
                    address,
                    next,
                    if held_out { "held_out" } else { "train" },
                    json,
                    run_label,
                    now()
                ],
            )
            .map_err(db)?;
            next += 1;
            if held_out {
                held += 1;
            } else {
                train += 1;
            }
        }
        tx.commit().map_err(db)?;
        Ok((train, held))
    }

    /// The harvested cases of a function in one split, in the order they were stored.
    pub fn harvested(
        &self,
        sha: &str,
        address: &str,
        split: HarvestSplit,
    ) -> Result<Vec<Vec<Arg>>, RewriteError> {
        let conn = self.conn();
        let mut q = conn
            .prepare(
                "SELECT case_json FROM harvested_cases
                 WHERE program_sha256 = ?1 AND address = ?2 AND split = ?3
                 ORDER BY ordinal",
            )
            .map_err(db)?;
        let rows = q
            .query_map(params![sha, address, split.as_str()], |r| {
                r.get::<_, String>(0)
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(serde_json::from_str(&r.map_err(db)?).map_err(js)?);
        }
        Ok(out)
    }

    /// Forgets the harvested cases of a function; returns how many there were.
    pub fn clear_harvest(&self, sha: &str, address: &str) -> Result<usize, RewriteError> {
        self.conn()
            .execute(
                "DELETE FROM harvested_cases WHERE program_sha256 = ?1 AND address = ?2",
                params![sha, address],
            )
            .map_err(db)
    }

    /// What the translation cache holds.
    pub fn cache_summary(&self) -> Result<CacheSummary, RewriteError> {
        self.conn()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(reply)), 0), COALESCE(SUM(hits), 0),
                        COALESCE(MIN(created_at), 0)
                 FROM translation_cache",
                [],
                |r| {
                    Ok(CacheSummary {
                        entries: r.get::<_, i64>(0)?.max(0).unsigned_abs(),
                        bytes: r.get::<_, i64>(1)?.max(0).unsigned_abs(),
                        hits: r.get::<_, i64>(2)?.max(0).unsigned_abs(),
                        oldest: r.get::<_, i64>(3)?.max(0).unsigned_abs(),
                    })
                },
            )
            .map_err(db)
    }

    /// Empties the translation cache; returns the entries removed.
    pub fn cache_clear(&self) -> Result<u64, RewriteError> {
        let n = self
            .conn()
            .execute("DELETE FROM translation_cache", [])
            .map_err(db)?;
        Ok(n as u64)
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
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
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

/// Why a version made from `source_hash` and `callees` is stale given the newest decompile
/// hashes seen (address to hash), or `None` when nothing it was made from changed. Functions
/// never observed count as unchanged.
pub fn stale_reason(
    own_address: &str,
    source_hash: &str,
    callees: &[CalleeRef],
    observed: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(now) = observed.get(own_address)
        && now != source_hash
    {
        return Some("the function's decompile changed since this version was made".into());
    }
    callees.iter().find_map(|c| {
        let now = observed.get(&c.address)?;
        (now != &c.decompile_hash).then(|| {
            format!(
                "the decompile of callee `{}` ({}) changed since this version was made",
                c.name, c.address
            )
        })
    })
}

fn observed_in(conn: &Connection, prog: &str) -> Result<BTreeMap<String, String>, RewriteError> {
    let mut st = conn
        .prepare("SELECT address, decompile_hash FROM observed_hashes WHERE program_sha256 = ?1")
        .map_err(db)?;
    st.query_map(params![prog], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(db)?
        .collect::<rusqlite::Result<BTreeMap<String, String>>>()
        .map_err(db)
}

/// Stale reasons per function address, judged on the accepted version or else the newest.
fn stale_reasons_in(
    conn: &Connection,
    prog: &str,
) -> Result<BTreeMap<String, String>, RewriteError> {
    let observed = observed_in(conn, prog)?;
    if observed.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut st = conn
        .prepare(
            "SELECT u.address, v.source_decompile_hash, v.callees_json
             FROM units u JOIN unit_versions v ON v.program_sha256 = u.program_sha256
                  AND v.address = u.address
                  AND v.version = COALESCE(u.accepted_version, u.current_version)
             WHERE u.program_sha256 = ?1",
        )
        .map_err(db)?;
    let rows = st
        .query_map(params![prog], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)?;
    let mut out = BTreeMap::new();
    for (address, hash, callees) in rows {
        let callees = serde_json::from_str::<Vec<CalleeRef>>(&callees).map_err(js)?;
        if let Some(why) = stale_reason(&address, &hash, &callees, &observed) {
            out.insert(address, why);
        }
    }
    Ok(out)
}

impl RewriteStore {
    /// Records the newest decompile hash seen for functions (`0x...` address to hash), which is
    /// what marks versions made from an older decompile as stale.
    pub fn observe(
        &self,
        program_sha256: &str,
        hashes: &[(String, String)],
    ) -> Result<(), RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        observe_in(&tx, program_sha256, hashes)?;
        tx.commit().map_err(db)
    }

    /// Stores a finished program rewrite and returns it with its run id (1, 2, ... for the
    /// project) and creation time filled in.
    pub fn put_program_run(
        &self,
        program_sha256: &str,
        mut result: RewriteProgramResult,
    ) -> Result<RewriteProgramResult, RewriteError> {
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(db)?;
        let at = now();
        tx.execute(
            "INSERT INTO program_runs (program_sha256, created_at, entry, verdict, cases_run,
                    passed, crate_dir, crate_sha256, result_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '')",
            params![
                program_sha256,
                at,
                format!("{:#x}", result.entry.0),
                result.verdict.verdict,
                result.verdict.cases_run,
                result.verdict.passed,
                result.crate_dir,
                result.crate_sha256,
            ],
        )
        .map_err(db)?;
        result.run = u64::try_from(tx.last_insert_rowid()).unwrap_or(0);
        result.created = u64::try_from(at).unwrap_or(0);
        tx.execute(
            "UPDATE program_runs SET result_json = ?2 WHERE id = ?1",
            params![
                i64::try_from(result.run).unwrap_or(0),
                serde_json::to_string(&result).map_err(js)?
            ],
        )
        .map_err(db)?;
        tx.commit().map_err(db)?;
        Ok(result)
    }

    /// A stored program rewrite: the run `id`, or the newest of the program.
    pub fn program_run(
        &self,
        program_sha256: &str,
        id: Option<u64>,
    ) -> Result<Option<RewriteProgramResult>, RewriteError> {
        let conn = self.conn();
        let json: Option<String> = match id {
            Some(id) => conn.query_row(
                "SELECT result_json FROM program_runs WHERE program_sha256 = ?1 AND id = ?2",
                params![program_sha256, i64::try_from(id).unwrap_or(-1)],
                |r| r.get(0),
            ),
            None => conn.query_row(
                "SELECT result_json FROM program_runs WHERE program_sha256 = ?1
                 ORDER BY id DESC LIMIT 1",
                params![program_sha256],
                |r| r.get(0),
            ),
        }
        .optional()
        .map_err(db)?;
        json.map(|j| serde_json::from_str(&j).map_err(js))
            .transpose()
    }

    /// The newest `limit` program rewrites of the program, newest first.
    pub fn program_runs(
        &self,
        program_sha256: &str,
        limit: u32,
    ) -> Result<Vec<ProgramRunSummary>, RewriteError> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT id, created_at, entry, verdict, cases_run, passed, crate_dir
                 FROM program_runs WHERE program_sha256 = ?1 ORDER BY id DESC LIMIT ?2",
            )
            .map_err(db)?;
        st.query_map(params![program_sha256, limit], |r| {
            let entry: String = r.get(2)?;
            Ok(ProgramRunSummary {
                run: u64::try_from(r.get::<_, i64>(0)?).unwrap_or(0),
                created: u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0),
                entry: kraken_proto::Hex64(
                    u64::from_str_radix(entry.trim_start_matches("0x"), 16).unwrap_or(0),
                ),
                verdict: r.get(3)?,
                cases_run: r.get(4)?,
                passed: r.get(5)?,
                crate_dir: r.get(6)?,
            })
        })
        .map_err(db)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(db)
    }

    /// The newest decompile hash seen per function address.
    pub fn observed(&self, program_sha256: &str) -> Result<BTreeMap<String, String>, RewriteError> {
        observed_in(&self.conn(), program_sha256)
    }

    /// Addresses whose decompile the stale check depends on: every function with a unit and the
    /// callees its accepted (else newest) version was made from.
    pub fn tracked_addresses(&self, program_sha256: &str) -> Result<Vec<String>, RewriteError> {
        let conn = self.conn();
        let mut st = conn
            .prepare(
                "SELECT u.address, v.callees_json
                 FROM units u JOIN unit_versions v ON v.program_sha256 = u.program_sha256
                      AND v.address = u.address
                      AND v.version = COALESCE(u.accepted_version, u.current_version)
                 WHERE u.program_sha256 = ?1",
            )
            .map_err(db)?;
        let rows = st
            .query_map(params![program_sha256], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(db)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(db)?;
        let mut out = std::collections::BTreeSet::new();
        for (address, callees) in rows {
            out.insert(address);
            for c in serde_json::from_str::<Vec<CalleeRef>>(&callees).map_err(js)? {
                out.insert(c.address);
            }
        }
        Ok(out.into_iter().collect())
    }

    /// Why the accepted (else newest) version of each function is stale; functions that are
    /// current are absent.
    pub fn stale_reasons(
        &self,
        program_sha256: &str,
    ) -> Result<BTreeMap<String, String>, RewriteError> {
        stale_reasons_in(&self.conn(), program_sha256)
    }
}

fn observe_in(
    tx: &rusqlite::Transaction<'_>,
    prog: &str,
    hashes: &[(String, String)],
) -> Result<(), RewriteError> {
    for (address, hash) in hashes {
        tx.execute(
            "INSERT INTO observed_hashes (program_sha256, address, decompile_hash, observed_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (program_sha256, address)
             DO UPDATE SET decompile_hash = ?3, observed_at = ?4",
            params![prog, address, hash, now()],
        )
        .map_err(db)?;
    }
    Ok(())
}

fn version_row(
    tx: &rusqlite::Transaction<'_>,
    id: &str,
) -> Result<(String, String, u32, String), RewriteError> {
    tx.query_row(
        "SELECT program_sha256, address, version, status FROM unit_versions WHERE id = ?1",
        params![id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .optional()
    .map_err(db)?
    .ok_or_else(|| RewriteError::Store(format!("no rewrite unit `{id}`")))
}

/// Sets the function row's status after a version changed: accepted when one is, otherwise
/// the status of the newest version.
fn refresh_function_status(
    tx: &rusqlite::Transaction<'_>,
    prog: &str,
    addr: &str,
) -> Result<(), RewriteError> {
    tx.execute(
        "UPDATE units SET status = CASE WHEN accepted_version IS NOT NULL THEN 'accepted'
                ELSE (SELECT status FROM unit_versions
                      WHERE program_sha256 = ?1 AND address = ?2 ORDER BY version DESC LIMIT 1)
                END, updated_at = ?3
         WHERE program_sha256 = ?1 AND address = ?2",
        params![prog, addr, now()],
    )
    .map_err(db)?;
    Ok(())
}

/// What replaying the cases of a version found ([`RewriteStore::record_replay`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replay {
    /// The verdict of the replay.
    pub verdict: Verdict,
    /// Cases run on both sides.
    pub cases_run: usize,
    /// Cases that agreed.
    pub passed: usize,
    /// Cases the oracle could not evaluate.
    pub skipped: usize,
    /// Disagreements (smallest input first).
    pub counterexamples: Vec<Counterexample>,
    /// What the cases reach, when it could be measured.
    pub coverage: Option<Coverage>,
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
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(db)?;
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
    let repair = conn
        .query_row(
            "SELECT attempt, repair_of, feedback FROM unit_repairs WHERE version_id = ?1",
            params![id],
            |r| {
                Ok(RepairLink {
                    attempt: r.get(0)?,
                    repair_of: r.get(1)?,
                    feedback: r.get(2)?,
                })
            },
        )
        .optional()
        .map_err(db)?;
    let coverage = conn
        .query_row(
            "SELECT coverage_json FROM verdicts WHERE version_id = ?1",
            params![id],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(db)?
        .flatten()
        .map(|j| serde_json::from_str::<Coverage>(&j).map_err(js))
        .transpose()?;
    let user_cases: u32 = conn
        .query_row(
            "SELECT COUNT(*) FROM test_cases WHERE version_id = ?1 AND origin = 'user'",
            params![id],
            |r| r.get(0),
        )
        .map_err(db)?;
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
        repair,
        coverage,
        user_cases,
    })
}

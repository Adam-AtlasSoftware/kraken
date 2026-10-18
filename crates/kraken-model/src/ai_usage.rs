//! The AI usage ledger: one row per model call in the project database, and a small file with
//! the daily totals of every project in the KRAKEN data directory (for the daily budget).
//!
//! Rows are written by whichever process made the call (the daemon for rewrite jobs, the window
//! for its assistant, the CLI for `kraken explain`); SQLite's WAL mode lets them share the file.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use kraken_proto::{
    AiBilling, AiCallRecord, AiFeature, AiOrigin, AiProviderKind, AiUsageTotals, ProtoError,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};

use crate::Store;
use crate::store::{db, now_ms};

pub(crate) const MIGRATION: &str = "CREATE TABLE ai_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        feature TEXT NOT NULL,
        provider_kind TEXT NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        job_id TEXT,
        run_id TEXT,
        origin TEXT NOT NULL,
        input_tokens INTEGER,
        output_tokens INTEGER,
        wall_ms INTEGER NOT NULL,
        cost_usd REAL,
        billing TEXT NOT NULL
    );
    CREATE INDEX ai_usage_ts ON ai_usage(ts);
    CREATE INDEX ai_usage_job ON ai_usage(job_id);
    CREATE INDEX ai_usage_run ON ai_usage(run_id);";

type Result<T> = std::result::Result<T, ProtoError>;

/// Which calls a usage query counts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageFilter {
    /// Calls at or after this time (milliseconds since the Unix epoch).
    pub since_ms: Option<i64>,
    /// Calls of this AI run or daemon job (matched against both ids).
    pub run: Option<String>,
}

/// Totals of one feature and model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageGroup {
    /// What the calls were for.
    pub feature: AiFeature,
    /// The model (or provider when no model is known).
    pub model: String,
    /// Their totals.
    pub totals: AiUsageTotals,
}

fn i64_of(v: Option<u64>) -> Option<i64> {
    v.map(|n| i64::try_from(n).unwrap_or(i64::MAX))
}

fn where_clause(f: &UsageFilter) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut conds = Vec::new();
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(s) = f.since_ms {
        conds.push(format!("ts >= ?{}", args.len() + 1));
        args.push(Box::new(s));
    }
    if let Some(r) = &f.run {
        let n = args.len() + 1;
        conds.push(format!("(run_id = ?{n} OR job_id = ?{n})"));
        args.push(Box::new(r.clone()));
    }
    let w = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
    (w, args)
}

impl Store {
    /// Stores one model call.
    pub fn ai_usage_add(&mut self, r: &AiCallRecord) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO ai_usage(ts, feature, provider_kind, provider, model, job_id, run_id,
                    origin, input_tokens, output_tokens, wall_ms, cost_usd, billing)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    r.ts_ms,
                    r.feature.as_str(),
                    r.provider_kind.as_str(),
                    r.provider,
                    r.model,
                    r.job_id,
                    r.run_id,
                    r.origin.as_str(),
                    i64_of(r.input_tokens),
                    i64_of(r.output_tokens),
                    i64::try_from(r.wall_ms).unwrap_or(i64::MAX),
                    r.cost_usd,
                    r.billing.as_str(),
                ],
            )
            .map_err(db)?;
        Ok(())
    }

    /// The calls `f` selects, newest first, at most `limit`.
    pub fn ai_usage_calls(&self, f: &UsageFilter, limit: u32) -> Result<Vec<AiCallRecord>> {
        let (w, mut args) = where_clause(f);
        let sql = format!(
            "SELECT ts, feature, provider_kind, provider, model, job_id, run_id, origin,
                input_tokens, output_tokens, wall_ms, cost_usd, billing
             FROM ai_usage {w} ORDER BY id DESC LIMIT ?{}",
            args.len() + 1
        );
        args.push(Box::new(i64::from(limit)));
        let mut stmt = self.conn.prepare(&sql).map_err(db)?;
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |r| {
                let feature: String = r.get(1)?;
                let kind: String = r.get(2)?;
                let origin: String = r.get(7)?;
                let billing: String = r.get(12)?;
                let input: Option<i64> = r.get(8)?;
                let output: Option<i64> = r.get(9)?;
                let wall: i64 = r.get(10)?;
                Ok(AiCallRecord {
                    ts_ms: r.get(0)?,
                    feature: AiFeature::parse(&feature),
                    provider_kind: AiProviderKind::parse(&kind),
                    provider: r.get(3)?,
                    model: r.get(4)?,
                    job_id: r.get(5)?,
                    run_id: r.get(6)?,
                    origin: AiOrigin::parse(&origin),
                    input_tokens: input.map(|n| n.max(0) as u64),
                    output_tokens: output.map(|n| n.max(0) as u64),
                    wall_ms: wall.max(0) as u64,
                    cost_usd: r.get(11)?,
                    billing: AiBilling::parse(&billing),
                })
            })
            .map_err(db)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(db)
    }

    /// Totals of the calls `f` selects, overall and per feature and model.
    pub fn ai_usage_summary(&self, f: &UsageFilter) -> Result<(AiUsageTotals, Vec<UsageGroup>)> {
        let calls = self.ai_usage_calls(f, u32::MAX)?;
        let mut total = AiUsageTotals::default();
        let mut groups: BTreeMap<(AiFeature, String), AiUsageTotals> = BTreeMap::new();
        for c in &calls {
            total.add(c);
            let model = if c.model.is_empty() {
                c.provider.clone()
            } else {
                c.model.clone()
            };
            groups.entry((c.feature, model)).or_default().add(c);
        }
        Ok((
            total,
            groups
                .into_iter()
                .map(|((feature, model), totals)| UsageGroup {
                    feature,
                    model,
                    totals,
                })
                .collect(),
        ))
    }
}

/// Something that keeps model calls.
pub trait UsageSink: Send + Sync {
    /// Keeps one call. Failures are logged, never raised: a full disk must not stop the work.
    fn record(&self, r: &AiCallRecord);
}

/// The ledger of one project: rows in its database.
pub struct ProjectLedger {
    path: PathBuf,
    store: Mutex<Option<Store>>,
}

impl ProjectLedger {
    /// The ledger of the project database at `db_path`; opened on the first call.
    pub fn new(db_path: impl Into<PathBuf>) -> Self {
        ProjectLedger {
            path: db_path.into(),
            store: Mutex::new(None),
        }
    }

    /// Stores one call, opening the database if needed.
    pub fn add(&self, r: &AiCallRecord) -> Result<()> {
        let mut g = self.store.lock().unwrap_or_else(PoisonError::into_inner);
        if g.is_none() {
            *g = Some(Store::open(&self.path)?);
        }
        match g.as_mut() {
            Some(s) => s.ai_usage_add(r),
            None => Ok(()),
        }
    }
}

impl UsageSink for ProjectLedger {
    fn record(&self, r: &AiCallRecord) {
        if let Err(e) = self.add(r) {
            eprintln!(
                "warning: could not record AI usage in {}: {}",
                self.path.display(),
                e.message
            );
        }
    }
}

/// Days kept in the daily file.
const DAYS_KEPT: usize = 62;

/// The daily totals of every project, in `<data dir>/ai-usage-daily.json`.
#[derive(Debug, Clone)]
pub struct DailyLedger {
    path: PathBuf,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct DailyFile {
    #[serde(default)]
    days: BTreeMap<String, AiUsageTotals>,
}

/// `YYYY-MM-DD` of `ms` since the Unix epoch, in UTC.
pub fn utc_day(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

impl DailyLedger {
    /// The file at `path`.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        DailyLedger { path: path.into() }
    }

    /// `$XDG_DATA_HOME/kraken/ai-usage-daily.json`, else under `~/.local/share/kraken`; `None`
    /// when neither variable is set. `KRAKEN_AI_USAGE_FILE` overrides it (tests).
    pub fn from_env(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Self> {
        let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if let Some(p) = non_empty("KRAKEN_AI_USAGE_FILE") {
            return Some(Self::at(p));
        }
        let base = non_empty("XDG_DATA_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| non_empty("HOME").map(|h| h.join(".local/share")))?;
        Some(Self::at(base.join("kraken").join("ai-usage-daily.json")))
    }

    /// The process environment's ledger.
    pub fn standard() -> Option<Self> {
        Self::from_env(&|k| std::env::var_os(k))
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> DailyFile {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Totals of the UTC day `day` (`YYYY-MM-DD`).
    pub fn day(&self, day: &str) -> AiUsageTotals {
        self.read().days.get(day).copied().unwrap_or_default()
    }

    /// Totals of today (UTC).
    pub fn today(&self) -> AiUsageTotals {
        self.day(&utc_day(now_ms()))
    }

    /// Adds one call to its day and writes the file (through a temporary file, so a reader
    /// never sees half of it).
    pub fn add(&self, r: &AiCallRecord) -> std::io::Result<()> {
        let mut f = self.read();
        f.days.entry(utc_day(r.ts_ms)).or_default().add(r);
        while f.days.len() > DAYS_KEPT {
            let Some(first) = f.days.keys().next().cloned() else {
                break;
            };
            f.days.remove(&first);
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(&f).map_err(std::io::Error::other)?;
        let tmp = self
            .path
            .with_extension(format!("json.{}.tmp", std::process::id()));
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
    }
}

impl UsageSink for DailyLedger {
    fn record(&self, r: &AiCallRecord) {
        if let Err(e) = self.add(r) {
            eprintln!(
                "warning: could not record AI usage in {}: {e}",
                self.path.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(ts: i64, job: Option<&str>, cost: f64) -> AiCallRecord {
        AiCallRecord {
            ts_ms: ts,
            feature: AiFeature::Rewrite,
            provider_kind: AiProviderKind::Api,
            provider: "anthropic".into(),
            model: "claude-x".into(),
            job_id: job.map(str::to_string),
            run_id: None,
            origin: AiOrigin::Cli,
            input_tokens: Some(100),
            output_tokens: Some(10),
            wall_ms: 7,
            cost_usd: Some(cost),
            billing: AiBilling::Metered,
        }
    }

    #[test]
    fn the_ledger_sums_calls_by_run_and_time() {
        let mut s = Store::open_in_memory().unwrap();
        s.ai_usage_add(&call(1_000, Some("job-1"), 0.5)).unwrap();
        s.ai_usage_add(&call(2_000, Some("job-1"), 0.25)).unwrap();
        s.ai_usage_add(&call(3_000, Some("job-2"), 1.0)).unwrap();
        let (all, groups) = s.ai_usage_summary(&UsageFilter::default()).unwrap();
        assert_eq!(all.calls, 3);
        assert!((all.cost_usd - 1.75).abs() < 1e-9);
        assert_eq!(groups.len(), 1);
        let (job, _) = s
            .ai_usage_summary(&UsageFilter {
                run: Some("job-1".into()),
                ..UsageFilter::default()
            })
            .unwrap();
        assert_eq!(job.calls, 2);
        let (late, _) = s
            .ai_usage_summary(&UsageFilter {
                since_ms: Some(2_500),
                ..UsageFilter::default()
            })
            .unwrap();
        assert_eq!(late.calls, 1);
        let calls = s.ai_usage_calls(&UsageFilter::default(), 2).unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].job_id.as_deref(), Some("job-2"));
        assert_eq!(calls[0].input_tokens, Some(100));
    }

    #[test]
    fn the_daily_file_adds_up_per_day() {
        let dir = std::env::temp_dir().join(format!("kraken-daily-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = DailyLedger::at(dir.join("daily.json"));
        let now = now_ms();
        d.add(&call(now, None, 0.5)).unwrap();
        d.add(&call(now, None, 0.25)).unwrap();
        d.add(&call(0, None, 9.0)).unwrap();
        let t = d.today();
        assert_eq!(t.calls, 2);
        assert!((t.cost_usd - 0.75).abs() < 1e-9);
        assert_eq!(d.day("1970-01-01").calls, 1);
        assert_eq!(utc_day(0), "1970-01-01");
        assert_eq!(utc_day(1_760_745_600_000), "2025-10-18");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

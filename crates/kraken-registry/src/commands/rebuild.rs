//! `rebuild`: recreate the engine project from the log and report drift (decisions 27, 56, 74).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use kraken_engine::{AnalyzeRequest, CancellationToken, Cap, SharedEngine, unsupported};
use kraken_model::{HistoryFilter, StateValue};
use kraken_proto::{
    ErrorCode, FunctionSummary, Hex64, LogStatus, PageRequest, ProtoError, SyncState, Untrusted,
    sanitize,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::jobs::{JobProgress, JobReporter};
use crate::session::{
    AnalysisPhase, EngineFactory, Project, Session, blocking, epoch_for, open_binary,
};
use crate::validate::untrusted;
use crate::views::locator_parts;

use super::{JobStarted, NoArgs};

/// How a function differs after a rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// The name differs between the old and the rebuilt engine project.
    NameChanged,
    /// The signature differs between the old and the rebuilt engine project.
    SignatureChanged,
    /// The function existed before and is gone after the rebuild.
    MissingAfter,
    /// The function exists only after the rebuild.
    NewAfter,
    /// The rebuilt engine project disagrees with the name the log says it should have.
    StateNameMismatch,
}

/// One function that differs after the rebuild.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DriftEntry {
    /// Function entry.
    pub address: Hex64,
    /// What differs.
    pub kind: DriftKind,
    /// Value before (old engine project, or the log's expectation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Untrusted<String>>,
    /// Value after (rebuilt engine project).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Untrusted<String>>,
}

/// A log entry the rebuilt engine refused while replaying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReplayFailure {
    /// The log entry.
    pub entry_id: u64,
    /// The engine's error code.
    pub code: String,
    /// The engine's reason; it can quote names from the binary.
    pub message: Untrusted<String>,
}

/// Result of a finished `rebuild` job (the `result` of `job_status`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RebuildReport {
    /// Log entries replayed successfully.
    pub replayed: u64,
    /// Log entries the new engine refused.
    pub failed: Vec<ReplayFailure>,
    /// Functions that differ from the previous engine project or from the log.
    pub drifted: Vec<DriftEntry>,
    /// Functions in the previous engine project.
    pub functions_before: u64,
    /// Functions in the rebuilt engine project.
    pub functions_after: u64,
    /// Engine directory now in use, relative to the project directory.
    pub engine_dir: String,
}

/// Starts a rebuild.
pub struct Rebuild;

#[async_trait]
impl Command for Rebuild {
    type Args = NoArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rebuild",
            "Recreate the engine project from the log and report drift (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Repairs a stale engine cache (`epoch_stale` in `project_info`): builds a fresh \
             engine project, re-analyses and replays the edit log, then reports any `drifted` \
             names or signatures. Returns a `job_id`; edits wait until it is done.\n\
             Example: rebuild {}",
        )
        .details(
            "Creates the fresh engine project through the engine factory, replays the applied \
             log in order and compares every function's name and signature with the previous \
             engine project and with the log. The job result is a `RebuildReport`. The old \
             engine directory is kept on disk.",
        )
        .needs(&[
            Cap::Analyzer,
            Cap::Mutator,
            Cap::FunctionLister,
            Cap::Loader,
        ])
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: NoArgs,
    ) -> Result<JobStarted, ProtoError> {
        let project = s.project()?;
        let factory = s.factory().clone();
        let prev = project.analysis().phase;
        let started = project.begin_analysis(|| {
            let project = project.clone();
            s.jobs().spawn("rebuild", move |reporter| async move {
                run_rebuild(project, factory, reporter, prev).await
            })
        });
        match started {
            Ok(id) => Ok(JobStarted { job_id: id.0 }),
            Err(_) => Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "analysis or a rebuild is already running",
            )),
        }
    }
}

pub(crate) async fn run_rebuild(
    project: Arc<Project>,
    factory: Arc<dyn EngineFactory>,
    reporter: JobReporter,
    prev: AnalysisPhase,
) -> Result<Value, ProtoError> {
    match rebuild(&project, factory, &reporter).await {
        Ok(report) => {
            project.end_analysis(AnalysisPhase::Complete, Some(report.functions_after), None);
            serde_json::to_value(report)
                .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))
        }
        Err(e) => {
            let phase = if prev == AnalysisPhase::Running {
                AnalysisPhase::NotStarted
            } else {
                prev
            };
            project.end_analysis(phase, None, Some(e.message.clone()));
            Err(e)
        }
    }
}

fn progress(reporter: &JobReporter, phase: &str, done: u64, total: u64, message: &str) {
    reporter.progress(JobProgress {
        phase: phase.to_string(),
        done,
        total,
        message: sanitize(message),
        ..Default::default()
    });
}

async fn rebuild(
    project: &Project,
    factory: Arc<dyn EngineFactory>,
    reporter: &JobReporter,
) -> Result<RebuildReport, ProtoError> {
    let token = reporter.cancel_token();
    let _write = project.write_lock.lock().await;
    let meta = project.meta();
    let old_engine = project.engine();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rel = format!("ghidra-rebuild-{stamp}");
    let dir = project.dir().join(&rel);
    {
        let dir = dir.clone();
        blocking(move || {
            std::fs::create_dir_all(&dir).map_err(|e| {
                ProtoError::new(
                    ErrorCode::Internal,
                    format!("cannot create {}: {e}", dir.display()),
                )
            })
        })
        .await?;
    }
    let engine = factory.create_kind(meta.engine_kind, &dir).await?;
    let program = open_binary(
        &engine,
        Path::new(&meta.binary_path),
        &meta.loader.clone().unwrap_or_default(),
    )
    .await?;

    let analyzer = engine.analyzer().ok_or_else(|| unsupported("analyzer"))?;
    let mut job = analyzer
        .analyze(AnalyzeRequest::default(), token.clone())
        .await?;
    while let Some(p) = job.next_progress().await {
        progress(
            reporter,
            &format!("analyze:{}", p.stage.as_str()),
            p.done,
            p.total,
            &p.message,
        );
    }
    job.wait().await?;

    let entries = all_entries(project).await?;
    let to_replay: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            e.status == LogStatus::Applied && !matches!(e.sync, SyncState::EngineRejected { .. })
        })
        .collect();
    let mutator = engine.mutator().ok_or_else(|| unsupported("mutator"))?;
    let total = to_replay.len() as u64;
    let mut replayed = 0u64;
    let mut failed = Vec::new();
    let mut last_ok = None;
    for (i, e) in to_replay.iter().enumerate() {
        progress(
            reporter,
            "replay",
            i as u64,
            total,
            "replaying the edit log",
        );
        match crate::session::apply_to_engine(mutator, &e.op, &token).await {
            Ok(()) => {
                replayed += 1;
                last_ok = Some(e.id);
                if e.sync == SyncState::Pending {
                    let id = e.id;
                    project.with_store(move |st| st.mark_pushed(id)).await?;
                }
            }
            Err(rej) if rej.code == ErrorCode::Cancelled => return Err(rej.into()),
            Err(rej) => failed.push(ReplayFailure {
                entry_id: e.id.0,
                code: rej.code.as_str().to_string(),
                message: Untrusted::sanitized(&rej.reason),
            }),
        }
    }
    progress(reporter, "replay", total, total, "replay finished");

    progress(reporter, "drift", 0, 1, "comparing functions");
    let cap = project.config().drift_function_cap;
    let before = collect_functions(&old_engine, cap, &token).await?;
    let after = collect_functions(&engine, cap, &token).await?;
    let state = project.with_store(|st| st.current_state()).await?;
    let drifted = drift(&before, &after, &state);

    if let Some(last) = last_ok {
        let mark = mutator.save(&token).await?;
        project
            .with_store(move |st| st.set_watermark(last, &mark.0))
            .await?;
    }
    let functions_after = after.len() as u64;
    let functions_before = before.len() as u64;
    let new_epoch = epoch_for(&engine, &meta.binary_sha256);
    project.set_engine(engine, program);
    project.mark_all_known().await?;
    project.update_meta(|m| {
        m.engine_dir = rel.clone();
        m.epoch = new_epoch;
        m.analysis_complete = true;
    });
    project.persist_meta().await?;
    progress(reporter, "drift", 1, 1, "done");
    Ok(RebuildReport {
        replayed,
        failed,
        drifted,
        functions_before,
        functions_after,
        engine_dir: rel,
    })
}

async fn all_entries(project: &Project) -> Result<Vec<kraken_model::LogEntryView>, ProtoError> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let req = PageRequest {
            cursor: cursor.clone(),
            limit: Some(500),
        };
        let page = project
            .with_store(move |st| st.history(&req, &HistoryFilter::default()))
            .await?;
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    out.reverse();
    Ok(out)
}

type FnMap = BTreeMap<(String, u64), FunctionSummary>;

async fn collect_functions(
    engine: &SharedEngine,
    cap: usize,
    cancel: &CancellationToken,
) -> Result<FnMap, ProtoError> {
    let lister = engine
        .function_lister()
        .ok_or_else(|| unsupported("function_lister"))?;
    let mut out = FnMap::new();
    let mut cursor = None;
    loop {
        let page = lister
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(500),
                },
                cancel,
            )
            .await?;
        for f in page.items {
            let (space, off) = locator_parts(&f.locator);
            out.insert((space, off.0), f);
        }
        match page.next_cursor {
            Some(c) if out.len() < cap => cursor = Some(c),
            _ => break,
        }
    }
    Ok(out)
}

fn drift(before: &FnMap, after: &FnMap, state: &kraken_model::AnnotationState) -> Vec<DriftEntry> {
    let entry = |kind, key: &(String, u64), b: Option<&str>, a: Option<&str>| DriftEntry {
        address: Hex64(key.1),
        kind,
        before: b.map(untrusted),
        after: a.map(untrusted),
    };
    let mut out = Vec::new();
    for (key, old) in before {
        match after.get(key) {
            None => out.push(entry(DriftKind::MissingAfter, key, Some(&old.name), None)),
            Some(new) => {
                if old.name != new.name {
                    out.push(entry(
                        DriftKind::NameChanged,
                        key,
                        Some(&old.name),
                        Some(&new.name),
                    ));
                }
                if old.signature != new.signature {
                    out.push(entry(
                        DriftKind::SignatureChanged,
                        key,
                        old.signature.as_deref(),
                        new.signature.as_deref(),
                    ));
                }
            }
        }
    }
    for (key, new) in after {
        if !before.contains_key(key) {
            out.push(entry(DriftKind::NewAfter, key, None, Some(&new.name)));
        }
    }
    for (k, v) in state {
        let StateValue::Name { name } = v else {
            continue;
        };
        let Some(rest) = k
            .strip_prefix("native:")
            .and_then(|r| r.strip_suffix(":name"))
        else {
            continue;
        };
        let Some((space, hex)) = rest.rsplit_once(':') else {
            continue;
        };
        let Some(off) = hex
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
        else {
            continue;
        };
        let key = (space.to_string(), off);
        if let Some(f) = after.get(&key)
            && f.name != *name
        {
            out.push(entry(
                DriftKind::StateNameMismatch,
                &key,
                Some(name),
                Some(&f.name),
            ));
        }
    }
    out
}

/// Where the engine's view of `found` contradicts the log's current state.
pub(crate) fn drift_against_log(
    found: &FnMap,
    state: &kraken_model::AnnotationState,
) -> Vec<DriftEntry> {
    drift(found, found, state)
}

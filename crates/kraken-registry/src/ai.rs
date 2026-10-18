//! The session's board of AI work: what is running or ran lately, by which model, for whom,
//! and what it has used so far. The rewrite pipeline (and anything else in the daemon that calls
//! a model) puts its work here; `ai_jobs` lists it and `krakend` turns changes into events.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kraken_proto::{
    AiFeature, AiJobStatus, AiJobView, AiOrigin, AiProviderKind, AiUsageTotals, sanitize,
};

/// Finished work kept for the listing.
const KEEP_FINISHED: usize = 40;

#[derive(Default)]
struct Inner {
    next: AtomicU64,
    version: AtomicU64,
    jobs: Mutex<Vec<AiJobView>>,
}

/// The board. Cheap to clone; clones share it.
#[derive(Clone, Default)]
pub struct AiBoard {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for AiBoard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiBoard").finish_non_exhaustive()
    }
}

/// What a new piece of AI work is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiWork {
    /// The feature.
    pub feature: AiFeature,
    /// One line ("Rewriting checksum").
    pub label: String,
    /// The daemon job behind it.
    pub job_id: Option<String>,
    /// Where the model runs.
    pub provider_kind: AiProviderKind,
    /// Provider or agent id.
    pub provider: String,
    /// The model.
    pub model: String,
    /// Who started it.
    pub origin: AiOrigin,
    /// The user or agent id that started it.
    pub started_by: String,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl AiBoard {
    /// An empty board.
    pub fn new() -> Self {
        AiBoard::default()
    }

    fn lock(&self) -> MutexGuard<'_, Vec<AiJobView>> {
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self) {
        self.inner.version.fetch_add(1, Ordering::Relaxed);
    }

    /// Changes so far; grows whenever anything on the board changes.
    pub fn version(&self) -> u64 {
        self.inner.version.load(Ordering::Relaxed)
    }

    /// Puts new running work on the board and returns its id (`ai-3`).
    pub fn start(&self, w: AiWork) -> String {
        let n = self.inner.next.fetch_add(1, Ordering::Relaxed) + 1;
        let id = format!("ai-{n}");
        let view = AiJobView {
            id: id.clone(),
            job_id: w.job_id,
            feature: w.feature,
            label: sanitize(&w.label),
            provider_kind: w.provider_kind,
            provider: w.provider,
            model: w.model,
            origin: w.origin,
            started_by: w.started_by,
            status: AiJobStatus::Running,
            started_ms: now_ms(),
            ended_ms: None,
            usage: AiUsageTotals::default(),
            message: None,
        };
        {
            let mut jobs = self.lock();
            jobs.push(view);
            let finished: Vec<usize> = jobs
                .iter()
                .enumerate()
                .filter(|(_, j)| j.status.is_terminal())
                .map(|(i, _)| i)
                .collect();
            if finished.len() > KEEP_FINISHED {
                let drop: Vec<usize> = finished[..finished.len() - KEEP_FINISHED].to_vec();
                let mut i = 0;
                jobs.retain(|_| {
                    let keep = !drop.contains(&i);
                    i += 1;
                    keep
                });
            }
        }
        self.bump();
        id
    }

    /// Records the usage so far (and the model, once a terminal agent says which it is).
    pub fn update(&self, id: &str, usage: AiUsageTotals, model: Option<&str>) {
        let mut jobs = self.lock();
        if let Some(j) = jobs.iter_mut().find(|j| j.id == id) {
            j.usage = usage;
            if let Some(m) = model.filter(|m| !m.is_empty()) {
                j.model = m.to_string();
            }
        }
        drop(jobs);
        self.bump();
    }

    /// Ends the work.
    pub fn finish(&self, id: &str, status: AiJobStatus, message: Option<String>) {
        let mut jobs = self.lock();
        if let Some(j) = jobs
            .iter_mut()
            .find(|j| j.id == id && !j.status.is_terminal())
        {
            j.status = status;
            j.ended_ms = Some(now_ms());
            j.message = message.map(|m| sanitize(&m));
        }
        drop(jobs);
        self.bump();
    }

    /// Running work first (oldest first), then finished work (newest first).
    pub fn list(&self) -> Vec<AiJobView> {
        let jobs = self.lock();
        let mut running: Vec<AiJobView> = jobs
            .iter()
            .filter(|j| !j.status.is_terminal())
            .cloned()
            .collect();
        let mut done: Vec<AiJobView> = jobs
            .iter()
            .filter(|j| j.status.is_terminal())
            .cloned()
            .collect();
        done.reverse();
        running.append(&mut done);
        running
    }

    /// The work with id `id`.
    pub fn get(&self, id: &str) -> Option<AiJobView> {
        self.lock().iter().find(|j| j.id == id).cloned()
    }

    /// Pieces of work still running.
    pub fn running(&self) -> usize {
        self.lock()
            .iter()
            .filter(|j| !j.status.is_terminal())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work(label: &str) -> AiWork {
        AiWork {
            feature: AiFeature::Rewrite,
            label: label.into(),
            job_id: Some("job-1".into()),
            provider_kind: AiProviderKind::Api,
            provider: "anthropic".into(),
            model: "claude".into(),
            origin: AiOrigin::Agent,
            started_by: "claude-code".into(),
        }
    }

    #[test]
    fn work_runs_updates_and_ends() {
        let b = AiBoard::new();
        let v0 = b.version();
        let a = b.start(work("first"));
        let c = b.start(work("second"));
        assert!(b.version() > v0);
        let usage = AiUsageTotals {
            calls: 3,
            ..AiUsageTotals::default()
        };
        b.update(&a, usage, None);
        b.finish(&a, AiJobStatus::Limited, Some("limit".into()));
        b.finish(&a, AiJobStatus::Succeeded, None);
        let list = b.list();
        assert_eq!(list[0].id, c, "running work first");
        assert_eq!(list[1].status, AiJobStatus::Limited);
        assert_eq!(list[1].usage.calls, 3);
        assert_eq!(b.running(), 1);
        assert_eq!(b.get(&a).unwrap().message.as_deref(), Some("limit"));
    }
}

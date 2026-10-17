//! In-memory job table: long operations run as tokio tasks with progress, cancel and await.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kraken_engine::CancellationToken;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::watch;

/// Terminal jobs kept for inspection; the oldest are dropped beyond this.
const KEEP_FINISHED: usize = 256;

/// Identifier of a job, e.g. `job-3`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct JobId(pub String);

/// Where a job stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Still working.
    Running,
    /// Finished with a result.
    Succeeded,
    /// Finished with an error.
    Failed,
    /// Ended because it was cancelled.
    Cancelled,
}

impl JobStatus {
    /// True once the job has ended.
    pub fn is_terminal(self) -> bool {
        self != JobStatus::Running
    }
}

/// The latest progress report of a job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobProgress {
    /// Phase name such as an analysis stage.
    pub phase: String,
    /// Work units done in the phase.
    pub done: u64,
    /// Work units in the phase.
    pub total: u64,
    /// Human-readable status; may contain engine text.
    pub message: String,
}

/// A point-in-time view of a job.
#[derive(Debug, Clone, PartialEq)]
pub struct JobSnapshot {
    /// Job id.
    pub id: JobId,
    /// Name of the command that started it.
    pub command: String,
    /// Status.
    pub status: JobStatus,
    /// Latest progress, if any.
    pub progress: Option<JobProgress>,
    /// Result once succeeded.
    pub result: Option<Value>,
    /// Error once failed or cancelled.
    pub error: Option<ProtoError>,
}

struct JobEntry {
    cancel: CancellationToken,
    tx: watch::Sender<JobSnapshot>,
}

impl JobEntry {
    fn snapshot(&self) -> JobSnapshot {
        self.tx.borrow().clone()
    }
}

/// Handed to a job's work function to report progress and observe cancellation.
#[derive(Clone)]
pub struct JobReporter {
    entry: Arc<JobEntry>,
}

impl JobReporter {
    /// Records the latest progress.
    pub fn progress(&self, p: JobProgress) {
        self.entry.tx.send_modify(|s| s.progress = Some(p));
    }

    /// The job's cancellation token; fires on `job_cancel`.
    pub fn cancel_token(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }
}

#[derive(Default)]
struct Inner {
    next: AtomicU64,
    jobs: Mutex<BTreeMap<u64, Arc<JobEntry>>>,
}

/// Table of jobs; cheap to clone, clones share state.
#[derive(Clone, Default)]
pub struct JobTable {
    inner: Arc<Inner>,
}

fn not_found(id: &str) -> ProtoError {
    ProtoError::new(ErrorCode::NotFound, format!("no job {id}"))
}

impl JobTable {
    /// An empty table.
    pub fn new() -> JobTable {
        JobTable::default()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<JobEntry>>> {
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn entry(&self, id: &JobId) -> Result<Arc<JobEntry>, ProtoError> {
        let n =
            id.0.strip_prefix("job-")
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or_else(|| not_found(&id.0))?;
        self.lock().get(&n).cloned().ok_or_else(|| not_found(&id.0))
    }

    /// Runs `work` as a job on the tokio runtime. A returned `cancelled` error ends the job as
    /// `cancelled`, any other error as `failed`; a panic fails the job with `internal`.
    pub fn spawn<F, Fut>(&self, command: &str, work: F) -> JobId
    where
        F: FnOnce(JobReporter) -> Fut,
        Fut: Future<Output = Result<Value, ProtoError>> + Send + 'static,
    {
        let n = self.inner.next.fetch_add(1, Ordering::Relaxed) + 1;
        let id = JobId(format!("job-{n}"));
        let (tx, _rx) = watch::channel(JobSnapshot {
            id: id.clone(),
            command: command.to_string(),
            status: JobStatus::Running,
            progress: None,
            result: None,
            error: None,
        });
        let entry = Arc::new(JobEntry {
            cancel: CancellationToken::new(),
            tx,
        });
        {
            let mut jobs = self.lock();
            jobs.insert(n, entry.clone());
            let finished: Vec<u64> = jobs
                .iter()
                .filter(|(_, e)| e.snapshot().status.is_terminal())
                .map(|(k, _)| *k)
                .collect();
            if finished.len() > KEEP_FINISHED {
                for k in &finished[..finished.len() - KEEP_FINISHED] {
                    jobs.remove(k);
                }
            }
        }
        let fut = work(JobReporter {
            entry: entry.clone(),
        });
        let worker = tokio::spawn(fut);
        tokio::spawn(async move {
            let outcome = match worker.await {
                Ok(r) => r,
                Err(e) => Err(ProtoError::new(
                    ErrorCode::Internal,
                    format!("job panicked: {e}"),
                )),
            };
            entry.tx.send_modify(|s| match outcome {
                Ok(v) => {
                    s.status = JobStatus::Succeeded;
                    s.result = Some(v);
                }
                Err(e) if e.code == ErrorCode::Cancelled => {
                    s.status = JobStatus::Cancelled;
                    s.error = Some(e.sanitized());
                }
                Err(e) => {
                    s.status = JobStatus::Failed;
                    s.error = Some(e.sanitized());
                }
            });
        });
        id
    }

    /// The current state of a job; `not_found` for unknown or pruned ids.
    pub fn snapshot(&self, id: &JobId) -> Result<JobSnapshot, ProtoError> {
        Ok(self.entry(id)?.snapshot())
    }

    /// Requests cancellation and returns the current state (usually still running).
    pub fn cancel(&self, id: &JobId) -> Result<JobSnapshot, ProtoError> {
        let e = self.entry(id)?;
        e.cancel.cancel();
        Ok(e.snapshot())
    }

    /// Waits until the job ends or `timeout` passes; returns the state and whether it timed out.
    /// `cancel` aborts the wait (not the job) with a `cancelled` error.
    pub async fn wait(
        &self,
        id: &JobId,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(JobSnapshot, bool), ProtoError> {
        let e = self.entry(id)?;
        let mut rx = e.tx.subscribe();
        let ended = async {
            let _ = rx.wait_for(|s| s.status.is_terminal()).await;
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtoError::new(ErrorCode::Cancelled, "wait cancelled")),
            () = ended => Ok((e.snapshot(), false)),
            () = tokio::time::sleep(timeout) => Ok((e.snapshot(), true)),
        }
    }

    /// All known jobs, oldest first.
    pub fn list(&self) -> Vec<JobSnapshot> {
        self.lock().values().map(|e| e.snapshot()).collect()
    }

    /// Cancels every running job; used when a project is closed or replaced.
    pub fn cancel_all(&self) {
        for e in self.lock().values() {
            e.cancel.cancel();
        }
    }
}

impl std::fmt::Debug for JobTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobTable").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn job_lifecycle_statuses() {
        let t = JobTable::new();
        let ok = t.spawn("a", |_| async { Ok(serde_json::json!({"x": 1})) });
        let bad = t.spawn("b", |_| async {
            Err(ProtoError::new(ErrorCode::Internal, "boom"))
        });
        let panicked = t.spawn("c", |_| async {
            if true {
                panic!("oops");
            }
            Ok(Value::Null)
        });
        let waiting = t.spawn("d", |r| async move {
            r.cancel_token().cancelled().await;
            Err(ProtoError::new(ErrorCode::Cancelled, "stop"))
        });
        let never = CancellationToken::new();
        let long = Duration::from_secs(5);
        let (s, timed_out) = t.wait(&ok, long, &never).await.unwrap();
        assert!(!timed_out);
        assert_eq!(s.status, JobStatus::Succeeded);
        assert_eq!(s.result, Some(serde_json::json!({"x": 1})));
        assert_eq!(
            t.wait(&bad, long, &never).await.unwrap().0.status,
            JobStatus::Failed
        );
        let (p, _) = t.wait(&panicked, long, &never).await.unwrap();
        assert_eq!(p.status, JobStatus::Failed);
        assert_eq!(p.error.unwrap().code, ErrorCode::Internal);
        let (w, timed_out) = t
            .wait(&waiting, Duration::from_millis(10), &never)
            .await
            .unwrap();
        assert!(timed_out && w.status == JobStatus::Running);
        t.cancel(&waiting).unwrap();
        assert_eq!(
            t.wait(&waiting, long, &never).await.unwrap().0.status,
            JobStatus::Cancelled
        );
        let stop = CancellationToken::new();
        stop.cancel();
        let again = t.spawn("e", |r| async move {
            r.cancel_token().cancelled().await;
            Ok(Value::Null)
        });
        assert_eq!(
            t.wait(&again, long, &stop).await.unwrap_err().code,
            ErrorCode::Cancelled
        );
        assert_eq!(t.list().len(), 5);
        assert_eq!(
            t.snapshot(&JobId("job-77".into())).unwrap_err().code,
            ErrorCode::NotFound
        );
    }
}

//! Job handle for long-running operations.

use std::future::Future;

use kraken_proto::{ErrorCode, ProtoError};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::types::{AnalysisSummary, Progress};

/// Producer side of a job's progress stream.
#[derive(Debug, Clone)]
pub struct ProgressSender(mpsc::UnboundedSender<Progress>);

impl ProgressSender {
    /// Emits a progress event; ignored if nobody listens any more.
    pub fn send(&self, p: Progress) {
        let _ = self.0.send(p);
    }
}

/// Handle to a running analysis: a progress stream plus a completion future.
#[derive(Debug)]
pub struct AnalysisJob {
    /// Progress events in order; closed when the job ends.
    pub progress: mpsc::UnboundedReceiver<Progress>,
    completion: oneshot::Receiver<Result<AnalysisSummary, ProtoError>>,
    cancel: CancellationToken,
}

impl AnalysisJob {
    /// Spawns `work` on the tokio runtime as a job. `work` receives the progress sender and the
    /// cancellation token and should return a `cancelled` error when the token fires.
    pub fn spawn<F, Fut>(cancel: CancellationToken, work: F) -> AnalysisJob
    where
        F: FnOnce(ProgressSender, CancellationToken) -> Fut,
        Fut: Future<Output = Result<AnalysisSummary, ProtoError>> + Send + 'static,
    {
        let (tx, progress) = mpsc::unbounded_channel();
        let (done_tx, completion) = oneshot::channel();
        let fut = work(ProgressSender(tx), cancel.clone());
        tokio::spawn(async move {
            let _ = done_tx.send(fut.await);
        });
        AnalysisJob {
            progress,
            completion,
            cancel,
        }
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// The job's cancellation token.
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Next progress event, or `None` once the job has ended and the stream is drained.
    pub async fn next_progress(&mut self) -> Option<Progress> {
        self.progress.recv().await
    }

    /// Waits for completion (progress events not read are dropped).
    pub async fn wait(self) -> Result<AnalysisSummary, ProtoError> {
        self.completion.await.unwrap_or_else(|_| {
            Err(ProtoError::new(
                ErrorCode::Internal,
                "analysis job ended without a result",
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Stage;

    #[tokio::test]
    async fn job_reports_progress_and_result() {
        let mut job = AnalysisJob::spawn(CancellationToken::new(), |tx, _| async move {
            tx.send(Progress {
                stage: Stage::Load,
                done: 1,
                total: 1,
                message: "x".into(),
            });
            Ok(AnalysisSummary {
                stages_completed: vec![Stage::Load],
                function_count: 0,
            })
        });
        assert_eq!(job.next_progress().await.map(|p| p.done), Some(1));
        assert_eq!(job.wait().await.unwrap().stages_completed.len(), 1);
    }

    #[tokio::test]
    async fn cancel_reaches_worker() {
        let job = AnalysisJob::spawn(CancellationToken::new(), |_, c| async move {
            c.cancelled().await;
            Err(ProtoError::new(ErrorCode::Cancelled, "c"))
        });
        job.cancel();
        assert_eq!(job.wait().await.unwrap_err().code, ErrorCode::Cancelled);
    }
}

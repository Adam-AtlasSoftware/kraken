//! Progress and cancellation of opening a project (`project_create`, `project_open` and the
//! daemon's implicit open).
//!
//! An open runs inside its command, but it is also a job in the session's table: `job_status`
//! shows how far it got, `job_cancel` stops it. [`OpenTracker`] keeps that job up to date and
//! hands every report to the caller's [`OpenProgressSink`].

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use kraken_engine::{CancellationToken, OpenReporter};
use kraken_proto::{
    ErrorCode, OpenPlan, OpenProgress, OpenStage, OpenUpdate, ProtoError, sanitize,
};
use serde_json::Value;

use crate::context::{CallContext, OpenProgressSink};
use crate::jobs::{JobTable, TrackedJob};

/// How an open reports and stops.
#[derive(Clone, Default)]
pub struct OpenOptions {
    /// Hears every progress report.
    pub sink: Option<OpenProgressSink>,
    /// Stops the open when it fires (as `job_cancel` on its job does).
    pub cancel: CancellationToken,
}

impl OpenOptions {
    /// The options of a command call: its progress sink and its cancellation.
    pub fn from_context(ctx: &CallContext) -> Self {
        OpenOptions {
            sink: ctx.open_progress.clone(),
            cancel: ctx.cancel.clone(),
        }
    }
}

struct State {
    plan: OpenPlan,
    engine: Option<String>,
    best: f64,
}

/// One open in progress.
pub(crate) struct OpenTracker {
    command: String,
    program: String,
    started: Instant,
    job: TrackedJob,
    sink: Option<OpenProgressSink>,
    cancel: CancellationToken,
    state: Mutex<State>,
}

pub(crate) fn cancelled() -> ProtoError {
    ProtoError::new(ErrorCode::Cancelled, "opening the project was cancelled")
}

impl OpenTracker {
    /// Starts tracking an open of `binary` by `command` as a job in `jobs`.
    pub(crate) fn new(
        jobs: &JobTable,
        command: &str,
        binary: &Path,
        opts: OpenOptions,
    ) -> Arc<OpenTracker> {
        let job = jobs.track(command);
        let cancel = job.reporter().cancel_token();
        // the caller giving up stops the open as `job_cancel` does
        let (outer, inner) = (opts.cancel, cancel.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = outer.cancelled() => inner.cancel(),
                () = inner.cancelled() => {}
            }
        });
        let program = binary
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| binary.display().to_string());
        Arc::new(OpenTracker {
            command: command.to_string(),
            program: sanitize(&program),
            started: Instant::now(),
            job,
            sink: opts.sink,
            cancel,
            state: Mutex::new(State {
                plan: OpenPlan::for_engine(None),
                engine: None,
                best: 0.0,
            }),
        })
    }

    /// Fires when the open should stop.
    pub(crate) fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// `cancelled` once the open should stop.
    pub(crate) fn check(&self) -> Result<(), ProtoError> {
        if self.cancel.is_cancelled() {
            Err(cancelled())
        } else {
            Ok(())
        }
    }

    /// Names the engine, which decides the stage list.
    pub(crate) fn set_engine(&self, engine: &str) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        st.plan = OpenPlan::for_engine(Some(engine));
        st.engine = Some(engine.to_string());
    }

    /// Enters `stage` with nothing more to say than `message`.
    pub(crate) fn stage(&self, stage: OpenStage, message: impl Into<String>) {
        self.update(OpenUpdate::stage(stage, message));
    }

    /// Records an engine report and passes it on.
    pub(crate) fn update(&self, u: OpenUpdate) {
        let p = {
            let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            // an engine that reports more stages than its kind usually has gets the full list
            if !st.plan.stages().contains(&u.stage) {
                st.plan = OpenPlan::for_engine(Some("native"));
            }
            // a stage that cannot tell how far it is, after one that could, is at least where
            // it starts: the bar stays put instead of turning into an endless animation
            let measured = st.plan.fraction(u.stage, u.stage_fraction).or_else(|| {
                (st.best > 0.0)
                    .then(|| st.plan.fraction(u.stage, Some(0.0)))
                    .flatten()
            });
            let fraction = measured.map(|f| {
                st.best = st.best.max(f);
                st.best
            });
            OpenProgress {
                command: self.command.clone(),
                program: self.program.clone(),
                job_id: Some(self.job.id().0.clone()),
                engine: st.engine.clone(),
                stages: st.plan.stages(),
                stage: u.stage,
                fraction,
                stage_fraction: u.stage_fraction.map(|f| f.clamp(0.0, 1.0)),
                found: u.found,
                queued: u.queued,
                covered_bytes: u.covered_bytes,
                code_bytes: u.code_bytes,
                from_cache: u.from_cache,
                message: sanitize(&u.message),
                elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            }
        };
        if let Some(sink) = &self.sink {
            sink(&p);
        }
        self.job.reporter().open_progress(p);
    }

    /// The engine's reports go to [`update`](Self::update).
    pub(crate) fn reporter(self: &Arc<Self>) -> OpenReporter {
        let me = self.clone();
        Arc::new(move |u| me.update(u))
    }

    /// Ends the job: `Ready` on success, the error otherwise.
    pub(crate) fn finish<T>(&self, outcome: &Result<T, ProtoError>) {
        match outcome {
            Ok(_) => {
                self.stage(OpenStage::Ready, format!("{} is open", self.program));
                self.job.finish(Ok(Value::Null));
            }
            Err(e) => self.job.finish(Err(e.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fraction_never_goes_back_and_the_job_follows() {
        let jobs = JobTable::new();
        let seen: Arc<Mutex<Vec<OpenProgress>>> = Arc::default();
        let sink: OpenProgressSink = {
            let seen = seen.clone();
            Arc::new(move |p| seen.lock().unwrap().push(p.clone()))
        };
        let t = OpenTracker::new(
            &jobs,
            "project_open",
            Path::new("/x/libpython.so"),
            OpenOptions {
                sink: Some(sink),
                cancel: CancellationToken::new(),
            },
        );
        t.stage(OpenStage::Prepare, "checking");
        t.set_engine("native");
        let r = t.reporter();
        for f in [0.1, 0.5, 0.3, 0.9] {
            r(OpenUpdate {
                stage_fraction: Some(f),
                found: Some(10),
                queued: Some(5),
                ..OpenUpdate::stage(OpenStage::Functions, "walking")
            });
        }
        t.finish(&Ok::<(), ProtoError>(()));
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].fraction, None, "the first stage cannot tell");
        let fractions: Vec<f64> = seen.iter().filter_map(|p| p.fraction).collect();
        assert!(fractions.windows(2).all(|w| w[0] <= w[1]), "{fractions:?}");
        assert_eq!(fractions.last(), Some(&1.0));
        assert_eq!(seen.last().unwrap().stage, OpenStage::Ready);
        assert_eq!(seen[1].program, "libpython.so");
        assert_eq!(seen[1].engine.as_deref(), Some("native"));
        assert!(
            jobs.list().is_empty(),
            "a finished open leaves the job table"
        );
    }

    #[tokio::test]
    async fn the_callers_cancel_and_job_cancel_both_stop_it() {
        let jobs = JobTable::new();
        let outer = CancellationToken::new();
        let t = OpenTracker::new(
            &jobs,
            "project_create",
            Path::new("a.out"),
            OpenOptions {
                sink: None,
                cancel: outer.clone(),
            },
        );
        assert!(t.check().is_ok());
        outer.cancel();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            t.cancel_token().cancelled(),
        )
        .await
        .unwrap();
        assert_eq!(t.check().unwrap_err().code, ErrorCode::Cancelled);

        let t2 = OpenTracker::new(
            &jobs,
            "project_open",
            Path::new("b"),
            OpenOptions::default(),
        );
        let id = jobs.list().last().unwrap().id.clone();
        jobs.cancel(&id).unwrap();
        assert!(t2.check().is_err());
        t2.finish(&Err::<(), _>(cancelled()));
        assert_eq!(
            jobs.snapshot(&id).unwrap().status,
            crate::jobs::JobStatus::Cancelled
        );
    }
}

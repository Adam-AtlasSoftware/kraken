//! The one tokio runtime of the process, and interruptible blocking calls on it.

use std::future::Future;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use kraken_engine::CancellationToken;
use kraken_proto::{ErrorCode, ProtoError};
use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Result<Runtime, String>> = OnceLock::new();

/// The process-wide runtime, created on first use. Every connection, daemon client and engine of
/// this process runs on it; there is never a second one.
pub fn runtime() -> Result<&'static Runtime, ProtoError> {
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("kraken-py")
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| ProtoError::new(ErrorCode::Internal, format!("cannot start runtime: {e}")))
}

/// A call running on the runtime that a blocking thread can wait on in short slices (so it can
/// release the GIL and look at signals between slices) and cancel.
pub struct Pending<T> {
    rx: Mutex<mpsc::Receiver<T>>,
    cancel: CancellationToken,
}

/// The outcome of one wait slice.
#[derive(Debug, PartialEq, Eq)]
pub enum Wait<T> {
    /// The call finished.
    Done(T),
    /// Still running.
    Pending,
    /// The task ended without producing a result (the runtime is shutting down).
    Lost,
}

impl<T: Send + 'static> Pending<T> {
    /// Spawns `make(cancel)` on the runtime.
    pub fn spawn<F, Fut>(make: F) -> Result<Self, ProtoError>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
    {
        let cancel = CancellationToken::new();
        let fut = make(cancel.clone());
        let (tx, rx) = mpsc::channel();
        runtime()?.spawn(async move {
            let _ = tx.send(fut.await);
        });
        Ok(Pending {
            rx: Mutex::new(rx),
            cancel,
        })
    }

    /// Waits at most `slice` for the result.
    pub fn wait(&self, slice: Duration) -> Wait<T> {
        let rx = self.rx.lock().unwrap_or_else(PoisonError::into_inner);
        match rx.recv_timeout(slice) {
            Ok(v) => Wait::Done(v),
            Err(RecvTimeoutError::Timeout) => Wait::Pending,
            Err(RecvTimeoutError::Disconnected) => Wait::Lost,
        }
    }

    /// Asks the call to stop; it then finishes with a `cancelled` error shortly.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn there_is_one_runtime() {
        let a = runtime().expect("runtime") as *const Runtime;
        let b = runtime().expect("runtime") as *const Runtime;
        assert_eq!(a, b);
    }

    #[test]
    fn a_pending_call_completes() {
        let p = Pending::spawn(|_| async { 7 }).expect("spawn");
        loop {
            match p.wait(Duration::from_millis(20)) {
                Wait::Done(v) => {
                    assert_eq!(v, 7);
                    break;
                }
                Wait::Pending => {}
                Wait::Lost => panic!("lost"),
            }
        }
    }

    #[test]
    fn cancel_reaches_the_task() {
        let p = Pending::spawn(|cancel| async move {
            cancel.cancelled().await;
            "stopped"
        })
        .expect("spawn");
        assert_eq!(p.wait(Duration::from_millis(30)), Wait::Pending);
        p.cancel();
        let mut got = None;
        for _ in 0..100 {
            if let Wait::Done(v) = p.wait(Duration::from_millis(20)) {
                got = Some(v);
                break;
            }
        }
        assert_eq!(got, Some("stopped"));
    }
}

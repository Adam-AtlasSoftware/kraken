//! Idle tracking and shutdown signalling for the daemon.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Default idle timeout before the daemon exits (10 minutes).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Monotonic time source, expressed as an offset from an arbitrary fixed origin.
pub trait Clock: Send + Sync + 'static {
    /// Current monotonic time.
    fn now(&self) -> Duration;
}

/// Real monotonic clock.
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Creates a clock whose origin is now.
    pub fn new() -> Self {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Test clock advanced by hand. Cloning shares the same time.
#[derive(Debug, Clone, Default)]
pub struct ManualClock {
    micros: Arc<AtomicU64>,
}

impl ManualClock {
    /// Creates a clock at time zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Moves time forward.
    pub fn advance(&self, by: Duration) {
        self.micros
            .fetch_add(by.as_micros() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_micros(self.micros.load(Ordering::SeqCst))
    }
}

/// A shared activity counter (clients, jobs or loaded models).
#[derive(Debug, Clone, Default)]
pub struct Counter(Arc<AtomicUsize>);

impl Counter {
    /// Creates a counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    /// Subtracts one, saturating at zero.
    pub fn dec(&self) {
        let _ = self
            .0
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(1));
    }

    /// Sets an absolute value.
    pub fn set(&self, n: usize) {
        self.0.store(n, Ordering::SeqCst);
    }

    /// Current value.
    pub fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// Increments and returns a guard that decrements on drop.
    pub fn guard(&self) -> CounterGuard {
        self.inc();
        CounterGuard(self.clone())
    }
}

/// Decrements its [`Counter`] on drop.
#[derive(Debug)]
pub struct CounterGuard(Counter);

impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// One-shot, cloneable shutdown signal.
#[derive(Debug, Clone, Default)]
pub struct Shutdown {
    inner: Arc<ShutdownInner>,
}

#[derive(Debug, Default)]
struct ShutdownInner {
    flag: AtomicBool,
    notify: Notify,
}

impl Shutdown {
    /// Creates an untriggered signal.
    pub fn new() -> Self {
        Self::default()
    }

    /// Triggers shutdown; idempotent.
    pub fn trigger(&self) {
        self.inner.flag.store(true, Ordering::SeqCst);
        self.inner.notify.notify_waiters();
    }

    /// Whether shutdown was triggered.
    pub fn is_triggered(&self) -> bool {
        self.inner.flag.load(Ordering::SeqCst)
    }

    /// Resolves once shutdown is triggered.
    pub async fn wait(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_triggered() {
                return;
            }
            notified.await;
        }
    }
}

/// Decides when the daemon has been idle long enough to exit: no connected clients, no running
/// jobs and no loaded models for `idle_timeout`.
///
/// The idle period starts when a check first observes all three at zero, so it is accurate to
/// within the polling interval of [`IdleMonitor::run`].
pub struct IdleMonitor<C: Clock = SystemClock> {
    clock: C,
    idle_timeout: Duration,
    clients: Counter,
    jobs: Counter,
    models: Counter,
    idle_since: Mutex<Option<Duration>>,
}

impl<C: Clock> IdleMonitor<C> {
    /// Creates a monitor with fresh counters.
    pub fn new(clock: C, idle_timeout: Duration) -> Self {
        IdleMonitor {
            clock,
            idle_timeout,
            clients: Counter::new(),
            jobs: Counter::new(),
            models: Counter::new(),
            idle_since: Mutex::new(None),
        }
    }

    /// Connected-client counter (hand to `Server::new`).
    pub fn clients(&self) -> &Counter {
        &self.clients
    }

    /// Running-job counter.
    pub fn jobs(&self) -> &Counter {
        &self.jobs
    }

    /// Loaded-model counter.
    pub fn models(&self) -> &Counter {
        &self.models
    }

    /// Whether any activity source is non-zero.
    pub fn is_active(&self) -> bool {
        self.clients.get() > 0 || self.jobs.get() > 0 || self.models.get() > 0
    }

    /// Samples the counters; returns true when the idle timeout has elapsed.
    pub fn should_shutdown(&self) -> bool {
        let now = self.clock.now();
        let mut since = self
            .idle_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.is_active() {
            *since = None;
            return false;
        }
        let start = *since.get_or_insert(now);
        now.saturating_sub(start) >= self.idle_timeout
    }

    /// Polls every `poll` and triggers `shutdown` once idle for the full timeout, or returns when
    /// `shutdown` is triggered by someone else.
    pub async fn run(&self, poll: Duration, shutdown: &Shutdown) {
        loop {
            if self.should_shutdown() {
                shutdown.trigger();
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(poll) => {}
                () = shutdown.wait() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: Duration = Duration::from_secs(600);

    #[test]
    fn fires_only_after_full_idle_timeout() {
        let clock = ManualClock::new();
        let m = IdleMonitor::new(clock.clone(), T);
        assert!(!m.should_shutdown());
        clock.advance(T - Duration::from_secs(1));
        assert!(!m.should_shutdown());
        clock.advance(Duration::from_secs(1));
        assert!(m.should_shutdown());
    }

    #[test]
    fn each_source_blocks_and_resets() {
        let clock = ManualClock::new();
        let m = IdleMonitor::new(clock.clone(), T);
        for c in [m.clients(), m.jobs(), m.models()] {
            let g = c.guard();
            clock.advance(T * 2);
            assert!(!m.should_shutdown());
            drop(g);
            assert!(!m.should_shutdown(), "idle period restarts after release");
            clock.advance(T - Duration::from_secs(1));
            assert!(!m.should_shutdown());
            clock.advance(Duration::from_secs(1));
            assert!(m.should_shutdown());
            c.inc();
            assert!(!m.should_shutdown());
            c.dec();
        }
    }

    #[test]
    fn counter_saturates() {
        let c = Counter::new();
        c.dec();
        assert_eq!(c.get(), 0);
    }

    #[tokio::test]
    async fn run_triggers_shutdown() {
        let m = IdleMonitor::new(SystemClock::new(), Duration::from_millis(30));
        let s = Shutdown::new();
        tokio::time::timeout(Duration::from_secs(5), m.run(Duration::from_millis(5), &s))
            .await
            .unwrap();
        assert!(s.is_triggered());
    }

    #[tokio::test]
    async fn shutdown_wait_sees_earlier_trigger() {
        let s = Shutdown::new();
        s.trigger();
        s.wait().await;
    }
}

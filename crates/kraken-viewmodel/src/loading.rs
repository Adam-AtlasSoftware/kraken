//! What the loading screen shows while a project is created or opened.

use std::time::{Duration, Instant};

use kraken_proto::{OpenPlan, OpenProgress, OpenStage};
use serde_json::json;

use crate::vm::ViewModel;

/// An estimate is shown only after this long in the slow stage...
const ESTIMATE_AFTER: Duration = Duration::from_secs(20);
/// ...and once this share of the work is done.
const ESTIMATE_FROM: f64 = 0.08;

/// A project being created or opened.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadingState {
    /// File name of the program (or the project folder until the engine names it).
    pub program: String,
    /// True when a new project is made (`project_create`), false for an existing one.
    pub creating: bool,
    /// The latest report, once one arrived.
    pub progress: Option<OpenProgress>,
    /// When the open started here.
    pub started: Instant,
    /// When the latest report arrived.
    pub updated: Option<Instant>,
    /// Cancel was pressed: the screen says it is stopping.
    pub cancelling: bool,
    /// The first report of the slow stage with a known fraction: where the estimate starts.
    origin: Option<(Instant, f64)>,
}

/// A count as people read it: `12,410`.
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `1:05` or `1:02:03`.
pub fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
    } else {
        format!("{}:{:02}", s / 60, s % 60)
    }
}

impl LoadingState {
    /// An open of `program` that just started.
    pub fn new(program: impl Into<String>, creating: bool) -> Self {
        LoadingState {
            program: program.into(),
            creating,
            progress: None,
            started: Instant::now(),
            updated: None,
            cancelling: false,
            origin: None,
        }
    }

    /// Takes a report in.
    pub fn apply(&mut self, p: OpenProgress, now: Instant) {
        if !p.program.is_empty() {
            self.program.clone_from(&p.program);
        }
        if p.stage == OpenStage::Functions && !p.from_cache {
            if let Some(f) = p.fraction
                && self.origin.is_none()
            {
                self.origin = Some((now, f));
            }
        } else {
            self.origin = None;
        }
        self.progress = Some(p);
        self.updated = Some(now);
    }

    /// The stages to list: the engine's, or the common ones before the first report.
    pub fn stages(&self) -> Vec<OpenStage> {
        match &self.progress {
            Some(p) if !p.stages.is_empty() => p.stages.clone(),
            _ => OpenPlan::for_engine(None).stages(),
        }
    }

    /// The current stage.
    pub fn stage(&self) -> OpenStage {
        self.progress
            .as_ref()
            .map_or(OpenStage::Prepare, |p| p.stage)
    }

    /// Overall share done, when the current stage can tell.
    pub fn fraction(&self) -> Option<f32> {
        self.progress
            .as_ref()
            .and_then(|p| p.fraction)
            .map(|f| f.clamp(0.0, 1.0) as f32)
    }

    /// Time since the open started.
    pub fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }

    /// `12,410 functions found, 2,300 to look at`, while functions are being found.
    pub fn counts_text(&self) -> Option<String> {
        let p = self.progress.as_ref()?;
        let found = p.found?;
        let mut text = format!(
            "{} function{} found",
            thousands(found),
            if found == 1 { "" } else { "s" }
        );
        if let Some(q) = p.queued.filter(|q| *q > 0) {
            text.push_str(&format!(", {} to look at", thousands(q)));
        }
        Some(text)
    }

    /// The engine's line about what it is doing.
    pub fn message(&self) -> &str {
        self.progress.as_ref().map_or("", |p| p.message.as_str())
    }

    /// True when the engine reads results an earlier open saved.
    pub fn from_cache(&self) -> bool {
        self.progress.as_ref().is_some_and(|p| p.from_cache)
    }

    /// The job that cancels the open, once it is known.
    pub fn job_id(&self) -> Option<&str> {
        self.progress.as_ref().and_then(|p| p.job_id.as_deref())
    }

    /// A rough time left, only when it means something: well into the slow stage of a first
    /// open, from how fast the fraction moved since that stage started.
    pub fn estimate(&self, now: Instant) -> Option<Duration> {
        let p = self.progress.as_ref()?;
        let f = p.fraction?;
        let (t0, f0) = self.origin?;
        let spent = now.saturating_duration_since(t0);
        if p.stage != OpenStage::Functions || spent < ESTIMATE_AFTER || f < ESTIMATE_FROM {
            return None;
        }
        let rate = (f - f0) / spent.as_secs_f64();
        (rate > 0.0).then(|| Duration::from_secs_f64(((1.0 - f) / rate).min(24.0 * 3600.0)))
    }
}

impl ViewModel {
    /// Stops the project that is opening. The engine stops and nothing of it stays open; the
    /// window goes back to the welcome screen.
    pub fn cancel_open(&mut self) {
        let Some(loading) = self.loading.as_mut() else {
            return;
        };
        if loading.cancelling {
            return;
        }
        loading.cancelling = true;
        if let Some(id) = loading.job_id().map(str::to_string) {
            self.send_open_cancel(id);
        }
    }

    pub(crate) fn send_open_cancel(&mut self, job_id: String) {
        self.call("job_cancel", json!({ "job_id": job_id }), |vm, res| {
            if let Err(e) = res {
                vm.toast_error(&e);
            }
        });
    }

    pub(crate) fn on_open_progress(&mut self, p: OpenProgress) {
        let Some(loading) = self.loading.as_mut() else {
            return;
        };
        // Cancel pressed before the job was known: send it now.
        let pending = loading.cancelling && loading.job_id().is_none();
        loading.apply(p, Instant::now());
        if pending && let Some(id) = loading.job_id().map(str::to_string) {
            self.send_open_cancel(id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(stage: OpenStage, fraction: Option<f64>) -> OpenProgress {
        OpenProgress {
            command: "project_open".into(),
            program: "libpython3.14.so".into(),
            job_id: Some("open-1".into()),
            engine: Some("native".into()),
            stages: OpenPlan::for_engine(Some("native")).stages(),
            stage,
            fraction,
            stage_fraction: None,
            found: Some(12_410),
            queued: Some(2_300),
            covered_bytes: None,
            code_bytes: None,
            from_cache: false,
            message: String::new(),
            elapsed_ms: 0,
        }
    }

    #[test]
    fn an_estimate_needs_time_and_progress_in_the_slow_stage() {
        let t0 = Instant::now();
        let mut s = LoadingState::new("x", true);
        assert_eq!(s.stage(), OpenStage::Prepare);
        assert_eq!(s.stages().last(), Some(&OpenStage::Ready));
        s.apply(report(OpenStage::Functions, Some(0.05)), t0);
        assert_eq!(s.program, "libpython3.14.so");
        assert_eq!(
            s.counts_text().as_deref(),
            Some("12,410 functions found, 2,300 to look at")
        );
        s.apply(
            report(OpenStage::Functions, Some(0.25)),
            t0 + Duration::from_secs(10),
        );
        assert_eq!(s.estimate(t0 + Duration::from_secs(10)), None, "too early");
        s.apply(
            report(OpenStage::Functions, Some(0.45)),
            t0 + Duration::from_secs(40),
        );
        let left = s.estimate(t0 + Duration::from_secs(40)).unwrap();
        // 0.40 in 40 s: 0.55 left takes 55 s
        assert_eq!(left.as_secs(), 55);
        let mut cached = report(OpenStage::Functions, Some(0.5));
        cached.from_cache = true;
        s.apply(cached, t0 + Duration::from_secs(41));
        assert_eq!(s.estimate(t0 + Duration::from_secs(60)), None);
    }

    fn slow_demo(delay: Duration) -> (tokio::runtime::Runtime, ViewModel) {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let demo = {
            let _g = rt.enter();
            crate::demo::demo_project_loading(delay, 12_000).unwrap()
        };
        let mut vm = ViewModel::new(demo.backend.clone(), rt.handle().clone());
        vm.create_project(
            demo.binary.to_string_lossy(),
            demo.project_dir.to_string_lossy(),
        );
        (rt, vm)
    }

    #[test]
    fn the_loading_state_follows_the_open_to_the_end() {
        let (_rt, mut vm) = slow_demo(Duration::from_millis(300));
        let loading = vm.loading.as_ref().expect("loading at once");
        assert!(loading.creating);
        assert_eq!(loading.program, "libpython3.14.so");
        let seen = std::cell::RefCell::new(Vec::new());
        let opened = vm.block_until(Duration::from_secs(20), |v| {
            if let Some(l) = &v.loading {
                let mut s = seen.borrow_mut();
                if s.last() != Some(&l.stage()) {
                    s.push(l.stage());
                }
            }
            v.connection == crate::Connection::Open
        });
        assert!(opened, "{:?}", vm.toasts);
        assert!(
            vm.loading.is_none(),
            "the loading screen ends with the open"
        );
        let seen = seen.into_inner();
        assert!(seen.contains(&OpenStage::Functions), "{seen:?}");
        assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{seen:?}");
    }

    #[test]
    fn mid_open_the_screen_has_counts_and_cancel_stops_it() {
        let (_rt, mut vm) = slow_demo(Duration::from_secs(30));
        let mid = vm.block_until(Duration::from_secs(20), |v| {
            v.loading
                .as_ref()
                .is_some_and(|l| l.stage() == OpenStage::Functions && l.job_id().is_some())
        });
        assert!(mid, "reached the function search");
        let l = vm.loading.as_ref().unwrap();
        assert!(l.counts_text().unwrap().contains("functions found"));
        assert!(l.fraction().is_some());
        assert!(l.stages().contains(&OpenStage::Functions));
        let started = Instant::now();
        vm.cancel_open();
        assert!(vm.loading.as_ref().unwrap().cancelling);
        let stopped = vm.block_until(Duration::from_secs(10), |v| {
            v.connection == crate::Connection::NoProject
        });
        assert!(stopped, "{:?}", vm.connection);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(vm.loading.is_none());
        assert!(vm.toasts.iter().any(|t| t.text.contains("cancelled")));
    }

    #[test]
    fn numbers_read_well() {
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(clock(Duration::from_secs(65)), "1:05");
        assert_eq!(clock(Duration::from_secs(3723)), "1:02:03");
    }
}

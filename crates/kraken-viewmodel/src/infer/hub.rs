//! The GUI's view of the local models: what the serving service says about each of them (kept
//! fresh on a timer), and the actions the cards start (start, stop, "serve automatically"),
//! including the choices offered when a model does not fit in memory.
//!
//! The service is a [`ServingApi`]: the daemon connection of this window, or the manager of this
//! process (`--no-daemon`). Holds taken through it belong to this window and end with it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use kraken_host::infer::{AutostartReport, InferManager, ModelStatus, ServingApi, StartOptions};
use kraken_proto::ProtoError;
use kraken_proto::infer::DeviceInfo;
use tokio::runtime::Handle;

const BUSY_EVERY: Duration = Duration::from_secs(1);
const IDLE_EVERY: Duration = Duration::from_secs(3);
const DEVICES_EVERY: Duration = Duration::from_secs(10);

type Repaint = Arc<dyn Fn() + Send + Sync>;

/// One thing the person can do when a model does not fit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FitOption {
    /// Stop another model that holds the memory, then start this one.
    StopModel {
        /// The other model.
        id: String,
        /// Its name.
        name: String,
    },
    /// Run on the processor instead of the card.
    Cpu,
    /// Start although it does not seem to fit.
    StartAnyway,
}

impl FitOption {
    /// The button's text.
    pub fn label(&self) -> String {
        match self {
            FitOption::StopModel { name, .. } => format!("Stop {name}"),
            FitOption::Cpu => "Run on the processor".into(),
            FitOption::StartAnyway => "Start anyway".into(),
        }
    }

    /// What pressing it does, in a sentence.
    pub fn help(&self) -> &'static str {
        match self {
            FitOption::StopModel { .. } => {
                "Frees its memory for this model. The other model stops serving."
            }
            FitOption::Cpu => "Slower, but uses the computer's memory instead of the card's.",
            FitOption::StartAnyway => "It may fail to load, or slow the computer down.",
        }
    }
}

/// The question shown when a start was refused for lack of memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FitPrompt {
    /// The model that did not fit.
    pub model: String,
    /// Its name.
    pub name: String,
    /// What the service said, in plain words.
    pub message: String,
    /// The ways out, besides cancelling.
    pub options: Vec<FitOption>,
}

impl FitPrompt {
    /// Reads the options out of a `no_fit` error; `None` for any other error.
    pub fn from_error(model: &str, name: &str, e: &ProtoError) -> Option<FitPrompt> {
        let d = e.details.as_ref().filter(|d| d["reason"] == "no_fit")?;
        let options = d["choices"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| match c["kind"].as_str()? {
                        "stop_model" => Some(FitOption::StopModel {
                            id: c["model"].as_str()?.to_string(),
                            name: c["name"].as_str().unwrap_or_default().to_string(),
                        }),
                        "cpu" => Some(FitOption::Cpu),
                        "start_anyway" => Some(FitOption::StartAnyway),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(FitPrompt {
            model: model.to_string(),
            name: name.to_string(),
            message: e.message.clone(),
            options,
        })
    }
}

#[derive(Default)]
struct Shared {
    models: Vec<ModelStatus>,
    grace_secs: u64,
    devices: Vec<DeviceInfo>,
    devices_at: Option<Instant>,
    loaded: bool,
    polling: bool,
    had_error: bool,
    /// Asked for a fresh autostart (first look, or the service came back).
    wants_autostart: bool,
    error: Option<String>,
    service_error: Option<String>,
    fit: Option<FitPrompt>,
    busy: HashSet<String>,
    autostart: Option<AutostartReport>,
}

fn lock(m: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The local models as the window sees them.
pub struct ServingHub {
    api: Arc<dyn ServingApi>,
    rt: Handle,
    repaint: Option<Repaint>,
    shared: Arc<Mutex<Shared>>,
    next_poll: Instant,
    ticker: Option<Arc<InferManager>>,
    setup_requested: bool,
}

impl ServingHub {
    /// A hub over `api`; the first look also holds the models marked "serve automatically".
    pub fn new(api: Arc<dyn ServingApi>, rt: Handle) -> Self {
        ServingHub {
            api,
            rt,
            repaint: None,
            shared: Arc::new(Mutex::new(Shared {
                wants_autostart: true,
                ..Shared::default()
            })),
            next_poll: Instant::now(),
            ticker: None,
            setup_requested: false,
        }
    }

    /// Wakes the window when something changed.
    pub fn with_repaint(mut self, f: Repaint) -> Self {
        self.repaint = Some(f);
        self
    }

    /// Lets the hub run the manager's housekeeping (stopping idle models); for a manager that
    /// lives in this process.
    pub fn with_manager(mut self, m: Arc<InferManager>) -> Self {
        self.ticker = Some(m);
        self
    }

    /// Asks for the models now, and then every second while one runs (every few seconds
    /// otherwise). Call each frame; returns when to call again.
    pub fn poll(&mut self, now: Instant) -> Duration {
        if now >= self.next_poll && !lock(&self.shared).polling {
            lock(&self.shared).polling = true;
            let busy = lock(&self.shared).models.iter().any(|m| {
                m.is_running() || matches!(m.state, kraken_proto::infer::ModelState::Stopping)
            });
            self.next_poll = now + if busy { BUSY_EVERY } else { IDLE_EVERY };
            self.spawn_refresh();
        }
        self.next_poll.saturating_duration_since(now)
    }

    fn spawn_refresh(&self) {
        let (api, shared, ticker, repaint) = (
            self.api.clone(),
            self.shared.clone(),
            self.ticker.clone(),
            self.repaint.clone(),
        );
        self.rt.spawn(async move {
            refresh(api.as_ref(), &shared, ticker.as_deref()).await;
            if let Some(f) = &repaint {
                f();
            }
        });
    }

    /// Looks again now (after an action).
    pub fn refresh(&mut self) {
        self.next_poll = Instant::now();
    }

    /// The service this hub talks to, for work that starts models itself (the guided setup).
    pub fn api(&self) -> Arc<dyn ServingApi> {
        self.api.clone()
    }

    /// True once the service answered.
    pub fn loaded(&self) -> bool {
        lock(&self.shared).loaded
    }

    /// Why the service cannot be reached, if it cannot.
    pub fn error(&self) -> Option<String> {
        let s = lock(&self.shared);
        s.error.clone().or_else(|| s.service_error.clone())
    }

    /// Every model the service knows, in the configuration's order.
    pub fn models(&self) -> Vec<ModelStatus> {
        lock(&self.shared).models.clone()
    }

    /// One model.
    pub fn status(&self, id: &str) -> Option<ModelStatus> {
        lock(&self.shared)
            .models
            .iter()
            .find(|m| m.id == id)
            .cloned()
    }

    /// The cards of this computer.
    pub fn devices(&self) -> Vec<DeviceInfo> {
        lock(&self.shared).devices.clone()
    }

    /// Seconds a model keeps running after nothing uses it.
    pub fn grace_secs(&self) -> u64 {
        lock(&self.shared).grace_secs
    }

    /// What the automatic start did when the window opened.
    pub fn autostart_report(&self) -> Option<AutostartReport> {
        lock(&self.shared).autostart.clone()
    }

    /// True while a start or stop of `id` is on its way.
    pub fn busy(&self, id: &str) -> bool {
        lock(&self.shared).busy.contains(id)
    }

    /// The question to show, if a start was refused for lack of memory.
    pub fn fit_prompt(&self) -> Option<FitPrompt> {
        lock(&self.shared).fit.clone()
    }

    /// Starts serving `id`; it keeps running until it is stopped. A refusal for lack of memory
    /// becomes [`fit_prompt`](Self::fit_prompt); any other error shows in the card.
    pub fn start(&mut self, id: &str, opts: StartOptions) {
        let name = self.status(id).map_or_else(|| id.to_string(), |s| s.name);
        self.spawn_action(
            id,
            move |api, id| Box::pin(async move { api.start_model(&id, opts).await.map(|_| ()) }),
            Some(name),
        );
    }

    /// Stops `id`.
    pub fn stop(&mut self, id: &str) {
        self.spawn_action(
            id,
            |api, id| Box::pin(async move { api.stop_model(&id).await.map(|_| ()) }),
            None,
        );
    }

    /// Does what the person chose in the memory question.
    pub fn answer_fit(&mut self, option: &FitOption) {
        let Some(prompt) = lock(&self.shared).fit.take() else {
            return;
        };
        match option {
            FitOption::StartAnyway => self.start(
                &prompt.model,
                StartOptions {
                    force: true,
                    cpu: false,
                },
            ),
            FitOption::Cpu => self.start(
                &prompt.model,
                StartOptions {
                    force: false,
                    cpu: true,
                },
            ),
            FitOption::StopModel { id, .. } => {
                let (target, other) = (prompt.model.clone(), id.clone());
                let name = prompt.name.clone();
                self.spawn_action(
                    &target,
                    move |api, target| {
                        Box::pin(async move {
                            api.stop_model(&other).await?;
                            api.start_model(&target, StartOptions::default())
                                .await
                                .map(|_| ())
                        })
                    },
                    Some(name),
                );
            }
        }
    }

    /// Leaves the memory question without doing anything.
    pub fn cancel_fit(&mut self) {
        lock(&self.shared).fit = None;
    }

    /// Clears the last error shown for the service.
    pub fn clear_error(&mut self) {
        lock(&self.shared).error = None;
    }

    /// The person chose "Set up a model on this computer...". The guided setup picks this up.
    pub fn request_setup(&mut self) {
        self.setup_requested = true;
    }

    /// True once after [`request_setup`](Self::request_setup).
    pub fn take_setup_request(&mut self) -> bool {
        std::mem::take(&mut self.setup_requested)
    }

    #[allow(clippy::type_complexity)]
    fn spawn_action(
        &mut self,
        id: &str,
        run: impl FnOnce(
            Arc<dyn ServingApi>,
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), ProtoError>> + Send>,
        > + Send
        + 'static,
        fit_name: Option<String>,
    ) {
        {
            let mut s = lock(&self.shared);
            s.busy.insert(id.to_string());
            s.error = None;
        }
        let (api, shared, repaint, id) = (
            self.api.clone(),
            self.shared.clone(),
            self.repaint.clone(),
            id.to_string(),
        );
        self.rt.spawn(async move {
            let result = run(api, id.clone()).await;
            {
                let mut s = lock(&shared);
                s.busy.remove(&id);
                if let Err(e) = result {
                    match fit_name
                        .as_deref()
                        .and_then(|n| FitPrompt::from_error(&id, n, &e))
                    {
                        Some(p) => s.fit = Some(p),
                        None => s.error = Some(e.message),
                    }
                }
            }
            if let Some(f) = &repaint {
                f();
            }
        });
        self.next_poll = Instant::now();
    }
}

async fn refresh(api: &dyn ServingApi, shared: &Mutex<Shared>, ticker: Option<&InferManager>) {
    if let Some(m) = ticker {
        m.tick().await;
    }
    let wants = std::mem::take(&mut lock(shared).wants_autostart);
    let mut autostart_error = None;
    if wants {
        match api.autostart().await {
            Ok(r) => lock(shared).autostart = Some(r),
            Err(e) => autostart_error = Some(e.message),
        }
    }
    let models = api.models().await;
    let need_devices = {
        let s = lock(shared);
        s.devices_at.is_none_or(|t| t.elapsed() >= DEVICES_EVERY)
    };
    let devices = if need_devices {
        Some(api.devices().await)
    } else {
        None
    };
    let mut s = lock(shared);
    s.polling = false;
    match models {
        Ok(r) => {
            s.service_error = None;
            if autostart_error.is_some() {
                s.error = autostart_error;
            }
            s.models = r.models;
            s.grace_secs = r.grace_secs;
            s.loaded = true;
            if s.had_error {
                // The service came back (a restarted daemon forgets this window's holds).
                s.had_error = false;
                s.wants_autostart = true;
            }
        }
        Err(e) => {
            // The service is not there: try the automatic start again when it is.
            s.had_error = true;
            s.service_error = Some(format!(
                "Cannot reach the service that runs local models: {}",
                e.message
            ));
        }
    }
    if let Some(Ok(d)) = devices {
        s.devices = d.devices;
        s.devices_at = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use kraken_proto::infer::ModelState;

    use super::*;
    use crate::infer::fake::{FakeCall, FakeServing, stopped_status};

    struct Rig {
        rt: tokio::runtime::Runtime,
        fake: Arc<FakeServing>,
        hub: ServingHub,
    }

    fn rig(models: Vec<ModelStatus>) -> Rig {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let fake = Arc::new(FakeServing::new(models, Vec::new()));
        let hub = ServingHub::new(fake.clone(), rt.handle().clone());
        Rig { rt, fake, hub }
    }

    impl Rig {
        fn until(&mut self, what: &str, mut cond: impl FnMut(&ServingHub) -> bool) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                self.hub.poll(Instant::now());
                if cond(&self.hub) {
                    return;
                }
                assert!(Instant::now() < deadline, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn the_first_look_starts_the_automatic_models_and_shows_them() {
        let mut quiet = stopped_status("b", "B");
        quiet.autostart = false;
        let mut r = rig(vec![stopped_status("a", "A"), quiet]);
        r.until("a running", |h| h.status("a").is_some_and(|s| s.is_ready()));
        assert_eq!(r.hub.status("b").unwrap().state, ModelState::Stopped);
        assert_eq!(r.hub.autostart_report().unwrap().started, vec!["a"]);
        assert_eq!(
            r.fake
                .calls()
                .iter()
                .filter(|c| **c == FakeCall::Autostart)
                .count(),
            1,
            "only once"
        );
        let _ = &r.rt;
    }

    #[test]
    fn start_and_stop_go_to_the_service_and_show_up() {
        let mut quiet = stopped_status("b", "B");
        quiet.autostart = false;
        let mut r = rig(vec![quiet]);
        r.until("loaded", ServingHub::loaded);
        r.hub.start("b", StartOptions::default());
        r.until("ready", |h| h.status("b").is_some_and(|s| s.is_ready()));
        r.hub.stop("b");
        r.until("stopped", |h| {
            h.status("b")
                .is_some_and(|s| s.state == ModelState::Stopped)
                && !h.busy("b")
        });
        assert_eq!(
            r.fake.calls(),
            vec![
                FakeCall::Autostart,
                FakeCall::Start("b".into(), StartOptions::default()),
                FakeCall::Stop("b".into())
            ]
        );
    }

    #[test]
    fn running_out_of_memory_asks_and_each_answer_does_its_thing() {
        let mut other = stopped_status("o", "Other");
        other.autostart = false;
        let mut big = stopped_status("big", "Big");
        big.autostart = false;
        let mut r = rig(vec![other, big]);
        r.until("loaded", ServingHub::loaded);
        r.hub.start("o", StartOptions::default());
        r.until("other ready", |h| {
            h.status("o").is_some_and(|s| s.is_ready())
        });
        r.fake.refuse_start("big");

        r.hub.start("big", StartOptions::default());
        r.until("the question", |h| h.fit_prompt().is_some());
        let q = r.hub.fit_prompt().unwrap();
        assert!(q.message.contains("only 2.1 GB"));
        assert_eq!(
            q.options,
            vec![
                FitOption::StopModel {
                    id: "o".into(),
                    name: "Other".into()
                },
                FitOption::Cpu,
                FitOption::StartAnyway
            ]
        );
        assert!(r.hub.error().is_none(), "a question, not an error");

        r.hub.cancel_fit();
        assert!(r.hub.fit_prompt().is_none());

        r.hub.start("big", StartOptions::default());
        r.until("the question again", |h| h.fit_prompt().is_some());
        r.hub.answer_fit(&FitOption::StopModel {
            id: "o".into(),
            name: "Other".into(),
        });
        r.until("big ready", |h| {
            h.status("big").is_some_and(|s| s.is_ready())
        });
        assert_eq!(r.hub.status("o").unwrap().state, ModelState::Stopped);
    }

    #[test]
    fn the_cpu_and_start_anyway_answers_pass_their_options() {
        for (option, expect) in [
            (
                FitOption::Cpu,
                StartOptions {
                    force: false,
                    cpu: true,
                },
            ),
            (
                FitOption::StartAnyway,
                StartOptions {
                    force: true,
                    cpu: false,
                },
            ),
        ] {
            let mut big = stopped_status("big", "Big");
            big.autostart = false;
            let mut r = rig(vec![big]);
            r.until("loaded", ServingHub::loaded);
            r.fake.refuse_start("big");
            r.hub.start("big", StartOptions::default());
            r.until("the question", |h| h.fit_prompt().is_some());
            r.hub.answer_fit(&option);
            r.until("started", |h| h.status("big").is_some_and(|s| s.is_ready()));
            assert_eq!(
                r.fake.calls().last(),
                Some(&FakeCall::Start("big".into(), expect))
            );
        }
    }

    #[test]
    fn other_errors_show_as_text() {
        let mut r = rig(vec![]);
        r.until("loaded", ServingHub::loaded);
        r.hub.start("nope", StartOptions::default());
        r.until("an error", |h| h.error().is_some());
        assert!(r.hub.error().unwrap().contains("no local model"));
        assert!(r.hub.fit_prompt().is_none());
    }
}

//! The Setup status window (Help > Setup status) and the progress of machine-global jobs, with
//! no egui in it.
//!
//! `setup_status` lists what is installed and ready; the Install buttons start `setup_ghidra`,
//! `setup_native` and `setup_dotnet`, which run as daemon jobs (`job-gN`) that the hub polls with
//! `job_status` and stops with `job_cancel`. None of it needs an open project.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kraken_registry::commands::{GlobalJobOut, JobView, SetupItem, SetupState, SetupStatusOut};
use serde_json::{Value, json};
use tokio::runtime::Handle;

use crate::Backend;

const POLL: Duration = Duration::from_millis(400);

/// A machine-global job the window started.
#[derive(Debug, Clone)]
pub struct SetupJob {
    /// `job-g1`, ...
    pub job_id: String,
    /// The item it installs (`ghidra`, `native`, `dotnet`).
    pub item: String,
    /// Its latest state.
    pub view: Option<JobView>,
    /// Cancel was asked.
    pub cancelling: bool,
}

impl SetupJob {
    /// True while it works.
    pub fn running(&self) -> bool {
        self.view.as_ref().is_none_or(|v| !v.status.is_terminal())
    }

    /// One line for the status bar.
    pub fn line(&self) -> String {
        let msg = self
            .view
            .as_ref()
            .and_then(|v| v.progress.as_ref())
            .map(|p| p.message.clone())
            .filter(|m| !m.is_empty());
        let what = self
            .view
            .as_ref()
            .map_or(self.item.as_str(), |v| v.command.as_str());
        match msg {
            Some(m) => format!("{what}: {m}"),
            None => format!("{what}: starting"),
        }
    }

    /// Fraction done of the current download, when it has a size.
    pub fn fraction(&self) -> Option<f32> {
        let p = self.view.as_ref()?.progress.as_ref()?;
        (p.total > 0).then(|| (p.done as f32 / p.total as f32).clamp(0.0, 1.0))
    }
}

/// State of the window.
#[derive(Debug, Default)]
pub struct SetupState2 {
    /// The window is open.
    pub open: bool,
    /// What `setup_status` reported last.
    pub items: Vec<SetupItem>,
    /// The report has been read at least once.
    pub loaded: bool,
    /// Jobs started here, newest last.
    pub jobs: Vec<SetupJob>,
    /// The last message, with whether it is an error.
    pub message: Option<(String, bool)>,
    inflight: bool,
}

impl SetupState2 {
    /// The job installing `item` that is still running.
    pub fn running_for(&self, item: &str) -> Option<&SetupJob> {
        self.jobs.iter().find(|j| j.item == item && j.running())
    }

    /// The job whose progress the status bar shows.
    pub fn active(&self) -> Option<&SetupJob> {
        self.jobs.iter().rev().find(|j| j.running())
    }

    /// Parts that are ready and parts that are not.
    pub fn counts(&self) -> (usize, usize) {
        let ready = self
            .items
            .iter()
            .filter(|i| i.state == SetupState::Ready)
            .count();
        (ready, self.items.len() - ready)
    }
}

/// The command that installs `item`, if one does.
pub fn install_command(item: &SetupItem) -> Option<&'static str> {
    match item.fix_command.as_deref()? {
        "setup_ghidra" => Some("setup_ghidra"),
        "setup_native" => Some("setup_native"),
        "setup_dotnet" => Some("setup_dotnet"),
        "setup_rust" => Some("setup_rust"),
        "setup_sysroots" => Some("setup_sysroots"),
        _ => None,
    }
}

/// Talks to the backend for the window.
#[derive(Clone)]
pub struct SetupHub {
    state: Arc<Mutex<SetupState2>>,
    backend: Arc<dyn Backend>,
    rt: Handle,
    repaint: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for SetupHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetupHub").finish_non_exhaustive()
    }
}

impl SetupHub {
    /// A hub over `backend`; `repaint` wakes the window when a result arrives.
    pub fn new(
        backend: Arc<dyn Backend>,
        rt: Handle,
        repaint: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        SetupHub {
            state: Arc::new(Mutex::new(SetupState2::default())),
            backend,
            rt,
            repaint,
        }
    }

    /// The state, for drawing.
    pub fn state(&self) -> MutexGuard<'_, SetupState2> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens the window and reads the report.
    pub fn open(&self) {
        self.state().open = true;
        self.refresh();
    }

    /// Reads `setup_status` again.
    pub fn refresh(&self) {
        {
            let mut s = self.state();
            if s.inflight {
                return;
            }
            s.inflight = true;
        }
        let me = self.clone();
        self.rt.spawn(async move {
            let res = me.backend.call("setup_status", json!({})).await;
            let mut s = me.state();
            s.inflight = false;
            match res.map_err(|e| e.message).and_then(|v| {
                serde_json::from_value::<SetupStatusOut>(v).map_err(|e| e.to_string())
            }) {
                Ok(out) => {
                    s.items = out.items;
                    s.loaded = true;
                }
                Err(e) => s.message = Some((e, true)),
            }
            drop(s);
            (me.repaint)();
        });
    }

    /// Starts the install of `item` (the daemon asks the person first when an agent asks).
    pub fn install(&self, item: &SetupItem) {
        let Some(command) = install_command(item) else {
            return;
        };
        if self.state().running_for(&item.id).is_some() {
            return;
        }
        let (me, id, name) = (self.clone(), item.id.clone(), item.name.clone());
        self.state().message = None;
        self.rt.spawn(async move {
            let res = me.backend.call(command, json!({})).await;
            let started = res
                .map_err(|e| e.message)
                .and_then(|v| serde_json::from_value::<GlobalJobOut>(v).map_err(|e| e.to_string()));
            match started {
                Ok(out) => {
                    me.state().jobs.push(SetupJob {
                        job_id: out.job_id.clone(),
                        item: id,
                        view: None,
                        cancelling: false,
                    });
                    (me.repaint)();
                    me.watch(out.job_id, name).await;
                }
                Err(e) => {
                    me.state().message = Some((e, true));
                    (me.repaint)();
                }
            }
        });
    }

    async fn watch(&self, job_id: String, name: String) {
        loop {
            let res = self
                .backend
                .call("job_status", json!({ "job_id": job_id }))
                .await;
            let view = res.map_err(|e| e.message).and_then(|v: Value| {
                serde_json::from_value::<JobView>(v).map_err(|e| e.to_string())
            });
            let done;
            {
                let mut s = self.state();
                match view {
                    Ok(v) => {
                        done = v.status.is_terminal();
                        if done {
                            s.message = Some(match (&v.error, v.status) {
                                (Some(e), _) => (format!("{name}: {}", e.message), true),
                                (None, kraken_registry::JobStatus::Cancelled) => {
                                    (format!("{name}: cancelled"), false)
                                }
                                _ => (format!("{name}: done"), false),
                            });
                        }
                        if let Some(j) = s.jobs.iter_mut().find(|j| j.job_id == job_id) {
                            j.view = Some(v);
                        }
                    }
                    Err(e) => {
                        done = true;
                        s.message = Some((format!("{name}: {e}"), true));
                        s.jobs.retain(|j| j.job_id != job_id);
                    }
                }
            }
            (self.repaint)();
            if done {
                self.refresh();
                return;
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Stops a running job; a partial download is kept.
    pub fn cancel(&self, job_id: &str) {
        if let Some(j) = self.state().jobs.iter_mut().find(|j| j.job_id == job_id) {
            j.cancelling = true;
        }
        let (me, id) = (self.clone(), job_id.to_string());
        self.rt.spawn(async move {
            let _ = me.backend.call("job_cancel", json!({ "job_id": id })).await;
            (me.repaint)();
        });
    }
}

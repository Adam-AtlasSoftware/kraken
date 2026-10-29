//! Runs the window's commands in the background and keeps the state up to date.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use kraken_registry::commands::{EmulatorRunOut, IntegrationsListOut};
use serde_json::{Value, json};
use tokio::runtime::Handle;

use super::{IntegrationsState, RunDialog};
use crate::Backend;

/// Talks to the backend for the Integrations window. It does not need an open project: the
/// commands are about this computer.
#[derive(Clone)]
pub struct IntegrationsHub {
    state: Arc<Mutex<IntegrationsState>>,
    backend: Arc<dyn Backend>,
    rt: Handle,
    repaint: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for IntegrationsHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegrationsHub").finish_non_exhaustive()
    }
}

impl IntegrationsHub {
    /// A hub over `backend`; `repaint` wakes the window when a result arrives.
    pub fn new(
        backend: Arc<dyn Backend>,
        rt: Handle,
        repaint: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        IntegrationsHub {
            state: Arc::new(Mutex::new(IntegrationsState::default())),
            backend,
            rt,
            repaint,
        }
    }

    /// The state, for drawing.
    pub fn state(&self) -> MutexGuard<'_, IntegrationsState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens the window and reads the list.
    pub fn open(&self) {
        self.state().open = true;
        self.refresh();
    }

    /// Re-reads the catalogue.
    pub fn refresh(&self) {
        {
            let mut s = self.state();
            if s.inflight {
                return;
            }
            s.inflight = true;
            s.last_poll = Some(Instant::now());
        }
        let me = self.clone();
        self.rt.spawn(async move {
            let res = me.backend.call("integrations_list", json!({})).await;
            let mut s = me.state();
            s.inflight = false;
            match res.map_err(|e| e.message).and_then(|v| {
                serde_json::from_value::<IntegrationsListOut>(v).map_err(|e| e.to_string())
            }) {
                Ok(out) => {
                    s.rows = out.integrations;
                    s.loaded = true;
                    if s.selected.is_none() {
                        s.selected = s.rows.first().map(|r| r.id.clone());
                    }
                }
                Err(e) => s.message = Some((e, true)),
            }
            drop(s);
            (me.repaint)();
        });
    }

    /// Selects a card and clears what belonged to the previous one.
    pub fn select(&self, id: &str) {
        let mut s = self.state();
        if s.selected.as_deref() != Some(id) {
            s.selected = Some(id.to_string());
            s.accepted = false;
            s.path_input.clear();
        }
    }

    fn background(&self, id: &str, command: &'static str, args: Value, done: String) {
        {
            let mut s = self.state();
            if s.busy.iter().any(|b| b == id) {
                return;
            }
            s.busy.push(id.to_string());
            s.message = None;
        }
        let (me, id) = (self.clone(), id.to_string());
        self.rt.spawn(async move {
            let res = me.backend.call(command, args).await;
            {
                let mut s = me.state();
                s.busy.retain(|b| b != &id);
                s.message = Some(match res {
                    Ok(_) => (done, false),
                    Err(e) => (e.message, true),
                });
                s.last_poll = None;
                s.inflight = false;
            }
            me.refresh();
            (me.repaint)();
        });
    }

    /// Downloads and installs `id`; the licence was accepted in the window.
    pub fn install(&self, id: &str) {
        let name = self
            .state()
            .row(id)
            .map_or_else(|| id.to_string(), |r| r.name.clone());
        self.background(
            id,
            "integration_install",
            json!({ "id": id, "accept_licence": true }),
            format!("{name} is installed"),
        );
    }

    /// Uses the program at `path` for `id`.
    pub fn use_path(&self, id: &str, path: &str) {
        self.state().path_input.clear();
        self.background(
            id,
            "integration_use_path",
            json!({ "id": id, "path": path }),
            format!("Using {path}"),
        );
    }

    /// Removes KRAKEN's copy of `id` (the daemon asks the person first).
    pub fn remove(&self, id: &str) {
        self.background(
            id,
            "integration_remove",
            json!({ "id": id }),
            "Removed".to_string(),
        );
    }

    /// Opens the run dialog, with the first ready emulator chosen.
    pub fn run_dialog_open(&self) {
        {
            let mut s = self.state();
            let first = s.ready().first().map(|r| r.id.clone());
            s.run = Some(RunDialog {
                emulator: first,
                ..RunDialog::default()
            });
            s.last_run = None;
        }
        self.refresh();
    }

    /// Starts the emulator chosen in the run dialog (the daemon asks the person first).
    pub fn run_dialog_start(&self) {
        let args = {
            let mut s = self.state();
            let Some(d) = s.run.clone() else {
                return;
            };
            let Some(id) = d.emulator else {
                return;
            };
            s.running = true;
            s.message = None;
            json!({ "id": id, "target": d.what.wire(), "debug": d.debug })
        };
        let me = self.clone();
        self.rt.spawn(async move {
            let res = me.backend.call("emulator_run", args).await;
            let mut s = me.state();
            s.running = false;
            match res.map_err(|e| e.message).and_then(|v| {
                serde_json::from_value::<EmulatorRunOut>(v).map_err(|e| e.to_string())
            }) {
                Ok(out) => s.last_run = Some(out),
                Err(e) => s.message = Some((e, true)),
            }
            drop(s);
            (me.repaint)();
        });
    }
}

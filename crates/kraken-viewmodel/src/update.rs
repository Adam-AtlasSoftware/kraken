//! The update strip, the Updates window (Help > Check for updates...) and About, with no egui in
//! it (ADR 0015).
//!
//! The hub asks the [`UpdateBackend`] for the cached status at start, then for a check (at most
//! once a day). The strip offers What's new, Update now (or Copy command for an install a package
//! manager made), Skip this version and Later; Update now runs the backend's install and shows its
//! progress, then Restart now.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use kraken_registry::commands::{UpdateApplied, UpdateBackend, UpdateStatusOut};
use kraken_registry::jobs::JobProgress;
use tokio::runtime::Handle;

/// What the strip's main button does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripAction {
    /// KRAKEN installs the update itself.
    UpdateNow,
    /// The person runs this command (package-managed installs).
    CopyCommand(String),
    /// Open the release page (KRAKEN cannot tell how it was installed, or the release is not
    /// signed).
    Download(String),
}

/// What the strip shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StripView {
    /// The sentence.
    pub text: String,
    /// The main button.
    pub action: StripAction,
    /// The release notes.
    pub notes_url: Option<String>,
    /// The version the strip is about.
    pub version: String,
}

/// State of the strip and the windows.
#[derive(Debug, Default)]
pub struct UpdateUi {
    /// The last status.
    pub status: Option<UpdateStatusOut>,
    /// The Updates window is open.
    pub dialog_open: bool,
    /// The About window is open.
    pub about_open: bool,
    /// Later was pressed: hidden until the next start.
    pub dismissed: bool,
    /// A check runs.
    pub checking: bool,
    /// The install runs, with its latest progress.
    pub applying: Option<JobProgress>,
    /// The install finished: restart to use it.
    pub applied: Option<UpdateApplied>,
    /// The last message, with whether it is an error.
    pub message: Option<(String, bool)>,
}

impl UpdateUi {
    /// The strip, when there is something to say.
    pub fn strip(&self) -> Option<StripView> {
        if self.dismissed || self.applied.is_some() || self.applying.is_some() {
            return None;
        }
        self.strip_ignoring_dismissal()
    }

    /// The offer of an available update, also after Later (the Updates window shows it).
    pub fn strip_ignoring_dismissal(&self) -> Option<StripView> {
        let s = self.status.as_ref()?;
        let latest = s.latest.clone()?;
        if !s.update_available || s.skipped.as_deref() == Some(latest.as_str()) {
            return None;
        }
        let releases = s
            .notes_url
            .clone()
            .unwrap_or_else(|| "https://github.com/Adam-AtlasSoftware/kraken/releases".into());
        let head = format!("KRAKEN {latest} is available (you have {}).", s.version);
        let (text, action) = if s.install.can_self_update && s.latest_signed {
            (head, StripAction::UpdateNow)
        } else if let Some(c) = &s.install.command {
            (
                format!("{head} Your package manager installed KRAKEN, so it updates it: {c}"),
                StripAction::CopyCommand(c.clone()),
            )
        } else if s.install.can_self_update {
            (
                format!("{head} This release is not signed, so KRAKEN cannot install it itself."),
                StripAction::Download(releases.clone()),
            )
        } else {
            (head, StripAction::Download(releases.clone()))
        };
        Some(StripView {
            text,
            action,
            notes_url: s.notes_url.clone(),
            version: latest,
        })
    }
}

/// A backend that checks nothing (tests and screenshots).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUpdates;

fn no_updates() -> kraken_proto::ProtoError {
    kraken_proto::ProtoError::new(
        kraken_proto::ErrorCode::Unsupported,
        "update checks are not available here",
    )
}

#[async_trait::async_trait]
impl UpdateBackend for NoUpdates {
    fn status(&self) -> Result<UpdateStatusOut, kraken_proto::ProtoError> {
        Err(no_updates())
    }
    async fn check(&self, _force: bool) -> Result<UpdateStatusOut, kraken_proto::ProtoError> {
        Err(no_updates())
    }
    async fn apply(
        &self,
        _progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<UpdateApplied, kraken_proto::ProtoError> {
        Err(no_updates())
    }
    fn rollback(&self) -> Result<UpdateApplied, kraken_proto::ProtoError> {
        Err(no_updates())
    }
    fn skip(&self, _version: Option<String>) -> Result<(), kraken_proto::ProtoError> {
        Ok(())
    }
}

/// Talks to the update backend for the strip and the windows.
#[derive(Clone)]
pub struct UpdateHub {
    state: Arc<Mutex<UpdateUi>>,
    backend: Arc<dyn UpdateBackend>,
    rt: Handle,
    repaint: Arc<dyn Fn() + Send + Sync>,
}

impl std::fmt::Debug for UpdateHub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateHub").finish_non_exhaustive()
    }
}

impl UpdateHub {
    /// A hub over `backend`; `repaint` wakes the window when a result arrives.
    pub fn new(
        backend: Arc<dyn UpdateBackend>,
        rt: Handle,
        repaint: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        UpdateHub {
            state: Arc::new(Mutex::new(UpdateUi::default())),
            backend,
            rt,
            repaint,
        }
    }

    /// The state, for drawing.
    pub fn state(&self) -> MutexGuard<'_, UpdateUi> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the cached status, then checks when the last check is a day old (the GUI's start).
    pub fn start(&self) {
        self.run_check(false);
    }

    /// Checks now, even when the last check is recent (the window's Check now).
    pub fn check_now(&self) {
        self.run_check(true);
    }

    fn run_check(&self, force: bool) {
        {
            let mut s = self.state();
            if s.checking {
                return;
            }
            s.checking = true;
        }
        let me = self.clone();
        self.rt.spawn(async move {
            let b = me.backend.clone();
            if let Ok(Ok(st)) = tokio::task::spawn_blocking(move || b.status()).await {
                me.state().status = Some(st);
                (me.repaint)();
            }
            let res = me.backend.check(force).await;
            let mut s = me.state();
            s.checking = false;
            match res {
                Ok(st) => {
                    if force {
                        s.message = Some(match &st.last_error {
                            Some(e) => (e.clone(), true),
                            None => (st.summary.clone(), false),
                        });
                    }
                    s.status = Some(st);
                }
                Err(e) => s.message = Some((e.message, true)),
            }
            drop(s);
            (me.repaint)();
        });
    }

    /// Opens the Updates window.
    pub fn open_dialog(&self) {
        self.state().dialog_open = true;
        if self.state().status.is_none() {
            self.start();
        }
    }

    /// Opens the About window.
    pub fn open_about(&self) {
        self.state().about_open = true;
        if self.state().status.is_none() {
            self.start();
        }
    }

    /// Later: hides the strip until the next start.
    pub fn later(&self) {
        self.state().dismissed = true;
    }

    /// Skip this version: the strip stays away until a newer one is out.
    pub fn skip(&self, version: &str) {
        if let Some(st) = self.state().status.as_mut() {
            st.skipped = Some(version.to_string());
        }
        let (b, v) = (self.backend.clone(), version.to_string());
        self.rt.spawn_blocking(move || {
            let _ = b.skip(Some(v));
        });
    }

    /// Update now: downloads, verifies and installs, with progress in the state.
    pub fn apply(&self) {
        {
            let mut s = self.state();
            if s.applying.is_some() {
                return;
            }
            s.applying = Some(JobProgress {
                message: "starting".into(),
                ..Default::default()
            });
            s.message = None;
        }
        let me = self.clone();
        self.rt.spawn(async move {
            let on = {
                let me = me.clone();
                move |p: JobProgress| {
                    me.state().applying = Some(p);
                    (me.repaint)();
                }
            };
            let res = me.backend.apply(&on).await;
            let mut s = me.state();
            s.applying = None;
            match res {
                Ok(done) => {
                    s.message = Some((done.message.clone(), false));
                    s.applied = Some(done);
                }
                Err(e) => s.message = Some((e.message, true)),
            }
            drop(s);
            (me.repaint)();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_registry::commands::{InstallView, SystemView};

    fn status(can_self_update: bool, command: Option<&str>, signed: bool) -> UpdateStatusOut {
        UpdateStatusOut {
            version: "0.3.0".into(),
            target: "x86_64-unknown-linux-gnu".into(),
            build_channel: "release".into(),
            channel: "stable".into(),
            install: InstallView {
                kind: "script".into(),
                label: "install script into ~/.local".into(),
                can_self_update,
                self_update_blocked: None,
                command: command.map(str::to_string),
                program: "/x/bin/kraken-gui".into(),
            },
            system: SystemView {
                os: "Linux".into(),
                arch: "x86_64".into(),
                libc: "glibc".into(),
                session: "desktop".into(),
            },
            checks_enabled: true,
            checks_disabled_by: None,
            last_check: Some(1),
            latest: Some("0.4.0".into()),
            notes_url: Some(
                "https://github.com/Adam-AtlasSoftware/kraken/releases/tag/v0.4.0".into(),
            ),
            latest_signed: signed,
            update_available: true,
            skipped: None,
            last_error: None,
            rollback_to: None,
            summary: String::new(),
        }
    }

    #[test]
    fn the_strip_offers_what_the_install_allows() {
        let mut ui = UpdateUi {
            status: Some(status(true, None, true)),
            ..Default::default()
        };
        let s = ui.strip().expect("strip");
        assert_eq!(s.action, StripAction::UpdateNow);
        assert_eq!(s.text, "KRAKEN 0.4.0 is available (you have 0.3.0).");
        ui.status = Some(status(false, Some("yay -Syu kraken-workbench-bin"), true));
        let s = ui.strip().expect("strip");
        assert_eq!(
            s.action,
            StripAction::CopyCommand("yay -Syu kraken-workbench-bin".into())
        );
        assert!(s.text.contains("package manager installed KRAKEN"));
        ui.status = Some(status(true, None, false));
        assert!(matches!(
            ui.strip().expect("strip").action,
            StripAction::Download(_)
        ));
    }

    #[test]
    fn skipped_dismissed_or_current_shows_nothing() {
        let mut st = status(true, None, true);
        st.skipped = Some("0.4.0".into());
        let mut ui = UpdateUi {
            status: Some(st),
            ..Default::default()
        };
        assert!(ui.strip().is_none());
        ui.status = Some(status(true, None, true));
        ui.dismissed = true;
        assert!(ui.strip().is_none());
        ui.dismissed = false;
        let mut st = status(true, None, true);
        st.update_available = false;
        ui.status = Some(st);
        assert!(ui.strip().is_none());
    }
}

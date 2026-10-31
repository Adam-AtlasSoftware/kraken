//! The updater (ADR 0015): how KRAKEN was installed (`install`), the daily check (`check`), the
//! release signature (`verify`), installing and rolling back (`apply`) and the cached state
//! (`state`). [`HostUpdater`] is the backend of the `update_*` commands, `kraken update` and the
//! GUI's update strip.

pub mod apply;
pub mod check;
pub mod install;
pub mod state;
pub mod verify;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{UpdateApplied, UpdateBackend, UpdateStatusOut};
use kraken_registry::jobs::JobProgress;
use semver::Version;

use crate::config::{KrakenConfig, UpdateChannel, UpdateSettings};
use crate::provision::{Fetcher, ProvisionError};
use install::{InstallKind, Probe, SystemProbe};
use state::{UpdateState, now_secs};

/// What went wrong while checking or updating.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The check did not get a usable answer.
    #[error("update check failed: {0}")]
    Check(String),
    /// The release signature is missing or wrong.
    #[error("{0}")]
    Signature(String),
    /// A download failed.
    #[error(transparent)]
    Download(#[from] ProvisionError),
    /// The update was refused before anything was replaced (or was undone).
    #[error("{0}")]
    Refused(String),
    /// File system failure.
    #[error("{what}: {source}")]
    Io {
        /// What was attempted.
        what: String,
        /// The OS error.
        #[source]
        source: std::io::Error,
    },
}

impl From<UpdateError> for ProtoError {
    fn from(e: UpdateError) -> Self {
        let code = match &e {
            UpdateError::Check(_) | UpdateError::Download(_) => ErrorCode::Unsupported,
            UpdateError::Signature(_) | UpdateError::Refused(_) => ErrorCode::Unsupported,
            UpdateError::Io { .. } => ErrorCode::Internal,
        };
        ProtoError::new(code, e.to_string())
    }
}

/// The running program and how it was installed, worked out once per process. Later lookups
/// return the same path even after an update moved the running file away, so a restart starts
/// the new program.
pub fn this_install() -> &'static (PathBuf, InstallKind) {
    static INSTALL: OnceLock<(PathBuf, InstallKind)> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let exe = std::env::current_exe().unwrap_or_default();
        let exe = exe.canonicalize().unwrap_or(exe);
        let kind = install::detect(&exe, install::BUILD_CHANNEL, &SystemProbe);
        (exe, kind)
    })
}

/// The program to start after an update: the AppImage file, else the install's own path of
/// `name` (`kraken-gui`) beside the running one.
pub fn restart_program(name: &str) -> PathBuf {
    let (exe, kind) = this_install();
    match kind {
        InstallKind::AppImage { path } => path.clone(),
        _ => {
            let file = if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.to_string()
            };
            exe.with_file_name(file)
        }
    }
}

/// `kraken <version>` and the build facts, as `kraken --version` prints them.
pub fn version_text() -> String {
    let (_, kind) = this_install();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    format!(
        "kraken {}\ntarget: {}\nchannel: {}\ninstall: {}\n",
        install::VERSION,
        install::BUILD_TARGET,
        install::BUILD_CHANNEL,
        kind.label(home.as_deref())
    )
}

/// An environment lookup (the process's, or a fake one in tests).
pub type EnvFn = Arc<dyn Fn(&str) -> Option<OsString> + Send + Sync>;

/// The backend of the `update_*` commands.
pub struct HostUpdater {
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    env: EnvFn,
    exe: PathBuf,
    kind: InstallKind,
    current: Version,
    target: String,
    public_key: String,
    download_base: String,
    api: Option<Arc<dyn Fetcher>>,
    downloads: Option<Arc<dyn Fetcher>>,
    check_timeout: Duration,
    version_timeout: Duration,
}

impl std::fmt::Debug for HostUpdater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostUpdater")
            .field("data_dir", &self.data_dir)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl HostUpdater {
    /// This computer: the real install, data directory, config file and GitHub.
    pub fn system() -> Self {
        let (exe, kind) = this_install().clone();
        HostUpdater {
            data_dir: crate::llama_setup::data_dir_with(&|k| std::env::var_os(k)),
            config: KrakenConfig::default_path(),
            env: Arc::new(|k| std::env::var_os(k)),
            exe,
            kind,
            current: Version::parse(install::VERSION).unwrap_or(Version::new(0, 0, 0)),
            target: install::BUILD_TARGET.into(),
            public_key: verify::RELEASE_PUBLIC_KEY.into(),
            download_base: check::DOWNLOAD_BASE.into(),
            api: None,
            downloads: None,
            check_timeout: Duration::from_secs(15),
            version_timeout: Duration::from_secs(30),
        }
    }

    /// An updater over given parts (tests: a temporary install, a canned fetcher, a test key).
    #[allow(clippy::too_many_arguments)]
    pub fn with_parts(
        data_dir: PathBuf,
        config: Option<PathBuf>,
        exe: PathBuf,
        kind: InstallKind,
        current: Version,
        public_key: String,
        download_base: String,
        fetcher: Arc<dyn Fetcher>,
    ) -> Self {
        HostUpdater {
            data_dir: Some(data_dir),
            config,
            env: Arc::new(|_| None),
            exe,
            kind,
            current,
            target: install::BUILD_TARGET.into(),
            public_key,
            download_base,
            api: Some(fetcher.clone()),
            downloads: Some(fetcher),
            check_timeout: Duration::from_secs(15),
            version_timeout: Duration::from_secs(30),
        }
    }

    /// Uses `env` instead of the process environment (tests).
    pub fn with_env(mut self, env: EnvFn) -> Self {
        self.env = env;
        self
    }

    /// Updates as if built for `target` (tests).
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = target.into();
        self
    }

    /// Waits at most `t` for the staged `kraken --version` (tests).
    pub fn with_version_timeout(mut self, t: Duration) -> Self {
        self.version_timeout = t;
        self
    }

    /// Bounds the network check (the CLI's after-command refresh uses 3 s).
    pub fn with_check_timeout(mut self, t: Duration) -> Self {
        self.check_timeout = t;
        self
    }

    /// How KRAKEN was installed.
    pub fn kind(&self) -> &InstallKind {
        &self.kind
    }

    fn settings(&self) -> UpdateSettings {
        self.config
            .as_deref()
            .and_then(|p| KrakenConfig::from_file(p).ok())
            .map(|c| c.updates)
            .unwrap_or_default()
    }

    fn channel_name(c: UpdateChannel) -> &'static str {
        match c {
            UpdateChannel::Stable => "stable",
            UpdateChannel::Prerelease => "prerelease",
        }
    }

    /// What turns checks off, if anything.
    pub fn disabled_by(&self) -> Option<String> {
        check::disabled_by(&*self.env, self.settings().check)
    }

    fn data_dir(&self) -> Result<&Path, UpdateError> {
        self.data_dir.as_deref().ok_or_else(|| {
            UpdateError::Refused("cannot tell where KRAKEN's data directory is: set HOME".into())
        })
    }

    fn load_state(&self) -> UpdateState {
        self.data_dir
            .as_deref()
            .map(UpdateState::load)
            .unwrap_or_default()
    }

    fn save_state(&self, s: &UpdateState) {
        if let Some(d) = &self.data_dir
            && let Err(e) = s.save(d)
        {
            tracing::warn!(error = %e, "cannot save update-state.json");
        }
    }

    /// The status from the cache, without the network.
    pub fn status_now(&self) -> UpdateStatusOut {
        struct EnvProbe<'a>(&'a (dyn Fn(&str) -> Option<OsString> + Send + Sync));
        impl Probe for EnvProbe<'_> {
            fn var(&self, key: &str) -> Option<OsString> {
                (self.0)(key).filter(|v| !v.is_empty())
            }
            fn run(&self, program: &str, args: &[&str]) -> Option<String> {
                SystemProbe.run(program, args)
            }
            fn owned_and_writable(&self, path: &Path) -> bool {
                SystemProbe.owned_and_writable(path)
            }
        }
        let probe = EnvProbe(&*self.env);
        let settings = self.settings();
        let st = self.load_state();
        let latest = st.latest.as_deref().and_then(|v| Version::parse(v).ok());
        // After an update that was not followed by a restart, the files on disk are newer.
        let on_disk = self
            .data_dir
            .as_deref()
            .map(|d| apply::installed_version(&self.kind, d, &self.current))
            .unwrap_or_else(|| self.current.clone());
        let update_available = latest
            .as_ref()
            .is_some_and(|l| check::is_newer(l, &on_disk));
        let latest_text = latest.as_ref().map(ToString::to_string);
        let install = install::view(&self.kind, &self.exe, latest_text.as_deref(), &probe);
        let disabled = check::disabled_by(&*self.env, settings.check);
        let summary = summary(
            &self.current.to_string(),
            latest_text.as_deref(),
            update_available,
            st.latest_signed,
            &install,
        );
        UpdateStatusOut {
            version: self.current.to_string(),
            target: install::BUILD_TARGET.into(),
            build_channel: install::BUILD_CHANNEL.into(),
            channel: Self::channel_name(settings.channel).into(),
            install,
            system: install::system(&probe),
            checks_enabled: disabled.is_none(),
            checks_disabled_by: disabled,
            last_check: st.checked_at,
            latest: latest_text,
            notes_url: st.notes_url,
            latest_signed: st.latest_signed,
            update_available,
            skipped: st.skipped,
            last_error: st.last_error,
            rollback_to: self.data_dir.as_deref().and_then(apply::rollback_target),
            summary,
        }
    }

    fn api_fetcher(&self) -> Result<Arc<dyn Fetcher>, UpdateError> {
        match &self.api {
            Some(f) => Ok(f.clone()),
            None => Ok(Arc::new(check::api_fetcher(self.check_timeout)?)),
        }
    }

    /// Asks GitHub when due (or `force`) and records the answer.
    pub async fn check_now(&self, force: bool) -> UpdateStatusOut {
        let settings = self.settings();
        let channel = Self::channel_name(settings.channel);
        let now = now_secs();
        let mut st = self.load_state();
        let due = force
            || (check::disabled_by(&*self.env, settings.check).is_none() && st.stale(now, channel));
        if due && self.data_dir.is_some() {
            let result = match self.api_fetcher() {
                Ok(f) => check::latest(f.as_ref(), settings.channel).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(found) => {
                    st.latest = found.as_ref().map(|f| f.version.to_string());
                    st.notes_url = found.as_ref().map(|f| f.notes_url.clone());
                    st.latest_signed = found.as_ref().is_some_and(|f| f.signed);
                    st.last_error = None;
                }
                Err(e) => st.last_error = Some(e.to_string()),
            }
            st.checked_at = Some(now);
            st.channel = Some(channel.into());
            self.save_state(&st);
        }
        self.status_now()
    }

    /// The line the CLI prints after an interactive command, at most once a day, and the
    /// one-time notice that checks exist. Records that it was shown.
    pub fn take_cli_notice(&self) -> Option<String> {
        if self.disabled_by().is_some() {
            return None;
        }
        let mut st = self.load_state();
        if !st.first_notice_shown {
            st.first_notice_shown = true;
            self.save_state(&st);
            return Some(FIRST_NOTICE.into());
        }
        let now = now_secs();
        if !st.notice_due(now) {
            return None;
        }
        let line = notice_line(&self.status_now())?;
        st.last_notice = Some(now);
        self.save_state(&st);
        Some(line)
    }

    /// True when the cache is old enough for a check and checks are on.
    pub fn check_due(&self) -> bool {
        let s = self.settings();
        self.disabled_by().is_none()
            && self
                .load_state()
                .stale(now_secs(), Self::channel_name(s.channel))
    }

    /// Records that the person was just told (the GUI's Later).
    pub fn snooze(&self) {
        let mut st = self.load_state();
        st.last_notice = Some(now_secs());
        self.save_state(&st);
    }

    async fn apply_now(
        &self,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<UpdateApplied, UpdateError> {
        let data_dir = self.data_dir()?.to_path_buf();
        if !self.kind.self_updating() {
            return Err(UpdateError::Refused(match self.kind.command(None) {
                Some(c) => format!("your package manager installed KRAKEN, so it updates it: {c}"),
                None => format!(
                    "KRAKEN cannot tell how it was installed; download the new version from {}",
                    install::RELEASES_URL
                ),
            }));
        }
        progress(JobProgress {
            phase: "check".into(),
            message: "asking GitHub for the newest release".into(),
            ..Default::default()
        });
        let settings = self.settings();
        let api = self.api_fetcher()?;
        let found = check::latest(api.as_ref(), settings.channel)
            .await?
            .ok_or_else(|| UpdateError::Refused("GitHub lists no release".into()))?;
        let downloads: Arc<dyn Fetcher> = match &self.downloads {
            Some(f) => f.clone(),
            None => Arc::new(check::download_fetcher()?),
        };
        let ctx = apply::ApplyContext {
            kind: self.kind.clone(),
            current: self.current.clone(),
            target: self.target.clone(),
            data_dir,
            public_key: self.public_key.clone(),
            download_base: self.download_base.clone(),
            version_timeout: self.version_timeout,
        };
        apply::install(&ctx, downloads.as_ref(), &found.version, progress).await
    }
}

/// The one-time notice of the CLI.
pub const FIRST_NOTICE: &str = "KRAKEN checks once a day whether a new version is out (it sends only its version to GitHub). Turn it off with `kraken config-set --key updates.check --value false` or KRAKEN_NO_UPDATE_CHECK=1.";

/// One line about a new version for a person, if there is one they did not skip.
pub fn notice_line(s: &UpdateStatusOut) -> Option<String> {
    let latest = s.latest.as_deref()?;
    if !s.update_available || s.skipped.as_deref() == Some(latest) {
        return None;
    }
    let how = if s.install.can_self_update {
        "run kraken update".to_string()
    } else if let Some(c) = &s.install.command {
        c.clone()
    } else {
        format!("see {}", install::RELEASES_URL)
    };
    Some(format!(
        "KRAKEN {latest} is available (you have {}): {how}",
        s.version
    ))
}

fn summary(
    current: &str,
    latest: Option<&str>,
    available: bool,
    signed: bool,
    install: &kraken_registry::commands::InstallView,
) -> String {
    match latest {
        None => format!("KRAKEN {current}; no update check has succeeded yet."),
        Some(l) if !available => format!("KRAKEN {current} is up to date (newest release: {l})."),
        Some(l) if install.can_self_update && !signed => format!(
            "KRAKEN {l} is out, but its release is not signed, so KRAKEN cannot install it; download it from {}.",
            install::RELEASES_URL
        ),
        Some(l) if install.can_self_update => {
            format!("KRAKEN {l} is available (you have {current}); run `kraken update`.")
        }
        Some(l) => match &install.command {
            Some(c) => format!(
                "KRAKEN {l} is available (you have {current}). Your {} updates it: {c}",
                install.label
            ),
            None => format!(
                "KRAKEN {l} is available (you have {current}); download it from {}.",
                install::RELEASES_URL
            ),
        },
    }
}

#[async_trait]
impl UpdateBackend for HostUpdater {
    fn status(&self) -> Result<UpdateStatusOut, ProtoError> {
        Ok(self.status_now())
    }

    async fn check(&self, force: bool) -> Result<UpdateStatusOut, ProtoError> {
        Ok(self.check_now(force).await)
    }

    async fn apply(
        &self,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<UpdateApplied, ProtoError> {
        Ok(self.apply_now(progress).await?)
    }

    fn rollback(&self) -> Result<UpdateApplied, ProtoError> {
        let d = self.data_dir()?.to_path_buf();
        Ok(apply::rollback(&d, &self.current.to_string())?)
    }

    fn skip(&self, version: Option<String>) -> Result<(), ProtoError> {
        let mut st = self.load_state();
        st.skipped = version;
        self.save_state(&st);
        Ok(())
    }
}

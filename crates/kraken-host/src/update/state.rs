//! `<data dir>/update-state.json`: the last check, the skipped version and when the person was
//! last told.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One day in seconds: checks and notices happen at most this often.
pub const DAY_SECS: u64 = 24 * 60 * 60;

/// What is kept between runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    /// Unix seconds of the last check that reached GitHub (or failed).
    pub checked_at: Option<u64>,
    /// The newest release seen, without the `v`.
    pub latest: Option<String>,
    /// Its release page.
    pub notes_url: Option<String>,
    /// It carries `SHA256SUMS.minisig`.
    pub latest_signed: bool,
    /// The channel the check used.
    pub channel: Option<String>,
    /// What went wrong in the last check.
    pub last_error: Option<String>,
    /// The person chose to skip this version.
    pub skipped: Option<String>,
    /// Unix seconds of the last notice about a new version.
    pub last_notice: Option<u64>,
    /// The one-time notice that KRAKEN checks for updates was shown.
    pub first_notice_shown: bool,
}

impl UpdateState {
    /// `<data dir>/update-state.json`.
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("update-state.json")
    }

    /// Reads the file; a missing or broken file is an empty state.
    pub fn load(data_dir: &Path) -> UpdateState {
        std::fs::read(Self::path(data_dir))
            .ok()
            .filter(|b| b.len() < 64 * 1024)
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Writes the file in one step (a temporary file renamed over it), readable by the user only.
    pub fn save(&self, data_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::path(data_dir);
        let tmp = data_dir.join(format!(".update-state.{}.tmp", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    }

    /// True when the last check is more than a day old (or there was none), or used another
    /// channel.
    pub fn stale(&self, now: u64, channel: &str) -> bool {
        self.channel.as_deref() != Some(channel)
            || self
                .checked_at
                .is_none_or(|t| now.saturating_sub(t) >= DAY_SECS || t > now)
    }

    /// True when a notice about a new version may be shown now.
    pub fn notice_due(&self, now: u64) -> bool {
        self.last_notice
            .is_none_or(|t| now.saturating_sub(t) >= DAY_SECS || t > now)
    }
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_ages_by_the_day() {
        let d = tempfile::tempdir().expect("tmp");
        assert_eq!(UpdateState::load(d.path()), UpdateState::default());
        let s = UpdateState {
            checked_at: Some(1000),
            latest: Some("0.4.0".into()),
            channel: Some("stable".into()),
            skipped: Some("0.4.0".into()),
            ..Default::default()
        };
        s.save(d.path()).expect("save");
        assert_eq!(UpdateState::load(d.path()), s);
        assert!(!s.stale(1000 + DAY_SECS - 1, "stable"));
        assert!(s.stale(1000 + DAY_SECS, "stable"));
        assert!(s.stale(1001, "prerelease"));
        // A clock that went backwards counts as stale rather than never checking again.
        assert!(s.stale(10, "stable"));
        assert!(s.notice_due(5));
        std::fs::write(UpdateState::path(d.path()), "not json").expect("write");
        assert_eq!(UpdateState::load(d.path()), UpdateState::default());
    }
}

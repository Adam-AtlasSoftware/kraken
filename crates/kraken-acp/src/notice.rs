//! The one-time warning shown before the first terminal agent is used (decision 50).
//!
//! KRAKEN's safety model (additive edits auto-apply, everything else is a proposal, every change
//! is logged and undoable) covers what happens through KRAKEN's own tools. A terminal agent also
//! has its own tools for running commands and editing files, and KRAKEN does not sandbox those.
//! The stance is "warn only": show this text, remember that it was shown, and do not block.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bump when [`WARNING_TEXT`] changes in substance, so people see it again.
pub const WARNING_VERSION: u32 = 1;

/// The title of the warning.
pub const WARNING_TITLE: &str = "Terminal agents work outside KRAKEN's safety net";

/// The warning. Plain language, for people new to reverse engineering. Every UI must show this
/// text (or a faithful rendering of it) before an agent is used for the first time.
pub const WARNING_TEXT: &str = "\
Terminal agents such as Claude Code, Codex and Gemini CLI bring their own tools. Besides the \
KRAKEN tools they are connected to, they can usually run shell commands and read, change or \
delete files on this computer, in your name.

KRAKEN's protections do not cover those tools. KRAKEN's own edits stay logged, tagged with the \
agent that made them, and can be undone, but KRAKEN does not sandbox the agent itself, does not \
watch what it runs and cannot undo what it does to your files.

Only use an agent you trust, with a project you can afford to lose, and read each permission \
request before you approve it. If the binary you are analysing is malware, remember that the \
agent reads untrusted data: a malicious file can try to talk the agent into running commands.

KRAKEN never gives agents its own settings or keys. Each agent signs in by itself and uses its \
own account.";

const ACK_FILE: &str = "acp-warning.json";

/// What is stored when the warning was shown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acknowledgement {
    /// The [`WARNING_VERSION`] that was shown.
    pub version: u32,
    /// Seconds since the Unix epoch.
    pub shown_at: u64,
}

/// Persistent record that the warning was shown, in KRAKEN's config dir.
#[derive(Debug, Clone)]
pub struct NoticeStore {
    path: PathBuf,
}

impl NoticeStore {
    /// A store keeping its file in `config_dir`.
    pub fn in_config_dir(config_dir: &Path) -> Self {
        NoticeStore {
            path: config_dir.join(ACK_FILE),
        }
    }

    /// The file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when the current version of the warning was already shown. An unreadable or
    /// outdated file counts as "not shown".
    pub fn is_acknowledged(&self) -> bool {
        let Ok(text) = fs::read_to_string(&self.path) else {
            return false;
        };
        serde_json::from_str::<Acknowledgement>(&text).is_ok_and(|a| a.version >= WARNING_VERSION)
    }

    /// Records that the warning was shown now.
    pub fn acknowledge(&self) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let ack = Acknowledgement {
            version: WARNING_VERSION,
            shown_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        };
        let text = serde_json::to_string_pretty(&ack).map_err(std::io::Error::other)?;
        fs::write(&self.path, format!("{text}\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acknowledgement_round_trips() {
        let d = tempfile::tempdir().expect("tempdir");
        let store = NoticeStore::in_config_dir(&d.path().join("cfg"));
        assert!(!store.is_acknowledged());
        store.acknowledge().expect("write");
        assert!(store.is_acknowledged());
        assert!(NoticeStore::in_config_dir(&d.path().join("cfg")).is_acknowledged());
    }

    #[test]
    fn an_older_or_broken_acknowledgement_does_not_count() {
        let d = tempfile::tempdir().expect("tempdir");
        let store = NoticeStore::in_config_dir(d.path());
        fs::write(store.path(), "{\"version\":0,\"shown_at\":1}").expect("write");
        assert!(!store.is_acknowledged());
        fs::write(store.path(), "not json").expect("write");
        assert!(!store.is_acknowledged());
    }

    #[test]
    fn the_warning_says_what_matters() {
        for needle in ["shell commands", "sandbox", "permission", "own account"] {
            assert!(WARNING_TEXT.contains(needle), "missing {needle}");
        }
    }
}

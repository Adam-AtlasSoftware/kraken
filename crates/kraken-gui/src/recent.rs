//! Small GUI preferences kept in a JSON file next to `config.toml`: the recent-projects list and
//! the theme.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Most projects remembered.
pub const MAX_RECENT: usize = 10;

/// One remembered project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentProject {
    /// Project folder.
    pub path: String,
    /// Short name (the program's file name).
    pub name: String,
    /// When it was last opened, milliseconds since the Unix epoch.
    pub opened_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    dark: Option<bool>,
    #[serde(default)]
    recent: Vec<RecentProject>,
}

/// The preferences and the file they live in.
#[derive(Debug, Default)]
pub struct Prefs {
    file: Option<PathBuf>,
    dark: Option<bool>,
    items: Vec<RecentProject>,
}

/// `gui.json` in the directory of `config.toml`.
pub fn default_file() -> Option<PathBuf> {
    kraken_host::KrakenConfig::default_path().map(|p| p.with_file_name("gui.json"))
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl Prefs {
    /// Loads the preferences from `file`. A missing or damaged file means defaults; projects
    /// whose folder is gone are dropped.
    pub fn load(file: Option<PathBuf>) -> Self {
        let stored: Stored = file
            .as_deref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        let mut items = stored.recent;
        items.retain(|r| Path::new(&r.path).is_dir());
        items.truncate(MAX_RECENT);
        Prefs {
            file,
            dark: stored.dark,
            items,
        }
    }

    /// The saved theme: `Some(true)` dark, `Some(false)` light, `None` never chosen.
    pub fn dark(&self) -> Option<bool> {
        self.dark
    }

    /// Remembers the theme and saves.
    pub fn set_dark(&mut self, dark: bool) {
        if self.dark != Some(dark) {
            self.dark = Some(dark);
            self.save();
        }
    }

    /// The remembered projects, most recent first.
    pub fn items(&self) -> &[RecentProject] {
        &self.items
    }

    /// Moves `path` to the front (adding it if new) and saves.
    pub fn touch(&mut self, path: &str, name: &str, now_ms: u64) {
        self.items.retain(|r| r.path != path);
        self.items.insert(
            0,
            RecentProject {
                path: path.to_string(),
                name: name.to_string(),
                opened_ms: now_ms,
            },
        );
        self.items.truncate(MAX_RECENT);
        self.save();
    }

    /// Forgets `path` and saves.
    pub fn remove(&mut self, path: &str) {
        self.items.retain(|r| r.path != path);
        self.save();
    }

    /// Forgets every project and saves.
    pub fn clear(&mut self) {
        self.items.clear();
        self.save();
    }

    fn save(&self) {
        let Some(file) = &self.file else {
            return;
        };
        let stored = Stored {
            dark: self.dark,
            recent: self.items.clone(),
        };
        let Ok(text) = serde_json::to_string_pretty(&stored) else {
            return;
        };
        if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = file.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, file);
        }
    }
}

/// "3 min ago" style text for the list.
pub fn ago(now_ms: u64, then_ms: u64) -> String {
    let s = now_ms.saturating_sub(then_ms) / 1000;
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_orders_dedupes_caps_and_persists() {
        let tmp = crate::testutil::tempdir();
        let file = tmp.path().join("cfg/gui.json");
        let dirs: Vec<PathBuf> = (0..12)
            .map(|i| {
                let d = tmp.path().join(format!("p{i}"));
                std::fs::create_dir_all(&d).unwrap();
                d
            })
            .collect();
        let mut r = Prefs::load(Some(file.clone()));
        assert!(r.items().is_empty());
        for (i, d) in dirs.iter().enumerate() {
            r.touch(&d.to_string_lossy(), &format!("prog{i}"), i as u64);
        }
        assert_eq!(r.items().len(), MAX_RECENT);
        assert_eq!(r.items()[0].name, "prog11");
        // Opening an old one again moves it to the front, without a duplicate.
        r.touch(&dirs[5].to_string_lossy(), "prog5", 99);
        assert_eq!(r.items()[0].name, "prog5");
        assert_eq!(r.items().iter().filter(|i| i.name == "prog5").count(), 1);

        r.set_dark(false);
        let again = Prefs::load(Some(file));
        assert_eq!(again.items(), r.items());
        assert_eq!(again.dark(), Some(false));
    }

    #[test]
    fn vanished_folders_and_damaged_files_are_dropped() {
        let tmp = crate::testutil::tempdir();
        let file = tmp.path().join("r.json");
        std::fs::write(&file, "not json").unwrap();
        assert!(Prefs::load(Some(file.clone())).items().is_empty());

        let live = tmp.path().join("live");
        std::fs::create_dir_all(&live).unwrap();
        let mut r = Prefs::load(Some(file.clone()));
        r.touch(&live.to_string_lossy(), "live", 1);
        r.touch(&tmp.path().join("gone").to_string_lossy(), "gone", 2);
        let again = Prefs::load(Some(file));
        assert_eq!(again.items().len(), 1);
        assert_eq!(again.items()[0].name, "live");

        r.remove(&live.to_string_lossy());
        assert_eq!(r.items().len(), 1, "only `gone` is left");
    }

    #[test]
    fn ago_is_plain() {
        assert_eq!(ago(10_000, 9_000), "just now");
        assert_eq!(ago(200_000, 20_000), "3 min ago");
        assert_eq!(ago(7_300_000, 0), "2 h ago");
        assert_eq!(ago(200_000_000, 0), "2 d ago");
    }
}

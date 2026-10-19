//! What a terminal agent may do with its own tools without asking: the `[permissions]` table.
//!
//! ```toml
//! [permissions]
//! default = "ask"            # ask | allow | deny: for a tool no list names
//! allow = ["read", "edit"]   # tool kinds, or the first word of a tool's title
//! deny = ["delete", "fetch"] # a deny entry always wins
//! ```
//!
//! An entry matches a tool by its kind (`read`, `edit`, `execute`, `delete`, `fetch`...) or by
//! the first word of its title, lower-case; `*` at the end matches any ending. The card in the
//! assistant offers "Allow once", "Always for this tool" (adds the tool to `allow`) and "Deny".
//! The rewrite pipeline never reads this table: its terminal agent runs with every request
//! denied.

use std::path::Path;

use kraken_host::KrakenConfig;
use serde::{Deserialize, Serialize};

use crate::error::AssistError;

/// What to do with a tool that no list names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    /// Show the permission card.
    #[default]
    Ask,
    /// Allow without asking.
    Allow,
    /// Refuse without asking.
    Deny,
}

/// The answer of the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    /// Show the card.
    Ask,
}

/// The `[permissions]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PermissionRules {
    pub default: DefaultMode,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

/// The identity of a tool for the rules: its kind when the agent says one, else the first word
/// of its title, lower-case.
pub fn tool_key(title: &str, kind: Option<&str>) -> String {
    match kind.map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => k.to_lowercase(),
        None => title
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('`')
            .to_lowercase(),
    }
}

fn matches(entry: &str, key: &str, title: &str) -> bool {
    let e = entry.trim().to_lowercase();
    if e.is_empty() {
        return false;
    }
    let hit = |s: &str| match e.strip_suffix('*') {
        Some(prefix) => s.starts_with(prefix),
        None => s == e,
    };
    hit(key) || hit(&title.trim().to_lowercase())
}

impl PermissionRules {
    /// The `[permissions]` table of a whole `config.toml`; the defaults when it is missing.
    pub fn from_config_text(text: &str) -> Result<Self, String> {
        let table: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        match table.get("permissions") {
            None => Ok(PermissionRules::default()),
            Some(v) => v
                .clone()
                .try_into::<PermissionRules>()
                .map_err(|e| format!("[permissions]: {e}")),
        }
    }

    /// The rules of the config file at `path`; the defaults (ask for everything) when the file
    /// or table is missing or does not parse.
    pub fn load(path: Option<&Path>) -> Self {
        path.and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| Self::from_config_text(&t).ok())
            .unwrap_or_default()
    }

    /// What to do with the tool `title` of kind `kind`. Deny beats allow beats the default.
    pub fn decide(&self, title: &str, kind: Option<&str>) -> Verdict {
        let key = tool_key(title, kind);
        if self.deny.iter().any(|e| matches(e, &key, title)) {
            return Verdict::Deny;
        }
        if self.allow.iter().any(|e| matches(e, &key, title)) {
            return Verdict::Allow;
        }
        match self.default {
            DefaultMode::Ask => Verdict::Ask,
            DefaultMode::Allow => Verdict::Allow,
            DefaultMode::Deny => Verdict::Deny,
        }
    }

    /// Adds `key` to `allow` in the config file at `path`, keeping everything else.
    pub fn allow_always(path: &Path, key: &str) -> Result<(), AssistError> {
        let key = key.trim().to_lowercase();
        if key.is_empty() {
            return Err(AssistError::Config("no tool to allow".into()));
        }
        let mut rules = Self::load(Some(path));
        rules.deny.retain(|d| d.trim().to_lowercase() != key);
        if !rules.allow.iter().any(|a| a.trim().to_lowercase() == key) {
            rules.allow.push(key);
        }
        let mut file =
            KrakenConfig::from_file(path).map_err(|e| AssistError::Config(e.to_string()))?;
        file.permissions =
            Some(serde_json::to_value(&rules).map_err(|e| AssistError::Config(e.to_string()))?);
        file.save(path)
            .map_err(|e| AssistError::Config(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> PermissionRules {
        PermissionRules::from_config_text(text).expect("parses")
    }

    #[test]
    fn nothing_configured_asks() {
        let r = rules("");
        assert_eq!(r.decide("Run ls", Some("execute")), Verdict::Ask);
    }

    #[test]
    fn allow_deny_and_default_apply_in_that_order() {
        let r = rules(
            "[permissions]\ndefault = \"deny\"\nallow = [\"read\", \"edit\"]\ndeny = [\"edit\"]\n",
        );
        assert_eq!(r.decide("Read file", Some("read")), Verdict::Allow);
        assert_eq!(r.decide("Edit main.rs", Some("edit")), Verdict::Deny);
        assert_eq!(r.decide("Run ls", Some("execute")), Verdict::Deny);
    }

    #[test]
    fn entries_match_the_title_word_and_globs() {
        let r = rules("[permissions]\nallow = [\"grep\", \"web*\"]\n");
        assert_eq!(r.decide("Grep `foo`", None), Verdict::Allow);
        assert_eq!(r.decide("WebFetch https://x", None), Verdict::Allow);
        assert_eq!(r.decide("Bash rm -rf", None), Verdict::Ask);
    }

    #[test]
    fn unknown_keys_are_an_error_not_silently_ignored() {
        assert!(PermissionRules::from_config_text("[permissions]\nalow = []\n").is_err());
    }

    #[test]
    fn always_writes_the_tool_and_keeps_the_rest() {
        let dir = std::env::temp_dir().join(format!("kraken-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "per_run_cap = 3\n[permissions]\ndeny = [\"delete\"]\n",
        )
        .expect("write");
        PermissionRules::allow_always(&path, "Execute").expect("saved");
        PermissionRules::allow_always(&path, "execute").expect("saved twice");
        let r = PermissionRules::load(Some(&path));
        assert_eq!(r.allow, vec!["execute".to_string()]);
        assert_eq!(r.deny, vec!["delete".to_string()]);
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("per_run_cap = 3")
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

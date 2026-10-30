//! The settings `config_get` and `config_set` reach, and the store that reads and writes them.
//!
//! An allowlist of non-secret keys of `config.toml`. Provider tables, API keys, local model
//! entries and the assistant's shell rules are not on it: they can hold credentials or grant
//! shell access, and are edited in the file or their own screens.

use std::path::{Path, PathBuf};

use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{ConfigEntry, ConfigStore};

use crate::config::KrakenConfig;

/// One setting that `config_get` and `config_set` reach.
#[derive(Debug, Clone, Copy)]
pub struct ConfigKey {
    /// Dotted path in the file (`daemon.idle_secs`).
    pub name: &'static str,
    /// What values it takes.
    pub accepts: &'static str,
    /// What it does.
    pub doc: &'static str,
    /// True for keys that loosen a safeguard.
    pub person_only: bool,
}

const fn key(
    name: &'static str,
    accepts: &'static str,
    doc: &'static str,
    person_only: bool,
) -> ConfigKey {
    ConfigKey {
        name,
        accepts,
        doc,
        person_only,
    }
}

/// The keys `config_get` and `config_set` reach.
pub const CONFIG_KEYS: &[ConfigKey] = &[
    key(
        "engine",
        "ghidra, native or auto",
        "Engine for new native-code projects",
        false,
    ),
    key(
        "native_in_process",
        "true or false",
        "Run the native engine inside the calling process instead of its confined worker",
        false,
    ),
    key(
        "max_heap_mb",
        "a whole number of MiB",
        "Upper bound of the Ghidra sidecar's JVM heap",
        false,
    ),
    key(
        "ghidra_home",
        "a directory",
        "Ghidra install directory",
        false,
    ),
    key(
        "java_home",
        "a directory",
        "JDK home for the Ghidra sidecar",
        false,
    ),
    key(
        "native_specs",
        "a directory",
        "Compiled Sleigh files for the native engine",
        false,
    ),
    key(
        "projects_root",
        "a directory",
        "Where projects created without a directory go",
        false,
    ),
    key(
        "daemon.idle_secs",
        "a whole number of seconds",
        "Seconds without clients or jobs before krakend exits (default 600)",
        false,
    ),
    key(
        "daemon.session_idle_secs",
        "a whole number of seconds",
        "Seconds without activity before a project session closes (default 1800)",
        false,
    ),
    key(
        "daemon.max_sessions",
        "a whole number",
        "Most project sessions open at once (default 4)",
        false,
    ),
    key(
        "local_serving.grace_secs",
        "a whole number of seconds",
        "How long a local model keeps running after its last user (default 120)",
        false,
    ),
    key(
        "local_serving.titlebar",
        "auto, custom or system",
        "Which window frame the GUI draws",
        false,
    ),
    key(
        "debuginfo.servers",
        "a list of http:// or https:// addresses",
        "debuginfod and Microsoft-style symbol servers `debuginfo_find` asks, in order",
        true,
    ),
    key(
        "debuginfo.consent",
        "true or false",
        "You agree to send build-ids and PDB identities to the symbol servers to download debug files",
        true,
    ),
    key(
        "debuginfo.offline",
        "true or false",
        "Ask no symbol server, whatever else is set",
        false,
    ),
    key(
        "per_run_cap",
        "a whole number",
        "Agent edits applied per run before further ones become proposals",
        true,
    ),
    key(
        "danger_mode",
        "deny, ask or yolo",
        "What the assistant may do with dangerous commands",
        true,
    ),
    key(
        "allow_unconfined",
        "true or false",
        "Run the sidecar without Landlock confinement when the host lacks it",
        true,
    ),
];

fn find_key(name: &str) -> Result<&'static ConfigKey, ProtoError> {
    CONFIG_KEYS.iter().find(|k| k.name == name).ok_or_else(|| {
        let secret = matches!(
            name.split('.').next(),
            Some("provider" | "rewrite" | "local_models" | "assistant_shell" | "pricing")
        );
        let why = if secret {
            "it can hold credentials or grant access, so edit config.toml by hand"
        } else {
            "run config_get without a key to list the keys"
        };
        ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("`{name}` is not a setting this command reaches: {why}"),
        )
    })
}

fn lookup<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.')
        .try_fold(root, |v, part| v.get(part))
        .filter(|v| !v.is_null())
}

fn entry_of(key: &ConfigKey, root: &serde_json::Value) -> ConfigEntry {
    ConfigEntry {
        key: key.name.to_string(),
        value: lookup(root, key.name).cloned(),
        accepts: key.accepts.to_string(),
        doc: key.doc.to_string(),
        person_only: key.person_only,
    }
}

fn internal(e: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, e.to_string())
}

/// The configuration file as `config_get` and `config_set` see it.
#[derive(Debug, Clone)]
pub struct HostConfigStore {
    path: Option<PathBuf>,
}

impl HostConfigStore {
    /// The file the process environment selects (`KRAKEN_CONFIG`, else the default location).
    pub fn system() -> Self {
        HostConfigStore {
            path: KrakenConfig::default_path(),
        }
    }

    /// A store over `path`.
    pub fn at(path: PathBuf) -> Self {
        HostConfigStore { path: Some(path) }
    }

    fn path(&self) -> Result<&Path, ProtoError> {
        self.path.as_deref().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "cannot tell where config.toml is: set KRAKEN_CONFIG or HOME",
            )
        })
    }

    fn load(&self) -> Result<serde_json::Value, ProtoError> {
        let cfg = KrakenConfig::from_file(self.path()?)
            .map_err(|e| ProtoError::new(ErrorCode::InvalidArgument, e.to_string()))?;
        serde_json::to_value(&cfg).map_err(internal)
    }
}

impl ConfigStore for HostConfigStore {
    fn get(&self, name: Option<&str>) -> Result<Vec<ConfigEntry>, ProtoError> {
        let root = self.load()?;
        match name {
            Some(n) => Ok(vec![entry_of(find_key(n)?, &root)]),
            None => Ok(CONFIG_KEYS.iter().map(|k| entry_of(k, &root)).collect()),
        }
    }

    fn set(&self, name: &str, value: serde_json::Value) -> Result<ConfigEntry, ProtoError> {
        let spec = find_key(name)?;
        let mut root = self.load()?;
        let parts: Vec<&str> = spec.name.split('.').collect();
        let Some((last, parents)) = parts.split_last() else {
            return Err(internal("empty key"));
        };
        let mut node = &mut root;
        for p in parents {
            let serde_json::Value::Object(map) = node else {
                return Err(internal("unexpected config layout"));
            };
            node = map
                .entry((*p).to_string())
                .or_insert_with(|| serde_json::json!({}));
        }
        let serde_json::Value::Object(map) = node else {
            return Err(internal("unexpected config layout"));
        };
        if value.is_null() {
            map.remove(*last);
        } else {
            map.insert((*last).to_string(), value);
        }
        // The file's own types decide what is valid, as when it is loaded.
        let cfg: KrakenConfig = serde_json::from_value(root.clone()).map_err(|e| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("`{name}` accepts {}: {e}", spec.accepts),
            )
        })?;
        cfg.save(self.path()?).map_err(internal)?;
        Ok(entry_of(spec, &root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sets_reads_and_unsets_and_refuses_secrets_and_bad_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[provider]\nkind = \"anthropic\"\n").expect("seed");
        let store = HostConfigStore::at(path.clone());

        let e = store.set("engine", json!("native")).expect("set engine");
        assert_eq!(e.value, Some(json!("native")));
        store
            .set("daemon.idle_secs", json!(30))
            .expect("set nested");
        let all = store.get(None).expect("get all");
        assert_eq!(all.len(), CONFIG_KEYS.len());
        let idle = store.get(Some("daemon.idle_secs")).expect("get one");
        assert_eq!(idle[0].value, Some(json!(30)));
        // The provider table survived the rewrite.
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .contains("anthropic")
        );

        store.set("engine", json!(null)).expect("unset");
        assert_eq!(store.get(Some("engine")).expect("get")[0].value, None);

        assert!(store.set("engine", json!("llvm")).is_err());
        assert!(store.set("max_heap_mb", json!("big")).is_err());
        let secret = store.get(Some("provider.api_key")).expect_err("secret");
        assert!(secret.message.contains("credentials"));
        assert!(store.set("provider", json!({})).is_err());
    }

    #[test]
    fn the_symbol_download_settings_round_trip_through_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let store = HostConfigStore::at(path.clone());
        store
            .set("debuginfo.servers", json!(["https://debuginfod.example"]))
            .expect("servers");
        store
            .set("debuginfo.consent", json!(true))
            .expect("consent");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            text.contains("[debuginfo]") && text.contains("consent = true"),
            "{text}"
        );
        let got = store.get(Some("debuginfo.servers")).expect("get");
        assert_eq!(got[0].value, Some(json!(["https://debuginfod.example"])));
        assert!(store.set("debuginfo.servers", json!("not a list")).is_err());
        store.set("debuginfo.consent", json!(null)).expect("unset");
        assert_eq!(
            store.get(Some("debuginfo.consent")).expect("get")[0].value,
            None
        );
    }
}

//! `KrakenConfig`: `~/.config/kraken/config.toml` plus environment overrides.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kraken_registry::SessionConfig;
use serde::{Deserialize, Serialize};

/// Environment variable overriding `max_heap_mb`.
pub const ENV_MAX_HEAP_MB: &str = "KRAKEN_MAX_HEAP_MB";
/// Environment variable overriding `allow_unconfined` (`1`, `true`, `yes` enable it).
pub const ENV_ALLOW_UNCONFINED: &str = "KRAKEN_ALLOW_UNCONFINED";
/// Environment variable overriding `per_run_cap`.
pub const ENV_PER_RUN_CAP: &str = "KRAKEN_PER_RUN_CAP";
/// Environment variable overriding `projects_root`.
pub const ENV_PROJECTS_ROOT: &str = "KRAKEN_PROJECTS_ROOT";
/// Environment variable overriding the config file location.
pub const ENV_CONFIG: &str = "KRAKEN_CONFIG";
/// Environment variable overriding `daemon.idle_secs`.
pub const ENV_DAEMON_IDLE_SECS: &str = "KRAKEN_DAEMON_IDLE_SECS";
/// Environment variable overriding `daemon.session_idle_secs`.
pub const ENV_SESSION_IDLE_SECS: &str = "KRAKEN_SESSION_IDLE_SECS";
/// Environment variable overriding `daemon.max_sessions`.
pub const ENV_MAX_SESSIONS: &str = "KRAKEN_MAX_SESSIONS";

/// Failure to read the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file exists but cannot be read.
    #[error("cannot read config {path}: {source}")]
    Io {
        /// File.
        path: PathBuf,
        /// OS error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML or has unknown keys.
    #[error("invalid config {path}: {message}")]
    Parse {
        /// File.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
    /// An environment override has an unusable value.
    #[error("invalid value for {var}: {value}")]
    Env {
        /// Variable name.
        var: &'static str,
        /// Offending value.
        value: String,
    },
}

/// The `[daemon]` table of the configuration (decisions 17, 40).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonSettings {
    /// Seconds without clients, jobs or running analysis before `krakend` exits (default 600).
    pub idle_secs: Option<u64>,
    /// Seconds without activity before a project session is closed (default 1800).
    pub session_idle_secs: Option<u64>,
    /// Most project sessions open at once (default 4).
    pub max_sessions: Option<u32>,
}

impl DaemonSettings {
    /// Default daemon idle timeout.
    pub const DEFAULT_IDLE_SECS: u64 = 600;
    /// Default per-session idle time.
    pub const DEFAULT_SESSION_IDLE_SECS: u64 = 1800;
    /// Default limit on open sessions.
    pub const DEFAULT_MAX_SESSIONS: u32 = 4;

    /// Daemon idle timeout.
    pub fn idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_secs.unwrap_or(Self::DEFAULT_IDLE_SECS))
    }

    /// Per-session idle time.
    pub fn session_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.session_idle_secs
                .unwrap_or(Self::DEFAULT_SESSION_IDLE_SECS),
        )
    }

    /// Open-session limit (at least one).
    pub fn max_sessions(&self) -> usize {
        self.max_sessions
            .unwrap_or(Self::DEFAULT_MAX_SESSIONS)
            .max(1) as usize
    }
}

/// User configuration. Unset fields fall back to the environment (`KRAKEN_GHIDRA_HOME`, ...) and
/// then to the engine's defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct KrakenConfig {
    /// Ghidra install directory.
    pub ghidra_home: Option<PathBuf>,
    /// JDK home.
    pub java_home: Option<PathBuf>,
    /// `kraken-ghidra.jar` (default: the `cargo xtask ghidra-ext` output).
    pub ext_jar: Option<PathBuf>,
    /// Upper bound of the sidecar JVM heap in MiB.
    pub max_heap_mb: Option<u64>,
    /// Run the sidecar without Landlock confinement when the host lacks it (default false).
    pub allow_unconfined: bool,
    /// Agent edits auto-applied per run before further ones become proposals.
    pub per_run_cap: Option<u32>,
    /// Directory holding projects created without an explicit directory.
    pub projects_root: Option<PathBuf>,
    /// `krakend` tunables.
    pub daemon: DaemonSettings,
    /// The `[provider]` table (chat model for the assistant). Kept opaque here and parsed by
    /// `kraken-assist` (`kraken_agent::ProviderConfig`); present so the file still loads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<serde_json::Value>,
}

impl KrakenConfig {
    /// `$KRAKEN_CONFIG`, else `$XDG_CONFIG_HOME/kraken/config.toml`, else
    /// `~/.config/kraken/config.toml`.
    pub fn default_path() -> Option<PathBuf> {
        Self::default_path_with(&|k| std::env::var_os(k))
    }

    /// [`default_path`](Self::default_path) with an injectable environment.
    pub fn default_path_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
        let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        if let Some(p) = non_empty(ENV_CONFIG) {
            return Some(p);
        }
        if let Some(x) = non_empty("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
            return Some(x.join("kraken/config.toml"));
        }
        non_empty("HOME").map(|h| h.join(".config/kraken/config.toml"))
    }

    /// Loads the default file (a missing file is an empty config) and applies the process
    /// environment.
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_with(&|k| std::env::var_os(k))
    }

    /// [`load`](Self::load) with an injectable environment.
    pub fn load_with(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let mut cfg = match Self::default_path_with(env) {
            Some(p) => Self::from_file(&p)?,
            None => Self::default(),
        };
        cfg.apply_env(env)?;
        Ok(cfg)
    }

    /// Reads `path`; a missing file is an empty config.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text).map_err(|message| ConfigError::Parse {
                path: path.to_path_buf(),
                message,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(ConfigError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Parses TOML text.
    pub fn from_toml(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// Applies environment overrides: `KRAKEN_GHIDRA_HOME`, `KRAKEN_JAVA_HOME`,
    /// `KRAKEN_GHIDRA_EXT_JAR`, `KRAKEN_MAX_HEAP_MB`, `KRAKEN_ALLOW_UNCONFINED`,
    /// `KRAKEN_PER_RUN_CAP` and `KRAKEN_PROJECTS_ROOT`. An environment value wins over the file;
    /// where neither names the JDK, `engine-ghidra` falls back to `JAVA_HOME` itself.
    pub fn apply_env(&mut self, env: &dyn Fn(&str) -> Option<OsString>) -> Result<(), ConfigError> {
        let get = |k: &str| env(k).filter(|v| !v.is_empty());
        if let Some(v) = get("KRAKEN_GHIDRA_HOME") {
            self.ghidra_home = Some(v.into());
        }
        if let Some(v) = get("KRAKEN_JAVA_HOME") {
            self.java_home = Some(v.into());
        }
        if let Some(v) = get("KRAKEN_GHIDRA_EXT_JAR") {
            self.ext_jar = Some(v.into());
        }
        if let Some(v) = get(ENV_PROJECTS_ROOT) {
            self.projects_root = Some(v.into());
        }
        let parse_num = |var: &'static str, v: &OsString| -> Result<u64, ConfigError> {
            let s = v.to_string_lossy().into_owned();
            s.trim().parse::<u64>().map_err(|_| ConfigError::Env {
                var,
                value: s.clone(),
            })
        };
        if let Some(v) = get(ENV_MAX_HEAP_MB) {
            self.max_heap_mb = Some(parse_num(ENV_MAX_HEAP_MB, &v)?);
        }
        if let Some(v) = get(ENV_PER_RUN_CAP) {
            let n = parse_num(ENV_PER_RUN_CAP, &v)?;
            self.per_run_cap = Some(u32::try_from(n).map_err(|_| ConfigError::Env {
                var: ENV_PER_RUN_CAP,
                value: v.to_string_lossy().into_owned(),
            })?);
        }
        if let Some(v) = get(ENV_DAEMON_IDLE_SECS) {
            self.daemon.idle_secs = Some(parse_num(ENV_DAEMON_IDLE_SECS, &v)?);
        }
        if let Some(v) = get(ENV_SESSION_IDLE_SECS) {
            self.daemon.session_idle_secs = Some(parse_num(ENV_SESSION_IDLE_SECS, &v)?);
        }
        if let Some(v) = get(ENV_MAX_SESSIONS) {
            let n = parse_num(ENV_MAX_SESSIONS, &v)?;
            self.daemon.max_sessions = Some(u32::try_from(n).map_err(|_| ConfigError::Env {
                var: ENV_MAX_SESSIONS,
                value: v.to_string_lossy().into_owned(),
            })?);
        }
        if let Some(v) = get(ENV_ALLOW_UNCONFINED) {
            let s = v.to_string_lossy().to_ascii_lowercase();
            self.allow_unconfined = match s.as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => {
                    return Err(ConfigError::Env {
                        var: ENV_ALLOW_UNCONFINED,
                        value: s,
                    });
                }
            };
        }
        Ok(())
    }

    /// The configuration as TOML text (unset fields are left out).
    pub fn to_toml(&self) -> Result<String, String> {
        toml::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Writes the configuration to `path` (creating its directory), replacing the file in one
    /// step so a daemon starting at the same moment never reads half of it.
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        let text = self.to_toml().map_err(|message| ConfigError::Parse {
            path: path.to_path_buf(),
            message,
        })?;
        let io = |source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)
    }

    /// Session tunables derived from this configuration.
    pub fn session_config(&self) -> SessionConfig {
        let mut s = SessionConfig::default();
        if let Some(cap) = self.per_run_cap {
            s.per_run_cap = cap;
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let m: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), OsString::from(v)))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn parses_the_documented_keys() {
        let c = KrakenConfig::from_toml(
            "ghidra_home = \"/opt/ghidra\"\njava_home = \"/opt/jdk\"\next_jar = \"/x/k.jar\"\n\
             max_heap_mb = 2048\nallow_unconfined = true\nper_run_cap = 7\n",
        )
        .unwrap();
        assert_eq!(c.ghidra_home, Some("/opt/ghidra".into()));
        assert_eq!(c.max_heap_mb, Some(2048));
        assert!(c.allow_unconfined);
        assert_eq!(c.session_config().per_run_cap, 7);
    }

    #[test]
    fn daemon_table_and_env() {
        let mut c = KrakenConfig::from_toml("[daemon]\nidle_secs = 5\nmax_sessions = 2\n").unwrap();
        assert_eq!(c.daemon.idle(), std::time::Duration::from_secs(5));
        assert_eq!(c.daemon.max_sessions(), 2);
        assert_eq!(c.daemon.session_idle().as_secs(), 1800);
        c.apply_env(&env_of(&[
            (ENV_MAX_SESSIONS, "7"),
            (ENV_SESSION_IDLE_SECS, "9"),
        ]))
        .unwrap();
        assert_eq!(c.daemon.max_sessions(), 7);
        assert_eq!(c.daemon.session_idle().as_secs(), 9);
        assert!(KrakenConfig::from_toml("[daemon]\nbogus = 1").is_err());
    }

    #[test]
    fn saving_round_trips_and_leaves_unset_fields_out() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let path = dir.join("nested/config.toml");
        let mut c = KrakenConfig {
            ghidra_home: Some("/opt/ghidra".into()),
            max_heap_mb: Some(3072),
            ..Default::default()
        };
        c.daemon.max_sessions = Some(2);
        c.save(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("java_home"), "{text}");
        assert_eq!(KrakenConfig::from_file(&path).unwrap(), c);
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(KrakenConfig::from_toml("bogus = 1").is_err());
    }

    #[test]
    fn defaults_are_conservative() {
        let c = KrakenConfig::default();
        assert!(!c.allow_unconfined);
        assert_eq!(
            c.session_config().per_run_cap,
            SessionConfig::default().per_run_cap
        );
    }

    #[test]
    fn env_overrides_the_file() {
        let mut c = KrakenConfig::from_toml("max_heap_mb = 1\nghidra_home = \"/a\"").unwrap();
        c.apply_env(&env_of(&[
            ("KRAKEN_GHIDRA_HOME", "/b"),
            (ENV_MAX_HEAP_MB, "4096"),
            (ENV_ALLOW_UNCONFINED, "yes"),
            (ENV_PER_RUN_CAP, "3"),
        ]))
        .unwrap();
        assert_eq!(c.ghidra_home, Some("/b".into()));
        assert_eq!(c.max_heap_mb, Some(4096));
        assert!(c.allow_unconfined);
        assert_eq!(c.per_run_cap, Some(3));
    }

    #[test]
    fn bad_env_values_are_errors() {
        let mut c = KrakenConfig::default();
        assert!(c.apply_env(&env_of(&[(ENV_MAX_HEAP_MB, "lots")])).is_err());
        assert!(
            c.apply_env(&env_of(&[(ENV_ALLOW_UNCONFINED, "maybe")]))
                .is_err()
        );
    }

    #[test]
    fn config_path_follows_xdg() {
        let p = KrakenConfig::default_path_with(&env_of(&[
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/home/u"),
        ]));
        assert_eq!(p, Some("/xdg/kraken/config.toml".into()));
        let p = KrakenConfig::default_path_with(&env_of(&[("HOME", "/home/u")]));
        assert_eq!(p, Some("/home/u/.config/kraken/config.toml".into()));
        let p = KrakenConfig::default_path_with(&env_of(&[(ENV_CONFIG, "/c.toml")]));
        assert_eq!(p, Some("/c.toml".into()));
    }

    #[test]
    fn missing_file_is_an_empty_config() {
        let c = KrakenConfig::from_file(Path::new("/nonexistent/kraken/config.toml")).unwrap();
        assert_eq!(c, KrakenConfig::default());
    }
}

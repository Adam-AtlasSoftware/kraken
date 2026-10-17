//! Project locations.
//!
//! Ghidra rejects any project path with an element starting with a dot, and the XDG default
//! `~/.local/share` has one. [`projects_root`] therefore picks the first candidate that is safe:
//!
//! 1. `projects_root` from the configuration (must be safe, otherwise it is an error),
//! 2. `$XDG_DATA_HOME/kraken/projects` when `$XDG_DATA_HOME` is set and has no dotted element,
//! 3. `~/kraken-projects`.
//!
//! So on a stock Linux desktop projects go to `~/kraken-projects/<name>`.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use kraken_proto::{ErrorCode, ProtoError};

use crate::config::KrakenConfig;

/// True when no element of `path` starts with a dot (`.` and `..` components are ignored).
pub fn is_ghidra_safe(path: &Path) -> bool {
    !path
        .components()
        .any(|c| matches!(c, Component::Normal(n) if n.to_string_lossy().starts_with('.')))
}

/// Fails with `invalid_argument` and an explanation when `path` has a dot-prefixed element.
pub fn check_ghidra_safe(path: &Path) -> Result<(), ProtoError> {
    if is_ghidra_safe(path) {
        return Ok(());
    }
    Err(ProtoError::new(
        ErrorCode::InvalidArgument,
        format!(
            "project path {} has a dot-prefixed element, which Ghidra rejects; \
             use a path without one, such as ~/kraken-projects/<name>",
            path.display()
        ),
    ))
}

/// The directory new projects are created in by default (not created by this call).
pub fn projects_root(cfg: &KrakenConfig) -> Result<PathBuf, ProtoError> {
    projects_root_with(cfg, &|k| std::env::var_os(k))
}

/// [`projects_root`] with an injectable environment.
pub fn projects_root_with(
    cfg: &KrakenConfig,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, ProtoError> {
    if let Some(p) = &cfg.projects_root {
        check_ghidra_safe(p)?;
        return Ok(p.clone());
    }
    let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(x) = non_empty("XDG_DATA_HOME").filter(|p| p.is_absolute()) {
        let candidate = x.join("kraken/projects");
        if is_ghidra_safe(&candidate) {
            return Ok(candidate);
        }
    }
    let home = non_empty("HOME").ok_or_else(|| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            "cannot place the project: HOME is not set; pass --project <dir>",
        )
    })?;
    let candidate = home.join("kraken-projects");
    check_ghidra_safe(&candidate)?;
    Ok(candidate)
}

/// Default directory of a project named `name`: `<projects_root>/<name>`.
pub fn default_project_dir(cfg: &KrakenConfig, name: &str) -> Result<PathBuf, ProtoError> {
    let clean: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let clean = clean.trim_start_matches(['.', '_']);
    let clean = if clean.is_empty() { "project" } else { clean };
    Ok(projects_root(cfg)?.join(clean))
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
    fn dotted_elements_are_unsafe() {
        assert!(is_ghidra_safe(Path::new("/home/u/kraken-projects/x")));
        assert!(is_ghidra_safe(Path::new("./rel/../x")));
        assert!(!is_ghidra_safe(Path::new("/home/u/.local/share/kraken")));
        assert!(!is_ghidra_safe(Path::new("/tmp/.tmpAbC/proj")));
        assert!(check_ghidra_safe(Path::new("/a/.b")).is_err());
    }

    #[test]
    fn stock_xdg_data_home_falls_back_to_home() {
        let cfg = KrakenConfig::default();
        let env = env_of(&[
            ("HOME", "/home/u"),
            ("XDG_DATA_HOME", "/home/u/.local/share"),
        ]);
        assert_eq!(
            projects_root_with(&cfg, &env).unwrap(),
            PathBuf::from("/home/u/kraken-projects")
        );
        let env = env_of(&[("HOME", "/home/u")]);
        assert_eq!(
            projects_root_with(&cfg, &env).unwrap(),
            PathBuf::from("/home/u/kraken-projects")
        );
    }

    #[test]
    fn a_clean_xdg_data_home_is_used() {
        // `/data` is not absolute on Windows, where it would be ignored.
        let data = if cfg!(windows) { "C:\\data" } else { "/data" };
        let pairs = [("HOME", "/home/u"), ("XDG_DATA_HOME", data)];
        let env = env_of(&pairs);
        assert_eq!(
            projects_root_with(&KrakenConfig::default(), &env).unwrap(),
            PathBuf::from(data).join("kraken/projects")
        );
    }

    #[test]
    fn configured_root_must_be_safe() {
        let mut cfg = KrakenConfig {
            projects_root: Some("/srv/kraken".into()),
            ..Default::default()
        };
        assert_eq!(
            projects_root_with(&cfg, &env_of(&[])).unwrap(),
            PathBuf::from("/srv/kraken")
        );
        cfg.projects_root = Some("/srv/.kraken".into());
        assert!(projects_root_with(&cfg, &env_of(&[])).is_err());
    }

    #[test]
    fn project_names_are_cleaned() {
        let cfg = KrakenConfig {
            projects_root: Some("/p".into()),
            ..Default::default()
        };
        assert_eq!(
            default_project_dir(&cfg, "pie list.O0").unwrap(),
            PathBuf::from("/p/pie_list_O0")
        );
        assert_eq!(
            default_project_dir(&cfg, "..").unwrap(),
            PathBuf::from("/p/project")
        );
    }
}

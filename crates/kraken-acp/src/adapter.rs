//! Installing the npm adapters (decision 69): a pinned `package.json` and `package-lock.json`
//! (exact versions, SHA-512 integrity of every package) are written into KRAKEN's data dir and
//! installed with `npm ci --ignore-scripts`, so nothing outside the lockfile is fetched and no
//! package runs code at install time.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::node::NodeRuntime;
use crate::paths::AgentPaths;
use crate::profile::{AdapterSpec, AgentProfile, AgentSetup};

/// The registry every adapter is installed from.
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org/";

const INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const MARKER: &str = ".kraken-adapter";

/// Failure to install an adapter.
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    /// The profile is not an npm adapter.
    #[error("{0} is not installed with npm; nothing to set up")]
    NotAnAdapter(String),
    /// The Node.js has no `npm` next to it.
    #[error("npm was not found next to {0}; install Node.js with npm, or let KRAKEN download one")]
    NoNpm(PathBuf),
    /// npm failed.
    #[error("npm could not install {package}@{version}: {detail}")]
    Npm {
        /// Package.
        package: &'static str,
        /// Version.
        version: &'static str,
        /// Exit status and the end of npm's output.
        detail: String,
    },
    /// The install finished but the entry script is missing.
    #[error("{package}@{version} installed but {entry} is missing")]
    EntryMissing {
        /// Package.
        package: &'static str,
        /// Version.
        version: &'static str,
        /// Expected script.
        entry: String,
    },
    /// File system failure.
    #[error("{what}: {source}")]
    Io {
        /// What was attempted.
        what: String,
        /// OS error.
        #[source]
        source: std::io::Error,
    },
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> AdapterError {
    let what = what.into();
    move |source| AdapterError::Io { what, source }
}

impl AdapterSpec {
    /// `<adapters dir>/<id>-<version>`.
    pub fn install_dir(&self, paths: &AgentPaths, profile_id: &str) -> PathBuf {
        paths
            .adapters_dir()
            .join(format!("{profile_id}-{}", self.version))
    }

    /// The script that starts the adapter once installed.
    pub fn entry_path(&self, paths: &AgentPaths, profile_id: &str) -> PathBuf {
        self.install_dir(paths, profile_id)
            .join("node_modules")
            .join(self.entry)
    }

    /// True when the adapter was installed completely.
    pub fn is_installed(&self, paths: &AgentPaths, profile_id: &str) -> bool {
        self.install_dir(paths, profile_id).join(MARKER).is_file()
            && self.entry_path(paths, profile_id).is_file()
    }
}

/// The npm arguments of an install. `--ignore-scripts` keeps package install scripts from
/// running; `--registry` and the empty config files stop a user's `.npmrc` (tokens, mirrors)
/// from being used.
pub fn npm_ci_args(cache: &Path, user_config: &Path, global_config: &Path) -> Vec<String> {
    let s = |p: &Path| p.to_string_lossy().into_owned();
    vec![
        "ci".into(),
        "--ignore-scripts".into(),
        "--no-audit".into(),
        "--no-fund".into(),
        "--no-progress".into(),
        "--loglevel=error".into(),
        format!("--registry={NPM_REGISTRY}"),
        format!("--cache={}", s(cache)),
        format!("--userconfig={}", s(user_config)),
        format!("--globalconfig={}", s(global_config)),
    ]
}

/// Installs the adapter of `profile` with `node`'s npm and returns the directory it lives in.
/// An adapter that is already installed is left alone.
pub async fn install_adapter(
    profile: &AgentProfile,
    paths: &AgentPaths,
    node: &NodeRuntime,
) -> Result<PathBuf, AdapterError> {
    let AgentSetup::NodeAdapter(spec) = profile.setup else {
        return Err(AdapterError::NotAnAdapter(profile.id.clone()));
    };
    let dest = spec.install_dir(paths, &profile.id);
    if spec.is_installed(paths, &profile.id) {
        return Ok(dest);
    }
    let npm = node
        .npm
        .clone()
        .ok_or_else(|| AdapterError::NoNpm(node.node.clone()))?;
    let adapters = paths.adapters_dir();
    fs::create_dir_all(&adapters).map_err(io(format!("cannot create {}", adapters.display())))?;
    let cache = paths.npm_cache_dir();
    fs::create_dir_all(&cache).map_err(io(format!("cannot create {}", cache.display())))?;

    let staging = adapters.join(format!(".staging-{}-{}", profile.id, std::process::id()));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging).map_err(io(format!("cannot create {}", staging.display())))?;
    let result = run_install(profile, spec, node, &npm, &staging, &cache).await;
    if let Err(e) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(e);
    }
    let entry = staging.join("node_modules").join(spec.entry);
    if !entry.is_file() {
        let _ = fs::remove_dir_all(&staging);
        return Err(AdapterError::EntryMissing {
            package: spec.package,
            version: spec.version,
            entry: spec.entry.to_string(),
        });
    }
    fs::write(
        staging.join(MARKER),
        format!("{}@{}\n", spec.package, spec.version),
    )
    .map_err(io("cannot write the install marker"))?;
    let _ = fs::remove_dir_all(&dest);
    fs::rename(&staging, &dest).map_err(io(format!("cannot move into {}", dest.display())))?;
    Ok(dest)
}

async fn run_install(
    profile: &AgentProfile,
    spec: &AdapterSpec,
    node: &NodeRuntime,
    npm: &Path,
    dir: &Path,
    cache: &Path,
) -> Result<(), AdapterError> {
    fs::write(dir.join("package.json"), spec.package_json)
        .map_err(io("cannot write package.json"))?;
    fs::write(dir.join("package-lock.json"), spec.lockfile)
        .map_err(io("cannot write package-lock.json"))?;
    // npm refuses to load one file as both the user and the global config, so there are two.
    let user_cfg = dir.join("empty-user.npmrc");
    let global_cfg = dir.join("empty-global.npmrc");
    for f in [&user_cfg, &global_cfg] {
        fs::write(f, "").map_err(io("cannot write the empty npm config"))?;
    }

    let mut path = std::ffi::OsString::from(node.bin_dir().as_os_str());
    if let Some(parent) = std::env::var_os("PATH") {
        path.push(if cfg!(windows) { ";" } else { ":" });
        path.push(parent);
    }
    let mut cmd = tokio::process::Command::new(npm);
    cmd.args(npm_ci_args(cache, &user_cfg, &global_cfg))
        .current_dir(dir)
        .env_clear()
        .env("PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    // Only what npm needs: a home for its logs, proxies and certificates. No tokens.
    for key in [
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "TMPDIR",
        "TEMP",
        "TMP",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    ] {
        if let Some(v) = std::env::var_os(key) {
            cmd.env(key, v);
        }
    }
    let npm_err = |detail: String| AdapterError::Npm {
        package: spec.package,
        version: spec.version,
        detail,
    };
    tracing::info!(agent = %profile.id, package = spec.package, version = spec.version, "installing adapter");
    // A script that was written a moment ago can be "text file busy" while another thread forks.
    let mut attempts = 0;
    let mut child = loop {
        match cmd.spawn() {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(26) && attempts < 20 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(npm_err(format!("cannot start {}: {e}", npm.display()))),
        }
    };
    let mut stderr = child.stderr.take();
    let mut stdout = child.stdout.take();
    let collect = async {
        let mut err_text = String::new();
        let mut out_text = String::new();
        if let (Some(e), Some(o)) = (stderr.as_mut(), stdout.as_mut()) {
            let _ = tokio::join!(
                e.read_to_string(&mut err_text),
                o.read_to_string(&mut out_text)
            );
        }
        let status = child.wait().await;
        (status, err_text, out_text)
    };
    let (status, err_text, out_text) = tokio::time::timeout(INSTALL_TIMEOUT, collect)
        .await
        .map_err(|_| npm_err("timed out after 15 minutes".into()))?;
    match status {
        Ok(st) if st.success() => Ok(()),
        Ok(st) => {
            let text = if err_text.trim().is_empty() {
                out_text
            } else {
                err_text
            };
            Err(npm_err(format!("{st}; {}", tail(&text, 1500))))
        }
        Err(e) => Err(npm_err(e.to_string())),
    }
}

fn tail(text: &str, max: usize) -> String {
    let t = text.trim();
    if t.len() <= max {
        return t.to_string();
    }
    let mut start = t.len() - max;
    while !t.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &t[start..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{NodeOrigin, NodeVersion};
    use crate::profile::builtin_profile;

    fn node_with_npm(npm: Option<PathBuf>) -> NodeRuntime {
        NodeRuntime {
            node: PathBuf::from("/nonexistent/bin/node"),
            npm,
            version: NodeVersion {
                major: 24,
                minor: 21,
                patch: 0,
            },
            origin: NodeOrigin::System,
        }
    }

    #[test]
    fn npm_arguments_ignore_scripts_and_user_config() {
        let args = npm_ci_args(Path::new("/cache"), Path::new("/u"), Path::new("/g"));
        assert_eq!(args[0], "ci");
        assert!(args.contains(&"--ignore-scripts".to_string()));
        assert!(args.contains(&"--registry=https://registry.npmjs.org/".to_string()));
        assert!(args.contains(&"--userconfig=/u".to_string()));
        assert!(args.contains(&"--globalconfig=/g".to_string()));
    }

    #[tokio::test]
    async fn custom_agents_have_nothing_to_install() {
        let d = tempfile::tempdir().expect("tempdir");
        let paths = AgentPaths::in_data_dir(d.path());
        let p = AgentProfile::custom("x", "X", "x", vec![]);
        let err = install_adapter(&p, &paths, &node_with_npm(None))
            .await
            .expect_err("no adapter");
        assert!(matches!(err, AdapterError::NotAnAdapter(_)));
    }

    #[tokio::test]
    async fn a_node_without_npm_is_reported() {
        let d = tempfile::tempdir().expect("tempdir");
        let paths = AgentPaths::in_data_dir(d.path());
        let p = builtin_profile("claude").expect("claude");
        let err = install_adapter(&p, &paths, &node_with_npm(None))
            .await
            .expect_err("no npm");
        assert!(matches!(err, AdapterError::NoNpm(_)));
    }

    #[cfg(unix)]
    fn fake_npm(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("npm");
        fs::write(&p, format!("#!/bin/sh\n{body}\n")).expect("write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
        p
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_runs_npm_ci_with_the_pinned_lockfile() {
        let d = tempfile::tempdir().expect("tempdir");
        let paths = AgentPaths::in_data_dir(d.path().join("data"));
        let p = builtin_profile("claude").expect("claude");
        let AgentSetup::NodeAdapter(spec) = p.setup else {
            panic!("adapter");
        };
        let npm = fake_npm(
            d.path(),
            &format!(
                "echo \"$@\" > npm-args.txt\ncp package-lock.json lock-seen.json\n\
                 mkdir -p node_modules/{dir}\necho '// adapter' > node_modules/{entry}",
                dir = Path::new(spec.entry).parent().expect("dir").display(),
                entry = spec.entry
            ),
        );
        let node = node_with_npm(Some(npm));
        let dest = install_adapter(&p, &paths, &node).await.expect("installed");
        assert!(spec.is_installed(&paths, "claude"));
        let args = fs::read_to_string(dest.join("npm-args.txt")).expect("args");
        assert!(args.starts_with("ci "), "{args}");
        assert!(args.contains("--ignore-scripts"), "{args}");
        let seen = fs::read_to_string(dest.join("lock-seen.json")).expect("lock");
        assert_eq!(seen, spec.lockfile, "npm ci saw the embedded lockfile");
        assert_eq!(
            fs::read_to_string(dest.join("package.json")).expect("pkg"),
            spec.package_json
        );
        // Installing again is a no-op (the fake npm would fail now).
        let node2 = node_with_npm(Some(fake_npm(d.path(), "exit 9")));
        install_adapter(&p, &paths, &node2).await.expect("no-op");
        // No staging directory is left behind.
        let names: Vec<_> = fs::read_dir(paths.adapters_dir())
            .expect("dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["claude-0.89.1".to_string()]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_failing_npm_leaves_nothing_installed() {
        let d = tempfile::tempdir().expect("tempdir");
        let paths = AgentPaths::in_data_dir(d.path().join("data"));
        let p = builtin_profile("codex").expect("codex");
        let npm = fake_npm(d.path(), "echo 'EINTEGRITY sha512 mismatch' >&2\nexit 1");
        let err = install_adapter(&p, &paths, &node_with_npm(Some(npm)))
            .await
            .expect_err("fails");
        match err {
            AdapterError::Npm { detail, .. } => assert!(detail.contains("EINTEGRITY"), "{detail}"),
            other => panic!("unexpected {other:?}"),
        }
        let AgentSetup::NodeAdapter(spec) = p.setup else {
            panic!("adapter");
        };
        assert!(!spec.is_installed(&paths, "codex"));
        let left: Vec<_> = fs::read_dir(paths.adapters_dir())
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_default();
        assert!(left.is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_install_without_the_entry_script_fails() {
        let d = tempfile::tempdir().expect("tempdir");
        let paths = AgentPaths::in_data_dir(d.path().join("data"));
        let p = builtin_profile("gemini").expect("gemini");
        let npm = fake_npm(d.path(), "mkdir -p node_modules");
        let err = install_adapter(&p, &paths, &node_with_npm(Some(npm)))
            .await
            .expect_err("fails");
        assert!(matches!(err, AdapterError::EntryMissing { .. }), "{err:?}");
    }
}

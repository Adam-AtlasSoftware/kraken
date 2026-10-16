//! Node.js for the agent adapters (decision 35): detect it, or download a pinned LTS into
//! KRAKEN's data dir.
//!
//! Downloads reuse `kraken_host::provision`: HTTPS only, resumable, SHA-256 checked before
//! anything is extracted, and extraction refuses paths that escape the destination (zip-slip),
//! absolute paths, device files and links pointing outside, and keeps archive mtimes.

use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use kraken_host::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, ProgressFn, ProvisionError, download, extract_tar_gz,
    extract_zip,
};
use serde::Serialize;

use crate::paths::AgentPaths;
use crate::platform::Platform;

/// The Node.js release KRAKEN downloads (an LTS line, "Krypton").
pub const NODE_VERSION: &str = "24.21.0";

/// The oldest Node.js any built-in adapter accepts (Claude Code's adapter needs 22).
pub const MIN_NODE_MAJOR: u64 = 22;

/// One pinned Node.js archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDownload {
    /// Platform label in Node's naming (`linux-x64`).
    pub target: &'static str,
    /// Archive file name on nodejs.org.
    pub file_name: &'static str,
    /// Lower-case hex SHA-256, copied from the release's `SHASUMS256.txt`.
    pub sha256: &'static str,
    /// Archive format.
    pub format: ArchiveFormat,
    /// Approximate download size in MiB, for the consent prompt.
    pub approx_mib: u64,
}

/// linux-x64 (the first platform).
pub const NODE_LINUX_X64: NodeDownload = NodeDownload {
    target: "linux-x64",
    file_name: "node-v24.21.0-linux-x64.tar.gz",
    sha256: "6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff",
    format: ArchiveFormat::TarGz,
    approx_mib: 60,
};

/// darwin-arm64.
pub const NODE_DARWIN_ARM64: NodeDownload = NodeDownload {
    target: "darwin-arm64",
    file_name: "node-v24.21.0-darwin-arm64.tar.gz",
    sha256: "bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057",
    format: ArchiveFormat::TarGz,
    approx_mib: 60,
};

/// win-x64.
pub const NODE_WIN_X64: NodeDownload = NodeDownload {
    target: "win-x64",
    file_name: "node-v24.21.0-win-x64.zip",
    sha256: "158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541",
    format: ArchiveFormat::Zip,
    approx_mib: 35,
};

/// The pinned download for `platform`, when there is one.
pub fn node_download_for(platform: &Platform) -> Option<NodeDownload> {
    match (platform.os.as_str(), platform.arch.as_str()) {
        ("linux", "x86_64") => Some(NODE_LINUX_X64),
        ("macos", "aarch64") => Some(NODE_DARWIN_ARM64),
        ("windows", "x86_64") => Some(NODE_WIN_X64),
        _ => None,
    }
}

impl NodeDownload {
    /// `https://nodejs.org/dist/v<version>/<file>`.
    pub fn url(&self) -> String {
        format!("https://nodejs.org/dist/v{NODE_VERSION}/{}", self.file_name)
    }

    /// The directory the archive extracts to.
    pub fn top_dir(&self) -> String {
        format!("node-v{NODE_VERSION}-{}", self.target)
    }

    /// As a `kraken-host` download spec.
    pub fn spec(&self) -> ArtifactSpec {
        ArtifactSpec {
            name: "node".into(),
            file_name: self.file_name.into(),
            url: self.url(),
            sha256: self.sha256.into(),
            format: self.format,
            top_dir: self.top_dir(),
        }
    }
}

/// A Node.js version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NodeVersion {
    /// Major.
    pub major: u64,
    /// Minor.
    pub minor: u64,
    /// Patch.
    pub patch: u64,
}

impl NodeVersion {
    /// Parses the output of `node --version` (`v24.21.0`, with or without the `v`, surrounding
    /// whitespace and a pre-release suffix such as `-nightly2024`).
    pub fn parse(text: &str) -> Option<NodeVersion> {
        let t = text.trim().trim_start_matches('v');
        let core = t.split(['-', '+']).next()?;
        let mut parts = core.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(NodeVersion {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for NodeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for NodeVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

/// Failure to find, run or install Node.js.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    /// No `node` on `PATH`.
    #[error("Node.js was not found on PATH")]
    NotFound,
    /// `node` exists but is older than the adapter needs.
    #[error("Node.js {found} is too old; version {required} or newer is needed")]
    TooOld {
        /// What was found.
        found: NodeVersion,
        /// What is needed (major version).
        required: u64,
    },
    /// `node --version` printed something unexpected or failed.
    #[error("cannot read the Node.js version from {path}: {detail}")]
    Version {
        /// The binary.
        path: PathBuf,
        /// What happened.
        detail: String,
    },
    /// This platform has no pinned download.
    #[error(
        "KRAKEN cannot download Node.js for {0}; install Node.js {MIN_NODE_MAJOR} or newer yourself"
    )]
    NoDownload(String),
    /// Download, verification or extraction failed.
    #[error(transparent)]
    Provision(#[from] ProvisionError),
    /// The extracted archive has no usable Node.js.
    #[error("the downloaded archive does not contain {0}")]
    Incomplete(String),
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

/// Where a Node.js came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeOrigin {
    /// Found on `PATH`.
    System,
    /// The copy KRAKEN downloaded into its data dir.
    Provisioned,
}

/// A usable Node.js.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRuntime {
    /// The `node` binary.
    pub node: PathBuf,
    /// The `npm` launcher next to it, when there is one.
    pub npm: Option<PathBuf>,
    /// Its version.
    pub version: NodeVersion,
    /// Where it came from.
    pub origin: NodeOrigin,
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// The first executable called `name` in the `PATH`-style list `path`.
pub fn find_in_path(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    let mut names = vec![name.to_string()];
    if cfg!(windows) {
        names = vec![format!("{name}.exe"), format!("{name}.cmd")];
    }
    for dir in std::env::split_paths(path) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        for n in &names {
            let candidate = dir.join(n);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// True when `p` is a regular file (after following links) that can be executed.
pub fn is_executable_file(p: &Path) -> bool {
    let Ok(meta) = fs::metadata(p) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Runs `program args` with a cleared environment (plus `PATH`), returning stdout when it exits
/// successfully within `timeout`.
fn capture(
    program: &Path,
    args: &[&str],
    path_env: Option<&OsStr>,
    timeout: Duration,
) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(p) = path_env {
        cmd.env("PATH", p);
    }
    if cfg!(windows)
        && let Some(root) = std::env::var_os("SYSTEMROOT")
    {
        cmd.env("SYSTEMROOT", root);
    }
    let mut attempts = 0;
    let mut child = loop {
        match cmd.spawn() {
            Ok(c) => break c,
            // "Text file busy": the binary was written a moment ago while another thread forked.
            Err(e) if e.raw_os_error() == Some(26) && attempts < 20 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(s) = stdout.as_mut() {
            let _ = std::io::Read::read_to_string(s, &mut text);
        }
        text
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timed out".into());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let text = reader.join().unwrap_or_default();
    if status.success() {
        Ok(text)
    } else {
        Err(format!("exited with {status}"))
    }
}

impl NodeRuntime {
    /// Looks for Node.js on the process's `PATH` and checks that it is at least
    /// [`MIN_NODE_MAJOR`].
    pub fn detect() -> Result<NodeRuntime, NodeError> {
        Self::detect_with(std::env::var_os("PATH").as_deref(), MIN_NODE_MAJOR)
    }

    /// [`detect`](Self::detect) on an explicit `PATH` and minimum major version.
    pub fn detect_with(path: Option<&OsStr>, min_major: u64) -> Result<NodeRuntime, NodeError> {
        let node = find_in_path("node", path).ok_or(NodeError::NotFound)?;
        let rt = Self::from_binary(node, path, NodeOrigin::System)?;
        if rt.version.major < min_major {
            return Err(NodeError::TooOld {
                found: rt.version,
                required: min_major,
            });
        }
        Ok(rt)
    }

    /// Runs `node --version` on `node` and builds a runtime. The npm launcher is looked up next
    /// to the binary first, then on `path`.
    pub fn from_binary(
        node: PathBuf,
        path: Option<&OsStr>,
        origin: NodeOrigin,
    ) -> Result<NodeRuntime, NodeError> {
        let dir = node.parent().map(Path::to_path_buf).unwrap_or_default();
        let mut search = OsString::from(dir.as_os_str());
        if let Some(p) = path {
            search.push(if cfg!(windows) { ";" } else { ":" });
            search.push(p);
        }
        let text = capture(
            &node,
            &["--version"],
            Some(&search),
            Duration::from_secs(10),
        )
        .map_err(|detail| NodeError::Version {
            path: node.clone(),
            detail,
        })?;
        let version = NodeVersion::parse(&text).ok_or_else(|| NodeError::Version {
            path: node.clone(),
            detail: format!("unexpected output {:?}", text.trim()),
        })?;
        let npm = find_in_path("npm", Some(&OsString::from(dir.as_os_str())))
            .or_else(|| find_in_path("npm", path));
        Ok(NodeRuntime {
            node,
            npm,
            version,
            origin,
        })
    }

    /// The directory holding the `node` binary.
    pub fn bin_dir(&self) -> PathBuf {
        self.node
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    /// The copy KRAKEN downloaded earlier, if it is in place and runs.
    pub fn provisioned(paths: &AgentPaths, platform: &Platform) -> Option<NodeRuntime> {
        let dl = node_download_for(platform)?;
        let node = provisioned_node_binary(paths, &dl.top_dir());
        if !node.is_file() {
            return None;
        }
        Self::from_binary(node, None, NodeOrigin::Provisioned).ok()
    }

    /// A Node.js that satisfies `min_major`: the one on `PATH`, else the downloaded copy.
    pub fn resolve(
        paths: &AgentPaths,
        platform: &Platform,
        path: Option<&OsStr>,
        min_major: u64,
    ) -> Option<NodeRuntime> {
        Self::detect_with(path, min_major)
            .ok()
            .or_else(|| Self::provisioned(paths, platform).filter(|n| n.version.major >= min_major))
    }

    /// Downloads and unpacks the pinned Node.js for this platform into `data_dir`
    /// (`<data_dir>/agents/node`). The archive is hashed before extraction; a mismatch deletes
    /// it and nothing is extracted.
    pub async fn provision(
        data_dir: &Path,
        fetcher: &dyn Fetcher,
        progress: ProgressFn<'_>,
    ) -> Result<NodeRuntime, NodeError> {
        let platform = Platform::current();
        let dl =
            node_download_for(&platform).ok_or_else(|| NodeError::NoDownload(platform.label()))?;
        let paths = AgentPaths::in_data_dir(data_dir);
        provision_download(&paths, &dl.spec(), fetcher, progress).await
    }
}

fn provisioned_node_binary(paths: &AgentPaths, top_dir: &str) -> PathBuf {
    let top = paths.node_dir().join(top_dir);
    if cfg!(windows) {
        top.join(exe_name("node"))
    } else {
        top.join("bin").join("node")
    }
}

/// [`NodeRuntime::provision`] for an explicit download description (tests use local archives).
pub async fn provision_download(
    paths: &AgentPaths,
    spec: &ArtifactSpec,
    fetcher: &dyn Fetcher,
    progress: ProgressFn<'_>,
) -> Result<NodeRuntime, NodeError> {
    let spec = spec.clone();
    let archive = download(fetcher, &spec, &paths.downloads_dir(), progress).await?;
    let node_dir = paths.node_dir();
    fs::create_dir_all(&node_dir).map_err(|source| NodeError::Io {
        what: format!("cannot create {}", node_dir.display()),
        source,
    })?;
    let staging = node_dir.join(format!(".staging-{}", std::process::id()));
    let (s, a, st) = (spec.clone(), archive, staging.clone());
    let extracted = tokio::task::spawn_blocking(move || {
        let _ = fs::remove_dir_all(&st);
        match s.format {
            ArchiveFormat::Zip => extract_zip(&a, &st),
            ArchiveFormat::TarGz => extract_tar_gz(&a, &st),
        }
    })
    .await
    .map_err(|e| NodeError::Io {
        what: "extraction task".into(),
        source: std::io::Error::other(e.to_string()),
    })?;
    if let Err(e) = extracted {
        let _ = fs::remove_dir_all(&staging);
        return Err(e.into());
    }
    let from = staging.join(&spec.top_dir);
    let dest = node_dir.join(&spec.top_dir);
    if !from.is_dir() {
        let _ = fs::remove_dir_all(&staging);
        return Err(NodeError::Incomplete(spec.top_dir));
    }
    let _ = fs::remove_dir_all(&dest);
    fs::rename(&from, &dest).map_err(|source| NodeError::Io {
        what: format!("cannot move into {}", dest.display()),
        source,
    })?;
    let _ = fs::remove_dir_all(&staging);
    let node = provisioned_node_binary(paths, &spec.top_dir);
    if !node.is_file() {
        return Err(NodeError::Incomplete(node.display().to_string()));
    }
    NodeRuntime::from_binary(node, None, NodeOrigin::Provisioned)
}

#[cfg(test)]
mod tests;

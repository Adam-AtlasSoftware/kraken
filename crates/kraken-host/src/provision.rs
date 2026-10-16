//! First-run provisioning: download the pinned Ghidra and Temurin JDK, verify their checksums,
//! extract them into the runtime directory and build the KRAKEN Ghidra extension against them
//! (decisions 10, 42, 48).
//!
//! - The URLs and SHA-256 hashes are compiled in ([`pinned`]); a download is hashed completely
//!   and rejected on mismatch **before** anything is extracted.
//! - Downloads are HTTPS only (redirects too), resumable (`Range` on a `.part` file) and report
//!   progress through a callback.
//! - Extraction refuses entries that would leave the destination (zip-slip, `..`, absolute
//!   paths, links pointing outside) and strips group/other write bits.
//! - The extension is compiled from the Java sources embedded in this binary with the
//!   downloaded JDK's `javac` and `jar` (the extension needs only Ghidra's own jars on the
//!   classpath, so no Gradle is involved).
//!
//! Everything lives under `$XDG_DATA_HOME/kraken/runtime` (default `~/.local/share/kraken/runtime`),
//! see [`Layout`]. The directory may have dotted elements: only Ghidra *project* paths cannot.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// The Ghidra version `kraken setup` installs.
pub const GHIDRA_VERSION: &str = "12.1.4";
/// Download URL of the pinned Ghidra release.
pub const GHIDRA_URL: &str = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip";
/// SHA-256 of the pinned Ghidra archive.
pub const GHIDRA_SHA256: &str = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db";
/// Directory the Ghidra archive extracts to.
pub const GHIDRA_TOP_DIR: &str = "ghidra_12.1.4_PUBLIC";
/// Download URL of the pinned Temurin 21 JDK (Linux x86_64).
pub const JDK_URL: &str = "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz";
/// SHA-256 of the pinned JDK archive.
pub const JDK_SHA256: &str = "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94";
/// Directory the JDK archive extracts to.
pub const JDK_TOP_DIR: &str = "jdk-21.0.12.1+1";

/// Most bytes one archive may extract to; guards against decompression bombs.
pub const MAX_EXTRACTED_BYTES: u64 = 16 << 30;

/// Failure while provisioning.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// No pinned artifacts exist for this platform.
    #[error(
        "automatic setup supports Linux x86_64 only (this is {0}); install Ghidra 12.1.4 and a JDK 21 yourself and set KRAKEN_GHIDRA_HOME / KRAKEN_JAVA_HOME"
    )]
    UnsupportedPlatform(String),
    /// A URL that is not `https://`.
    #[error("refusing to download {0}: only https is allowed")]
    NotHttps(String),
    /// The server answered with an error or something unusable.
    #[error("download of {url} failed: {message}")]
    Http {
        /// The URL.
        url: String,
        /// What went wrong.
        message: String,
    },
    /// The server cannot serve the requested byte range (the partial file is stale).
    #[error("range not satisfiable")]
    RangeNotSatisfiable,
    /// The download is complete but its hash is not the pinned one.
    #[error(
        "sha256 mismatch for {name}: expected {expected}, got {actual}; the download was discarded"
    )]
    Sha256Mismatch {
        /// Artifact name.
        name: String,
        /// Pinned hash.
        expected: String,
        /// Hash of the download.
        actual: String,
    },
    /// The connection ended before the announced length.
    #[error(
        "download of {name} ended early ({got} of {expected} bytes); run `kraken setup` again to resume"
    )]
    Truncated {
        /// Artifact name.
        name: String,
        /// Bytes received.
        got: u64,
        /// Bytes announced.
        expected: u64,
    },
    /// An archive entry would be written outside the destination.
    #[error("archive entry {0:?} would be extracted outside the destination")]
    UnsafePath(String),
    /// An archive holds something that is not extracted (devices, zip symlinks, ...) or is too big.
    #[error("unsupported archive content: {0}")]
    BadArchive(String),
    /// The extension did not compile.
    #[error("building the Ghidra extension failed: {0}")]
    Build(String),
    /// File system failure.
    #[error("{what}: {source}")]
    Io {
        /// What was attempted.
        what: String,
        /// The OS error.
        #[source]
        source: io::Error,
    },
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> ProvisionError {
    let what = what.into();
    move |source| ProvisionError::Io { what, source }
}

/// Archive container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// A `.zip`.
    Zip,
    /// A gzip-compressed tar.
    TarGz,
}

/// One pinned download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSpec {
    /// Short name (`ghidra`, `jdk`), also the directory under the runtime root.
    pub name: String,
    /// File name in the downloads directory.
    pub file_name: String,
    /// `https://` URL.
    pub url: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
    /// Container format.
    pub format: ArchiveFormat,
    /// The single top-level directory the archive extracts to.
    pub top_dir: String,
}

/// The pinned Ghidra and JDK for this platform.
pub fn pinned() -> Result<(ArtifactSpec, ArtifactSpec), ProvisionError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(ProvisionError::UnsupportedPlatform(format!(
            "{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )));
    }
    Ok((
        ArtifactSpec {
            name: "ghidra".into(),
            file_name: "ghidra_12.1.4_PUBLIC_20260921.zip".into(),
            url: GHIDRA_URL.into(),
            sha256: GHIDRA_SHA256.into(),
            format: ArchiveFormat::Zip,
            top_dir: GHIDRA_TOP_DIR.into(),
        },
        ArtifactSpec {
            name: "jdk".into(),
            file_name: "OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz".into(),
            url: JDK_URL.into(),
            sha256: JDK_SHA256.into(),
            format: ArchiveFormat::TarGz,
            top_dir: JDK_TOP_DIR.into(),
        },
    ))
}

/// Where the provisioned runtime lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    root: PathBuf,
}

/// The pieces of a provisioned runtime that exist and look valid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provisioned {
    /// Ghidra install directory.
    pub ghidra_home: Option<PathBuf>,
    /// JDK home.
    pub java_home: Option<PathBuf>,
    /// `kraken-ghidra.jar`.
    pub ext_jar: Option<PathBuf>,
}

impl Provisioned {
    /// True when all three pieces exist.
    pub fn is_complete(&self) -> bool {
        self.ghidra_home.is_some() && self.java_home.is_some() && self.ext_jar.is_some()
    }
}

impl Layout {
    /// A layout rooted at `root`.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Layout { root: root.into() }
    }

    /// `$XDG_DATA_HOME/kraken/runtime`, else `$HOME/.local/share/kraken/runtime`.
    pub fn from_env() -> Option<Self> {
        Self::from_env_with(&|k| std::env::var_os(k))
    }

    /// [`from_env`](Self::from_env) with an injectable environment.
    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Self> {
        let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
        let base = non_empty("XDG_DATA_HOME")
            .filter(|p| p.is_absolute())
            .or_else(|| non_empty("HOME").map(|h| h.join(".local/share")))?;
        Some(Layout::at(base.join("kraken/runtime")))
    }

    /// The runtime root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Downloaded archives and partial downloads.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }

    /// Where an artifact extracts to: `<root>/<name>/<top_dir>`.
    pub fn install_dir(&self, spec: &ArtifactSpec) -> PathBuf {
        self.root.join(&spec.name).join(&spec.top_dir)
    }

    /// The built extension jar.
    pub fn ext_jar(&self) -> PathBuf {
        self.root.join("ext/kraken-ghidra.jar")
    }

    /// Which pieces exist and look valid (a Ghidra install has `Ghidra/application.properties`,
    /// a JDK has `bin/java` and `bin/javac`, the extension is a file).
    pub fn provisioned(&self) -> Provisioned {
        let Ok((g, j)) = pinned() else {
            return Provisioned::default();
        };
        let ghidra = self.install_dir(&g);
        let jdk = self.install_dir(&j);
        let jar = self.ext_jar();
        Provisioned {
            ghidra_home: ghidra
                .join("Ghidra/application.properties")
                .is_file()
                .then_some(ghidra),
            java_home: (jdk.join("bin/java").is_file() && jdk.join("bin/javac").is_file())
                .then_some(jdk),
            ext_jar: jar.is_file().then_some(jar),
        }
    }
}

/// What a setup is doing right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// Bytes of an artifact received so far.
    Downloading {
        /// Artifact name.
        name: String,
        /// Bytes on disk, including a resumed prefix.
        done: u64,
        /// Total bytes when the server said.
        total: Option<u64>,
        /// Bytes that were already on disk when the download started.
        resumed_from: u64,
    },
    /// Hashing a finished download.
    Verifying {
        /// Artifact name.
        name: String,
    },
    /// Extracting a verified archive.
    Extracting {
        /// Artifact name.
        name: String,
    },
    /// Compiling the Ghidra extension.
    BuildingExtension,
    /// An artifact is already installed and was left alone.
    Skipped {
        /// Artifact name.
        name: String,
    },
}

/// Progress callback.
pub type ProgressFn<'a> = &'a mut (dyn FnMut(Progress) + Send);

// ---------------------------------------------------------------------------------------------
// Fetching

/// One response body, read chunk by chunk.
#[async_trait]
pub trait Body: Send {
    /// The next chunk; `None` at the end.
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError>;
}

/// A started response.
pub struct Fetched {
    /// True when the server honoured the `Range` request (the body continues at the offset).
    pub resumed: bool,
    /// Length of the whole file when known.
    pub total: Option<u64>,
    /// The body.
    pub body: Box<dyn Body>,
}

/// Source of bytes. The real implementation is [`HttpsFetcher`]; tests supply canned ones.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Starts a GET of `url` at byte offset `from` (0 for the whole file).
    async fn fetch(&self, url: &str, from: u64) -> Result<Fetched, ProvisionError>;
}

/// Fails unless `url` is `https://`.
pub fn require_https(url: &str) -> Result<(), ProvisionError> {
    if url.len() > 8 && url[..8].eq_ignore_ascii_case("https://") {
        Ok(())
    } else {
        Err(ProvisionError::NotHttps(url.to_string()))
    }
}

/// `reqwest` over rustls; HTTPS only, redirects included.
pub struct HttpsFetcher {
    client: reqwest::Client,
}

impl HttpsFetcher {
    /// A fetcher with sensible timeouts.
    pub fn new() -> Result<Self, ProvisionError> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .user_agent(concat!("kraken/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| ProvisionError::Http {
                url: String::new(),
                message: e.to_string(),
            })?;
        Ok(HttpsFetcher { client })
    }
}

struct ReqwestBody {
    resp: reqwest::Response,
    url: String,
}

#[async_trait]
impl Body for ReqwestBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        self.resp
            .chunk()
            .await
            .map(|c| c.map(|b| b.to_vec()))
            .map_err(|e| ProvisionError::Http {
                url: self.url.clone(),
                message: e.to_string(),
            })
    }
}

/// `bytes a-b/total` -> (a, total).
fn parse_content_range(v: &str) -> Option<(u64, Option<u64>)> {
    let rest = v.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let start = range.split_once('-')?.0.trim().parse().ok()?;
    Some((start, total.trim().parse().ok()))
}

#[async_trait]
impl Fetcher for HttpsFetcher {
    async fn fetch(&self, url: &str, from: u64) -> Result<Fetched, ProvisionError> {
        require_https(url)?;
        let mut req = self.client.get(url);
        if from > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={from}-"));
        }
        let http_err = |m: String| ProvisionError::Http {
            url: url.to_string(),
            message: m,
        };
        let resp = req.send().await.map_err(|e| http_err(e.to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            return Err(ProvisionError::RangeNotSatisfiable);
        }
        if !status.is_success() {
            return Err(http_err(format!("HTTP {status}")));
        }
        let (resumed, total) = if status == reqwest::StatusCode::PARTIAL_CONTENT {
            let cr = resp
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_content_range);
            match cr {
                Some((start, total)) if start == from => (true, total),
                _ => return Err(http_err("unexpected Content-Range".into())),
            }
        } else {
            (false, resp.content_length())
        };
        Ok(Fetched {
            resumed,
            total,
            body: Box::new(ReqwestBody {
                resp,
                url: url.to_string(),
            }),
        })
    }
}

/// SHA-256 of a file, lower-case hex.
pub fn sha256_file(path: &Path) -> Result<String, ProvisionError> {
    let mut f = File::open(path).map_err(io_err(format!("cannot read {}", path.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(io_err(format!("cannot read {}", path.display())))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn verify(spec: &ArtifactSpec, path: &Path) -> Result<(), ProvisionError> {
    let actual = sha256_file(path)?;
    if actual.eq_ignore_ascii_case(&spec.sha256) {
        Ok(())
    } else {
        Err(ProvisionError::Sha256Mismatch {
            name: spec.name.clone(),
            expected: spec.sha256.clone(),
            actual,
        })
    }
}

async fn blocking<T, F>(f: F) -> Result<T, ProvisionError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ProvisionError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ProvisionError::Build(format!("background task failed: {e}")))?
}

/// Downloads `spec` into `dir` (resuming `<file>.part`), checks the hash and returns the path of
/// the verified file. A hash mismatch deletes the download. An already downloaded, verified file
/// is reused.
pub async fn download(
    fetcher: &dyn Fetcher,
    spec: &ArtifactSpec,
    dir: &Path,
    progress: ProgressFn<'_>,
) -> Result<PathBuf, ProvisionError> {
    require_https(&spec.url)?;
    fs::create_dir_all(dir).map_err(io_err(format!("cannot create {}", dir.display())))?;
    let final_path = dir.join(&spec.file_name);
    let part = dir.join(format!("{}.part", spec.file_name));

    if final_path.is_file() {
        let (p, s) = (final_path.clone(), spec.clone());
        progress(Progress::Verifying {
            name: spec.name.clone(),
        });
        if blocking(move || verify(&s, &p)).await.is_ok() {
            return Ok(final_path);
        }
        let _ = fs::remove_file(&final_path);
    }

    let mut retried = false;
    loop {
        let have = fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        let fetched = match fetcher.fetch(&spec.url, have).await {
            Ok(f) => f,
            Err(ProvisionError::RangeNotSatisfiable) if have > 0 && !retried => {
                // The partial file is longer than the resource or stale: start over.
                let _ = fs::remove_file(&part);
                retried = true;
                continue;
            }
            Err(e) => return Err(e),
        };
        let mut file = if fetched.resumed {
            fs::OpenOptions::new()
                .append(true)
                .open(&part)
                .map_err(io_err(format!("cannot open {}", part.display())))?
        } else {
            File::create(&part).map_err(io_err(format!("cannot create {}", part.display())))?
        };
        let start = if fetched.resumed { have } else { 0 };
        let mut done = start;
        let mut body = fetched.body;
        let mut last_report = std::time::Instant::now();
        progress(Progress::Downloading {
            name: spec.name.clone(),
            done,
            total: fetched.total,
            resumed_from: start,
        });
        while let Some(chunk) = body.next_chunk().await? {
            file.write_all(&chunk)
                .map_err(io_err(format!("cannot write {}", part.display())))?;
            done += chunk.len() as u64;
            if last_report.elapsed() >= Duration::from_millis(250) {
                last_report = std::time::Instant::now();
                progress(Progress::Downloading {
                    name: spec.name.clone(),
                    done,
                    total: fetched.total,
                    resumed_from: start,
                });
            }
        }
        file.flush()
            .map_err(io_err(format!("cannot write {}", part.display())))?;
        drop(file);
        progress(Progress::Downloading {
            name: spec.name.clone(),
            done,
            total: fetched.total,
            resumed_from: start,
        });
        if let Some(expected) = fetched.total
            && done < expected
        {
            return Err(ProvisionError::Truncated {
                name: spec.name.clone(),
                got: done,
                expected,
            });
        }
        progress(Progress::Verifying {
            name: spec.name.clone(),
        });
        let (p, s) = (part.clone(), spec.clone());
        if let Err(e) = blocking(move || verify(&s, &p)).await {
            let _ = fs::remove_file(&part);
            return Err(e);
        }
        fs::rename(&part, &final_path)
            .map_err(io_err(format!("cannot move {} into place", part.display())))?;
        return Ok(final_path);
    }
}

// ---------------------------------------------------------------------------------------------
// Extraction

/// Fails unless `name` is a relative path of plain components.
fn safe_relative(name: &str) -> Result<PathBuf, ProvisionError> {
    let p = Path::new(name);
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProvisionError::UnsafePath(name.to_string()));
            }
        }
    }
    if out.as_os_str().is_empty() {
        return Err(ProvisionError::UnsafePath(name.to_string()));
    }
    Ok(out)
}

/// Whether `target`, resolved against the directory `link_parent` (relative to the extraction
/// root), stays inside the root.
fn link_stays_inside(link_parent: &Path, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth: i64 = link_parent
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count() as i64;
    for c in target.components() {
        match c {
            Component::Normal(_) => depth += 1,
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

/// Extracts a zip into `dest`, refusing unsafe entries. File modes are kept without group/other
/// write bits; symbolic links are refused.
pub fn extract_zip(archive: &Path, dest: &Path) -> Result<(), ProvisionError> {
    let file = File::open(archive).map_err(io_err(format!("cannot open {}", archive.display())))?;
    let mut zip = zip::ZipArchive::new(file)
        .map_err(|e| ProvisionError::BadArchive(format!("{}: {e}", archive.display())))?;
    fs::create_dir_all(dest).map_err(io_err(format!("cannot create {}", dest.display())))?;
    let mut budget = MAX_EXTRACTED_BYTES;
    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| ProvisionError::BadArchive(e.to_string()))?;
        let name = entry
            .name()
            .map_err(|e| ProvisionError::BadArchive(e.to_string()))?
            .into_owned();
        let rel = safe_relative(&name)?;
        if entry.is_symlink() {
            return Err(ProvisionError::BadArchive(format!(
                "{name} is a symbolic link"
            )));
        }
        let out = dest.join(&rel);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(io_err(format!("cannot create {}", out.display())))?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent)
                .map_err(io_err(format!("cannot create {}", parent.display())))?;
        }
        let mut f =
            File::create(&out).map_err(io_err(format!("cannot create {}", out.display())))?;
        let n = io::copy(&mut (&mut entry).take(budget + 1), &mut f)
            .map_err(io_err(format!("cannot write {}", out.display())))?;
        if n > budget {
            return Err(ProvisionError::BadArchive(
                "archive expands beyond the size limit".into(),
            ));
        }
        budget -= n;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = entry.unix_mode().unwrap_or(0o644) & 0o755;
            fs::set_permissions(&out, fs::Permissions::from_mode(mode | 0o600))
                .map_err(io_err(format!("cannot chmod {}", out.display())))?;
        }
        // Ghidra recompiles a `.sla` that is older than its sources, which fails in a read-only
        // install: keep the archive's modification times.
        if let Some(dt) = entry.last_modified() {
            let secs = dos_to_unix_secs(
                i32::from(dt.year()),
                dt.month(),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second(),
            );
            filetime::set_file_mtime(&out, filetime::FileTime::from_unix_time(secs, 0))
                .map_err(io_err(format!("cannot set the time of {}", out.display())))?;
        }
    }
    Ok(())
}

/// Seconds since the Unix epoch of a zip (MS-DOS) timestamp, read as UTC. The zone is unknown in
/// the archive; only the order of entries matters.
pub(crate) fn dos_to_unix_secs(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> i64 {
    // Days from civil (Howard Hinnant's algorithm).
    let y = i64::from(year) - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
}

/// Extracts a `.tar.gz` into `dest`, refusing unsafe entries and links that point outside.
pub fn extract_tar_gz(archive: &Path, dest: &Path) -> Result<(), ProvisionError> {
    let file = File::open(archive).map_err(io_err(format!("cannot open {}", archive.display())))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    tar.set_preserve_permissions(false);
    tar.set_unpack_xattrs(false);
    fs::create_dir_all(dest).map_err(io_err(format!("cannot create {}", dest.display())))?;
    let mut budget = MAX_EXTRACTED_BYTES;
    let entries = tar
        .entries()
        .map_err(|e| ProvisionError::BadArchive(format!("{}: {e}", archive.display())))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| ProvisionError::BadArchive(e.to_string()))?;
        let raw = entry
            .path()
            .map_err(|e| ProvisionError::BadArchive(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        let rel = safe_relative(&raw)?;
        let kind = entry.header().entry_type();
        use tar::EntryType as T;
        match kind {
            T::Regular | T::Continuous | T::Directory => {}
            T::Symlink => {
                let target = entry
                    .link_name()
                    .map_err(|e| ProvisionError::BadArchive(e.to_string()))?
                    .ok_or_else(|| ProvisionError::BadArchive(format!("{raw}: empty link")))?
                    .into_owned();
                let parent = rel.parent().unwrap_or(Path::new(""));
                if !link_stays_inside(parent, &target) {
                    return Err(ProvisionError::UnsafePath(format!(
                        "{raw} -> {}",
                        target.display()
                    )));
                }
            }
            T::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| ProvisionError::BadArchive(e.to_string()))?
                    .ok_or_else(|| ProvisionError::BadArchive(format!("{raw}: empty link")))?
                    .to_string_lossy()
                    .into_owned();
                safe_relative(&target)?;
            }
            T::XGlobalHeader | T::XHeader | T::GNULongName | T::GNULongLink => continue,
            other => {
                return Err(ProvisionError::BadArchive(format!(
                    "{raw}: unsupported entry type {other:?}"
                )));
            }
        }
        let size = entry.size();
        if size > budget {
            return Err(ProvisionError::BadArchive(
                "archive expands beyond the size limit".into(),
            ));
        }
        budget -= size;
        let unpacked = entry
            .unpack_in(dest)
            .map_err(|e| ProvisionError::BadArchive(format!("{raw}: {e}")))?;
        if !unpacked {
            return Err(ProvisionError::UnsafePath(raw));
        }
    }
    Ok(())
}

fn extract(spec: &ArtifactSpec, archive: &Path, dest: &Path) -> Result<(), ProvisionError> {
    match spec.format {
        ArchiveFormat::Zip => extract_zip(archive, dest),
        ArchiveFormat::TarGz => extract_tar_gz(archive, dest),
    }
}

// ---------------------------------------------------------------------------------------------
// The extension

/// The Java sources of the Ghidra extension, embedded so `kraken setup` can compile them with
/// the downloaded JDK.
pub const EXT_SOURCES: &[(&str, &str)] = &[
    (
        "Dispatcher.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/Dispatcher.java"),
    ),
    (
        "Engine.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/Engine.java"),
    ),
    (
        "Inspect.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/Inspect.java"),
    ),
    (
        "J.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/J.java"),
    ),
    (
        "KrakenError.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/KrakenError.java"),
    ),
    (
        "KrakenSidecar.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/KrakenSidecar.java"),
    ),
    (
        "Proto.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/Proto.java"),
    ),
    (
        "SelfTest.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/SelfTest.java"),
    ),
    (
        "TypeConv.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/TypeConv.java"),
    ),
    (
        "Wire.java",
        include_str!("../../../java/kraken-ghidra/src/main/java/kraken/ghidra/Wire.java"),
    ),
];

fn jars_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            jars_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "jar") {
            out.push(path);
        }
    }
}

/// Ghidra's own jars, the same set `buildExtension.gradle` compiles against.
pub fn ghidra_classpath(ghidra_home: &Path) -> Vec<PathBuf> {
    let mut jars = Vec::new();
    for sub in ["Framework", "Features", "Debug", "Processors"] {
        jars_under(&ghidra_home.join("Ghidra").join(sub), &mut jars);
    }
    jars.sort();
    jars
}

/// The `javac` argument file: options one per line, values quoted.
pub fn javac_args(classpath: &[PathBuf], classes: &Path, sources: &[PathBuf]) -> String {
    fn q(p: &Path) -> String {
        let s = p
            .to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("\"{s}\"")
    }
    let cp = classpath
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(if cfg!(windows) { ";" } else { ":" });
    let mut out = String::new();
    out.push_str("--release\n21\n-nowarn\n-encoding\nUTF-8\n-cp\n");
    out.push_str(&q(Path::new(&cp)));
    out.push_str("\n-d\n");
    out.push_str(&q(classes));
    out.push('\n');
    for s in sources {
        out.push_str(&q(s));
        out.push('\n');
    }
    out
}

fn run_tool(cmd: &mut Command, what: &str) -> Result<(), ProvisionError> {
    let out = cmd
        .output()
        .map_err(|e| ProvisionError::Build(format!("cannot run {what}: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    let mut text = String::from_utf8_lossy(&out.stderr).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stdout));
    let tail: Vec<&str> = text.lines().rev().take(30).collect();
    let tail: Vec<&str> = tail.into_iter().rev().collect();
    Err(ProvisionError::Build(format!(
        "{what} exited with {}: {}",
        out.status,
        tail.join("\n")
    )))
}

/// Compiles [`EXT_SOURCES`] with the JDK at `java_home` against the Ghidra at `ghidra_home` and
/// writes the jar to `out_jar` (atomically).
pub fn build_extension(
    java_home: &Path,
    ghidra_home: &Path,
    work: &Path,
    out_jar: &Path,
) -> Result<(), ProvisionError> {
    let _ = fs::remove_dir_all(work);
    let src_dir = work.join("src/kraken/ghidra");
    let classes = work.join("classes");
    fs::create_dir_all(&src_dir).map_err(io_err(format!("cannot create {}", src_dir.display())))?;
    fs::create_dir_all(&classes).map_err(io_err(format!("cannot create {}", classes.display())))?;
    let mut sources = Vec::new();
    for (name, text) in EXT_SOURCES {
        let p = src_dir.join(name);
        fs::write(&p, text).map_err(io_err(format!("cannot write {}", p.display())))?;
        sources.push(p);
    }
    let classpath = ghidra_classpath(ghidra_home);
    if classpath.is_empty() {
        return Err(ProvisionError::Build(format!(
            "no Ghidra jars under {}",
            ghidra_home.display()
        )));
    }
    let argfile = work.join("javac.args");
    fs::write(&argfile, javac_args(&classpath, &classes, &sources))
        .map_err(io_err(format!("cannot write {}", argfile.display())))?;
    let mut javac = Command::new(java_home.join("bin/javac"));
    javac.arg(format!("@{}", argfile.display())).env_clear();
    run_tool(&mut javac, "javac")?;

    let tmp_jar = work.join("kraken-ghidra.jar");
    let mut jar = Command::new(java_home.join("bin/jar"));
    jar.args(["--create", "--file"])
        .arg(&tmp_jar)
        .arg("-C")
        .arg(&classes)
        .arg(".")
        .env_clear();
    run_tool(&mut jar, "jar")?;

    if let Some(parent) = out_jar.parent() {
        fs::create_dir_all(parent)
            .map_err(io_err(format!("cannot create {}", parent.display())))?;
    }
    fs::copy(&tmp_jar, out_jar).map_err(io_err(format!("cannot write {}", out_jar.display())))?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Setup

/// Options of [`setup`].
#[derive(Debug, Clone, Default)]
pub struct SetupOptions {
    /// Download, extract and build again even when everything is in place.
    pub force: bool,
}

/// Installs the pinned Ghidra and JDK and builds the extension. Idempotent: pieces that are
/// already in place are skipped unless `force` is set.
pub async fn setup(
    layout: &Layout,
    fetcher: &dyn Fetcher,
    specs: &(ArtifactSpec, ArtifactSpec),
    opts: &SetupOptions,
    progress: ProgressFn<'_>,
) -> Result<Provisioned, ProvisionError> {
    fs::create_dir_all(layout.root())
        .map_err(io_err(format!("cannot create {}", layout.root().display())))?;
    let mut installed_now = false;
    for spec in [&specs.0, &specs.1] {
        let dest = layout.install_dir(spec);
        let marker = if spec.name == "ghidra" {
            dest.join("Ghidra/application.properties")
        } else {
            dest.join("bin/javac")
        };
        if marker.is_file() && !opts.force {
            progress(Progress::Skipped {
                name: spec.name.clone(),
            });
            continue;
        }
        let archive = download(fetcher, spec, &layout.downloads_dir(), progress).await?;
        progress(Progress::Extracting {
            name: spec.name.clone(),
        });
        let staging = layout
            .root()
            .join(format!(".staging-{}-{}", spec.name, std::process::id()));
        let (s, a, st) = (spec.clone(), archive.clone(), staging.clone());
        let extracted = blocking(move || {
            let _ = fs::remove_dir_all(&st);
            extract(&s, &a, &st)
        })
        .await;
        if let Err(e) = extracted {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
        let from = staging.join(&spec.top_dir);
        if !from.is_dir() {
            let _ = fs::remove_dir_all(&staging);
            return Err(ProvisionError::BadArchive(format!(
                "{} does not contain {}",
                spec.file_name, spec.top_dir
            )));
        }
        let parent = dest.parent().unwrap_or(layout.root()).to_path_buf();
        fs::create_dir_all(&parent)
            .map_err(io_err(format!("cannot create {}", parent.display())))?;
        let _ = fs::remove_dir_all(&dest);
        fs::rename(&from, &dest).map_err(io_err(format!("cannot move into {}", dest.display())))?;
        let _ = fs::remove_dir_all(&staging);
        installed_now = true;
    }

    let have = layout.provisioned();
    if opts.force || installed_now || have.ext_jar.is_none() {
        let (Some(ghidra), Some(jdk)) = (have.ghidra_home.clone(), have.java_home.clone()) else {
            return Err(ProvisionError::Build(
                "Ghidra or the JDK is missing after extraction".into(),
            ));
        };
        progress(Progress::BuildingExtension);
        let work = layout.root().join(".ext-build");
        let out = layout.ext_jar();
        let w = work.clone();
        let built = blocking(move || build_extension(&jdk, &ghidra, &w, &out)).await;
        let _ = fs::remove_dir_all(&work);
        built?;
    }
    Ok(layout.provisioned())
}

#[cfg(test)]
mod tests;

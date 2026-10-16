//! `kraken infer setup llama`: a pinned upstream llama.cpp release build in KRAKEN's data
//! directory (decision 69).
//!
//! Every build is named by exact release tag, file name and SHA-256 (taken from the GitHub
//! release assets and checked against real downloads). [`provision::download`] verifies the hash
//! before anything is extracted; extraction refuses paths that leave the destination, and the
//! tree is moved into place only when `llama-server` is in it. Model files are never downloaded:
//! people choose their own GGUF (see `docs/local-models.md`).

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use kraken_infer::GpuApi;
use serde::{Deserialize, Serialize};

use crate::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, Progress, ProgressFn, ProvisionError, download,
    extract_tar_gz, extract_zip,
};

/// The llama.cpp release the builds below come from.
pub const LLAMA_TAG: &str = "b11696";

const BASE_URL: &str = "https://github.com/ggml-org/llama.cpp/releases/download";

/// Name of the server executable inside a build.
pub const LLAMA_BINARY: &str = if cfg!(windows) {
    "llama-server.exe"
} else {
    "llama-server"
};

struct Row {
    variant: &'static str,
    os: &'static str,
    arch: &'static str,
    file: &'static str,
    sha256: &'static str,
    size: u64,
    format: ArchiveFormat,
    /// Directory the archive extracts to; `None` for archives with the files at the top.
    top_dir: Option<&'static str>,
    gpu: GpuApi,
}

const ROWS: &[Row] = &[
    Row {
        variant: "cpu",
        os: "linux",
        arch: "x86_64",
        file: "llama-b11696-bin-ubuntu-x64.tar.gz",
        sha256: "6a04629ca5265eb4c5c7d6edec8d6fa429e7e7da2de1cd5d5e357a492fc8f802",
        size: 17_883_307,
        format: ArchiveFormat::TarGz,
        top_dir: Some("llama-b11696"),
        gpu: GpuApi::Cpu,
    },
    Row {
        variant: "vulkan",
        os: "linux",
        arch: "x86_64",
        file: "llama-b11696-bin-ubuntu-vulkan-x64.tar.gz",
        sha256: "eac48cc39b960deabe8345f16fc3a27f09317cddeb072b666b967bc13ea60c03",
        size: 30_528_842,
        format: ArchiveFormat::TarGz,
        top_dir: Some("llama-b11696"),
        gpu: GpuApi::Vulkan,
    },
    Row {
        variant: "metal",
        os: "macos",
        arch: "aarch64",
        file: "llama-b11696-bin-macos-arm64.tar.gz",
        sha256: "6aac007fbe153efefe06250d2cf05d0487583aa0706379082ebef2b05579f649",
        size: 12_222_784,
        format: ArchiveFormat::TarGz,
        top_dir: Some("llama-b11696"),
        gpu: GpuApi::Metal,
    },
    Row {
        variant: "cpu",
        os: "windows",
        arch: "x86_64",
        file: "llama-b11696-bin-win-cpu-x64.zip",
        sha256: "1e7c47dff58467540d53e6cf302d83951bcb165afb252c2952ed3872190fc60d",
        size: 19_575_690,
        format: ArchiveFormat::Zip,
        top_dir: None,
        gpu: GpuApi::Cpu,
    },
    Row {
        variant: "vulkan",
        os: "windows",
        arch: "x86_64",
        file: "llama-b11696-bin-win-vulkan-x64.zip",
        sha256: "f62bbf1ce154911ce37a381b9b308893b064301ecb7512f30c7c2abf7f812e75",
        size: 32_220_792,
        format: ArchiveFormat::Zip,
        top_dir: None,
        gpu: GpuApi::Vulkan,
    },
];

/// One downloadable llama.cpp build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlamaRelease {
    /// `cpu`, `vulkan` or `metal`.
    pub variant: String,
    /// `std::env::consts::OS` value.
    pub os: String,
    /// `std::env::consts::ARCH` value.
    pub arch: String,
    /// Release tag.
    pub tag: String,
    /// Asset file name.
    pub file_name: String,
    /// `https://` URL of the asset.
    pub url: String,
    /// Lower-case hex SHA-256 of the asset.
    pub sha256: String,
    /// Asset size in bytes.
    pub size: u64,
    /// Container format.
    pub format: ArchiveFormat,
    /// Top-level directory of the archive, when it has one.
    pub top_dir: Option<String>,
    /// GPU API the build uses.
    pub gpu_api: GpuApi,
}

impl LlamaRelease {
    fn from_row(r: &Row) -> Self {
        LlamaRelease {
            variant: r.variant.into(),
            os: r.os.into(),
            arch: r.arch.into(),
            tag: LLAMA_TAG.into(),
            file_name: r.file.into(),
            url: format!("{BASE_URL}/{LLAMA_TAG}/{}", r.file),
            sha256: r.sha256.into(),
            size: r.size,
            format: r.format,
            top_dir: r.top_dir.map(str::to_string),
            gpu_api: r.gpu,
        }
    }

    /// The download as a generic pinned artifact.
    pub fn spec(&self) -> ArtifactSpec {
        ArtifactSpec {
            name: "llama-server".into(),
            file_name: self.file_name.clone(),
            url: self.url.clone(),
            sha256: self.sha256.clone(),
            format: self.format,
            top_dir: self.top_dir.clone().unwrap_or_default(),
        }
    }
}

/// Every pinned build.
pub fn pinned_releases() -> Vec<LlamaRelease> {
    ROWS.iter().map(LlamaRelease::from_row).collect()
}

/// The builds for a platform, the default one first.
pub fn releases_for(os: &str, arch: &str) -> Vec<LlamaRelease> {
    ROWS.iter()
        .filter(|r| r.os == os && r.arch == arch)
        .map(LlamaRelease::from_row)
        .collect()
}

/// The builds for the running platform.
pub fn current_releases() -> Vec<LlamaRelease> {
    releases_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Picks the build named `variant`, or the platform's default when `None`.
pub fn choose(
    releases: &[LlamaRelease],
    variant: Option<&str>,
) -> Result<LlamaRelease, ProvisionError> {
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    if releases.is_empty() {
        return Err(ProvisionError::NoBuild(format!(
            "KRAKEN has no pinned llama.cpp build for {platform}; install llama-server yourself \
             (it is found on PATH) or run another engine through a manifest, see docs/local-models.md"
        )));
    }
    match variant {
        None => Ok(releases[0].clone()),
        Some(v) => releases
            .iter()
            .find(|r| r.variant == v)
            .cloned()
            .ok_or_else(|| {
                let names: Vec<&str> = releases.iter().map(|r| r.variant.as_str()).collect();
                ProvisionError::NoBuild(format!(
                    "there is no `{v}` llama.cpp build for {platform}; choose one of: {}",
                    names.join(", ")
                ))
            }),
    }
}

/// KRAKEN's per-user data directory (`$XDG_DATA_HOME/kraken`, else `~/.local/share/kraken`,
/// else `%LOCALAPPDATA%\kraken` on Windows).
pub fn data_dir_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let non_empty = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(x) = non_empty("XDG_DATA_HOME").filter(|p| p.is_absolute()) {
        return Some(x.join("kraken"));
    }
    if let Some(h) = non_empty("HOME") {
        return Some(h.join(".local/share/kraken"));
    }
    if cfg!(windows) {
        return non_empty("LOCALAPPDATA").map(|l| l.join("kraken"));
    }
    None
}

/// What is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledLlama {
    /// Release tag.
    pub tag: String,
    /// Build variant.
    pub variant: String,
    /// Path of `llama-server`.
    pub binary: PathBuf,
}

/// Where llama.cpp builds live: `<data dir>/llama/<tag>-<variant>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlamaLayout {
    root: PathBuf,
}

const CURRENT_FILE: &str = "current.json";

fn io_err(what: impl Into<String>, source: std::io::Error) -> ProvisionError {
    ProvisionError::Io {
        what: what.into(),
        source,
    }
}

impl LlamaLayout {
    /// A layout whose files live under `data_dir/llama`.
    pub fn in_data_dir(data_dir: &Path) -> Self {
        LlamaLayout {
            root: data_dir.join("llama"),
        }
    }

    /// From the environment (see [`data_dir_with`]).
    pub fn from_env_with(env: &dyn Fn(&str) -> Option<OsString>) -> Option<Self> {
        data_dir_with(env).map(|d| Self::in_data_dir(&d))
    }

    /// The root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Downloaded archives.
    pub fn downloads_dir(&self) -> PathBuf {
        self.root.join("downloads")
    }

    /// Where `release` is installed.
    pub fn install_dir(&self, release: &LlamaRelease) -> PathBuf {
        self.root
            .join(format!("{}-{}", release.tag, release.variant))
    }

    /// The build that `kraken infer start` uses, when one is installed and still intact.
    pub fn installed(&self) -> Option<InstalledLlama> {
        let text = fs::read_to_string(self.root.join(CURRENT_FILE)).ok()?;
        let cur: InstalledLlama = serde_json::from_str(&text).ok()?;
        cur.binary.is_file().then_some(cur)
    }
}

/// Downloads, verifies and installs `release`. Idempotent: an intact install is kept unless
/// `force` is set.
pub async fn install_llama(
    layout: &LlamaLayout,
    fetcher: &dyn Fetcher,
    release: &LlamaRelease,
    force: bool,
    progress: ProgressFn<'_>,
) -> Result<InstalledLlama, ProvisionError> {
    let dest = layout.install_dir(release);
    let binary = dest.join(LLAMA_BINARY);
    let installed = InstalledLlama {
        tag: release.tag.clone(),
        variant: release.variant.clone(),
        binary: binary.clone(),
    };
    if binary.is_file() && !force {
        progress(Progress::Skipped {
            name: "llama-server".into(),
        });
        write_current(layout, &installed)?;
        return Ok(installed);
    }
    let spec = release.spec();
    let archive = download(fetcher, &spec, &layout.downloads_dir(), progress).await?;
    progress(Progress::Extracting {
        name: "llama-server".into(),
    });
    fs::create_dir_all(layout.root())
        .map_err(|e| io_err(format!("cannot create {}", layout.root().display()), e))?;
    let staging = layout.root().join(format!(
        ".staging-{}-{}",
        release.variant,
        std::process::id()
    ));
    let (fmt, a, st) = (release.format, archive, staging.clone());
    let extracted = tokio::task::spawn_blocking(move || {
        let _ = fs::remove_dir_all(&st);
        match fmt {
            ArchiveFormat::Zip => extract_zip(&a, &st),
            ArchiveFormat::TarGz => extract_tar_gz(&a, &st),
        }
    })
    .await
    .map_err(|e| ProvisionError::BadArchive(format!("background task failed: {e}")))
    .and_then(|r| r);
    let result = extracted.and_then(|()| move_into_place(release, &staging, &dest));
    let _ = fs::remove_dir_all(&staging);
    result?;
    write_current(layout, &installed)?;
    Ok(installed)
}

fn move_into_place(
    release: &LlamaRelease,
    staging: &Path,
    dest: &Path,
) -> Result<(), ProvisionError> {
    let from = match &release.top_dir {
        Some(top) => staging.join(top),
        None => staging.to_path_buf(),
    };
    if !from.join(LLAMA_BINARY).is_file() {
        return Err(ProvisionError::BadArchive(format!(
            "{} does not contain {LLAMA_BINARY}",
            release.file_name
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let bin = from.join(LLAMA_BINARY);
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755))
            .map_err(|e| io_err(format!("cannot chmod {}", bin.display()), e))?;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| io_err(format!("cannot create {}", parent.display()), e))?;
    }
    let _ = fs::remove_dir_all(dest);
    fs::rename(&from, dest).map_err(|e| io_err(format!("cannot move into {}", dest.display()), e))
}

fn write_current(layout: &LlamaLayout, installed: &InstalledLlama) -> Result<(), ProvisionError> {
    let text = serde_json::to_string_pretty(installed)
        .map_err(|e| ProvisionError::BadArchive(e.to_string()))?;
    let path = layout.root().join(CURRENT_FILE);
    let tmp = layout.root().join(format!(".{CURRENT_FILE}.part"));
    fs::write(&tmp, text).map_err(|e| io_err(format!("cannot write {}", tmp.display()), e))?;
    fs::rename(&tmp, &path).map_err(|e| io_err(format!("cannot write {}", path.display()), e))
}

#[cfg(test)]
mod tests;

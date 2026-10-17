//! `kraken setup --dotnet`: a pinned .NET runtime plus the prebuilt `kraken-dotnet` sidecar that
//! ships next to the release binaries (ADR 0014 style: nothing is compiled on the user's machine,
//! and the .NET SDK is not needed).
//!
//! The runtime archive is downloaded from Microsoft's CDN, hashed completely and rejected on a
//! mismatch **before** anything is extracted ([`provision::download`]). The pinned SHA-256 was
//! computed from an archive that matched the sha512 in Microsoft's release metadata
//! (`releases.json` of the 10.0 channel). The sidecar is copied from the release layout (the
//! `kraken-dotnet/` directory next to the executable or in `share/kraken`), never downloaded.
//! Only Linux x86_64 is pinned, like the sidecar sandbox.

use std::fs;
use std::path::{Path, PathBuf};

use crate::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, Layout, Progress, ProgressFn, ProvisionError, download,
    extract_tar_gz,
};

/// The .NET runtime version `kraken setup --dotnet` installs (the sidecar targets `net10.0`).
pub const DOTNET_VERSION: &str = "10.0.13";
/// Download URL of the pinned runtime (Linux x64).
pub const DOTNET_URL: &str = "https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.13/dotnet-runtime-10.0.13-linux-x64.tar.gz";
/// SHA-256 of the pinned runtime archive.
pub const DOTNET_SHA256: &str = "958c952691d2c3f8ce21f717f4e911c02b5da0e21ead21bd576368c454b79c77";
/// SHA-512 Microsoft publishes for the same archive (kept for cross-checking against
/// `releases.json`; the download itself is verified with the SHA-256).
pub const DOTNET_SHA512: &str = "9574d95364110409416735e7842796f8d614c21d74cb25d204a3e4cfd11b2c05efdf19ca89b8069650a04f64add2705967dcb04b8665a36d7a3f30a5d8c05afe";
/// File name of the sidecar assembly.
pub const SIDECAR_DLL: &str = "kraken-dotnet.dll";
/// Directory name of the sidecar in release archives and in the runtime directory.
pub const SIDECAR_DIR: &str = "kraken-dotnet";

/// Most nested directories and files accepted when copying a bundled sidecar.
const MAX_COPY_DEPTH: usize = 8;
const MAX_COPY_FILES: usize = 512;

/// The pinned runtime for this platform. The spec's `top_dir` is the install directory name (the
/// archive itself has its files at the top level).
pub fn pinned_dotnet() -> Result<ArtifactSpec, ProvisionError> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(ProvisionError::NoBuild(format!(
            "the .NET engine is provisioned for Linux x86_64 only (this is {}-{}); install a \
             .NET {DOTNET_VERSION} runtime yourself and set KRAKEN_DOTNET_ROOT and \
             KRAKEN_DOTNET_EXT_DLL",
            std::env::consts::OS,
            std::env::consts::ARCH
        )));
    }
    Ok(ArtifactSpec {
        name: "dotnet".into(),
        file_name: format!("dotnet-runtime-{DOTNET_VERSION}-linux-x64.tar.gz"),
        url: DOTNET_URL.into(),
        sha256: DOTNET_SHA256.into(),
        format: ArchiveFormat::TarGz,
        top_dir: DOTNET_VERSION.into(),
    })
}

/// The pieces of a provisioned .NET engine that exist and look valid.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DotnetProvisioned {
    /// Directory holding the `dotnet` host.
    pub dotnet_root: Option<PathBuf>,
    /// `kraken-dotnet.dll`.
    pub ext_dll: Option<PathBuf>,
}

impl DotnetProvisioned {
    /// True when both pieces exist.
    pub fn is_complete(&self) -> bool {
        self.dotnet_root.is_some() && self.ext_dll.is_some()
    }
}

fn host_name() -> &'static str {
    if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    }
}

impl Layout {
    /// Where the pinned runtime is installed.
    pub fn dotnet_dir(&self) -> PathBuf {
        self.root().join("dotnet").join(DOTNET_VERSION)
    }

    /// Where the sidecar is installed (a directory with its dependencies).
    pub fn dotnet_ext_dir(&self) -> PathBuf {
        self.root().join("ext").join(SIDECAR_DIR)
    }

    /// Which .NET pieces exist: a runtime has the host and `shared/Microsoft.NETCore.App`, the
    /// sidecar is `kraken-dotnet.dll`.
    pub fn dotnet_provisioned(&self) -> DotnetProvisioned {
        let root = self.dotnet_dir();
        let dll = self.dotnet_ext_dir().join(SIDECAR_DLL);
        DotnetProvisioned {
            dotnet_root: (root.join(host_name()).is_file()
                && root.join("shared/Microsoft.NETCore.App").is_dir())
            .then_some(root),
            ext_dll: dll.is_file().then_some(dll),
        }
    }
}

/// Candidate locations of a release's prebuilt sidecar relative to an executable: next to it,
/// then `../share/kraken/` (the prefix layout).
pub fn bundled_sidecar_candidates(exe: &Path) -> Vec<PathBuf> {
    let Some(dir) = exe.parent() else {
        return Vec::new();
    };
    let mut out = vec![dir.join(SIDECAR_DIR)];
    if let Some(prefix) = dir.parent() {
        out.push(prefix.join("share/kraken").join(SIDECAR_DIR));
    }
    out
}

/// The prebuilt sidecar directory that ships with this release, if there is one.
pub fn bundled_sidecar() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = exe.canonicalize().unwrap_or(exe);
    bundled_sidecar_candidates(&exe)
        .into_iter()
        .find(|p| p.join(SIDECAR_DLL).is_file())
}

fn io_err(what: impl Into<String>, source: std::io::Error) -> ProvisionError {
    ProvisionError::Io {
        what: what.into(),
        source,
    }
}

fn copy_tree(
    from: &Path,
    to: &Path,
    depth: usize,
    files: &mut usize,
) -> Result<(), ProvisionError> {
    if depth > MAX_COPY_DEPTH {
        return Err(ProvisionError::BadArchive(format!(
            "{} is nested too deeply",
            from.display()
        )));
    }
    fs::create_dir_all(to).map_err(|e| io_err(format!("cannot create {}", to.display()), e))?;
    let entries =
        fs::read_dir(from).map_err(|e| io_err(format!("cannot read {}", from.display()), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| io_err(format!("cannot read {}", from.display()), e))?;
        let kind = entry
            .file_type()
            .map_err(|e| io_err(format!("cannot stat {}", entry.path().display()), e))?;
        let dest = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest, depth + 1, files)?;
        } else if kind.is_file() {
            *files += 1;
            if *files > MAX_COPY_FILES {
                return Err(ProvisionError::BadArchive(format!(
                    "{} holds too many files",
                    from.display()
                )));
            }
            fs::copy(entry.path(), &dest)
                .map_err(|e| io_err(format!("cannot copy {}", entry.path().display()), e))?;
        } else {
            return Err(ProvisionError::BadArchive(format!(
                "{} is not a regular file or directory",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

/// Copies the prebuilt sidecar directory `bundled` to `out_dir` (through a sibling temporary
/// directory, so a half-copied sidecar is never visible).
pub fn install_bundled_sidecar(bundled: &Path, out_dir: &Path) -> Result<(), ProvisionError> {
    if !bundled.join(SIDECAR_DLL).is_file() {
        return Err(ProvisionError::BadArchive(format!(
            "{} has no {SIDECAR_DLL}",
            bundled.display()
        )));
    }
    let Some(parent) = out_dir.parent() else {
        return Err(ProvisionError::Build(format!(
            "{} has no parent directory",
            out_dir.display()
        )));
    };
    fs::create_dir_all(parent)
        .map_err(|e| io_err(format!("cannot create {}", parent.display()), e))?;
    let tmp = parent.join(format!(".{SIDECAR_DIR}.{}.part", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let copied = copy_tree(bundled, &tmp, 0, &mut 0).and_then(|()| {
        let _ = fs::remove_dir_all(out_dir);
        fs::rename(&tmp, out_dir)
            .map_err(|e| io_err(format!("cannot write {}", out_dir.display()), e))
    });
    if copied.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    copied
}

/// Installs the pinned runtime and the sidecar. Idempotent: pieces in place are skipped unless
/// `force` is set. `bundled` is the prebuilt sidecar directory (see [`bundled_sidecar`]).
pub async fn setup_dotnet(
    layout: &Layout,
    fetcher: &dyn Fetcher,
    spec: &ArtifactSpec,
    bundled: Option<&Path>,
    force: bool,
    progress: ProgressFn<'_>,
) -> Result<DotnetProvisioned, ProvisionError> {
    // Fail before downloading 35 MB if the sidecar cannot be installed afterwards.
    let have = layout.dotnet_provisioned();
    if bundled.is_none() && (force || have.ext_dll.is_none()) {
        return Err(ProvisionError::NoBuild(
            "this KRAKEN build ships no prebuilt .NET sidecar (a `kraken-dotnet` directory next to \
             the executable or in share/kraken); build it with `cargo xtask dotnet-ext` and set \
             KRAKEN_DOTNET_ROOT and KRAKEN_DOTNET_EXT_DLL"
                .into(),
        ));
    }
    fs::create_dir_all(layout.root())
        .map_err(|e| io_err(format!("cannot create {}", layout.root().display()), e))?;

    let dest = layout.dotnet_dir();
    if have.dotnet_root.is_some() && !force {
        progress(Progress::Skipped {
            name: spec.name.clone(),
        });
    } else {
        let archive = download(fetcher, spec, &layout.downloads_dir(), progress).await?;
        progress(Progress::Extracting {
            name: spec.name.clone(),
        });
        let staging = layout
            .root()
            .join(format!(".staging-dotnet-{}", std::process::id()));
        let (a, st) = (archive, staging.clone());
        let extracted = tokio::task::spawn_blocking(move || {
            let _ = fs::remove_dir_all(&st);
            extract_tar_gz(&a, &st)
        })
        .await
        .map_err(|e| ProvisionError::BadArchive(format!("background task failed: {e}")))
        .and_then(|r| r);
        let moved = extracted.and_then(|()| {
            let host = staging.join(host_name());
            if !host.is_file() || !staging.join("shared/Microsoft.NETCore.App").is_dir() {
                return Err(ProvisionError::BadArchive(format!(
                    "{} does not contain a .NET runtime",
                    spec.file_name
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&host, fs::Permissions::from_mode(0o755))
                    .map_err(|e| io_err(format!("cannot chmod {}", host.display()), e))?;
            }
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| io_err(format!("cannot create {}", parent.display()), e))?;
            }
            let _ = fs::remove_dir_all(&dest);
            fs::rename(&staging, &dest)
                .map_err(|e| io_err(format!("cannot move into {}", dest.display()), e))
        });
        if moved.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        moved?;
    }

    if let Some(bundled) = bundled
        && (force || have.ext_dll.is_none())
    {
        progress(Progress::Extracting {
            name: SIDECAR_DIR.into(),
        });
        let (b, out) = (bundled.to_path_buf(), layout.dotnet_ext_dir());
        tokio::task::spawn_blocking(move || install_bundled_sidecar(&b, &out))
            .await
            .map_err(|e| ProvisionError::BadArchive(format!("background task failed: {e}")))??;
    } else if have.ext_dll.is_some() {
        progress(Progress::Skipped {
            name: SIDECAR_DIR.into(),
        });
    }
    Ok(layout.dotnet_provisioned())
}

#[cfg(test)]
mod tests;

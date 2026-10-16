//! Locating the isolated .NET SDK/runtime and the built sidecar.

use std::path::{Path, PathBuf};

use crate::error::DotnetError;

/// Env var naming the .NET installation (a directory containing the `dotnet` host).
pub const ENV_DOTNET_ROOT: &str = "KRAKEN_DOTNET_ROOT";
/// Env var naming `kraken-dotnet.dll`.
pub const ENV_EXT_DLL: &str = "KRAKEN_DOTNET_EXT_DLL";

/// Where to look; unset fields use the environment, then the dev cache.
#[derive(Debug, Clone, Default)]
pub struct InstallConfig {
    /// Directory containing the `dotnet` host and `shared/`.
    pub dotnet_root: Option<PathBuf>,
    /// Path of the published `kraken-dotnet.dll`.
    pub ext_dll: Option<PathBuf>,
}

/// A usable .NET installation plus the sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DotnetInstall {
    /// Directory containing the `dotnet` host.
    pub dotnet_root: PathBuf,
    /// The `dotnet` executable.
    pub host: PathBuf,
    /// The sidecar assembly.
    pub ext_dll: PathBuf,
}

fn host_name() -> &'static str {
    if cfg!(windows) {
        "dotnet.exe"
    } else {
        "dotnet"
    }
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

impl DotnetInstall {
    /// Finds the installation: explicit config, then `KRAKEN_DOTNET_ROOT` / `KRAKEN_DOTNET_EXT_DLL`,
    /// then `~/.cache/kraken-dev/dotnet` and `dotnet/kraken-dotnet/bin/kraken-dotnet.dll` in the
    /// repository. The system-wide `dotnet` is never used.
    pub fn discover(cfg: &InstallConfig) -> Result<DotnetInstall, DotnetError> {
        let root = cfg
            .dotnet_root
            .clone()
            .or_else(|| std::env::var_os(ENV_DOTNET_ROOT).map(PathBuf::from))
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kraken-dev/dotnet"))
            })
            .ok_or_else(|| {
                DotnetError::Install(format!("{ENV_DOTNET_ROOT} is not set and HOME is unknown"))
            })?;
        let host = root.join(host_name());
        if !host.is_file() {
            return Err(DotnetError::Install(format!(
                "no `{}` in {}; install the pinned SDK with dotnet/install-sdk.sh or set \
                 {ENV_DOTNET_ROOT}",
                host_name(),
                root.display()
            )));
        }
        let ext_dll = cfg
            .ext_dll
            .clone()
            .or_else(|| std::env::var_os(ENV_EXT_DLL).map(PathBuf::from))
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../dotnet/kraken-dotnet/bin/kraken-dotnet.dll")
            });
        if !ext_dll.is_file() {
            return Err(DotnetError::Install(format!(
                "the sidecar {} is missing; build it with `cargo xtask dotnet-ext`",
                ext_dll.display()
            )));
        }
        Ok(DotnetInstall {
            host: canonical(&host),
            dotnet_root: canonical(&root),
            ext_dll: canonical(&ext_dll),
        })
    }
}

//! Installs the Strata engine and one of its models under KRAKEN's data directory.
//!
//! Nothing is piped to a shell and nothing is written outside `<data dir>/engines/strata`:
//!
//! 1. the pinned Strata source archive and the pinned llama.cpp source archive are downloaded
//!    and their SHA-256 checked against `kraken-infer`'s `data/strata.toml`;
//! 2. a private Python venv gets the requirements the pinned source lists (the file's own hash
//!    is checked first);
//! 3. the model files are downloaded and checked against Hugging Face's published LFS oids;
//! 4. Strata's own `setup.py` runs in the venv with `--build --yes --no-start` against those
//!    verified inputs (it finds llama.cpp already in place and the GGUF files by `--gguf-dir`,
//!    so it downloads neither), with a `sudo` that always fails first on `PATH`.
//!
//! Missing system pieces (NVIDIA driver, `nvcc`, a C++ compiler, Python with venv) stop the
//! setup before any download, naming each one; they are never installed here.

use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use kraken_infer::strata::{
    Missing, Source, StrataManifest, StrataModel, backend_manifest, backend_manifest_text,
};
use sha2::{Digest, Sha256};

use crate::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, Progress, ProvisionError, download, extract_tar_gz,
};

/// Why a Strata setup stopped.
#[derive(Debug, thiserror::Error)]
pub enum StrataError {
    /// The computer lacks something KRAKEN does not install.
    #[error("{}", render_missing(.0))]
    Missing(Vec<Missing>),
    /// A download, hash check or extraction failed.
    #[error(transparent)]
    Provision(#[from] ProvisionError),
    /// A file operation failed.
    #[error("{what}: {source}")]
    Io {
        what: String,
        #[source]
        source: std::io::Error,
    },
    /// A pinned input is not what the manifest says.
    #[error("{0}")]
    Pin(String),
    /// A build or install command failed; its output is in the setup log.
    #[error("step `{step}` failed: {message} (see {log})")]
    Step {
        step: String,
        message: String,
        log: String,
    },
}

fn render_missing(m: &[Missing]) -> String {
    let items: Vec<String> = m
        .iter()
        .map(|x| format!("{} -- {}", x.what, x.how_to_fix))
        .collect();
    format!(
        "this computer is missing what Strata needs and KRAKEN does not install system software: {}",
        items.join("; ")
    )
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> StrataError {
    let what = what.into();
    move |source| StrataError::Io { what, source }
}

/// Where everything lives: `<data dir>/engines/strata`.
#[derive(Debug, Clone)]
pub struct StrataLayout {
    root: PathBuf,
}

impl StrataLayout {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        StrataLayout { root: root.into() }
    }

    /// `<data dir>/engines/strata` for a data dir like `~/.local/share/kraken`.
    pub fn in_data_dir(data_dir: &Path) -> Self {
        Self::at(data_dir.join("engines").join("strata"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Strata's checkout (its `setup.py` and `serve/`).
    pub fn src(&self) -> PathBuf {
        self.root.join("src")
    }
    pub fn venv(&self) -> PathBuf {
        self.root.join("venv")
    }
    pub fn python(&self) -> PathBuf {
        self.venv().join("bin").join("python")
    }
    pub fn downloads(&self) -> PathBuf {
        self.root.join("downloads")
    }
    /// Directory holding every shard of one quantisation.
    pub fn gguf_dir(&self, quant: &str) -> PathBuf {
        self.root.join("models").join(quant)
    }
    pub fn shims(&self) -> PathBuf {
        self.root.join("shims")
    }
    pub fn log(&self) -> PathBuf {
        self.root.join("setup.log")
    }
    /// The supervised-server manifest written at the end.
    pub fn backend_manifest(&self) -> PathBuf {
        self.root.join("backend.toml")
    }
}

/// One command to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// Added to the small environment the command gets.
    pub env: Vec<(String, String)>,
}

/// Runs the commands of a setup. The real one is [`SystemRunner`]; tests record them.
#[async_trait]
pub trait Runner: Send + Sync {
    async fn run(&self, step: &str, cmd: &Cmd, log: &Path) -> Result<(), StrataError>;
}

/// Runs commands with a cleared environment: `HOME`, caches and temp dirs are inside the
/// install root, and the shim directory (a failing `sudo`) comes first on `PATH`.
pub struct SystemRunner {
    root: PathBuf,
    shims: PathBuf,
    venv_bin: PathBuf,
}

impl SystemRunner {
    pub fn new(layout: &StrataLayout) -> Self {
        SystemRunner {
            root: layout.root().to_path_buf(),
            shims: layout.shims(),
            venv_bin: layout.venv().join("bin"),
        }
    }
}

#[async_trait]
impl Runner for SystemRunner {
    async fn run(&self, step: &str, cmd: &Cmd, log: &Path) -> Result<(), StrataError> {
        use std::io::Write as _;
        let logfile = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(io(format!("cannot open {}", log.display())))?;
        let mut head = logfile
            .try_clone()
            .map_err(io("cannot duplicate the log handle"))?;
        let _ = writeln!(head, "\n=== {step}: {:?} {:?}", cmd.program, cmd.args);
        let err = logfile
            .try_clone()
            .map_err(io("cannot duplicate the log handle"))?;
        let inherited_path = std::env::var_os("PATH").unwrap_or_default();
        let mut path = std::ffi::OsString::new();
        for dir in [&self.shims, &self.venv_bin] {
            path.push(dir);
            path.push(":");
        }
        path.push(inherited_path);
        let mut c = tokio::process::Command::new(&cmd.program);
        c.args(&cmd.args)
            .current_dir(&cmd.cwd)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.root.join("home"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_DATA_HOME", self.root.join("xdg-data"))
            .env("XDG_CONFIG_HOME", self.root.join("xdg-config"))
            .env("TMPDIR", self.root.join("tmp"))
            .env("PIP_CONFIG_FILE", "/dev/null")
            .env("PIP_REQUIRE_VIRTUALENV", "1")
            .env("PYTHONNOUSERSITE", "1")
            .stdin(std::process::Stdio::null())
            .stdout(logfile)
            .stderr(err)
            .kill_on_drop(true);
        for k in [
            "LANG",
            "LC_ALL",
            "USER",
            "CUDA_HOME",
            "CUDA_PATH",
            "LD_LIBRARY_PATH",
            "CC",
            "CXX",
        ] {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
        for (k, v) in &cmd.env {
            c.env(k, v);
        }
        let status = c
            .status()
            .await
            .map_err(io(format!("cannot run {}", cmd.program.display())))?;
        if status.success() {
            Ok(())
        } else {
            Err(StrataError::Step {
                step: step.into(),
                message: format!("exited with {status}"),
                log: log.display().to_string(),
            })
        }
    }
}

/// What a finished setup produced.
#[derive(Debug, Clone)]
pub struct StrataInstall {
    pub root: PathBuf,
    pub gguf_dir: PathBuf,
    pub backend_manifest: PathBuf,
    pub config: PathBuf,
}

/// One progress report: step `index` of `steps`, and bytes of the current file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrataEvent {
    pub index: usize,
    pub steps: usize,
    pub label: String,
    pub done: u64,
    pub total: u64,
}

fn spec_for(name: &str, file: &str, url: &str, sha256: &str) -> ArtifactSpec {
    ArtifactSpec {
        name: name.into(),
        file_name: file.into(),
        url: url.into(),
        sha256: sha256.into(),
        format: ArchiveFormat::TarGz,
        top_dir: String::new(),
    }
}

/// Replaces `dest` with the single top-level directory of the archive.
fn unpack_source(archive: &Path, dest: &Path) -> Result<(), StrataError> {
    let staging = dest.with_extension("unpack");
    let _ = fs::remove_dir_all(&staging);
    extract_tar_gz(archive, &staging)?;
    let mut dirs = fs::read_dir(&staging)
        .map_err(io(format!("cannot read {}", staging.display())))?
        .filter_map(|e| e.ok())
        .map(|e| e.path());
    let top = dirs
        .next()
        .filter(|p| p.is_dir())
        .ok_or_else(|| StrataError::Pin("the source archive is empty".into()))?;
    if dirs.next().is_some() {
        return Err(StrataError::Pin(
            "the source archive has more than one top-level entry".into(),
        ));
    }
    let _ = fs::remove_dir_all(dest);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(io(format!("cannot create {}", parent.display())))?;
    }
    fs::rename(&top, dest).map_err(io(format!("cannot move into {}", dest.display())))?;
    let _ = fs::remove_dir_all(&staging);
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, StrataError> {
    let bytes = fs::read(path).map_err(io(format!("cannot read {}", path.display())))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

async fn fetch_source(
    fetcher: &dyn Fetcher,
    layout: &StrataLayout,
    label: &str,
    s: &Source,
    progress: &mut (dyn FnMut(Progress) + Send),
) -> Result<PathBuf, StrataError> {
    let spec = spec_for(
        label,
        &format!("{label}-{}.tar.gz", s.commit),
        &s.url,
        &s.sha256,
    );
    Ok(download(fetcher, &spec, &layout.downloads(), progress).await?)
}

/// Installs Strata and `model`. `missing` is the result of the prerequisite check; a
/// non-empty list stops the setup before anything is downloaded.
pub async fn install_strata(
    layout: &StrataLayout,
    fetcher: &dyn Fetcher,
    runner: &dyn Runner,
    manifest: &StrataManifest,
    model: &StrataModel,
    missing: Vec<Missing>,
    on_event: &mut (dyn FnMut(StrataEvent) + Send),
) -> Result<StrataInstall, StrataError> {
    if !missing.is_empty() {
        return Err(StrataError::Missing(missing));
    }
    let steps = 6;
    let mut index = 0usize;
    let mut event = |label: &str, done: u64, total: u64, index: usize| {
        on_event(StrataEvent {
            index,
            steps,
            label: label.into(),
            done,
            total,
        });
    };
    for sub in ["home", "cache", "xdg-data", "xdg-config", "tmp", "shims"] {
        fs::create_dir_all(layout.root().join(sub))
            .map_err(io(format!("cannot create {}", layout.root().display())))?;
    }
    let log = layout.log();

    // 1. Strata's source, at the pinned commit.
    index += 1;
    event("Strata source", 0, manifest.engine.source.size, index);
    let mut prog = |p: Progress| {
        if let Progress::Downloading { done, total, .. } = p {
            event("Strata source", done, total.unwrap_or(0), index);
        }
    };
    let archive = fetch_source(
        fetcher,
        layout,
        "strata",
        &manifest.engine.source,
        &mut prog,
    )
    .await?;
    unpack_source(&archive, &layout.src())?;
    let req = layout.src().join("requirements.txt");
    if file_sha256(&req)? != manifest.engine.requirements_sha256 {
        return Err(StrataError::Pin(
            "requirements.txt in the Strata source is not the pinned one; refusing to install it"
                .into(),
        ));
    }

    // 2. llama.cpp (ggml) at the commit Strata pins, placed where setup.py looks first.
    index += 1;
    let mut prog = |p: Progress| {
        if let Progress::Downloading { done, total, .. } = p {
            event("llama.cpp source", done, total.unwrap_or(0), index);
        }
    };
    let archive =
        fetch_source(fetcher, layout, "llama-cpp", &manifest.llama_cpp, &mut prog).await?;
    unpack_source(
        &archive,
        &layout.src().join("third_party").join("llama.cpp"),
    )?;

    // 3. A `sudo` that refuses, so no step can reach for system packages.
    let sudo = layout.shims().join("sudo");
    fs::write(
        &sudo,
        "#!/bin/sh\necho 'KRAKEN does not allow sudo during the Strata setup' >&2\nexit 1\n",
    )
    .map_err(io("cannot write the sudo shim"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755))
            .map_err(io("cannot mark the sudo shim executable"))?;
    }

    // 4. The private venv and the pinned Python packages.
    index += 1;
    event("Python environment", 0, 0, index);
    runner
        .run(
            "create venv",
            &Cmd {
                program: "python3".into(),
                args: vec![
                    "-m".into(),
                    "venv".into(),
                    layout.venv().display().to_string(),
                ],
                cwd: layout.root().to_path_buf(),
                env: vec![],
            },
            &log,
        )
        .await?;
    runner
        .run(
            "install pinned Python packages",
            &Cmd {
                program: layout.python(),
                args: [
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-input",
                    "--no-cache-dir",
                    "--only-binary",
                    ":all:",
                    "-r",
                ]
                .iter()
                .map(|s| s.to_string())
                .chain([req.display().to_string()])
                .collect(),
                cwd: layout.src(),
                env: vec![],
            },
            &log,
        )
        .await?;

    // 5. The model, shard by shard.
    index += 1;
    let dir = layout.gguf_dir(&model.quant);
    for f in &model.files {
        let spec = spec_for(&model.id, &f.name, &f.url, &f.sha256);
        let label = f.name.clone();
        let mut prog = |p: Progress| match p {
            Progress::Downloading { done, total, .. } => {
                event(&label, done, total.unwrap_or(f.size), index)
            }
            Progress::Verifying { .. } => {
                event(&format!("Checking {label}"), f.size, f.size, index)
            }
            _ => {}
        };
        download(fetcher, &spec, &dir, &mut prog).await?;
    }

    // 6. Strata's own installer builds the engine from the verified inputs.
    index += 1;
    event("Building the engine (10-20 minutes)", 0, 0, index);
    let data_dir = layout.root().join("data");
    runner
        .run(
            "build the engine",
            &Cmd {
                program: layout.python(),
                args: [
                    "setup.py",
                    "--build",
                    "--yes",
                    "--no-start",
                    "--no-browser",
                    "--host",
                    "127.0.0.1",
                    "--family",
                    &model.family,
                    "--model",
                    &model.quant,
                    "--gguf-dir",
                    &dir.display().to_string(),
                    "--data-dir",
                    &data_dir.display().to_string(),
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
                cwd: layout.src(),
                env: vec![],
            },
            &log,
        )
        .await?;

    let config = fs::read_dir(layout.src())
        .map_err(io("cannot read the Strata checkout"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .find(|p| {
            p.extension().is_some_and(|x| x == "json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("strata-"))
        })
        .ok_or_else(|| StrataError::Step {
            step: "build the engine".into(),
            message: "Strata's installer wrote no strata-*.json run configuration".into(),
            log: log.display().to_string(),
        })?;
    let (py, src, cfg) = (
        layout.python().display().to_string(),
        layout.src().display().to_string(),
        config.display().to_string(),
    );
    backend_manifest(&py, &src, &cfg).map_err(StrataError::Pin)?;
    fs::write(
        layout.backend_manifest(),
        backend_manifest_text(&py, &src, &cfg),
    )
    .map_err(io("cannot write backend.toml"))?;
    event("Done", 1, 1, steps);
    Ok(StrataInstall {
        root: layout.root().to_path_buf(),
        gguf_dir: dir,
        backend_manifest: layout.backend_manifest(),
        config,
    })
}

#[cfg(test)]
mod tests;

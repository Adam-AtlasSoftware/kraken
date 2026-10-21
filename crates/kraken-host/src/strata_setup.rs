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
    EngineMethod, EngineVersion, ExistingModel, Missing, SetupOptions, Source, StrataManifest,
    StrataModel, backend_manifest, backend_manifest_text,
};
use sha2::{Digest, Sha256};

use crate::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, Progress, ProvisionError, download, download_unpinned,
    extract_tar_gz, fetch_text,
};

/// Strata's repository on GitHub.
const REPO: &str = "Niko1221/Strata";

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
    /// Which revision was installed and how, for people ("v0.2.1, ready-made engine").
    pub description: String,
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

/// Adds a line to the setup log (best effort).
fn note(log: &Path, line: &str) {
    use std::io::Write as _;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = writeln!(f, "{line}");
    }
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

/// Where the model comes from.
#[derive(Debug, Clone, Copy)]
pub enum ModelSource<'a> {
    /// A catalog model: downloaded and checked against the pinned hashes.
    Catalog(&'a StrataModel),
    /// Files already on this computer, used where they are.
    Existing(&'a ExistingModel),
}

/// What to install.
#[derive(Debug, Clone, Copy)]
pub struct StrataRequest<'a> {
    pub manifest: &'a StrataManifest,
    pub options: SetupOptions,
    pub model: ModelSource<'a>,
}

/// The Strata revision chosen for this setup.
struct Revision {
    /// The source archive to fetch.
    url: String,
    /// `v0.2.1` or a commit id.
    label: String,
    /// The release whose ready-made engine to use, when the revision is a release.
    release: Option<String>,
    /// Set when the archive is checked against hashes written down in advance.
    pinned: Option<Source>,
    /// GitHub's listing of the release (its assets), when it was fetched already.
    listing: Option<serde_json::Value>,
}

fn plain_ref(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The asset name of the ready-made Linux engine (CUDA 13) in a release listing.
const ENGINE_SUFFIX: &str = "-linux-x86_64-cuda-cuda13.tar.gz";
/// Writes the files named after the output path into a zip, whatever their timestamps (the
/// tarball's are older than a zip can record, which `python -m zipfile` refuses).
const PACK_SCRIPT: &str = concat!(
    "import os, sys, zipfile\n",
    "out, items = sys.argv[1], sys.argv[2:]\n",
    "with zipfile.ZipFile(out, 'w', zipfile.ZIP_STORED, strict_timestamps=False) as z:\n",
    "    for item in items:\n",
    "        if os.path.isdir(item):\n",
    "            for root, _, files in os.walk(item):\n",
    "                for f in files:\n",
    "                    z.write(os.path.join(root, f))\n",
    "        else:\n",
    "            z.write(item)\n",
);
/// The name setup.py looks for in a local folder given with `--prebuilt`.
const ENGINE_ZIP: &str = "strata-linux-x64.zip";

/// The download URLs of the ready-made engine and of the release's checksums.
fn engine_assets(listing: &serde_json::Value) -> Result<(String, String, String), StrataError> {
    let url_of = |pick: &dyn Fn(&str) -> bool| {
        listing["assets"].as_array().and_then(|a| {
            a.iter().find_map(|x| {
                let name = x["name"].as_str()?;
                let url = x["browser_download_url"].as_str()?;
                pick(name).then(|| (name.to_string(), url.to_string()))
            })
        })
    };
    let (name, url) = url_of(&|n| n.starts_with("strata-engine-") && n.ends_with(ENGINE_SUFFIX))
        .ok_or_else(|| {
            StrataError::Pin(
                "this Strata release has no ready-made Linux engine (CUDA 13); build it from source"
                    .into(),
            )
        })?;
    let (_, sums) = url_of(&|n| n == "SHA256SUMS.txt").ok_or_else(|| {
        StrataError::Pin(
            "this Strata release lists no SHA-256 checksums; refusing its engine".into(),
        )
    })?;
    Ok((name, url, sums))
}

/// The hash `SHA256SUMS.txt` lists for `name`.
fn listed_sha256(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, file) = l.split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name
            && hash.len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hash.to_ascii_lowercase())
    })
}

/// Looks up the newest release or commit; the pinned revision needs no lookup.
async fn resolve_revision(
    fetcher: &dyn Fetcher,
    manifest: &StrataManifest,
    version: EngineVersion,
) -> Result<Revision, StrataError> {
    let json = |text: String, url: &str| {
        serde_json::from_str::<serde_json::Value>(&text).map_err(|e| {
            StrataError::Pin(format!(
                "GitHub's answer from {url} is not what was expected: {e}"
            ))
        })
    };
    match version {
        EngineVersion::Pinned => Ok(Revision {
            url: manifest.engine.source.url.clone(),
            label: format!("v{}", manifest.engine.version),
            release: Some(format!("v{}", manifest.engine.version)),
            pinned: Some(manifest.engine.source.clone()),
            listing: None,
        }),
        EngineVersion::LatestRelease => {
            let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
            let v = json(fetch_text(fetcher, &url).await?, &url)?;
            let tag = v["tag_name"]
                .as_str()
                .filter(|t| plain_ref(t))
                .ok_or_else(|| {
                    StrataError::Pin("GitHub named no usable latest release of Strata".into())
                })?;
            Ok(Revision {
                url: format!("https://codeload.github.com/{REPO}/tar.gz/refs/tags/{tag}"),
                label: tag.into(),
                release: Some(tag.into()),
                pinned: None,
                listing: Some(v.clone()),
            })
        }
        EngineVersion::LatestCommit => {
            let url = format!("https://api.github.com/repos/{REPO}/commits/main");
            let v = json(fetch_text(fetcher, &url).await?, &url)?;
            let sha = v["sha"]
                .as_str()
                .filter(|t| plain_ref(t) && t.len() == 40)
                .ok_or_else(|| {
                    StrataError::Pin("GitHub named no usable latest commit of Strata".into())
                })?;
            Ok(Revision {
                url: format!("https://codeload.github.com/{REPO}/tar.gz/{sha}"),
                label: sha[..12].into(),
                release: None,
                pinned: None,
                listing: None,
            })
        }
    }
}

/// Installs Strata and a model. `missing` is the result of the prerequisite check for the
/// chosen method; a non-empty list stops the setup before anything is downloaded.
pub async fn install_strata(
    layout: &StrataLayout,
    fetcher: &dyn Fetcher,
    runner: &dyn Runner,
    req: &StrataRequest<'_>,
    missing: Vec<Missing>,
    on_event: &mut (dyn FnMut(StrataEvent) + Send),
) -> Result<StrataInstall, StrataError> {
    let (manifest, options) = (req.manifest, req.options);
    if let Some(why) = options.problem() {
        return Err(StrataError::Pin(why.into()));
    }
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

    // 1. Strata's source: the pinned commit (hash-checked) or the newest release or commit.
    index += 1;
    event("Looking up the Strata revision", 0, 0, index);
    let revision = resolve_revision(fetcher, manifest, options.version).await?;
    let size = revision.pinned.as_ref().map_or(0, |p| p.size);
    event("Strata source", 0, size, index);
    let mut prog = |p: Progress| {
        if let Progress::Downloading { done, total, .. } = p {
            event("Strata source", done, total.unwrap_or(size), index);
        }
    };
    let archive = match &revision.pinned {
        Some(source) => fetch_source(fetcher, layout, "strata", source, &mut prog).await?,
        None => {
            let dest = layout
                .downloads()
                .join(format!("strata-{}.tar.gz", revision.label));
            let sha = download_unpinned(fetcher, "strata", &revision.url, &dest, &mut prog).await?;
            note(
                &log,
                &format!(
                    "Strata {} source: sha256 {sha} (no hash is pinned for it)",
                    revision.label
                ),
            );
            dest
        }
    };
    unpack_source(&archive, &layout.src())?;
    let req_file = layout.src().join("requirements.txt");
    if revision.pinned.is_some() && file_sha256(&req_file)? != manifest.engine.requirements_sha256 {
        return Err(StrataError::Pin(
            "requirements.txt in the Strata source is not the pinned one; refusing to install it"
                .into(),
        ));
    }

    // 2. llama.cpp (ggml) at the commit KRAKEN pins, placed where setup.py looks first. A newer
    // Strata asks for its own llama.cpp commit and fetches it itself.
    if revision.pinned.is_some() {
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
    }

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
                .chain([req_file.display().to_string()])
                .collect(),
                cwd: layout.src(),
                env: vec![],
            },
            &log,
        )
        .await?;

    // 5. The model: downloaded shard by shard and checked, or the person's own files as they are.
    index += 1;
    let (dir, family, quant) = match req.model {
        ModelSource::Catalog(model) => {
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
            (dir, model.family.clone(), model.quant.clone())
        }
        ModelSource::Existing(m) => {
            event("Using your model files", 1, 1, index);
            (m.dir.clone(), m.family.clone(), m.quant.clone())
        }
    };

    // 5b. The ready-made engine. Strata publishes it for Linux as a tarball for its own app, not as
    // the zip that setup.py downloads, so it is fetched here, checked against the release's
    // checksums, and handed to setup.py as a local folder holding that zip.
    let mut prebuilt_dir: Option<PathBuf> = None;
    if options.method == EngineMethod::Prebuilt {
        let tag = revision
            .release
            .clone()
            .ok_or_else(|| StrataError::Pin("the newest commit has no ready-made engine".into()))?;
        let listing = match &revision.listing {
            Some(l) => l.clone(),
            None => {
                let url = format!("https://api.github.com/repos/{REPO}/releases/tags/{tag}");
                serde_json::from_str(&fetch_text(fetcher, &url).await?).map_err(|e| {
                    StrataError::Pin(format!(
                        "GitHub's answer for release {tag} is unusable: {e}"
                    ))
                })?
            }
        };
        let (name, url, sums_url) = engine_assets(&listing)?;
        let sums = fetch_text(fetcher, &sums_url).await?;
        let sha256 = listed_sha256(&sums, &name).ok_or_else(|| {
            StrataError::Pin(format!("the release's checksums do not list {name}"))
        })?;
        index += 1;
        let work = layout.downloads().join(format!("engine-{tag}"));
        let spec = ArtifactSpec {
            name: "Strata engine".into(),
            file_name: name.clone(),
            url,
            sha256,
            format: ArchiveFormat::TarGz,
            top_dir: String::new(),
        };
        let mut prog = |p: Progress| match p {
            Progress::Downloading { done, total, .. } => {
                event("Strata engine", done, total.unwrap_or(0), index)
            }
            Progress::Verifying { .. } => event("Checking the Strata engine", 1, 1, index),
            _ => {}
        };
        let tarball = download(fetcher, &spec, &work, &mut prog).await?;
        let unpacked = work.join("unpacked");
        let _ = fs::remove_dir_all(&unpacked);
        extract_tar_gz(&tarball, &unpacked)?;
        let mut items: Vec<String> = fs::read_dir(&unpacked)
            .map_err(io(format!("cannot read {}", unpacked.display())))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        items.sort();
        let folder = work.join("prebuilt");
        fs::create_dir_all(&folder).map_err(io(format!("cannot create {}", folder.display())))?;
        let mut args = vec![
            "-c".to_string(),
            PACK_SCRIPT.into(),
            folder.join(ENGINE_ZIP).display().to_string(),
        ];
        args.extend(items);
        runner
            .run(
                "pack the engine",
                &Cmd {
                    program: layout.python(),
                    args,
                    cwd: unpacked.clone(),
                    env: vec![],
                },
                &log,
            )
            .await?;
        let _ = fs::remove_dir_all(&unpacked);
        prebuilt_dir = Some(folder);
    }

    // 6. Strata's own installer sets up the engine (ready-made, or compiled from the sources).
    index += 1;
    event(
        match options.method {
            EngineMethod::Prebuilt => "Installing the engine",
            EngineMethod::Build => "Building the engine (10-20 minutes)",
        },
        0,
        0,
        index,
    );
    let data_dir = layout.root().join("data");
    let mut args: Vec<String> = ["setup.py", "--yes", "--no-start", "--no-browser"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    match (options.method, &revision.release) {
        (EngineMethod::Build, _) => args.push("--build".into()),
        (EngineMethod::Prebuilt, _) => {
            let dir = prebuilt_dir
                .as_ref()
                .ok_or_else(|| StrataError::Pin("the ready-made engine was not prepared".into()))?;
            args.extend(["--prebuilt".into(), format!("{}/", dir.display())]);
        }
    }
    args.extend([
        "--host".into(),
        "127.0.0.1".into(),
        "--family".into(),
        family,
        "--model".into(),
        quant,
        "--gguf-dir".into(),
        dir.display().to_string(),
        "--data-dir".into(),
        data_dir.display().to_string(),
    ]);
    runner
        .run(
            "build the engine",
            &Cmd {
                program: layout.python(),
                args,
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
    let how = match options.method {
        EngineMethod::Prebuilt => "ready-made engine",
        EngineMethod::Build => "built from source",
    };
    Ok(StrataInstall {
        description: format!("Strata {} ({how})", revision.label),
        root: layout.root().to_path_buf(),
        gguf_dir: dir,
        backend_manifest: layout.backend_manifest(),
        config,
    })
}

#[cfg(test)]
mod tests;

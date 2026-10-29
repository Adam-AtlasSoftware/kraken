//! The integrations catalogue: detect, install, verify and remove emulators and tools.
//!
//! Nothing is bundled. Every entry that upstream publishes a Linux build for is downloaded from
//! the upstream's own release on the user's machine (pinned version, SHA-256 checked before
//! anything is unpacked) into `<data dir>/integrations/<id>/<version>/`. An entry can also use a
//! copy the person already has: found on `PATH` or in a well-known place, or a path they chose.
//! Removing deletes only what KRAKEN installed.
//!
//! The manifest format is in [`manifest`]; the catalogue that ships with KRAKEN is compiled in
//! (`catalogue.toml`) and the person's own emulators are TOML files in
//! `<config dir>/emulators.d/`.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    InstallProgress, IntegrationRemoveOut, IntegrationSource, IntegrationStatus, IntegrationView,
    IntegrationsBackend, LaunchSpec,
};
use serde::{Deserialize, Serialize};

use crate::config::KrakenConfig;
use crate::llama_setup::data_dir_with;
use crate::provision::{
    ArchiveFormat, ArtifactSpec, Fetcher, HttpsFetcher, Progress, download, extract_tar_gz,
    extract_tar_xz, extract_zip,
};

pub mod manifest;

use manifest::{Artifact, Entry, Format};

/// What KRAKEN remembers per entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Saved {
    /// Installed release.
    #[serde(default)]
    version: Option<String>,
    /// The program, relative to `<root>/<id>/<version>`.
    #[serde(default)]
    entry: Option<String>,
    /// A path the person chose.
    #[serde(default)]
    path: Option<String>,
    /// Bytes of the installed copy.
    #[serde(default)]
    disk_bytes: u64,
}

type State = BTreeMap<String, Saved>;

/// The catalogue and what is installed.
pub struct Integrations {
    root: PathBuf,
    user_dir: Option<PathBuf>,
    fetcher: Arc<dyn Fetcher>,
    path_env: Option<OsString>,
    home: Option<PathBuf>,
    flatpak_dirs: Vec<PathBuf>,
    state_lock: Mutex<()>,
    progress: Arc<Mutex<BTreeMap<String, InstallProgress>>>,
    probes: Mutex<HashMap<PathBuf, Option<String>>>,
}

impl std::fmt::Debug for Integrations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Integrations")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn internal(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg)
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

impl Integrations {
    /// Real downloads; the user's data and config directories.
    pub fn system() -> Result<Self, ProtoError> {
        let env = |k: &str| std::env::var_os(k);
        let data = data_dir_with(&env)
            .ok_or_else(|| internal("cannot find KRAKEN's data directory (set HOME)"))?;
        let user_dir =
            KrakenConfig::default_path().and_then(|p| p.parent().map(|d| d.join("emulators.d")));
        let fetcher = HttpsFetcher::new().map_err(|e| internal(e.to_string()))?;
        let mut me = Integrations::new(data.join("integrations"), user_dir, Arc::new(fetcher));
        me.path_env = None;
        me.home = std::env::var_os("HOME").map(PathBuf::from);
        me.flatpak_dirs = flatpak_export_dirs(me.home.as_deref());
        Ok(me)
    }

    /// A catalogue rooted at `root` that downloads through `fetcher`. Nothing is looked for on
    /// the system until [`with_search`](Self::with_search).
    pub fn new(root: PathBuf, user_dir: Option<PathBuf>, fetcher: Arc<dyn Fetcher>) -> Self {
        Integrations {
            root,
            user_dir,
            fetcher,
            path_env: Some(OsString::new()),
            home: None,
            flatpak_dirs: Vec::new(),
            state_lock: Mutex::new(()),
            progress: Arc::new(Mutex::new(BTreeMap::new())),
            probes: Mutex::new(HashMap::new()),
        }
    }

    /// Looks for system copies on `path` (a `PATH` value) and under `home`.
    pub fn with_search(mut self, path: OsString, home: Option<PathBuf>) -> Self {
        self.path_env = Some(path);
        self.flatpak_dirs = flatpak_export_dirs(home.as_deref());
        self.home = home;
        self
    }

    fn state_path(&self) -> PathBuf {
        self.root.join("state.json")
    }

    fn load_state(&self) -> State {
        std::fs::read(self.state_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn update_state<R>(&self, f: impl FnOnce(&mut State) -> R) -> Result<R, ProtoError> {
        let _g = lock(&self.state_lock);
        let mut st = self.load_state();
        let r = f(&mut st);
        std::fs::create_dir_all(&self.root)
            .map_err(|e| internal(format!("{}: {e}", self.root.display())))?;
        let tmp = self.root.join("state.json.tmp");
        let json = serde_json::to_vec_pretty(&st).map_err(|e| internal(e.to_string()))?;
        std::fs::write(&tmp, json).map_err(|e| internal(format!("{}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, self.state_path())
            .map_err(|e| internal(format!("cannot save {}: {e}", self.state_path().display())))?;
        Ok(r)
    }

    /// The catalogue and the person's manifests, in that order. A user manifest that does not
    /// parse or clashes with an earlier id is skipped and logged.
    fn entries(&self) -> Vec<(Entry, bool)> {
        let mut out: Vec<(Entry, bool)> = match manifest::parse(manifest::CATALOGUE) {
            Ok(v) => v.into_iter().map(|e| (e, false)).collect(),
            Err(e) => {
                tracing::error!("the compiled-in integrations catalogue is invalid: {e}");
                Vec::new()
            }
        };
        let Some(dir) = &self.user_dir else {
            return out;
        };
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        let mut files: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        files.sort();
        for f in files {
            let parsed = std::fs::read_to_string(&f)
                .map_err(|e| e.to_string())
                .and_then(|t| manifest::parse(&t).map_err(|e| e.to_string()));
            match parsed {
                Ok(v) => {
                    for e in v {
                        if out.iter().any(|(o, _)| o.id == e.id) {
                            tracing::warn!(
                                "{}: id `{}` is already taken; skipped",
                                f.display(),
                                e.id
                            );
                        } else {
                            out.push((e, true));
                        }
                    }
                }
                Err(e) => tracing::warn!("{}: {e}; skipped", f.display()),
            }
        }
        out
    }

    fn entry(&self, id: &str) -> Result<(Entry, bool), ProtoError> {
        self.entries()
            .into_iter()
            .find(|(e, _)| e.id == id)
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::NotFound,
                    format!("no integration `{id}`; see integrations_list"),
                )
            })
    }

    fn artifact<'a>(&self, e: &'a Entry) -> Option<&'a Artifact> {
        e.artifact
            .iter()
            .find(|a| a.os == std::env::consts::OS && a.arch == std::env::consts::ARCH)
    }

    /// The usable program of an entry and where it came from.
    fn find(&self, e: &Entry, saved: &Saved) -> Option<(PathBuf, IntegrationSource)> {
        if let Some(p) = saved.path.as_deref().map(PathBuf::from)
            && is_program(&p)
        {
            return Some((p, IntegrationSource::UserPath));
        }
        if let (Some(v), Some(rel)) = (&saved.version, &saved.entry) {
            let p = self.root.join(&e.id).join(v).join(rel);
            if is_program(&p) {
                return Some((p, IntegrationSource::Downloaded));
            }
        }
        self.detect_system(e)
            .map(|p| (p, IntegrationSource::System))
    }

    fn detect_system(&self, e: &Entry) -> Option<PathBuf> {
        let path = self
            .path_env
            .clone()
            .unwrap_or_else(|| std::env::var_os("PATH").unwrap_or_default());
        for name in &e.detect.names {
            for dir in std::env::split_paths(&path) {
                let p = dir.join(name);
                if is_program(&p) {
                    return Some(p);
                }
            }
        }
        for pattern in &e.detect.paths {
            if let Some(p) = expand_pattern(pattern, self.home.as_deref())
                .into_iter()
                .rev()
                .find(|p| is_program(p))
            {
                return Some(p);
            }
        }
        if let Some(app) = &e.detect.flatpak {
            for dir in &self.flatpak_dirs {
                let p = dir.join(app);
                if is_program(&p) {
                    return Some(p);
                }
            }
        }
        None
    }

    /// First line of `exe --version`, cached; the program gets three seconds.
    fn probe(&self, exe: &Path) -> Option<String> {
        if let Some(v) = lock(&self.probes).get(exe) {
            return v.clone();
        }
        let v = run_version(exe);
        lock(&self.probes).insert(exe.to_path_buf(), v.clone());
        v
    }

    fn view(&self, e: &Entry, user: bool, saved: &Saved) -> IntegrationView {
        let found = self.find(e, saved);
        let artifact = self.artifact(e);
        let progress = lock(&self.progress).get(&e.id).cloned();
        let status = if progress.is_some() {
            IntegrationStatus::Installing
        } else if found.is_some() {
            IntegrationStatus::Ready
        } else if artifact.is_some() {
            IntegrationStatus::NotInstalled
        } else {
            IntegrationStatus::ManualOnly
        };
        let version = found.as_ref().and_then(|(p, src)| match src {
            IntegrationSource::Downloaded => saved.version.clone(),
            _ if e.detect.probe => self.probe(p),
            _ => None,
        });
        IntegrationView {
            id: e.id.clone(),
            name: e.name.clone(),
            kind: e.kind.clone(),
            summary: e.summary.clone(),
            homepage: e.homepage.clone(),
            platforms: e.platforms.clone(),
            formats: e.formats.clone(),
            status,
            source: found.as_ref().map(|(_, s)| *s),
            version,
            pinned_version: artifact.map(|a| a.version.clone()),
            path: found.map(|(p, _)| p.display().to_string()),
            download_bytes: artifact.map_or(0, |a| a.size),
            disk_bytes: saved.disk_bytes,
            license: e.license.clone(),
            notice: e.notice.clone(),
            contains_key_material: e.contains_key_material,
            user_supplied: user,
            debuggable: e.run.gdb_argv.is_some(),
            argv: e.run.argv.clone(),
            progress,
        }
    }

    fn view_of(&self, id: &str) -> Result<IntegrationView, ProtoError> {
        let (e, user) = self.entry(id)?;
        let saved = self.load_state().remove(id).unwrap_or_default();
        Ok(self.view(&e, user, &saved))
    }

    fn set_progress(&self, id: &str, phase: &str, done: u64, total: u64) {
        lock(&self.progress).insert(
            id.to_string(),
            InstallProgress {
                phase: phase.to_string(),
                done,
                total,
            },
        );
    }

    async fn install_entry(&self, e: &Entry, a: &Artifact) -> Result<(), ProtoError> {
        let downloads = self.root.join("downloads");
        let file_name = a
            .url
            .rsplit('/')
            .next()
            .filter(|n| !n.is_empty())
            .unwrap_or("download")
            .to_string();
        let spec = ArtifactSpec {
            name: e.id.clone(),
            file_name,
            url: a.url.clone(),
            sha256: a.sha256.clone(),
            format: match a.format {
                Format::Zip => ArchiveFormat::Zip,
                _ => ArchiveFormat::TarGz,
            },
            top_dir: String::new(),
        };
        let id = e.id.clone();
        let progress = self.progress.clone();
        let mut on_progress = move |p: Progress| {
            let (phase, done, total) = match p {
                Progress::Downloading { done, total, .. } => {
                    ("downloading", done, total.unwrap_or(0))
                }
                Progress::Verifying { .. } => ("verifying", 0, 0),
                Progress::Extracting { .. } => ("extracting", 0, 0),
                _ => return,
            };
            lock(&progress).insert(
                id.clone(),
                InstallProgress {
                    phase: phase.into(),
                    done,
                    total,
                },
            );
        };
        let archive = download(&*self.fetcher, &spec, &downloads, &mut on_progress)
            .await
            .map_err(|err| ProtoError::new(ErrorCode::Unsupported, err.to_string()))?;
        self.set_progress(&e.id, "extracting", 0, 0);
        let (root, id2, art) = (self.root.clone(), e.id.clone(), a.clone());
        let disk = tokio::task::spawn_blocking(move || stage(&root, &id2, &art, &archive))
            .await
            .map_err(|err| internal(format!("install task failed: {err}")))??;
        let (version, entry) = (a.version.clone(), a.entry.clone());
        self.update_state(|st| {
            let s = st.entry(e.id.clone()).or_default();
            s.version = Some(version);
            s.entry = Some(entry);
            s.disk_bytes = disk;
        })
    }
}

/// Unpacks `archive` into `<root>/<id>/<version>` through a staging directory; returns the bytes
/// the installed copy uses. Other versions of the entry are deleted afterwards.
fn stage(root: &Path, id: &str, a: &Artifact, archive: &Path) -> Result<u64, ProtoError> {
    let base = root.join(id);
    let staging = base.join(format!("{}.partial", a.version));
    let target = base.join(&a.version);
    let io = |what: &str, e: std::io::Error| internal(format!("{what}: {e}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|e| io("cannot create the install directory", e))?;
    let unpacked = match a.format {
        Format::File => std::fs::copy(archive, staging.join(&a.entry))
            .map(|_| ())
            .map_err(|e| io("cannot copy the download", e)),
        Format::Zip => extract_zip(archive, &staging)
            .map_err(|e| ProtoError::new(ErrorCode::Unsupported, e.to_string())),
        Format::TarGz => extract_tar_gz(archive, &staging)
            .map_err(|e| ProtoError::new(ErrorCode::Unsupported, e.to_string())),
        Format::TarXz => extract_tar_xz(archive, &staging)
            .map_err(|e| ProtoError::new(ErrorCode::Unsupported, e.to_string())),
    };
    if let Err(e) = unpacked {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    let program = staging.join(&a.entry);
    // A symbolic link in the archive may not lead the entry out of the install directory.
    let inside = match (program.canonicalize(), staging.canonicalize()) {
        (Ok(p), Ok(s)) => p.starts_with(&s) && p.is_file(),
        _ => false,
    };
    if !inside {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "the release does not contain `{}` (or it is a link leaving the install)",
                a.entry
            ),
        ));
    }
    make_executable(&program);
    let _ = std::fs::remove_dir_all(&target);
    std::fs::rename(&staging, &target).map_err(|e| io("cannot move the install into place", e))?;
    if let Ok(rd) = std::fs::read_dir(&base) {
        for other in rd.filter_map(Result::ok) {
            if other.path() != target && other.path().is_dir() {
                let _ = std::fs::remove_dir_all(other.path());
            }
        }
    }
    let _ = std::fs::remove_file(archive);
    Ok(dir_size(&target))
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else {
        return 0;
    };
    rd.filter_map(Result::ok)
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

#[cfg(unix)]
fn make_executable(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755));
}

#[cfg(not(unix))]
fn make_executable(_p: &Path) {}

/// A regular file the user can run.
fn is_program(p: &Path) -> bool {
    let Ok(m) = std::fs::metadata(p) else {
        return false;
    };
    if !m.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn flatpak_export_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/var/lib/flatpak/exports/bin")];
    if let Some(h) = home {
        v.push(h.join(".local/share/flatpak/exports/bin"));
    }
    v
}

/// `*` matches any run of characters.
fn wild_match(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first) || !name[first.len()..].ends_with(last) {
        return false;
    }
    if name.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

/// The paths a pattern names (`~` is the home directory, `*` only in the last component),
/// sorted.
fn expand_pattern(pattern: &str, home: Option<&Path>) -> Vec<PathBuf> {
    let full = match pattern.strip_prefix("~/") {
        Some(rest) => match home {
            Some(h) => h.join(rest),
            None => return Vec::new(),
        },
        None => PathBuf::from(pattern),
    };
    let (Some(parent), Some(name)) = (full.parent(), full.file_name().and_then(|n| n.to_str()))
    else {
        return Vec::new();
    };
    if !name.contains('*') {
        return vec![full];
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(parent)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_str().is_some_and(|n| wild_match(name, n)))
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// First line of `exe --version`; `None` when it does not answer in three seconds.
fn run_version(exe: &Path) -> Option<String> {
    use std::io::Read;
    let mut child = std::process::Command::new(exe)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > Duration::from_secs(3) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return None,
        }
    }
    let mut text = String::new();
    child
        .stdout
        .take()?
        .take(4096)
        .read_to_string(&mut text)
        .ok()?;
    text.lines()
        .next()
        .map(|l| l.trim().chars().take(120).collect::<String>())
        .filter(|l| !l.is_empty())
}

#[async_trait]
impl IntegrationsBackend for Integrations {
    fn list(&self) -> Result<Vec<IntegrationView>, ProtoError> {
        let state = self.load_state();
        Ok(self
            .entries()
            .iter()
            .map(|(e, user)| self.view(e, *user, &state.get(&e.id).cloned().unwrap_or_default()))
            .collect())
    }

    async fn install(&self, id: &str, accept_licence: bool) -> Result<IntegrationView, ProtoError> {
        let (entry, _) = self.entry(id)?;
        if !accept_licence {
            return Err(invalid("the licence and notice have to be accepted first"));
        }
        let Some(artifact) = self.artifact(&entry).cloned() else {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!(
                    "upstream publishes no {}-{} build of {} that KRAKEN can download; install it yourself and use integration_use_path. {}",
                    std::env::consts::OS,
                    std::env::consts::ARCH,
                    entry.name,
                    entry.notice
                ),
            ));
        };
        {
            let mut p = lock(&self.progress);
            if p.contains_key(id) {
                return Err(invalid(format!(
                    "{} is already being installed",
                    entry.name
                )));
            }
            p.insert(
                id.to_string(),
                InstallProgress {
                    phase: "downloading".into(),
                    done: 0,
                    total: artifact.size,
                },
            );
        }
        let result = self.install_entry(&entry, &artifact).await;
        lock(&self.progress).remove(id);
        result?;
        self.view_of(id)
    }

    fn use_path(&self, id: &str, path: &Path) -> Result<IntegrationView, ProtoError> {
        self.entry(id)?;
        let path = path.canonicalize().map_err(|e| {
            ProtoError::new(ErrorCode::NotFound, format!("{}: {e}", path.display()))
        })?;
        if !is_program(&path) {
            return Err(invalid(format!(
                "{} is not an executable file",
                path.display()
            )));
        }
        let p = path.display().to_string();
        self.update_state(|st| st.entry(id.to_string()).or_default().path = Some(p))?;
        self.view_of(id)
    }

    fn remove(&self, id: &str) -> Result<IntegrationRemoveOut, ProtoError> {
        self.entry(id)?;
        if lock(&self.progress).contains_key(id) {
            return Err(invalid("it is being installed right now"));
        }
        let dir = self.root.join(id);
        let freed = dir_size(&dir);
        let had_dir = dir.is_dir();
        if had_dir {
            std::fs::remove_dir_all(&dir)
                .map_err(|e| internal(format!("cannot remove {}: {e}", dir.display())))?;
        }
        let had_path = self.update_state(|st| {
            let had = st.get(id).is_some_and(|s| s.path.is_some());
            st.remove(id);
            had
        })?;
        let note = match (had_dir, had_path) {
            (true, true) => "deleted KRAKEN's copy and forgot the chosen path",
            (true, false) => "deleted KRAKEN's copy",
            (false, true) => "forgot the chosen path; the program itself was not touched",
            (false, false) => "nothing of KRAKEN's was installed for it",
        };
        Ok(IntegrationRemoveOut {
            id: id.to_string(),
            freed_bytes: freed,
            note: note.into(),
        })
    }

    fn launch_spec(&self, id: &str) -> Result<LaunchSpec, ProtoError> {
        let (e, _) = self.entry(id)?;
        let saved = self.load_state().remove(id).unwrap_or_default();
        let Some((exe, _)) = self.find(&e, &saved) else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "{} is not installed: Install it, or point KRAKEN at your copy (integration_use_path)",
                    e.name
                ),
            ));
        };
        let mut env: Vec<(String, String)> = e
            .run
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let lower = exe.to_string_lossy().to_ascii_lowercase();
        if lower.ends_with(".appimage") {
            // No FUSE needed and no mount left behind.
            env.push(("APPIMAGE_EXTRACT_AND_RUN".into(), "1".into()));
        }
        Ok(LaunchSpec {
            id: e.id.clone(),
            name: e.name.clone(),
            exe,
            argv: e.run.argv.clone(),
            gdb_argv: e.run.gdb_argv.clone(),
            gdb_port: e.run.gdb_port,
            gui: e.run.gui,
            env,
        })
    }
}

#[cfg(test)]
mod tests;

//! Installing a release over a per-user install, and rolling it back (ADR 0015, "Installing").
//!
//! The order is fixed: signature first, then the archive's SHA-256, extraction into a private
//! staging directory on the install's filesystem, the staged `kraken --version`, and only then the
//! swap under an exclusive lock. Every file that is replaced must be a regular file (or, for the
//! data directories, a directory) that the user owns; the old ones go to
//! `<data dir>/previous/<old version>/`, and a failure puts back what was already moved.
//!
//! Windows does not let a running program be overwritten or deleted, but it can be renamed, so
//! every step is a rename: the running `kraken.exe` moves aside and the new one takes its name.
//! When the data directory is on another volume than the install, a file is first renamed beside
//! itself (`<name>.kraken-old-<n>`), then copied to `previous/`, and the renamed file is deleted
//! when it can be, else by [`sweep_leftovers`] on the next start. Renames and deletes are retried
//! for a few seconds while another program (an antivirus scan of a new file) holds the file. All
//! of this goes through [`SwapFs`], so tests make the operations fail as Windows does.

use std::fs::{self, File};
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use kraken_registry::commands::UpdateApplied;
use kraken_registry::jobs::JobProgress;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::UpdateError;
use super::check::{fetch_capped, is_newer};
use super::install::{InstallKind, is_root};
use super::verify::{sum_for, verify_sums};
use crate::provision::{Fetcher, extract_tar_gz, extract_zip};

/// Largest release file accepted.
pub const MAX_ASSET_BYTES: u64 = 2 << 30;

/// What an update works with.
#[derive(Clone)]
pub struct ApplyContext {
    /// How KRAKEN was installed.
    pub kind: InstallKind,
    /// The running version.
    pub current: Version,
    /// The compiled-in target triple.
    pub target: String,
    /// KRAKEN's data directory (`previous/`, the lock).
    pub data_dir: PathBuf,
    /// The minisign public key releases are checked against.
    pub public_key: String,
    /// `<base>/v<version>/<file>` is where release files are.
    pub download_base: String,
    /// Longest wait for the staged `kraken --version`.
    pub version_timeout: Duration,
    /// Runs the staged program and returns what it printed (tests use a stand-in).
    pub run_version: RunVersion,
    /// The file operations of the swap.
    pub fs: Arc<dyn SwapFs>,
    /// Runs after the new release passed every check and before the first file moves: the CLI
    /// stops the daemon here on Windows, so no KRAKEN program holds the old files.
    pub before_swap: Option<BeforeSwap>,
}

impl std::fmt::Debug for ApplyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApplyContext")
            .field("kind", &self.kind)
            .field("current", &self.current)
            .field("target", &self.target)
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

/// Runs a program with arguments and extra environment, with a timeout; stdout on success.
pub type RunVersion = fn(&Path, &[&str], &[(&str, &str)], Duration) -> Option<String>;

/// A step before the swap.
pub type BeforeSwap = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The file operations a swap makes. The defaults are the real ones; tests override them to fail
/// the way Windows does (a file in use, another volume).
pub trait SwapFs: Send + Sync {
    /// Renames `from` to `to`.
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
    /// Deletes a file or a whole directory; a missing one is fine.
    fn remove(&self, path: &Path) -> io::Result<()> {
        remove_any(path)
    }
    /// The waits between tries of an operation that failed for a moment.
    fn retry_delays(&self) -> &[Duration] {
        &RETRY_DELAYS
    }
}

/// The real file system.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealFs;

impl SwapFs for RealFs {}

/// About three seconds in all: long enough for an antivirus scan of a new program.
const RETRY_DELAYS: [Duration; 6] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(200),
    Duration::from_millis(400),
    Duration::from_millis(800),
    Duration::from_millis(1500),
];

/// True for an error that goes away once another program lets go of the file: a sharing or lock
/// violation on Windows (an antivirus scan, an indexer), or access denied while a file is being
/// deleted. `ResourceBusy` stands for the same everywhere else.
pub fn is_transient(e: &io::Error) -> bool {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    e.kind() == io::ErrorKind::ResourceBusy
        || (cfg!(windows)
            && matches!(
                e.raw_os_error(),
                Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
            ))
}

/// Runs `op`, trying again after each of `delays` while it fails with a transient error.
fn with_retries<T>(delays: &[Duration], mut op: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut waits = delays.iter();
    loop {
        match op() {
            Err(e) if is_transient(&e) => match waits.next() {
                Some(d) => std::thread::sleep(*d),
                None => return Err(e),
            },
            r => return r,
        }
    }
}

fn rename_retrying(fs: &dyn SwapFs, from: &Path, to: &Path) -> io::Result<()> {
    with_retries(fs.retry_delays(), || fs.rename(from, to))
}

fn remove_retrying(fs: &dyn SwapFs, path: &Path) -> io::Result<()> {
    with_retries(fs.retry_delays(), || fs.remove(path))
}

/// Marks a file that was renamed aside because it could not be deleted (a running program).
const LEFTOVER_MARK: &str = ".kraken-old-";

/// A free name beside `path` for moving it aside: `<name>.kraken-old-<n>`.
fn aside_name(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    (0u32..)
        .map(|n| path.with_file_name(format!("{name}{LEFTOVER_MARK}{n}")))
        .find(|p| fs::symlink_metadata(p).is_err())
        .unwrap_or_else(|| path.with_file_name(format!("{name}{LEFTOVER_MARK}x")))
}

/// Deletes what earlier updates had to leave behind in an install (programs that were running
/// when they were replaced). Errors are ignored: a file still in use stays for the next start.
pub fn sweep_leftovers(prefix: &Path) {
    for sub in ["bin", "share/kraken"] {
        let Ok(rd) = fs::read_dir(prefix.join(sub)) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().contains(LEFTOVER_MARK) {
                let _ = remove_any(&e.path());
            }
        }
    }
}

/// The release file for `version`: never taken from the release metadata.
pub fn asset_name(kind: &InstallKind, version: &Version, target: &str) -> String {
    match kind {
        InstallKind::AppImage { .. } => format!("KRAKEN-{version}-x86_64.AppImage"),
        _ if target.contains("windows") => format!("kraken-{version}-{target}.zip"),
        _ => format!("kraken-{version}-{target}.tar.gz"),
    }
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> UpdateError {
    let what = what.into();
    move |source| UpdateError::Io { what, source }
}

fn refused(m: impl Into<String>) -> UpdateError {
    UpdateError::Refused(m.into())
}

/// Fails unless `path` is a regular file (or, with `dir_ok`, a directory) owned by the current
/// user. Links are refused.
pub fn check_replaceable(path: &Path, dir_ok: bool) -> Result<(), UpdateError> {
    let md =
        fs::symlink_metadata(path).map_err(io_err(format!("cannot read {}", path.display())))?;
    let ft = md.file_type();
    if ft.is_symlink() {
        return Err(refused(format!(
            "{} is a link; KRAKEN only replaces its own files",
            path.display()
        )));
    }
    if !(ft.is_file() || (dir_ok && ft.is_dir())) {
        return Err(refused(format!("{} is not a regular file", path.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let me = unsafe { libc::geteuid() };
        if md.uid() != me {
            return Err(refused(format!(
                "{} belongs to another user; update it the way it was installed",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Moves `from` to `to`: a rename, or across volumes a rename beside itself, a copy and a delete
/// that may wait for the next start (a running program cannot be deleted on Windows).
fn relocate(fs: &dyn SwapFs, from: &Path, to: &Path) -> io::Result<()> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?;
    }
    match rename_retrying(fs, from, to) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            let aside = aside_name(from);
            rename_retrying(fs, from, &aside)?;
            if let Err(e) = copy_tree(&aside, to) {
                let _ = remove_any(to);
                let _ = rename_retrying(fs, &aside, from);
                return Err(e);
            }
            if let Err(e) = remove_retrying(fs, &aside) {
                tracing::info!(file = %aside.display(), error = %e, "left for the next start");
            }
            Ok(())
        }
        r => r,
    }
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(from)?;
    if md.is_dir() {
        fs::create_dir_all(to)?;
        for e in fs::read_dir(from)? {
            let e = e?;
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        }
        Ok(())
    } else if md.is_file() {
        fs::copy(from, to).map(|_| ())
    } else {
        Err(io::Error::other(format!(
            "{} is neither a file nor a directory",
            from.display()
        )))
    }
}

fn remove_any(p: &Path) -> io::Result<()> {
    match fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(p),
        Ok(_) => fs::remove_file(p),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// A private directory (`0700`), emptied first.
fn private_dir(p: &Path) -> Result<(), UpdateError> {
    if fs::symlink_metadata(p).is_ok() {
        check_replaceable(p, true)?;
        with_retries(&RETRY_DELAYS, || remove_any(p))
            .map_err(io_err(format!("cannot clear {}", p.display())))?;
    }
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(p)
        .map_err(io_err(format!("cannot create {}", p.display())))
}

/// Refuses any link in the unpacked tree.
fn refuse_links(dir: &Path) -> Result<(), UpdateError> {
    for e in fs::read_dir(dir).map_err(io_err(format!("cannot read {}", dir.display())))? {
        let e = e.map_err(io_err("cannot read the unpacked release"))?;
        let ft = e
            .file_type()
            .map_err(io_err("cannot read the unpacked release"))?;
        if ft.is_symlink() {
            return Err(refused(format!(
                "the release archive holds a link ({}); nothing was installed",
                e.path().display()
            )));
        }
        if ft.is_dir() {
            refuse_links(&e.path())?;
        }
    }
    Ok(())
}

/// Downloads `url` to `dest` (at most `cap` bytes) and returns its SHA-256.
async fn download(
    fetcher: &dyn Fetcher,
    url: &str,
    dest: &Path,
    cap: u64,
    label: &str,
    progress: &(dyn Fn(JobProgress) + Send + Sync),
) -> Result<String, UpdateError> {
    let fetched = fetcher.fetch(url, 0).await?;
    if fetched.total.is_some_and(|t| t > cap) {
        return Err(refused(format!("{label} is larger than {cap} bytes")));
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(dest)
        .map_err(io_err(format!("cannot create {}", dest.display())))?;
    let mut hash = Sha256::new();
    let (mut done, mut body) = (0u64, fetched.body);
    let mut last = std::time::Instant::now();
    while let Some(chunk) = body.next_chunk().await? {
        done += chunk.len() as u64;
        if done > cap {
            return Err(refused(format!("{label} is larger than {cap} bytes")));
        }
        file.write_all(&chunk)
            .map_err(io_err(format!("cannot write {}", dest.display())))?;
        hash.update(&chunk);
        if last.elapsed() >= Duration::from_millis(250) {
            last = std::time::Instant::now();
            progress(JobProgress {
                phase: "download".into(),
                message: format!("downloading {label}"),
                done,
                total: fetched.total.unwrap_or(0),
                ..Default::default()
            });
        }
    }
    file.sync_all()
        .map_err(io_err(format!("cannot write {}", dest.display())))?;
    if let Some(t) = fetched.total
        && done < t
    {
        return Err(refused(format!(
            "the download of {label} ended early ({done} of {t} bytes)"
        )));
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn step(progress: &(dyn Fn(JobProgress) + Send + Sync), phase: &str, message: String) {
    progress(JobProgress {
        phase: phase.into(),
        message,
        ..Default::default()
    });
}

/// Checks that the program at `exe` (run with `args`) reports `version`.
fn check_version(
    run: RunVersion,
    exe: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    version: &Version,
    timeout: Duration,
) -> Result<(), UpdateError> {
    let out = run(exe, args, env, timeout).ok_or_else(|| {
        refused(format!(
            "the new program did not run (`{} --version`); nothing was replaced",
            exe.display()
        ))
    })?;
    let first = out.lines().next().unwrap_or_default().trim();
    let want = format!("kraken {version}");
    let ok = first == want || first.starts_with(&format!("{want} "));
    if !ok {
        return Err(refused(format!(
            "the new program reports \"{first}\", not \"{want}\"; nothing was replaced"
        )));
    }
    Ok(())
}

/// One kept generation: what was replaced and where the old copy is.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Generation {
    version: String,
    entries: Vec<Kept>,
    /// The version that update installed (older manifests lack it).
    #[serde(default)]
    installed: Option<String>,
    /// The install receipt the update rewrote, set back to `version` by a rollback.
    #[serde(default)]
    receipt: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kept {
    original: PathBuf,
    /// `None` when the release added the file (rollback removes it).
    backup: Option<PathBuf>,
}

const MANIFEST: &str = "manifest.json";

fn previous_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("previous")
}

/// Moves each `(new, original)` into place, the old copies under `backup_root` (keyed by
/// `rel`). Any failure puts back what was moved and returns the error.
fn swap(
    fs: &dyn SwapFs,
    entries: &[(PathBuf, PathBuf, PathBuf)],
    backup_root: &Path,
) -> Result<Vec<Kept>, UpdateError> {
    let mut done: Vec<Kept> = Vec::new();
    let mut result = Ok(());
    for (new, original, rel) in entries {
        let backup = if fs::symlink_metadata(original).is_ok() {
            let b = backup_root.join(rel);
            if let Err(e) = relocate(fs, original, &b) {
                result = Err(UpdateError::Io {
                    what: format!(
                        "cannot move {} aside{}",
                        original.display(),
                        in_use_hint(&e)
                    ),
                    source: e,
                });
                break;
            }
            Some(b)
        } else {
            None
        };
        done.push(Kept {
            original: original.clone(),
            backup,
        });
        if let Err(e) = rename_retrying(fs, new, original) {
            result = Err(UpdateError::Io {
                what: format!(
                    "cannot move the new {} into place{}",
                    original.display(),
                    in_use_hint(&e)
                ),
                source: e,
            });
            break;
        }
    }
    match result {
        Ok(()) => Ok(done),
        Err(e) => {
            undo(fs, &done);
            Err(e)
        }
    }
}

/// What to do about a file that stays in use (a folder whose library a running sidecar loaded).
fn in_use_hint(e: &io::Error) -> &'static str {
    if is_transient(e) {
        "; close KRAKEN (`kraken daemon stop`) and try again; nothing was changed"
    } else {
        ""
    }
}

/// Puts the kept copies back, newest move first.
fn undo(fs: &dyn SwapFs, done: &[Kept]) {
    for k in done.iter().rev() {
        let _ = remove_retrying(fs, &k.original);
        if let Some(b) = &k.backup
            && let Err(e) = relocate(fs, b, &k.original)
        {
            tracing::error!(error = %e, file = %k.original.display(), "could not put back the old file");
        }
    }
}

/// The files of an unpacked release that replace those under `prefix`: `(new, original, rel)`.
fn plan_entries(
    root: &Path,
    prefix: &Path,
) -> Result<Vec<(PathBuf, PathBuf, PathBuf)>, UpdateError> {
    let mut out = Vec::new();
    for sub in ["bin", "share/kraken"] {
        let dir = root.join(sub);
        if !dir.is_dir() {
            continue;
        }
        let mut names: Vec<_> = fs::read_dir(&dir)
            .map_err(io_err(format!("cannot read {}", dir.display())))?
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        names.sort();
        for n in names {
            let rel = Path::new(sub).join(&n);
            out.push((dir.join(&n), prefix.join(&rel), rel));
        }
    }
    for f in [
        "share/applications/kraken-gui.desktop",
        "share/icons/hicolor/scalable/apps/kraken-gui.svg",
    ] {
        if root.join(f).is_file() {
            out.push((root.join(f), prefix.join(f), PathBuf::from(f)));
        }
    }
    Ok(out)
}

/// Takes the update lock; `None` when another update holds it.
fn lock(data_dir: &Path) -> Result<File, UpdateError> {
    fs::create_dir_all(data_dir)
        .map_err(io_err(format!("cannot create {}", data_dir.display())))?;
    let path = data_dir.join("update.lock");
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(io_err(format!("cannot open {}", path.display())))?;
    // A process this one forks keeps every open file, the lock among them, until it execs; for
    // those few moments the lock looks taken. A real update holds it far longer than this wait.
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(refused("another update is running; wait for it to finish"));
            }
            Err(fs::TryLockError::Error(e)) => {
                return Err(UpdateError::Io {
                    what: "cannot lock the update".into(),
                    source: e,
                });
            }
        }
    }
}

/// How long a busy update lock is waited for before another update is assumed.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Keeps `keep` and drops every other generation.
fn prune_generations(data_dir: &Path, keep: &str) {
    let Ok(rd) = fs::read_dir(previous_dir(data_dir)) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy() != keep {
            let _ = remove_any(&e.path());
        }
    }
}

fn receipt_path(prefix: &Path) -> PathBuf {
    prefix.join("share/kraken/install.json")
}

fn receipt_version(path: &Path) -> Option<Version> {
    let text = fs::read_to_string(path).ok()?;
    if text.len() > 64 * 1024 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    Version::parse(v.get("version")?.as_str()?).ok()
}

/// The version the install holds on disk. It is newer than the running program after an update
/// that was not followed by a restart, so a second update must start from it, not from the
/// compiled-in version: otherwise it would overwrite the kept copy of the old version.
pub fn installed_version(kind: &InstallKind, data_dir: &Path, running: &Version) -> Version {
    let mut found = running.clone();
    let mut consider = |v: Option<Version>| {
        if let Some(v) = v
            && v > found
        {
            found = v;
        }
    };
    if let Some(prefix) = kind.prefix() {
        consider(receipt_version(&receipt_path(prefix)));
    }
    consider(
        newest_generation(data_dir)
            .and_then(|(_, g)| g.installed)
            .and_then(|v| Version::parse(&v).ok()),
    );
    found
}

/// Clears `previous/<old>` before a new generation is kept there, unless it is the only copy of
/// `old` from an update that moved the install on to another version.
fn clear_backup_root(backup_root: &Path, old: &str) -> Result<(), UpdateError> {
    if fs::symlink_metadata(backup_root).is_err() {
        return Ok(());
    }
    if let Ok(text) = fs::read(backup_root.join(MANIFEST))
        && let Ok(g) = serde_json::from_slice::<Generation>(&text)
        && let Some(w) = g.installed.filter(|w| w != old)
    {
        return Err(refused(format!(
            "{} holds the only copy of {old}, kept when {w} was installed; restart KRAKEN or roll back first",
            backup_root.display()
        )));
    }
    check_replaceable(backup_root, true)?;
    remove_any(backup_root).map_err(io_err("cannot clear the previous copy"))
}

fn update_receipt(prefix: &Path, version: &Version) {
    write_receipt_version(&receipt_path(prefix), &version.to_string());
}

fn write_receipt_version(path: &Path, version: &str) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("version".into(), version.into());
        if let Ok(t) = serde_json::to_string_pretty(&v) {
            let tmp = path.with_extension("json.tmp");
            if fs::write(&tmp, t).is_ok() {
                let _ = fs::rename(&tmp, path);
            }
        }
    }
}

/// Downloads, verifies and installs `version`.
pub async fn install(
    ctx: &ApplyContext,
    fetcher: &dyn Fetcher,
    version: &Version,
    progress: &(dyn Fn(JobProgress) + Send + Sync),
) -> Result<UpdateApplied, UpdateError> {
    if is_root() {
        return Err(refused(
            "KRAKEN does not update itself as root; run `kraken update` as the user who installed it",
        ));
    }
    if !ctx.kind.self_updating() {
        return Err(refused(
            match ctx.kind.command(Some(&version.to_string())) {
                Some(c) => format!("your package manager installed KRAKEN, so it updates it: {c}"),
                None => format!(
                    "KRAKEN cannot tell how it was installed; download the new version from {}",
                    super::install::RELEASES_URL
                ),
            },
        ));
    }
    let on_disk = installed_version(&ctx.kind, &ctx.data_dir, &ctx.current);
    if on_disk != ctx.current && !is_newer(version, &on_disk) {
        return Err(refused(format!(
            "{on_disk} is already installed; restart KRAKEN to use it"
        )));
    }
    if !is_newer(version, &on_disk) {
        return Err(refused(format!(
            "{version} is not newer than the running {on_disk}; KRAKEN never downgrades"
        )));
    }
    let ctx = &ApplyContext {
        current: on_disk,
        ..ctx.clone()
    };
    let asset = asset_name(&ctx.kind, version, &ctx.target);
    let base = format!("{}/v{version}", ctx.download_base);

    step(progress, "verify", "checking the release signature".into());
    let sums = fetch_capped(fetcher, &format!("{base}/SHA256SUMS"), 1 << 20).await?;
    let sig = match fetch_capped(fetcher, &format!("{base}/SHA256SUMS.minisig"), 64 << 10).await {
        Ok(s) => s,
        Err(e) => {
            return Err(UpdateError::Signature(format!(
                "release v{version} has no signature (SHA256SUMS.minisig: {e}); without a valid signature nothing is installed"
            )));
        }
    };
    let sig = String::from_utf8(sig)
        .map_err(|_| UpdateError::Signature("SHA256SUMS.minisig is not text".into()))?;
    verify_sums(&sums, &sig, &version.to_string(), &ctx.public_key)?;
    let sums = String::from_utf8(sums).map_err(|_| refused("SHA256SUMS is not text"))?;
    let expected = sum_for(&sums, &asset)
        .ok_or_else(|| refused(format!("{asset} is not in the signed SHA256SUMS")))?;

    let _lock = lock(&ctx.data_dir)?;
    match &ctx.kind {
        InstallKind::AppImage { path } => {
            install_appimage(
                ctx, fetcher, version, &base, &asset, &expected, path, progress,
            )
            .await
        }
        kind => {
            let Some(prefix) = kind.prefix() else {
                return Err(refused("this install has no prefix to update"));
            };
            install_prefix(
                ctx, fetcher, version, &base, &asset, &expected, prefix, progress,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn install_prefix(
    ctx: &ApplyContext,
    fetcher: &dyn Fetcher,
    version: &Version,
    base: &str,
    asset: &str,
    expected: &str,
    prefix: &Path,
    progress: &(dyn Fn(JobProgress) + Send + Sync),
) -> Result<UpdateApplied, UpdateError> {
    let staging = prefix.join("share/kraken/.update-staging");
    private_dir(&staging)?;
    let result = async {
        let file = staging.join(asset);
        let actual = download(
            fetcher,
            &format!("{base}/{asset}"),
            &file,
            MAX_ASSET_BYTES,
            asset,
            progress,
        )
        .await?;
        if actual != expected {
            return Err(refused(format!(
                "{asset} does not match the signed SHA-256 (expected {expected}, got {actual}); nothing was installed"
            )));
        }
        step(progress, "extract", format!("unpacking {asset}"));
        let x = staging.join("x");
        let (f2, x2) = (file.clone(), x.clone());
        let zip = asset.ends_with(".zip");
        tokio::task::spawn_blocking(move || {
            if zip {
                extract_zip(&f2, &x2)
            } else {
                extract_tar_gz(&f2, &x2)
            }
        })
        .await
        .map_err(|e| refused(format!("unpacking failed: {e}")))??;
        refuse_links(&x)?;
        let root = x.join(format!("kraken-{version}-{}", ctx.target));
        let exe_name = if ctx.target.contains("windows") {
            "kraken.exe"
        } else {
            "kraken"
        };
        let exe = root.join("bin").join(exe_name);
        if !exe.is_file() {
            return Err(refused(format!(
                "the release archive does not hold bin/{exe_name}; nothing was installed"
            )));
        }
        step(progress, "check", "trying the new kraken --version".into());
        check_version(
            ctx.run_version,
            &exe,
            &["--version"],
            &[],
            version,
            ctx.version_timeout,
        )?;
        if let Some(hook) = &ctx.before_swap {
            step(progress, "install", "stopping the KRAKEN daemon".into());
            hook().await;
        }

        let entries = plan_entries(&root, prefix)?;
        for (new, original, _) in &entries {
            let new_is_dir = new.is_dir();
            if fs::symlink_metadata(original).is_ok() {
                check_replaceable(original, new_is_dir)?;
                if original.is_dir() != new_is_dir {
                    return Err(refused(format!(
                        "{} changed between a file and a directory; nothing was replaced",
                        original.display()
                    )));
                }
            }
        }
        step(progress, "install", format!("installing {version}"));
        let old = ctx.current.to_string();
        let backup_root = previous_dir(&ctx.data_dir).join(&old);
        clear_backup_root(&backup_root, &old)?;
        let kept = swap(ctx.fs.as_ref(), &entries, &backup_root)?;
        let receipt = receipt_path(prefix);
        let generation = Generation {
            version: old.clone(),
            entries: kept.clone(),
            installed: Some(version.to_string()),
            receipt: receipt.is_file().then_some(receipt),
        };
        let manifest = serde_json::to_vec_pretty(&generation)
            .map_err(|e| refused(e.to_string()))?;
        if let Err(e) = fs::create_dir_all(&backup_root)
            .and_then(|()| fs::write(backup_root.join(MANIFEST), manifest))
        {
            undo(ctx.fs.as_ref(), &kept);
            return Err(UpdateError::Io {
                what: "cannot record the previous version; the update was undone".into(),
                source: e,
            });
        }
        prune_generations(&ctx.data_dir, &old);
        update_receipt(prefix, version);
        Ok(UpdateApplied {
            from: old,
            to: version.to_string(),
            replaced: kept
                .iter()
                .map(|k| k.original.display().to_string())
                .collect(),
            message: format!("Updated to {version}. Restart KRAKEN to use it."),
        })
    }
    .await;
    let _ = remove_any(&staging);
    result
}

#[allow(clippy::too_many_arguments)]
async fn install_appimage(
    ctx: &ApplyContext,
    fetcher: &dyn Fetcher,
    version: &Version,
    base: &str,
    asset: &str,
    expected: &str,
    image: &Path,
    progress: &(dyn Fn(JobProgress) + Send + Sync),
) -> Result<UpdateApplied, UpdateError> {
    check_replaceable(image, false)?;
    let mut part_name = image.as_os_str().to_owned();
    part_name.push(".part");
    let part = PathBuf::from(part_name);
    if fs::symlink_metadata(&part).is_ok() {
        check_replaceable(&part, false)?;
    }
    let result = async {
        let actual = download(
            fetcher,
            &format!("{base}/{asset}"),
            &part,
            MAX_ASSET_BYTES,
            asset,
            progress,
        )
        .await?;
        if actual != expected {
            return Err(refused(format!(
                "{asset} does not match the signed SHA-256 (expected {expected}, got {actual}); nothing was installed"
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&part, fs::Permissions::from_mode(0o755))
                .map_err(io_err("cannot make the new AppImage executable"))?;
        }
        step(progress, "check", "trying the new AppImage".into());
        check_version(
            ctx.run_version,
            &part,
            &["kraken", "--version"],
            &[("APPIMAGE_EXTRACT_AND_RUN", "1")],
            version,
            ctx.version_timeout,
        )?;
        step(progress, "install", format!("installing {version}"));
        let old = ctx.current.to_string();
        let backup_root = previous_dir(&ctx.data_dir).join(&old);
        clear_backup_root(&backup_root, &old)?;
        let rel = PathBuf::from(image.file_name().unwrap_or_default());
        let kept = swap(
            ctx.fs.as_ref(),
            &[(part.clone(), image.to_path_buf(), rel)],
            &backup_root,
        )?;
        let generation = Generation {
            version: old.clone(),
            entries: kept.clone(),
            installed: Some(version.to_string()),
            receipt: None,
        };
        let manifest = serde_json::to_vec_pretty(&generation)
            .map_err(|e| refused(e.to_string()))?;
        if let Err(e) = fs::create_dir_all(&backup_root)
            .and_then(|()| fs::write(backup_root.join(MANIFEST), manifest))
        {
            undo(ctx.fs.as_ref(), &kept);
            return Err(UpdateError::Io {
                what: "cannot record the previous version; the update was undone".into(),
                source: e,
            });
        }
        prune_generations(&ctx.data_dir, &old);
        Ok(UpdateApplied {
            from: old,
            to: version.to_string(),
            replaced: vec![image.display().to_string()],
            message: format!("Updated to {version}. Restart KRAKEN to use it."),
        })
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&part);
    }
    result
}

/// The version the kept generation holds, if there is one.
pub fn rollback_target(data_dir: &Path) -> Option<String> {
    newest_generation(data_dir).map(|(_, g)| g.version)
}

fn newest_generation(data_dir: &Path) -> Option<(PathBuf, Generation)> {
    let rd = fs::read_dir(previous_dir(data_dir)).ok()?;
    rd.flatten()
        .filter_map(|e| {
            let text = fs::read(e.path().join(MANIFEST)).ok()?;
            let g: Generation = serde_json::from_slice(&text).ok()?;
            let v = Version::parse(&g.version).ok()?;
            Some((v, e.path(), g))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, p, g)| (p, g))
}

/// Puts back the kept generation: the files the last update replaced.
pub fn rollback(data_dir: &Path, current: &str) -> Result<UpdateApplied, UpdateError> {
    rollback_with(&RealFs, data_dir, current)
}

/// [`rollback`] over the given file operations.
pub fn rollback_with(
    fs: &dyn SwapFs,
    data_dir: &Path,
    current: &str,
) -> Result<UpdateApplied, UpdateError> {
    if is_root() {
        return Err(refused("KRAKEN does not roll back as root"));
    }
    let _lock = lock(data_dir)?;
    let (dir, g) = newest_generation(data_dir)
        .ok_or_else(|| refused("no earlier version is kept; nothing to roll back to"))?;
    for k in &g.entries {
        if fs::symlink_metadata(&k.original).is_ok() {
            check_replaceable(&k.original, true)?;
        }
        if let Some(b) = &k.backup {
            check_replaceable(b, true)?;
        }
    }
    let aside = previous_dir(data_dir).join(".rollback");
    let _ = remove_any(&aside);
    // Each entry: the current file moves aside, the kept one back into place.
    let mut moved: Vec<(usize, Option<PathBuf>)> = Vec::new();
    let mut failure = None;
    for (i, k) in g.entries.iter().enumerate() {
        let current_copy = if fs::symlink_metadata(&k.original).is_ok() {
            let a = aside.join(i.to_string());
            if let Err(e) = relocate(fs, &k.original, &a) {
                let what = format!(
                    "cannot move {} aside{}",
                    k.original.display(),
                    in_use_hint(&e)
                );
                failure = Some((what, e));
                break;
            }
            Some(a)
        } else {
            None
        };
        moved.push((i, current_copy));
        if let Some(b) = &k.backup
            && let Err(e) = relocate(fs, b, &k.original)
        {
            failure = Some((format!("cannot put back {}", k.original.display()), e));
            break;
        }
    }
    if let Some((what, source)) = failure {
        for (i, current_copy) in moved.into_iter().rev() {
            let k = &g.entries[i];
            if let Some(b) = &k.backup
                && fs::symlink_metadata(b).is_err()
            {
                let _ = relocate(fs, &k.original, b);
            }
            if let Some(a) = current_copy {
                let _ = remove_retrying(fs, &k.original);
                let _ = relocate(fs, &a, &k.original);
            }
        }
        return Err(UpdateError::Io { what, source });
    }
    let _ = remove_any(&aside);
    let _ = remove_any(&dir);
    if let Some(r) = &g.receipt {
        write_receipt_version(r, &g.version);
    }
    Ok(UpdateApplied {
        from: g.installed.clone().unwrap_or_else(|| current.to_string()),
        to: g.version.clone(),
        replaced: g
            .entries
            .iter()
            .map(|k| k.original.display().to_string())
            .collect(),
        message: format!("Back to {}. Restart KRAKEN to use it.", g.version),
    })
}

#[cfg(test)]
#[path = "apply_tests.rs"]
mod tests;

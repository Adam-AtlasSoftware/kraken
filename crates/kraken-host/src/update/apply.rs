//! Installing a release over a per-user install, and rolling it back (ADR 0015, "Installing").
//!
//! The order is fixed: signature first, then the archive's SHA-256, extraction into a private
//! staging directory on the install's filesystem, the staged `kraken --version`, and only then the
//! swap under an exclusive lock. Every file that is replaced must be a regular file (or, for the
//! data directories, a directory) that the user owns; the old ones go to
//! `<data dir>/previous/<old version>/`, and a failure puts back what was already moved.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kraken_registry::commands::UpdateApplied;
use kraken_registry::jobs::JobProgress;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::UpdateError;
use super::check::{fetch_capped, is_newer};
use super::install::{InstallKind, is_root, run_path_with_timeout};
use super::verify::{sum_for, verify_sums};
use crate::provision::{Fetcher, extract_tar_gz, extract_zip};

/// Largest release file accepted.
pub const MAX_ASSET_BYTES: u64 = 2 << 30;

/// What an update works with.
#[derive(Debug, Clone)]
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

/// Moves `from` to `to`: a rename, or a copy and delete across filesystems.
fn relocate(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?;
    }
    match fs::rename(from, to) {
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            copy_tree(from, to)?;
            remove_any(from)
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
        remove_any(p).map_err(io_err(format!("cannot clear {}", p.display())))?;
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
    exe: &Path,
    args: &[&str],
    env: &[(&str, &str)],
    version: &Version,
    timeout: Duration,
) -> Result<(), UpdateError> {
    let out = run_path_with_timeout(exe, args, env, timeout).ok_or_else(|| {
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
    entries: &[(PathBuf, PathBuf, PathBuf)],
    backup_root: &Path,
) -> Result<Vec<Kept>, UpdateError> {
    let mut done: Vec<Kept> = Vec::new();
    let mut result = Ok(());
    for (new, original, rel) in entries {
        let backup = if fs::symlink_metadata(original).is_ok() {
            let b = backup_root.join(rel);
            if let Err(e) = relocate(original, &b) {
                result = Err(UpdateError::Io {
                    what: format!("cannot move {} aside", original.display()),
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
        if let Err(e) = fs::rename(new, original) {
            result = Err(UpdateError::Io {
                what: format!("cannot move the new {} into place", original.display()),
                source: e,
            });
            break;
        }
    }
    match result {
        Ok(()) => Ok(done),
        Err(e) => {
            undo(&done);
            Err(e)
        }
    }
}

/// Puts the kept copies back, newest move first.
fn undo(done: &[Kept]) {
    for k in done.iter().rev() {
        if let Some(b) = &k.backup {
            let _ = remove_any(&k.original);
            if let Err(e) = relocate(b, &k.original) {
                tracing::error!(error = %e, file = %k.original.display(), "could not put back the old file");
            }
        } else {
            let _ = remove_any(&k.original);
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
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(fs::TryLockError::WouldBlock) => {
            Err(refused("another update is running; wait for it to finish"))
        }
        Err(fs::TryLockError::Error(e)) => Err(UpdateError::Io {
            what: "cannot lock the update".into(),
            source: e,
        }),
    }
}

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
        check_version(&exe, &["--version"], &[], version, ctx.version_timeout)?;

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
        let kept = swap(&entries, &backup_root)?;
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
            undo(&kept);
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
        let kept = swap(&[(part.clone(), image.to_path_buf(), rel)], &backup_root)?;
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
            undo(&kept);
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
            if let Err(e) = relocate(&k.original, &a) {
                failure = Some((format!("cannot move {} aside", k.original.display()), e));
                break;
            }
            Some(a)
        } else {
            None
        };
        moved.push((i, current_copy));
        if let Some(b) = &k.backup
            && let Err(e) = relocate(b, &k.original)
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
                let _ = relocate(&k.original, b);
            }
            if let Some(a) = current_copy {
                let _ = remove_any(&k.original);
                let _ = relocate(&a, &k.original);
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

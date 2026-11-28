//! End-to-end updates on a temporary prefix, against canned release files signed with a key made
//! for the test run.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use super::*;
use crate::provision::{Body, Fetched, ProvisionError};
use crate::update::HostUpdater;
use crate::update::verify::tests::TestKey;
use crate::update::verify::trusted_comment;
use kraken_registry::commands::UpdateBackend;

const BASE: &str = "https://github.com/Adam-AtlasSoftware/kraken/releases/download";
const TARGET: &str = "x86_64-unknown-linux-gnu";

struct MemBody(Vec<Vec<u8>>);

#[async_trait]
impl Body for MemBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        Ok((!self.0.is_empty()).then(|| self.0.remove(0)))
    }
}

#[derive(Default)]
struct MemFetcher {
    files: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemFetcher {
    fn put(&self, url: &str, bytes: Vec<u8>) {
        self.files
            .lock()
            .expect("lock")
            .insert(url.to_string(), bytes);
    }
}

#[async_trait]
impl Fetcher for MemFetcher {
    async fn fetch(&self, url: &str, _from: u64) -> Result<Fetched, ProvisionError> {
        let bytes = self
            .files
            .lock()
            .expect("lock")
            .get(url)
            .cloned()
            .ok_or_else(|| ProvisionError::Http {
                url: url.into(),
                message: "HTTP 404".into(),
            })?;
        Ok(Fetched {
            resumed: false,
            total: Some(bytes.len() as u64),
            body: Box::new(MemBody(bytes.chunks(4096).map(<[u8]>::to_vec).collect())),
        })
    }
}

fn script(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho \"kraken {version}\"\n").into_bytes()
}

fn write_exec(p: &Path, bytes: &[u8]) {
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, bytes).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(p, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
}

/// A release archive like `scripts/package.sh` makes, with `kraken` reporting `reports`.
fn release_tar(version: &str, reports: &str, link: bool) -> Vec<u8> {
    let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::fast(),
    ));
    let top = format!("kraken-{version}-{TARGET}");
    let mut add = |path: String, bytes: &[u8], mode: u32| {
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(mode);
        h.set_cksum();
        tar.append_data(&mut h, path, bytes).expect("append");
    };
    add(format!("{top}/bin/kraken"), &script(reports), 0o755);
    add(format!("{top}/bin/krakend"), b"new daemon", 0o755);
    add(
        format!("{top}/share/kraken/kraken-ghidra.jar"),
        b"new jar",
        0o644,
    );
    add(
        format!("{top}/share/kraken/native-sla/x86.sla"),
        b"new sla",
        0o644,
    );
    add(format!("{top}/docs/index.html"), b"docs", 0o644);
    if link {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_cksum();
        tar.append_link(&mut h, format!("{top}/bin/kraken-link"), "kraken")
            .expect("link");
    }
    tar.into_inner().expect("tar").finish().expect("gz")
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Fixture {
    _dir: tempfile::TempDir,
    prefix: PathBuf,
    data: PathBuf,
    key: TestKey,
    fetcher: Arc<MemFetcher>,
}

impl Fixture {
    /// An install of 0.3.0 by the script, and release 0.4.0 published and signed.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tmp");
        let prefix = dir.path().join("prefix");
        let data = dir.path().join("data");
        write_exec(&prefix.join("bin/kraken"), &script("0.3.0"));
        write_exec(&prefix.join("bin/krakend"), b"old daemon");
        fs::create_dir_all(prefix.join("share/kraken/native-sla")).expect("mkdir");
        fs::write(prefix.join("share/kraken/kraken-ghidra.jar"), b"old jar").expect("jar");
        fs::write(prefix.join("share/kraken/native-sla/old.sla"), b"old sla").expect("sla");
        fs::write(
            prefix.join("share/kraken/install.json"),
            r#"{"method": "script", "version": "0.3.0", "prefix": "x"}"#,
        )
        .expect("receipt");
        let f = Fixture {
            _dir: dir,
            prefix,
            data,
            key: TestKey::new(),
            fetcher: Arc::new(MemFetcher::default()),
        };
        f.publish("0.4.0", &release_tar("0.4.0", "0.4.0", false), "0.4.0");
        f
    }

    /// Publishes `version` with `archive`, its SHA256SUMS signed for `signed_for`.
    fn publish(&self, version: &str, archive: &[u8], signed_for: &str) {
        let name = format!("kraken-{version}-{TARGET}.tar.gz");
        let sums = format!("{}  {name}\n", sha(archive));
        let base = format!("{BASE}/v{version}");
        self.fetcher
            .put(&format!("{base}/{name}"), archive.to_vec());
        self.fetcher.put(
            &format!("{base}/SHA256SUMS.minisig"),
            self.key
                .sign(sums.as_bytes(), &trusted_comment(signed_for))
                .into_bytes(),
        );
        self.fetcher
            .put(&format!("{base}/SHA256SUMS"), sums.into_bytes());
        self.fetcher.put(
            crate::update::check::LATEST_URL,
            format!(r#"{{"tag_name":"v{version}","html_url":"https://github.com/Adam-AtlasSoftware/kraken/releases/tag/v{version}","assets":[{{"name":"SHA256SUMS"}},{{"name":"SHA256SUMS.minisig"}}]}}"#).into_bytes(),
        );
    }

    fn updater(&self, kind: InstallKind) -> HostUpdater {
        HostUpdater::with_parts(
            self.data.clone(),
            None,
            self.prefix.join("bin/kraken"),
            kind,
            Version::new(0, 3, 0),
            self.key.public(),
            BASE.into(),
            self.fetcher.clone(),
        )
        .with_target(TARGET)
    }

    fn script_updater(&self) -> HostUpdater {
        self.updater(InstallKind::Script {
            prefix: self.prefix.clone(),
        })
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.prefix.join(rel)).unwrap_or_default()
    }
}

fn quiet(_: JobProgress) {}

#[cfg(unix)]
#[tokio::test]
async fn an_update_swaps_the_files_and_a_rollback_puts_them_back() {
    let f = Fixture::new();
    let u = f.script_updater();
    let s = u.check_now(true).await;
    assert!(s.update_available && s.latest_signed, "{s:?}");
    let done = u.apply(&quiet).await.expect("update");
    assert_eq!((done.from.as_str(), done.to.as_str()), ("0.3.0", "0.4.0"));
    assert_eq!(done.message, "Updated to 0.4.0. Restart KRAKEN to use it.");
    assert!(f.read("bin/kraken").contains("kraken 0.4.0"));
    assert_eq!(f.read("bin/krakend"), "new daemon");
    assert_eq!(f.read("share/kraken/kraken-ghidra.jar"), "new jar");
    assert_eq!(f.read("share/kraken/native-sla/x86.sla"), "new sla");
    assert!(!f.prefix.join("share/kraken/native-sla/old.sla").exists());
    // Only bin/ and share/kraken/ are installed; the staging directory is gone.
    assert!(!f.prefix.join("docs").exists());
    assert!(!f.prefix.join("share/kraken/.update-staging").exists());
    assert!(f.read("share/kraken/install.json").contains("\"0.4.0\""));
    assert!(f.data.join("previous/0.3.0/bin/kraken").is_file());
    assert_eq!(u.status_now().rollback_to.as_deref(), Some("0.3.0"));

    let back = u.rollback().expect("rollback");
    assert_eq!(back.to, "0.3.0");
    assert!(f.read("bin/kraken").contains("kraken 0.3.0"));
    assert_eq!(f.read("bin/krakend"), "old daemon");
    assert_eq!(f.read("share/kraken/kraken-ghidra.jar"), "old jar");
    assert!(f.prefix.join("share/kraken/native-sla/old.sla").is_file());
    assert!(!f.prefix.join("share/kraken/native-sla/x86.sla").exists());
    assert!(u.rollback().is_err(), "one generation only");
}

#[cfg(unix)]
#[tokio::test]
async fn a_link_in_place_of_a_program_is_refused_and_nothing_changes() {
    let f = Fixture::new();
    let real = f.prefix.join("bin/kraken-real");
    fs::rename(f.prefix.join("bin/kraken"), &real).expect("mv");
    std::os::unix::fs::symlink(&real, f.prefix.join("bin/kraken")).expect("link");
    let e = f.script_updater().apply(&quiet).await.expect_err("refused");
    assert!(e.message.contains("is a link"), "{e:?}");
    assert_eq!(f.read("bin/krakend"), "old daemon");
    assert!(!f.data.join("previous").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn signatures_must_be_valid_and_for_this_version() {
    let f = Fixture::new();
    // Signed by another key.
    let other = Fixture::new();
    let sums = f.fetcher.files.lock().expect("lock")[&format!("{BASE}/v0.4.0/SHA256SUMS")].clone();
    f.fetcher.put(
        &format!("{BASE}/v0.4.0/SHA256SUMS.minisig"),
        other
            .key
            .sign(&sums, &trusted_comment("0.4.0"))
            .into_bytes(),
    );
    let e = f.script_updater().apply(&quiet).await.expect_err("bad key");
    assert!(
        e.message.contains("not signed by the KRAKEN release key"),
        "{e:?}"
    );
    // A list signed for an older release, replayed as 0.4.0.
    f.publish("0.4.0", &release_tar("0.4.0", "0.4.0", false), "0.3.9");
    let e = f.script_updater().apply(&quiet).await.expect_err("replay");
    assert!(e.message.contains("kraken v0.4.0 SHA256SUMS"), "{e:?}");
    // No signature at all.
    f.fetcher
        .files
        .lock()
        .expect("lock")
        .remove(&format!("{BASE}/v0.4.0/SHA256SUMS.minisig"));
    let e = f
        .script_updater()
        .apply(&quiet)
        .await
        .expect_err("unsigned");
    assert!(e.message.contains("no signature"), "{e:?}");
    assert_eq!(f.read("bin/krakend"), "old daemon");
}

#[cfg(unix)]
#[tokio::test]
async fn a_changed_archive_a_wrong_version_or_a_link_inside_stop_the_update() {
    let f = Fixture::new();
    // The archive does not match the signed hash.
    f.fetcher.put(
        &format!("{BASE}/v0.4.0/kraken-0.4.0-{TARGET}.tar.gz"),
        release_tar("0.4.0", "0.4.1", false),
    );
    let e = f.script_updater().apply(&quiet).await.expect_err("hash");
    assert!(
        e.message.contains("does not match the signed SHA-256"),
        "{e:?}"
    );
    // The new program reports another version.
    f.publish("0.4.0", &release_tar("0.4.0", "0.3.5", false), "0.4.0");
    let e = f.script_updater().apply(&quiet).await.expect_err("version");
    assert!(e.message.contains("reports \"kraken 0.3.5\""), "{e:?}");
    // A link inside the archive.
    f.publish("0.4.0", &release_tar("0.4.0", "0.4.0", true), "0.4.0");
    let e = f.script_updater().apply(&quiet).await.expect_err("link");
    assert!(e.message.contains("holds a link"), "{e:?}");
    assert!(f.read("bin/kraken").contains("0.3.0"));
    assert!(!f.prefix.join("share/kraken/.update-staging").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn never_a_downgrade_and_never_for_a_package_managed_install() {
    let f = Fixture::new();
    f.publish("0.3.0", &release_tar("0.3.0", "0.3.0", false), "0.3.0");
    let e = f.script_updater().apply(&quiet).await.expect_err("same");
    assert!(e.message.contains("never downgrades"), "{e:?}");
    let aur = f.updater(InstallKind::Aur {
        package: "kraken-workbench-bin".into(),
        helper: "yay".into(),
    });
    let e = aur.apply(&quiet).await.expect_err("aur");
    assert!(e.message.contains("yay -Syu kraken-workbench-bin"), "{e:?}");
}

#[test]
fn a_failed_swap_puts_back_what_was_moved() {
    let d = tempfile::tempdir().expect("tmp");
    let p = d.path();
    fs::create_dir_all(p.join("new")).expect("mkdir");
    fs::create_dir_all(p.join("bin")).expect("mkdir");
    fs::write(p.join("new/a"), "new a").expect("w");
    fs::write(p.join("bin/a"), "old a").expect("w");
    fs::write(p.join("bin/b"), "old b").expect("w");
    // The second new file is missing, so its rename fails after the first swap.
    let entries = vec![
        (p.join("new/a"), p.join("bin/a"), PathBuf::from("bin/a")),
        (p.join("new/b"), p.join("bin/b"), PathBuf::from("bin/b")),
    ];
    assert!(swap(&RealFs, &entries, &p.join("backup")).is_err());
    assert_eq!(fs::read_to_string(p.join("bin/a")).expect("a"), "old a");
    assert_eq!(fs::read_to_string(p.join("bin/b")).expect("b"), "old b");
}

#[cfg(unix)]
#[tokio::test]
async fn an_appimage_is_replaced_beside_itself_and_rolled_back() {
    let f = Fixture::new();
    let image = f.prefix.join("Apps/KRAKEN.AppImage");
    write_exec(&image, &script("0.3.0"));
    let new_image = script("0.4.0");
    let name = "KRAKEN-0.4.0-x86_64.AppImage";
    let sums = format!("{}  {name}\n", sha(&new_image));
    f.fetcher.put(&format!("{BASE}/v0.4.0/{name}"), new_image);
    f.fetcher.put(
        &format!("{BASE}/v0.4.0/SHA256SUMS.minisig"),
        f.key
            .sign(sums.as_bytes(), &trusted_comment("0.4.0"))
            .into_bytes(),
    );
    f.fetcher
        .put(&format!("{BASE}/v0.4.0/SHA256SUMS"), sums.into_bytes());
    let u = f.updater(InstallKind::AppImage {
        path: image.clone(),
    });
    let done = u.apply(&quiet).await.expect("update");
    assert_eq!(done.replaced, vec![image.display().to_string()]);
    assert!(fs::read_to_string(&image).expect("read").contains("0.4.0"));
    assert!(!f.prefix.join("Apps/KRAKEN.AppImage.part").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&image).expect("md").permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }
    u.rollback().expect("rollback");
    assert!(fs::read_to_string(&image).expect("read").contains("0.3.0"));
}

#[cfg(unix)]
#[tokio::test]
async fn skipping_and_notices_follow_the_state_file() {
    let f = Fixture::new();
    let u = f.script_updater();
    // First run: the one-time notice; then nothing until a check found something.
    assert_eq!(
        u.take_cli_notice().as_deref(),
        Some(crate::update::FIRST_NOTICE)
    );
    assert_eq!(u.take_cli_notice(), None);
    u.check_now(true).await;
    let line = u.take_cli_notice().expect("notice");
    assert!(
        line.starts_with("KRAKEN 0.4.0 is available (you have 0.3.0)"),
        "{line}"
    );
    // At most once a day.
    assert_eq!(u.take_cli_notice(), None);
    let mut st = crate::update::state::UpdateState::load(&f.data);
    st.last_notice = None;
    st.save(&f.data).expect("save");
    u.skip(Some("0.4.0".into())).expect("skip");
    assert_eq!(u.take_cli_notice(), None);
    assert_eq!(u.status_now().skipped.as_deref(), Some("0.4.0"));
    // Turned off.
    let off = f
        .script_updater()
        .with_env(Arc::new(|k| (k == "CI").then(|| "true".into())));
    assert_eq!(off.status_now().checks_disabled_by.as_deref(), Some("CI"));
    assert!(!off.check_due());
}

#[cfg(unix)]
#[tokio::test]
async fn a_second_update_before_a_restart_keeps_the_old_version() {
    let f = Fixture::new();
    // The same process (still 0.3.0 in memory) updates twice.
    let u = f.script_updater();
    u.apply(&quiet).await.expect("update");
    assert!(!u.status_now().update_available, "0.4.0 is on disk already");
    let e = u.apply(&quiet).await.expect_err("already installed");
    assert!(e.message.contains("0.4.0 is already installed"), "{e:?}");
    assert!(
        fs::read_to_string(f.data.join("previous/0.3.0/bin/kraken"))
            .expect("kept")
            .contains("kraken 0.3.0")
    );
    // A newer release still installs, from the version on disk.
    f.publish("0.5.0", &release_tar("0.5.0", "0.5.0", false), "0.5.0");
    let done = u.apply(&quiet).await.expect("second update");
    assert_eq!((done.from.as_str(), done.to.as_str()), ("0.4.0", "0.5.0"));
    assert!(
        fs::read_to_string(f.data.join("previous/0.4.0/bin/kraken"))
            .expect("kept")
            .contains("kraken 0.4.0")
    );
    let back = u.rollback().expect("rollback");
    assert_eq!((back.from.as_str(), back.to.as_str()), ("0.5.0", "0.4.0"));
    assert!(f.read("bin/kraken").contains("kraken 0.4.0"));
    assert!(f.read("share/kraken/install.json").contains("\"0.4.0\""));
}

#[test]
fn a_kept_copy_of_another_install_is_not_cleared() {
    let d = tempfile::tempdir().expect("tmp");
    let root = d.path().join("previous/0.4.0");
    fs::create_dir_all(&root).expect("mkdir");
    fs::write(
        root.join(MANIFEST),
        r#"{"version":"0.4.0","entries":[],"installed":"0.5.0"}"#,
    )
    .expect("manifest");
    let e = clear_backup_root(&root, "0.4.0").expect_err("refused");
    assert!(e.to_string().contains("only copy of 0.4.0"), "{e}");
    assert!(root.join(MANIFEST).is_file());
    // A copy kept by an older manifest (no `installed`) or a stray directory is cleared.
    fs::write(root.join(MANIFEST), r#"{"version":"0.4.0","entries":[]}"#).expect("manifest");
    clear_backup_root(&root, "0.4.0").expect("cleared");
    assert!(!root.exists());
}

// ---------------------------------------------------------------------------------------------
// Windows behaviour, simulated: a running program can be renamed but not deleted, the data
// directory may be on another volume than the install, and an antivirus scan holds a new file
// for a moment. The real rules are checked on Windows by the `cfg(windows)` test at the end.

/// The real file system with Windows' refusals added.
#[derive(Default)]
struct WindowsLikeFs {
    /// Running programs: they can be renamed (the name follows the file) but not deleted.
    running: Mutex<Vec<PathBuf>>,
    /// Paths under this directory are on another volume than everything else.
    other_volume: Option<PathBuf>,
    /// Renames from these paths fail as "busy" this many more times.
    busy: Mutex<HashMap<PathBuf, u32>>,
}

impl WindowsLikeFs {
    fn on_other_volume(&self, p: &Path) -> bool {
        self.other_volume.as_ref().is_some_and(|v| p.starts_with(v))
    }

    fn holds_running(&self, p: &Path) -> bool {
        self.running
            .lock()
            .expect("lock")
            .iter()
            .any(|r| r.starts_with(p))
    }
}

impl SwapFs for WindowsLikeFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        if let Some(n) = self.busy.lock().expect("lock").get_mut(from)
            && *n > 0
        {
            *n -= 1;
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, "scanned"));
        }
        if self.on_other_volume(from) != self.on_other_volume(to) {
            return Err(io::Error::new(
                io::ErrorKind::CrossesDevices,
                "other volume",
            ));
        }
        fs::rename(from, to)?;
        for r in self.running.lock().expect("lock").iter_mut() {
            if let Ok(rest) = r.strip_prefix(from) {
                *r = to.join(rest);
            }
        }
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        if self.holds_running(path) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "running"));
        }
        remove_any(path)
    }

    fn retry_delays(&self) -> &[Duration] {
        &[Duration::ZERO; 3]
    }
}

const WIN_TARGET: &str = "x86_64-pc-windows-msvc";

/// Reads the stand-in program instead of running it: these "programs" are text.
fn read_version(exe: &Path, _: &[&str], _: &[(&str, &str)], _: Duration) -> Option<String> {
    let text = fs::read_to_string(exe).ok()?;
    let at = text.find("kraken ")?;
    Some(text[at..].trim_end_matches(['"', '\n', '\r']).to_string())
}

/// The Windows release zip as `scripts/package.sh` makes it.
fn release_zip(version: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default();
        let top = format!("kraken-{version}-{WIN_TARGET}");
        for (name, body) in [
            ("bin/kraken.exe", format!("kraken {version}")),
            ("bin/krakend.exe", "new daemon".to_string()),
            ("bin/kraken-gui.exe", "new gui".to_string()),
            ("share/kraken/kraken-ghidra.jar", "new jar".to_string()),
            (
                "share/kraken/kraken-dotnet/kraken-dotnet.dll",
                "new dll".to_string(),
            ),
            ("README.md", "readme".to_string()),
        ] {
            z.start_file(format!("{top}/{name}"), opts).expect("start");
            z.write_all(body.as_bytes()).expect("write");
        }
        z.finish().expect("finish");
    }
    buf.into_inner()
}

/// An install by `install.ps1` (receipt `windows_installer`) of 0.3.0, release 0.4.0 signed.
fn windows_fixture() -> Fixture {
    let f = Fixture::new();
    for p in ["bin/kraken", "bin/krakend"] {
        let _ = fs::remove_file(f.prefix.join(p));
    }
    fs::write(f.prefix.join("bin/kraken.exe"), "kraken 0.3.0").expect("w");
    fs::write(f.prefix.join("bin/krakend.exe"), "old daemon").expect("w");
    fs::write(f.prefix.join("bin/kraken-gui.exe"), "old gui").expect("w");
    fs::create_dir_all(f.prefix.join("share/kraken/kraken-dotnet")).expect("mkdir");
    fs::write(
        f.prefix
            .join("share/kraken/kraken-dotnet/kraken-dotnet.dll"),
        "old dll",
    )
    .expect("w");
    fs::write(
        f.prefix.join("share/kraken/install.json"),
        r#"{"method": "windows_installer", "version": "0.3.0", "prefix": "x"}"#,
    )
    .expect("receipt");
    let zip = release_zip("0.4.0");
    let name = format!("kraken-0.4.0-{WIN_TARGET}.zip");
    let sums = format!("{}  {name}\n", sha(&zip));
    let base = format!("{BASE}/v0.4.0");
    f.fetcher.put(&format!("{base}/{name}"), zip);
    f.fetcher.put(
        &format!("{base}/SHA256SUMS.minisig"),
        f.key
            .sign(sums.as_bytes(), &trusted_comment("0.4.0"))
            .into_bytes(),
    );
    f.fetcher
        .put(&format!("{base}/SHA256SUMS"), sums.into_bytes());
    f
}

fn windows_updater(f: &Fixture, fs: Arc<WindowsLikeFs>) -> HostUpdater {
    f.updater(InstallKind::WindowsInstaller {
        prefix: f.prefix.clone(),
    })
    .with_target(WIN_TARGET)
    .with_version_runner(read_version)
    .with_fs(fs)
}

fn leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.contains(LEFTOVER_MARK))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn running_programs_are_renamed_aside_and_rolled_back_on_windows() {
    for other_volume in [false, true] {
        let f = windows_fixture();
        let wfs = Arc::new(WindowsLikeFs {
            running: Mutex::new(vec![
                f.prefix.join("bin/kraken.exe"),
                f.prefix.join("bin/krakend.exe"),
                f.prefix
                    .join("share/kraken/kraken-dotnet/kraken-dotnet.dll"),
            ]),
            other_volume: other_volume.then(|| f.data.clone()),
            busy: Mutex::new(HashMap::new()),
        });
        let stopped = Arc::new(Mutex::new(false));
        let s2 = stopped.clone();
        let u = windows_updater(&f, wfs.clone()).with_before_swap(Arc::new(move || {
            let s2 = s2.clone();
            Box::pin(async move {
                *s2.lock().expect("lock") = true;
            })
        }));
        let done = u.apply(&quiet).await.expect("update");
        assert!(
            *stopped.lock().expect("lock"),
            "the daemon is stopped first"
        );
        assert_eq!(done.to, "0.4.0");
        assert_eq!(f.read("bin/kraken.exe"), "kraken 0.4.0");
        assert_eq!(f.read("bin/krakend.exe"), "new daemon");
        assert_eq!(f.read("bin/kraken-gui.exe"), "new gui");
        assert_eq!(
            f.read("share/kraken/kraken-dotnet/kraken-dotnet.dll"),
            "new dll"
        );
        assert!(f.read("share/kraken/install.json").contains("\"0.4.0\""));
        let kept = f.data.join("previous/0.3.0/bin/kraken.exe");
        assert_eq!(fs::read_to_string(&kept).expect("kept"), "kraken 0.3.0");
        // Across volumes the running programs could only be renamed beside themselves; they
        // wait in the install for the next start.
        let left = leftovers(&f.prefix.join("bin"));
        if other_volume {
            assert_eq!(left.len(), 2, "{left:?}");
            assert_eq!(leftovers(&f.prefix.join("share/kraken")).len(), 1);
        } else {
            assert!(left.is_empty(), "{left:?}");
        }

        // The rollback runs from the new program, which is running now.
        *wfs.running.lock().expect("lock") = vec![f.prefix.join("bin/kraken.exe")];
        let back = u.rollback().expect("rollback");
        assert_eq!(back.to, "0.3.0");
        assert_eq!(f.read("bin/kraken.exe"), "kraken 0.3.0");
        assert_eq!(f.read("bin/krakend.exe"), "old daemon");
        assert_eq!(
            f.read("share/kraken/kraken-dotnet/kraken-dotnet.dll"),
            "old dll"
        );
        assert!(f.read("share/kraken/install.json").contains("\"0.3.0\""));

        // The next start deletes what had to stay.
        sweep_leftovers(&f.prefix);
        assert!(leftovers(&f.prefix.join("bin")).is_empty());
        assert!(leftovers(&f.prefix.join("share/kraken")).is_empty());
        assert_eq!(f.read("bin/kraken.exe"), "kraken 0.3.0");
    }
}

fn two_file_swap(p: &Path) -> Vec<(PathBuf, PathBuf, PathBuf)> {
    fs::create_dir_all(p.join("new")).expect("mkdir");
    fs::create_dir_all(p.join("bin")).expect("mkdir");
    for n in ["a", "b"] {
        fs::write(p.join("new").join(n), format!("new {n}")).expect("w");
        fs::write(p.join("bin").join(n), format!("old {n}")).expect("w");
    }
    vec![
        (p.join("new/a"), p.join("bin/a"), PathBuf::from("bin/a")),
        (p.join("new/b"), p.join("bin/b"), PathBuf::from("bin/b")),
    ]
}

#[test]
fn a_file_held_for_a_moment_is_tried_again_and_one_held_too_long_undoes_the_swap() {
    // Held twice: the retries get through.
    let d = tempfile::tempdir().expect("tmp");
    let entries = two_file_swap(d.path());
    let wfs = WindowsLikeFs::default();
    wfs.busy
        .lock()
        .expect("lock")
        .insert(d.path().join("new/b"), 2);
    swap(&wfs, &entries, &d.path().join("backup")).expect("swap");
    assert_eq!(
        fs::read_to_string(d.path().join("bin/b")).expect("b"),
        "new b"
    );

    // Held longer than the retries last: everything is put back and the message says why.
    let d = tempfile::tempdir().expect("tmp");
    let entries = two_file_swap(d.path());
    let wfs = WindowsLikeFs::default();
    wfs.busy
        .lock()
        .expect("lock")
        .insert(d.path().join("bin/b"), 10);
    let e = swap(&wfs, &entries, &d.path().join("backup")).expect_err("held");
    assert!(e.to_string().contains("kraken daemon stop"), "{e}");
    assert_eq!(
        fs::read_to_string(d.path().join("bin/a")).expect("a"),
        "old a"
    );
    assert_eq!(
        fs::read_to_string(d.path().join("bin/b")).expect("b"),
        "old b"
    );
}

#[test]
fn the_update_lock_is_held_by_one_update_at_a_time() {
    let d = tempfile::tempdir().expect("tmp");
    let first = lock(d.path()).expect("first");
    let e = lock(d.path()).expect_err("second");
    assert!(e.to_string().contains("another update is running"), "{e}");
    drop(first);
    lock(d.path()).expect("free again");
}

/// On Windows itself: a running program cannot be overwritten, but the update renames it aside,
/// puts the new one in its place, and a rollback brings it back.
#[cfg(windows)]
#[tokio::test]
async fn on_windows_a_running_daemon_is_replaced_and_restored() {
    let f = windows_fixture();
    let system = std::env::var_os("SystemRoot").expect("SystemRoot");
    let ping = PathBuf::from(system).join(r"System32\PING.EXE");
    let daemon = f.prefix.join("bin/krakend.exe");
    fs::copy(&ping, &daemon).expect("copy");
    let original = fs::read(&daemon).expect("read");
    let mut child = std::process::Command::new(&daemon)
        .args(["-n", "60", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start");
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        fs::write(&daemon, b"x").is_err(),
        "a running program cannot be overwritten"
    );
    let u = f
        .updater(InstallKind::WindowsInstaller {
            prefix: f.prefix.clone(),
        })
        .with_target(WIN_TARGET)
        .with_version_runner(read_version);
    let result = u.apply(&quiet).await;
    let replaced = f.read("bin/krakend.exe");
    let back = result.as_ref().ok().map(|_| u.rollback());
    let _ = child.kill();
    let _ = child.wait();
    result.expect("update");
    assert_eq!(replaced, "new daemon");
    back.expect("rollback ran").expect("rollback");
    assert_eq!(fs::read(&daemon).expect("read"), original);
    assert_eq!(f.read("bin/kraken.exe"), "kraken 0.3.0");
}

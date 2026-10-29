use std::collections::HashMap;
use std::io::Write;

use sha2::{Digest, Sha256};

use super::*;
use crate::provision::{Body, Fetched, ProvisionError};

struct MemBody(Vec<u8>, bool);

#[async_trait]
impl Body for MemBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        if self.1 {
            return Ok(None);
        }
        self.1 = true;
        Ok(Some(std::mem::take(&mut self.0)))
    }
}

/// Serves canned bytes by URL; no network.
struct Canned(HashMap<String, Vec<u8>>);

#[async_trait]
impl Fetcher for Canned {
    async fn fetch(&self, url: &str, from: u64) -> Result<Fetched, ProvisionError> {
        crate::provision::require_https(url)?;
        let all = self
            .0
            .get(url)
            .cloned()
            .ok_or_else(|| ProvisionError::Http {
                url: url.into(),
                message: "HTTP 404".into(),
            })?;
        let body = all[from as usize..].to_vec();
        Ok(Fetched {
            resumed: from > 0,
            total: Some(all.len() as u64),
            body: Box::new(MemBody(body, false)),
        })
    }
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

fn zip_with(name: &str, content: &[u8]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o644);
        z.start_file(name, opts).unwrap();
        z.write_all(content).unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

const SCRIPT: &[u8] = b"#!/bin/sh\necho \"toyemu 1.2 $*\"\n";

fn manifest_for(zip: &[u8], bad_hash: bool) -> String {
    let hash = if bad_hash { "0".repeat(64) } else { sha(zip) };
    format!(
        r#"schema = 1
[[emulator]]
id = "toyemu"
name = "Toy"
summary = "a test emulator"
license = "MIT"
notice = "read me"
[emulator.run]
argv = ["{{exe}}", "{{binary}}"]
gui = false
[[emulator.artifact]]
version = "1.2"
url = "https://example.test/toy.zip"
sha256 = "{hash}"
size = {size}
format = "zip"
entry = "bin/toy"
"#,
        size = zip.len()
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    catalogue: Integrations,
}

fn fixture(bad_hash: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_with("bin/toy", SCRIPT);
    let user = dir.path().join("emulators.d");
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(user.join("toy.toml"), manifest_for(&zip, bad_hash)).unwrap();
    let mut files = HashMap::new();
    files.insert("https://example.test/toy.zip".to_string(), zip);
    let root = dir.path().join("data/integrations");
    let catalogue = Integrations::new(root.clone(), Some(user), Arc::new(Canned(files)));
    Fixture {
        _dir: dir,
        root,
        catalogue,
    }
}

fn toy(c: &Integrations) -> IntegrationView {
    c.list()
        .unwrap()
        .into_iter()
        .find(|v| v.id == "toyemu")
        .unwrap()
}

#[test]
fn the_catalogue_lists_the_shipped_emulators_and_the_users() {
    let f = fixture(false);
    let list = f.catalogue.list().unwrap();
    assert!(list.iter().any(|v| v.id == "xemu"));
    let t = toy(&f.catalogue);
    assert!(t.user_supplied);
    assert_eq!(t.status, IntegrationStatus::NotInstalled);
    assert_eq!(t.pinned_version.as_deref(), Some("1.2"));
    // Dolphin has no Linux artifact: use your own copy.
    let d = list.iter().find(|v| v.id == "dolphin").unwrap();
    assert_eq!(d.status, IntegrationStatus::ManualOnly);
}

#[tokio::test]
async fn install_verifies_unpacks_runs_and_removes() {
    let f = fixture(false);
    assert!(f.catalogue.install("toyemu", false).await.is_err());
    let v = f.catalogue.install("toyemu", true).await.unwrap();
    assert_eq!(v.status, IntegrationStatus::Ready);
    assert_eq!(v.source, Some(IntegrationSource::Downloaded));
    assert_eq!(v.version.as_deref(), Some("1.2"));
    assert!(v.disk_bytes > 0);
    assert!(v.progress.is_none());
    let exe = f.root.join("toyemu/1.2/bin/toy");
    assert!(exe.is_file());
    assert_eq!(v.path.as_deref(), exe.to_str());
    let spec = f.catalogue.launch_spec("toyemu").unwrap();
    assert_eq!(spec.exe, exe);
    let out = std::process::Command::new(&spec.exe)
        .arg("--version")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("toyemu 1.2"));
    // The archive is gone; the install is all that is left.
    assert!(!f.root.join("downloads/toy.zip").exists());

    let r = f.catalogue.remove("toyemu").unwrap();
    assert!(r.freed_bytes > 0);
    assert!(!f.root.join("toyemu").exists());
    assert_eq!(toy(&f.catalogue).status, IntegrationStatus::NotInstalled);
    assert!(f.catalogue.launch_spec("toyemu").is_err());
}

#[tokio::test]
async fn a_wrong_hash_installs_nothing() {
    let f = fixture(true);
    let err = f.catalogue.install("toyemu", true).await.unwrap_err();
    assert!(err.message.contains("sha256"), "{}", err.message);
    assert!(!f.root.join("toyemu").exists());
    assert!(toy(&f.catalogue).progress.is_none());
    assert_eq!(toy(&f.catalogue).status, IntegrationStatus::NotInstalled);
}

#[tokio::test]
async fn an_entry_without_a_build_cannot_be_installed() {
    let f = fixture(false);
    let err = f.catalogue.install("dolphin", true).await.unwrap_err();
    assert!(
        err.message.contains("integration_use_path"),
        "{}",
        err.message
    );
}

#[test]
fn use_path_and_remove_forget_without_touching_the_program() {
    let f = fixture(false);
    let prog = f._dir.path().join("my-toy");
    std::fs::write(&prog, SCRIPT).unwrap();
    assert!(
        f.catalogue.use_path("toyemu", &prog).is_err(),
        "not executable yet"
    );
    make_executable(&prog);
    let v = f.catalogue.use_path("toyemu", &prog).unwrap();
    assert_eq!(v.source, Some(IntegrationSource::UserPath));
    assert_eq!(
        f.catalogue.launch_spec("toyemu").unwrap().exe,
        prog.canonicalize().unwrap()
    );
    let r = f.catalogue.remove("toyemu").unwrap();
    assert_eq!(r.freed_bytes, 0);
    assert!(prog.is_file(), "the person's program stays");
    assert_eq!(toy(&f.catalogue).status, IntegrationStatus::NotInstalled);
}

#[test]
fn system_copies_are_found_on_path_and_in_well_known_places() {
    let f = fixture(false);
    let home = f._dir.path().join("home");
    let bin = f._dir.path().join("bin");
    std::fs::create_dir_all(home.join("Applications")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let c = Integrations::new(f.root.clone(), None, Arc::new(Canned(HashMap::new())))
        .with_search(bin.clone().into_os_string(), Some(home.clone()));
    let find = |id: &str| c.list().unwrap().into_iter().find(|v| v.id == id).unwrap();
    assert_eq!(find("mgba").status, IntegrationStatus::NotInstalled);
    let on_path = bin.join("mgba-qt");
    std::fs::write(&on_path, SCRIPT).unwrap();
    make_executable(&on_path);
    let v = find("mgba");
    assert_eq!(v.source, Some(IntegrationSource::System));
    assert_eq!(v.path.as_deref(), on_path.to_str());
    // A well-known place, matched by pattern.
    let appimage = home.join("Applications/xemu-0.8.1-x86_64.AppImage");
    std::fs::write(&appimage, SCRIPT).unwrap();
    make_executable(&appimage);
    assert_eq!(find("xemu").path.as_deref(), appimage.to_str());
    let spec = c.launch_spec("xemu").unwrap();
    assert!(
        spec.env
            .iter()
            .any(|(k, _)| k == "APPIMAGE_EXTRACT_AND_RUN")
    );
    // A probed tool reports the version it prints.
    let qemu = bin.join("qemu-aarch64");
    std::fs::write(&qemu, SCRIPT).unwrap();
    make_executable(&qemu);
    assert_eq!(
        find("qemu-user-aarch64").version.as_deref(),
        Some("toyemu 1.2 --version")
    );
}

#[test]
fn patterns_match_one_component() {
    assert!(wild_match("pcsx2*.AppImage", "pcsx2-v2.8.2.AppImage"));
    assert!(!wild_match("pcsx2*.AppImage", "pcsx2.zip"));
    assert!(wild_match("*hadps4*.AppImage", "Shadps4-sdl.AppImage"));
    assert!(wild_match("melonDS", "melonDS"));
    assert!(!wild_match("a*b*c", "acb"));
}

#[test]
fn a_broken_user_manifest_is_skipped() {
    let f = fixture(false);
    let user = f._dir.path().join("emulators.d");
    std::fs::write(
        user.join("bad.toml"),
        "schema = 1\n[[emulator]]\nid = \"BAD ID\"\n",
    )
    .unwrap();
    std::fs::write(
        user.join("dup.toml"),
        manifest_for(&zip_with("x", b"x"), false).replace("toyemu", "xemu"),
    )
    .unwrap();
    let list = f.catalogue.list().unwrap();
    assert!(list.iter().all(|v| v.id != "BAD ID"));
    assert_eq!(list.iter().filter(|v| v.id == "xemu").count(), 1);
    assert!(!list.iter().find(|v| v.id == "xemu").unwrap().user_supplied);
}

#[test]
fn tar_xz_archives_unpack() {
    // A tiny tar holding one file, xz-compressed.
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        let mut h = tar::Header::new_gnu();
        h.set_size(SCRIPT.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        b.append_data(&mut h, "a/b/prog", SCRIPT).unwrap();
        b.finish().unwrap();
    }
    let mut xz = Vec::new();
    lzma_rs::xz_compress(&mut std::io::Cursor::new(&tar_bytes), &mut xz).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("x.tar.xz");
    std::fs::write(&archive, &xz).unwrap();
    let out = dir.path().join("out");
    extract_tar_xz(&archive, &out).unwrap();
    assert_eq!(std::fs::read(out.join("a/b/prog")).unwrap(), SCRIPT);
    assert!(!dir.path().join("x.tar.unxz").exists());
}

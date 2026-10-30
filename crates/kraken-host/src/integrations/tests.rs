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

/// Every emulator id the format detector suggests exists in the catalogue.
#[test]
fn emulators_suggested_by_the_format_detector_are_in_the_catalogue() {
    let f = fixture(false);
    let ids: Vec<String> = f
        .catalogue
        .list()
        .unwrap()
        .into_iter()
        .map(|v| v.id)
        .collect();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kraken-formats/src");
    let mut seen = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        for line in text.lines() {
            let wanted = line.contains("run_with(")
                || line.contains("Some(\"qemu-user-")
                || line.contains("emulators = vec![")
                || line.contains("SNES_EMU: ")
                || line.contains("push(q)");
            if !wanted {
                continue;
            }
            for quoted in line.split('"').skip(1).step_by(2) {
                if quoted.contains(' ') || quoted.is_empty() {
                    continue;
                }
                seen += 1;
                assert!(
                    ids.iter().any(|i| i == quoted),
                    "`{quoted}` is not a catalogue emulator"
                );
            }
        }
    }
    assert!(
        seen >= 20,
        "found only {seen} suggestions: did the detector's source change shape?"
    );
}

// ---- sysroot and toolchain recipes ----

/// A hand-built Debian package: `ar` holding `debian-binary`, a control member and a data tar
/// (xz-compressed) with `files` (path, content) and `links` (path, target).
fn deb_with(files: &[(&str, &[u8])], links: &[(&str, &str)], data_name: &str) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut b = tar::Builder::new(&mut tar_bytes);
        // Debian packages start with an entry for the root itself.
        let mut root = tar::Header::new_gnu();
        root.set_entry_type(tar::EntryType::Directory);
        root.set_size(0);
        root.set_mode(0o755);
        root.set_cksum();
        b.append_data(&mut root, "./", std::io::empty()).unwrap();
        for (path, content) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(content.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, format!("./{path}"), *content)
                .unwrap();
        }
        for (path, target) in links {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_mode(0o777);
            h.set_cksum();
            b.append_link(&mut h, format!("./{path}"), target).unwrap();
        }
        b.finish().unwrap();
    }
    let mut xz = Vec::new();
    lzma_rs::xz_compress(&mut std::io::Cursor::new(&tar_bytes), &mut xz).unwrap();
    let mut out = b"!<arch>\n".to_vec();
    for (name, body) in [
        ("debian-binary", b"2.0\n".to_vec()),
        ("control.tar.xz", vec![0u8; 3]),
        (data_name, xz),
    ] {
        out.extend_from_slice(
            format!(
                "{:<16}{:<12}0     0     100644  {:<10}`\n",
                name,
                0,
                body.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&body);
        if body.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

fn sysroot_manifest(libc: &[u8], gcc: &[u8], bad_hash: bool) -> String {
    let h = |b: &[u8]| if bad_hash { "0".repeat(64) } else { sha(b) };
    format!(
        r#"schema = 1
[[emulator]]
id = "sysroot-toy"
name = "Toy libraries"
kind = "sysroot"
summary = "s"
license = "LGPL-2.1-or-later"
[emulator.sysroot]
set = "aarch64"
loader = "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
[[emulator.artifact]]
version = "d13-1"
url = "https://example.test/libc6.deb"
sha256 = "{}"
size = {}
format = "deb"
[[emulator.artifact]]
version = "d13-1"
url = "https://example.test/libgcc-s1.deb"
sha256 = "{}"
size = {}
format = "deb"
"#,
        h(libc),
        libc.len(),
        h(gcc),
        gcc.len()
    )
}

fn sysroot_fixture(data_member: &str, bad_hash: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let libc = deb_with(
        &[
            ("usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1", b"LOADER"),
            ("usr/lib/aarch64-linux-gnu/libc.so.6", b"LIBC"),
            ("usr/share/doc/libc6/copyright", b"docs"),
            ("usr/bin/ldd", b"script"),
            ("etc/ld.so.conf", b"conf"),
        ],
        &[(
            "usr/lib/ld-linux-aarch64.so.1",
            "aarch64-linux-gnu/ld-linux-aarch64.so.1",
        )],
        data_member,
    );
    let gcc = deb_with(
        &[("usr/lib/aarch64-linux-gnu/libgcc_s.so.1", b"GCC")],
        &[],
        data_member,
    );
    let user = dir.path().join("emulators.d");
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(user.join("s.toml"), sysroot_manifest(&libc, &gcc, bad_hash)).unwrap();
    let mut files = HashMap::new();
    files.insert("https://example.test/libc6.deb".to_string(), libc);
    files.insert("https://example.test/libgcc-s1.deb".to_string(), gcc);
    let root = dir.path().join("data/integrations");
    let catalogue = Integrations::new(root.clone(), Some(user), Arc::new(Canned(files)));
    Fixture {
        _dir: dir,
        root,
        catalogue,
    }
}

fn view(c: &Integrations, id: &str) -> IntegrationView {
    c.list().unwrap().into_iter().find(|v| v.id == id).unwrap()
}

#[test]
fn the_shipped_catalogue_has_the_sysroots_and_the_toolchain() {
    let entries = manifest::parse(manifest::CATALOGUE).unwrap();
    for (id, set) in [
        ("sysroot-aarch64", "aarch64"),
        ("sysroot-armhf", "arm32"),
        ("sysroot-riscv64", "riscv64"),
        ("sysroot-i386", "elf32"),
        ("sysroot-x86-64", "x86_64"),
    ] {
        let e = entries.iter().find(|e| e.id == id).unwrap();
        assert_eq!(e.kind, "sysroot");
        assert_eq!(e.sysroot.as_ref().unwrap().set, set);
        let names: Vec<&str> = e
            .artifact
            .iter()
            .map(|a| a.url.rsplit('/').next().unwrap().split('_').next().unwrap())
            .collect();
        assert_eq!(names, ["libc6", "libgcc-s1", "libstdc++6"], "{id}");
        assert!(e.artifact.iter().all(|a| {
            a.url
                .starts_with("https://deb.debian.org/debian/pool/main/")
        }));
    }
    assert!(!entries.iter().any(|e| e.id.contains("riscv32")));
    let t = entries.iter().find(|e| e.id == "rust-toolchain").unwrap();
    assert_eq!(t.kind, "toolchain");
    assert_eq!(t.detect.names, ["cargo"]);
    assert!(
        t.toolchain
            .as_ref()
            .unwrap()
            .targets
            .iter()
            .all(|x| x.ends_with("-musl"))
    );
}

#[tokio::test]
async fn a_sysroot_is_unpacked_in_the_emulator_layout_and_removed() {
    let f = sysroot_fixture("data.tar.xz", false);
    let before = view(&f.catalogue, "sysroot-toy");
    assert_eq!(before.status, IntegrationStatus::NotInstalled);
    assert_eq!(before.kind, "sysroot");
    assert_eq!(before.pinned_version.as_deref(), Some("d13-1"));
    assert!(before.download_bytes > 0);
    let v = f.catalogue.install("sysroot-toy", true).await.unwrap();
    assert_eq!(v.status, IntegrationStatus::Ready);
    assert_eq!(v.source, Some(IntegrationSource::Downloaded));
    let root = f.root.join("sysroot-toy/d13-1");
    let lib = root.join("usr/lib/aarch64-linux-gnu");
    assert_eq!(std::fs::read(lib.join("libc.so.6")).unwrap(), b"LIBC");
    assert_eq!(std::fs::read(lib.join("libgcc_s.so.1")).unwrap(), b"GCC");
    // lib is a link to usr/lib, the loader is reachable at its absolute path and the packages'
    // documentation, binaries and configuration are gone.
    assert!(root.join("lib").is_dir());
    assert_eq!(
        std::fs::read(root.join("lib/ld-linux-aarch64.so.1")).unwrap(),
        b"LOADER"
    );
    assert!(!root.join("usr/share").exists());
    assert!(!root.join("usr/bin").exists());
    assert!(!root.join("etc").exists());
    // The downloads are deleted once installed.
    assert!(!f.root.join("downloads/libc6.deb").exists());
    f.catalogue.remove("sysroot-toy").unwrap();
    assert!(!f.root.join("sysroot-toy").exists());
    assert_eq!(
        view(&f.catalogue, "sysroot-toy").status,
        IntegrationStatus::NotInstalled
    );
}

#[tokio::test]
async fn a_sysroot_with_a_wrong_hash_or_an_unsupported_package_installs_nothing() {
    let f = sysroot_fixture("data.tar.xz", true);
    let err = f.catalogue.install("sysroot-toy", true).await.unwrap_err();
    assert!(err.message.contains("sha256"), "{}", err.message);
    assert!(!f.root.join("sysroot-toy").exists());
    let z = sysroot_fixture("data.tar.zst", false);
    let err = z.catalogue.install("sysroot-toy", true).await.unwrap_err();
    assert!(err.message.contains("xz or gzip"), "{}", err.message);
    assert!(!z.root.join("sysroot-toy/d13-1").exists());
    assert_eq!(
        view(&z.catalogue, "sysroot-toy").status,
        IntegrationStatus::NotInstalled
    );
}

fn parse_text(t: &str) -> Result<(), String> {
    manifest::parse(t).map(|_| ()).map_err(|e| e.to_string())
}

#[test]
fn sysroot_and_toolchain_manifests_are_linted() {
    let base = |extra: &str| {
        format!(
            "schema = 1\n[[emulator]]\nid = \"t\"\nname = \"T\"\nsummary = \"s\"\nlicense = \"MIT\"\n{extra}"
        )
    };
    let art = "[[emulator.artifact]]\nversion=\"1\"\nurl=\"https://x/y.deb\"\nsha256=\"0000000000000000000000000000000000000000000000000000000000000000\"\nsize=1\nformat=\"deb\"\n";
    for (extra, needle) in [
        ("kind = \"sysroot\"\n".to_string(), "sysroot"),
        (
            format!(
                "kind = \"sysroot\"\n[emulator.sysroot]\nset = \"mips\"\nloader = \"lib/ld.so\"\n{art}"
            ),
            "sysroot.set",
        ),
        (
            format!(
                "kind = \"sysroot\"\n[emulator.sysroot]\nset = \"aarch64\"\nloader = \"../ld.so\"\n{art}"
            ),
            "loader",
        ),
        ("kind = \"toolchain\"\n".to_string(), "toolchain"),
        (
            format!("[emulator.run]\nargv = [\"{{exe}}\"]\n{art}"),
            "deb artifacts",
        ),
    ] {
        let err = parse_text(&base(&extra)).unwrap_err();
        assert!(err.contains(needle), "{err} should mention {needle}");
    }
    let ok = base(&format!(
        "kind = \"sysroot\"\n[emulator.sysroot]\nset = \"aarch64\"\nloader = \"lib/ld.so\"\n{art}"
    ));
    assert!(parse_text(&ok).is_ok());
}

/// A stand-in for `rustup-init` that records how it was run and makes the files a real one
/// would.
const FAKE_RUSTUP: &[u8] = b"#!/bin/sh\n\
echo \"$@\" > \"$CARGO_HOME.args\"\n\
echo \"$RUSTUP_HOME|$CARGO_HOME|$RUSTUP_INIT_SKIP_PATH_CHECK\" > \"$CARGO_HOME.env\"\n\
mkdir -p \"$CARGO_HOME/bin\" \"$RUSTUP_HOME/toolchains/1.2.3-x86_64-unknown-linux-gnu/bin\"\n\
printf '#!/bin/sh\\necho cargo 1.2.3\\n' > \"$CARGO_HOME/bin/cargo\"\n\
chmod +x \"$CARGO_HOME/bin/cargo\"\n";

fn toolchain_fixture(rustup: &[u8]) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let user = dir.path().join("emulators.d");
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(
        user.join("rust.toml"),
        format!(
            r#"schema = 1
[[emulator]]
id = "rust-toy"
name = "Rust"
kind = "toolchain"
summary = "s"
license = "MIT"
[emulator.detect]
names = ["cargo"]
[emulator.toolchain]
channel = "1.2.3"
targets = ["x86_64-unknown-linux-musl"]
[[emulator.artifact]]
version = "rustup-9"
url = "https://example.test/rustup-init"
sha256 = "{}"
size = {}
format = "file"
entry = "rustup-init"
"#,
            sha(rustup),
            rustup.len()
        ),
    )
    .unwrap();
    let mut files = HashMap::new();
    files.insert(
        "https://example.test/rustup-init".to_string(),
        rustup.to_vec(),
    );
    let root = dir.path().join("data/integrations");
    let catalogue = Integrations::new(root.clone(), Some(user), Arc::new(Canned(files)));
    Fixture {
        _dir: dir,
        root,
        catalogue,
    }
}

#[tokio::test]
async fn the_toolchain_is_installed_by_rustup_inside_the_data_directory() {
    let f = toolchain_fixture(FAKE_RUSTUP);
    assert_eq!(
        view(&f.catalogue, "rust-toy").status,
        IntegrationStatus::NotInstalled
    );
    let v = f.catalogue.install("rust-toy", true).await.unwrap();
    assert_eq!(v.status, IntegrationStatus::Ready);
    assert_eq!(v.source, Some(IntegrationSource::Downloaded));
    let dir = f.root.join("rust-toy/rustup-9");
    assert_eq!(v.path.as_deref(), dir.join("cargo/bin/cargo").to_str());
    assert!(
        dir.join("rustup/toolchains/1.2.3-x86_64-unknown-linux-gnu/bin")
            .is_dir()
    );
    // The installer is gone; it ran with the pinned toolchain, the musl target and homes inside
    // the install directory (the person's ~/.cargo and ~/.rustup are never named).
    assert!(!dir.join("rustup-init").exists());
    let args = std::fs::read_to_string(dir.join("cargo.args")).unwrap();
    for want in [
        "-y",
        "--no-modify-path",
        "--default-toolchain 1.2.3",
        "-t x86_64-unknown-linux-musl",
    ] {
        assert!(args.contains(want), "{args} should contain {want}");
    }
    let env = std::fs::read_to_string(dir.join("cargo.env")).unwrap();
    let parts: Vec<&str> = env.trim().split('|').collect();
    assert!(
        parts[0].contains("rust-toy/rustup-9.partial/rustup"),
        "{env}"
    );
    assert!(
        parts[1].contains("rust-toy/rustup-9.partial/cargo"),
        "{env}"
    );
    assert_eq!(parts[2], "yes");
    f.catalogue.remove("rust-toy").unwrap();
    assert!(!f.root.join("rust-toy").exists());
}

#[tokio::test]
async fn a_failing_rustup_leaves_nothing_behind() {
    let f = toolchain_fixture(b"#!/bin/sh\necho 'no network' >&2\nexit 3\n");
    let err = f.catalogue.install("rust-toy", true).await.unwrap_err();
    assert!(
        err.message.contains("rustup-init failed"),
        "{}",
        err.message
    );
    assert!(err.message.contains("no network"), "{}", err.message);
    assert!(!f.root.join("rust-toy/rustup-9").exists());
    assert!(!f.root.join("rust-toy/rustup-9.partial").exists());
    assert_eq!(
        view(&f.catalogue, "rust-toy").status,
        IntegrationStatus::NotInstalled
    );
}

#[test]
fn a_cargo_on_path_is_used_before_anything_is_installed() {
    let f = toolchain_fixture(FAKE_RUSTUP);
    let bin = f._dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let c = Integrations::new(
        f.root.clone(),
        Some(f._dir.path().join("emulators.d")),
        Arc::new(Canned(HashMap::new())),
    )
    .with_search(bin.clone().into_os_string(), None);
    assert_eq!(view(&c, "rust-toy").status, IntegrationStatus::NotInstalled);
    let cargo = bin.join("cargo");
    std::fs::write(&cargo, b"#!/bin/sh\necho cargo 9\n").unwrap();
    make_executable(&cargo);
    let v = view(&c, "rust-toy");
    assert_eq!(v.status, IntegrationStatus::Ready);
    assert_eq!(v.source, Some(IntegrationSource::System));
    assert_eq!(v.path.as_deref(), cargo.to_str());
}

/// Downloads the real Debian packages and unpacks them. Needs the network:
/// `cargo test -p kraken-host real_debian -- --ignored`.
#[tokio::test]
#[ignore = "downloads about 20 MB from deb.debian.org"]
async fn real_debian_sysroots_install_for_every_architecture() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("integrations");
    let c = Integrations::new(root.clone(), None, Arc::new(HttpsFetcher::new().unwrap()));
    for (id, loader) in [
        (
            "sysroot-aarch64",
            "usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
        ),
        (
            "sysroot-armhf",
            "usr/lib/arm-linux-gnueabihf/ld-linux-armhf.so.3",
        ),
        (
            "sysroot-riscv64",
            "usr/lib/riscv64-linux-gnu/ld-linux-riscv64-lp64d.so.1",
        ),
        ("sysroot-i386", "usr/lib/i386-linux-gnu/ld-linux.so.2"),
        (
            "sysroot-x86-64",
            "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ),
    ] {
        let v = c
            .install(id, true)
            .await
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(v.status, IntegrationStatus::Ready, "{id}");
        let version = v.version.unwrap();
        let sys = root.join(id).join(&version);
        assert!(sys.join(loader).is_file(), "{id}: {loader}");
        assert!(sys.join("lib").is_dir(), "{id}");
        let libs = std::fs::read_dir(sys.join(loader).parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        for want in ["libc.so.6", "libgcc_s.so.1", "libstdc++.so.6"] {
            assert!(libs.iter().any(|l| l == want), "{id}: {want} in {libs:?}");
        }
    }
}

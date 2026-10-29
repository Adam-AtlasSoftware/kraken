//! Provisioning tests: small local fixture archives and an in-memory fetcher, no network.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use super::*;

fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn zip_bytes(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, data, mode) in entries {
            let opts = zip::write::SimpleFileOptions::default().unix_permissions(*mode);
            w.start_file(*name, opts).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

/// A tar entry written without the checks of `Header::set_path`.
fn raw_tar_entry(b: &mut tar::Builder<Vec<u8>>, name: &str, kind: tar::EntryType, link: &str) {
    let mut h = tar::Header::new_gnu();
    {
        let old = h.as_old_mut();
        old.name[..name.len()].copy_from_slice(name.as_bytes());
        old.linkname[..link.len()].copy_from_slice(link.as_bytes());
    }
    h.set_entry_type(kind);
    h.set_size(0);
    h.set_mode(0o644);
    h.set_cksum();
    b.append(&h, std::io::empty()).unwrap();
}

fn tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    let tar_bytes = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn tar_file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8], mode: u32) {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    h.set_cksum();
    b.append_data(&mut h, name, data).unwrap();
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    p
}

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-prov")
        .tempdir()
        .unwrap()
}

// ---- fetching ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MemFetcher {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    calls: Arc<Mutex<Vec<(String, u64)>>>,
    honour_range: bool,
    cut_body_at: Option<usize>,
    always_416: bool,
}

impl MemFetcher {
    fn new(honour_range: bool) -> Self {
        MemFetcher {
            honour_range,
            ..Default::default()
        }
    }

    fn with(self, url: &str, bytes: Vec<u8>) -> Self {
        self.files.lock().unwrap().insert(url.to_string(), bytes);
        self
    }
}

struct MemBody(Vec<Vec<u8>>);

#[async_trait]
impl Body for MemBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        Ok(if self.0.is_empty() {
            None
        } else {
            Some(self.0.remove(0))
        })
    }
}

#[async_trait]
impl Fetcher for MemFetcher {
    async fn fetch(&self, url: &str, from: u64) -> Result<Fetched, ProvisionError> {
        require_https(url)?;
        self.calls.lock().unwrap().push((url.to_string(), from));
        if self.always_416 && from > 0 {
            return Err(ProvisionError::RangeNotSatisfiable);
        }
        let all = self
            .files
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| ProvisionError::Http {
                url: url.into(),
                message: "HTTP 404".into(),
            })?;
        let total = all.len() as u64;
        if from > total {
            return Err(ProvisionError::RangeNotSatisfiable);
        }
        let resumed = self.honour_range && from > 0;
        let mut body = if resumed {
            all[from as usize..].to_vec()
        } else {
            all
        };
        if let Some(cut) = self.cut_body_at {
            body.truncate(cut);
        }
        let chunks = body.chunks(5).map(<[u8]>::to_vec).collect();
        Ok(Fetched {
            resumed,
            total: Some(total),
            body: Box::new(MemBody(chunks)),
        })
    }
}

fn spec_for(bytes: &[u8], format: ArchiveFormat, url: &str) -> ArtifactSpec {
    ArtifactSpec {
        name: "thing".into(),
        file_name: "thing.bin".into(),
        url: url.into(),
        sha256: sha_hex(bytes),
        format,
        top_dir: "top".into(),
    }
}

const URL: &str = "https://example.invalid/thing.bin";

fn sink() -> impl FnMut(Progress) + Send {
    |_| {}
}

#[test]
fn only_https_is_allowed() {
    assert!(require_https("https://example.com/x").is_ok());
    for bad in [
        "http://example.com/x",
        "file:///etc/passwd",
        "ftp://x/y",
        "https://",
        "",
    ] {
        assert!(
            matches!(require_https(bad), Err(ProvisionError::NotHttps(_))),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn download_rejects_plain_http_before_fetching() {
    let t = tmp();
    let f = MemFetcher::new(true);
    let mut spec = spec_for(b"x", ArchiveFormat::Zip, "http://example.invalid/x");
    spec.url = "http://example.invalid/x".into();
    let err = download(&f, &spec, t.path(), &mut sink())
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::NotHttps(_)));
    assert!(f.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn download_verifies_and_moves_into_place() {
    let t = tmp();
    let data = b"0123456789abcdefghij".to_vec();
    let f = MemFetcher::new(true).with(URL, data.clone());
    let spec = spec_for(&data, ArchiveFormat::Zip, URL);
    let mut seen = Vec::new();
    let path = download(&f, &spec, t.path(), &mut |p| seen.push(p))
        .await
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), data);
    assert!(!t.path().join("thing.bin.part").exists());
    assert!(seen.iter().any(|p| matches!(p, Progress::Verifying { .. })));
    assert!(seen.iter().any(|p| matches!(
        p,
        Progress::Downloading {
            done: 20,
            total: Some(20),
            ..
        }
    )));
    // A second call reuses the verified file without fetching.
    let before = f.calls.lock().unwrap().len();
    download(&f, &spec, t.path(), &mut sink()).await.unwrap();
    assert_eq!(f.calls.lock().unwrap().len(), before);
}

#[tokio::test]
async fn sha256_mismatch_is_rejected_and_discarded() {
    let t = tmp();
    let f = MemFetcher::new(true).with(URL, b"tampered bytes".to_vec());
    let spec = spec_for(b"the pinned bytes", ArchiveFormat::Zip, URL);
    let err = download(&f, &spec, t.path(), &mut sink())
        .await
        .unwrap_err();
    match err {
        ProvisionError::Sha256Mismatch {
            expected, actual, ..
        } => {
            assert_eq!(expected, spec.sha256);
            assert_eq!(actual, sha_hex(b"tampered bytes"));
        }
        other => panic!("{other}"),
    }
    assert!(!t.path().join("thing.bin").exists());
    assert!(!t.path().join("thing.bin.part").exists());
}

#[tokio::test]
async fn a_partial_download_is_resumed_with_a_range_request() {
    let t = tmp();
    let data: Vec<u8> = (0..100u8).collect();
    fs::write(t.path().join("thing.bin.part"), &data[..37]).unwrap();
    let f = MemFetcher::new(true).with(URL, data.clone());
    let spec = spec_for(&data, ArchiveFormat::Zip, URL);
    let mut resumed_from = None;
    let path = download(&f, &spec, t.path(), &mut |p| {
        if let Progress::Downloading {
            resumed_from: r, ..
        } = p
        {
            resumed_from = Some(r);
        }
    })
    .await
    .unwrap();
    assert_eq!(fs::read(path).unwrap(), data);
    assert_eq!(f.calls.lock().unwrap().as_slice(), &[(URL.to_string(), 37)]);
    assert_eq!(resumed_from, Some(37));
}

#[tokio::test]
async fn a_server_that_ignores_ranges_restarts_the_download() {
    let t = tmp();
    let data: Vec<u8> = (0..60u8).collect();
    fs::write(
        t.path().join("thing.bin.part"),
        b"stale prefix that is wrong",
    )
    .unwrap();
    let f = MemFetcher::new(false).with(URL, data.clone());
    let spec = spec_for(&data, ArchiveFormat::Zip, URL);
    let path = download(&f, &spec, t.path(), &mut sink()).await.unwrap();
    assert_eq!(fs::read(path).unwrap(), data);
}

#[tokio::test]
async fn an_unsatisfiable_range_discards_the_partial_file_once() {
    let t = tmp();
    let data: Vec<u8> = (0..30u8).collect();
    fs::write(t.path().join("thing.bin.part"), vec![9u8; 50]).unwrap();
    let f = MemFetcher::new(true).with(URL, data.clone());
    let spec = spec_for(&data, ArchiveFormat::Zip, URL);
    let path = download(&f, &spec, t.path(), &mut sink()).await.unwrap();
    assert_eq!(fs::read(path).unwrap(), data);
    let calls = f.calls.lock().unwrap().clone();
    assert_eq!(calls, vec![(URL.to_string(), 50), (URL.to_string(), 0)]);
}

#[tokio::test]
async fn a_cut_connection_keeps_the_partial_file_for_the_next_run() {
    let t = tmp();
    let data: Vec<u8> = (0..40u8).collect();
    let mut f = MemFetcher::new(true).with(URL, data.clone());
    f.cut_body_at = Some(15);
    let spec = spec_for(&data, ArchiveFormat::Zip, URL);
    let err = download(&f, &spec, t.path(), &mut sink())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        ProvisionError::Truncated {
            got: 15,
            expected: 40,
            ..
        }
    ));
    assert_eq!(
        fs::metadata(t.path().join("thing.bin.part")).unwrap().len(),
        15
    );
    f.cut_body_at = None;
    let path = download(&f, &spec, t.path(), &mut sink()).await.unwrap();
    assert_eq!(fs::read(path).unwrap(), data);
}

// ---- extraction -------------------------------------------------------------------------

#[test]
fn zip_extracts_files_and_keeps_the_exec_bit() {
    let t = tmp();
    let z = zip_bytes(&[
        ("top/readme.txt", b"hello", 0o666),
        ("top/bin/run", b"#!/bin/sh\n", 0o777),
    ]);
    let a = write(t.path(), "a.zip", &z);
    let dest = t.path().join("out");
    extract_zip(&a, &dest).unwrap();
    assert_eq!(fs::read(dest.join("top/readme.txt")).unwrap(), b"hello");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = |p: &str| fs::metadata(dest.join(p)).unwrap().permissions().mode() & 0o777;
        assert_eq!(m("top/bin/run") & 0o111, 0o111, "exec bit kept");
        assert_eq!(m("top/readme.txt") & 0o022, 0, "no group/other write");
    }
}

#[test]
fn dos_times_convert_to_unix_seconds() {
    assert_eq!(dos_to_unix_secs(2026, 9, 21, 16, 40, 14), 1_790_008_814);
    assert_eq!(dos_to_unix_secs(1980, 1, 1, 0, 0, 0), 315_532_800);
    assert_eq!(dos_to_unix_secs(2020, 2, 29, 23, 59, 58), 1_583_020_798);
}

/// A `.sla` newer than its sources must stay newer after extraction, or Ghidra tries to
/// recompile it inside the read-only install.
#[test]
fn zip_extraction_keeps_modification_times() {
    let t = tmp();
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, (y, mo, d, h, mi, s)) in [
            ("top/x.slaspec", (2026u16, 9u8, 21u8, 16u8, 37u8, 28u8)),
            ("top/x.sla", (2026, 9, 21, 16, 40, 14)),
        ] {
            let opts = zip::write::SimpleFileOptions::default()
                .last_modified_time(zip::DateTime::from_date_and_time(y, mo, d, h, mi, s).unwrap());
            w.start_file(name, opts).unwrap();
            w.write_all(b"data").unwrap();
        }
        w.finish().unwrap();
    }
    let a = write(t.path(), "a.zip", &buf.into_inner());
    let dest = t.path().join("out");
    extract_zip(&a, &dest).unwrap();
    let mtime = |p: &str| fs::metadata(dest.join(p)).unwrap().modified().unwrap();
    assert!(mtime("top/x.sla") > mtime("top/x.slaspec"));
    let secs = mtime("top/x.sla")
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(secs, 1_790_008_814);
}

#[test]
fn tar_extraction_keeps_modification_times() {
    let t = tmp();
    let gz = tar_gz(|b| {
        let mut h = tar::Header::new_gnu();
        h.set_size(1);
        h.set_mode(0o644);
        h.set_mtime(1_600_000_000);
        h.set_cksum();
        b.append_data(&mut h, "top/f", &b"x"[..]).unwrap();
    });
    let a = write(t.path(), "a.tar.gz", &gz);
    let dest = t.path().join("out");
    extract_tar_gz(&a, &dest).unwrap();
    let secs = fs::metadata(dest.join("top/f"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(secs, 1_600_000_000);
}

#[test]
fn zip_slip_entries_are_rejected() {
    for evil in ["../evil.txt", "top/../../evil.txt", "/etc/evil.txt"] {
        let t = tmp();
        let z = zip_bytes(&[("top/ok.txt", b"fine", 0o644), (evil, b"pwned", 0o644)]);
        let a = write(t.path(), "a.zip", &z);
        let dest = t.path().join("out");
        let err = extract_zip(&a, &dest).unwrap_err();
        assert!(
            matches!(err, ProvisionError::UnsafePath(_)),
            "{evil}: {err}"
        );
        assert!(!t.path().join("evil.txt").exists(), "{evil}");
    }
}

#[test]
fn tar_extracts_files_symlinks_and_keeps_the_exec_bit() {
    let t = tmp();
    let gz = tar_gz(|b| {
        tar_file(b, "top/bin/java", b"#!/bin/sh\n", 0o755);
        tar_file(b, "top/lib/data.txt", b"data", 0o644);
        raw_tar_entry(b, "top/bin/alias", tar::EntryType::Symlink, "java");
        raw_tar_entry(b, "top/lib/up", tar::EntryType::Symlink, "../bin/java");
    });
    let a = write(t.path(), "a.tar.gz", &gz);
    let dest = t.path().join("out");
    extract_tar_gz(&a, &dest).unwrap();
    assert_eq!(fs::read(dest.join("top/lib/data.txt")).unwrap(), b"data");
    assert!(
        fs::symlink_metadata(dest.join("top/bin/alias"))
            .unwrap()
            .is_symlink()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dest.join("top/bin/java"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
}

#[test]
fn tar_path_traversal_and_escaping_links_are_rejected() {
    type Case = (&'static str, Box<dyn Fn(&mut tar::Builder<Vec<u8>>)>);
    let cases: Vec<Case> = vec![
        (
            "dotdot",
            Box::new(|b| raw_tar_entry(b, "../evil.txt", tar::EntryType::Regular, "")),
        ),
        (
            "nested dotdot",
            Box::new(|b| raw_tar_entry(b, "top/../../evil.txt", tar::EntryType::Regular, "")),
        ),
        (
            "absolute",
            Box::new(|b| raw_tar_entry(b, "/tmp/evil.txt", tar::EntryType::Regular, "")),
        ),
        (
            "absolute symlink",
            Box::new(|b| raw_tar_entry(b, "top/link", tar::EntryType::Symlink, "/etc")),
        ),
        (
            "escaping symlink",
            Box::new(|b| raw_tar_entry(b, "top/link", tar::EntryType::Symlink, "../../outside")),
        ),
        (
            "escaping hardlink",
            Box::new(|b| raw_tar_entry(b, "top/h", tar::EntryType::Link, "../../etc/passwd")),
        ),
        (
            "device",
            Box::new(|b| raw_tar_entry(b, "top/dev", tar::EntryType::Char, "")),
        ),
    ];
    for (label, build) in cases {
        let t = tmp();
        let gz = tar_gz(|b| {
            tar_file(b, "top/ok.txt", b"fine", 0o644);
            build(b);
        });
        let a = write(t.path(), "a.tar.gz", &gz);
        let dest = t.path().join("out");
        let err = extract_tar_gz(&a, &dest).expect_err(label);
        assert!(
            matches!(
                err,
                ProvisionError::UnsafePath(_) | ProvisionError::BadArchive(_)
            ),
            "{label}: {err}"
        );
        assert!(!t.path().join("evil.txt").exists(), "{label}");
        assert!(!Path::new("/tmp/evil.txt").exists(), "{label}");
    }
}

#[test]
fn link_checks_are_lexical_and_depth_aware() {
    assert!(link_stays_inside(Path::new("a/b"), Path::new("../c")));
    assert!(link_stays_inside(Path::new("a/b"), Path::new("../../c")));
    assert!(!link_stays_inside(
        Path::new("a/b"),
        Path::new("../../../c")
    ));
    assert!(!link_stays_inside(Path::new(""), Path::new("..")));
    assert!(!link_stays_inside(Path::new("a"), Path::new("/abs")));
    assert!(link_stays_inside(Path::new("a"), Path::new("b/./c")));
}

// ---- setup end to end -------------------------------------------------------------------

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn fixture_specs() -> (ArtifactSpec, ArtifactSpec, MemFetcher) {
    let ghidra_zip = zip_bytes(&[
        (
            "ghidra_12.2_PUBLIC/Ghidra/application.properties",
            b"application.version=12.2\n",
            0o644,
        ),
        (
            "ghidra_12.2_PUBLIC/Ghidra/Framework/Utility/lib/Utility.jar",
            b"not really a jar",
            0o644,
        ),
    ]);
    let jdk = tar_gz(|b| {
        tar_file(b, "jdk-25.0.5+8/bin/java", b"#!/bin/sh\nexit 0\n", 0o755);
        // The fake javac reads the `-d` option from the argument file and "compiles" one class.
        tar_file(
            b,
            "jdk-25.0.5+8/bin/javac",
            b"#!/bin/sh\nf=\"${1#@}\"\nd=$(awk '/^-d$/ {getline; gsub(/\"/, \"\"); print; exit}' \"$f\")\nmkdir -p \"$d/kraken/ghidra\" && echo class > \"$d/kraken/ghidra/X.class\"\n",
            0o755,
        );
        tar_file(
            b,
            "jdk-25.0.5+8/bin/jar",
            b"#!/bin/sh\necho jar > \"$3\"\n",
            0o755,
        );
    });
    let (mut g, mut j) = pinned().unwrap();
    g.url = "https://example.invalid/ghidra.zip".into();
    g.sha256 = sha_hex(&ghidra_zip);
    j.url = "https://example.invalid/jdk.tar.gz".into();
    j.sha256 = sha_hex(&jdk);
    let f = MemFetcher::new(true)
        .with(&g.url, ghidra_zip)
        .with(&j.url, jdk);
    (g, j, f)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn setup_installs_both_archives_and_builds_the_extension() {
    let t = tmp();
    let layout = Layout::at(t.path().join("runtime"));
    let (g, j, f) = fixture_specs();
    assert_eq!(layout.provisioned(), Provisioned::default());
    let mut steps = Vec::new();
    let p = setup(&layout, &f, &(g, j), &SetupOptions::default(), &mut |s| {
        steps.push(s)
    })
    .await
    .unwrap();
    assert!(p.is_complete(), "{p:?}");
    assert_eq!(
        fs::read_to_string(p.ext_jar.unwrap()).unwrap().trim(),
        "jar"
    );
    assert!(steps.contains(&Progress::BuildingExtension));
    assert!(!layout.root().join(".ext-build").exists());
    assert!(
        fs::read_dir(layout.root())
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with(".staging")),
        "staging directories are cleaned up"
    );

    // A second run skips everything.
    let (g, j, f2) = fixture_specs();
    let mut again = Vec::new();
    setup(&layout, &f2, &(g, j), &SetupOptions::default(), &mut |s| {
        again.push(s)
    })
    .await
    .unwrap();
    assert!(f2.calls.lock().unwrap().is_empty());
    assert!(!again.contains(&Progress::BuildingExtension));
    assert_eq!(
        again
            .iter()
            .filter(|s| matches!(s, Progress::Skipped { .. }))
            .count(),
        2
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn a_bad_hash_stops_setup_before_anything_is_extracted() {
    let t = tmp();
    let layout = Layout::at(t.path().join("runtime"));
    let (mut g, j, f) = fixture_specs();
    g.sha256 = sha_hex(b"something else");
    let err = setup(&layout, &f, &(g, j), &SetupOptions::default(), &mut sink())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ProvisionError::Sha256Mismatch { .. }),
        "{err}"
    );
    assert!(!layout.root().join("ghidra").exists());
    assert!(
        fs::read_dir(layout.root())
            .map(|rd| rd.flatten().all(|e| {
                let n = e.file_name().to_string_lossy().into_owned();
                !n.starts_with(".staging")
            }))
            .unwrap_or(true)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn an_archive_with_a_zip_slip_entry_fails_setup_cleanly() {
    let t = tmp();
    let layout = Layout::at(t.path().join("runtime"));
    let (mut g, j, f) = fixture_specs();
    let evil = zip_bytes(&[("../escape.txt", b"x", 0o644)]);
    g.sha256 = sha_hex(&evil);
    f.files.lock().unwrap().insert(g.url.clone(), evil);
    let err = setup(&layout, &f, &(g, j), &SetupOptions::default(), &mut sink())
        .await
        .unwrap_err();
    assert!(matches!(err, ProvisionError::UnsafePath(_)), "{err}");
    assert!(!layout.root().parent().unwrap().join("escape.txt").exists());
    assert!(!layout.root().join("escape.txt").exists());
}

// ---- constants and layout ---------------------------------------------------------------

#[test]
fn embedded_extension_sources_are_every_java_file() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../java/kraken-ghidra/src/main/java/kraken/ghidra");
    let mut on_disk: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".java"))
        .collect();
    on_disk.sort();
    let mut embedded: Vec<String> = EXT_SOURCES.iter().map(|(n, _)| n.to_string()).collect();
    embedded.sort();
    assert_eq!(embedded, on_disk, "add new Java files to EXT_SOURCES");
    for (name, text) in EXT_SOURCES {
        assert_eq!(fs::read_to_string(dir.join(name)).unwrap(), *text, "{name}");
    }
}

#[test]
fn pins_match_the_nightly_drift_workflow() {
    let wf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/drift.yml");
    let Ok(text) = fs::read_to_string(wf) else {
        return;
    };
    for pin in [GHIDRA_URL, GHIDRA_SHA256, JDK_URL, JDK_SHA256] {
        assert!(text.contains(pin), "drift.yml does not contain {pin}");
    }
    assert!(GHIDRA_URL.starts_with("https://") && JDK_URL.starts_with("https://"));
    assert_eq!(GHIDRA_SHA256.len(), 64);
    assert_eq!(JDK_SHA256.len(), 64);
}

/// An absolute path on every platform: `/x` on Unix, `C:\x` on Windows.
fn abs(rest: &str) -> PathBuf {
    let root = if cfg!(windows) { "C:\\" } else { "/" };
    PathBuf::from(format!("{root}{rest}"))
}

#[test]
fn layout_follows_xdg_data_home() {
    let env_of = |pairs: Vec<(&'static str, OsString)>| {
        move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone())
    };
    let x = abs("x").into_os_string();
    let h = abs("h").into_os_string();
    let l = Layout::from_env_with(&env_of(vec![
        ("XDG_DATA_HOME", x.clone()),
        ("HOME", h.clone()),
    ]))
    .unwrap();
    assert_eq!(l.root(), abs("x").join("kraken").join("runtime"));
    let l = Layout::from_env_with(&env_of(vec![("HOME", h)])).unwrap();
    assert_eq!(
        l.root(),
        abs("h").join(".local/share").join("kraken").join("runtime")
    );
    assert!(Layout::from_env_with(&env_of(vec![])).is_none());
}

#[test]
fn javac_argument_file_quotes_paths_and_lists_sources() {
    let jar_ab = abs("a b").join("x.jar");
    let jar_c = abs("c.jar");
    let out_dir = abs("out dir");
    let src = abs("src").join("A.java");
    let args = javac_args(
        &[jar_ab.clone(), jar_c.clone()],
        &out_dir,
        std::slice::from_ref(&src),
    );
    // The file escapes backslashes and quotes, exactly as javac reads it.
    let q = |s: String| format!("\"{}\"", s.replace('\\', "\\\\"));
    let sep = if cfg!(windows) { ";" } else { ":" };
    let cp = format!("{}{sep}{}", jar_ab.display(), jar_c.display());
    assert!(args.contains("--release\n25\n"));
    assert!(args.contains(&q(cp)), "{args}");
    assert!(args.contains(&format!("-d\n{}\n", q(out_dir.display().to_string()))));
    assert!(args.trim_end().ends_with(&q(src.display().to_string())));
}

/// Compiles the real extension with a real JDK and Ghidra. Needs the dev environment:
/// `KRAKEN_JAVA_HOME` and `KRAKEN_GHIDRA_HOME`.
#[test]
#[ignore = "needs a JDK 25 and Ghidra 12.2 (scripts/dev-env.sh)"]
fn the_real_extension_compiles_with_javac() {
    let (Some(jdk), Some(ghidra)) = (
        std::env::var_os("KRAKEN_JAVA_HOME"),
        std::env::var_os("KRAKEN_GHIDRA_HOME"),
    ) else {
        panic!("set KRAKEN_JAVA_HOME and KRAKEN_GHIDRA_HOME");
    };
    let t = tmp();
    let jar = t.path().join("out/kraken-ghidra.jar");
    build_extension(
        Path::new(&jdk),
        Path::new(&ghidra),
        &t.path().join("work"),
        &jar,
    )
    .unwrap();
    assert!(fs::metadata(&jar).unwrap().len() > 10_000);
}

#[test]
fn bundled_jar_is_looked_up_next_to_the_exe_then_in_share() {
    let c = bundled_ext_jar_candidates(Path::new("/opt/kraken/bin/kraken"));
    assert_eq!(
        c,
        vec![
            PathBuf::from("/opt/kraken/bin/kraken-ghidra.jar"),
            PathBuf::from("/opt/kraken/share/kraken/kraken-ghidra.jar"),
        ]
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn a_bundled_jar_is_installed_instead_of_building() {
    let t = tmp();
    let layout = Layout::at(t.path().join("runtime"));
    let bundled = write(t.path(), "kraken-ghidra.jar", b"prebuilt");
    let (g, j, f) = fixture_specs();
    let opts = SetupOptions {
        force: false,
        bundled_jar: Some(bundled),
    };
    let mut steps = Vec::new();
    let p = setup(&layout, &f, &(g, j), &opts, &mut |s| steps.push(s))
        .await
        .unwrap();
    assert!(p.is_complete(), "{p:?}");
    assert_eq!(fs::read(p.ext_jar.unwrap()).unwrap(), b"prebuilt");
    assert!(steps.contains(&Progress::InstallingBundledExtension));
    assert!(!steps.contains(&Progress::BuildingExtension));
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
async fn a_missing_bundled_jar_falls_back_to_building() {
    let t = tmp();
    let layout = Layout::at(t.path().join("runtime"));
    let (g, j, f) = fixture_specs();
    let opts = SetupOptions {
        force: false,
        bundled_jar: Some(t.path().join("absent.jar")),
    };
    let mut steps = Vec::new();
    setup(&layout, &f, &(g, j), &opts, &mut |s| steps.push(s))
        .await
        .unwrap();
    assert!(steps.contains(&Progress::BuildingExtension));
}

#[cfg(unix)]
#[test]
fn tar_extraction_masks_group_and_other_write_bits() {
    use std::os::unix::fs::PermissionsExt;
    let t = tmp();
    let gz = tar_gz(|b| {
        tar_file(b, "top/open.txt", b"x", 0o666);
        tar_file(b, "top/bin/run", b"#!/bin/sh\n", 0o777);
    });
    let a = write(t.path(), "a.tar.gz", &gz);
    let dest = t.path().join("out");
    extract_tar_gz(&a, &dest).unwrap();
    let m = |p: &str| fs::metadata(dest.join(p)).unwrap().permissions().mode() & 0o777;
    assert_eq!(m("top/open.txt") & 0o022, 0);
    assert_eq!(m("top/bin/run") & 0o022, 0);
    assert_eq!(m("top/bin/run") & 0o111, 0o111, "exec bit kept");
}

#[test]
fn every_extension_source_is_embedded() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../java/kraken-ghidra/src/main/java/kraken/ghidra");
    let mut on_disk: Vec<String> = fs::read_dir(&dir)
        .expect("extension sources")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".java"))
        .collect();
    on_disk.sort();
    let mut embedded: Vec<String> = EXT_SOURCES.iter().map(|(n, _)| n.to_string()).collect();
    embedded.sort();
    assert_eq!(on_disk, embedded, "add new .java files to EXT_SOURCES");
}

#[test]
fn an_extension_without_this_builds_stamp_is_out_of_date() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let jar = tmp.path().join("kraken-ghidra.jar");
    fs::write(&jar, b"jar").expect("jar");
    assert!(!ext_is_current(&jar), "no stamp: built by an older KRAKEN");
    fs::write(jar.with_extension("jar.sources"), "0123").expect("stamp");
    assert!(!ext_is_current(&jar), "other sources");
    write_ext_stamp(&jar).expect("stamp");
    assert!(ext_is_current(&jar));
}

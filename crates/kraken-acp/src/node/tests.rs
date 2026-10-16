//! Node.js detection and provisioning tests: fake `node` scripts and local fixture archives.
//! No network.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use kraken_host::provision::{Body, Fetched};
use sha2::{Digest, Sha256};

use super::*;

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-acp-node")
        .tempdir()
        .expect("tempdir")
}

#[test]
fn parses_node_versions() {
    let v = |s: &str| NodeVersion::parse(s);
    assert_eq!(
        v("v24.21.0\n"),
        Some(NodeVersion {
            major: 24,
            minor: 21,
            patch: 0
        })
    );
    assert_eq!(v("22.1.3").map(|x| x.major), Some(22));
    assert_eq!(
        v("  v20.0.0-nightly20230101abc ").map(|x| x.major),
        Some(20)
    );
    assert_eq!(v("v18.19.1+build5").map(|x| x.patch), Some(1));
    assert_eq!(v(""), None);
    assert_eq!(v("node"), None);
    assert_eq!(v("v24.21"), None);
    assert_eq!(v("v1.2.3.4"), None);
    assert!(v("v24.21.0") > v("v24.9.9"));
    assert!(v("v22.0.0") < v("v22.0.1"));
    assert_eq!(v("v24.21.0").map(|x| x.to_string()), Some("24.21.0".into()));
}

#[test]
fn pinned_downloads_are_https_and_hashes_well_formed() {
    for dl in [NODE_LINUX_X64, NODE_DARWIN_ARM64, NODE_WIN_X64] {
        assert!(dl.url().starts_with("https://nodejs.org/dist/v"));
        assert!(dl.url().contains(NODE_VERSION));
        assert_eq!(dl.sha256.len(), 64);
        assert!(dl.sha256.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(dl.file_name.contains(NODE_VERSION));
        assert!(dl.top_dir().starts_with("node-v"));
    }
    assert!(node_download_for(&Platform::new("linux", "riscv64")).is_none());
}

#[cfg(unix)]
fn fake_node(dir: &Path, output: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = dir.join("node");
    fs::write(&p, format!("#!/bin/sh\necho '{output}'\n")).expect("write");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[cfg(unix)]
#[test]
fn detect_reads_the_version_from_a_node_on_path() {
    let d = tmp();
    fake_node(d.path(), "v24.21.0");
    let rt = NodeRuntime::detect_with(Some(d.path().as_os_str()), 22).expect("detected");
    assert_eq!(rt.version.major, 24);
    assert_eq!(rt.origin, NodeOrigin::System);
    assert_eq!(rt.node, d.path().join("node"));
}

#[cfg(unix)]
#[test]
fn detect_rejects_old_missing_and_garbled_node() {
    let old = tmp();
    fake_node(old.path(), "v20.11.1");
    match NodeRuntime::detect_with(Some(old.path().as_os_str()), 22) {
        Err(NodeError::TooOld { found, required }) => {
            assert_eq!(found.major, 20);
            assert_eq!(required, 22);
        }
        other => panic!("expected TooOld, got {other:?}"),
    }
    let empty = tmp();
    assert!(matches!(
        NodeRuntime::detect_with(Some(empty.path().as_os_str()), 22),
        Err(NodeError::NotFound)
    ));
    assert!(matches!(
        NodeRuntime::detect_with(None, 22),
        Err(NodeError::NotFound)
    ));
    let junk = tmp();
    fake_node(junk.path(), "not a version");
    assert!(matches!(
        NodeRuntime::detect_with(Some(junk.path().as_os_str()), 22),
        Err(NodeError::Version { .. })
    ));
}

// ---- provisioning -----------------------------------------------------------------------

fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

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
    b.append(&h, std::io::empty()).expect("append");
}

fn tar_file(b: &mut tar::Builder<Vec<u8>>, name: &str, data: &[u8], mode: u32, mtime: u64) {
    let mut h = tar::Header::new_gnu();
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    h.set_mtime(mtime);
    h.set_cksum();
    b.append_data(&mut h, name, data).expect("append");
}

fn tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    let tar_bytes = b.into_inner().expect("tar");
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&tar_bytes).expect("gz");
    gz.finish().expect("gz finish")
}

const TOP: &str = "node-v24.21.0-fixture";
const FIXTURE_MTIME: u64 = 1_700_000_000;

fn good_archive() -> Vec<u8> {
    tar_gz(|b| {
        tar_file(
            b,
            &format!("{TOP}/bin/node"),
            b"#!/bin/sh\necho v24.21.0\n",
            0o755,
            FIXTURE_MTIME,
        );
        tar_file(
            b,
            &format!("{TOP}/bin/npm"),
            b"#!/bin/sh\nexit 0\n",
            0o755,
            FIXTURE_MTIME,
        );
    })
}

fn spec_for(bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec {
        name: "node".into(),
        file_name: "node-fixture.tar.gz".into(),
        url: "https://example.invalid/node-fixture.tar.gz".into(),
        sha256: sha_hex(bytes),
        format: ArchiveFormat::TarGz,
        top_dir: TOP.into(),
    }
}

#[derive(Clone, Default)]
struct MemFetcher {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemFetcher {
    fn with(self, url: &str, bytes: Vec<u8>) -> Self {
        self.files
            .lock()
            .expect("lock")
            .insert(url.to_string(), bytes);
        self
    }
}

struct MemBody(Option<Vec<u8>>);

#[async_trait]
impl Body for MemBody {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        Ok(self.0.take())
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
            body: Box::new(MemBody(Some(bytes))),
        })
    }
}

#[cfg(unix)]
#[tokio::test]
async fn provision_verifies_extracts_and_keeps_mtimes() {
    let d = tmp();
    let paths = AgentPaths::in_data_dir(d.path());
    let bytes = good_archive();
    let spec = spec_for(&bytes);
    let fetcher = MemFetcher::default().with(&spec.url, bytes);
    let mut steps = Vec::new();
    let rt = provision_download(&paths, &spec, &fetcher, &mut |p| steps.push(p))
        .await
        .expect("provisioned");
    assert_eq!(rt.origin, NodeOrigin::Provisioned);
    assert_eq!(rt.version.major, 24);
    assert_eq!(rt.node, paths.node_dir().join(TOP).join("bin/node"));
    assert!(rt.npm.is_some());
    let mtime = fs::metadata(&rt.node)
        .and_then(|m| m.modified())
        .expect("mtime");
    let secs = mtime
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after epoch")
        .as_secs();
    assert_eq!(secs, FIXTURE_MTIME, "archive mtimes are preserved");
    assert!(
        steps
            .iter()
            .any(|p| matches!(p, kraken_host::provision::Progress::Verifying { .. }))
    );
    // The staging directory is gone.
    let leftovers: Vec<_> = fs::read_dir(paths.node_dir())
        .expect("node dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers, vec![TOP.to_string()]);
    // And the second lookup finds it without a platform download entry (resolve uses Platform).
    let again = NodeRuntime::from_binary(rt.node.clone(), None, NodeOrigin::Provisioned);
    assert!(again.is_ok());
}

#[tokio::test]
async fn hash_mismatch_extracts_nothing_and_discards_the_download() {
    let d = tmp();
    let paths = AgentPaths::in_data_dir(d.path());
    let bytes = good_archive();
    let mut spec = spec_for(&bytes);
    spec.sha256 = sha_hex(b"something else");
    let fetcher = MemFetcher::default().with(&spec.url, bytes);
    let err = provision_download(&paths, &spec, &fetcher, &mut |_| {})
        .await
        .expect_err("must fail");
    assert!(
        matches!(
            err,
            NodeError::Provision(ProvisionError::Sha256Mismatch { .. })
        ),
        "{err:?}"
    );
    assert!(!paths.node_dir().exists(), "nothing was extracted");
    assert!(
        !paths.downloads_dir().join("node-fixture.tar.gz").exists(),
        "the bad download was deleted"
    );
}

async fn slip_fails(spec_format: ArchiveFormat, bytes: Vec<u8>) {
    let d = tmp();
    let paths = AgentPaths::in_data_dir(d.path().join("data"));
    let mut spec = spec_for(&bytes);
    spec.format = spec_format;
    let fetcher = MemFetcher::default().with(&spec.url, bytes);
    let err = provision_download(&paths, &spec, &fetcher, &mut |_| {})
        .await
        .expect_err("must fail");
    assert!(
        matches!(
            err,
            NodeError::Provision(ProvisionError::UnsafePath(_) | ProvisionError::BadArchive(_))
        ),
        "{err:?}"
    );
    assert!(!d.path().join("evil.txt").exists());
    assert!(!d.path().join("data/evil.txt").exists());
    assert!(!d.path().join("data/agents/evil.txt").exists());
    assert!(
        !paths.node_dir().join(TOP).exists(),
        "a rejected archive is not installed"
    );
}

#[tokio::test]
async fn tar_zip_slip_is_rejected() {
    for evil in ["../evil.txt", "../../evil.txt", "/tmp/kraken-evil.txt"] {
        let bytes = tar_gz(|b| {
            tar_file(
                b,
                &format!("{TOP}/bin/node"),
                b"#!/bin/sh\n",
                0o755,
                FIXTURE_MTIME,
            );
            raw_tar_entry(b, evil, tar::EntryType::Regular, "");
        });
        slip_fails(ArchiveFormat::TarGz, bytes).await;
    }
    // A symlink that points out of the tree.
    let bytes = tar_gz(|b| {
        raw_tar_entry(
            b,
            &format!("{TOP}/bin/up"),
            tar::EntryType::Symlink,
            "../../../x",
        )
    });
    slip_fails(ArchiveFormat::TarGz, bytes).await;
}

#[tokio::test]
async fn zip_zip_slip_is_rejected() {
    for evil in ["../evil.txt", "node/../../evil.txt", "/tmp/kraken-evil.txt"] {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default().unix_permissions(0o755);
            w.start_file(format!("{TOP}/node.exe"), opts)
                .expect("start");
            w.write_all(b"MZ").expect("write");
            w.start_file(evil, opts).expect("start evil");
            w.write_all(b"pwned").expect("write evil");
            w.finish().expect("finish");
        }
        slip_fails(ArchiveFormat::Zip, buf.into_inner()).await;
    }
}

#[tokio::test]
async fn an_archive_without_the_expected_top_directory_is_refused() {
    let d = tmp();
    let paths = AgentPaths::in_data_dir(d.path());
    let bytes = tar_gz(|b| tar_file(b, "other/bin/node", b"x", 0o755, FIXTURE_MTIME));
    let spec = spec_for(&bytes);
    let fetcher = MemFetcher::default().with(&spec.url, bytes);
    let err = provision_download(&paths, &spec, &fetcher, &mut |_| {})
        .await
        .expect_err("must fail");
    assert!(matches!(err, NodeError::Incomplete(_)), "{err:?}");
    assert!(!paths.node_dir().join(TOP).exists());
}

/// Downloads the real pinned Node.js from nodejs.org (hash-checked) into a private directory.
/// Ignored by default: it needs the network.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
#[ignore = "downloads Node.js from nodejs.org"]
async fn real_download_matches_the_pinned_hash() {
    let d = tmp();
    let fetcher = kraken_host::provision::HttpsFetcher::new().expect("fetcher");
    let rt = NodeRuntime::provision(d.path(), &fetcher, &mut |_| {})
        .await
        .expect("provisioned");
    assert_eq!(rt.version.to_string(), NODE_VERSION);
    assert!(rt.npm.is_some());
}

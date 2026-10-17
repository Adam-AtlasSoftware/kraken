//! The .NET provisioning: verify-before-extract, idempotence and the bundled sidecar copy, with
//! fixture archives and an in-memory fetcher (no network).

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use super::*;
use crate::provision::{Body, Fetched, require_https};

fn sha_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn tar_gz(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data, mode) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(*mode);
        h.set_cksum();
        b.append_data(&mut h, name, *data).unwrap();
    }
    let raw = b.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&raw).unwrap();
    gz.finish().unwrap()
}

#[derive(Clone, Default)]
struct MemFetcher {
    files: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    fetched: Arc<Mutex<Vec<String>>>,
}

struct OneChunk(Option<Vec<u8>>);

#[async_trait]
impl Body for OneChunk {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        Ok(self.0.take())
    }
}

#[async_trait]
impl Fetcher for MemFetcher {
    async fn fetch(&self, url: &str, _from: u64) -> Result<Fetched, ProvisionError> {
        require_https(url)?;
        self.fetched.lock().unwrap().push(url.to_string());
        let data = self
            .files
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .ok_or_else(|| ProvisionError::Http {
                url: url.into(),
                message: "HTTP 404".into(),
            })?;
        Ok(Fetched {
            resumed: false,
            total: Some(data.len() as u64),
            body: Box::new(OneChunk(Some(data))),
        })
    }
}

fn spec_for(bytes: &[u8]) -> ArtifactSpec {
    ArtifactSpec {
        name: "dotnet".into(),
        file_name: "rt.tar.gz".into(),
        url: "https://example.invalid/rt.tar.gz".into(),
        sha256: sha_hex(bytes),
        format: ArchiveFormat::TarGz,
        top_dir: DOTNET_VERSION.into(),
    }
}

fn runtime_archive() -> Vec<u8> {
    tar_gz(&[
        ("./dotnet", b"#!host", 0o644),
        ("./LICENSE.txt", b"mit", 0o644),
        (
            "./shared/Microsoft.NETCore.App/10.0.13/System.Runtime.dll",
            b"dll",
            0o644,
        ),
    ])
}

fn fetcher_with(spec: &ArtifactSpec, bytes: Vec<u8>) -> MemFetcher {
    let f = MemFetcher::default();
    f.files.lock().unwrap().insert(spec.url.clone(), bytes);
    f
}

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-dotnet-setup")
        .tempdir()
        .unwrap()
}

fn bundled_dir(root: &Path) -> PathBuf {
    let d = root.join("bundle/kraken-dotnet");
    fs::create_dir_all(d.join("runtimes")).unwrap();
    fs::write(d.join(SIDECAR_DLL), b"sidecar").unwrap();
    fs::write(d.join("ICSharpCode.Decompiler.dll"), b"ilspy").unwrap();
    fs::write(d.join("runtimes/x.txt"), b"x").unwrap();
    d
}

fn noop(_: Progress) {}

#[test]
fn the_pin_is_well_formed() {
    assert!(DOTNET_URL.starts_with("https://builds.dotnet.microsoft.com/dotnet/Runtime/"));
    assert!(DOTNET_URL.contains(DOTNET_VERSION));
    assert_eq!(DOTNET_SHA256.len(), 64);
    assert_eq!(DOTNET_SHA512.len(), 128);
    assert!(DOTNET_SHA256.bytes().all(|b| b.is_ascii_hexdigit()));
    if let Ok(spec) = pinned_dotnet() {
        assert!(spec.url.ends_with(&spec.file_name));
        assert_eq!(spec.top_dir, DOTNET_VERSION);
    }
}

#[test]
fn bundled_sidecars_are_looked_up_next_to_the_binary_and_in_share() {
    let exe = Path::new("/opt/kraken/bin").join("kraken");
    let c = bundled_sidecar_candidates(&exe);
    assert_eq!(
        c,
        vec![
            Path::new("/opt/kraken/bin").join(SIDECAR_DIR),
            Path::new("/opt/kraken")
                .join("share/kraken")
                .join(SIDECAR_DIR),
        ]
    );
}

#[tokio::test]
async fn setup_installs_the_runtime_and_the_sidecar_and_is_idempotent() {
    let root = tmp();
    let layout = Layout::at(root.path().join("runtime"));
    let bytes = runtime_archive();
    let spec = spec_for(&bytes);
    let fetcher = fetcher_with(&spec, bytes);
    let bundled = bundled_dir(root.path());
    let mut steps = Vec::new();

    let done = setup_dotnet(&layout, &fetcher, &spec, Some(&bundled), false, &mut |p| {
        steps.push(p)
    })
    .await
    .unwrap();
    assert!(done.is_complete(), "{done:?}");
    let rt = done.dotnet_root.unwrap();
    assert!(rt.join("dotnet").is_file());
    assert!(
        rt.join("shared/Microsoft.NETCore.App/10.0.13/System.Runtime.dll")
            .is_file()
    );
    let dll = done.ext_dll.unwrap();
    assert_eq!(fs::read(&dll).unwrap(), b"sidecar");
    assert!(dll.with_file_name("runtimes/x.txt").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(rt.join("dotnet"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
        assert_eq!(mode & 0o022, 0);
    }
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, Progress::Verifying { .. }))
    );
    assert_eq!(fetcher.fetched.lock().unwrap().len(), 1);
    assert!(!layout.root().join(".staging-dotnet-0").exists());

    // A second run changes nothing and downloads nothing.
    let mut again = Vec::new();
    setup_dotnet(&layout, &fetcher, &spec, Some(&bundled), false, &mut |p| {
        again.push(p)
    })
    .await
    .unwrap();
    assert_eq!(fetcher.fetched.lock().unwrap().len(), 1);
    assert_eq!(
        again
            .iter()
            .filter(|s| matches!(s, Progress::Skipped { .. }))
            .count(),
        2
    );
}

#[tokio::test]
async fn a_hash_mismatch_extracts_nothing() {
    let root = tmp();
    let layout = Layout::at(root.path().join("runtime"));
    let bytes = runtime_archive();
    let mut spec = spec_for(&bytes);
    spec.sha256 = sha_hex(b"something else");
    let fetcher = fetcher_with(&spec, bytes);
    let bundled = bundled_dir(root.path());

    let e = setup_dotnet(&layout, &fetcher, &spec, Some(&bundled), false, &mut noop)
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::Sha256Mismatch { .. }), "{e}");
    let p = layout.dotnet_provisioned();
    assert_eq!(p, DotnetProvisioned::default());
    assert!(!layout.dotnet_dir().exists());
    let leftovers: Vec<_> = fs::read_dir(layout.root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".staging"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn an_archive_without_a_runtime_is_refused_and_cleaned_up() {
    let root = tmp();
    let layout = Layout::at(root.path().join("runtime"));
    let bytes = tar_gz(&[("./README", b"nothing", 0o644)]);
    let spec = spec_for(&bytes);
    let fetcher = fetcher_with(&spec, bytes);
    let bundled = bundled_dir(root.path());

    let e = setup_dotnet(&layout, &fetcher, &spec, Some(&bundled), false, &mut noop)
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::BadArchive(_)), "{e}");
    assert!(!layout.dotnet_dir().exists());
    assert!(!layout.dotnet_ext_dir().exists());
    let staging: Vec<_> = fs::read_dir(layout.root())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".staging"))
        .collect();
    assert!(staging.is_empty());
}

#[tokio::test]
async fn without_a_bundled_sidecar_nothing_is_downloaded() {
    let root = tmp();
    let layout = Layout::at(root.path().join("runtime"));
    let bytes = runtime_archive();
    let spec = spec_for(&bytes);
    let fetcher = fetcher_with(&spec, bytes);

    let e = setup_dotnet(&layout, &fetcher, &spec, None, false, &mut noop)
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::NoBuild(_)), "{e}");
    assert!(e.to_string().contains("dotnet-ext"));
    assert!(fetcher.fetched.lock().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn a_bundled_sidecar_with_a_symlink_is_refused() {
    let root = tmp();
    let bundled = bundled_dir(root.path());
    std::os::unix::fs::symlink("/etc/passwd", bundled.join("evil")).unwrap();
    let out = root.path().join("ext/kraken-dotnet");
    let e = install_bundled_sidecar(&bundled, &out).unwrap_err();
    assert!(matches!(e, ProvisionError::BadArchive(_)), "{e}");
    assert!(!out.exists());
    let parts: Vec<_> = fs::read_dir(root.path().join("ext"))
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert!(parts.is_empty());
}

#[test]
fn a_directory_without_the_sidecar_dll_is_not_installable() {
    let root = tmp();
    let e = install_bundled_sidecar(root.path(), &root.path().join("out")).unwrap_err();
    assert!(matches!(e, ProvisionError::BadArchive(_)));
}

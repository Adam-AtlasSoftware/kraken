//! Pinned-release table and the verify-before-extract install, with fixture archives and an
//! in-memory fetcher (no network).

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

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        for (name, data) in entries {
            w.start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    buf.into_inner()
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

fn release(format: ArchiveFormat, top: Option<&str>, bytes: &[u8]) -> LlamaRelease {
    let ext = if format == ArchiveFormat::Zip {
        "zip"
    } else {
        "tar.gz"
    };
    LlamaRelease {
        variant: "cpu".into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        tag: "b1".into(),
        file_name: format!("llama-b1.{ext}"),
        url: format!("https://example.invalid/llama-b1.{ext}"),
        sha256: sha_hex(bytes),
        size: bytes.len() as u64,
        format,
        top_dir: top.map(str::to_string),
        gpu_api: GpuApi::Cpu,
    }
}

fn tmp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-llama")
        .tempdir()
        .unwrap()
}

fn noop(_: Progress) {}

#[test]
fn the_pin_table_is_complete_and_well_formed() {
    let all = pinned_releases();
    assert_eq!(all.len(), 5);
    for r in &all {
        assert_eq!(r.tag, LLAMA_TAG);
        assert_eq!(r.sha256.len(), 64, "{}", r.file_name);
        assert!(
            r.sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert!(r.file_name.contains(LLAMA_TAG), "{}", r.file_name);
        assert_eq!(
            r.url,
            format!(
                "https://github.com/ggml-org/llama.cpp/releases/download/{LLAMA_TAG}/{}",
                r.file_name
            )
        );
        assert!(r.size > 1_000_000);
        require_https(&r.url).unwrap();
    }
    let ids = |os, arch| -> Vec<String> {
        releases_for(os, arch)
            .into_iter()
            .map(|r| r.variant)
            .collect()
    };
    assert_eq!(ids("linux", "x86_64"), ["cpu", "vulkan"]);
    assert_eq!(ids("windows", "x86_64"), ["cpu", "vulkan"]);
    assert_eq!(ids("macos", "aarch64"), ["metal"]);
    assert!(releases_for("linux", "riscv64").is_empty());
}

#[test]
fn choose_defaults_to_the_first_and_explains_misses() {
    let rs = releases_for("linux", "x86_64");
    assert_eq!(choose(&rs, None).unwrap().variant, "cpu");
    assert_eq!(choose(&rs, Some("vulkan")).unwrap().variant, "vulkan");
    let e = choose(&rs, Some("metal")).unwrap_err().to_string();
    assert!(e.contains("cpu, vulkan"), "{e}");
    let e = choose(&[], None).unwrap_err().to_string();
    assert!(e.contains("local-models.md"), "{e}");
}

#[test]
fn data_dir_follows_xdg_then_home() {
    // An absolute root on every platform (a bare `/x` has no drive on Windows).
    let abs = |p: &str| {
        if cfg!(windows) {
            format!("C:{}", p.replace('/', "\\"))
        } else {
            p.to_string()
        }
    };
    let (x, h) = (abs("/x"), abs("/h"));
    let env = |pairs: Vec<(&'static str, String)>| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    };
    assert_eq!(
        data_dir_with(&env(vec![
            ("XDG_DATA_HOME", x.clone()),
            ("HOME", h.clone())
        ])),
        Some(PathBuf::from(&x).join("kraken"))
    );
    assert_eq!(
        data_dir_with(&env(vec![("HOME", h.clone())])),
        Some(PathBuf::from(&h).join(".local/share/kraken"))
    );
    assert_eq!(
        data_dir_with(&env(vec![
            ("XDG_DATA_HOME", "relative".to_string()),
            ("HOME", h.clone())
        ])),
        Some(PathBuf::from(&h).join(".local/share/kraken"))
    );
}

#[tokio::test]
async fn installs_a_tarball_after_verifying_it() {
    let bytes = tar_gz(&[
        ("llama-b1/llama-server", b"#!/bin/sh\n", 0o644),
        ("llama-b1/llama-server.exe", b"MZ", 0o644),
        ("llama-b1/libllama.so", b"lib", 0o644),
    ]);
    let r = release(ArchiveFormat::TarGz, Some("llama-b1"), &bytes);
    let fetcher = MemFetcher::default();
    fetcher.files.lock().unwrap().insert(r.url.clone(), bytes);
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());
    assert!(layout.installed().is_none());

    let got = install_llama(&layout, &fetcher, &r, false, &mut noop)
        .await
        .unwrap();
    assert_eq!(got.binary, layout.install_dir(&r).join(LLAMA_BINARY));
    assert!(got.binary.is_file());
    assert!(layout.install_dir(&r).join("libllama.so").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&got.binary).unwrap().permissions().mode();
        assert_eq!(mode & 0o111, 0o111, "llama-server is executable");
    }
    assert_eq!(layout.installed(), Some(got));
    let names: Vec<_> = fs::read_dir(layout.root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.iter().all(|n| !n.starts_with(".staging")),
        "{names:?}"
    );
}

#[tokio::test]
async fn installs_a_flat_zip_and_skips_when_present() {
    let bytes = zip_bytes(&[
        ("llama-server.exe", b"MZ"),
        ("llama-server", b"elf"),
        ("ggml.dll", b"dll"),
    ]);
    let mut r = release(ArchiveFormat::Zip, None, &bytes);
    r.variant = "vulkan".into();
    let fetcher = MemFetcher::default();
    fetcher.files.lock().unwrap().insert(r.url.clone(), bytes);
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());
    install_llama(&layout, &fetcher, &r, false, &mut noop)
        .await
        .unwrap();
    assert!(layout.install_dir(&r).join("ggml.dll").is_file());
    assert!(layout.installed().is_some());

    let before = fetcher.fetched.lock().unwrap().len();
    let mut seen = Vec::new();
    install_llama(&layout, &fetcher, &r, false, &mut |p| seen.push(p))
        .await
        .unwrap();
    assert_eq!(
        fetcher.fetched.lock().unwrap().len(),
        before,
        "no re-download"
    );
    assert!(matches!(seen[0], Progress::Skipped { .. }));
}

#[tokio::test]
async fn a_hash_mismatch_is_refused_before_anything_is_extracted() {
    let bytes = tar_gz(&[("llama-b1/llama-server", b"x", 0o755)]);
    let mut r = release(ArchiveFormat::TarGz, Some("llama-b1"), &bytes);
    r.sha256 = sha_hex(b"something else");
    let fetcher = MemFetcher::default();
    fetcher.files.lock().unwrap().insert(r.url.clone(), bytes);
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());
    let mut extracting = false;
    let e = install_llama(&layout, &fetcher, &r, false, &mut |p| {
        extracting |= matches!(p, Progress::Extracting { .. });
    })
    .await
    .unwrap_err();
    assert!(matches!(e, ProvisionError::Sha256Mismatch { .. }), "{e}");
    assert!(!extracting, "extraction must not start");
    assert!(!layout.install_dir(&r).exists());
    assert!(layout.installed().is_none());
    assert!(!layout.downloads_dir().join(&r.file_name).exists());
}

#[tokio::test]
async fn zip_slip_archives_with_a_valid_hash_are_still_refused() {
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());

    let bytes = zip_bytes(&[("../escape.txt", b"boom"), (LLAMA_BINARY, b"x")]);
    let r = release(ArchiveFormat::Zip, None, &bytes);
    let fetcher = MemFetcher::default();
    fetcher.files.lock().unwrap().insert(r.url.clone(), bytes);
    let e = install_llama(&layout, &fetcher, &r, false, &mut noop)
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::UnsafePath(_)), "{e}");
    assert!(!t.path().join("escape.txt").exists());
    assert!(!layout.root().join("escape.txt").exists());
    assert!(!layout.install_dir(&r).exists());
    assert!(layout.installed().is_none());
}

#[tokio::test]
async fn an_archive_without_the_server_is_refused() {
    let bytes = tar_gz(&[("llama-b1/readme.txt", b"hi", 0o644)]);
    let r = release(ArchiveFormat::TarGz, Some("llama-b1"), &bytes);
    let fetcher = MemFetcher::default();
    fetcher.files.lock().unwrap().insert(r.url.clone(), bytes);
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());
    let e = install_llama(&layout, &fetcher, &r, false, &mut noop)
        .await
        .unwrap_err();
    assert!(matches!(e, ProvisionError::BadArchive(_)), "{e}");
    assert!(layout.installed().is_none());
}

#[test]
fn a_broken_install_is_not_reported() {
    let t = tmp();
    let layout = LlamaLayout::in_data_dir(t.path());
    fs::create_dir_all(layout.root()).unwrap();
    let cur = InstalledLlama {
        tag: "b1".into(),
        variant: "cpu".into(),
        binary: t.path().join("gone/llama-server"),
    };
    fs::write(
        layout.root().join(CURRENT_FILE),
        serde_json::to_string(&cur).unwrap(),
    )
    .unwrap();
    assert!(layout.installed().is_none());
}

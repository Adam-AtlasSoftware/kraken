use std::collections::HashMap;
use std::sync::Mutex;

use kraken_infer::strata::{
    EngineSource, Source, StrataFile, StrataManifest, StrataModel, manifest,
};

use super::*;
use crate::provision::{Body, Fetched};

fn targz(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, *data).expect("append");
    }
    let tar = b.into_inner().expect("tar");
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut enc, &tar).expect("gz");
    enc.finish().expect("finish")
}

fn hex(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

struct Mem {
    files: HashMap<String, Vec<u8>>,
    calls: Mutex<Vec<String>>,
}

struct OneChunk(Option<Vec<u8>>);

#[async_trait]
impl Body for OneChunk {
    async fn next_chunk(&mut self) -> Result<Option<Vec<u8>>, ProvisionError> {
        Ok(self.0.take())
    }
}

#[async_trait]
impl Fetcher for Mem {
    async fn fetch(&self, url: &str, _from: u64) -> Result<Fetched, ProvisionError> {
        self.calls.lock().expect("lock").push(url.to_string());
        let all = self.files.get(url).cloned().ok_or(ProvisionError::Http {
            url: url.into(),
            message: "404".into(),
        })?;
        Ok(Fetched {
            resumed: false,
            total: Some(all.len() as u64),
            body: Box::new(OneChunk(Some(all))),
        })
    }
}

#[derive(Default)]
struct Recorder {
    seen: Mutex<Vec<(String, Cmd)>>,
}

#[async_trait]
impl Runner for Recorder {
    async fn run(&self, step: &str, cmd: &Cmd, _log: &Path) -> Result<(), StrataError> {
        self.seen
            .lock()
            .expect("lock")
            .push((step.into(), cmd.clone()));
        if step == "build the engine" {
            fs::write(cmd.cwd.join("strata-iq3_s.json"), "{}").expect("config");
        }
        Ok(())
    }
}

struct Fixture {
    fetcher: Mem,
    manifest: StrataManifest,
}

fn fixture() -> Fixture {
    let req = b"numpy==2.2.6\n";
    let strata = targz(&[
        ("Strata-abc/requirements.txt", req),
        ("Strata-abc/serve/server.py", b"print(1)"),
    ]);
    let llama = targz(&[
        ("llama.cpp-def/ggml/CMakeLists.txt", b"x"),
        ("llama.cpp-def/gguf-py/a.py", b"x"),
    ]);
    let (s1, s2) = (b"shard-one".to_vec(), b"shard-two".to_vec());
    let src = |url: &str, data: &[u8]| Source {
        commit: "0123456789012345678901234567890123456789".into(),
        url: url.into(),
        sha256: hex(data),
        size: data.len() as u64,
        license: "MIT".into(),
    };
    let mut m = manifest();
    m.engine = EngineSource {
        source: src("https://example.test/strata.tar.gz", &strata),
        requirements_sha256: hex(req),
        ..m.engine
    };
    m.llama_cpp = src("https://example.test/llama.tar.gz", &llama);
    let model = StrataModel {
        id: "strata-iq3-s".into(),
        name: "Test".into(),
        family: "qwen".into(),
        quant: "IQ3_S".into(),
        min_ram_gib: 62,
        arena_gib: 50.3,
        license: "x".into(),
        files: vec![
            StrataFile {
                name: "m-00001-of-00002.gguf".into(),
                url: "https://example.test/m1".into(),
                size: s1.len() as u64,
                sha256: hex(&s1),
            },
            StrataFile {
                name: "m-00002-of-00002.gguf".into(),
                url: "https://example.test/m2".into(),
                size: s2.len() as u64,
                sha256: hex(&s2),
            },
        ],
    };
    m.models = vec![model];
    let files = HashMap::from([
        (m.engine.source.url.clone(), strata),
        (m.llama_cpp.url.clone(), llama),
        ("https://example.test/m1".to_string(), s1),
        ("https://example.test/m2".to_string(), s2),
    ]);
    Fixture {
        fetcher: Mem {
            files,
            calls: Mutex::new(vec![]),
        },
        manifest: m,
    }
}

const BUILD_PINNED: SetupOptions = SetupOptions {
    method: EngineMethod::Build,
    version: EngineVersion::Pinned,
};

async fn install_with(
    f: &Fixture,
    root: &Path,
    options: SetupOptions,
    model: ModelSource<'_>,
    runner: &Recorder,
) -> Result<StrataInstall, StrataError> {
    let layout = StrataLayout::at(root);
    let req = StrataRequest {
        manifest: &f.manifest,
        options,
        model,
    };
    install_strata(&layout, &f.fetcher, runner, &req, vec![], &mut |_| {}).await
}

async fn install(
    f: &Fixture,
    root: &Path,
    missing: Vec<Missing>,
    runner: &Recorder,
) -> Result<StrataInstall, StrataError> {
    let layout = StrataLayout::at(root);
    let req = StrataRequest {
        manifest: &f.manifest,
        options: BUILD_PINNED,
        model: ModelSource::Catalog(&f.manifest.models[0]),
    };
    install_strata(&layout, &f.fetcher, runner, &req, missing, &mut |_| {}).await
}

#[tokio::test]
async fn a_full_setup_runs_the_steps_inside_the_install_root() {
    let f = fixture();
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("engines/strata");
    let rec = Recorder::default();
    let out = install(&f, &root, vec![], &rec).await.expect("installed");
    let seen = rec.seen.lock().expect("lock");
    let steps: Vec<&str> = seen.iter().map(|(s, _)| s.as_str()).collect();
    assert_eq!(
        steps,
        [
            "create venv",
            "install pinned Python packages",
            "build the engine"
        ]
    );
    let build = &seen[2].1;
    assert!(build.args.iter().any(|a| a == "--no-start"));
    assert!(build.args.windows(2).any(|w| w == ["--host", "127.0.0.1"]));
    assert!(
        build
            .args
            .iter()
            .any(|a| a.starts_with(root.to_str().expect("utf8")))
    );
    assert!(seen[1].1.args.iter().any(|a| a == "--only-binary"));
    assert!(
        root.join("src/third_party/llama.cpp/ggml/CMakeLists.txt")
            .is_file()
    );
    assert!(root.join("shims/sudo").is_file());
    assert!(out.gguf_dir.join("m-00002-of-00002.gguf").is_file());
    let text = fs::read_to_string(&out.backend_manifest).expect("backend.toml");
    assert!(kraken_infer::Manifest::parse(&text).is_ok());
}

#[tokio::test]
async fn a_model_hash_mismatch_refuses_and_builds_nothing() {
    let mut f = fixture();
    f.manifest.models[0].files[1].sha256 = "0".repeat(64);
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let err = install(&f, &dir.path().join("s"), vec![], &rec)
        .await
        .expect_err("refused");
    assert!(
        matches!(
            err,
            StrataError::Provision(ProvisionError::Sha256Mismatch { .. })
        ),
        "{err}"
    );
    assert!(
        rec.seen
            .lock()
            .expect("lock")
            .iter()
            .all(|(s, _)| s != "build the engine")
    );
    assert!(
        !dir.path()
            .join("s/models/IQ3_S/m-00002-of-00002.gguf")
            .exists()
    );
}

#[tokio::test]
async fn a_source_archive_hash_mismatch_refuses() {
    let mut f = fixture();
    f.manifest.engine.source.sha256 = "1".repeat(64);
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let err = install(&f, &dir.path().join("s"), vec![], &rec)
        .await
        .expect_err("refused");
    assert!(err.to_string().contains("sha256 mismatch"), "{err}");
    assert!(rec.seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn changed_python_pins_are_refused() {
    let mut f = fixture();
    f.manifest.engine.requirements_sha256 = "2".repeat(64);
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let err = install(&f, &dir.path().join("s"), vec![], &rec)
        .await
        .expect_err("refused");
    assert!(matches!(err, StrataError::Pin(_)), "{err}");
    assert!(rec.seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn missing_system_pieces_stop_before_any_download() {
    let f = fixture();
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let missing = vec![Missing {
        what: "CUDA toolkit (`nvcc` not on PATH)".into(),
        how_to_fix: "install it".into(),
    }];
    let err = install(&f, &dir.path().join("s"), missing, &rec)
        .await
        .expect_err("stopped");
    assert!(err.to_string().contains("nvcc"), "{err}");
    assert!(f.fetcher.calls.lock().expect("lock").is_empty());
    assert!(!dir.path().join("s").exists());
}

fn setup_args(rec: &Recorder) -> Vec<String> {
    let seen = rec.seen.lock().expect("lock");
    let (_, cmd) = seen
        .iter()
        .find(|(step, _)| step == "build the engine")
        .expect("setup.py ran");
    cmd.args.clone()
}

const ENGINE_NAME: &str = "strata-engine-0.9.9-linux-x86_64-cuda-cuda13.tar.gz";

fn with_release(f: &mut Fixture, tag: &str, setup_py_requirements: &[u8]) {
    let archive = targz(&[
        ("Strata-new/requirements.txt", setup_py_requirements),
        ("Strata-new/serve/server.py", b"print(2)"),
    ]);
    let engine = targz(&[("strata", b"engine"), ("BUILD.json", b"{}")]);
    let listing = format!(
        "{{\"tag_name\": \"{tag}\", \"assets\": [\
         {{\"name\": \"{ENGINE_NAME}\", \"browser_download_url\": \"https://example.test/engine.tgz\"}},\
         {{\"name\": \"SHA256SUMS.txt\", \"browser_download_url\": \"https://example.test/sums\"}}]}}"
    );
    f.fetcher.files.insert(
        "https://api.github.com/repos/Niko1221/Strata/releases/latest".into(),
        listing.into_bytes(),
    );
    f.fetcher.files.insert(
        format!("https://codeload.github.com/Niko1221/Strata/tar.gz/refs/tags/{tag}"),
        archive,
    );
    f.fetcher.files.insert(
        "https://example.test/sums".into(),
        format!(
            "{}  {ENGINE_NAME}\n{}  other.zip\n",
            hex(&engine),
            "0".repeat(64)
        )
        .into_bytes(),
    );
    f.fetcher
        .files
        .insert("https://example.test/engine.tgz".into(), engine);
}

fn your_files(dir: &Path) -> kraken_infer::strata::ExistingModel {
    let prefix = "Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS";
    for i in 1..=2 {
        fs::write(dir.join(format!("{prefix}-0000{i}-of-00002.gguf")), b"mine").expect("shard");
    }
    kraken_infer::strata::existing_model(&dir.join(format!("{prefix}-00001-of-00002.gguf")))
        .expect("recognised")
}

#[tokio::test]
async fn the_ready_made_engine_is_fetched_checked_packed_and_handed_over_as_a_folder() {
    let mut f = fixture();
    with_release(&mut f, "v9.9.9", b"numpy==9\n");
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let model = f.manifest.models[0].clone();
    let root = dir.path().join("s");
    let out = install_with(
        &f,
        &root,
        SetupOptions::default(),
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect("installed");
    let args = setup_args(&rec);
    assert!(!args.iter().any(|a| a == "--build"), "{args:?}");
    let folder = root.join("downloads/engine-v9.9.9/prebuilt");
    assert!(
        args.windows(2)
            .any(|w| w[0] == "--prebuilt" && w[1] == format!("{}/", folder.display())),
        "{args:?}"
    );
    {
        let seen = rec.seen.lock().expect("lock");
        let (_, pack) = seen
            .iter()
            .find(|(step, _)| step == "pack the engine")
            .expect("the tarball is packed into the zip setup.py expects");
        assert_eq!(pack.args[0], "-c");
        assert!(pack.args[1].contains("strict_timestamps=False"));
        assert!(
            pack.args[2].ends_with("strata-linux-x64.zip"),
            "{:?}",
            pack.args
        );
        assert!(
            pack.args[3..].contains(&"strata".to_string()),
            "{:?}",
            pack.args
        );
    }
    assert!(out.description.contains("v9.9.9") && out.description.contains("ready-made"));
    // The newest release has no pinned hashes, so the pinned llama.cpp is not placed either.
    assert!(!root.join("src/third_party").exists());
    let calls = f.fetcher.calls.lock().expect("lock");
    assert!(calls.iter().all(|u| !u.contains("llama")), "{calls:?}");
    let log = fs::read_to_string(root.join("setup.log")).unwrap_or_default();
    assert!(log.contains("sha256"), "{log}");
}

#[tokio::test]
async fn a_ready_made_engine_that_does_not_match_the_release_checksums_is_refused() {
    let mut f = fixture();
    with_release(&mut f, "v9.9.9", b"numpy==9\n");
    f.fetcher.files.insert(
        "https://example.test/engine.tgz".into(),
        targz(&[("strata", b"evil")]),
    );
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let model = f.manifest.models[0].clone();
    let err = install_with(
        &f,
        &dir.path().join("s"),
        SetupOptions::default(),
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect_err("refused");
    assert!(err.to_string().contains("sha256 mismatch"), "{err}");
    let seen = rec.seen.lock().expect("lock");
    assert!(
        seen.iter()
            .all(|(s, _)| s != "pack the engine" && s != "build the engine")
    );
}

#[test]
fn the_engine_asset_and_its_checksum_are_found_in_a_release_listing() {
    let v: serde_json::Value = serde_json::json!({"assets": [
        {"name": "strata-engine-1.0-linux-x86_64-cuda-cuda12.tar.gz", "browser_download_url": "https://x/12"},
        {"name": "strata-engine-1.0-linux-x86_64-cuda-cuda13.tar.gz", "browser_download_url": "https://x/13"},
        {"name": "SHA256SUMS.txt", "browser_download_url": "https://x/sums"},
    ]});
    let (name, url, sums) = engine_assets(&v).expect("found");
    assert_eq!(
        (name.as_str(), url.as_str(), sums.as_str()),
        (
            "strata-engine-1.0-linux-x86_64-cuda-cuda13.tar.gz",
            "https://x/13",
            "https://x/sums"
        )
    );
    assert!(engine_assets(&serde_json::json!({"assets": []})).is_err());
    let no_sums = serde_json::json!({"assets": [
        {"name": "strata-engine-1.0-linux-x86_64-cuda-cuda13.tar.gz", "browser_download_url": "https://x/13"}]});
    assert!(engine_assets(&no_sums).is_err(), "no checksums, no engine");

    let h = "ab".repeat(32);
    let text = format!("{h}  file-a\n{}  *file-b\nnot a line\n", "cd".repeat(32));
    assert_eq!(listed_sha256(&text, "file-a"), Some(h));
    assert_eq!(listed_sha256(&text, "file-b"), Some("cd".repeat(32)));
    assert_eq!(listed_sha256(&text, "file-c"), None);
}

#[tokio::test]
async fn building_the_newest_release_passes_build() {
    let mut f = fixture();
    with_release(&mut f, "v9.9.9", b"numpy==9\n");
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let model = f.manifest.models[0].clone();
    let options = SetupOptions {
        method: EngineMethod::Build,
        version: EngineVersion::LatestRelease,
    };
    install_with(
        &f,
        &dir.path().join("s"),
        options,
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect("installed");
    let args = setup_args(&rec);
    assert!(args.iter().any(|a| a == "--build"));
    assert!(!args.iter().any(|a| a == "--prebuilt"));
}

#[tokio::test]
async fn the_newest_commit_is_looked_up_and_only_built() {
    let mut f = fixture();
    let sha = "a".repeat(40);
    f.fetcher.files.insert(
        "https://api.github.com/repos/Niko1221/Strata/commits/main".into(),
        format!("{{\"sha\": \"{sha}\"}}").into_bytes(),
    );
    f.fetcher.files.insert(
        format!("https://codeload.github.com/Niko1221/Strata/tar.gz/{sha}"),
        targz(&[("Strata-x/requirements.txt", b"x")]),
    );
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let model = f.manifest.models[0].clone();
    let build = SetupOptions {
        method: EngineMethod::Build,
        version: EngineVersion::LatestCommit,
    };
    let out = install_with(
        &f,
        &dir.path().join("s"),
        build,
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect("built");
    assert!(out.description.contains(&sha[..12]), "{}", out.description);

    let prebuilt = SetupOptions {
        method: EngineMethod::Prebuilt,
        version: EngineVersion::LatestCommit,
    };
    let rec = Recorder::default();
    let err = install_with(
        &f,
        &dir.path().join("t"),
        prebuilt,
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect_err("no ready-made engine for a commit");
    assert!(matches!(err, StrataError::Pin(_)), "{err}");
    assert!(rec.seen.lock().expect("lock").is_empty());
}

#[tokio::test]
async fn a_strange_release_name_is_refused() {
    let mut f = fixture();
    with_release(&mut f, "../evil", b"x");
    let dir = tempfile::tempdir().expect("dir");
    let rec = Recorder::default();
    let model = f.manifest.models[0].clone();
    let err = install_with(
        &f,
        &dir.path().join("s"),
        SetupOptions::default(),
        ModelSource::Catalog(&model),
        &rec,
    )
    .await
    .expect_err("refused");
    assert!(matches!(err, StrataError::Pin(_)), "{err}");
}

#[tokio::test]
async fn your_own_model_files_are_used_in_place_and_nothing_is_downloaded_for_them() {
    let mut f = fixture();
    with_release(&mut f, "v9.9.9", b"numpy==9\n");
    let dir = tempfile::tempdir().expect("dir");
    let mine = dir.path().join("mine");
    fs::create_dir_all(&mine).expect("dir");
    let existing = your_files(&mine);
    let rec = Recorder::default();
    let root = dir.path().join("s");
    let out = install_with(
        &f,
        &root,
        SetupOptions::default(),
        ModelSource::Existing(&existing),
        &rec,
    )
    .await
    .expect("installed");
    let args = setup_args(&rec);
    let pair = |k: &str, v: &str| args.windows(2).any(|w| w[0] == k && w[1] == v);
    assert!(pair("--family", "swift"), "{args:?}");
    assert!(pair("--model", "IQ2_XS"), "{args:?}");
    assert!(pair("--gguf-dir", mine.to_str().expect("utf8")), "{args:?}");
    assert_eq!(out.gguf_dir, mine);
    let calls = f.fetcher.calls.lock().expect("lock");
    assert!(
        calls
            .iter()
            .all(|u| !u.contains("/m1") && !u.contains("/m2")),
        "{calls:?}"
    );
    assert!(!root.join("models").exists(), "the files are not copied");
}

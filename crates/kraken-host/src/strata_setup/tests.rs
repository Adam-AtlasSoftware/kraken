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

async fn install(
    f: &Fixture,
    root: &Path,
    missing: Vec<Missing>,
    runner: &Recorder,
) -> Result<StrataInstall, StrataError> {
    let layout = StrataLayout::at(root);
    install_strata(
        &layout,
        &f.fetcher,
        runner,
        &f.manifest,
        &f.manifest.models[0],
        missing,
        &mut |_| {},
    )
    .await
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

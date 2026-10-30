//! `debuginfo_find` and `debuginfo_servers` against a local HTTP server that plays debuginfod:
//! the debug file of `stripped_calc-O0` served under the build-id of its stripped twin.
//!
//! Needs `objcopy` (to give the corpus programs a build-id); without it the tests say "skipped".

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};

use async_trait::async_trait;
use common::{agent, tiny, user};
use kraken_engine::SharedEngine;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{ConfigEntry, ConfigStore};
use kraken_registry::{AutoApprove, CallContext, EngineFactory, JobTable, Registry, Session};
use serde_json::{Value, json};

#[derive(Debug, Default)]
struct MemStore(Mutex<HashMap<String, Value>>);

impl ConfigStore for MemStore {
    fn get(&self, _key: Option<&str>) -> Result<Vec<ConfigEntry>, ProtoError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| ConfigEntry {
                key: k.clone(),
                value: Some(v.clone()),
                accepts: String::new(),
                doc: String::new(),
                person_only: false,
            })
            .collect())
    }

    fn set(&self, key: &str, value: Value) -> Result<ConfigEntry, ProtoError> {
        let mut m = self.0.lock().unwrap();
        if value.is_null() {
            m.remove(key);
        } else {
            m.insert(key.to_string(), value.clone());
        }
        Ok(ConfigEntry {
            key: key.into(),
            value: Some(value),
            accepts: String::new(),
            doc: String::new(),
            person_only: false,
        })
    }
}

struct Factory;

#[async_trait]
impl EngineFactory for Factory {
    async fn create(&self, _engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(engine_fake::FakeEngine::new(tiny())))
    }
}

fn session() -> Session {
    Session::new(Arc::new(Factory))
        .with_jobs(JobTable::global())
        .with_config_store(Arc::new(MemStore::default()))
}

async fn call(
    s: &Session,
    ctx: &CallContext,
    name: &str,
    args: Value,
) -> Result<Value, ProtoError> {
    Registry::standard().call_json(name, s, ctx, args).await
}

async fn ok(s: &Session, name: &str, args: Value) -> Value {
    call(s, &user(), name, args)
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

async fn find_result(s: &Session, ctx: &CallContext, path: &Path) -> Result<Value, ProtoError> {
    let started = call(s, ctx, "debuginfo_find", json!({"path": path})).await?;
    let done = ok(
        s,
        "job_await",
        json!({"job_id": started["job_id"], "timeout_ms": 30000}),
    )
    .await;
    assert_eq!(done["status"], "succeeded", "{done}");
    Ok(done["result"].clone())
}

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn cache_dir() -> PathBuf {
    static ONCE: Once = Once::new();
    static DIR: Mutex<Option<PathBuf>> = Mutex::new(None);
    ONCE.call_once(|| {
        let d = tempfile::tempdir().unwrap().keep();
        // SAFETY: set before any test in this binary reads it, under `Once`.
        unsafe {
            std::env::set_var("KRAKEN_DEBUGINFO_CACHE", &d);
            std::env::remove_var("DEBUGINFOD_URLS");
            std::env::remove_var("KRAKEN_OFFLINE");
        }
        *DIR.lock().unwrap() = Some(d);
    });
    DIR.lock().unwrap().clone().unwrap()
}

/// `src` with the GNU build-id `[tag; 20]` added.
fn with_build_id(src: &Path, dst: &Path, tag: u8) -> bool {
    let mut note = Vec::new();
    note.extend_from_slice(&4u32.to_le_bytes());
    note.extend_from_slice(&20u32.to_le_bytes());
    note.extend_from_slice(&3u32.to_le_bytes());
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(&[tag; 20]);
    let note_path = dst.with_extension("note");
    std::fs::write(&note_path, &note).unwrap();
    std::process::Command::new("objcopy")
        .arg("--add-section")
        .arg(format!(".note.gnu.build-id={}", note_path.display()))
        .arg("--set-section-flags")
        .arg(".note.gnu.build-id=alloc,readonly")
        .arg(src)
        .arg(dst)
        .status()
        .is_ok_and(|s| s.success())
}

fn id_hex(tag: u8) -> String {
    format!("{tag:02x}").repeat(20)
}

/// A program with build-id `tag` in a fresh folder, and the debug file that belongs to it.
fn program(tag: u8) -> Option<(tempfile::TempDir, PathBuf, Vec<u8>)> {
    cache_dir();
    let dir = tempfile::tempdir().unwrap();
    let prog = dir.path().join("prog");
    let dbg = dir.path().join("prog.full");
    if !with_build_id(&corpus("bin/stripped_calc-O0-stripped"), &prog, tag)
        || !with_build_id(&corpus("bin/stripped_calc-O0"), &dbg, tag)
    {
        eprintln!("skipped: objcopy is not available");
        return None;
    }
    let bytes = std::fs::read(&dbg).unwrap();
    Some((dir, prog, bytes))
}

/// A debuginfod stand-in: `routes` maps request paths to bodies; counts the requests.
fn serve(routes: HashMap<String, Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let text = String::from_utf8_lossy(&req).into_owned();
            let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
            let (status, body) = match routes.get(&path) {
                Some(b) => ("200 OK", b.clone()),
                None => ("404 Not Found", b"no".to_vec()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    (url, hits)
}

async fn configure(s: &Session, url: &str, consent: bool) {
    let out = ok(
        s,
        "debuginfo_servers",
        json!({"servers": [url], "consent": consent}),
    )
    .await;
    assert_eq!(out["servers"][0]["url"]["value"], url);
    assert_eq!(out["consent"], consent);
}

#[tokio::test]
async fn a_matching_download_is_checked_cached_and_found_by_the_probe() {
    let Some((_dir, prog, debug)) = program(0xA1) else {
        return;
    };
    let (url, hits) = serve(HashMap::from([(
        format!("/buildid/{}/debuginfo", id_hex(0xA1)),
        debug.clone(),
    )]));
    let s = session();
    configure(&s, &url, true).await;

    let out = find_result(&s, &user(), &prog).await.unwrap();
    assert_eq!(out["found"], true, "{out}");
    assert_eq!(out["cache_hit"], false);
    assert_eq!(out["bytes"], debug.len());
    let file = PathBuf::from(out["file"]["value"].as_str().unwrap());
    assert!(file.starts_with(cache_dir()), "{}", file.display());
    assert_eq!(std::fs::read(&file).unwrap(), debug);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // the probe now finds it, and attaching it is accepted
    let probe = ok(&s, "debuginfo_probe", json!({"path": prog})).await;
    assert_eq!(
        probe["best"]["value"],
        file.to_string_lossy().as_ref(),
        "{probe}"
    );
    let cand = &probe["candidates"][0];
    assert_eq!(cand["source"], "downloaded");
    assert_eq!(cand["verdict"], "match", "{probe}");
    let chosen = kraken_registry::commands::resolve_for_attach(&prog, &file).unwrap();
    assert_eq!(chosen, file);
    kraken_registry::commands::engine_accepts(kraken_registry::EngineKind::Native, &chosen)
        .unwrap();
}

#[tokio::test]
async fn a_file_with_another_build_id_is_refused_and_never_cached() {
    let Some((_dir, prog, _)) = program(0xB2) else {
        return;
    };
    let Some((_d2, _p2, other)) = program(0xB3) else {
        return;
    };
    let (url, _hits) = serve(HashMap::from([(
        format!("/buildid/{}/debuginfo", id_hex(0xB2)),
        other,
    )]));
    let s = session();
    configure(&s, &url, true).await;
    let out = find_result(&s, &user(), &prog).await.unwrap();
    assert_eq!(out["found"], false, "{out}");
    let why = out["attempts"][0]["outcome"]["value"].as_str().unwrap();
    assert!(
        why.contains("refused") && why.contains("another build"),
        "{why}"
    );
    let cached = cache_dir()
        .join("buildid")
        .join(id_hex(0xB2))
        .join("debuginfo");
    assert!(!cached.exists());
    // nothing for the probe to find either
    let probe = ok(&s, "debuginfo_probe", json!({"path": prog})).await;
    assert!(probe["best"].is_null(), "{probe}");
}

#[tokio::test]
async fn a_cache_hit_asks_no_server_even_offline() {
    let Some((_dir, prog, debug)) = program(0xC4) else {
        return;
    };
    let (url, hits) = serve(HashMap::from([(
        format!("/buildid/{}/debuginfo", id_hex(0xC4)),
        debug,
    )]));
    let s = session();
    configure(&s, &url, true).await;
    assert_eq!(
        find_result(&s, &user(), &prog).await.unwrap()["found"],
        true
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    ok(&s, "debuginfo_servers", json!({"offline": true})).await;
    let again = find_result(&s, &user(), &prog).await.unwrap();
    assert_eq!(again["found"], true);
    assert_eq!(again["cache_hit"], true, "{again}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the cache hit must not ask the server"
    );
}

#[tokio::test]
async fn offline_mode_and_missing_consent_refuse_before_any_request() {
    let Some((_dir, prog, debug)) = program(0xD5) else {
        return;
    };
    let (url, hits) = serve(HashMap::from([(
        format!("/buildid/{}/debuginfo", id_hex(0xD5)),
        debug,
    )]));
    let s = session();
    configure(&s, &url, false).await;
    let e = call(&s, &user(), "debuginfo_find", json!({"path": prog}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("consent"), "{e}");

    configure(&s, &url, true).await;
    ok(&s, "debuginfo_servers", json!({"offline": true})).await;
    let e = call(&s, &user(), "debuginfo_find", json!({"path": prog}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unsupported);
    assert!(e.message.contains("offline"), "{e}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_agent_needs_a_persons_approval_and_cannot_change_the_settings() {
    let Some((_dir, prog, debug)) = program(0xE6) else {
        return;
    };
    let (url, hits) = serve(HashMap::from([(
        format!("/buildid/{}/debuginfo", id_hex(0xE6)),
        debug,
    )]));
    let s = session();
    configure(&s, &url, false).await;
    // the person's consent flag is not an agent's approval, and no flag stands in for it
    let e = call(&s, &agent("r"), "debuginfo_find", json!({"path": prog}))
        .await
        .unwrap_err();
    assert_eq!(e.details.as_ref().unwrap()["approval"], "denied", "{e}");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let approved = agent("r").with_approval(Arc::new(AutoApprove));
    let out = find_result(&s, &approved, &prog).await.unwrap();
    assert_eq!(out["found"], true, "{out}");
    let e = call(
        &s,
        &agent("r"),
        "debuginfo_servers",
        json!({"consent": true}),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::RejectedHumanPriority);
    // listing is open to agents
    let list = call(&s, &agent("r"), "debuginfo_servers", json!({}))
        .await
        .unwrap();
    assert_eq!(list["servers"][0]["source"], "config");
}

#[tokio::test]
async fn bad_server_addresses_are_refused() {
    let s = session();
    let e = call(
        &s,
        &user(),
        "debuginfo_servers",
        json!({"servers": ["ftp://x"]}),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
    let e = call(
        &s,
        &user(),
        "debuginfo_servers",
        json!({"servers": ["https://u:p@x"]}),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgument);
}

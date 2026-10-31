//! `debug_trace` on a corpus program with the native engine: coverage of `switch_vm-O0`, its
//! drcov export, a step trace and the stored runs.
//!
//! The program runs a fixed bytecode (push, mul, xor, drop, then a countdown with print, dec, dup
//! and jnz, then halt), so the cases of `vm_run`'s switch that must have run are known: the
//! jump table's targets in source order are the opcodes 0..14 and the program executes exactly
//! 0, 1, 4, 5, 7, 9, 10, 11 and 14.
//!
//! Needs the native build and Sleigh specs (as `exit_criterion_native.rs`), Landlock and the
//! emulator's runner (`cargo build -p kraken-emu --bin kraken-emu-run`); otherwise it prints
//! "skipped" and passes.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use engine_native::{Isolation, NativeConfig, NativeEngine};
use kraken_engine::SharedEngine;
use kraken_proto::ProtoError;
use kraken_proto::trace::parse_drcov;
use kraken_registry::{CallContext, EngineFactory, Registry, Session, Surface};
use serde_json::{Value, json};

struct NativeFactory {
    config: NativeConfig,
}

#[async_trait]
impl EngineFactory for NativeFactory {
    async fn create(&self, engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        let mut config = self.config.clone();
        config.state_dir = Some(engine_dir.to_path_buf());
        Ok(Arc::new(NativeEngine::new(config)))
    }
}

fn corpus(rel: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel);
    std::fs::canonicalize(&p).unwrap_or(p)
}

fn runner() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.parent()?.join("kraken-emu-run");
    p.is_file().then_some(p)
}

async fn call(registry: &Registry, session: &Session, name: &str, args: Value) -> Value {
    let ctx = CallContext::user("adam", Surface::Test);
    registry
        .call_json(name, session, &ctx, args)
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

async fn job(registry: &Registry, session: &Session, name: &str, args: Value) -> Value {
    let started = call(registry, session, name, args).await;
    let done = call(
        registry,
        session,
        "job_await",
        json!({"job_id": started["job_id"], "timeout_ms": 300_000}),
    )
    .await;
    assert_eq!(done["status"], "succeeded", "{name}: {done}");
    done["result"].clone()
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().expect("hex string").trim_start_matches("0x"), 16)
        .expect("hex address")
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_of_switch_vm_matches_the_cases_that_ran() {
    let Some(mut config) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh specs");
        return;
    };
    if !NativeEngine::is_usable(&config) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    let Some(runner) = runner() else {
        eprintln!("skipped: kraken-emu-run is not built");
        return;
    };
    // SAFETY: set before any other thread of this test binary reads it; this is its only test.
    unsafe { std::env::set_var("KRAKEN_EMU_RUN", runner) };
    config.isolation = Isolation::InProcess;
    let factory = Arc::new(NativeFactory { config });
    let registry = Registry::standard();
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("proj");
    let binary = corpus("bin/switch_vm-O0");
    assert!(binary.is_file(), "missing {}", binary.display());

    let session = Session::new(factory.clone());
    let base = session
        .create_project(&project, &binary)
        .await
        .expect("project")
        .program()
        .base
        .0;
    job(&registry, &session, "analyze", json!({})).await;

    // Two runs of the same input: the same blocks, the same counts.
    let drcov_path = tmp.path().join("run1.drcov");
    let first = job(
        &registry,
        &session,
        "debug_trace",
        json!({"label": "first", "format": "drcov", "export_path": drcov_path}),
    )
    .await;
    let second = job(
        &registry,
        &session,
        "debug_trace",
        json!({"label": "second"}),
    )
    .await;
    let hit = first["run"]["blocks_hit"].as_u64().expect("blocks_hit");
    assert!(hit > 10, "{first}");
    assert_eq!(second["run"]["blocks_hit"], first["run"]["blocks_hit"]);
    assert_eq!(second["run"]["instructions"], first["run"]["instructions"]);
    assert_eq!(first["run"]["exit"], "exit 0", "{first}");

    // The drcov file parses and lists the same blocks as offsets from the image base.
    let d = parse_drcov(&std::fs::read(&drcov_path).expect("drcov file")).expect("drcov parses");
    assert_eq!(d.modules.len(), 1);
    assert_eq!(d.modules[0].base, base);
    assert_eq!(d.blocks.len() as u64, hit);
    assert_eq!(
        first["exported"]["bytes"],
        json!(std::fs::metadata(&drcov_path).unwrap().len())
    );

    // The blocks the store holds equal the file's.
    let page = call(
        &registry,
        &session,
        "coverage_blocks",
        json!({"run": 1, "limit": 5000}),
    )
    .await;
    let ran: BTreeSet<u64> = page["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|b| hex(&b["start"]))
        .collect();
    let from_file: BTreeSet<u64> = d
        .blocks
        .iter()
        .map(|(o, _, _)| base + u64::from(*o))
        .collect();
    assert_eq!(ran, from_file);

    // The jump table of vm_run: its targets in order are the opcodes 0..14.
    let tables = call(&registry, &session, "jump_tables", json!({"limit": 200})).await;
    let table = tables["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|t| t["target_count"].as_u64() == Some(15))
        .unwrap_or_else(|| panic!("no 15-way switch: {tables}"));
    let executed: Vec<usize> = table["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .enumerate()
        .filter(|(_, t)| ran.contains(&hex(t)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(executed, [0, 1, 4, 5, 7, 9, 10, 11, 14]);

    // A step trace from vm_run: starts at the function, records register deltas and writes.
    let text_path = tmp.path().join("steps.txt");
    let traced = job(
        &registry,
        &session,
        "debug_trace",
        json!({
            "step_trace": 200, "memory": true, "from_symbol": "vm_run",
            "format": "text", "export_path": text_path,
        }),
    )
    .await;
    assert_eq!(traced["run"]["steps_recorded"], 200);
    assert_eq!(traced["run"]["blocks_hit"], first["run"]["blocks_hit"]);
    let vm_run = hex(&table["function"]);
    assert_eq!(hex(&traced["steps_preview"][0]["address"]), vm_run);
    let text = std::fs::read_to_string(&text_path).expect("step trace file");
    assert!(text.starts_with("# KRAKEN step trace v1"), "{text}");
    assert!(text.lines().any(|l| l.contains("->")), "register deltas");
    assert!(text.lines().any(|l| l.contains("<-")), "memory writes");

    // The store: three runs, then cleared.
    let list = call(&registry, &session, "coverage_list", json!({})).await;
    assert_eq!(list["runs"].as_array().expect("runs").len(), 3);
    let cleared = call(&registry, &session, "coverage_clear", json!({"run": 1})).await;
    assert_eq!(cleared["removed"], 1);
    let cleared = call(&registry, &session, "coverage_clear", json!({})).await;
    assert_eq!(cleared["remaining"], 0);
}

//! Tests against a real Ghidra. All `#[ignore]`d: run with
//! `cargo xtask ghidra-ext && cargo test -p engine-ghidra -- --ignored`.
//!
//! The install comes from `KRAKEN_GHIDRA_HOME` / `KRAKEN_JAVA_HOME` / `KRAKEN_GHIDRA_EXT_JAR`;
//! when those are unset the pinned copies in `~/.cache/kraken-dev` and the xtask build output
//! are used.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use engine_ghidra::{EngineConfig, GhidraEngine, GhidraInstall, InstallConfig};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Engine, FunctionLister, Loader, LoaderSpec,
    Mutator, ProgramInfo,
};
use kraken_proto::{Anchor, FunctionSummary, Hex64, Locator, LogOp, PageRequest, VersionedLogOp};
use serde::Deserialize;

const BINARY: &str = "pie_list-O0";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn first_child(parent: &Path) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(parent)
        .ok()?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next()
}

fn install() -> GhidraInstall {
    let cache = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/kraken-dev"));
    let fallback = |var: &str, sub: &str| {
        if std::env::var_os(var).is_some() {
            None
        } else {
            cache.as_ref().and_then(|c| first_child(&c.join(sub)))
        }
    };
    let cfg = InstallConfig {
        ghidra_home: fallback("KRAKEN_GHIDRA_HOME", "ghidra"),
        java_home: if std::env::var_os("KRAKEN_JAVA_HOME").is_some()
            || std::env::var_os("JAVA_HOME").is_some()
        {
            None
        } else {
            cache.as_ref().and_then(|c| first_child(&c.join("jdk")))
        },
        ext_jar: None,
    };
    GhidraInstall::discover(&cfg).unwrap_or_else(|e| {
        panic!("no usable Ghidra install ({e}); run `cargo xtask ghidra-ext` and set KRAKEN_GHIDRA_HOME / KRAKEN_JAVA_HOME")
    })
}

/// Temp dirs without dotted path elements (`tempfile::tempdir` makes `.tmpXXXX`, which Ghidra rejects).
fn scratch_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-test-")
        .tempdir()
        .unwrap()
}

fn corpus_binary() -> PathBuf {
    repo_root().join("corpus/bin").join(BINARY)
}

fn new_engine(project: &Path) -> GhidraEngine {
    GhidraEngine::new(EngineConfig::new(install(), project))
}

#[derive(Deserialize)]
struct Truth {
    functions: Vec<TruthFunction>,
}

#[derive(Deserialize)]
struct TruthFunction {
    name: String,
    entry: Hex64,
}

fn truth() -> Truth {
    let path = repo_root().join(format!("corpus/truth/{BINARY}.json"));
    serde_json::from_slice(&std::fs::read(&path).expect("truth file")).expect("truth json")
}

fn offset_of(l: &Locator) -> u64 {
    match l {
        Locator::Native { offset, .. } => offset.0,
        other => panic!("unexpected locator {other:?}"),
    }
}

async fn list_all(engine: &GhidraEngine) -> Vec<FunctionSummary> {
    let cancel = CancellationToken::new();
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = engine
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(500),
                },
                &cancel,
            )
            .await
            .expect("list_functions");
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

async fn open_and_analyze(engine: &GhidraEngine, binary: &Path) -> ProgramInfo {
    let cancel = CancellationToken::new();
    let info = engine
        .open_binary(binary, &LoaderSpec::default(), &cancel)
        .await
        .expect("open_binary");
    let job = engine
        .analyze(AnalyzeRequest::default(), cancel.clone())
        .await
        .expect("analyze");
    job.wait().await.expect("analysis");
    info
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real Ghidra (cargo xtask ghidra-ext)"]
async fn contract_suite_passes_on_pie_list_o0() {
    let binary = corpus_binary();

    // Pass 1: learn what Ghidra finds, and check it against the corpus ground truth.
    let scout_dir = scratch_dir();
    let scout = new_engine(&scout_dir.path().join("project"));
    let program = open_and_analyze(&scout, &binary).await;
    let found = list_all(&scout).await;
    let diag = scout.diagnostics();
    eprintln!("sidecar: {diag:#?}");
    let report = diag.confinement.expect("confinement report");
    assert!(
        report.is_confined() && report.network_blocked(),
        "the sidecar must run confined with the network blocked: {report}"
    );
    for t in truth().functions {
        let at = program.base.0 + t.entry.0;
        let hit = found.iter().find(|f| offset_of(&f.locator) == at);
        assert_eq!(
            hit.map(|f| f.name.as_str()),
            Some(t.name.as_str()),
            "ground-truth function {} at {at:#x}",
            t.name
        );
    }
    // At -O0 the functions are packed: no 16 free bytes anywhere. Make room by deleting one
    // corpus function from the analysed project; its entry becomes the scratch address.
    let victim = found
        .iter()
        .skip(1)
        .rev()
        .skip(1)
        .find(|f| f.name == "cmp_id")
        .expect("cmp_id in the listing")
        .clone();
    let cancel = CancellationToken::new();
    let delete = VersionedLogOp::new(LogOp::DeleteFunction {
        anchor: Anchor::Native {
            space: "ram".into(),
            offset: Hex64(offset_of(&victim.locator)),
            fn_entry: Hex64(offset_of(&victim.locator)),
            fn_hash: victim.fn_hash.clone().unwrap_or_default(),
        },
        old_body: None,
    });
    scout.apply(&delete, &cancel).await.expect("delete cmp_id");
    scout.save(&cancel).await.expect("save");
    let scratch = victim.locator.clone();
    let found: Vec<FunctionSummary> = list_all(&scout).await;
    assert!(found.iter().all(|f| f.locator != scratch));
    eprintln!("{} functions, scratch at {scratch:?}", found.len());
    scout.shutdown().await;

    // Pass 2: the contract suite on a fresh engine over that persisted project (it mutates it).
    let mut functions: Vec<ExpectedFunction> = found
        .iter()
        .map(|f| ExpectedFunction {
            locator: f.locator.clone(),
            name: f.name.clone(),
        })
        .collect();
    functions.sort_by_key(|f| offset_of(&f.locator));
    let exp = FixtureExpectations {
        binary_path: binary,
        program,
        functions,
        rename_to: "kraken_renamed_fn".into(),
        scratch,
    };
    let engine = new_engine(&scout_dir.path().join("project"));
    run_contract_suite(&engine, &exp).await.unwrap_or_else(|e| {
        panic!(
            "{e}\nsidecar log tail:\n{}",
            engine.diagnostics().log_tail.join("\n")
        )
    });
    engine.shutdown().await;
}

const HELPER_ENV: &str = "KRAKEN_KILL_PARENT_HELPER";

/// Runs inside a child process (see [`killing_the_parent_kills_the_jvm`]): starts the sidecar,
/// prints its pid and then just sleeps until it is killed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "helper process of killing_the_parent_kills_the_jvm"]
async fn kill_parent_helper() {
    if std::env::var_os(HELPER_ENV).is_none() {
        return;
    }
    let dir = scratch_dir();
    let engine = new_engine(&dir.path().join("project"));
    engine
        .open_binary(
            &corpus_binary(),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open_binary");
    let pid = engine.diagnostics().pid.expect("pid");
    println!("JVM_PID={pid}");
    tokio::time::sleep(Duration::from_secs(120)).await;
}

fn process_gone(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        // `pid (comm) S ...`: a zombie is as dead as it gets
        Ok(stat) => {
            stat.rsplit_once(')')
                .and_then(|(_, rest)| rest.trim_start().chars().next())
                == Some('Z')
        }
    }
}

#[test]
#[ignore = "needs a real Ghidra (cargo xtask ghidra-ext)"]
fn killing_the_parent_kills_the_jvm() {
    let exe = std::env::current_exe().unwrap();
    let mut helper = Command::new(exe)
        .args([
            "--exact",
            "kill_parent_helper",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HELPER_ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn helper");
    let stdout = helper.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // libtest prefixes the line with "test <name> ... "
            if let Some(i) = line.find("JVM_PID=") {
                let _ = tx.send(line[i + 8..].trim().parse::<u32>().unwrap());
            }
        }
    });
    let jvm = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(pid) => pid,
        Err(e) => {
            let _ = helper.kill();
            panic!("the helper never reported a JVM pid: {e}");
        }
    };
    assert!(!process_gone(jvm), "JVM {jvm} should be running");

    helper.kill().expect("kill -9 the parent"); // SIGKILL
    let _ = helper.wait();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !process_gone(jvm) {
        if Instant::now() > deadline {
            // clean up before failing
            // SAFETY: signalling a pid we know belongs to the leaked JVM.
            unsafe { libc::kill(jvm as i32, libc::SIGKILL) };
            panic!("the JVM {jvm} survived the death of its parent");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The sidecar must not be able to reach the network. The kernel-level checks (a real TCP
/// connect and bind from a child under the same confinement code) live in the crate's
/// `sandbox::tests::network_is_denied_inside_the_sandbox`; the Ghidra sidecar has no
/// "connect" method, so here we assert that the confinement report of the live JVM says the
/// network is blocked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real Ghidra (cargo xtask ghidra-ext)"]
async fn live_sidecar_reports_network_confinement() {
    let dir = scratch_dir();
    let engine = new_engine(&dir.path().join("project"));
    engine
        .open_binary(
            &corpus_binary(),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open_binary");
    let d = engine.diagnostics();
    assert_eq!(d.state, "running");
    let report = d.confinement.expect("report");
    eprintln!("confinement: {report}");
    assert!(report.filesystem && report.network_blocked(), "{report}");
    assert!(report.parent_death_signal);
    assert!(d.heap_mb.unwrap_or(0) >= 1024);
    assert!(engine.capabilities().has(kraken_engine::Cap::Mutator));
    engine.shutdown().await;
    assert_eq!(engine.diagnostics().state, "exited");
}

/// switch_vm-O0 compiles its dispatch loop to a jump table: the CFG of that function must carry
/// `switch` edges that lead to blocks of the function, and the listing a computed jump.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real Ghidra (cargo xtask ghidra-ext)"]
async fn switch_vm_o0_cfg_has_switch_edges() {
    use kraken_engine::{DisasmRequest, Disassembler, FlowGraph};
    use kraken_proto::{CfgEdgeKind, DisasmScope, FlowKind};

    let name = "switch_vm-O0";
    let binary = repo_root().join("corpus/bin").join(name);
    let truth: Truth = serde_json::from_slice(
        &std::fs::read(repo_root().join(format!("corpus/truth/{name}.json"))).expect("truth"),
    )
    .expect("truth json");
    let dir = scratch_dir();
    let engine = new_engine(&dir.path().join("project"));
    let program = open_and_analyze(&engine, &binary).await;
    let cancel = CancellationToken::new();

    let mut with_switch = Vec::new();
    for t in &truth.functions {
        let at = program.base.0 + t.entry.0;
        let cfg = engine
            .cfg(&Locator::ram(at), &cancel)
            .await
            .unwrap_or_else(|e| panic!("cfg of {} at {at:#x}: {e}", t.name));
        for e in &cfg.edges {
            assert!(
                cfg.blocks.iter().any(|b| b.start == e.from)
                    && cfg.blocks.iter().any(|b| b.start == e.to),
                "{}: dangling edge {e:?}",
                t.name
            );
        }
        let cases = cfg
            .edges
            .iter()
            .filter(|e| e.kind == CfgEdgeKind::Switch)
            .count();
        if cases > 0 {
            with_switch.push((t.name.clone(), at, cases, cfg));
        }
    }
    eprintln!(
        "functions with switch edges: {:?}",
        with_switch
            .iter()
            .map(|(n, _, c, _)| (n.as_str(), *c))
            .collect::<Vec<_>>()
    );
    assert!(
        !with_switch.is_empty(),
        "no function of {name} has a switch edge"
    );
    let (name, at, cases, cfg) = with_switch
        .iter()
        .max_by_key(|(_, _, c, _)| *c)
        .expect("one");
    assert!(*cases >= 3, "{name}: only {cases} switch edges");
    // every switch edge starts at the block that ends in the computed jump
    let source = cfg
        .edges
        .iter()
        .find(|e| e.kind == CfgEdgeKind::Switch)
        .expect("edge")
        .from;
    let rows = engine
        .disassemble(
            &DisasmRequest {
                start: Hex64(*at),
                scope: DisasmScope::Function,
            },
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &cancel,
        )
        .await
        .expect("disassemble");
    let block = cfg
        .blocks
        .iter()
        .find(|b| b.start == source)
        .expect("source block");
    let last = rows
        .items
        .iter()
        .rfind(|r| r.address >= block.start && r.address < block.end)
        .expect("last instruction of the block");
    assert_eq!(last.flow, FlowKind::Indirect, "{name}: {last:?}");
    engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a real Ghidra (cargo xtask ghidra-ext)"]
async fn the_sleigh_assembler_encodes_lines_in_either_case() {
    let dir = scratch_dir();
    let engine = new_engine(&dir.path().join("project"));
    let info = open_and_analyze(&engine, &corpus_binary()).await;
    let cancel = CancellationToken::new();
    let asm = engine.assembler().expect("assembler");
    let at = Locator::ram(info.base.0 + 0x1266);
    let enc = asm
        .assemble(&at, "SUB EAX, EDX", &cancel)
        .await
        .expect("sub");
    assert_eq!(enc[0], [0x29, 0xd0]);
    let enc = asm
        .assemble(&at, "mov eax, 0x7", &cancel)
        .await
        .expect("lower case");
    assert_eq!(enc[0], [0xb8, 7, 0, 0, 0]);
    // A short jump two bytes ahead is relative to `at`.
    let target = format!("JMP {:#x}", info.base.0 + 0x1268);
    let enc = asm.assemble(&at, &target, &cancel).await.expect("jmp");
    assert_eq!(enc[0], [0xeb, 0x00]);
    let e = asm
        .assemble(&at, "frobnicate rax", &cancel)
        .await
        .expect_err("not an instruction");
    assert_eq!(e.code, kraken_proto::ErrorCode::InvalidArgument);
}

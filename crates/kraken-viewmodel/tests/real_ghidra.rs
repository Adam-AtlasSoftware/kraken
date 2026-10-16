//! The GUI view-model against a real Ghidra through a spawned `krakend`. `#[ignore]`d:
//!
//! ```text
//! cargo xtask ghidra-ext && cargo build -p krakend && \
//!   env KRAKEN_GHIDRA_HOME=... KRAKEN_JAVA_HOME=... \
//!   cargo test -p kraken-viewmodel --test real_ghidra -- --ignored --nocapture
//! ```
//!
//! The daemon runs in a private runtime directory with a private (empty) configuration, so the
//! developer's own daemon is never touched, and it is stopped at the end of the test.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kraken_host::daemon::{StartOptions, find_krakend, wait_until_stopped};
use kraken_ipc::{DaemonInfo, RuntimeDir};
use kraken_viewmodel::{
    AnalysisPhase, BackendOptions, Connection, DaemonClientBackend, ViewModel, start_connector,
};

const SLOW: Duration = Duration::from_secs(300);

struct Daemon {
    rt: Arc<tokio::runtime::Runtime>,
    dir: RuntimeDir,
    backend: Arc<DaemonClientBackend>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Ask politely, then insist: no krakend or JVM may outlive the test.
        let b = self.backend.clone();
        self.rt.block_on(async {
            let _ = tokio::time::timeout(Duration::from_secs(5), b.shutdown_daemon()).await;
        });
        let stopped = self
            .rt
            .block_on(wait_until_stopped(&self.dir, Duration::from_secs(30)));
        if !stopped && let Ok(Some(info)) = DaemonInfo::read(&self.dir.info_path()) {
            let _ = std::process::Command::new("kill")
                .arg(info.pid.to_string())
                .status();
        }
    }
}

fn corpus_binary() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/pie_list-O0")
}

#[test]
#[ignore = "needs Ghidra, a JDK, the built extension and a built krakend"]
fn the_gui_view_model_creates_analyzes_lists_and_renames_through_a_spawned_daemon() {
    // Ghidra rejects dot-prefixed path elements, so no `.tmpXXXX` directory.
    let tmp = tempfile::Builder::new()
        .prefix("kraken-vm-real")
        .tempdir()
        .expect("temp dir");
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "").expect("empty config");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let krakend = find_krakend().expect("build krakend first: cargo build -p krakend");
    let start = StartOptions {
        krakend: Some(krakend),
        env: vec![
            ("KRAKEN_RUNTIME_DIR".into(), dir.path().into()),
            ("KRAKEN_CONFIG".into(), config.into()),
            ("KRAKEN_DAEMON_IDLE_SECS".into(), "300".into()),
        ],
        timeout: Duration::from_secs(60),
        ..Default::default()
    };

    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime"),
    );
    let backend = Arc::new(
        rt.block_on(DaemonClientBackend::connect(
            start_connector(dir.clone(), start),
            BackendOptions::default(),
        ))
        .expect("the GUI starts and reaches krakend"),
    );
    let _daemon = Daemon {
        rt: rt.clone(),
        dir: dir.clone(),
        backend: backend.clone(),
    };

    let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
    let project = tmp.path().join("proj");
    vm.create_project(
        corpus_binary().to_string_lossy().into_owned(),
        project.to_string_lossy().into_owned(),
    );
    assert!(
        vm.block_until(SLOW, |v| !matches!(v.connection, Connection::Opening(_))),
        "project_create finishes"
    );
    assert_eq!(vm.connection, Connection::Open, "{:?}", vm.toasts);
    assert_eq!(vm.project.as_ref().map(|p| p.format.as_str()), Some("elf"));

    vm.start_analysis();
    assert!(
        vm.block_until(SLOW, |v| {
            v.analysis.phase != AnalysisPhase::Running && !v.busy() && !v.functions.items.is_empty()
        }),
        "analysis finishes: {:?} {:?}",
        vm.analysis,
        vm.toasts
    );
    assert_eq!(
        vm.analysis.phase,
        AnalysisPhase::Complete,
        "{:?}",
        vm.analysis
    );
    let count = vm.functions.items.len();
    assert!(count >= 10, "pie_list has dozens of functions, got {count}");
    println!("analyzed: {count} functions loaded");

    // Rename one function the engine named itself, as the person would.
    let (addr, old) = {
        let f = vm
            .functions
            .items
            .iter()
            .find(|f| f.name.starts_with("FUN_"))
            .expect("a default-named function");
        (f.address, f.name.clone())
    };
    vm.begin_rename(addr, Some(&old));
    vm.set_rename_input("gui_renamed_entry");
    vm.submit_rename();
    assert!(
        vm.block_until(SLOW, |v| {
            v.rename.is_none()
                && !v.busy()
                && v.functions
                    .items
                    .iter()
                    .any(|f| f.name == "gui_renamed_entry")
        }),
        "rename applied: {:?} {:?}",
        vm.rename,
        vm.toasts
    );
    assert!(
        vm.history
            .entries
            .iter()
            .any(|h| h.op == "rename" && !h.by_agent),
        "history shows the edit"
    );
    println!("renamed {old} -> gui_renamed_entry at {addr:#x}");

    // The program views against the real engine: listing, graph, hex, xrefs, strings, symbols.
    let main = vm
        .functions
        .items
        .iter()
        .find(|f| f.name == "main")
        .expect("main")
        .address;
    vm.select_function(main);
    assert!(
        vm.block_until(SLOW, |v| {
            !v.busy()
                && v.current
                    .as_ref()
                    .is_some_and(|c| c.decompiled.ready().is_some())
        }),
        "main decompiles"
    );
    {
        let d = vm
            .current
            .as_ref()
            .and_then(|c| c.decompiled.ready())
            .expect("decompiled");
        assert!(
            d.result.tokens.iter().any(|t| t.target.is_some()),
            "the server's token spans carry call targets"
        );
    }
    vm.ensure_graph();
    vm.ensure_xrefs();
    vm.ensure_strings();
    vm.ensure_symbols(kraken_viewmodel::SymbolTable::Imports);
    assert!(
        vm.block_until(SLOW, |v| {
            !v.busy()
                && v.views.graph.data.is_some()
                && v.views.strings.loaded
                && v.views.imports.loaded
        }),
        "views load: {:?}",
        vm.views.graph.error
    );
    let v = &vm.views;
    assert!(v.listing.rows.len() > 50 && v.listing.rows[0].address <= main + 1);
    let graph = v.graph.data.as_ref().expect("graph");
    assert!(graph.blocks.len() > 5 && !graph.edges.is_empty());
    assert_eq!(
        graph.blocks.iter().map(|b| b.lines.len()).sum::<usize>(),
        v.listing.rows.len()
    );
    assert!(!v.xrefs.callees.items.is_empty());
    assert!(!v.strings.items.is_empty() && !v.imports.items.is_empty());
    let text = v
        .memory
        .blocks
        .iter()
        .find(|b| b.name == ".text")
        .expect(".text");
    assert!(text.contains(main));
    let first = &v.listing.rows[0];
    assert_eq!(v.bytes.byte(first.address), first.bytes.first().copied());
    println!(
        "views: {} rows, {} blocks, {} callees, {} strings, {} imports",
        v.listing.rows.len(),
        graph.blocks.len(),
        v.xrefs.callees.items.len(),
        v.strings.items.len(),
        v.imports.items.len()
    );
}

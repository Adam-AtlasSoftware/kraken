//! The GUI view-model against a native-engine project through a spawned `krakend`: functions,
//! decompiler, listing, graph, xrefs, strings, rename, undo, history and an assistant explanation
//! with a scripted provider. No Java and no Ghidra install.
//!
//! The test skips (with a note) when the pieces are missing: a built `krakend` and
//! `kraken-native-worker` next to each other (`cargo build -p krakend -p engine-native`, or point
//! `KRAKEN_KRAKEND` at a release build) and the compiled Sleigh files (`kraken setup --native`).
//!
//! The daemon runs in a private runtime directory with a private configuration, and is stopped at
//! the end of the test.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kraken_host::daemon::{StartOptions, find_krakend, wait_until_stopped};
use kraken_ipc::{DaemonInfo, RuntimeDir};
use kraken_registry::EngineChoice;
use kraken_viewmodel::assist::ChatItem;
use kraken_viewmodel::assist::script::{answer, scripted_provider, tool_call};
use kraken_viewmodel::{
    AnalysisPhase, BackendOptions, Connection, DaemonClientBackend, SymbolTable, ViewModel,
    start_connector,
};
use serde_json::json;

const SLOW: Duration = Duration::from_secs(120);

struct Daemon {
    rt: Arc<tokio::runtime::Runtime>,
    dir: RuntimeDir,
    backend: Arc<DaemonClientBackend>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
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

fn skip(why: &str) {
    eprintln!("skipping the native GUI test: {why}");
}

#[test]
fn the_gui_view_model_works_end_to_end_on_a_native_project() {
    let Ok(krakend) = find_krakend() else {
        return skip("no krakend (cargo build -p krakend -p engine-native, or set KRAKEN_KRAKEND)");
    };
    let worker = krakend.with_file_name("kraken-native-worker");
    if !worker.is_file() {
        return skip("no kraken-native-worker next to krakend (cargo build -p engine-native)");
    }
    let probe = kraken_host::native::NativeProbe::detect(None);
    if let Some(problem) = probe.problem() {
        // The probe looks for the worker next to this test binary; that one may be absent while
        // the daemon's own is there. Only the missing specs matter here.
        if problem.contains("Sleigh") || problem.contains("sla") {
            return skip(&problem);
        }
    }

    let tmp = tempfile::Builder::new()
        .prefix("kraken-vm-native")
        .tempdir()
        .expect("temp dir");
    let config = tmp.path().join("config.toml");
    std::fs::write(&config, "").expect("empty config");
    let dir = RuntimeDir::from_dir(tmp.path().join("rt")).expect("runtime dir");
    let start = StartOptions {
        krakend: Some(krakend),
        env: vec![
            ("KRAKEN_RUNTIME_DIR".into(), dir.path().into()),
            ("KRAKEN_CONFIG".into(), config.into()),
            ("KRAKEN_DAEMON_IDLE_SECS".into(), "300".into()),
            ("KRAKEN_NATIVE_WORKER".into(), worker.into()),
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
    vm.create_project_with(
        corpus_binary().to_string_lossy().into_owned(),
        project.to_string_lossy().into_owned(),
        Some(EngineChoice::Native),
    );
    assert!(vm.block_until(SLOW, |v| !matches!(v.connection, Connection::Opening(_))));
    assert_eq!(vm.connection, Connection::Open, "{:?}", vm.toasts);
    let info = vm.project.as_ref().expect("project info");
    assert_eq!(info.engine, "native", "{info:?}");
    assert_eq!(info.format, "elf");

    vm.start_analysis();
    assert!(
        vm.block_until(SLOW, |v| {
            v.analysis.phase != AnalysisPhase::Running && !v.busy() && !v.functions.items.is_empty()
        }),
        "analysis finishes: {:?} {:?}",
        vm.analysis,
        vm.toasts
    );
    assert_eq!(vm.analysis.phase, AnalysisPhase::Complete);
    assert!(vm.functions.items.len() >= 10);

    // Decompiler, with call targets in the token spans.
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
        assert!(d.result.tokens.iter().any(|t| t.target.is_some()));
    }

    // Listing, graph, xrefs, strings, imports, memory map and bytes.
    vm.ensure_graph();
    vm.ensure_xrefs();
    vm.ensure_strings();
    vm.ensure_symbols(SymbolTable::Imports);
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
    assert!(v.listing.rows.len() > 20 && v.listing.rows[0].address <= main + 1);
    let graph = v.graph.data.as_ref().expect("graph");
    assert!(graph.blocks.len() > 3 && !graph.edges.is_empty());
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

    // Rename, undo, history.
    let (addr, old) = {
        let f = vm
            .functions
            .items
            .iter()
            .find(|f| f.name.starts_with("FUN_") && f.address != main)
            .expect("a default-named function");
        (f.address, f.name.clone())
    };
    vm.begin_rename(addr, Some(&old));
    vm.set_rename_input("native_renamed");
    vm.submit_rename();
    assert!(
        vm.block_until(SLOW, |v| {
            v.rename.is_none()
                && !v.busy()
                && v.functions.items.iter().any(|f| f.name == "native_renamed")
        }),
        "rename applied: {:?} {:?}",
        vm.rename,
        vm.toasts
    );
    vm.refresh_history();
    assert!(vm.block_until(SLOW, |v| !v.busy()));
    assert!(
        vm.history
            .entries
            .iter()
            .any(|h| h.op == "rename" && !h.by_agent && !h.undone)
    );
    vm.undo_last();
    assert!(
        vm.block_until(SLOW, |v| {
            !v.busy()
                && v.functions.items.iter().any(|f| f.name == old)
                && !v.functions.items.iter().any(|f| f.name == "native_renamed")
        }),
        "undo restores {old}: {:?}",
        vm.toasts
    );
    vm.refresh_history();
    assert!(vm.block_until(SLOW, |v| !v.busy()));
    assert!(vm.history.entries.iter().any(|h| h.is_undo));
    assert!(
        vm.history
            .entries
            .iter()
            .any(|h| h.op == "rename" && h.undone)
    );

    // The assistant explains `main` with a scripted provider; its tool calls run against the
    // native engine through the daemon, and explaining edits nothing.
    let a = format!("{main:#x}");
    let result = json!({
        "summary": "It builds a small list and prints it.",
        "key_behaviours": ["allocates nodes", "prints each one"],
        "suggested_names": [{"name": "run_list_demo", "reason": "it only exercises the list"}],
        "caveats": ["I did not check every callee"]
    });
    let (provider, badge) = scripted_provider(
        vec![
            tool_call("c1", "get_function", json!({"address": a})),
            tool_call("c2", "decompile", json!({"address": a})),
            answer("It builds a small list and prints it.", &result),
        ],
        "test-model",
    );
    vm.assist.set_provider(provider, badge);
    let before = vm.history.entries.len();
    vm.assist_explain_function(main);
    assert!(
        vm.block_until(SLOW, |v| !v.assist.busy() && !v.busy()),
        "{:?}",
        vm.assist.items
    );
    let Some(ChatItem::Explanation(card)) = vm.assist.items.last() else {
        panic!("expected a card: {:?}", vm.assist.items);
    };
    assert_eq!(card.address, Some(main));
    assert_eq!(card.suggested_names[0].0, "run_list_demo");
    let chips: Vec<_> = vm
        .assist
        .items
        .iter()
        .filter_map(|i| match i {
            ChatItem::Tool(t) => Some(t),
            _ => None,
        })
        .collect();
    assert_eq!(chips.len(), 2, "{:?}", vm.assist.items);
    assert!(chips.iter().all(|c| !c.is_error), "{chips:?}");
    vm.refresh_history();
    assert!(vm.block_until(SLOW, |v| !v.busy()));
    assert_eq!(vm.history.entries.len(), before);
}

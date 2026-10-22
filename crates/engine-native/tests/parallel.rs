//! Discovery on several sessions finds exactly what one session finds, and a run that takes its
//! jump tables from the cache of an earlier one finds the same again without asking the
//! decompiler. Needs the native build and a spec tree (see `tests/native.rs`); skips otherwise.

use std::path::{Path, PathBuf};

use engine_native::discover::{Discovery, JumpCache, Options, discover};
use engine_native::elf::load;
use engine_native::{NativeConfig, NativeEngine};
use engine_native_sys::Session;
use tokio_util::sync::CancellationToken;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(
    data: &[u8],
    use_symbols: bool,
    cache: JumpCache,
    threads: usize,
    min_code: u64,
) -> Discovery {
    let loaded = load(data, None).expect("load");
    let mut session = Session::new(
        loaded.language.id,
        loaded.language.compiler,
        loaded.image.clone(),
    )
    .expect("session");
    discover(
        &loaded,
        &mut session,
        &CancellationToken::new(),
        Options {
            cache,
            threads,
            parallel_min_code: min_code,
            ..Options::new(use_symbols)
        },
    )
    .expect("discovery")
    .expect("not cancelled")
}

#[test]
fn lanes_and_the_cache_do_not_change_what_is_found() {
    let Some(config) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree");
        return;
    };
    if !NativeEngine::is_usable(&config) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    engine_native_sys::start(&config.spec_root).expect("library");
    for name in [
        "bin/switch_vm-O0",
        "bin/switch_vm-O2-stripped",
        "bin/pie_list-O2",
        "bin/cpp_shapes-O0",
        "bin/stripped_calc-O2-stripped",
        // PIC thunks are named during the walks
        "elf32/bin/switch_vm-i386-O2-stripped",
        "elf32/bin/pie_list-i386-O0-stripped",
        "pe/bin/win_tls-x86-O2-stripped.exe",
        "pe/bin/switch_vm-x64-O2.exe",
    ] {
        let data = std::fs::read(root().join("corpus").join(name)).expect("corpus binary");
        for use_symbols in [true, false] {
            let one = run(&data, use_symbols, JumpCache::default(), 1, 0);
            let four = run(&data, use_symbols, JumpCache::default(), 4, 0);
            assert_eq!(one.functions, four.functions, "{name}: functions");
            assert_eq!(one.insns, four.insns, "{name}: instructions");
            assert_eq!(one.rounds, four.rounds, "{name}: rounds");
            assert_eq!(one.jumps, four.jumps, "{name}: jump tables used");
            assert!(one.recovered > 0 || one.jumps.is_empty(), "{name}");

            // the progress report says how many functions were found so far
            let reports = std::sync::Mutex::new(Vec::new());
            let report = |d: &engine_native::discover::DiscoverProgress| {
                reports.lock().unwrap().push((d.found, d.queued))
            };
            let loaded = load(&data, None).expect("load");
            let mut session = Session::new(
                loaded.language.id,
                loaded.language.compiler,
                loaded.image.clone(),
            )
            .expect("session");
            let reported = discover(
                &loaded,
                &mut session,
                &CancellationToken::new(),
                Options {
                    threads: 2,
                    parallel_min_code: 0,
                    progress: Some(&report),
                    ..Options::new(use_symbols)
                },
            )
            .expect("discovery")
            .expect("not cancelled");
            let reports = reports.into_inner().unwrap();
            assert!(!reports.is_empty(), "{name}: progress");
            assert_eq!(
                reports.last().map(|r| r.1),
                Some(0),
                "{name}: the last report has nothing left to walk"
            );
            assert_eq!(one.functions, reported.functions, "{name}: reported run");

            let cached = run(&data, use_symbols, one.jumps.clone(), 4, 0);
            assert_eq!(
                cached.recovered, 0,
                "{name}: nothing asked of the decompiler"
            );
            assert_eq!(one.functions, cached.functions, "{name}: cached functions");
            assert_eq!(one.insns, cached.insns, "{name}: cached instructions");
            assert_eq!(one.jumps, cached.jumps, "{name}: cached log");
        }
    }
}

/// The analysis job decompiles on several sessions at once (forks of the program's session):
/// with one session or four it fills in exactly the same signatures, through the worker as a
/// project runs it.
#[tokio::test(flavor = "multi_thread")]
async fn analysis_lanes_do_not_change_the_signatures() {
    use kraken_engine::{AnalyzeRequest, Analyzer, FunctionLister, Loader, LoaderSpec};
    use kraken_proto::PageRequest;

    let Some(mut config) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree");
        return;
    };
    if !NativeEngine::is_usable(&config) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    config.isolation = engine_native::Isolation::Worker(
        engine_native::WorkerOptions::with_program(env!("CARGO_BIN_EXE_kraken-native-worker")),
    );
    // static C library code: enough functions for the job to use several sessions
    for name in ["bin/static_strops-O2", "bin/cpp_shapes-O2"] {
        let mut runs = Vec::new();
        for threads in [1, 4] {
            let mut c = config.clone();
            c.discovery_threads = Some(threads);
            let e = NativeEngine::new(c);
            let cancel = CancellationToken::new();
            e.open_binary(
                &root().join("corpus").join(name),
                &LoaderSpec::default(),
                &cancel,
            )
            .await
            .expect("open");
            let mut job = e
                .analyze(AnalyzeRequest::default(), cancel.clone())
                .await
                .expect("analyze");
            let mut last = None;
            while let Some(p) = job.next_progress().await {
                assert!(p.done <= p.total, "{name}: {p:?}");
                last = Some(p.message);
            }
            job.wait().await.expect("analysis");
            let mut fns = Vec::new();
            let mut cursor = None;
            loop {
                let page = e
                    .list_functions(
                        &PageRequest {
                            cursor,
                            limit: Some(500),
                        },
                        &cancel,
                    )
                    .await
                    .expect("list");
                fns.extend(
                    page.items
                        .into_iter()
                        .map(|f| (f.locator, f.name, f.signature)),
                );
                match page.next_cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            runs.push((fns, last));
        }
        assert!(
            runs[0].0.len() >= 32,
            "{name}: big enough for several sessions"
        );
        assert!(
            runs[0].0.iter().all(|f| f.2.is_some()),
            "{name}: every function has a signature"
        );
        assert_eq!(runs[0], runs[1], "{name}");
    }
}

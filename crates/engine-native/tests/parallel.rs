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

//! Rust symbols (legacy and v0 mangling, `corpus/lang`) are shown demangled, with the mangled
//! name kept; a stripped build keeps only the C-named `main`. Needs the native build and a spec
//! tree (`cargo xtask native-sla`); skips otherwise.

use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{CancellationToken, FunctionLister, Loader, LoaderSpec};
use kraken_proto::{FunctionSummary, PageRequest};

fn bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/lang/bin")
        .join(name)
}

async fn functions(name: &str) -> Option<Vec<FunctionSummary>> {
    let mut c = NativeConfig::discover()?;
    if !NativeEngine::is_usable(&c) {
        return None;
    }
    c.isolation = Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )));
    let e = NativeEngine::new(c);
    let cancel = CancellationToken::new();
    e.open_binary(&bin(name), &LoaderSpec::default(), &cancel)
        .await
        .expect("open_binary");
    let page = e
        .list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &cancel,
        )
        .await
        .expect("list");
    Some(page.items)
}

fn find<'a>(fns: &'a [FunctionSummary], name: &str) -> Vec<&'a FunctionSummary> {
    fns.iter().filter(|f| f.name == name).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn rust_names_are_demangled_for_both_manglings() {
    for (file, prefix) in [("rust_hello-legacy", "_ZN"), ("rust_hello-v0", "_R")] {
        let Some(fns) = functions(file).await else {
            eprintln!("skipped: no native engine here");
            return;
        };
        for want in ["say", "checksum"] {
            let f = find(&fns, want);
            assert_eq!(f.len(), 1, "{file}: {want} in {:?}", names(&fns));
            let m = f[0].mangled.as_deref().expect("mangled name kept");
            assert!(m.starts_with(prefix) && m.contains("rust_hello"), "{m}");
        }
        // the two Greeting<T>::weight instances
        assert_eq!(find(&fns, "weight").len(), 2, "{file}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stripped_rust_build_has_no_rust_names() {
    let Some(fns) = functions("rust_hello-v0-stripped").await else {
        eprintln!("skipped: no native engine here");
        return;
    };
    assert!(find(&fns, "say").is_empty() && find(&fns, "checksum").is_empty());
    assert!(fns.iter().all(|f| f.mangled.is_none()), "{:?}", names(&fns));
}

fn names(fns: &[FunctionSummary]) -> Vec<&str> {
    fns.iter().map(|f| f.name.as_str()).collect()
}

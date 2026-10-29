//! The native engine on raw images (`corpus/raw`): flat blobs from `objcopy -O binary`, opened
//! with a processor, a base address and an entry point. Skips without the native build and the
//! Sleigh specs (`cargo xtask native-sla`).

use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{
    CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, ProgramInfo,
};
use kraken_proto::{Hex64, Locator, PageRequest};

fn blob(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/raw")
        .join(name)
}

fn engine(isolation: Isolation) -> Option<NativeEngine> {
    let mut c = NativeConfig::discover()?;
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = isolation;
    Some(NativeEngine::new(c))
}

fn worker() -> Isolation {
    Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )))
}

async fn open(e: &NativeEngine, name: &str, spec: &LoaderSpec) -> ProgramInfo {
    let cancel = CancellationToken::new();
    e.open_binary(&blob(name), spec, &cancel).await.unwrap()
}

async fn names(e: &NativeEngine) -> Vec<(u64, String)> {
    let page = e
        .list_functions(&PageRequest::default(), &CancellationToken::new())
        .await
        .unwrap();
    page.items
        .into_iter()
        .map(|f| match f.locator {
            Locator::Native { offset, .. } => (offset.0, f.name),
            other => panic!("unexpected locator {other:?}"),
        })
        .collect()
}

fn cortex_spec() -> LoaderSpec {
    LoaderSpec {
        format: Some("raw".into()),
        arch: Some("cortex-m".into()),
        base: Some(Hex64(0x0800_0000)),
        ..LoaderSpec::default()
    }
}

#[tokio::test]
async fn a_cortex_m_blob_opens_with_its_vector_table_named() {
    for iso in [worker(), Isolation::InProcess] {
        let Some(e) = engine(iso) else { return };
        let info = open(&e, "fw_cortexm.bin", &cortex_spec()).await;
        assert_eq!(info.format, "raw");
        assert_eq!(info.arch, "ARM:LE:32:Cortex");
        assert_eq!(info.base, Hex64(0x0800_0000));
        let found = names(&e).await;
        let at = |a: u64| found.iter().find(|(x, _)| *x == a).map(|(_, n)| n.as_str());
        assert_eq!(at(0x0800_00dc), Some("Reset_Handler"), "{found:?}");
        assert_eq!(at(0x0800_007a), Some("SysTick_Handler"), "{found:?}");
        // fib and checksum are reached by calls from main
        assert!(
            at(0x0800_0040).is_some() && at(0x0800_005e).is_some(),
            "{found:?}"
        );
    }
}

#[tokio::test]
async fn an_x86_blob_decompiles_at_its_base() {
    let Some(e) = engine(Isolation::InProcess) else {
        return;
    };
    let spec = LoaderSpec {
        format: Some("raw".into()),
        arch: Some("x86".into()),
        base: Some(Hex64(0x10_0000)),
        ..LoaderSpec::default()
    };
    open(&e, "fw_x86.bin", &spec).await;
    let found = names(&e).await;
    assert!(
        found.iter().any(|(a, n)| *a == 0x10_0000 && n == "entry"),
        "{found:?}"
    );
    assert!(found.iter().any(|(a, _)| *a == 0x10_002a), "{found:?}");
    let d = e
        .decompile(&Locator::ram(0x10_002a), &CancellationToken::new())
        .await
        .unwrap();
    assert!(
        d.text.contains("% ") || d.text.contains("param_1"),
        "{}",
        d.text
    );
}

#[tokio::test]
async fn bad_raw_options_are_refused() {
    let Some(e) = engine(Isolation::InProcess) else {
        return;
    };
    let cancel = CancellationToken::new();
    let mut spec = cortex_spec();
    spec.arch = None;
    assert!(
        e.open_binary(&blob("fw_cortexm.bin"), &spec, &cancel)
            .await
            .is_err()
    );
    let mut spec = cortex_spec();
    spec.arch = Some("z80".into());
    assert!(
        e.open_binary(&blob("fw_cortexm.bin"), &spec, &cancel)
            .await
            .is_err()
    );
    let mut spec = cortex_spec();
    spec.entry = Some(Hex64(0x1000));
    assert!(
        e.open_binary(&blob("fw_cortexm.bin"), &spec, &cancel)
            .await
            .is_err()
    );
}

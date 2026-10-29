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

fn hex_spec(format: &str) -> LoaderSpec {
    LoaderSpec {
        format: Some(format.into()),
        arch: Some("cortex-m".into()),
        ..LoaderSpec::default()
    }
}

#[tokio::test]
async fn intel_hex_and_srec_open_at_their_real_addresses() {
    for (file, format) in [("fw_cortexm.hex", "ihex"), ("fw_cortexm.srec", "srec")] {
        for iso in [worker(), Isolation::InProcess] {
            let Some(e) = engine(iso) else { return };
            let info = open(&e, file, &hex_spec(format)).await;
            assert_eq!(info.format, format);
            assert_eq!(info.arch, "ARM:LE:32:Cortex");
            assert_eq!(info.base, Hex64(0x0800_0000));
            let found = names(&e).await;
            let at = |a: u64| found.iter().find(|(x, _)| *x == a).map(|(_, n)| n.as_str());
            assert_eq!(at(0x0800_00dc), Some("Reset_Handler"), "{file}: {found:?}");
            assert_eq!(
                at(0x0800_007a),
                Some("SysTick_Handler"),
                "{file}: {found:?}"
            );
            let d = e
                .decompile(&Locator::ram(0x0800_0040), &CancellationToken::new())
                .await
                .unwrap();
            assert!(d.text.contains("return"), "{}", d.text);
        }
    }
}

#[tokio::test]
async fn a_hex_file_with_two_blocks_maps_both() {
    let Some(e) = engine(Isolation::InProcess) else {
        return;
    };
    // the same program split into two blocks with a gap, as a bootloader plus an application
    let bin = std::fs::read(blob("fw_cortexm.bin")).unwrap();
    let rec = |addr: u16, ty: u8, data: &[u8]| {
        let mut r = vec![data.len() as u8, (addr >> 8) as u8, addr as u8, ty];
        r.extend(data);
        let sum = r.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        r.push(sum.wrapping_neg());
        let hex: String = r.iter().map(|b| format!("{b:02X}")).collect();
        format!(":{hex}\n")
    };
    let mut text = rec(0, 4, &[0x08, 0x00]);
    for (i, c) in bin[..0x80].chunks(16).enumerate() {
        text += &rec((i * 16) as u16, 0, c);
    }
    for (i, c) in bin[0xc0..].chunks(16).enumerate() {
        text += &rec((0xc0 + i * 16) as u16, 0, c);
    }
    text += &rec(0, 1, &[]);
    let dir = std::env::temp_dir().join(format!("kr-hex2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("two.hex");
    std::fs::write(&path, text).unwrap();
    let info = e
        .open_binary(&path, &hex_spec("ihex"), &CancellationToken::new())
        .await
        .unwrap();
    assert!(info.description.unwrap_or_default().contains("2 blocks"));
    let found = names(&e).await;
    assert!(found.iter().any(|(a, _)| *a == 0x0800_00dc), "{found:?}");
    std::fs::remove_dir_all(&dir).ok();
}

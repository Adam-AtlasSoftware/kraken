//! The native engine on the Mach-O set (`corpus/macho`, x86-64 and arm64 built without an Apple
//! SDK): the loader's shape, chained fixups and the older binding tables, a universal binary, the
//! decompiler on both architectures, truth recall and the contract suite. Needs the native build
//! and a spec tree (`cargo xtask native-sla` compiles both); skips otherwise.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use engine_native::macho::load;
use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, ProgramInfo,
};
use kraken_proto::{FunctionSummary, Hex64, Locator, PageRequest};
use serde_json::Value;

fn bin(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/macho/bin")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(bin(name)).expect("corpus binary")
}

fn config() -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )));
    Some(c)
}

async fn open(path: &Path, spec: &LoaderSpec) -> Option<(NativeEngine, ProgramInfo)> {
    let e = NativeEngine::new(config()?);
    let info = e
        .open_binary(path, spec, &CancellationToken::new())
        .await
        .expect("open");
    Some((e, info))
}

async fn functions(e: &NativeEngine) -> Vec<FunctionSummary> {
    let cancel = CancellationToken::new();
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let p = e
            .list_functions(
                &PageRequest {
                    cursor,
                    limit: Some(500),
                },
                &cancel,
            )
            .await
            .expect("list");
        out.extend(p.items);
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

async fn decompiled(e: &NativeEngine, name: &str) -> String {
    let all = functions(e).await;
    let f = all
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no {name}"));
    e.decompile(&f.locator, &CancellationToken::new())
        .await
        .expect("decompile")
        .text
}

#[test]
fn segments_become_ghidra_blocks() {
    let l = load(&read("pie_list-arm64-O2"), None).expect("load");
    assert_eq!(l.format, "macho");
    assert_eq!(l.language.id, "AARCH64:LE:64:AppleSilicon");
    assert_eq!(l.language.compiler, "default");
    assert_eq!(l.base, 0x1_0000_0000);
    let block = |n: &str| l.blocks.iter().find(|b| b.name == n).expect(n);
    assert_eq!(block("__TEXT").perms, "r-x");
    assert_eq!(block("__text").perms, "r-x");
    assert_eq!(block("__cstring").perms, "r--");
    assert_eq!(block("__got").perms, "rw-");
    assert!(block("EXTERNAL").start.0 % 0x1000 == 0);
    assert!(!l.blocks.iter().any(|b| b.name == "__PAGEZERO"));
    let x64 = load(&read("pie_list-x64-O2"), None).expect("load");
    assert_eq!(x64.language.id, "x86:LE:64:default");
    assert_eq!(x64.language.compiler, "gcc");
}

#[test]
fn chained_fixups_and_binding_tables_agree() {
    for arch in ["x64", "arm64"] {
        let chained = load(&read(&format!("pie_list-{arch}-O2")), None).expect("chained");
        let classic = load(&read(&format!("pie_list-{arch}-O2-classic")), None).expect("classic");
        let names = |l: &engine_native::elf::Loaded| -> BTreeSet<String> {
            l.plt.values().cloned().collect()
        };
        assert_eq!(names(&chained), names(&classic), "{arch}");
        assert!(names(&chained).contains("_printf"), "{arch}");
        // the slot of a stubbed import holds the stub, as in Ghidra
        for l in [&chained, &classic] {
            let (stub, name) = l.plt.iter().next().expect("stub");
            let (slot, _) = l
                .import_slots
                .iter()
                .find(|(_, n)| *n == name)
                .expect("slot");
            let mut b = [0u8; 8];
            assert!(l.image.read(*slot, &mut b));
            assert_eq!(u64::from_le_bytes(b), *stub, "{arch} {name}");
        }
        let lib = chained
            .imports
            .iter()
            .find(|i| i.name == "_printf")
            .expect("import");
        assert_eq!(lib.library.as_deref(), Some("/usr/lib/libSystem.B.dylib"));
    }
}

#[test]
fn the_entry_is_named_as_ghidra_names_it_and_stripped_files_keep_their_starts() {
    let l = load(&read("pie_list-arm64-O2"), None).expect("load");
    let entry = l.entry.expect("entry");
    assert_eq!(l.functions.get(&entry).map(String::as_str), Some("entry"));
    assert!(l.code_symbols[&entry].contains(&"_main".to_string()));
    let s = load(&read("stripped_calc-arm64-O2-stripped"), None).expect("load");
    assert!(s.pdata_starts.len() > 2, "{:x?}", s.pdata_starts);
    assert!(s.functions.len() <= 2, "{:?}", s.functions);
}

#[test]
fn a_library_exports_through_its_trie() {
    for arch in ["x64", "arm64"] {
        let l = load(&read(&format!("mac_lib-{arch}-O2.dylib")), None).expect("load");
        assert_eq!(l.base, 0);
        assert_eq!(l.description, "macOS library");
        let names: BTreeSet<&str> = l.exports.values().map(|e| e.name.as_str()).collect();
        for n in [
            "_kr_add",
            "_kr_hash",
            "_kr_show",
            "_kr_counter",
            "_kr_version",
        ] {
            assert!(names.contains(n), "{arch} {n}: {names:?}");
        }
    }
}

#[test]
fn rebasing_moves_everything_and_the_pointers_follow() {
    let d = read("mac_lib-arm64-O2.dylib");
    let l = load(&d, None).expect("load");
    let r = load(&d, Some(0x7000_0000)).expect("rebased");
    assert_eq!(r.pointer_slots.len(), l.pointer_slots.len());
    let (slot, target) = *r
        .pointer_slots
        .iter()
        .find(|(s, _)| !r.import_slots.contains_key(s))
        .expect("a rebased pointer");
    let mut b = [0u8; 8];
    assert!(r.image.read(slot, &mut b));
    assert_eq!(u64::from_le_bytes(b), target);
    assert!(target >= 0x7000_0000);
}

/// Flips, zeroes and maxes the bytes of the load commands and tables: the loader must stay
/// bounded and either refuse or load, never panic.
#[test]
fn hostile_files_are_refused_or_bounded() {
    for name in [
        "pie_list-arm64-O2",
        "pie_list-x64-O2-classic",
        "mac_lib-x64-O0.dylib",
    ] {
        let clean = read(name);
        let cmds = u32::from_le_bytes(clean[20..24].try_into().expect("size")) as usize + 32;
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for round in 0..1500usize {
            let mut d = clean.clone();
            for _ in 0..1 + round % 6 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                // mostly the load commands, sometimes the tables behind them
                let room = if round % 3 == 0 { d.len() } else { cmds };
                let at = (x as usize >> 8) % room;
                d[at] = match x & 3 {
                    0 => 0,
                    1 => 0xff,
                    2 => 0x7f,
                    _ => d[at] ^ (x >> 56) as u8,
                };
            }
            if let Ok(l) = load(&d, None) {
                assert!(l.blocks.iter().all(|b| b.start.0 <= b.end.0));
            }
        }
    }
    let mut d = read("pie_list-x64-O2");
    d[4..8].copy_from_slice(&18u32.to_le_bytes());
    let Err(e) = load(&d, None) else {
        panic!("a PowerPC file must be refused");
    };
    assert!(e.message.contains("processor"), "{}", e.message);
}

#[tokio::test(flavor = "multi_thread")]
async fn decompiles_a_sample_function_on_both_architectures() {
    for arch in ["x64", "arm64"] {
        let Some((e, info)) =
            open(&bin(&format!("pie_list-{arch}-O0")), &LoaderSpec::default()).await
        else {
            return;
        };
        assert_eq!(info.format, "macho");
        let push = decompiled(&e, "_list_push").await;
        assert!(push.contains("_list_push"), "{push}");
        assert!(push.contains("return"), "{push}");
        let main = decompiled(&e, "entry").await;
        assert!(
            main.contains("_calloc") || main.contains("_list_push"),
            "{main}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_universal_binary_opens_the_slice_that_was_asked_for() {
    let path = bin("pie_list-fat-O2");
    for (slice, language) in [
        ("x86-64", "x86:LE:64:default"),
        ("arm64", "AARCH64:LE:64:AppleSilicon"),
    ] {
        let spec = LoaderSpec {
            slice: Some(slice.into()),
            ..LoaderSpec::default()
        };
        let Some((e, info)) = open(&path, &spec).await else {
            return;
        };
        assert_eq!(info.arch, language);
        let text = decompiled(&e, "_list_sort").await;
        assert!(text.contains("_list_sort"), "{text}");
    }
    let Some(c) = config() else { return };
    let e = NativeEngine::new(c);
    let Err(no_choice) = e
        .open_binary(&path, &LoaderSpec::default(), &CancellationToken::new())
        .await
    else {
        panic!("two architectures and no choice must be refused");
    };
    assert!(no_choice.message.contains("arm64"), "{}", no_choice.message);
}

/// Every function of the truth files is found, stripped programs included.
#[tokio::test(flavor = "multi_thread")]
async fn finds_every_function_of_the_truth() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/macho/truth");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("truth")
        .map(|e| e.expect("entry").path())
        .collect();
    files.sort();
    assert!(files.len() >= 24, "{}", files.len());
    for file in files {
        let t: Value =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("read")).expect("json");
        let binary = t["binary"].as_str().expect("binary");
        let Some((e, _)) = open(&bin(binary), &LoaderSpec::default()).await else {
            return;
        };
        let ours: BTreeSet<u64> = functions(&e)
            .await
            .iter()
            .filter_map(|f| match &f.locator {
                Locator::Native { offset, .. } => Some(offset.0),
                _ => None,
            })
            .collect();
        for f in t["functions"].as_array().expect("functions") {
            let entry = f["entry"].as_str().expect("entry");
            let a = u64::from_str_radix(entry.trim_start_matches("0x"), 16).expect("hex");
            assert!(ours.contains(&a), "{binary}: {} at {entry}", f["name"]);
        }
    }
}

/// The contract suite on both architectures, in the worker and in-process.
#[tokio::test(flavor = "multi_thread")]
async fn contract_suite_on_mach_o() {
    for binary in ["pie_list-x64-O0", "pie_list-arm64-O0"] {
        let path = bin(binary);
        let Some((e, info)) = open(&path, &LoaderSpec::default()).await else {
            return;
        };
        let listed = functions(&e).await;
        // inside the first function: an address with no function of its own
        let first = match &listed[0].locator {
            Locator::Native { offset, .. } => offset.0,
            other => panic!("{other:?}"),
        };
        let exp = FixtureExpectations {
            binary_path: path,
            program: info,
            functions: listed
                .into_iter()
                .map(|f| ExpectedFunction {
                    locator: f.locator,
                    name: f.name,
                })
                .collect(),
            rename_to: "kraken_renamed".into(),
            scratch: Locator::ram(Hex64(first + 0x10).0),
        };
        for isolation in [
            Isolation::Worker(WorkerOptions::with_program(env!(
                "CARGO_BIN_EXE_kraken-native-worker"
            ))),
            Isolation::InProcess,
        ] {
            let mut c = config().expect("config");
            c.isolation = isolation;
            run_contract_suite(&NativeEngine::new(c), &exp)
                .await
                .unwrap_or_else(|err| panic!("{binary}: {err}"));
        }
    }
}

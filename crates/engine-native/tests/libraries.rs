//! The native engine on the library set (`corpus/lib`: libkr as a Linux shared library, static
//! library and object files, and as Windows DLLs, static libraries, import libraries and COFF
//! objects for x64 and x86): function names and sizes against the toolchain's truth, exports and
//! imports, member blocks, a decompile that names a call into another member or an external, and
//! the contract suite; and libkr for ARM (Thumb-2 and A32), AArch64 and RISC-V (`corpus/xlib`).
//! Needs the native build and a spec tree with the x86 (and for `corpus/xlib` the ARM, AArch64
//! and RISC-V) `.sla` files (`cargo xtask native-sla` compiles them); skips otherwise.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, MemoryReader, ProgramInfo,
    SymbolLister,
};
use kraken_proto::{FunctionSummary, Locator, MemoryBlock, PageRequest, SymbolEntry};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn lib(name: &str) -> PathBuf {
    root().join("corpus/lib/bin").join(name)
}

fn config() -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree (cargo xtask native-sla, or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.isolation = worker();
    Some(c)
}

fn worker() -> Isolation {
    Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )))
}

/// Everything a test looks at, read once.
struct Opened {
    engine: NativeEngine,
    info: ProgramInfo,
    functions: BTreeMap<u64, FunctionSummary>,
    blocks: Vec<MemoryBlock>,
    imports: Vec<SymbolEntry>,
    exports: Vec<SymbolEntry>,
}

impl Opened {
    fn named(&self, name: &str) -> &FunctionSummary {
        self.functions
            .values()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no function {name}"))
    }

    fn block_of(&self, f: &FunctionSummary) -> &str {
        let Locator::Native { offset, .. } = &f.locator else {
            panic!("not a native locator");
        };
        self.blocks
            .iter()
            .find(|b| b.start.0 <= offset.0 && offset.0 < b.end.0)
            .map_or("", |b| b.name.as_str())
    }

    async fn decompile(&self, name: &str) -> String {
        let f = self.named(name);
        let d = self
            .engine
            .decompile(&f.locator, &CancellationToken::new())
            .await
            .unwrap_or_else(|e| panic!("decompile {name}: {e}"));
        d.validate_tokens().expect("token spans");
        d.text
    }
}

async fn all<T>(mut page: impl AsyncFnMut(PageRequest) -> kraken_proto::Page<T>) -> Vec<T> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let p = page(PageRequest {
            cursor,
            limit: Some(500),
        })
        .await;
        out.extend(p.items);
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

async fn open(name: &str) -> Option<Opened> {
    open_path(&lib(name)).await
}

async fn open_path(path: &Path) -> Option<Opened> {
    let name = path.display();
    let engine = NativeEngine::new(config()?);
    let t = CancellationToken::new();
    let info = engine
        .open_binary(path, &LoaderSpec::default(), &t)
        .await
        .unwrap_or_else(|e| panic!("open {name}: {e}"));
    let functions = all(async |p| engine.list_functions(&p, &t).await.expect("list"))
        .await
        .into_iter()
        .filter_map(|f| match &f.locator {
            Locator::Native { offset, .. } => Some((offset.0, f)),
            _ => None,
        })
        .collect();
    let blocks = engine.memory_map(&t).await.expect("memory map");
    let imports = all(async |p| engine.imports(&p, &t).await.expect("imports")).await;
    let exports = all(async |p| engine.exports(&p, &t).await.expect("exports")).await;
    Some(Opened {
        engine,
        info,
        functions,
        blocks,
        imports,
        exports,
    })
}

fn truth(name: &str) -> Value {
    truth_in("lib", name)
}

fn truth_in(set: &str, name: &str) -> Value {
    let p = root()
        .join("corpus")
        .join(set)
        .join("truth")
        .join(format!("{name}.json"));
    serde_json::from_str(&std::fs::read_to_string(p).expect("truth")).expect("json")
}

fn names(list: &Value) -> BTreeSet<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v["name"].as_str().map(str::to_string))
        .collect()
}

/// Every function of the truth is listed under its name (the symbol, its C name, or the DWARF
/// name of a clone such as `bump.constprop.0`), in the block of its member, with at most the
/// compiler's size (at `-O2` the padding between switch cases is not part of the body) and more
/// than half of it.
fn check_functions(o: &Opened, t: &Value, binary: &str) {
    for f in t["functions"].as_array().expect("functions") {
        let name = f["name"].as_str().unwrap_or_default();
        let c_name = f["demangled"].as_str().unwrap_or(name);
        let base = c_name.split('.').next().unwrap_or(c_name);
        let want = f["size"].as_u64().unwrap_or(0);
        if want == 0 {
            continue;
        }
        // a linked file says where (a shared library linked at 0 is loaded at Ghidra's base);
        // in an object or archive the name has to do
        // (an ARM symbol has the Thumb bit; the function starts at the even address)
        let thumb_bit = if o.info.arch.starts_with("ARM:") {
            !1
        } else {
            u64::MAX
        };
        let entry = f["entry"]
            .as_str()
            .and_then(|e| u64::from_str_radix(e.trim_start_matches("0x"), 16).ok())
            .map(|e| e & thumb_bit)
            .map(|e| {
                if e < o.info.base.0 {
                    e + o.info.base.0
                } else {
                    e
                }
            });
        let found = match entry {
            Some(at) => o.functions.get(&at),
            None => o
                .functions
                .values()
                .find(|s| s.name == name || s.name == c_name || s.name == base),
        }
        .unwrap_or_else(|| panic!("{binary}: truth function {name} not listed"));
        assert!(
            [name, c_name, base].contains(&found.name.as_str()),
            "{binary}: {name} is listed as {}",
            found.name
        );
        let size = found.size.unwrap_or(0);
        assert!(
            size <= want && size * 2 > want,
            "{binary}: {name} has size {size}, the compiler says {want}"
        );
        if let Some(member) = f["member"].as_str() {
            let block = o.block_of(found);
            assert!(
                block.starts_with(&format!("{member}:")),
                "{binary}: {name} is in block {block}, not in member {member}"
            );
        }
    }
}

fn check_symbols(o: &Opened, t: &Value, binary: &str) {
    let exports: BTreeSet<String> = o.exports.iter().map(|e| e.name.clone()).collect();
    let missing: Vec<_> = names(&t["exports"]).difference(&exports).cloned().collect();
    assert!(missing.is_empty(), "{binary}: exports missing {missing:?}");
    let imports: BTreeSet<String> = o.imports.iter().map(|i| i.name.clone()).collect();
    assert_eq!(imports, names(&t["imports"]), "{binary}: imports");
}

#[tokio::test(flavor = "multi_thread")]
async fn linux_objects_and_static_library() {
    for binary in ["kr.o", "kr-i386.o", "libkr.a"] {
        let Some(o) = open(binary).await else {
            return;
        };
        let t = truth(binary);
        check_functions(&o, &t, binary);
        check_symbols(&o, &t, binary);
        assert_eq!(
            o.info.format,
            if binary.ends_with(".a") { "ar" } else { "elf" }
        );
        // objects have no entry point; the exports are the global definitions only
        assert!(o.exports.iter().all(|e| e.name != "entry"));
        let text = o.decompile("kr_report").await;
        assert!(text.contains("puts("), "{binary}: external call\n{text}");
        assert!(text.contains("kr_kind_name("), "{binary}: call\n{text}");
        assert!(text.contains("strlen("), "{binary}: external call\n{text}");
    }
    let Some(a) = open("libkr.a").await else {
        return;
    };
    assert_eq!(
        a.info.description.as_deref(),
        Some("Linux static library with 2 objects")
    );
    assert_eq!(a.info.members, ["kr_core.o", "kr_text.o"]);
    // the call from kr_core.o reaches the function of kr_text.o, which is no import
    assert_eq!(a.block_of(a.named("kr_kind_name")), "kr_text.o:.text");
    assert!(!a.imports.iter().any(|i| i.name == "kr_kind_name"));
    let blocks: Vec<&str> = a.blocks.iter().map(|b| b.name.as_str()).collect();
    assert!(blocks.contains(&"kr_core.o:.text"), "{blocks:?}");
    assert!(blocks.contains(&"kr_text.o:.rodata"), "{blocks:?}");
    // strings of one member are found and read through the relocated references
    let text = a.decompile("kr_kind_name").await;
    assert!(text.contains("punctuation"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn linux_shared_library() {
    let Some(o) = open("libkr.so").await else {
        return;
    };
    let t = truth("libkr.so");
    check_functions(&o, &t, "libkr.so");
    check_symbols(&o, &t, "libkr.so");
    assert_eq!(o.info.description.as_deref(), Some("Linux shared library"));
    // no entry point: nothing is named `entry`, and the PLT imports have their stubs
    assert!(!o.functions.values().any(|f| f.name == "entry"));
    let puts = o.imports.iter().find(|i| i.name == "puts").expect("puts");
    assert!(puts.address.is_some(), "a PLT import has its stub");
    let text = o.decompile("kr_report").await;
    assert!(
        text.contains("puts(") && text.contains("kr_kind_name("),
        "{text}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_objects_and_static_libraries() {
    for binary in ["kr-x64.obj", "kr-x86.obj", "kr-x64.lib", "kr-x86.lib"] {
        let Some(o) = open(binary).await else {
            return;
        };
        let t = truth(binary);
        check_functions(&o, &t, binary);
        check_symbols(&o, &t, binary);
        let text = o.decompile("kr_report").await;
        assert!(text.contains("puts("), "{binary}: external call\n{text}");
        assert!(text.contains("kr_kind_name("), "{binary}: call\n{text}");
        if binary.ends_with(".lib") {
            assert_eq!(o.info.format, "ar");
            assert_eq!(
                o.info.description.as_deref(),
                Some("Windows static library with 2 objects")
            );
            assert_eq!(o.info.members, ["kr_core.obj", "kr_text.obj"]);
            assert_eq!(o.block_of(o.named("kr_checksum")), "kr_text.obj:.text");
        } else {
            assert_eq!(o.info.format, "coff");
            assert!(
                o.info
                    .description
                    .as_deref()
                    .is_some_and(|d| d.starts_with("COFF object"))
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_dlls_export_by_name_and_ordinal() {
    for binary in ["kr-x64.dll", "kr-x86.dll"] {
        let Some(o) = open(binary).await else {
            return;
        };
        let t = truth(binary);
        check_functions(&o, &t, binary);
        assert_eq!(o.info.description.as_deref(), Some("Windows DLL"));
        let exports: BTreeSet<&str> = o.exports.iter().map(|e| e.name.as_str()).collect();
        for e in t["exports"].as_array().expect("exports") {
            match e["name"].as_str() {
                Some(n) => assert!(exports.contains(n), "{binary}: export {n}"),
                // exported by ordinal only: named by its COFF symbol
                None => assert!(exports.contains("kr_checksum"), "{binary}: {exports:?}"),
            }
        }
        let text = o.decompile("kr_report").await;
        assert!(text.contains("puts("), "{binary}: import call\n{text}");
    }
}

/// libkr for ARM (Thumb-2, and one A32 object), AArch64, RISC-V 64 and RISC-V 32 as object
/// files, static libraries and shared libraries (`corpus/xlib`): the functions of the truth, the
/// exports and imports, and a decompile that names the external `puts` and the call into the
/// other member.
#[tokio::test(flavor = "multi_thread")]
async fn cross_architecture_objects_and_libraries() {
    let dir = root().join("corpus/xlib/bin");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("corpus/xlib/bin")
        .filter_map(|e| e.ok()?.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    for binary in names {
        let Some(o) = open_path(&dir.join(&binary)).await else {
            return;
        };
        let t = truth_in("xlib", &binary);
        check_functions(&o, &t, &binary);
        check_symbols(&o, &t, &binary);
        let want = match t["arch"].as_str().unwrap_or_default() {
            "arm32" => "ARM:LE:32:v8",
            "aarch64" => "AARCH64:LE:64:v8A",
            "riscv64" => "RISCV:LE:64:default",
            _ => "RISCV:LE:32:default",
        };
        assert_eq!(o.info.arch, want, "{binary}");
        let text = o.decompile("kr_report").await;
        assert!(text.contains("puts("), "{binary}: external call\n{text}");
        assert!(text.contains("kr_kind_name("), "{binary}: call\n{text}");
        if binary.ends_with(".a") {
            assert_eq!(o.info.members, ["kr_core.o", "kr_text.o"], "{binary}");
            assert_eq!(o.block_of(o.named("kr_kind_name")), "kr_text.o:.text");
            // the strings of the other member, read through its relocated references
            let text = o.decompile("kr_kind_name").await;
            assert!(text.contains("punctuation"), "{binary}\n{text}");
        }
    }
}

/// A DLL without an entry point (resource-only DLLs, or `/NOENTRY`) loads with none.
#[test]
fn a_dll_without_an_entry_point_has_none() {
    let mut d = std::fs::read(lib("kr-x64.dll")).expect("dll");
    let pe = u32::from_le_bytes(d[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
    // AddressOfEntryPoint: optional header + 16
    d[pe + 24 + 16..pe + 24 + 20].copy_from_slice(&0u32.to_le_bytes());
    let l = engine_native::elf::load(&d, None).expect("load");
    assert_eq!(l.entry, None);
    assert!(!l.exports.is_empty());
    assert_eq!(l.description, "Windows DLL");
}

#[tokio::test(flavor = "multi_thread")]
async fn import_libraries_list_their_symbols_and_dll() {
    for binary in ["libkr-x64.dll.a", "libkr-x86.dll.a"] {
        let Some(o) = open(binary).await else {
            return;
        };
        let t = truth(binary);
        assert!(o.functions.is_empty(), "{binary}: no code");
        let description = o.info.description.clone().unwrap_or_default();
        assert!(
            description.starts_with("import library for kr.dll") && description.contains("no code"),
            "{description}"
        );
        assert_eq!(o.info.members.len(), 8);
        let got: BTreeSet<(String, Option<String>)> = o
            .imports
            .iter()
            .map(|i| (i.name.clone(), i.library.clone()))
            .collect();
        let want: BTreeSet<(String, Option<String>)> = t["imports"]
            .as_array()
            .expect("imports")
            .iter()
            .map(|i| {
                (
                    i["name"].as_str().unwrap_or_default().to_string(),
                    i["library"].as_str().map(str::to_string),
                )
            })
            .collect();
        assert_eq!(got, want, "{binary}");
        let data: Vec<&str> = o
            .imports
            .iter()
            .filter(|i| i.kind == kraken_proto::SymbolKind::Data)
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(data, ["kr_calls"], "{binary}: the variable is data");
    }
}

/// The contract suite on an object, an archive and an i386 object, in the worker and
/// in-process.
#[tokio::test(flavor = "multi_thread")]
async fn contract_suite_on_objects_and_archives() {
    for binary in ["kr-x64.obj", "libkr.a", "kr-i386.o"] {
        let Some(o) = open(binary).await else {
            return;
        };
        // an initialized byte outside every function: the first data block
        let scratch = o
            .blocks
            .iter()
            .find(|b| b.initialized && !b.perms.ends_with('x'))
            .map(|b| b.start.0)
            .expect("a data block");
        let functions: Vec<ExpectedFunction> = o
            .functions
            .values()
            .map(|f| ExpectedFunction {
                locator: f.locator.clone(),
                name: f.name.clone(),
            })
            .collect();
        let exp = FixtureExpectations {
            binary_path: lib(binary),
            program: o.info.clone(),
            functions,
            rename_to: "kraken_renamed".into(),
            scratch: Locator::ram(scratch),
        };
        for isolation in [worker(), Isolation::InProcess] {
            let mut c = config().expect("config");
            c.isolation = isolation;
            run_contract_suite(&NativeEngine::new(c), &exp)
                .await
                .unwrap_or_else(|e| panic!("{binary}: {e}"));
        }
    }
}

/// Opens the files named in `KR_FILES` (comma-separated paths) and prints what came out and
/// how long it took; for trying the loaders on large real files by hand:
/// `KR_FILES=/tmp/x/libc.a cargo test --release -p engine-native --test libraries -- --ignored
/// --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "manual: needs files named in KR_FILES"]
async fn open_files_from_env() {
    let Some(mut c) = config() else {
        return;
    };
    c.isolation = Isolation::InProcess;
    for name in std::env::var("KR_FILES").unwrap_or_default().split(',') {
        if name.is_empty() {
            continue;
        }
        let t0 = std::time::Instant::now();
        if let Ok(data) = std::fs::read(name)
            && let Ok(l) = engine_native::elf::load(&data, None)
        {
            println!(
                "{name}: loaded in {:.2?}: {} blocks, {} symbols, {} DWARF types, {} DWARF \
                 functions",
                t0.elapsed(),
                l.blocks.len(),
                l.functions.len(),
                l.debug.types.len(),
                l.debug.functions.len()
            );
        }
        let e = NativeEngine::new(c.clone());
        let t = CancellationToken::new();
        let t0 = std::time::Instant::now();
        let info = match e
            .open_binary(Path::new(name), &LoaderSpec::default(), &t)
            .await
        {
            Ok(i) => i,
            Err(err) => {
                println!("{name}: {err}");
                continue;
            }
        };
        let opened = t0.elapsed();
        if let Ok(s) = e.stats().await {
            println!(
                "  {} discovery rounds, {} noreturn, {} references",
                s.discovery_rounds,
                s.noreturn.len(),
                s.references
            );
        }
        let functions = all(async |p| e.list_functions(&p, &t).await.expect("list")).await;
        let t1 = std::time::Instant::now();
        let mut decompiled = 0;
        for f in functions.iter().take(20) {
            match e.decompile(&f.locator, &t).await {
                Ok(_) => decompiled += 1,
                Err(err) => println!("  {}: {err}", f.name),
            }
        }
        println!(
            "{name}: {} ({} members), opened in {opened:.2?}, {} functions ({} named), \
             {decompiled}/20 decompiled in {:.2?}",
            info.description.unwrap_or_default(),
            info.members.len(),
            functions.len(),
            functions
                .iter()
                .filter(|f| !f.name.starts_with("FUN_"))
                .count(),
            t1.elapsed()
        );
    }
}

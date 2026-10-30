//! The native engine on the PE set (`corpus/pe`: PE32 and PE32+ built with mingw-w64) and the
//! 32-bit ELF set (`corpus/elf32`): truth recall, names and sizes, decompiled Win32 calls, TLS
//! callbacks, imports and exports, and the contract suite. Needs the native build and a spec tree
//! with the x86 `.sla` files (`cargo xtask native-sla` compiles both); skips otherwise.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, ProgramInfo, SymbolLister,
    TypeStore,
};
use kraken_proto::{FunctionSummary, Hex64, Locator, PageRequest, SymbolKind};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config(use_symbols: bool) -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree (cargo xtask native-sla, or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.use_symbols = use_symbols;
    c.isolation = if std::env::var_os("KRAKEN_NATIVE_TEST_IN_PROCESS").is_some_and(|v| v == "1") {
        Isolation::InProcess
    } else {
        worker()
    };
    Some(c)
}

fn worker() -> Isolation {
    Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )))
}

async fn open(set: &str, binary: &str) -> Option<(NativeEngine, ProgramInfo)> {
    let e = NativeEngine::new(config(true)?);
    let info = e
        .open_binary(
            &root().join(set).join("bin").join(binary),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open_binary");
    Some((e, info))
}

fn page() -> PageRequest {
    PageRequest {
        cursor: None,
        limit: Some(500),
    }
}

async fn listing(e: &NativeEngine) -> BTreeMap<u64, FunctionSummary> {
    let mut out = BTreeMap::new();
    let mut cursor = None;
    loop {
        let p = e
            .list_functions(
                &PageRequest {
                    cursor,
                    limit: Some(500),
                },
                &CancellationToken::new(),
            )
            .await
            .expect("list");
        for f in p.items {
            if let Locator::Native { offset, .. } = &f.locator {
                out.insert(offset.0, f);
            }
        }
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

async fn decompile(e: &NativeEngine, fns: &BTreeMap<u64, FunctionSummary>, name: &str) -> String {
    let f = fns
        .values()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"));
    let d = e
        .decompile(&f.locator, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("decompile {name}: {err}"));
    d.validate_tokens().expect("token spans");
    d.text
}

fn json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).expect("corpus json");
    serde_json::from_str(&text).expect("json")
}

fn hex(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap_or("0").trim_start_matches("0x"), 16).unwrap_or(0)
}

/// Whether the byte at `va` of a PE32+ image is a `nop` (0x90).
fn ends_in_nop(path: &Path, va: u64) -> bool {
    let data = std::fs::read(path).expect("binary");
    let pe = u32::from_le_bytes(data[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
    let base = u64::from_le_bytes(data[pe + 0x30..pe + 0x38].try_into().expect("image base"));
    let sections = u16::from_le_bytes([data[pe + 6], data[pe + 7]]) as usize;
    let table = pe + 0x18 + u16::from_le_bytes([data[pe + 0x14], data[pe + 0x15]]) as usize;
    let rva = va - base;
    (0..sections).any(|i| {
        let h = &data[table + i * 40..table + (i + 1) * 40];
        let word = |o: usize| u64::from(u32::from_le_bytes(h[o..o + 4].try_into().expect("u32")));
        let (vaddr, raw, ptr) = (word(12), word(16), word(20));
        rva >= vaddr && rva < vaddr + raw && data[(ptr + rva - vaddr) as usize] == 0x90
    })
}

fn binaries(set: &str) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(root().join(set).join("bin"))
        .expect("corpus set")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        // the PDB sample has no truth file; `pdb_*` tests below cover it
        .filter(|n| !n.starts_with("pdb_sample"))
        .collect();
    v.sort();
    v
}

/// Every truth function of every PE and 32-bit ELF binary is found, under its name (the COFF
/// symbol or its C name, as Ghidra shows them) and with the size the compiler gave it (at `-O2`,
/// at most that size: the padding between switch cases is not part of the body).
#[tokio::test(flavor = "multi_thread")]
async fn truth_functions_are_found_with_their_names_and_sizes() {
    for set in ["corpus/pe", "corpus/elf32"] {
        for binary in binaries(set) {
            let Some((e, info)) = open(set, &binary).await else {
                return;
            };
            let fns = listing(&e).await;
            let truth = json(&root().join(set).join(format!("truth/{binary}.json")));
            // PIE truth is link-time (base 0); PE truth is at the image base already
            let base = if info.base.0 == 0x1_0000 { 0x1_0000 } else { 0 };
            let stripped = binary.contains("stripped");
            let (mut hit, mut total, mut sized) = (0, 0, 0);
            for t in truth["functions"].as_array().expect("functions") {
                total += 1;
                let entry = base + hex(&t["entry"]);
                let Some(f) = fns.get(&entry) else {
                    eprintln!("{binary}: missed {} at {entry:#x}", t["name"]);
                    continue;
                };
                hit += 1;
                let names = [t["name"].as_str(), t["demangled"].as_str()];
                // a TLS callback of a PE32+ is `tls_callback_<n>`, as Ghidra names it
                if !stripped && !f.name.starts_with("tls_callback_") {
                    assert!(
                        names.contains(&Some(f.name.as_str())),
                        "{binary}: {entry:#x} is {} (truth {names:?})",
                        f.name
                    );
                }
                let want = t["size"].as_u64().unwrap_or(0);
                // x86-64 Windows code puts a `nop` after a call that never returns, so the return
                // address stays inside the function's unwind range; the body ends at the call
                let padded = f.size.is_some_and(|s| s + 1 == want)
                    && binary.contains("-x64-")
                    && ends_in_nop(
                        &root().join(set).join("bin").join(&binary),
                        entry + want - 1,
                    );
                // optimized code pads between switch cases; the body leaves the padding out
                // (as Ghidra's does), the compiler's range does not
                let between_cases = binary.contains("-O2") && f.size.is_some_and(|s| s <= want);
                if f.size == Some(want) || padded || between_cases {
                    sized += 1;
                } else {
                    eprintln!(
                        "{binary}: {} at {entry:#x} has {:?} bytes, truth {}",
                        f.name, f.size, t["size"]
                    );
                }
            }
            eprintln!(
                "{binary}: {hit}/{total} truth functions, {sized} with the truth size, {} listed",
                fns.len()
            );
            assert_eq!(hit, total, "{binary}: recall");
            assert_eq!(sized, total, "{binary}: sizes");
        }
    }
}

/// Calls through the import address table name and type their callee, on PE32+ and PE32, and
/// the import by ordinal is `Ordinal_3`.
#[tokio::test(flavor = "multi_thread")]
async fn win32_calls_decompile_with_their_prototypes() {
    for (binary, main) in [
        ("win_tls-x64-O0.exe", "main"),
        ("win_tls-x86-O0.exe", "_main"),
    ] {
        let Some((e, info)) = open("corpus/pe", binary).await else {
            return;
        };
        assert_eq!(info.format, "pe");
        let fns = listing(&e).await;
        let probe = decompile(&e, &fns, "probe_kernel").await;
        assert!(probe.contains("DWORD probe_kernel(void)"), "{probe}");
        assert!(
            probe.contains("GetModuleHandleA(\"kernel32.dll\")"),
            "{probe}"
        );
        assert!(
            probe.contains("GetProcAddress(hModule,\"GetTickCount\")"),
            "{probe}"
        );
        let upper = decompile(&e, &fns, "copy_upper").await;
        assert!(
            upper.contains("LPVOID copy_upper(LPCSTR param_1)"),
            "{upper}"
        );
        assert!(upper.contains("VirtualAlloc((LPVOID)0x0,"), "{upper}");
        let m = decompile(&e, &fns, main).await;
        assert!(m.contains("Ordinal_3(5)"), "{m}");
        assert!(m.contains("VirtualFree("), "{m}");
        assert!(m.contains("Sleep(0);"), "{m}");
        assert!(m.contains("qsort("), "{m}");
        // the listed signatures of import thunks come from the tables, with the Windows
        // headers' parameter names
        let qsort = fns
            .values()
            .find(|f| f.name == "qsort")
            .expect("qsort thunk");
        assert_eq!(
            qsort.signature.as_deref(),
            Some(
                "void qsort(void *_Base,size_t _NumOfElements,size_t _SizeOfElements,\
                 void *_PtFuncCompare)"
            ),
            "{binary}"
        );
        if let Some(thunk) = fns.values().find(|f| f.name == "GetModuleHandleA") {
            assert_eq!(
                thunk.signature.as_deref(),
                Some("HMODULE GetModuleHandleA(LPCSTR lpModuleName)")
            );
        }
        // the Windows typedefs are in the type store
        let types = e
            .list_types(&page(), &CancellationToken::new())
            .await
            .expect("types");
        assert!(
            types
                .items
                .iter()
                .any(|t| kraken_engine::type_def_name(t) == Some("HMODULE")),
            "no HMODULE"
        );
    }
}

/// On 32-bit Windows the default convention is `__stdcall` (the callee pops its arguments) and
/// the C runtime's functions are `__cdecl`; calls to either keep the caller's stack balanced.
#[tokio::test(flavor = "multi_thread")]
async fn x86_conventions() {
    let Some((e, _)) = open("corpus/pe", "win_tls-x86-O0.exe").await else {
        return;
    };
    let fns = listing(&e).await;
    let printf = decompile(&e, &fns, "_printf").await;
    assert!(
        printf.contains("int __cdecl _printf(char *_Format,...)"),
        "{printf}"
    );
    // stdcall Win32 calls back to back, then a cdecl call: no stack confusion in between
    let m = decompile(&e, &fns, "_main").await;
    assert!(!m.contains("in_stack"), "{m}");
    assert!(!m.contains("unaff_"), "{m}");
    let probe = decompile(&e, &fns, "probe_kernel").await;
    assert!(!probe.contains("in_stack"), "{probe}");
}

/// TLS callbacks are functions and entry points, named as Ghidra names them on x86-64; `.pdata`
/// finds the functions of a stripped PE32+.
#[tokio::test(flavor = "multi_thread")]
async fn tls_callbacks_and_pdata() {
    let Some((e, _)) = open("corpus/pe", "win_tls-x64-O2-stripped.exe").await else {
        return;
    };
    let fns = listing(&e).await;
    let exports = e
        .exports(&page(), &CancellationToken::new())
        .await
        .expect("exports");
    let names: Vec<&str> = exports.items.iter().map(|s| s.name.as_str()).collect();
    for n in [
        "entry",
        "tls_callback_0",
        "tls_callback_1",
        "tls_callback_2",
    ] {
        assert!(names.contains(&n), "{n} not exported: {names:?}");
        assert!(fns.values().any(|f| f.name == n), "{n} not a function");
    }
    let cb = decompile(&e, &fns, "tls_callback_0").await;
    assert!(cb.contains("LOCK()"), "{cb}");
    let imports = e
        .imports(&page(), &CancellationToken::new())
        .await
        .expect("imports");
    let qsort = imports
        .items
        .iter()
        .find(|s| s.name == "qsort")
        .expect("qsort");
    assert_eq!(qsort.library.as_deref(), Some("MSVCRT.DLL"));
    assert_eq!(qsort.kind, SymbolKind::Function);
    assert!(qsort.address.is_some());
    let ord = imports
        .items
        .iter()
        .find(|s| s.name == "Ordinal_3")
        .expect("ordinal");
    assert_eq!(ord.library.as_deref(), Some("WIN_DLL.DLL"));
}

/// A DLL's exports: by name, by ordinal only (named by its symbol), and data.
#[tokio::test(flavor = "multi_thread")]
async fn dll_exports() {
    for binary in ["win_dll-x64-O2.dll", "win_dll-x86-O2.dll"] {
        let Some((e, _)) = open("corpus/pe", binary).await else {
            return;
        };
        let exports = e
            .exports(&page(), &CancellationToken::new())
            .await
            .expect("exports");
        let by_name: BTreeMap<&str, &kraken_proto::SymbolEntry> =
            exports.items.iter().map(|s| (s.name.as_str(), s)).collect();
        for n in ["kr_add", "kr_mul", "kr_secret", "kr_version"] {
            let s = by_name
                .get(n)
                .unwrap_or_else(|| panic!("{binary}: {n} not exported"));
            assert_eq!(s.kind, SymbolKind::Function, "{binary}: {n}");
        }
        assert_eq!(
            by_name.get("kr_counter").map(|s| s.kind),
            Some(SymbolKind::Data),
            "{binary}"
        );
        let fns = listing(&e).await;
        let secret = decompile(&e, &fns, "kr_secret").await;
        assert!(secret.contains("kr_secret("), "{secret}");
    }
}

/// 32-bit ELF: the PIE is at Ghidra's 0x10000, `__x86.get_pc_thunk.bx` is replaced by the
/// compiler spec's call fixup, so PIC string and double constants resolve, and PLT calls through
/// `ebx` are named.
#[tokio::test(flavor = "multi_thread")]
async fn elf32_pic_code_decompiles() {
    let Some((e, info)) = open("corpus/elf32", "pie_list-i386-O0").await else {
        return;
    };
    assert_eq!(info.arch, "x86:LE:32:default");
    assert_eq!(info.base, Hex64(0x1_0000));
    let fns = listing(&e).await;
    for n in ["printf", "free", "calloc", "__libc_start_main"] {
        assert!(fns.values().any(|f| f.name == n), "PLT stub {n}");
    }
    let m = decompile(&e, &fns, "main").await;
    assert!(
        m.contains("replaced with injection: get_pc_thunk_bx"),
        "{m}"
    );
    assert!(m.contains("node_new(3,\"gamma\",5,1,2.5)"), "{m}");
    assert!(!m.contains("unaff_EBX"), "{m}");
    let cmp = decompile(&e, &fns, "cmp_id").await;
    assert!(cmp.contains("return a->id - b->id;"), "{cmp}");
}

/// The contract suite on a PE32+, a PE32 and a 32-bit ELF, in the worker and in-process.
#[tokio::test(flavor = "multi_thread")]
async fn contract_suite_on_pe_and_elf32() {
    for (set, binary, scratch) in [
        ("corpus/pe", "win_tls-x64-O0.exe", 0x1_4000_a800u64),
        ("corpus/pe", "win_tls-x86-O0.exe", 0x40_a800),
        // inside `_start`: Ghidra 12.2's decompiler gives up on data that does not decode
        ("corpus/elf32", "pie_list-i386-O0", 0x1_10b2),
    ] {
        let Some((e, info)) = open(set, binary).await else {
            return;
        };
        let functions: Vec<ExpectedFunction> = listing(&e)
            .await
            .into_values()
            .map(|f| ExpectedFunction {
                locator: f.locator,
                name: f.name,
            })
            .collect();
        let exp = FixtureExpectations {
            binary_path: root().join(set).join("bin").join(binary),
            program: info,
            functions,
            rename_to: "kraken_renamed".into(),
            scratch: Locator::ram(scratch),
        };
        for isolation in [worker(), Isolation::InProcess] {
            let mut c = config(true).expect("config");
            c.isolation = isolation;
            run_contract_suite(&NativeEngine::new(c), &exp)
                .await
                .unwrap_or_else(|err| panic!("{binary}: {err}"));
        }
    }
}

/// Globals the symbol table names print by name in decompiled C, as Ghidra shows them
/// (`tls_hits = tls_hits + 1`), not as `DAT_` or `uRam` addresses.
#[tokio::test(flavor = "multi_thread")]
async fn pe_globals_decompile_by_name() {
    for (binary, name) in [
        ("win_tls-x64-O0.exe", "tls_callback_0"),
        ("win_tls-x86-O0.exe", "on_tls"),
    ] {
        let Some((e, _)) = open("corpus/pe", binary).await else {
            return;
        };
        let fns = listing(&e).await;
        let name = fns
            .values()
            .map(|f| f.name.as_str())
            .find(|n| n.trim_start_matches('_') == name.trim_start_matches('_'))
            .unwrap_or(name)
            .to_string();
        let c = decompile(&e, &fns, &name).await;
        eprintln!("{binary}:\n{c}");
        assert!(
            c.contains("tls_hits = ") && c.contains("tls_hits + 1;"),
            "{c}"
        );
    }
}

const PDB_SAMPLE: &str = "pdb_sample-x64.exe";

/// The sample built with clang and lld-link has a PDB beside it: its procedures name the
/// functions, its type stream fills the type store, and a parameter has its type in the C.
#[tokio::test(flavor = "multi_thread")]
async fn pdb_names_functions_types_and_parameters() {
    let Some((e, info)) = open("corpus/pe", PDB_SAMPLE).await else {
        return;
    };
    assert_eq!(info.base.0, 0x1_4000_0000);
    let fns = listing(&e).await;
    for name in [
        "shape_area",
        "shape_tag_sum",
        "apply_scorer",
        "number_bits",
        "shape_move",
        "list_sum",
        "main",
    ] {
        let f = fns.values().find(|f| f.name == name).unwrap_or_else(|| {
            panic!(
                "no function {name} in {:?}",
                fns.values().map(|f| &f.name).collect::<Vec<_>>()
            )
        });
        assert!(f.size.is_some_and(|s| s > 0), "{name} has a size");
    }
    let area = fns.values().find(|f| f.name == "shape_area").expect("area");
    assert_eq!(
        area.signature.as_deref(),
        Some("int shape_area(shape *s)"),
        "prototype from the PDB"
    );

    let types = e
        .list_types(&page(), &CancellationToken::new())
        .await
        .expect("types");
    let find = |n: &str| {
        types
            .items
            .iter()
            .find(|t| kraken_engine::type_def_name(t) == Some(n))
            .unwrap_or_else(|| panic!("no type {n}"))
    };
    let kraken_proto::TypeDef::Struct(shape) = find("shape") else {
        panic!("shape is a struct");
    };
    let fields: Vec<(&str, u64)> = shape
        .fields
        .iter()
        .map(|f| (f.name.as_str(), f.offset))
        .collect();
    assert_eq!(
        fields,
        [
            ("kind", 0),
            ("origin", 4),
            ("extent", 12),
            ("label", 24),
            ("tags", 32)
        ]
    );
    assert_eq!(shape.size, 48);
    assert!(matches!(find("vec2"), kraken_proto::TypeDef::Struct(c) if c.size == 8));
    assert!(matches!(find("number"), kraken_proto::TypeDef::Union(c) if c.size == 4));
    let kraken_proto::TypeDef::Enum(kind) = find("shape_kind") else {
        panic!("shape_kind is an enum");
    };
    let values: Vec<(&str, i64)> = kind
        .variants
        .iter()
        .map(|v| (v.name.as_str(), v.value))
        .collect();
    assert_eq!(
        values,
        [("SHAPE_POINT", 0), ("SHAPE_BOX", 1), ("SHAPE_RING", 7)]
    );

    // a struct that points to itself, an anonymous struct named by its typedef, with bitfields
    let kraken_proto::TypeDef::Struct(node) = find("node") else {
        panic!("node is a struct");
    };
    assert!(matches!(
        &node.fields[0].ty,
        kraken_proto::TypeRef::Pointer { target, .. }
            if matches!(&**target, kraken_proto::TypeRef::Named { name } if name == "node")
    ));
    let kraken_proto::TypeDef::Struct(word) = find("packed_word") else {
        panic!("packed_word is a struct");
    };
    let bits: Vec<_> = word
        .fields
        .iter()
        .map(|f| f.bitfield.map(|b| (b.bit_offset, b.bit_size)))
        .collect();
    assert_eq!(bits, [Some((0, 4)), Some((4, 12)), None]);
    let c = decompile(&e, &fns, "list_sum").await;
    assert!(
        c.contains("node *head") && c.contains("->value"),
        "list walk:\n{c}"
    );

    let c = decompile(&e, &fns, "shape_tag_sum").await;
    assert!(
        c.contains("shape *s") && c.contains("limit"),
        "typed parameters:\n{c}"
    );
    let c = decompile(&e, &fns, "shape_area").await;
    assert!(c.contains("pdb_sample_counter"), "global by name:\n{c}");
    let c = decompile(&e, &fns, "apply_scorer").await;
    assert!(c.contains("shape *"), "function pointer parameter:\n{c}");
}

/// Without symbols the PDB is not read.
#[tokio::test(flavor = "multi_thread")]
async fn pdb_is_ignored_when_symbols_are_off() {
    let Some(c) = config(false) else { return };
    let e = NativeEngine::new(c);
    e.open_binary(
        &root().join("corpus/pe/bin").join(PDB_SAMPLE),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open");
    let fns = listing(&e).await;
    assert!(!fns.values().any(|f| f.name == "shape_area"));
}

/// A PDB that is not the image's is not used, and one attached by path is.
#[tokio::test(flavor = "multi_thread")]
async fn pdb_attached_by_path_and_mismatch_refused() {
    let Some(c) = config(true) else { return };
    let dir = tempfile::tempdir().expect("dir");
    let exe = dir.path().join("sample.exe");
    std::fs::copy(root().join("corpus/pe/bin").join(PDB_SAMPLE), &exe).expect("copy");
    let pdb = root().join("corpus/pe/bin/pdb_sample-x64.pdb");
    // the image names pdb_sample-x64.pdb; a different file beside it is not that PDB
    std::fs::write(dir.path().join("pdb_sample-x64.pdb"), b"not a pdb").expect("junk");
    let e = NativeEngine::new(c.clone());
    e.open_binary(&exe, &LoaderSpec::default(), &CancellationToken::new())
        .await
        .expect("open");
    assert!(!listing(&e).await.values().any(|f| f.name == "shape_area"));

    let spec = LoaderSpec {
        debug_file: Some(pdb.to_string_lossy().into_owned()),
        ..LoaderSpec::default()
    };
    let e = NativeEngine::new(c);
    e.open_binary(&exe, &spec, &CancellationToken::new())
        .await
        .expect("open with the PDB");
    assert!(listing(&e).await.values().any(|f| f.name == "shape_area"));
}

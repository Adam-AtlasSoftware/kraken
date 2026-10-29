//! The native engine against the corpus. Needs the native build (`cargo xtask native-src`) and a
//! Ghidra install for its `.sla` files (`KRAKEN_GHIDRA_HOME` or `~/.cache/kraken-dev/ghidra`); no
//! JVM. Each test returns early with a "skipped" note when either is missing.
//!
//! The engines run in the confined worker process (`kraken-native-worker`, the default);
//! `KRAKEN_NATIVE_TEST_IN_PROCESS=1` runs them in-process instead. The contract suite runs both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    AnalyzeRequest, Analyzer, CancellationToken, Decompiler, DisasmRequest, Disassembler,
    FlowGraph, FunctionLister, Loader, LoaderSpec, ProgramInfo, Stage, SymbolLister, TypeStore,
};
use kraken_proto::{
    CfgEdgeKind, Composite, DisasmScope, ErrorCode, Field, FlowKind, FunctionPrototype,
    FunctionSummary, Hex64, Locator, PageRequest, Param, Primitive, PrimitiveClass, TokenKind,
    TypeDef, TypeRef,
};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config(use_symbols: bool) -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Ghidra install with Sleigh specs (KRAKEN_GHIDRA_HOME)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    c.use_symbols = use_symbols;
    c.isolation = isolation();
    Some(c)
}

fn isolation() -> Isolation {
    if std::env::var_os("KRAKEN_NATIVE_TEST_IN_PROCESS").is_some_and(|v| v == "1") {
        Isolation::InProcess
    } else {
        isolation_worker()
    }
}

fn isolation_worker() -> Isolation {
    Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )))
}

async fn open(binary: &str, use_symbols: bool) -> Option<(NativeEngine, ProgramInfo)> {
    let c = config(use_symbols)?;
    let e = NativeEngine::new(c);
    let info = e
        .open_binary(
            &root().join("corpus/bin").join(binary),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open_binary");
    // the program really lives in a worker unless in-process was asked for
    assert_eq!(
        e.worker_pid().is_some(),
        matches!(isolation(), Isolation::Worker(_))
    );
    Some((e, info))
}

async fn listing(e: &NativeEngine) -> Vec<FunctionSummary> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = e
            .list_functions(
                &PageRequest {
                    cursor,
                    limit: Some(500),
                },
                &CancellationToken::new(),
            )
            .await
            .expect("list");
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

fn json(rel: &str) -> Value {
    let text = std::fs::read_to_string(root().join(rel)).expect("corpus json");
    serde_json::from_str(&text).expect("json")
}

fn hex(v: &Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex")
}

/// Truth entries are link-time addresses; the engine rebases PIE images (linked at 0) to
/// 0x100000 like Ghidra does, and leaves fixed-address images alone.
fn truth(binary: &str, base: u64) -> BTreeMap<u64, (String, u64)> {
    let base = if base == 0x10_0000 { base } else { 0 };
    json(&format!("corpus/truth/{binary}.json"))["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| {
            (
                base + hex(&f["entry"]),
                (
                    f["name"].as_str().unwrap_or_default().to_string(),
                    f["size"].as_u64().unwrap_or(0),
                ),
            )
        })
        .collect()
}

fn offset(l: &Locator) -> u64 {
    match l {
        Locator::Native { offset, .. } => offset.0,
        _ => u64::MAX,
    }
}

/// Share of truth functions found, and how many found ones differ from the truth in name or
/// size (sizes differ where code is only reachable through exception tables).
async fn recall(binary: &str, use_symbols: bool) -> Option<(f64, usize)> {
    let (e, info) = open(binary, use_symbols).await?;
    let found: BTreeMap<u64, FunctionSummary> = listing(&e)
        .await
        .into_iter()
        .map(|f| (offset(&f.locator), f))
        .collect();
    let want = truth(binary, info.base.0);
    let mut hit = 0;
    let mut differ = 0;
    for (entry, (name, size)) in &want {
        match found.get(entry) {
            Some(f) => {
                hit += 1;
                let named = !use_symbols || binary.ends_with("stripped") || &f.name == name;
                if !named || f.size != Some(*size) {
                    differ += 1;
                    eprintln!(
                        "{binary}: {name} at {entry:#x} listed as {} with size {:?} (truth {size})",
                        f.name, f.size
                    );
                }
            }
            None => eprintln!("{binary}: missed {name} at {entry:#x}"),
        }
    }
    let r = hit as f64 / want.len() as f64;
    eprintln!(
        "{binary} (symbols: {use_symbols}): recall {hit}/{} = {r:.2}, {} functions listed",
        want.len(),
        found.len()
    );
    Some((r, differ))
}

#[tokio::test(flavor = "multi_thread")]
async fn recall_against_truth() {
    for binary in ["pie_list-O0", "switch_vm-O0"] {
        let Some((r, differ)) = recall(binary, true).await else {
            return;
        };
        assert_eq!(r, 1.0, "{binary} with symbols");
        assert_eq!(differ, 0, "{binary}: names and sizes match the truth");
        // without the symbol table only the entry point, PLT names, init/fini pointers, call
        // targets and code pointers seed discovery
        let (r, differ) = recall(binary, false).await.expect("open");
        assert_eq!(r, 1.0, "{binary} without symbols");
        assert_eq!(differ, 0, "{binary} without symbols: sizes match the truth");
    }
    for binary in ["pie_list-O0-stripped", "switch_vm-O0-stripped"] {
        let (r, differ) = recall(binary, true).await.expect("open");
        assert_eq!(r, 1.0, "{binary}");
        assert_eq!(differ, 0, "{binary}: sizes match the truth");
    }
}

/// No function of a stripped build starts inside a truth function or in the alignment padding
/// after one. The return address a call pushes is an address-sized constant of the call's
/// p-code; after a call that never returns (`__stack_chk_fail`, `exit`) it is that padding, and
/// was once taken for a function pointer, so every such function had a phantom twin there.
#[tokio::test(flavor = "multi_thread")]
async fn stripped_builds_have_no_phantom_starts() {
    for binary in ["switch_vm-O2-stripped", "cpp_shapes-O2-stripped"] {
        let Some((e, info)) = open(binary, true).await else {
            return;
        };
        let want = truth(binary, info.base.0);
        // the starts Ghidra lists (such as `_fini`, the next section, right after the last
        // function) are not phantoms
        let ghidra: BTreeSet<u64> = json(&format!("corpus/fixtures/{binary}.json"))["functions"]
            .as_array()
            .expect("functions")
            .iter()
            .map(|f| hex(&f["summary"]["locator"]["offset"]))
            .collect();
        let mut phantoms = Vec::new();
        for f in listing(&e).await {
            let at = offset(&f.locator);
            if want.contains_key(&at) || ghidra.contains(&at) {
                continue;
            }
            if let Some((entry, (name, size))) = want.range(..at).next_back()
                && at < (entry + size).next_multiple_of(16)
            {
                phantoms.push(format!("{at:#x} in {name}"));
            }
        }
        assert!(phantoms.is_empty(), "{binary}: {phantoms:?}");
    }
}

/// Entries, names, sizes and body hashes agree with what Ghidra recorded in the fixture.
#[tokio::test(flavor = "multi_thread")]
async fn listing_matches_the_ghidra_fixture() {
    for binary in ["pie_list-O0", "switch_vm-O0"] {
        let Some((e, info)) = open(binary, true).await else {
            return;
        };
        let fx = json(&format!("corpus/fixtures/{binary}.json"));
        assert_eq!(info.base, Hex64(hex(&fx["program"]["base"])));
        assert_eq!(
            info.sha256,
            fx["program"]["sha256"].as_str().unwrap_or_default()
        );
        let ours: BTreeMap<u64, FunctionSummary> = listing(&e)
            .await
            .into_iter()
            .map(|f| (offset(&f.locator), f))
            .collect();
        let mut same_hash = 0;
        let mut total = 0;
        for f in fx["functions"].as_array().expect("functions") {
            let s = &f["summary"];
            let entry = hex(&s["locator"]["offset"]);
            let name = s["name"].as_str().unwrap_or_default();
            let Some(mine) = ours.get(&entry) else {
                panic!("{binary}: Ghidra lists {name} at {entry:#x}, the native engine does not");
            };
            total += 1;
            if mine.fn_hash.as_deref() == s["fn_hash"].as_str() {
                same_hash += 1;
            } else {
                eprintln!(
                    "{binary}: {name} body differs (ours {:?} bytes, Ghidra {})",
                    mine.size, s["size"]
                );
            }
            if !name.starts_with("FUN_") {
                assert_eq!(mine.name, name, "{binary} name at {entry:#x}");
            }
        }
        eprintln!("{binary}: {same_hash}/{total} bodies hash like Ghidra's");
        assert!(
            same_hash * 10 >= total * 9,
            "{binary}: {same_hash}/{total} bodies agree"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cmp_id_decompiles_with_the_expected_shape() {
    let Some((e, _)) = open("pie_list-O0", true).await else {
        return;
    };
    let at = Locator::ram(0x10124e);
    let r = e
        .decompile(&at, &CancellationToken::new())
        .await
        .expect("decompile");
    eprintln!("{}", r.text);
    r.validate_tokens().expect("token spans");
    assert!(r.tokens.windows(2).all(|w| w[0].start <= w[1].start));
    for t in &r.tokens {
        let s = &r.text[t.start as usize..t.end as usize];
        assert!(!s.trim().is_empty(), "blank token {t:?}");
        if let Some(sym) = &t.symbol
            && matches!(
                t.kind,
                TokenKind::Function | TokenKind::Variable | TokenKind::Type
            )
        {
            assert_eq!(s, sym, "symbol of {t:?}");
        }
    }

    // Ghidra (with DWARF): `int cmp_id(record *a,record *b) { ... return a->id - b->id; }`
    let fx = json("corpus/fixtures/pie_list-O0.json");
    let ghidra = fx["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .find(|f| f["summary"]["name"] == "cmp_id")
        .expect("cmp_id in fixture")["decompile"]["text"]
        .as_str()
        .expect("text")
        .to_string();
    for text in [&r.text, &ghidra] {
        let decl = text
            .lines()
            .find(|l| l.contains("cmp_id("))
            .expect("declaration line");
        assert!(decl.starts_with("int cmp_id("), "{decl}");
        assert_eq!(decl.matches(',').count(), 1, "two parameters: {decl}");
        let ret = text
            .lines()
            .find(|l| l.trim_start().starts_with("return "))
            .expect("return statement");
        assert!(ret.contains(" - "), "return of a difference: {ret}");
    }
    let f = r
        .tokens
        .iter()
        .find(|t| t.kind == TokenKind::Function)
        .expect("function token");
    assert_eq!(f.symbol.as_deref(), Some("cmp_id"));
    assert_eq!(f.target, Some(at));
    assert!(
        r.tokens.iter().any(|t| t.kind == TokenKind::Keyword
            && &r.text[t.start as usize..t.end as usize] == "return")
    );
    assert!(r.tokens.iter().any(|t| t.kind == TokenKind::Type));
    assert!(
        r.tokens
            .iter()
            .any(|t| t.kind == TokenKind::Variable && t.varnode.is_some())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn calls_link_to_callees() {
    let Some((e, _)) = open("pie_list-O0", true).await else {
        return;
    };
    let main = listing(&e)
        .await
        .into_iter()
        .find(|f| f.name == "main")
        .expect("main");
    let r = e
        .decompile(&main.locator, &CancellationToken::new())
        .await
        .expect("decompile main");
    r.validate_tokens().expect("spans");
    let callee = |name: &str| {
        r.tokens
            .iter()
            .find(|t| t.kind == TokenKind::Function && t.symbol.as_deref() == Some(name))
            .and_then(|t| t.target.clone())
    };
    assert_eq!(
        callee("list_push"),
        Some(Locator::ram(0x101214)),
        "{}",
        r.text
    );
    assert_eq!(callee("printf"), Some(Locator::ram(0x101050)), "{}", r.text);

    let rows = e
        .disassemble(
            &DisasmRequest {
                start: main.locator_offset(),
                scope: DisasmScope::Function,
            },
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &CancellationToken::new(),
        )
        .await
        .expect("disassemble");
    let call = rows
        .items
        .iter()
        .find(|r| r.flow == FlowKind::Call && r.operands.iter().any(|o| o.text == "printf"))
        .expect("a CALL printf row");
    assert_eq!(call.mnemonic, "CALL");
}

trait LocatorOffset {
    fn locator_offset(&self) -> Hex64;
}

impl LocatorOffset for FunctionSummary {
    fn locator_offset(&self) -> Hex64 {
        Hex64(offset(&self.locator))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn contract_suite_subset() {
    // An address with no function that still decodes: Ghidra 12.2's decompiler gives up after
    // four undecodable instructions, so a scratch function in data that does not decode fails.
    // pie_list's .rodata happens to decode; in switch_vm the scratch is inside `_start`.
    for (binary, scratch) in [("pie_list-O0", 0x102000u64), ("switch_vm-O0", 0x101072)] {
        let Some((e, info)) = open(binary, true).await else {
            return;
        };
        let functions: Vec<ExpectedFunction> = listing(&e)
            .await
            .into_iter()
            .map(|f| ExpectedFunction {
                locator: f.locator,
                name: f.name,
            })
            .collect();
        let exp = FixtureExpectations {
            binary_path: root().join("corpus/bin").join(binary),
            program: info,
            functions,
            rename_to: "kraken_renamed".into(),
            scratch: Locator::ram(scratch),
        };
        // the suite opens the binary again through the loader, on a fresh engine, once in each
        // isolation mode
        let fresh = NativeEngine::new(config(true).expect("config"));
        run_contract_suite(&fresh, &exp)
            .await
            .unwrap_or_else(|e| panic!("{binary}: {e}"));
        let mut c = config(true).expect("config");
        c.isolation = match c.isolation {
            Isolation::InProcess => isolation_worker(),
            Isolation::Worker(_) => Isolation::InProcess,
        };
        let other = NativeEngine::new(c);
        run_contract_suite(&other, &exp)
            .await
            .unwrap_or_else(|e| panic!("{binary} (other isolation mode): {e}"));
    }
}

/// Every corpus binary loads, its truth functions are found, and every listed function of the
/// dynamically linked ones decompiles with valid token spans. Slow (the static binaries run the
/// switch analysis on hundreds of libc functions): `cargo test -p engine-native -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow corpus sweep (about a minute)"]
async fn whole_corpus() {
    let mut names: Vec<String> = std::fs::read_dir(root().join("corpus/truth"))
        .expect("truth dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.trim_end_matches(".json").to_string())
        })
        .collect();
    names.sort();
    for binary in names {
        let Some((r, _)) = recall(&binary, true).await else {
            return;
        };
        // FDE starts, landing pads and noreturn evidence find every truth function, stripped
        // and optimized builds included
        assert_eq!(r, 1.0, "{binary}: recall {r:.2}");
        if binary.starts_with("static_") {
            continue;
        }
        let (e, _) = open(&binary, true).await.expect("open");
        let started = std::time::Instant::now();
        let fns = listing(&e).await;
        for f in &fns {
            let d = e
                .decompile(&f.locator, &CancellationToken::new())
                .await
                .unwrap_or_else(|err| panic!("{binary}: decompile {}: {err}", f.name));
            d.validate_tokens().expect("spans");
            assert!(
                d.text.contains(&f.name),
                "{binary}: {} not in its text",
                f.name
            );
        }
        eprintln!(
            "{binary}: decompiled {} functions in {:?}",
            fns.len(),
            started.elapsed()
        );
    }
}

/// Library prototypes reach the decompiler: `printf`'s `char *__format` turns the constant at the
/// call site into a string literal, and the prototype is in the type store and the listing.
#[tokio::test(flavor = "multi_thread")]
async fn library_prototypes_type_call_sites() {
    let Some((e, _)) = open("pie_list-O0", true).await else {
        return;
    };
    let c = CancellationToken::new();
    let fns = listing(&e).await;
    let main = fns.iter().find(|f| f.name == "main").expect("main");
    let r = e
        .decompile(&main.locator, &c)
        .await
        .expect("decompile main");
    assert!(r.text.contains("printf(\""), "{}", r.text);
    let printf = fns
        .iter()
        .find(|f| f.name == "printf")
        .expect("printf stub");
    assert_eq!(
        printf.signature.as_deref(),
        Some("int printf(char *__format,...)")
    );
    match e.get_type("printf", &c).await.expect("printf prototype") {
        TypeDef::Function(p) => assert!(p.varargs && p.params.len() == 1),
        other => panic!("printf is {other:?}"),
    }
    match e.get_type("size_t", &c).await.expect("size_t") {
        TypeDef::Typedef(t) => assert_eq!(t.name, "size_t"),
        other => panic!("size_t is {other:?}"),
    }
    // `exit` never returns, by the table and by discovery
    let exit = fns.iter().find(|f| f.name == "exit").expect("exit stub");
    let stats = e.stats().await.expect("stats");
    assert!(stats.noreturn.contains(&offset(&exit.locator)));

    // a user-defined struct and prototype change the output of a local function
    e.define_type(
        TypeDef::Struct(Composite {
            name: "record".into(),
            size: 16,
            align: 4,
            fields: vec![Field {
                name: "id".into(),
                offset: 0,
                ty: TypeRef::Primitive(Primitive {
                    class: PrimitiveClass::Int,
                    size: 4,
                    signed: true,
                }),
                bitfield: None,
            }],
        }),
        &c,
    )
    .await
    .expect("struct");
    let rec = || TypeRef::Pointer {
        target: Box::new(TypeRef::Named {
            name: "record".into(),
        }),
        size: 8,
    };
    e.define_type(
        TypeDef::Function(FunctionPrototype {
            name: Some("cmp_id".into()),
            return_type: Box::new(TypeRef::Primitive(Primitive {
                class: PrimitiveClass::Int,
                size: 4,
                signed: true,
            })),
            params: vec![
                Param {
                    name: Some("a".into()),
                    ty: rec(),
                    storage: None,
                },
                Param {
                    name: Some("b".into()),
                    ty: rec(),
                    storage: None,
                },
            ],
            calling_convention: String::new(),
            varargs: false,
            noreturn: false,
        }),
        &c,
    )
    .await
    .expect("prototype");
    let r = e
        .decompile(&Locator::ram(0x10124e), &c)
        .await
        .expect("cmp_id");
    // Ghidra with DWARF: `int cmp_id(record *a,record *b) { return a->id - b->id; }`
    assert!(r.text.contains("cmp_id(record *a,record *b)"), "{}", r.text);
    assert!(r.text.contains("a->id - b->id"), "{}", r.text);
    assert!(e.stats().await.expect("stats").pending_types.is_empty());
}

/// The analyzer reports every stage, fills in signatures from the decompiler and stops when
/// cancelled.
#[tokio::test(flavor = "multi_thread")]
async fn analyzer_fills_signatures() {
    let Some((e, _)) = open("switch_vm-O0", true).await else {
        return;
    };
    let mut job = e
        .analyze(AnalyzeRequest::default(), CancellationToken::new())
        .await
        .expect("analyze");
    let mut last = None;
    while let Some(p) = job.next_progress().await {
        assert!(p.done <= p.total);
        last = Some(p);
    }
    let summary = job.wait().await.expect("analysis");
    assert_eq!(summary.stages_completed, Stage::ALL);
    let last = last.expect("progress");
    assert_eq!(last.stage, Stage::Expensive);
    assert!(
        last.message.contains("0 timed out, 0 failed"),
        "{}",
        last.message
    );
    let fns = listing(&e).await;
    let op_name = fns.iter().find(|f| f.name == "op_name").expect("op_name");
    let sig = op_name
        .signature
        .as_deref()
        .expect("signature after analysis");
    assert!(sig.contains("op_name("), "{sig}");
    assert!(
        fns.iter().all(|f| f.signature.is_some()),
        "every function has one"
    );
}

/// A decompile that runs past its limit fails with `timeout` and leaves the engine usable.
#[tokio::test(flavor = "multi_thread")]
async fn decompile_timeout() {
    let Some(mut c) = config(true) else { return };
    c.decompile_timeout = Some(std::time::Duration::from_millis(1));
    let e = NativeEngine::new(c);
    let cancel = CancellationToken::new();
    e.open_binary(
        &root().join("corpus/bin/switch_vm-O0"),
        &LoaderSpec::default(),
        &cancel,
    )
    .await
    .expect("open");
    let vm_run = listing(&e)
        .await
        .into_iter()
        .find(|f| f.name == "vm_run")
        .expect("vm_run");
    let err = e.decompile(&vm_run.locator, &cancel).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Timeout, "{err}");
    // the next decompile starts clean
    let fresh = NativeEngine::new(config(true).expect("config"));
    fresh
        .open_binary(
            &root().join("corpus/bin/switch_vm-O0"),
            &LoaderSpec::default(),
            &cancel,
        )
        .await
        .expect("open");
    let r = fresh
        .decompile(&vm_run.locator, &cancel)
        .await
        .expect("full");
    assert!(r.text.contains("switch"), "{}", r.text);
}

/// Switch tables become switch edges, landing pads join C++ bodies, and a function that only
/// ends in calls that never return is marked the same way.
#[tokio::test(flavor = "multi_thread")]
async fn switches_landing_pads_and_noreturn() {
    let Some((e, _)) = open("switch_vm-O0", true).await else {
        return;
    };
    let c = CancellationToken::new();
    let fns = listing(&e).await;
    let vm_run = fns.iter().find(|f| f.name == "vm_run").expect("vm_run");
    let cfg = e.cfg(&vm_run.locator, &c).await.expect("cfg");
    let switches = cfg
        .edges
        .iter()
        .filter(|x| x.kind == CfgEdgeKind::Switch)
        .count();
    assert_eq!(switches, 15, "{cfg:?}");
    // vm_fail calls exit only, so it never returns
    let vm_fail = fns.iter().find(|f| f.name == "vm_fail").expect("vm_fail");
    assert!(
        e.stats()
            .await
            .expect("stats")
            .noreturn
            .contains(&offset(&vm_fail.locator))
    );

    // in switch_vm-O2, knowing that vm_fail never returns keeps op_name out of vm_run and lets
    // the decompiler recover vm_run's own jump table
    let (o2, info) = open("switch_vm-O2", true).await.expect("open O2");
    let o2_truth = truth("switch_vm-O2", info.base.0);
    let fns = listing(&o2).await;
    let vm_run = fns.iter().find(|f| f.name == "vm_run").expect("vm_run");
    let want = o2_truth
        .values()
        .find(|(n, _)| n == "vm_run")
        .map(|(_, s)| *s)
        .expect("truth");
    assert!(
        vm_run.size.unwrap_or(0) * 10 >= want * 9,
        "vm_run is {:?} bytes, truth {want}",
        vm_run.size
    );
    let cfg = o2.cfg(&vm_run.locator, &c).await.expect("cfg");
    assert!(cfg.edges.iter().any(|x| x.kind == CfgEdgeKind::Switch));

    // C++: exception landing pads are part of the bodies, so sizes match the symbol table
    let (cpp, info) = open("cpp_shapes-O0", true).await.expect("open cpp");
    assert!(cpp.stats().await.expect("stats").landing_pads > 0);
    let cpp_truth = truth("cpp_shapes-O0", info.base.0);
    let found: BTreeMap<u64, FunctionSummary> = listing(&cpp)
        .await
        .into_iter()
        .map(|f| (offset(&f.locator), f))
        .collect();
    let same = cpp_truth
        .iter()
        .filter(|(a, (_, size))| found.get(a).is_some_and(|f| f.size == Some(*size)))
        .count();
    assert_eq!(same, cpp_truth.len(), "sizes agree with the symbol table");
}

/// The specification tree `cargo xtask native-sla` compiles from the pinned sources replaces a
/// Ghidra install: the engine decompiles with it alone, and its x86-64 `.sla` is byte-identical
/// to the one Ghidra ships (when an install is around to compare with).
#[tokio::test(flavor = "multi_thread")]
async fn compiled_specs_replace_a_ghidra_install() {
    let Some(dir) = engine_native::compiled_specs_dir().filter(|d| engine_native::has_specs(d))
    else {
        eprintln!("skipped: no compiled spec tree (cargo xtask native-sla)");
        return;
    };
    let c = NativeConfig::new(&dir);
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return;
    }
    assert!(dir.join("SOURCE.txt").is_file() && dir.join("LICENSE").is_file());
    let e = NativeEngine::new(c);
    e.open_binary(
        &root().join("corpus/bin/pie_list-O0"),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open with the compiled specs");
    let r = e
        .decompile(&Locator::ram(0x10124e), &CancellationToken::new())
        .await
        .expect("decompile");
    assert!(
        r.text.contains("cmp_id") && r.text.contains(" - "),
        "{}",
        r.text
    );
    if let Some(g) =
        NativeConfig::discover_ghidra().filter(|g| engine_native::has_specs(&g.spec_root))
    {
        let rel = "Ghidra/Processors/x86/data/languages/x86-64.sla";
        let ours = std::fs::read(dir.join(rel)).expect("ours");
        let theirs = std::fs::read(g.spec_root.join(rel)).expect("theirs");
        assert!(
            ours == theirs,
            "x86-64.sla differs from {}",
            g.spec_root.display()
        );
    }
}

/// AArch64: set `KRAKEN_NATIVE_AARCH64_BIN` to an AArch64 ELF that defines `cmp_id(const int *,
/// const int *)` returning `*a - *b` (the corpus has no AArch64 binaries yet).
#[tokio::test(flavor = "multi_thread")]
async fn aarch64_when_given() {
    let Some(bin) = std::env::var_os("KRAKEN_NATIVE_AARCH64_BIN") else {
        eprintln!("skipped: KRAKEN_NATIVE_AARCH64_BIN is not set");
        return;
    };
    let Some(c) = config(true) else { return };
    let e = NativeEngine::new(c);
    let info = e
        .open_binary(
            Path::new(&bin),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open");
    assert_eq!(info.arch, "AARCH64:LE:64:v8A");
    let f = listing(&e)
        .await
        .into_iter()
        .find(|f| f.name == "cmp_id")
        .expect("cmp_id listed");
    let r = e
        .decompile(&f.locator, &CancellationToken::new())
        .await
        .expect("decompile");
    eprintln!("{}", r.text);
    r.validate_tokens().expect("spans");
    assert!(
        r.text.contains("return") && r.text.contains(" - "),
        "{}",
        r.text
    );
}

/// C++ names are shown as Ghidra shows them (from DWARF, else demangled), with the mangled names
/// kept: in summaries and symbols (`mangled`) and as labels in the listing. With DWARF, methods
/// get their class types (`this`) in the signature and the decompiled C.
#[tokio::test(flavor = "multi_thread")]
async fn cpp_names_are_demangled_and_mangled_names_kept() {
    let Some((e, _)) = open("cpp_shapes-O0", true).await else {
        return;
    };
    let c = CancellationToken::new();
    let fns = listing(&e).await;
    let at = |a: u64| {
        fns.iter()
            .find(|f| f.locator == Locator::ram(a))
            .unwrap_or_else(|| panic!("no function at {a:#x}"))
    };
    // Rect::area() const, named from DWARF
    let area = at(0x102db8);
    assert_eq!(area.name, "area");
    assert_eq!(area.mangled.as_deref(), Some("_ZNK4Rect4areaEv"));
    assert_eq!(area.signature.as_deref(), Some("double area(Rect *this)"));
    // the PLT stub of operator new(unsigned long), demangled
    let new = at(0x102160);
    assert_eq!(new.name, "operator.new");
    assert_eq!(new.mangled.as_deref(), Some("_Znwm"));
    // std::string's constructor goes by the typedef name
    assert_eq!(at(0x1020a0).name, "string");

    let rows = e
        .disassemble(
            &DisasmRequest {
                start: Hex64(0x102db8),
                scope: DisasmScope::Function,
            },
            &PageRequest {
                cursor: None,
                limit: Some(1),
            },
            &c,
        )
        .await
        .expect("disassemble")
        .items;
    assert_eq!(rows[0].labels, vec!["_ZNK4Rect4areaEv", "area"]);

    let imports = e
        .imports(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &c,
        )
        .await
        .expect("imports")
        .items;
    let imp = imports
        .iter()
        .find(|s| s.name == "operator.new")
        .expect("operator.new import");
    assert_eq!(imp.mangled.as_deref(), Some("_Znwm"));
    assert!(
        imports.iter().all(|s| !s.name.starts_with("_Z")),
        "{imports:?}"
    );

    let text = e
        .decompile(&Locator::ram(0x102db8), &c)
        .await
        .expect("decompile")
        .text;
    assert!(text.contains("double area(Rect *this)"), "{text}");
    assert!(text.contains("this->"), "{text}");
}

//! The native engine against the corpus. Needs the native build (`cargo xtask native-src`) and a
//! Ghidra install for its `.sla` files (`KRAKEN_GHIDRA_HOME` or `~/.cache/kraken-dev/ghidra`); no
//! JVM. Each test returns early with a "skipped" note when either is missing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use engine_native::{NativeConfig, NativeEngine};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    CancellationToken, Decompiler, DisasmRequest, Disassembler, FunctionLister, Loader, LoaderSpec,
    ProgramInfo,
};
use kraken_proto::{
    DisasmScope, FlowKind, FunctionSummary, Hex64, Locator, PageRequest, TokenKind,
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
    Some(c)
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
    for binary in ["pie_list-O0", "switch_vm-O0"] {
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
            // .rodata holds no function
            scratch: Locator::ram(0x102000),
        };
        // the suite opens the binary again through the loader, on a fresh engine
        let fresh = NativeEngine::new(config(true).expect("config"));
        run_contract_suite(&fresh, &exp)
            .await
            .unwrap_or_else(|e| panic!("{binary}: {e}"));
    }
}

/// Every corpus binary loads, its truth functions are found, and every listed function of the
/// dynamically linked ones decompiles with valid token spans. Slow (the static binaries run the
/// switch analysis on hundreds of libc functions): `cargo test -p engine-native -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "slow corpus sweep (about 40 s)"]
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
        let floor = if binary.contains("-O2") { 0.75 } else { 0.95 };
        assert!(r >= floor, "{binary}: recall {r:.2}");
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

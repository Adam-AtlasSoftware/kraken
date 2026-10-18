//! How closely the native engine agrees with Ghidra, measured against the fixtures recorded from
//! real Ghidra (`corpus/fixtures`, `kraken-record`): function bodies, cross-references, CFGs,
//! strings, imports and exports. Needs the native build and a spec tree (see `tests/native.rs`);
//! skips otherwise.
//!
//! `cargo test -p engine-native --test agreement -- --nocapture` prints the numbers for the
//! guarded binaries; `-- --ignored --nocapture` prints them for all 20 (and with
//! `KRAKEN_AGREEMENT_SET=corpus/pe`, `corpus/elf32`, `corpus/arm32`, `corpus/aarch64`,
//! `corpus/riscv64` or `corpus/riscv32` for those sets). Names are compared by entry,
//! signatures without spacing (exactly, and by types alone).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use engine_native::{NativeConfig, NativeEngine};
use kraken_engine::{
    CancellationToken, FlowGraph, FunctionLister, Loader, LoaderSpec, MemoryReader, StringLister,
    StringsRequest, SymbolLister, XrefProvider, XrefRequest,
};
use kraken_proto::{Hex64, Locator, PageRequest, XrefDirection};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config() -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree (cargo xtask native-sla, or KRAKEN_GHIDRA_HOME)");
        return None;
    };
    c.isolation = engine_native::Isolation::Worker(engine_native::WorkerOptions::with_program(
        env!("CARGO_BIN_EXE_kraken-native-worker"),
    ));
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    Some(c)
}

fn hex(v: &Value) -> u64 {
    v.as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(u64::MAX)
}

fn page(cursor: Option<String>) -> PageRequest {
    PageRequest {
        cursor,
        limit: Some(500),
    }
}

/// Hits over the reference set and over our set.
#[derive(Debug, Default, Clone, Copy)]
struct Score {
    common: usize,
    theirs: usize,
    ours: usize,
}

impl Score {
    fn add<T: Ord>(&mut self, theirs: &BTreeSet<T>, ours: &BTreeSet<T>) {
        self.common += theirs.intersection(ours).count();
        self.theirs += theirs.len();
        self.ours += ours.len();
    }
    fn recall(&self) -> f64 {
        if self.theirs == 0 {
            1.0
        } else {
            self.common as f64 / self.theirs as f64
        }
    }
    fn precision(&self) -> f64 {
        if self.ours == 0 {
            1.0
        } else {
            self.common as f64 / self.ours as f64
        }
    }
}

impl std::fmt::Display for Score {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} = {:.1}% (precision {:.1}%)",
            self.common,
            self.theirs,
            100.0 * self.recall(),
            100.0 * self.precision()
        )
    }
}

#[derive(Debug, Default)]
struct Report {
    functions: Score,
    bodies: Score,
    xrefs: Score,
    xrefs_untyped: Score,
    xrefs_image: Score,
    callers: Score,
    cfg_same: Score,
    blocks: Score,
    edges: Score,
    strings: Score,
    imports: Score,
    exports: Score,
    names: Score,
    signatures: Score,
    signature_types: Score,
}

async fn compare(binary: &str, c: NativeConfig) -> Report {
    compare_in("corpus", binary, c).await
}

/// [`compare`] for a binary of the corpus set in `set` (`corpus`, `corpus/pe`, `corpus/elf32`).
async fn compare_in(set: &str, binary: &str, c: NativeConfig) -> Report {
    let e = NativeEngine::new(c);
    let cancel = CancellationToken::new();
    e.open_binary(
        &root().join(set).join("bin").join(binary),
        &LoaderSpec::default(),
        &cancel,
    )
    .await
    .expect("open");
    let text = std::fs::read_to_string(root().join(set).join(format!("fixtures/{binary}.json")))
        .expect("fixture");
    let fx: Value = serde_json::from_str(&text).expect("json");
    let mut r = Report::default();
    let mapped: Vec<(u64, u64)> = e
        .memory_map(&cancel)
        .await
        .expect("memory map")
        .iter()
        .map(|b| (b.start.0, b.end.0))
        .collect();

    let mut ours = BTreeMap::new();
    let mut cursor = None;
    loop {
        let p = e
            .list_functions(&page(cursor), &cancel)
            .await
            .expect("list");
        for f in p.items {
            if let Locator::Native { offset, .. } = &f.locator {
                ours.insert(offset.0, f);
            }
        }
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }

    for f in fx["functions"].as_array().into_iter().flatten() {
        let s = &f["summary"];
        let entry = hex(&s["locator"]["offset"]);
        let theirs: BTreeSet<u64> = [entry].into();
        let mine: BTreeSet<u64> = ours.keys().copied().filter(|a| *a == entry).collect();
        r.functions.add(&theirs, &mine);
        let Some(mine) = ours.get(&entry) else {
            continue;
        };
        let their_name = s["name"].as_str().unwrap_or("").to_string();
        if their_name != mine.name && std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
            eprintln!(
                "  {binary} name differs at {entry:#x}: native {:?}, Ghidra {their_name:?}",
                mine.name
            );
        }
        r.names
            .add(&[their_name].into(), &[mine.name.clone()].into());
        // signatures without spacing (Ghidra writes `record * a`, the decompiler `record *a`)
        let squash = |t: &str| t.split_whitespace().collect::<String>();
        let their_sig = s["signature"].as_str().map(squash);
        let my_sig = mine.signature.as_deref().map(squash);
        if let Some(t) = s["signature"].as_str() {
            let theirs = signature_types(t);
            let mine = mine.signature.as_deref().map(signature_types);
            r.signature_types.theirs += 1;
            r.signature_types.ours += usize::from(mine.is_some());
            r.signature_types.common += usize::from(mine.as_ref() == Some(&theirs));
        }
        if their_sig.is_some() {
            r.signatures.theirs += 1;
            r.signatures.ours += usize::from(my_sig.is_some());
            if their_sig == my_sig {
                r.signatures.common += 1;
            } else if my_sig.is_some() && std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
                eprintln!(
                    "  {binary} signature differs at {entry:#x}: native {:?}, Ghidra {:?}",
                    mine.signature,
                    s["signature"].as_str().unwrap_or("")
                );
            }
        }
        let same = mine.fn_hash.as_deref() == s["fn_hash"].as_str();
        if !same && std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
            eprintln!(
                "  {binary} body differs: {} at {entry:#x}, native {:?} bytes, Ghidra {}",
                s["name"].as_str().unwrap_or(""),
                mine.size,
                s["size"]
            );
        }
        r.bodies
            .add(&[0].into(), &(if same { [0].into() } else { [1].into() }));

        // outgoing references of the function, and the calls into it
        if let Some(xs) = f["xrefs"].as_array() {
            let typed = |x: &Value| (hex(&x["from"]), hex(&x["to"]), x["kind"].to_string());
            let theirs: BTreeSet<(u64, u64, String)> = xs
                .iter()
                .filter(|x| hex(&x["from_function"]["address"]) == entry)
                .map(typed)
                .collect();
            let callers: BTreeSet<u64> = xs
                .iter()
                .filter(|x| hex(&x["to"]) == entry && x["kind"] == "call")
                .map(|x| hex(&x["from"]))
                .collect();
            let mut mine = BTreeSet::new();
            let mut cursor = None;
            loop {
                let p = e
                    .xrefs(
                        &XrefRequest {
                            address: Hex64(entry),
                            direction: XrefDirection::From,
                            kind: None,
                            whole_function: true,
                        },
                        &page(cursor),
                        &cancel,
                    )
                    .await
                    .expect("xrefs");
                for x in p.items {
                    let v = serde_json::to_value(&x).expect("xref json");
                    mine.insert(typed(&v));
                }
                match p.next_cursor {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
            if std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
                for x in theirs.difference(&mine) {
                    eprintln!("  {binary} only Ghidra: {:#x} -> {:#x} {}", x.0, x.1, x.2);
                }
                for x in mine.difference(&theirs) {
                    eprintln!("  {binary} only native: {:#x} -> {:#x} {}", x.0, x.1, x.2);
                }
            }
            r.xrefs.add(&theirs, &mine);
            // Ghidra gives imports addresses in a synthetic EXTERNAL block past the image, which
            // has no counterpart in the file
            let in_image = |s: &BTreeSet<(u64, u64, String)>| {
                s.iter()
                    .filter(|(_, to, _)| mapped.iter().any(|(lo, hi)| lo <= to && to < hi))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            };
            r.xrefs_image.add(&in_image(&theirs), &in_image(&mine));
            let untyped = |s: &BTreeSet<(u64, u64, String)>| {
                s.iter().map(|(a, b, _)| (*a, *b)).collect::<BTreeSet<_>>()
            };
            r.xrefs_untyped.add(&untyped(&theirs), &untyped(&mine));
            let incoming = e
                .xrefs(
                    &XrefRequest {
                        address: Hex64(entry),
                        direction: XrefDirection::To,
                        kind: Some(kraken_proto::XrefKind::Call),
                        whole_function: false,
                    },
                    &PageRequest {
                        cursor: None,
                        limit: Some(100),
                    },
                    &cancel,
                )
                .await
                .expect("callers");
            let mine: BTreeSet<u64> = incoming.items.iter().map(|x| x.from.0).collect();
            if std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
                for x in callers.difference(&mine) {
                    eprintln!("  {binary} caller only Ghidra: {x:#x} -> {entry:#x}");
                }
            }
            r.callers.add(&callers, &mine);
        }

        if !f["cfg"].is_null() {
            let g = &f["cfg"];
            let theirs_b: BTreeSet<(u64, u64, u64)> = g["blocks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|b| {
                    (
                        hex(&b["start"]),
                        hex(&b["end"]),
                        b["instructions"].as_u64().unwrap_or(0),
                    )
                })
                .collect();
            let theirs_e: BTreeSet<(u64, u64, String)> = g["edges"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|x| (hex(&x["from"]), hex(&x["to"]), x["kind"].to_string()))
                .collect();
            let cfg = e.cfg(&Locator::ram(entry), &cancel).await.expect("cfg");
            let v = serde_json::to_value(&cfg).expect("cfg json");
            let mine_b: BTreeSet<(u64, u64, u64)> = v["blocks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|b| {
                    (
                        hex(&b["start"]),
                        hex(&b["end"]),
                        b["instructions"].as_u64().unwrap_or(0),
                    )
                })
                .collect();
            let mine_e: BTreeSet<(u64, u64, String)> = v["edges"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|x| (hex(&x["from"]), hex(&x["to"]), x["kind"].to_string()))
                .collect();
            let same = theirs_b == mine_b && theirs_e == mine_e;
            if std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
                for b in theirs_b.difference(&mine_b) {
                    eprintln!(
                        "  {binary} block only Ghidra: {:#x}..{:#x} n={}",
                        b.0, b.1, b.2
                    );
                }
                for b in mine_b.difference(&theirs_b) {
                    eprintln!(
                        "  {binary} block only native: {:#x}..{:#x} n={}",
                        b.0, b.1, b.2
                    );
                }
                for x in theirs_e.difference(&mine_e) {
                    eprintln!(
                        "  {binary} edge only Ghidra: {:#x} -> {:#x} {}",
                        x.0, x.1, x.2
                    );
                }
                for x in mine_e.difference(&theirs_e) {
                    eprintln!(
                        "  {binary} edge only native: {:#x} -> {:#x} {}",
                        x.0, x.1, x.2
                    );
                }
            }
            r.cfg_same
                .add(&[0].into(), &(if same { [0].into() } else { [1].into() }));
            r.blocks.add(&theirs_b, &mine_b);
            r.edges.add(&theirs_e, &mine_e);
        }
    }

    // strings: the fixture holds the referenced ones first, then the lowest addresses, capped;
    // precision only means something when it recorded every string Ghidra listed
    let theirs: BTreeSet<(u64, String)> = fx["strings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|s| {
            (
                hex(&s["address"]),
                s["value"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let mut mine = BTreeSet::new();
    let mut cursor = None;
    loop {
        let p = e
            .strings(
                &StringsRequest {
                    min_len: 4,
                    filter: None,
                },
                &page(cursor),
                &cancel,
            )
            .await
            .expect("strings");
        for s in p.items {
            mine.insert((s.address.0, s.value));
        }
        match p.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    let complete = fx["recording"]["strings_listed"] == fx["recording"]["strings_recorded"];
    if !complete {
        let lowest_capped: BTreeSet<_> = mine
            .iter()
            .filter(|s| theirs.contains(s))
            .cloned()
            .collect();
        // precision over ours is not measurable: count only the matched ones as ours
        r.strings.common = lowest_capped.len();
        r.strings.theirs = theirs.len();
        r.strings.ours = lowest_capped.len();
    } else {
        r.strings.add(&theirs, &mine);
    }

    let names = |v: &Value| -> BTreeSet<String> {
        v.as_array()
            .into_iter()
            .flatten()
            .map(|s| s["name"].as_str().unwrap_or("").to_string())
            .collect()
    };
    let imp = e.imports(&page(None), &cancel).await.expect("imports");
    let exp = e.exports(&page(None), &cancel).await.expect("exports");
    r.imports.add(
        &names(&fx["imports"]),
        &imp.items.iter().map(|s| s.name.clone()).collect(),
    );
    let exports_at = |v: &Value| -> BTreeSet<(u64, String)> {
        v.as_array()
            .into_iter()
            .flatten()
            .map(|s| {
                (
                    hex(&s["address"]),
                    s["name"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    };
    let theirs = exports_at(&fx["exports"]);
    let mine: BTreeSet<(u64, String)> = exp
        .items
        .iter()
        .map(|s| (s.address.map_or(u64::MAX, |a| a.0), s.name.clone()))
        .collect();
    if std::env::var_os("KRAKEN_AGREEMENT_DIFF").is_some() {
        for x in theirs.difference(&mine) {
            eprintln!("  {binary} export only Ghidra: {:#x} {}", x.0, x.1);
        }
        for x in mine.difference(&theirs) {
            eprintln!("  {binary} export only native: {:#x} {}", x.0, x.1);
        }
    }
    r.exports.add(&theirs, &mine);
    r
}

/// A signature without parameter names or spacing: `int cmp_id(record*,record*)`.
fn signature_types(sig: &str) -> String {
    let Some(open) = sig.find('(') else {
        return sig.split_whitespace().collect();
    };
    let close = sig.rfind(')').unwrap_or(sig.len());
    let head: String = sig[..open].split_whitespace().collect();
    let mut params = Vec::new();
    let (mut depth, mut start) = (0i32, open + 1);
    let inner_end = close.max(open + 1);
    for (i, c) in sig[..inner_end].char_indices().skip(open + 1) {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                params.push(&sig[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    params.push(&sig[start..inner_end]);
    let typed: Vec<String> = params
        .iter()
        .map(|p| {
            let spaced = p.replace('*', " * ");
            let mut words: Vec<&str> = spaced.split_whitespace().collect();
            let ident = |w: &str| w.chars().all(|c| c.is_alphanumeric() || c == '_');
            if words.len() >= 2 && words.last().is_some_and(|w| ident(w)) {
                words.pop();
            }
            words.concat()
        })
        .collect();
    format!("{head}({})", typed.join(","))
}

fn print(binary: &str, r: &Report) {
    eprintln!("== {binary}");
    eprintln!("  functions found      {}", r.functions);
    eprintln!("  bodies (fn_hash)     {}", r.bodies);
    eprintln!("  xrefs out (kind)     {}", r.xrefs);
    eprintln!("  xrefs out (from,to)  {}", r.xrefs_untyped);
    eprintln!("  xrefs out, in image  {}", r.xrefs_image);
    eprintln!("  callers              {}", r.callers);
    eprintln!("  cfg identical        {}", r.cfg_same);
    eprintln!("  cfg blocks           {}", r.blocks);
    eprintln!("  cfg edges (kind)     {}", r.edges);
    eprintln!("  strings              {}", r.strings);
    eprintln!("  imports (names)      {}", r.imports);
    eprintln!("  exports (addr,name)  {}", r.exports);
    eprintln!("  names (entry)        {}", r.names);
    eprintln!("  signatures           {}", r.signatures);
    eprintln!("  signature types      {}", r.signature_types);
}

#[tokio::test(flavor = "multi_thread")]
async fn agrees_with_ghidra_on_the_guarded_binaries() {
    for binary in ["pie_list-O0", "switch_vm-O0"] {
        let Some(c) = config() else { return };
        let r = compare(binary, c).await;
        print(binary, &r);
        assert_eq!(r.functions.recall(), 1.0, "{binary}: functions");
        assert!(r.bodies.recall() >= 0.9, "{binary}: bodies {}", r.bodies);
        assert!(
            r.xrefs_image.recall() >= 0.95,
            "{binary}: xrefs {}",
            r.xrefs_image
        );
        // Ghidra makes no operand references in code it reaches only through its later switch
        // analysis (switch_vm case bodies), where the native engine does
        assert!(
            r.xrefs_image.precision() >= 0.85,
            "{binary}: xrefs {}",
            r.xrefs_image
        );
        assert!(
            r.callers.recall() >= 0.95,
            "{binary}: callers {}",
            r.callers
        );
        assert!(r.edges.recall() >= 0.95, "{binary}: cfg edges {}", r.edges);
        assert!(
            r.blocks.recall() >= 0.95,
            "{binary}: cfg blocks {}",
            r.blocks
        );
        assert!(r.strings.recall() >= 0.9, "{binary}: strings {}", r.strings);
        assert_eq!(r.imports.recall(), 1.0, "{binary}: imports {}", r.imports);
        assert!(r.exports.recall() >= 0.8, "{binary}: exports {}", r.exports);
        assert_eq!(r.names.recall(), 1.0, "{binary}: names {}", r.names);
    }
}

/// PE images (mingw-w64, PE32+ and PE32, a DLL, a stripped PE32+ found through `.pdata`) and
/// 32-bit PIC ELF against Ghidra's fixtures (`corpus/pe`, `corpus/elf32`; the PE fixtures hold
/// the first 32 functions of each image). The PE sweep over all 14 full recordings is in the ADR.
#[tokio::test(flavor = "multi_thread")]
async fn agrees_with_ghidra_on_pe_and_elf32() {
    for (set, binary) in [
        ("corpus/pe", "win_tls-x64-O0.exe"),
        ("corpus/pe", "win_tls-x86-O0.exe"),
        ("corpus/pe", "win_dll-x64-O0.dll"),
        ("corpus/pe", "win_tls-x64-O2-stripped.exe"),
        ("corpus/elf32", "pie_list-i386-O0"),
        ("corpus/elf32", "switch_vm-i386-O0"),
    ] {
        let Some(c) = config() else { return };
        let r = compare_in(set, binary, c).await;
        print(binary, &r);
        assert_eq!(r.functions.recall(), 1.0, "{binary}: functions");
        assert!(r.bodies.recall() >= 0.95, "{binary}: bodies {}", r.bodies);
        assert!(
            r.blocks.recall() >= 0.95,
            "{binary}: cfg blocks {}",
            r.blocks
        );
        assert!(r.edges.recall() >= 0.95, "{binary}: cfg edges {}", r.edges);
        assert!(r.callers.recall() >= 0.9, "{binary}: callers {}", r.callers);
        // Ghidra's constant propagation follows a few more register values (PE header reads)
        assert!(
            r.xrefs_image.recall() >= 0.75,
            "{binary}: xrefs {}",
            r.xrefs_image
        );
        assert!(
            r.strings.recall() >= 0.95,
            "{binary}: strings {}",
            r.strings
        );
        assert!(
            r.imports.recall() >= 0.95,
            "{binary}: imports {}",
            r.imports
        );
        assert!(
            r.exports.recall() >= 0.75,
            "{binary}: exports {}",
            r.exports
        );
        assert!(r.names.recall() >= 0.85, "{binary}: names {}", r.names);
    }
}

/// ARM (A32 and Thumb-2), AArch64, RISC-V 64 and RISC-V 32 against Ghidra's fixtures. Ghidra
/// leaves RISC-V PLT entries unnamed (`FUN_ram_...`) where the native engine names them after
/// their imports, hence the lower bar for names there.
#[tokio::test(flavor = "multi_thread")]
async fn agrees_with_ghidra_on_arm_aarch64_and_riscv() {
    for (set, binary) in [
        ("corpus/arm32", "switch_vm-arm32-O0"),
        ("corpus/arm32", "switch_vm-arm32-thumb-O2"),
        ("corpus/aarch64", "switch_vm-aarch64-O0"),
        ("corpus/riscv64", "switch_vm-riscv64-O0"),
        ("corpus/riscv32", "switch_vm-riscv32-O0"),
    ] {
        let Some(c) = config() else { return };
        let langs = c.spec_root.join("Ghidra/Processors");
        if !langs.join("ARM/data/languages/ARM8_le.sla").is_file()
            || !langs.join("RISCV/data/languages/riscv.lp64d.sla").is_file()
        {
            eprintln!("skipped: the spec tree has no ARM or RISC-V specifications");
            return;
        }
        let r = compare_in(set, binary, c).await;
        print(binary, &r);
        assert_eq!(r.functions.recall(), 1.0, "{binary}: functions");
        assert!(r.bodies.recall() >= 0.9, "{binary}: bodies {}", r.bodies);
        assert!(
            r.xrefs_image.recall() >= 0.85,
            "{binary}: xrefs {}",
            r.xrefs_image
        );
        assert!(
            r.callers.recall() >= 0.95,
            "{binary}: callers {}",
            r.callers
        );
        assert!(r.edges.recall() >= 0.95, "{binary}: cfg edges {}", r.edges);
        assert!(
            r.blocks.recall() >= 0.95,
            "{binary}: cfg blocks {}",
            r.blocks
        );
        assert!(
            r.strings.recall() >= 0.95,
            "{binary}: strings {}",
            r.strings
        );
        assert_eq!(r.imports.recall(), 1.0, "{binary}: imports {}", r.imports);
        assert!(r.exports.recall() >= 0.8, "{binary}: exports {}", r.exports);
        assert!(r.names.recall() >= 0.7, "{binary}: names {}", r.names);
    }
}

/// C++ names (from DWARF, else demangled) and DWARF signatures against Ghidra with DWARF.
#[tokio::test(flavor = "multi_thread")]
async fn cpp_names_and_dwarf_signatures_agree_with_ghidra() {
    let binary = "cpp_shapes-O0";
    let Some(c) = config() else { return };
    let r = compare(binary, c).await;
    print(binary, &r);
    assert!(r.names.recall() >= 0.99, "names {}", r.names);
    assert_eq!(r.imports.recall(), 1.0, "imports {}", r.imports);
    assert!(r.exports.recall() >= 0.99, "exports {}", r.exports);
    assert!(r.signatures.recall() >= 0.65, "signatures {}", r.signatures);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "all 20 fixtures, including the slow static binaries"]
async fn agreement_over_the_corpus() {
    // KRAKEN_AGREEMENT_SET=corpus/pe (or corpus/elf32) sweeps another set
    let set = std::env::var("KRAKEN_AGREEMENT_SET").unwrap_or_else(|_| "corpus".into());
    let set = set.as_str();
    let mut names: Vec<String> = std::fs::read_dir(root().join(set).join("fixtures"))
        .expect("fixtures")
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".json").map(str::to_string))
        })
        .collect();
    names.sort();
    // KRAKEN_AGREEMENT_BINARIES=a,b narrows the sweep
    if let Ok(only) = std::env::var("KRAKEN_AGREEMENT_BINARIES") {
        let only: Vec<&str> = only.split(',').collect();
        names.retain(|n| only.contains(&n.as_str()));
    }
    let mut total = Report::default();
    for binary in names {
        let Some(c) = config() else { return };
        let r = compare_in(set, &binary, c).await;
        print(&binary, &r);
        macro_rules! sum {
            ($($f:ident),*) => {$(
                total.$f.common += r.$f.common;
                total.$f.theirs += r.$f.theirs;
                total.$f.ours += r.$f.ours;
            )*};
        }
        sum!(
            functions,
            bodies,
            xrefs,
            xrefs_untyped,
            xrefs_image,
            callers,
            cfg_same,
            blocks,
            edges,
            strings,
            imports,
            exports,
            names,
            signatures,
            signature_types
        );
    }
    print("all fixtures", &total);
}

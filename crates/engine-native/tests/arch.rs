//! The native engine on ARM (A32 and Thumb-2), AArch64, RISC-V 64 and RISC-V 32: the corpus sets
//! `corpus/arm32`, `corpus/aarch64`, `corpus/riscv64` and `corpus/riscv32` (see the corpus
//! README). Needs the native build and a spec tree with the ARM, AARCH64 and RISCV
//! specifications (`cargo xtask native-sla`); skips otherwise.
//!
//! `cargo test -p engine-native --test arch -- --ignored --nocapture` sweeps every binary of the
//! four sets (truth recall with names and sizes, and the time each open takes).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::testing::{ExpectedFunction, FixtureExpectations, run_contract_suite};
use kraken_engine::{
    CancellationToken, Decompiler, DisasmRequest, Disassembler, FunctionLister, Loader, LoaderSpec,
    MemoryReader, ProgramInfo,
};
use kraken_proto::{DisasmScope, FunctionSummary, Hex64, Locator, PageRequest};
use serde_json::Value;

const SETS: &[&str] = &["arm32", "aarch64", "riscv64", "riscv32"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn isolation() -> Isolation {
    if std::env::var_os("KRAKEN_NATIVE_TEST_IN_PROCESS").is_some_and(|v| v == "1") {
        Isolation::InProcess
    } else {
        Isolation::Worker(WorkerOptions::with_program(env!(
            "CARGO_BIN_EXE_kraken-native-worker"
        )))
    }
}

/// A config whose spec tree has the four processors, or `None` (skipped).
fn config(use_symbols: bool) -> Option<NativeConfig> {
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no Sleigh spec tree (cargo xtask native-sla)");
        return None;
    };
    if !NativeEngine::is_usable(&c) {
        eprintln!("skipped: engine-native-sys was built without the decompiler sources");
        return None;
    }
    let langs = c.spec_root.join("Ghidra/Processors");
    for (proc_dir, sla) in [
        ("ARM", "ARM8_le.sla"),
        ("AARCH64", "AARCH64.sla"),
        ("RISCV", "riscv.lp64d.sla"),
        ("RISCV", "riscv.ilp32d.sla"),
    ] {
        if !langs
            .join(proc_dir)
            .join("data/languages")
            .join(sla)
            .is_file()
        {
            eprintln!(
                "skipped: {} has no {sla} (cargo xtask native-sla compiles it)",
                c.spec_root.display()
            );
            return None;
        }
    }
    c.use_symbols = use_symbols;
    c.isolation = isolation();
    Some(c)
}

fn bin(set: &str, binary: &str) -> PathBuf {
    root().join("corpus").join(set).join("bin").join(binary)
}

async fn open(set: &str, binary: &str) -> Option<(NativeEngine, ProgramInfo)> {
    let c = config(true)?;
    let e = NativeEngine::new(c);
    let info = e
        .open_binary(
            &bin(set, binary),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap_or_else(|err| panic!("{set}/{binary}: open: {err}"));
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

fn offset(l: &Locator) -> u64 {
    match l {
        Locator::Native { offset, .. } => offset.0,
        _ => u64::MAX,
    }
}

fn hex(v: &Value) -> u64 {
    v.as_str()
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(u64::MAX)
}

/// A truth function: name, size and whether it is Thumb code.
struct Truth {
    name: String,
    size: u64,
    thumb: bool,
}

/// The ARM mapping symbols of the unstripped twin of `binary`, at link-time addresses: where
/// data in code (`$d`: literal pools, switch tables) starts (true) and where code starts
/// (false).
fn mapping(set: &str, binary: &str) -> Vec<(u64, bool)> {
    use object::{Object, ObjectSymbol};
    let twin = binary.trim_end_matches("-stripped");
    let data = std::fs::read(bin(set, twin)).expect("unstripped twin");
    let file = object::File::parse(&*data).expect("elf");
    let mut out: Vec<(u64, bool)> = file
        .symbols()
        .filter_map(|s| {
            let n = s.name().ok()?;
            let kind = n.strip_prefix('$')?.split('.').next()?;
            match kind {
                "d" => Some((s.address(), true)),
                "a" | "t" => Some((s.address(), false)),
                _ => None,
            }
        })
        .collect();
    out.sort_unstable();
    out
}

/// The bytes of code in `[start, start + size)` by the mapping symbols `map`.
fn code_bytes(map: &[(u64, bool)], start: u64, size: u64) -> u64 {
    let end = start + size;
    let mut data = map
        .iter()
        .take_while(|(a, _)| *a <= start)
        .last()
        .is_some_and(|(_, d)| *d);
    let mut at = start;
    let mut code = 0;
    for (a, d) in map.iter().filter(|(a, _)| start < *a && *a < end) {
        if !data {
            code += a - at;
        }
        at = *a;
        data = *d;
    }
    if !data {
        code += end - at;
    }
    code
}

/// The truth of a binary at load addresses: a position-independent image (ELF type `ET_DYN`)
/// is rebased to `base` like Ghidra does; fixed-address images keep their addresses. On ARM a
/// function's DWARF size covers its literal pools and switch tables; the size here counts the
/// code only, as the body (and Ghidra's) does.
fn truth(set: &str, binary: &str, base: u64) -> BTreeMap<u64, Truth> {
    let data = std::fs::read(bin(set, binary)).expect("binary");
    let pie = u16::from_le_bytes([data[16], data[17]]) == 3;
    let map = if set == "arm32" {
        mapping(set, binary)
    } else {
        Vec::new()
    };
    let text = std::fs::read_to_string(
        root()
            .join("corpus")
            .join(set)
            .join(format!("truth/{binary}.json")),
    )
    .expect("truth");
    let v: Value = serde_json::from_str(&text).expect("json");
    v["functions"]
        .as_array()
        .expect("functions")
        .iter()
        .map(|f| {
            let link = hex(&f["entry"]);
            let mut size = f["size"].as_u64().unwrap_or(0);
            if !map.is_empty() {
                size = code_bytes(&map, link, size);
            }
            let entry = link + if pie { base } else { 0 };
            (
                entry,
                Truth {
                    name: f["name"].as_str().unwrap_or_default().to_string(),
                    size,
                    thumb: f["thumb"].as_bool().unwrap_or(false),
                },
            )
        })
        .collect()
}

/// Whether a body of `size` bytes matches the truth's `want`. ARM code keeps an unreachable
/// padding instruction now and then (a `nop` after `add pc, pc, r3`, a halfword before a
/// literal pool) that DWARF counts and the body, like Ghidra's, does not.
fn sized(set: &str, size: Option<u64>, want: u64) -> bool {
    match size {
        Some(s) if set == "arm32" => s <= want && want - s <= 4,
        Some(s) => s == want,
        None => false,
    }
}

/// What a sweep of one binary found.
#[derive(Debug, Default)]
struct Recall {
    want: usize,
    found: usize,
    named: usize,
    sized: usize,
    listed: usize,
}

async fn recall(set: &str, binary: &str) -> Option<Recall> {
    let started = Instant::now();
    let (e, info) = open(set, binary).await?;
    let opened = started.elapsed();
    let found: BTreeMap<u64, FunctionSummary> = listing(&e)
        .await
        .into_iter()
        .map(|f| (offset(&f.locator), f))
        .collect();
    let want = truth(set, binary, info.base.0);
    let stripped = binary.ends_with("stripped");
    let mut r = Recall {
        want: want.len(),
        listed: found.len(),
        ..Recall::default()
    };
    for (entry, t) in &want {
        let Some(f) = found.get(entry) else {
            eprintln!("  {binary}: missed {} at {entry:#x}", t.name);
            continue;
        };
        r.found += 1;
        if stripped || f.name == t.name {
            r.named += 1;
        } else {
            eprintln!("  {binary}: {} at {entry:#x} named {}", t.name, f.name);
        }
        if sized(set, f.size, t.size) {
            r.sized += 1;
        } else {
            eprintln!(
                "  {binary}: {} at {entry:#x} has size {:?} (truth {})",
                t.name, f.size, t.size
            );
        }
    }
    eprintln!(
        "{set}/{binary} ({}): {}/{} found, {} named, {} sized, {} listed, opened in {:.2?}",
        info.arch, r.found, r.want, r.named, r.sized, r.listed, opened
    );
    Some(r)
}

/// Truth recall on two binaries of each set (one with symbols, one stripped): every function
/// is found with its name and size.
#[tokio::test(flavor = "multi_thread")]
async fn truth_functions_are_found_on_every_architecture() {
    for set in SETS {
        for binary in [
            format!("switch_vm-{set}-O0"),
            format!("stripped_calc-{set}-O2-stripped"),
        ] {
            let Some(r) = recall(set, &binary).await else {
                return;
            };
            assert_eq!(r.found, r.want, "{set}/{binary}: functions");
            assert_eq!(r.named, r.want, "{set}/{binary}: names");
            assert_eq!(r.sized, r.want, "{set}/{binary}: sizes");
        }
    }
    let Some(r) = recall("arm32", "switch_vm-arm32-thumb-O2-stripped").await else {
        return;
    };
    assert_eq!((r.found, r.sized), (r.want, r.want), "Thumb, stripped");
}

/// Every binary of the four sets: truth functions found, named and sized, and how long each open
/// takes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "sweep of all 68 cross-architecture binaries"]
async fn every_cross_binary() {
    let mut total = Recall::default();
    for set in SETS {
        let mut names: Vec<String> = std::fs::read_dir(root().join("corpus").join(set).join("bin"))
            .expect("bin dir")
            .filter_map(|e| e.ok()?.file_name().to_str().map(str::to_string))
            .collect();
        names.sort();
        if let Ok(only) = std::env::var("KRAKEN_ARCH_BINARIES") {
            names.retain(|n| only.split(',').any(|o| n.contains(o)));
        }
        for binary in names {
            let Some(r) = recall(set, &binary).await else {
                return;
            };
            total.want += r.want;
            total.found += r.found;
            total.named += r.named;
            total.sized += r.sized;
        }
    }
    eprintln!(
        "all: {}/{} found, {} named, {} sized",
        total.found, total.want, total.named, total.sized
    );
    assert_eq!(total.found, total.want, "every truth function is found");
}

/// Thumb functions decode as Thumb: 2-byte instructions appear, and the Thumb truth functions
/// of the Thumb-2 build are listed at their even entry with their sizes.
#[tokio::test(flavor = "multi_thread")]
async fn thumb_functions_decode_as_thumb() {
    for binary in [
        "switch_vm-arm32-thumb-O2",
        "switch_vm-arm32-thumb-O2-stripped",
    ] {
        let Some((e, info)) = open("arm32", binary).await else {
            return;
        };
        let want = truth("arm32", binary, info.base.0);
        let found: BTreeMap<u64, FunctionSummary> = listing(&e)
            .await
            .into_iter()
            .map(|f| (offset(&f.locator), f))
            .collect();
        for (entry, t) in &want {
            assert!(t.thumb, "{binary}: {} is Thumb in the truth", t.name);
            let f = found
                .get(entry)
                .unwrap_or_else(|| panic!("{binary}: {} at {entry:#x}", t.name));
            assert!(
                sized("arm32", f.size, t.size),
                "{binary}: {} size {:?}, truth {}",
                t.name,
                f.size,
                t.size
            );
            let rows = e
                .disassemble(
                    &DisasmRequest {
                        start: Hex64(*entry),
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
            let narrow = rows.items.iter().filter(|r| r.bytes.len() == 4).count();
            assert!(
                narrow > 0,
                "{binary}: {} has no 2-byte (Thumb) instruction",
                t.name
            );
        }
    }
}

/// A decompile per architecture names a C library call through its PLT entry and shows the
/// VM's switch.
#[tokio::test(flavor = "multi_thread")]
async fn decompiles_name_libc_calls_and_show_the_switch() {
    for (set, binary) in [
        ("arm32", "switch_vm-arm32-O0"),
        ("arm32", "switch_vm-arm32-thumb-O2"),
        ("aarch64", "switch_vm-aarch64-O0"),
        ("riscv64", "switch_vm-riscv64-O0"),
        ("riscv32", "switch_vm-riscv32-O0"),
    ] {
        let Some((e, _)) = open(set, binary).await else {
            return;
        };
        let fns = listing(&e).await;
        let main = decompiled(&e, &fns, binary, "main").await;
        assert!(
            main.contains("printf("),
            "{binary}: main names printf:\n{main}"
        );
        let vm = decompiled(&e, &fns, binary, "vm_run").await;
        assert!(
            vm.contains("switch"),
            "{binary}: vm_run shows its switch:\n{vm}"
        );
        let fail = decompiled(&e, &fns, binary, "vm_fail").await;
        assert!(
            fail.contains("fprintf(") && fail.contains("exit("),
            "{binary}: vm_fail names fprintf and exit:\n{fail}"
        );
    }
}

/// Variables of the ELF symbol table print by name (`kr_brk`, `kr_heap`), not as `DAT_` or
/// `uRam` addresses.
#[tokio::test(flavor = "multi_thread")]
async fn elf_globals_decompile_by_name() {
    let binary = "static_strops-riscv32-O0";
    let Some((e, _)) = open("riscv32", binary).await else {
        return;
    };
    let fns = listing(&e).await;
    let sbrk = decompiled(&e, &fns, binary, "sbrk").await;
    eprintln!("{sbrk}");
    assert!(sbrk.contains("kr_brk"), "{sbrk}");
    assert!(sbrk.contains("kr_heap"), "{sbrk}");
}

/// The engine contract suite on one binary of each set.
#[tokio::test(flavor = "multi_thread")]
async fn contract_suite_per_architecture() {
    for set in SETS {
        let binary = format!("pie_list-{set}-O0");
        let Some((e, info)) = open(set, &binary).await else {
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
        // a scratch address outside every function: the start of `.rodata`
        let rodata = e
            .memory_map(&CancellationToken::new())
            .await
            .expect("memory map")
            .into_iter()
            .find(|b| b.name == ".rodata")
            .expect(".rodata");
        let scratch = Locator::ram(rodata.start.0);
        let exp = FixtureExpectations {
            binary_path: bin(set, &binary),
            program: info,
            functions,
            rename_to: "kraken_renamed".into(),
            scratch,
        };
        let fresh = NativeEngine::new(config(true).expect("config"));
        run_contract_suite(&fresh, &exp)
            .await
            .unwrap_or_else(|err| panic!("{set}/{binary}: {err}"));
    }
}

/// The decompiled C of the listed function `name`, with valid token spans.
async fn decompiled(e: &NativeEngine, fns: &[FunctionSummary], binary: &str, name: &str) -> String {
    let f = fns
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{binary}: {name} listed"));
    let d = e
        .decompile(&f.locator, &CancellationToken::new())
        .await
        .unwrap_or_else(|err| panic!("{binary}: decompile {name}: {err}"));
    d.validate_tokens().expect("spans");
    d.text
}

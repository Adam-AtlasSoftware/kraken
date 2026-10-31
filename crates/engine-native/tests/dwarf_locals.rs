//! DWARF local variables and function statics reach the decompiled C: names and types of the
//! locals of `main` and `list_sort`, `main::orders`, and the 32-bit layout of `node`. Needs the
//! native build and a spec tree; skips otherwise.

use std::path::{Path, PathBuf};

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec, TypeStore};
use kraken_proto::{PageRequest, TypeDef};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

async fn open(set: &str, binary: &str) -> Option<NativeEngine> {
    let mut c = NativeConfig::discover()?;
    if !NativeEngine::is_usable(&c) {
        return None;
    }
    c.isolation = if std::env::var_os("KRAKEN_NATIVE_TEST_IN_PROCESS").is_some_and(|v| v == "1") {
        Isolation::InProcess
    } else {
        Isolation::Worker(WorkerOptions::with_program(env!(
            "CARGO_BIN_EXE_kraken-native-worker"
        )))
    };
    let e = NativeEngine::new(c);
    e.open_binary(
        &root().join(set).join("bin").join(binary),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open_binary");
    Some(e)
}

async fn decompile_full(e: &NativeEngine, name: &str) -> kraken_proto::DecompileResult {
    let c = CancellationToken::new();
    let page = e
        .list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &c,
        )
        .await
        .expect("list");
    let f = page
        .items
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no function {name}"));
    e.decompile(&f.locator, &c).await.expect("decompile")
}

async fn decompile(e: &NativeEngine, name: &str) -> String {
    decompile_full(e, name).await.text
}

#[tokio::test(flavor = "multi_thread")]
async fn main_gets_its_locals_and_the_static_table() {
    let Some(e) = open("corpus", "pie_list-O0").await else {
        eprintln!("skipped: no native build or spec tree");
        return;
    };
    let text = decompile(&e, "main").await;
    for want in [
        "double total;",
        "list l;",
        "uint i;",
        "main::orders[i].label",
    ] {
        assert!(text.contains(want), "{want:?} missing from\n{text}");
    }
    assert!(!text.contains("local_"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn i386_list_sort_names_its_block_locals() {
    let Some(e) = open("corpus/elf32", "pie_list-i386-O0").await else {
        eprintln!("skipped: no native build or spec tree");
        return;
    };
    let text = decompile(&e, "list_sort").await;
    for want in ["node **pp;", "node *a;", "node *b;", "swapped;"] {
        assert!(text.contains(want), "{want:?} missing from\n{text}");
    }
    // the realigned `main` keeps its locals in ebp-relative slots
    let main = decompile(&e, "main").await;
    for want in ["list l;", "double total;", "uint i;"] {
        assert!(main.contains(want), "{want:?} missing from\n{main}");
    }
    let TypeDef::Struct(node) = e
        .get_type("node", &CancellationToken::new())
        .await
        .expect("type node")
    else {
        panic!("node is a struct");
    };
    assert!(
        node.fields.iter().all(|f| !f.name.starts_with("_pad")),
        "{node:?}"
    );
    let next = node.fields.iter().find(|f| f.name == "next").expect("next");
    assert_eq!(next.offset, node.size - 4, "{node:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn pe_function_known_by_a_second_symbol_gets_its_prototype() {
    let Some(e) = open("corpus/pe", "win_tls-x64-O0.exe").await else {
        eprintln!("skipped: no native build or spec tree");
        return;
    };
    // the primary name is the section symbol `.text`; `_matherr` is the other symbol there
    let text = e
        .decompile(
            &kraken_proto::Locator::ram(0x140001bf0),
            &CancellationToken::new(),
        )
        .await
        .expect("decompile")
        .text;
    assert!(
        text.contains("int .text(_exception *_Except)"),
        "{}",
        &text[..text.len().min(300)]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parameter_named_like_its_struct_still_gets_the_prototype() {
    let Some(e) = open("corpus", "switch_vm-O0").await else {
        eprintln!("skipped: no native build or spec tree");
        return;
    };
    // `static void push(struct vm *vm, int32_t v)`
    let text = decompile(&e, "push").await;
    assert!(text.contains("vm *vm") && text.contains("vm->sp"), "{text}");
}

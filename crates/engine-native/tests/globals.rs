//! Global variables in decompiled C: named by the ELF symbol table, and named and typed by
//! DWARF. The test programs are built with the host `cc`; the tests skip without it, the native
//! build or the Sleigh specs.

use std::path::Path;
use std::process::Command;

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{CancellationToken, Decompiler, FunctionLister, Loader, LoaderSpec};
use kraken_proto::PageRequest;

const SOURCE: &str = r#"
struct point { int x; int y; };
int counter;
struct point origin = { 3, 4 };
const char *names[3] = { "a", "b", "c" };
int bump(int d) { counter += d; return counter + origin.y; }
const char *pick(int i) { return names[i % 3]; }
int main(void) { return bump(1) + (int)(pick(2)[0]); }
"#;

fn build(dir: &Path, name: &str, flags: &[&str]) -> Option<std::path::PathBuf> {
    let src = dir.join("g.c");
    std::fs::write(&src, SOURCE).ok()?;
    let out = dir.join(name);
    let ok = Command::new("cc")
        .args(["-O0", "-no-pie", "-fno-pic", "-fcf-protection=none"])
        .args(flags)
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .status()
        .ok()?
        .success();
    ok.then_some(out)
}

async fn decompile_all(path: &Path) -> Option<String> {
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
    let token = CancellationToken::new();
    e.open_binary(path, &LoaderSpec::default(), &token)
        .await
        .expect("open");
    let page = e
        .list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &token,
        )
        .await
        .expect("list");
    let mut out = String::new();
    for f in page.items {
        if ["bump", "pick"].contains(&f.name.as_str()) {
            let d = e.decompile(&f.locator, &token).await.expect("decompile");
            out.push_str(&d.text);
        }
    }
    Some(out)
}

#[tokio::test(flavor = "multi_thread")]
async fn symbol_table_names_globals() {
    let dir = tempfile::tempdir().expect("tmp");
    let Some(bin) = build(dir.path(), "plain", &[]) else {
        eprintln!("skipped: no cc");
        return;
    };
    let Some(text) = decompile_all(&bin).await else {
        eprintln!("skipped: no native engine");
        return;
    };
    eprintln!("{text}");
    assert!(text.contains("counter"), "{text}");
    assert!(text.contains("names"), "{text}");
    // a field inside a named variable is labelled like any data, never an anonymous `Ram0`
    assert!(!text.contains("Ram0"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn dwarf_types_globals() {
    let dir = tempfile::tempdir().expect("tmp");
    let Some(bin) = build(dir.path(), "debug", &["-g"]) else {
        eprintln!("skipped: no cc");
        return;
    };
    let Some(text) = decompile_all(&bin).await else {
        eprintln!("skipped: no native engine");
        return;
    };
    eprintln!("{text}");
    // `origin` is a typed struct, so its field is printed as one
    assert!(text.contains("origin.y"), "{text}");
    assert!(text.contains("counter"), "{text}");
    assert!(text.contains("names"), "{text}");
}

/// Decompiles the function at `entry` of a corpus program with the native engine in its worker.
async fn corpus_function(binary: &str, entry: u64) -> Option<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/bin")
        .join(binary);
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
    let token = CancellationToken::new();
    e.open_binary(&path, &LoaderSpec::default(), &token)
        .await
        .expect("open");
    let d = e
        .decompile(&kraken_proto::Locator::ram(entry), &token)
        .await
        .expect("decompile");
    Some(d.text)
}

/// Data the code refers to gets Ghidra's automatic labels, and stack variables are `local_<hex>`.
#[tokio::test(flavor = "multi_thread")]
async fn automatic_labels_and_locals_as_ghidra() {
    let name = "stripped_calc-O0-stripped";
    let Some(fini) = corpus_function(name, 0x101100).await else {
        eprintln!("skipped: no native engine");
        return;
    };
    eprintln!("{fini}");
    assert!(fini.contains("DAT_00104020"), "{fini}");
    assert!(fini.contains("PTR_LOOP_00104018"), "{fini}");
    let main = corpus_function(name, 0x1014c1).await.expect("engine");
    eprintln!("{main}");
    assert!(main.contains("local_18"), "{main}");
    assert!(!main.contains("Stack_"), "{main}");
    assert!(
        main.contains("(&PTR_s_1_+_2_*_3_00103da0)[local_10]"),
        "{main}"
    );
}

/// A user's name for an automatically labelled address wins, and removing it brings the label
/// back.
#[tokio::test(flavor = "multi_thread")]
async fn user_names_win_over_automatic_labels() {
    use kraken_engine::Mutator;
    use kraken_proto::{Anchor, Hex64, LogOp, VersionedLogOp};

    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/stripped_calc-O0-stripped");
    let Some(mut c) = NativeConfig::discover() else {
        eprintln!("skipped: no native engine");
        return;
    };
    if !NativeEngine::is_usable(&c) {
        return;
    }
    c.isolation = Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )));
    let e = NativeEngine::new(c);
    let token = CancellationToken::new();
    e.open_binary(&path, &LoaderSpec::default(), &token)
        .await
        .expect("open");
    assert!(fini_text(&e).await.contains("DAT_00104020"));
    let rename = |old: Option<&str>, new: &str| {
        VersionedLogOp::new(LogOp::Rename {
            anchor: Anchor::Native {
                space: "ram".into(),
                offset: Hex64(0x104020),
                fn_entry: Hex64(0x104020),
                fn_hash: String::new(),
            },
            old_name: old.map(str::to_string),
            new_name: new.to_string(),
        })
    };
    e.apply(&rename(None, "done_flag"), &token)
        .await
        .expect("rename");
    let named = fini_text(&e).await;
    assert!(
        named.contains("done_flag") && !named.contains("DAT_00104020"),
        "{named}"
    );
    e.apply(&rename(Some("done_flag"), ""), &token)
        .await
        .expect("clear");
    assert!(fini_text(&e).await.contains("DAT_00104020"));
}

async fn fini_text(e: &NativeEngine) -> String {
    e.decompile(
        &kraken_proto::Locator::ram(0x101100),
        &CancellationToken::new(),
    )
    .await
    .expect("decompile")
    .text
}

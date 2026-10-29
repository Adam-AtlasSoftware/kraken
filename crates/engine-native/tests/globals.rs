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
    assert!(!text.contains("DAT_") && !text.contains("Ram0"), "{text}");
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

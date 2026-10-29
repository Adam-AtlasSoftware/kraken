//! A stripped program gets its names from a separate debug file found through `.gnu_debuglink`
//! (next to the program) or its build-id (`.build-id/..` next to it), also in the confined
//! worker, and keeps placeholder names when the file is not there or is not its own.
//! Needs the native build, a spec tree and `objcopy`/`strip`; skips otherwise.

use std::path::{Path, PathBuf};
use std::process::Command;

use engine_native::{Isolation, NativeConfig, NativeEngine, WorkerOptions};
use kraken_engine::{CancellationToken, FunctionLister, Loader, LoaderSpec};
use kraken_proto::PageRequest;

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn o(s: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(s)
}

fn run(program: &str, args: &[&std::ffi::OsStr]) -> bool {
    Command::new(program)
        .args(args)
        .status()
        .is_ok_and(|s| s.success())
}

async fn names(path: &Path) -> Option<Vec<String>> {
    let mut c = NativeConfig::discover()?;
    if !NativeEngine::is_usable(&c) {
        return None;
    }
    c.isolation = Isolation::Worker(WorkerOptions::with_program(env!(
        "CARGO_BIN_EXE_kraken-native-worker"
    )));
    let e = NativeEngine::new(c);
    let cancel = CancellationToken::new();
    e.open_binary(path, &LoaderSpec::default(), &cancel)
        .await
        .expect("open_binary");
    let page = e
        .list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(500),
            },
            &cancel,
        )
        .await
        .expect("list");
    Some(page.items.into_iter().map(|f| f.name).collect())
}

#[tokio::test(flavor = "multi_thread")]
async fn names_come_from_the_debuglink_and_build_id_files() {
    let dir = tempfile::tempdir().unwrap();
    // the corpus programs carry no build-id: give a copy one (a GNU note of 8 bytes)
    let mut note = Vec::new();
    for w in [4u32, 8, 3] {
        note.extend_from_slice(&w.to_le_bytes());
    }
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    let note_file = dir.path().join("note.bin");
    std::fs::write(&note_file, &note).unwrap();
    let src = dir.path().join("with_id");
    let section = format!("--add-section=.note.gnu.build-id={}", note_file.display());
    if !run(
        "objcopy",
        &[
            o(&section),
            o("--set-section-flags=.note.gnu.build-id=alloc,readonly,data"),
            corpus("bin/pie_list-O0").as_os_str(),
            src.as_os_str(),
        ],
    ) {
        eprintln!("skipped: objcopy is missing");
        return;
    }
    let (stripped, debug) = (dir.path().join("prog"), dir.path().join("prog.debug"));
    if !run(
        "objcopy",
        &[o("--only-keep-debug"), src.as_os_str(), debug.as_os_str()],
    ) || !run("strip", &[o("-o"), stripped.as_os_str(), src.as_os_str()])
        || !run(
            "objcopy",
            &[
                o("--add-gnu-debuglink"),
                debug.as_os_str(),
                stripped.as_os_str(),
            ],
        )
    {
        eprintln!("skipped: objcopy or strip is missing");
        return;
    }
    // the debug file is next to the program: its names are used
    let Some(with) = names(&stripped).await else {
        eprintln!("skipped: no native engine here");
        return;
    };
    for want in ["list_push", "list_sort", "main"] {
        assert!(with.iter().any(|n| n == want), "{want} in {with:?}");
    }

    // moved away: placeholder names again
    let hidden = dir.path().join("hidden.debug");
    std::fs::rename(&debug, &hidden).unwrap();
    let without = names(&stripped).await.unwrap();
    assert!(!without.iter().any(|n| n == "list_push"), "{without:?}");

    // a file of the right name that is not this program's debug file is refused (CRC)
    std::fs::copy(corpus("bin/switch_vm-O0"), &debug).unwrap();
    let wrong = names(&stripped).await.unwrap();
    assert!(!wrong.iter().any(|n| n == "list_push"), "{wrong:?}");
    std::fs::remove_file(&debug).unwrap();

    // by build-id, under .build-id/xx/yyyy.debug next to the program
    let data = std::fs::read(&stripped).unwrap();
    let w = engine_native::debugfile::wanted(&data).expect("the program names a debug file");
    if let Some(id) = w.build_id {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let target = dir
            .path()
            .join(format!(".build-id/{}/{}.debug", &hex[..2], &hex[2..]));
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::rename(&hidden, &target).unwrap();
        let by_id = names(&stripped).await.unwrap();
        assert!(by_id.iter().any(|n| n == "list_push"), "{by_id:?}");
    } else {
        eprintln!("the toolchain wrote no build-id; the build-id case is skipped");
    }
}

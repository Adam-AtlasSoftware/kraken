//! DWARF in compressed sections (`objcopy --compress-debug-sections`) gives the same functions
//! as the plain file, for both zlib and zstd.

use std::path::{Path, PathBuf};
use std::process::Command;

fn corpus(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus")
        .join(rel)
}

fn functions(path: &Path) -> Vec<(u64, String)> {
    let data = std::fs::read(path).unwrap();
    let file = object::File::parse(&*data).unwrap();
    engine_native::dwarf::parse(&file)
        .functions
        .iter()
        .map(|(a, f)| (*a, f.name.clone()))
        .collect()
}

#[test]
fn compressed_sections_read_like_plain_ones() {
    let src = corpus("bin/pie_list-O0");
    let plain = functions(&src);
    assert!(!plain.is_empty(), "the corpus binary has DWARF functions");
    let dir = tempfile::tempdir().unwrap();
    let mut checked = 0;
    for fmt in ["zlib", "zstd"] {
        let out = dir.path().join(format!("pie_{fmt}"));
        let ok = Command::new("objcopy")
            .arg(format!("--compress-debug-sections={fmt}"))
            .arg(&src)
            .arg(&out)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("objcopy cannot write {fmt} sections here; skipped");
            continue;
        }
        assert_eq!(functions(&out), plain, "{fmt}");
        checked += 1;
    }
    eprintln!("{checked} compressed variants checked");
}

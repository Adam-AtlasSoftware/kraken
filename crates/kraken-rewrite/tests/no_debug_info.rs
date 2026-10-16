//! Guards the reasoning behind the `RUSTSEC-2026-0344` ignore in `deny.toml`.
//!
//! The advisory is about `ruzstd`, which the dependency graph reaches through
//! `icicle-cpu -> addr2line -> object` (zstd-compressed DWARF sections). icicle has no feature to
//! drop that dependency, and `Cargo.toml` of the workspace may not patch it, so the ignore stays.
//! It is sound only while no KRAKEN code calls the one icicle entry point that parses debug
//! information of a program image: `icicle_cpu::debug_info::DebugInfo::add_file`, reached through
//! the PE loader (`icicle_cpu::pe`) and the Linux layer (`icicle-linux`). The oracle maps
//! `PT_LOAD` segments itself and reads symbols with `object`'s ELF reader, never DWARF. This test
//! fails if source under `src/` starts naming any of those, so the ignore cannot go stale quietly.

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "debug_info",
    "DebugInfo",
    "add_file",
    "icicle_linux",
    "icicle-linux",
    "icicle_cpu::pe",
    "addr2line",
    "ruzstd",
    "gimli",
];

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).expect("read_dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn kraken_code_never_loads_debug_information_of_a_program_image() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 10, "found {} source files", files.len());
    let mut hits = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).expect("read");
        for (n, line) in text.lines().enumerate() {
            // Comments may explain the reasoning; code may not name the entry points.
            let code = line.split("//").next().unwrap_or("");
            for pat in FORBIDDEN {
                if code.contains(pat) {
                    hits.push(format!("{}:{}: `{pat}`", f.display(), n + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "these would make the ruzstd advisory ignore in deny.toml unsound; see this test's \
         header:\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_crate_depends_on_icicle_only_through_the_three_crates_the_oracle_needs() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("manifest");
    let icicle: Vec<&str> = manifest
        .lines()
        .filter(|l| l.contains("icicle-emu/icicle-emu"))
        .filter_map(|l| l.split('=').next())
        .map(str::trim)
        .collect();
    assert_eq!(icicle, ["icicle-cpu", "icicle-vm", "pcode"]);
}

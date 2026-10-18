//! Guards the reasoning behind the `RUSTSEC-2026-0344` ignore in `deny.toml` for this crate.
//!
//! The advisory is about `ruzstd`, which the dependency graph reaches through
//! `icicle-cpu -> addr2line -> object`. The ignore is sound only while no KRAKEN code calls the
//! icicle entry points that parse a program image's debug information:
//! `icicle_cpu::debug_info::DebugInfo::add_file`, reached through icicle's PE and ELF loaders
//! and its Linux layer. kraken-emu loads images and answers system calls itself (`loader`,
//! `linux`), so it never names them; this test fails if that changes.

use std::path::Path;

const FORBIDDEN: &[&str] = &[
    "debug_info",
    "DebugInfo",
    "add_file",
    "icicle_linux",
    "icicle-linux",
    "icicle_cpu::pe",
    "icicle_cpu::elf",
    "ElfLoader",
    "PeLoader",
    "addr2line",
    "ruzstd",
    "gimli",
    "build_auto",
    "build_linux_env",
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
fn kraken_emu_never_loads_debug_information_of_a_program_image() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty());
    for f in files {
        let text = std::fs::read_to_string(&f).expect("read");
        for word in FORBIDDEN {
            assert!(
                !text.contains(word),
                "{} names `{word}`: see deny.toml RUSTSEC-2026-0344",
                f.display()
            );
        }
    }
}

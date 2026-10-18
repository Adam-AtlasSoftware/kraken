//! Shared helpers for the corpus tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use kraken_emu::{Arch, SpecRoots};

pub fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus")
}

pub fn bin(set: &str, name: &str) -> PathBuf {
    corpus().join(set).join("bin").join(name)
}

/// The architecture of a corpus set.
pub fn set_arch(set: &str) -> Arch {
    match set {
        "arm32" => Arch::Arm,
        "aarch64" => Arch::Aarch64,
        "riscv64" => Arch::Riscv64,
        "riscv32" => Arch::Riscv32,
        "elf32" => Arch::X86,
        _ => Arch::X86_64,
    }
}

/// Spec roots, failing loudly when an architecture has none (these tests are `#[ignore]`d and
/// run where Ghidra's processor sources are installed).
pub fn specs(arch: Arch) -> SpecRoots {
    let s = SpecRoots::discover();
    if let Err(e) = s.processors_for(arch) {
        panic!("{e}");
    }
    s
}

/// The sysroot extracted by `cargo xtask emu-sysroots` for a set, if present.
pub fn sysroot(set: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_SYSROOTS").filter(|v| !v.is_empty()) {
        let d = PathBuf::from(p).join(set);
        return d.is_dir().then_some(d);
    }
    let home = std::env::var_os("HOME")?;
    let d = Path::new(&home)
        .join(".cache/kraken-dev/emu-sysroots")
        .join(set);
    d.join("lib").is_dir().then_some(d)
}

/// The baseline stdout of a program from `corpus/expected/<program>.json` (the x86-64 build).
pub fn expected_stdout(program: &str) -> String {
    let p = corpus().join("expected").join(format!("{program}.json"));
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&p).expect("expected json")).expect("json");
    v["cases"][0]["stdout"]
        .as_str()
        .expect("baseline stdout")
        .to_string()
}

/// The output a corpus binary must print: the x86-64 baseline, except `static_strops` on the
/// ILP32 sets, whose `unsigned long` hash is 32 bits wide (see `<set>/QEMU-CHECK.txt`).
pub fn want_stdout(set: &str, program: &str) -> String {
    let s = expected_stdout(program);
    if program == "static_strops" && matches!(set, "arm32" | "riscv32" | "elf32") {
        s.replace("hash=6490", "hash=36474")
    } else {
        s
    }
}

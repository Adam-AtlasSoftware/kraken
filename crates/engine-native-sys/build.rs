//! Builds the Ghidra decompiler core and Sleigh (C++17) plus the KRAKEN shim.
//!
//! Source lookup: `KRAKEN_GHIDRA_SRC` (a directory holding `cpp/` and `zlib/`, i.e. Ghidra's
//! `Ghidra/Features/Decompiler/src/decompile`), else the copy `cargo xtask native-src` puts in
//! `~/.cache/kraken-dev/ghidra-src/Ghidra_12.2_build/decompile`. When neither exists the crate
//! builds a stub whose `available()` is false, unless the `require-native` feature is on, which
//! turns that into a build error. `KRAKEN_NATIVE_STUB=1` forces the stub. Only Linux builds the
//! native library for now (decision 95).

use std::env;
use std::path::{Path, PathBuf};

const TAG: &str = "Ghidra_12.2_build";

/// Ghidra sources of the decompiler library: the Makefile's CORE, DECCORE and SLEIGH sets plus
/// the Sleigh architecture glue. Console, Ghidra-protocol, BFD and sleigh-compiler files are left
/// out, so the archive has no external dependencies besides the bundled zlib.
const SOURCES: &[&str] = &[
    // CORE
    "xml",
    "marshal",
    "space",
    "float",
    "address",
    "pcoderaw",
    "translate",
    "opcodes",
    "globalcontext",
    // DECCORE
    "capability",
    "architecture",
    "options",
    "graph",
    "cover",
    "block",
    "cast",
    "typeop",
    "database",
    "cpool",
    "comment",
    "stringmanage",
    "modelrules",
    "fspec",
    "action",
    "loadimage",
    "grammar",
    "varnode",
    "op",
    "type",
    "variable",
    "varmap",
    "jumptable",
    "emulate",
    "emulateutil",
    "flow",
    "userop",
    "expression",
    "multiprecision",
    "funcdata",
    "funcdata_block",
    "funcdata_op",
    "funcdata_varnode",
    "unionresolve",
    "pcodeinject",
    "heritage",
    "prefersplit",
    "rangeutil",
    "ruleaction",
    "subflow",
    "blockaction",
    "merge",
    "double",
    "transform",
    "constseq",
    "bitfield",
    "coreaction",
    "condexe",
    "override",
    "dynamic",
    "crc32",
    "prettyprint",
    "printlanguage",
    "printc",
    "printjava",
    "memstate",
    "opbehavior",
    "paramid",
    "signature",
    // SLEIGH
    "sleigh",
    "pcodeparse",
    "pcodecompile",
    "sleighbase",
    "slghsymbol",
    "slghpatexpress",
    "slghpattern",
    "semantics",
    "context",
    "slaformat",
    "compression",
    "filemanage",
    // Sleigh-backed architecture
    "sleigh_arch",
    "inject_sleigh",
];

const ZLIB: &[&str] = &[
    "adler32", "deflate", "inffast", "inflate", "inftrees", "trees", "zutil",
];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(kraken_native)");
    println!("cargo::rerun-if-env-changed=KRAKEN_GHIDRA_SRC");
    println!("cargo::rerun-if-env-changed=KRAKEN_NATIVE_STUB");
    println!("cargo::rerun-if-env-changed=HOME");
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=shim/kraken_shim.hh");
    println!("cargo::rerun-if-changed=shim/kraken_shim.cc");
    println!("cargo::rerun-if-changed=src/lib.rs");

    let required = env::var_os("CARGO_FEATURE_REQUIRE_NATIVE").is_some();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os != "linux" {
        if required {
            panic!("engine-native-sys: the native decompiler only builds on Linux for now");
        }
        println!(
            "cargo::warning=engine-native-sys: native decompiler not built on {os} (Linux only)"
        );
        return;
    }

    if env::var_os("KRAKEN_NATIVE_STUB").is_some_and(|v| v == "1") {
        if required {
            panic!("engine-native-sys: KRAKEN_NATIVE_STUB=1 conflicts with feature require-native");
        }
        println!("cargo::warning=engine-native-sys: KRAKEN_NATIVE_STUB=1, building the stub");
        return;
    }
    let Some(src) = locate_sources() else {
        let msg = format!(
            "engine-native-sys: Ghidra decompiler sources not found. Run `cargo xtask native-src` \
             (fetches {TAG} into ~/.cache/kraken-dev/ghidra-src) or set KRAKEN_GHIDRA_SRC to a \
             directory holding Ghidra's decompile/cpp and decompile/zlib. Building the stub."
        );
        if required {
            panic!("{msg}");
        }
        println!("cargo::warning={msg}");
        return;
    };
    let cpp = src.join("cpp");
    let zlib = src.join("zlib");
    println!("cargo::rerun-if-changed={}", cpp.display());
    println!("cargo::rerun-if-changed={}", zlib.display());

    let mut z = cc::Build::new();
    z.warnings(false)
        .extra_warnings(false)
        .flag_if_supported("-w");
    z.define("NO_GZIP", None).opt_level(2);
    for f in ZLIB {
        z.file(zlib.join(format!("{f}.c")));
    }
    z.compile("kraken_ghidra_zlib");

    let mut d = cc::Build::new();
    d.cpp(true)
        .std("c++17")
        .warnings(false)
        .extra_warnings(false)
        .flag_if_supported("-w")
        .opt_level(2)
        .define("LOCAL_ZLIB", None)
        .define("LINUX", None)
        .define("_LINUX", None)
        .include(&cpp)
        // the decompiler registers capabilities through static constructors: keep every object
        .link_lib_modifier("+whole-archive");
    for f in SOURCES {
        let p = cpp.join(format!("{f}.cc"));
        if !p.is_file() {
            panic!(
                "engine-native-sys: {} is missing; {} does not look like {TAG} sources",
                p.display(),
                src.display()
            );
        }
        d.file(p);
    }
    d.compile("kraken_ghidra_decomp");

    let mut bridge = cxx_build::bridge("src/lib.rs");
    bridge
        .file("shim/kraken_shim.cc")
        .std("c++17")
        // Ghidra's headers as system headers: their warnings are not ours to fix
        .flag("-isystem")
        .flag(cpp.to_string_lossy().as_ref())
        .define("LOCAL_ZLIB", None)
        .define("LINUX", None)
        .define("_LINUX", None)
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-sign-compare")
        // false positives in cxx's generated Vec constructors with GCC 16
        .flag_if_supported("-Wno-maybe-uninitialized")
        .opt_level(2);
    bridge.compile("kraken_native_shim");

    println!("cargo::rustc-cfg=kraken_native");
    println!("cargo::metadata=src={}", src.display());
}

fn locate_sources() -> Option<PathBuf> {
    if let Some(v) = env::var_os("KRAKEN_GHIDRA_SRC") {
        let p = PathBuf::from(v);
        if is_source_dir(&p) {
            return Some(p);
        }
        panic!(
            "engine-native-sys: KRAKEN_GHIDRA_SRC={} has no cpp/sleigh.cc and zlib/inflate.c",
            p.display()
        );
    }
    let home = env::var_os("HOME")?;
    let p = Path::new(&home)
        .join(".cache/kraken-dev/ghidra-src")
        .join(TAG)
        .join("decompile");
    is_source_dir(&p).then_some(p)
}

fn is_source_dir(p: &Path) -> bool {
    p.join("cpp/sleigh.cc").is_file() && p.join("zlib/inflate.c").is_file()
}

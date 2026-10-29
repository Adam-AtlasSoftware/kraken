//! `cargo xtask native-sla`: builds Ghidra's Sleigh compiler from the pinned source archive and
//! compiles the processor specifications the native engine supports, so it needs no Ghidra
//! install at run time.
//!
//! The result is a tree laid out like an install, which the library's language scan reads:
//! `~/.cache/kraken-dev/native-sla/Ghidra_12.2_build/Ghidra/Processors/<proc>/data/languages`
//! with the `.ldefs`, `.pspec`, `.cspec` files from the archive and the `.sla` files compiled
//! here. The compiler itself is the Makefile's `sleigh_opt` set (CORE, SLEIGH and SLACOMP)
//! plus the bundled zlib, built with the system C++ compiler (`CXX`, default `c++`; `CC` for
//! zlib, default `cc`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::native_src::{PREFIX, SHA256, TAG, URL, extract, fetch_archive, source_root};
use crate::{Result, cache_dir};

/// Processors compiled: x86 (`x86-64.sla` for x86-64, `x86.sla` for 32-bit ELF and PE32) first,
/// AArch64 second (decision 95), then ARM (A32 and Thumb-2, `ARM8_le.sla`) and RISC-V
/// (`riscv.lp64d.sla`, `riscv.ilp32d.sla`).
const PROCESSORS: &[&str] = &["x86", "AARCH64", "ARM", "RISCV"];

/// The Makefile's SLEIGH_NAMES: CORE, SLEIGH and SLACOMP.
const COMPILER_SOURCES: &[&str] = &[
    "xml",
    "marshal",
    "space",
    "float",
    "address",
    "pcoderaw",
    "translate",
    "opcodes",
    "globalcontext",
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
    "slgh_compile",
    "slghparse",
    "slghscan",
];

const ZLIB: &[&str] = &[
    "adler32", "deflate", "inffast", "inflate", "inftrees", "trees", "zutil",
];

/// Where the compiled tree goes.
pub fn sla_root() -> Result<PathBuf> {
    Ok(cache_dir().ok_or("HOME is not set")?.join("native-sla"))
}

pub fn native_sla() -> Result<()> {
    let archive = fetch_archive()?;
    let src = source_root()?.join("decompile");
    if !src.join("cpp/slgh_compile.cc").is_file() {
        crate::native_src::native_src()?;
    }
    let root = sla_root()?;
    let sleigh = build_compiler(&src, &root.join("build"))?;

    let dest = root.join(TAG);
    let staging = root.join(format!("{TAG}.staging"));
    let _ = fs::remove_dir_all(&staging);
    fs::create_dir_all(&staging)
        .map_err(|e| format!("cannot create {}: {e}", staging.display()))?;
    for proc_name in PROCESSORS {
        extract(
            &archive,
            &staging,
            &format!("{PREFIX}/Ghidra/Processors/{proc_name}/data/languages"),
            1,
        )?;
    }
    extract(&archive, &staging, &format!("{PREFIX}/LICENSE"), 1)?;

    let mut specs = Vec::new();
    for proc_name in PROCESSORS {
        let dir = staging.join(format!("Ghidra/Processors/{proc_name}/data/languages"));
        let mut found: Vec<PathBuf> = fs::read_dir(&dir)
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "slaspec"))
            .collect();
        found.sort();
        specs.extend(found);
    }
    if specs.is_empty() {
        return Err("the archive held no .slaspec files".into());
    }
    compile_all(&sleigh, &specs)?;
    fs::write(
        staging.join("SOURCE.txt"),
        format!(
            "Compiled by `cargo xtask native-sla` from\n{URL}\nsha256 {SHA256}\nprocessors: {}\n\
             (Apache-2.0, see LICENSE)\n",
            PROCESSORS.join(", ")
        ),
    )
    .map_err(|e| format!("cannot write SOURCE.txt: {e}"))?;
    let _ = fs::remove_dir_all(&dest);
    fs::rename(&staging, &dest).map_err(|e| format!("cannot move into place: {e}"))?;
    println!(
        "native-sla: {} specifications in {} (the native engine finds them; KRAKEN_NATIVE_SPECS \
         overrides)",
        specs.len(),
        dest.display()
    );
    compare_with_install(&dest);
    Ok(())
}

/// Compiles the Sleigh compiler into `build/sleigh`, reusing objects newer than their source.
fn build_compiler(src: &Path, build: &Path) -> Result<PathBuf> {
    let obj = build.join("obj");
    fs::create_dir_all(&obj).map_err(|e| format!("cannot create {}: {e}", obj.display()))?;
    let cxx = std::env::var("CXX").unwrap_or_else(|_| "c++".into());
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let cpp = src.join("cpp");
    let zlib = src.join("zlib");
    let mut jobs: Vec<(String, PathBuf, PathBuf)> = Vec::new();
    for f in COMPILER_SOURCES {
        let s = cpp.join(format!("{f}.cc"));
        if !s.is_file() {
            return Err(format!("{} is missing", s.display()));
        }
        jobs.push((cxx.clone(), s, obj.join(format!("{f}.o"))));
    }
    for f in ZLIB {
        jobs.push((
            cc.clone(),
            zlib.join(format!("{f}.c")),
            obj.join(format!("z_{f}.o")),
        ));
    }
    let stale: Vec<&(String, PathBuf, PathBuf)> =
        jobs.iter().filter(|(_, s, o)| !newer(o, s)).collect();
    if !stale.is_empty() {
        println!(
            "native-sla: compiling the Sleigh compiler ({} of {} files)",
            stale.len(),
            jobs.len()
        );
    }
    let next = AtomicUsize::new(0);
    let errors = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads.min(stale.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((tool, s, o)) = stale.get(i) else {
                        break;
                    };
                    let mut c = Command::new(tool);
                    if tool == &cxx {
                        c.arg("-std=c++17");
                    }
                    c.args(["-O2", "-w", "-DLOCAL_ZLIB", "-DNO_GZIP", "-c"])
                        .arg("-I")
                        .arg(&cpp)
                        .arg("-I")
                        .arg(&zlib)
                        .arg(s)
                        .arg("-o")
                        .arg(o);
                    match c.status() {
                        Ok(st) if st.success() => {}
                        Ok(st) => errors
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(format!("{} failed on {}: {st}", tool, s.display())),
                        Err(e) => errors
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .push(format!("cannot run {tool}: {e}")),
                    }
                }
            });
        }
    });
    let errors = errors.into_inner().unwrap_or_else(|p| p.into_inner());
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    let exe = build.join("sleigh");
    if !stale.is_empty() || !exe.is_file() {
        let status = Command::new(&cxx)
            .arg("-o")
            .arg(&exe)
            .args(jobs.iter().map(|(_, _, o)| o))
            .status()
            .map_err(|e| format!("cannot run {cxx}: {e}"))?;
        if !status.success() {
            return Err(format!("linking the Sleigh compiler failed: {status}"));
        }
    }
    Ok(exe)
}

fn newer(a: &Path, b: &Path) -> bool {
    let m = |p: &Path| fs::metadata(p).and_then(|m| m.modified()).ok();
    matches!((m(a), m(b)), (Some(x), Some(y)) if x >= y)
}

/// Runs the compiler on every `.slaspec` in parallel, writing the `.sla` next to it.
fn compile_all(sleigh: &Path, specs: &[PathBuf]) -> Result<()> {
    println!("native-sla: compiling {} specifications", specs.len());
    let next = AtomicUsize::new(0);
    let errors = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|scope| {
        for _ in 0..threads.min(specs.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(spec) = specs.get(i) else { break };
                    let out = spec.with_extension("sla");
                    let r = Command::new(sleigh).arg(spec).arg(&out).output();
                    let mut errs = errors.lock().unwrap_or_else(|p| p.into_inner());
                    match r {
                        Ok(o) if o.status.success() && out.is_file() => {
                            println!(
                                "native-sla:   {}",
                                out.file_name().unwrap_or_default().to_string_lossy()
                            );
                        }
                        Ok(o) => errs.push(format!(
                            "{} failed: {}{}",
                            spec.display(),
                            String::from_utf8_lossy(&o.stdout),
                            String::from_utf8_lossy(&o.stderr)
                        )),
                        Err(e) => errs.push(format!("cannot run {}: {e}", sleigh.display())),
                    }
                }
            });
        }
    });
    let errors = errors.into_inner().unwrap_or_else(|p| p.into_inner());
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Reports whether the compiled x86-64 specification equals the one of a Ghidra install, when
/// there is one to compare with (`KRAKEN_GHIDRA_HOME` or `~/.cache/kraken-dev/ghidra/*`).
fn compare_with_install(dest: &Path) {
    let install = std::env::var_os("KRAKEN_GHIDRA_HOME")
        .map(PathBuf::from)
        .or_else(|| cache_dir().and_then(|c| crate::sole_child(&c.join("ghidra"))));
    let Some(install) = install else { return };
    let rel = "Ghidra/Processors/x86/data/languages/x86-64.sla";
    let (Ok(theirs), Ok(ours)) = (fs::read(install.join(rel)), fs::read(dest.join(rel))) else {
        return;
    };
    if theirs == ours {
        println!(
            "native-sla: x86-64.sla is byte-identical to {}",
            install.display()
        );
    } else {
        println!(
            "native-sla: x86-64.sla differs from {} ({} vs {} bytes; the compressed encoding may \
             differ while the specification is the same)",
            install.display(),
            ours.len(),
            theirs.len()
        );
    }
}

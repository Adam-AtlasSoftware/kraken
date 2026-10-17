//! Export: accepted units become a Cargo workspace for the strangler pattern.
//!
//! ```text
//! <dir>/Cargo.toml            workspace of the two crates below
//! <dir>/README.md             coverage, how to link the shim in place of the originals
//! <dir>/manifest.json         symbol -> original address, unit, version, verdict (also the marker
//!                             that lets a later export overwrite this directory)
//! <dir>/<name>-rewrite/       library: one module per accepted unit (the model's Rust, with its
//!                             symbol attributes removed so nothing is exported twice)
//! <dir>/<name>-ffi/           cdylib + staticlib: one `extern "C"` function per unit with the
//!                             original name and signature, calling into the library; plus a C
//!                             header
//! ```
//!
//! The generated code is the model's code, so building it is as dangerous as running a
//! translation: [`build_in_sandbox`] copies the workspace into a scratch directory and builds it
//! under the same confinement as the differential tests (read-only file system, no network).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use kraken_registry::commands::ExportCoverage;
use serde::{Deserialize, Serialize};

use crate::abi::{Param, Ret, Signature};
use crate::error::RewriteError;
use crate::native::lint_translation;
use crate::reuse;
use crate::sandbox::{Confinement, ReadScope, confine, run_captured, scratch_dir, toolchain};
use crate::unit::RewriteUnit;

/// Name of the manifest file; its presence marks a directory as an earlier export.
pub const MANIFEST: &str = "manifest.json";
/// Wall-clock limit of the sandboxed build.
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);
/// Cap on build output kept for error messages.
const OUTPUT_CAP: usize = 64 * 1024;

/// What the export says about the program it was made from.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// File name of the analysed binary.
    pub binary_name: String,
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// Crate name prefix (already sanitised).
    pub prefix: String,
    /// Coverage figures.
    pub coverage: ExportCoverage,
}

/// One exported function in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// The `extern "C"` symbol the shim exports.
    pub symbol: String,
    /// The original function's entry as KRAKEN reported it.
    pub address: String,
    /// The original function's name.
    pub original_name: String,
    /// Unit version id.
    pub unit: String,
    /// Version number.
    pub version: u32,
    /// The Rust declaration the code was verified at.
    pub prototype: String,
    /// Test cases that agreed.
    pub cases_passed: usize,
    /// Test cases that ran.
    pub cases_run: usize,
    /// `incremental` or `spec`.
    pub mode: String,
    /// Provider that wrote it.
    pub provider: Option<String>,
    /// Model that wrote it.
    pub model: Option<String>,
}

/// The manifest written next to the workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Always `kraken-rewrite`.
    pub generator: String,
    /// Layout version.
    pub schema: u32,
    /// The analysed binary's file name.
    pub binary: String,
    /// Its SHA-256.
    pub program_sha256: String,
    /// The library crate.
    pub lib_crate: String,
    /// The shim crate.
    pub ffi_crate: String,
    /// Exported functions.
    pub exports: Vec<ManifestEntry>,
    /// Accepted units exported.
    pub accepted: u32,
    /// Functions in the stored plan.
    pub planned: u32,
    /// Functions the engine listed.
    pub functions_total: u64,
}

/// What was written.
#[derive(Debug, Clone)]
pub struct Written {
    /// The library crate name.
    pub lib_crate: String,
    /// The shim crate name.
    pub ffi_crate: String,
    /// Exported symbols, sorted.
    pub symbols: Vec<String>,
    /// The README path.
    pub readme: PathBuf,
}

/// Result of the sandboxed build.
#[derive(Debug, Clone)]
pub struct Built {
    /// How the build was confined.
    pub sandbox: String,
    /// Symbols the built shared library exports (defined, global, not starting with `_`).
    pub symbols: BTreeSet<String>,
}

/// A crate-name prefix from a file name: lowercase letters, digits and hyphens, starting with a
/// letter.
pub fn crate_prefix(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let s = s.trim_matches('-').to_string();
    let s = if s.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) {
        s
    } else {
        format!("p{s}")
    };
    let s: String = s.chars().take(40).collect();
    let s = s.trim_end_matches('-').to_string();
    if s.len() < 2 {
        "program".to_string()
    } else {
        s
    }
}

fn c_type(bits: u8, signed: bool) -> String {
    format!("{}int{bits}_t", if signed { "" } else { "u" })
}

/// The C prototype of a signature.
pub fn c_prototype(sig: &Signature) -> String {
    let ret = match sig.ret {
        Ret::Void => "void".to_string(),
        Ret::Int { bits, signed } => c_type(bits, signed),
        Ret::Ptr => "const void *".to_string(),
        Ret::Double => "double".to_string(),
    };
    let params = if sig.params.is_empty() {
        "void".to_string()
    } else {
        sig.params
            .iter()
            .enumerate()
            .map(|(i, p)| match p {
                Param::Int { bits, signed } => format!("{} a{i}", c_type(*bits, *signed)),
                Param::Buf | Param::FnPtr => format!("void *a{i}"),
                Param::Double => format!("double a{i}"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("{ret} {}({params});", sig.name)
}

/// The shim function for `sig`, calling `path`.
fn shim_fn(sig: &Signature, path: &str) -> String {
    let args: Vec<String> = sig
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| match p {
            Param::FnPtr => format!("unsafe {{ std::mem::transmute::<usize, _>(a{i}) }}"),
            _ => format!("a{i} as _"),
        })
        .collect();
    let call = format!("{path}({})", args.join(", "));
    let body = match sig.ret {
        Ret::Void => format!("unsafe {{ {call} }};"),
        Ret::Int { bits, signed } => format!(
            "(unsafe {{ {call} }}) as {}",
            crate::abi::int_ty(bits, signed)
        ),
        Ret::Ptr => format!("(unsafe {{ {call} }}) as *const u8"),
        Ret::Double => format!("unsafe {{ {call} }}"),
    };
    format!(
        "#[unsafe(no_mangle)]\n{} {{\n    {body}\n}}\n",
        sig.rust_prototype()
    )
}

/// The unit's code as a library module: symbol attributes removed. Refuses code that sets its
/// own symbol names or sections, which would export something the manifest does not list.
fn module_code(unit: &RewriteUnit, uses: &str) -> Result<String, RewriteError> {
    let code = &unit.rust_code;
    if let Some(why) = lint_translation(code) {
        return Err(RewriteError::Store(format!(
            "unit {} ({}): {why}",
            unit.id, unit.anchor.name
        )));
    }
    for pat in ["export_name", "link_name", "link_section", "no_main"] {
        if code.contains(pat) {
            return Err(RewriteError::Store(format!(
                "unit {} ({}) uses `{pat}`, which the export does not allow",
                unit.id, unit.anchor.name
            )));
        }
    }
    Ok(format!(
        "{uses}{}",
        code.replace("#[unsafe(no_mangle)]", "")
            .replace("#[no_mangle]", "")
    ))
}

fn io(what: &str, e: std::io::Error) -> RewriteError {
    RewriteError::Store(format!("{what}: {e}"))
}

fn write(path: &Path, text: &str) -> Result<(), RewriteError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(&parent.display().to_string(), e))?;
    }
    std::fs::write(path, text).map_err(|e| io(&path.display().to_string(), e))
}

/// Checks that `dir` may be written: absent, empty, or an earlier export.
pub fn check_target(dir: &Path) -> Result<(), RewriteError> {
    match std::fs::read_dir(dir) {
        Ok(mut it) => {
            if it.next().is_none() || is_earlier_export(dir) {
                Ok(())
            } else {
                Err(RewriteError::Store(format!(
                    "{} is not empty and is not an earlier KRAKEN export (no {MANIFEST} from \
                     kraken-rewrite); choose another directory",
                    dir.display()
                )))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(&dir.display().to_string(), e)),
    }
}

fn is_earlier_export(dir: &Path) -> bool {
    std::fs::read_to_string(dir.join(MANIFEST))
        .ok()
        .and_then(|t| serde_json::from_str::<Manifest>(&t).ok())
        .is_some_and(|m| m.generator == "kraken-rewrite")
}

/// Writes the workspace for `units` (accepted, verified) into `dir`.
pub fn write_workspace(
    dir: &Path,
    info: &ExportInfo,
    units: &[RewriteUnit],
) -> Result<Written, RewriteError> {
    if units.is_empty() {
        return Err(RewriteError::Store(
            "no accepted units to export; accept verified units with rewrite_accept first".into(),
        ));
    }
    check_target(dir)?;
    // Same names as an earlier export are replaced; anything else in the directory is left.
    if let Ok(text) = std::fs::read_to_string(dir.join(MANIFEST))
        && let Ok(old) = serde_json::from_str::<Manifest>(&text)
        && old.generator == "kraken-rewrite"
    {
        for c in [&old.lib_crate, &old.ffi_crate] {
            if !c.is_empty() && !c.contains(['/', '\\', '.']) {
                let _ = std::fs::remove_dir_all(dir.join(c));
            }
        }
    }
    let lib_crate = format!("{}-rewrite", info.prefix);
    let ffi_crate = format!("{}-ffi", info.prefix);
    let lib_ident = lib_crate.replace('-', "_");
    let ffi_ident = ffi_crate.replace('-', "_");

    let by_address: std::collections::BTreeMap<u64, reuse::ExportedUnit> = units
        .iter()
        .map(|u| {
            (
                u64::from_str_radix(u.anchor.address.trim_start_matches("0x"), 16).unwrap_or(0),
                (
                    format!("u_{}", u.signature.name),
                    u.version,
                    u.signature.name.clone(),
                ),
            )
        })
        .collect();
    let mut symbols = BTreeSet::new();
    let mut exports = Vec::new();
    let mut modules = Vec::new();
    for u in units {
        let sym = u.signature.name.clone();
        if !symbols.insert(sym.clone()) {
            return Err(RewriteError::Store(format!(
                "two accepted units export the symbol `{sym}`; reject or re-translate one of them"
            )));
        }
        let uses = reuse::export_uses(u, &|a| by_address.get(&a).cloned())?;
        let code = module_code(u, &uses)?;
        let module = format!("u_{sym}");
        write(
            &dir.join(&lib_crate)
                .join("src")
                .join(format!("{module}.rs")),
            &format!(
                "// Unit {id} (version {ver}) of {name} at {addr}, {mode}-mode translation.\n\
                 // Generated by KRAKEN from an accepted rewrite unit; regenerate rather than edit.\n\
                 {code}\n",
                id = u.id,
                ver = u.version,
                name = u.anchor.name,
                addr = u.anchor.address,
                mode = u.mode.as_str(),
            ),
        )?;
        modules.push((module, u));
        exports.push(ManifestEntry {
            symbol: sym,
            address: u.anchor.address.clone(),
            original_name: u.anchor.name.clone(),
            unit: u.id.clone(),
            version: u.version,
            prototype: u.rust_prototype.clone(),
            cases_passed: u.summary.passed,
            cases_run: u.summary.cases_run,
            mode: u.mode.as_str().to_string(),
            provider: u.provenance.provider.clone(),
            model: u.provenance.model.clone(),
        });
    }

    write(
        &dir.join("Cargo.toml"),
        &format!("[workspace]\nmembers = [\"{lib_crate}\", \"{ffi_crate}\"]\nresolver = \"2\"\n"),
    )?;
    write(
        &dir.join(&lib_crate).join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{lib_crate}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             publish = false\ndescription = \"Rust rewrites of functions of {bin}, generated by KRAKEN\"\n\n\
             [lib]\npath = \"src/lib.rs\"\n",
            bin = info.binary_name.replace(['"', '\\', '\n'], "_"),
        ),
    )?;
    let mut lib_rs = String::from(
        "//! Rust rewrites of accepted KRAKEN rewrite units, one module per function.\n\
         //! Each function was checked against the original machine code on seeded inputs; see the\n\
         //! README and manifest.json next to the workspace manifest.\n\
         #![allow(warnings)]\n\n",
    );
    for (m, _) in &modules {
        lib_rs.push_str(&format!("pub mod {m};\n"));
    }
    write(&dir.join(&lib_crate).join("src/lib.rs"), &lib_rs)?;

    write(
        &dir.join(&ffi_crate).join("Cargo.toml"),
        &format!(
            "[package]\nname = \"{ffi_crate}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
             publish = false\ndescription = \"extern C shims for the rewrites in {lib_crate}\"\n\n\
             [lib]\nname = \"{ffi_ident}\"\npath = \"src/lib.rs\"\ncrate-type = [\"cdylib\", \"staticlib\"]\n\n\
             [dependencies]\n{lib_crate} = {{ path = \"../{lib_crate}\" }}\n"
        ),
    )?;
    let mut ffi_rs = String::from(
        "//! `extern \"C\"` entry points with the original names and signatures. Each calls the\n\
         //! verified Rust version in the library crate. Generated by KRAKEN.\n\
         #![allow(warnings)]\n\n",
    );
    let mut header = String::from(
        "/* Generated by KRAKEN: prototypes of the rewritten functions. */\n\
         #pragma once\n#include <stdint.h>\n\n#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n",
    );
    for (m, u) in &modules {
        ffi_rs.push_str(&shim_fn(
            &u.signature,
            &format!("{lib_ident}::{m}::{}", u.signature.name),
        ));
        ffi_rs.push('\n');
        header.push_str(&c_prototype(&u.signature));
        header.push('\n');
    }
    header.push_str("\n#ifdef __cplusplus\n}\n#endif\n");
    write(&dir.join(&ffi_crate).join("src/lib.rs"), &ffi_rs)?;
    write(
        &dir.join(&ffi_crate)
            .join("include")
            .join(format!("{}.h", info.prefix)),
        &header,
    )?;

    let manifest = Manifest {
        generator: "kraken-rewrite".into(),
        schema: 1,
        binary: info.binary_name.clone(),
        program_sha256: info.program_sha256.clone(),
        lib_crate: lib_crate.clone(),
        ffi_crate: ffi_crate.clone(),
        exports,
        accepted: info.coverage.accepted,
        planned: info.coverage.planned,
        functions_total: info.coverage.functions_total,
    };
    write(
        &dir.join(MANIFEST),
        &serde_json::to_string_pretty(&manifest).map_err(|e| RewriteError::Store(e.to_string()))?,
    )?;
    let readme = dir.join("README.md");
    write(&readme, &readme_text(info, &manifest, &ffi_ident))?;
    Ok(Written {
        lib_crate,
        ffi_crate,
        symbols: symbols.into_iter().collect(),
        readme,
    })
}

fn readme_text(info: &ExportInfo, m: &Manifest, ffi_ident: &str) -> String {
    let c = &info.coverage;
    let planned = if c.planned > 0 {
        format!("{} of {} planned functions", c.accepted, c.planned)
    } else {
        format!("{} functions (no plan was stored)", c.accepted)
    };
    let mut rows = String::new();
    for e in &m.exports {
        rows.push_str(&format!(
            "| `{}` | `{}` | `{}` | {}/{} | {} |\n",
            e.symbol,
            e.address,
            e.prototype.replace('|', "\\|"),
            e.cases_passed,
            e.cases_run,
            e.mode
        ));
    }
    format!(
        "# Rust rewrite of `{bin}`\n\n\
         Generated by KRAKEN (`rewrite_export`). Program SHA-256 `{sha}`.\n\n\
         ## Coverage\n\n\
         {planned} are rewritten and accepted; the program has {total} functions in the engine's \
         listing. Everything else still runs from the original binary.\n\n\
         Each rewritten function was run side by side with the original machine code under \
         emulation on seeded inputs (edge cases and random cases) and agreed on every one: return \
         value, memory it wrote through its pointer arguments, output text and how it ended. That is \
         evidence, not proof. What the tests do not control: global data the function reads, \
         library calls the emulator does not model, concurrency, and inputs outside the generated \
         ones. A person accepted each function after reading its verdict.\n\n\
         | Symbol | Original address | Verified signature | Cases passed | Mode |\n\
         |---|---|---|---|---|\n\
         {rows}\n\
         `manifest.json` has the same table with unit ids and providers.\n\n\
         ## Crates\n\n\
         - `{lib}`: the Rust code, one module per function.\n\
         - `{ffi}`: a `cdylib` and a `staticlib` named `{ffi_ident}` exporting one `extern \"C\"` \
         function per row above, with the original name and signature, and the C header \
         `{ffi}/include/{prefix}.h`.\n\n\
         Build with `cargo build --release`; the libraries are `target/release/lib{ffi_ident}.so` \
         (`.dylib`/`.dll` on other systems) and `lib{ffi_ident}.a`. The workspace has no \
         dependencies and builds offline.\n\n\
         ## Linking it in place of the originals (strangler pattern)\n\n\
         Pointer arguments are `void *` in the header; the layouts they point to are those of the \
         original program. Choose the way that fits how the program is built:\n\n\
         1. **Rebuilding from source**: drop the original definitions of these functions from the \
         build and link `lib{ffi_ident}.a` (or the `.so`). Calls to the rewritten functions now run \
         the Rust code; every other function is unchanged.\n\
         2. **Symbol interposition**: for a function that the original reaches through the dynamic \
         symbol table (exported from a shared library and called across the library boundary), run \
         the program with `LD_PRELOAD=$PWD/target/release/lib{ffi_ident}.so`. Calls inside one \
         executable or library normally do not go through the symbol table and are not redirected.\n\
         3. **Patching the binary**: overwrite each original function's entry with a jump to the \
         shim of the same name; `manifest.json` lists the original addresses. KRAKEN does not \
         patch binaries yet.\n\n\
         Functions that call a rewritten function from rewritten code (for example a helper that \
         was translated together with its caller) have their own copy of that helper inside their \
         module; the exported symbols are only the accepted functions.\n\n\
         Regenerate this directory with `kraken rewrite-export` after accepting more functions; \
         do not edit the generated files.\n",
        bin = info.binary_name,
        sha = info.program_sha256,
        total = c.functions_total,
        lib = m.lib_crate,
        ffi = m.ffi_crate,
        prefix = info.prefix,
    )
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), RewriteError> {
    std::fs::create_dir_all(to).map_err(|e| io(&to.display().to_string(), e))?;
    for entry in std::fs::read_dir(from).map_err(|e| io(&from.display().to_string(), e))? {
        let entry = entry.map_err(|e| io("read_dir", e))?;
        let ty = entry.file_type().map_err(|e| io("file_type", e))?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        if ty.is_dir() {
            if entry.file_name() == "target" {
                continue;
            }
            copy_tree(&src, &dst)?;
        } else if ty.is_file() {
            std::fs::copy(&src, &dst).map_err(|e| io(&src.display().to_string(), e))?;
        }
        // Symbolic links and special files are not copied.
    }
    Ok(())
}

/// Builds the workspace in `dir` inside the sandbox and reads the symbols of the shared library.
///
/// The workspace is copied to a scratch directory first, so the build writes nothing next to the
/// exported files; the build runs with the file system read-only except for that scratch
/// directory, no network, and a scrubbed environment; the scratch directory is private to the
/// user (never under a shared `/tmp`) and the build reads only the toolchain, system libraries and
/// that directory.
pub fn build_in_sandbox(
    dir: &Path,
    ffi_crate: &str,
    confinement: &Confinement,
) -> Result<Built, RewriteError> {
    let b = cargo_build(dir, confinement, "the exported workspace")?;
    let lib = b
        .target
        .join("release")
        .join(format!("lib{}.so", ffi_crate.replace('-', "_")));
    let symbols = exported_symbols(&lib)?;
    Ok(Built {
        sandbox: b.sandbox,
        symbols,
    })
}

/// A finished sandboxed `cargo build --release`.
#[derive(Debug)]
pub struct CargoBuild {
    /// Scratch directory holding the copy that was built and its target directory; the build
    /// products live until this is dropped.
    pub run: tempfile::TempDir,
    /// The target directory (`release/` is inside it).
    pub target: PathBuf,
    /// How the build was confined.
    pub sandbox: String,
}

/// Copies the Cargo project at `dir` into a private scratch directory and builds it in release
/// mode, offline, under the sandbox (read-only file system outside the scratch directory, no
/// network). `what` names the project in error messages.
pub fn cargo_build(
    dir: &Path,
    confinement: &Confinement,
    what: &str,
) -> Result<CargoBuild, RewriteError> {
    cargo_build_with(dir, confinement, what, &[])
}

/// [`cargo_build`] with extra environment variables for cargo (for example
/// `CARGO_PROFILE_RELEASE_OPT_LEVEL` to change the release profile).
pub fn cargo_build_with(
    dir: &Path,
    confinement: &Confinement,
    what: &str,
    env: &[(&str, &str)],
) -> Result<CargoBuild, RewriteError> {
    let tc = toolchain()?;
    let run = scratch_dir("kraken-export-")?;
    let ws = run.path().join("ws");
    copy_tree(dir, &ws)?;
    let cargo_home = run.path().join("cargo-home");
    std::fs::create_dir_all(&cargo_home).map_err(|e| io("cargo-home", e))?;
    let target = run.path().join("target");

    let mut cmd = Command::new(&tc.cargo);
    cmd.args(["build", "--release", "--offline", "--quiet", "--target-dir"])
        .arg(&target);
    let report = confine(&mut cmd, run.path(), ReadScope::Toolchain, confinement)?;
    cmd.current_dir(&ws)
        .env("CARGO_HOME", &cargo_home)
        .env("RUSTC", &tc.rustc)
        // No wrapper or extra flags from anywhere: the scratch directory has no ancestor config
        // (see `scratch_dir`), and these override any other source.
        .env("RUSTC_WRAPPER", "")
        .env("RUSTC_WORKSPACE_WRAPPER", "")
        .env("CARGO_ENCODED_RUSTFLAGS", "")
        .env("CARGO_TERM_COLOR", "never")
        .env("CARGO_NET_OFFLINE", "true")
        .env("TMPDIR", run.path());
    cmd.envs(env.iter().copied());
    let out = run_captured(
        &mut cmd,
        BUILD_TIMEOUT,
        OUTPUT_CAP,
        Duration::from_millis(20),
    )
    .map_err(|e| RewriteError::Compile(format!("cannot run cargo: {e}")))?;
    let captured_status = out.status;
    let (out, err) = (out.stdout, out.stderr);
    let Some(status) = captured_status else {
        return Err(RewriteError::Compile(format!(
            "the build did not finish within {} s",
            BUILD_TIMEOUT.as_secs()
        )));
    };
    if !status.success() {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&err),
            String::from_utf8_lossy(&out)
        );
        return Err(RewriteError::Compile(format!(
            "{what} does not build:\n{}",
            text.lines().take(30).collect::<Vec<_>>().join("\n")
        )));
    }
    Ok(CargoBuild {
        run,
        target,
        sandbox: report.label(),
    })
}

/// Defined global dynamic symbols of a shared library whose names do not start with `_`.
#[cfg(target_os = "linux")]
fn exported_symbols(lib: &Path) -> Result<BTreeSet<String>, RewriteError> {
    use object::read::elf::ElfFile64;
    use object::{Object, ObjectSymbol};
    let data = std::fs::read(lib).map_err(|e| io(&lib.display().to_string(), e))?;
    let file = ElfFile64::<object::Endianness>::parse(&*data)
        .map_err(|e| RewriteError::Native(format!("built library: {e}")))?;
    Ok(file
        .dynamic_symbols()
        .filter(|s| s.is_definition() && s.is_global())
        .filter_map(|s| s.name().ok().map(str::to_string))
        .filter(|n| !n.starts_with('_') && !n.is_empty())
        .collect())
}

#[cfg(not(target_os = "linux"))]
fn exported_symbols(_lib: &Path) -> Result<BTreeSet<String>, RewriteError> {
    Err(RewriteError::Native(
        "checking the built library's symbols is only implemented on Linux".into(),
    ))
}

/// Compares the built library's symbols with the expected ones.
pub fn check_symbols(expected: &[String], built: &BTreeSet<String>) -> Result<(), RewriteError> {
    let want: BTreeSet<&String> = expected.iter().collect();
    let got: BTreeSet<&String> = built.iter().collect();
    let missing: Vec<&&String> = want.difference(&got).collect();
    let extra: Vec<&&String> = got.difference(&want).collect();
    if missing.is_empty() && extra.is_empty() {
        Ok(())
    } else {
        Err(RewriteError::Native(format!(
            "the built library's symbol table does not match the accepted units: missing \
             {missing:?}, unexpected {extra:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{Param, Ret};

    fn sig() -> Signature {
        Signature {
            name: "vm_run".into(),
            params: vec![
                Param::Buf,
                Param::Buf,
                Param::Int {
                    bits: 32,
                    signed: false,
                },
            ],
            ret: Ret::Int {
                bits: 32,
                signed: true,
            },
        }
    }

    #[test]
    fn prefixes_are_valid_crate_names() {
        assert_eq!(crate_prefix("switch_vm-O0"), "switch-vm-o0");
        assert_eq!(crate_prefix("9lives"), "p9lives");
        assert_eq!(crate_prefix("a"), "program");
        assert_eq!(crate_prefix("--x--y--"), "x-y");
        assert_eq!(crate_prefix(&"z".repeat(100)).len(), 40);
    }

    #[test]
    fn shims_and_headers_follow_the_signature() {
        let s = shim_fn(&sig(), "lib::u_vm_run::vm_run");
        assert!(s.starts_with("#[unsafe(no_mangle)]\npub unsafe extern \"C\" fn vm_run("));
        assert!(s.contains("lib::u_vm_run::vm_run(a0 as _, a1 as _, a2 as _)"));
        assert!(s.contains(") as i32"));
        assert_eq!(
            c_prototype(&sig()),
            "int32_t vm_run(void *a0, void *a1, uint32_t a2);"
        );
        let v = Signature {
            name: "f".into(),
            params: vec![],
            ret: Ret::Void,
        };
        assert_eq!(c_prototype(&v), "void f(void);");
        assert!(shim_fn(&v, "l::f").contains("unsafe { l::f() };"));
    }

    #[test]
    fn symbol_tables_must_match_exactly() {
        let built: BTreeSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        assert!(check_symbols(&["a".into(), "b".into()], &built).is_ok());
        let e = check_symbols(&["a".into(), "c".into()], &built).expect_err("mismatch");
        let text = e.to_string();
        assert!(text.contains("missing") && text.contains("\"c\"") && text.contains("\"b\""));
    }
}

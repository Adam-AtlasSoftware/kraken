//! Whole-program rewrite: assemble the chosen translations into a standalone Rust binary crate,
//! build it in the sandbox, and verify the program against the original on the same inputs
//! (ADR 0013, oracle kind `process`).
//!
//! ```text
//! <dir>/Cargo.toml          one binary, no dependencies, its own [workspace]
//! <dir>/kraken-program.json marker and manifest: functions, units, versions, verdicts
//! <dir>/README.md           what this is and how far to trust it
//! <dir>/src/main.rs         builds argc/argv/envp as C sees them and calls the translated entry
//! <dir>/src/rt.rs           the runtime shim (libc calls on Rust std), same text for every program
//! <dir>/src/u_<name>.rs     one module per function: the unit's code, symbol attributes removed,
//!                           `use` lines for the translations it calls instead of re-translating
//! ```
//!
//! The model's code is untrusted: building and running the crate happen only under the sandbox
//! (see [`crate::sandbox`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kraken_proto::Untrusted;
use kraken_registry::commands::{ProgramCaseResult, ProgramRunView, ProgramVerdictView};
use serde::{Deserialize, Serialize};

use crate::abi::{Param, Ret};
use crate::error::RewriteError;
use crate::export::{CargoBuild, cargo_build, crate_prefix};
use crate::native::lint_translation;
use crate::process::{Exit, Outcome, ProgramCase, VIEW_BYTES, compare, run_case};
use crate::reuse;
use crate::sandbox::{Confinement, ConfinementReport};
use crate::unit::{RewriteUnit, sha256_hex};

/// `generator` of the manifest; its presence marks a directory as an earlier program rewrite.
pub const GENERATOR: &str = "kraken-rewrite/program";
/// Marker and manifest file name.
pub const MANIFEST: &str = "kraken-program.json";
/// Most cases kept in a stored verdict.
pub const MAX_VIEW_CASES: usize = 200;

fn io(what: &str, e: std::io::Error) -> RewriteError {
    RewriteError::Store(format!("{what}: {e}"))
}

/// One function in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFunction {
    /// Rust function name.
    pub symbol: String,
    /// Original entry as KRAKEN reported it.
    pub address: String,
    /// Original name.
    pub original_name: String,
    /// Unit version id.
    pub unit: String,
    /// Version number.
    pub version: u32,
    /// Status of that version when the crate was made.
    pub status: String,
    /// Function-level verdict kind.
    pub verdict: String,
    /// Oracle kind of the function-level check.
    pub oracle: String,
    /// Provider and model that wrote it.
    pub author: String,
    /// Symbols of the translations it calls.
    pub calls: Vec<String>,
}

/// The manifest of a generated crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramManifest {
    /// Always [`GENERATOR`].
    pub generator: String,
    /// Layout version.
    pub schema: u32,
    /// File name of the analysed binary.
    pub binary: String,
    /// Its SHA-256.
    pub program_sha256: String,
    /// The binary target's name.
    pub bin_name: String,
    /// The translated entry point's Rust symbol.
    pub entry: String,
    /// SHA-256 over `Cargo.toml` and the `src` files.
    pub crate_sha256: String,
    /// The functions in the crate.
    pub functions: Vec<ManifestFunction>,
}

/// What [`assemble`] needs to know.
#[derive(Debug, Clone)]
pub struct AssembleInfo<'a> {
    /// File name of the analysed binary.
    pub binary_name: &'a str,
    /// Its SHA-256.
    pub program_sha256: &'a str,
}

/// A written crate.
#[derive(Debug, Clone)]
pub struct Assembled {
    /// Name of the binary target.
    pub bin_name: String,
    /// SHA-256 over the crate sources.
    pub crate_sha256: String,
    /// The entry point's Rust symbol.
    pub entry_symbol: String,
    /// Rust symbols of the functions in the crate.
    pub symbols: Vec<String>,
}

fn module_of(unit: &RewriteUnit) -> String {
    format!("u_{}", unit.signature.name)
}

fn parse_addr(a: &str) -> u64 {
    u64::from_str_radix(a.trim_start_matches("0x"), 16).unwrap_or(0)
}

/// A unit's code as a module of the program crate: symbol attributes removed (the program has no
/// reason to export anything), the shim and the translations it calls in scope.
fn module_source(unit: &RewriteUnit, uses: &str) -> Result<String, RewriteError> {
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
                "unit {} ({}) uses `{pat}`, which a program crate does not allow",
                unit.id, unit.anchor.name
            )));
        }
    }
    let body = code
        .replace("#[unsafe(no_mangle)]", "")
        .replace("#[no_mangle]", "");
    Ok(format!(
        "// Unit {id} (version {ver}) of {name} at {addr}, generated by KRAKEN.\n\
         // Regenerate rather than edit.\n\
         #![allow(warnings)]\n\
         use super::rt;\n\
         {uses}\n\
         {body}\n",
        id = unit.id,
        ver = unit.version,
        name = unit.anchor.name.replace(['\n', '\r'], " "),
        addr = unit.anchor.address,
    ))
}

/// `main.rs`: the C runtime's job (argc, argv, envp) and the call into the entry unit.
fn main_source(entry: &RewriteUnit, modules: &[String]) -> String {
    let sig = &entry.signature;
    let args: Vec<String> = sig
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| match (p, i) {
            (Param::Int { .. }, 0) => "argc as _".to_string(),
            (Param::Int { .. }, _) => "0 as _".to_string(),
            (Param::Buf, 1) => "argv.as_ptr() as _".to_string(),
            (Param::Buf, 2) => "envp.as_ptr() as _".to_string(),
            (Param::Buf, _) => "std::ptr::null_mut::<u8>() as _".to_string(),
            (Param::Double, _) => "0.0".to_string(),
            (Param::FnPtr, _) => "unsafe { std::mem::transmute::<usize, _>(0usize) }".to_string(),
        })
        .collect();
    let call = format!("{}::{}({})", module_of(entry), sig.name, args.join(", "));
    let finish = match sig.ret {
        Ret::Int { .. } => format!("let code = unsafe {{ {call} }} as i32;"),
        Ret::Void | Ret::Ptr | Ret::Double => {
            format!("unsafe {{ {call} }};\n    let code = 0;")
        }
    };
    let mods: String = modules.iter().map(|m| format!("mod {m};\n")).collect();
    format!(
        r#"//! Rust rewrite of `{name}`, generated by KRAKEN. The entry point is `{sym}`.
#![allow(warnings)]

mod rt;
{mods}
fn os_bytes(s: &std::ffi::OsStr) -> Vec<u8> {{
    #[cfg(unix)]
    {{
        use std::os::unix::ffi::OsStrExt;
        s.as_bytes().to_vec()
    }}
    #[cfg(not(unix))]
    {{
        s.to_string_lossy().into_owned().into_bytes()
    }}
}}

/// A NUL-terminated copy that lives for the rest of the process.
fn c_string(mut bytes: Vec<u8>) -> *const u8 {{
    bytes.retain(|b| *b != 0);
    bytes.push(0);
    Box::leak(bytes.into_boxed_slice()).as_ptr()
}}

fn main() {{
    // Debugging aid of KRAKEN's program-level repair: `KRAKEN_TRACE_AT=out:<byte>` (or `err:`,
    // `exit`) prints the call stack at that point to stderr. Unset, it does nothing.
    if let Some(spec) = std::env::var_os("KRAKEN_TRACE_AT") {{
        rt::trace_arm(&spec.to_string_lossy());
    }}
    let mut argv: Vec<*const u8> = std::env::args_os()
        .map(|a| c_string(os_bytes(&a)))
        .collect();
    let argc = argv.len() as i32;
    argv.push(std::ptr::null());
    let mut envp: Vec<*const u8> = std::env::vars_os()
        .map(|(k, v)| {{
            let mut kv = os_bytes(&k);
            kv.push(b'=');
            kv.extend(os_bytes(&v));
            c_string(kv)
        }})
        .collect();
    envp.push(std::ptr::null());
    {finish}
    rt::exit(code)
}}
"#,
        name = entry.anchor.name.replace(['\n', '\r'], " "),
        sym = sig.name,
    )
}

fn cargo_toml(bin: &str, binary_name: &str) -> String {
    format!(
        "[package]\nname = \"{bin}-rewrite\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\
         publish = false\ndescription = \"Rust rewrite of {desc}, generated by KRAKEN\"\n\n\
         [[bin]]\nname = \"{bin}\"\npath = \"src/main.rs\"\n\n\
         [profile.release]\nopt-level = 1\noverflow-checks = true\ndebug = false\n\n\
         [workspace]\n",
        desc = binary_name.replace(['"', '\\', '\n'], "_"),
    )
}

fn readme(info: &AssembleInfo<'_>, m: &ProgramManifest) -> String {
    format!(
        "# Rust rewrite of `{bin}`\n\n\
         Generated by KRAKEN (`rewrite_program`). Program SHA-256 `{sha}`; crate SHA-256 `{crate_sha}`.\n\n\
         - `src/main.rs` builds `argc`, `argv` and `envp` the way the C runtime does and calls the \
         translated entry point `{entry}`.\n\
         - `src/rt.rs` is the runtime shim: the libc calls the translations make (`printf`, `puts`, \
         `strlen`, `malloc`, `free`, `exit`, ...) on Rust `std`. It is the same text for every program.\n\
         - `src/u_*.rs` hold one translated function each ({n} functions). They are the model's code \
         for the original machine code: read them before you trust them.\n\n\
         ## How far to trust it\n\n\
         Each function was built in a sandbox, and compared with the original under emulation when \
         the function-level test could run (see `{manifest}`). The program as a whole was run next to \
         the original, both in a sandbox with no network, on a set of inputs; `kraken \
         rewrite-program-status` shows the cases and every difference. That is evidence about the \
         inputs tried, not a proof. Output is written through Rust's stdout, which flushes at every \
         newline, where libc buffers it when it is a pipe: only the interleaving of stdout and \
         stderr could show it.\n\n\
         Build with `cargo build --release` (no dependencies).\n",
        bin = info.binary_name.replace('`', "'"),
        sha = info.program_sha256,
        crate_sha = m.crate_sha256,
        entry = m.entry,
        n = m.functions.len(),
        manifest = MANIFEST,
    )
}

/// Checks that `dir` may be written: absent, empty, or an earlier program rewrite.
pub fn check_target(dir: &Path) -> Result<(), RewriteError> {
    match std::fs::read_dir(dir) {
        Ok(mut it) => {
            let earlier = std::fs::read_to_string(dir.join(MANIFEST))
                .ok()
                .and_then(|t| serde_json::from_str::<ProgramManifest>(&t).ok())
                .is_some_and(|m| m.generator == GENERATOR);
            if it.next().is_none() || earlier {
                Ok(())
            } else {
                Err(RewriteError::Store(format!(
                    "{} is not empty and is not an earlier KRAKEN program rewrite (no {MANIFEST} \
                     from {GENERATOR}); choose another directory",
                    dir.display()
                )))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(&dir.display().to_string(), e)),
    }
}

/// Writes the crate for `entry` and the translations it needs (`units`, which include `entry`,
/// each the chosen version of its function) into `dir`.
pub fn assemble(
    dir: &Path,
    info: &AssembleInfo<'_>,
    entry: &RewriteUnit,
    units: &[RewriteUnit],
) -> Result<Assembled, RewriteError> {
    check_target(dir)?;
    let bin_name = crate_prefix(info.binary_name);
    let by_address: BTreeMap<u64, reuse::ExportedUnit> = units
        .iter()
        .map(|u| {
            (
                parse_addr(&u.anchor.address),
                (module_of(u), u.version, u.signature.name.clone()),
            )
        })
        .collect();
    if !by_address.contains_key(&parse_addr(&entry.anchor.address)) {
        return Err(RewriteError::Store(
            "the entry unit is not among the units of the crate".into(),
        ));
    }
    let mut files: Vec<(String, String)> = Vec::new();
    let mut modules: Vec<String> = Vec::new();
    let mut functions: Vec<ManifestFunction> = Vec::new();
    let mut symbols: Vec<String> = Vec::new();
    for u in units {
        let sym = u.signature.name.clone();
        if symbols.contains(&sym) {
            return Err(RewriteError::Store(format!(
                "two functions of the program are called `{sym}` in Rust; rename one of them"
            )));
        }
        let uses = reuse::program_uses(u, &|a| by_address.get(&a).cloned())?;
        files.push((format!("src/{}.rs", module_of(u)), module_source(u, &uses)?));
        modules.push(module_of(u));
        functions.push(ManifestFunction {
            symbol: sym.clone(),
            address: u.anchor.address.clone(),
            original_name: u.anchor.name.clone(),
            unit: u.id.clone(),
            version: u.version,
            status: u.status.as_str().to_string(),
            verdict: verdict_kind(&u.verdict).to_string(),
            oracle: u.oracle.kind.clone(),
            author: format!(
                "{} {}",
                u.provenance.provider.clone().unwrap_or_default(),
                u.provenance.model.clone().unwrap_or_default()
            )
            .trim()
            .to_string(),
            calls: u
                .callees
                .iter()
                .filter_map(|c| c.reused.as_ref().map(|r| r.symbol.clone()))
                .collect(),
        });
        symbols.push(sym);
    }
    modules.sort();
    files.push(("src/rt.rs".to_string(), crate::RT_SOURCE.to_string()));
    files.push(("src/main.rs".to_string(), main_source(entry, &modules)));
    files.push((
        "Cargo.toml".to_string(),
        cargo_toml(&bin_name, info.binary_name),
    ));
    files.sort();
    let crate_sha256 = sha256_hex(
        &files
            .iter()
            .map(|(p, t)| format!("{p}\n{}\n{t}", t.len()))
            .collect::<Vec<_>>()
            .join("\n--\n"),
    );
    functions.sort_by(|a, b| a.symbol.cmp(&b.symbol));
    let manifest = ProgramManifest {
        generator: GENERATOR.into(),
        schema: 1,
        binary: info.binary_name.to_string(),
        program_sha256: info.program_sha256.to_string(),
        bin_name: bin_name.clone(),
        entry: entry.signature.name.clone(),
        crate_sha256: crate_sha256.clone(),
        functions,
    };
    // An earlier run's sources go; anything else in the directory stays.
    let src = dir.join("src");
    if src.is_dir() {
        std::fs::remove_dir_all(&src).map_err(|e| io(&src.display().to_string(), e))?;
    }
    for (path, text) in &files {
        write(&dir.join(path), text)?;
    }
    write(
        &dir.join(MANIFEST),
        &serde_json::to_string_pretty(&manifest).map_err(|e| RewriteError::Store(e.to_string()))?,
    )?;
    write(&dir.join("README.md"), &readme(info, &manifest))?;
    Ok(Assembled {
        bin_name,
        crate_sha256,
        entry_symbol: entry.signature.name.clone(),
        symbols,
    })
}

fn write(path: &Path, text: &str) -> Result<(), RewriteError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io(&parent.display().to_string(), e))?;
    }
    std::fs::write(path, text).map_err(|e| io(&path.display().to_string(), e))
}

fn verdict_kind(v: &crate::difftest::Verdict) -> &'static str {
    match v {
        crate::difftest::Verdict::Pass => "pass",
        crate::difftest::Verdict::Fail => "fail",
        crate::difftest::Verdict::Rejected { .. } => "rejected",
        crate::difftest::Verdict::Inconclusive { .. } => "inconclusive",
    }
}

/// A built program.
#[derive(Debug)]
pub struct BuiltProgram {
    /// The build's scratch directory; the executable lives in it until this is dropped.
    pub build: CargoBuild,
    /// The executable.
    pub exe: PathBuf,
}

/// Builds the crate at `dir` in the sandbox and returns the executable.
pub fn build_program(
    dir: &Path,
    bin_name: &str,
    confinement: &Confinement,
) -> Result<BuiltProgram, RewriteError> {
    let build = cargo_build(dir, confinement, "the rewritten program")?;
    let exe = build.target.join("release").join(bin_name);
    if !exe.is_file() {
        return Err(RewriteError::Compile(format!(
            "the build produced no executable `{bin_name}`"
        )));
    }
    Ok(BuiltProgram { build, exe })
}

// ----- verification -----

/// What the program-level test concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramVerdictKind {
    /// Every case agreed.
    Pass,
    /// At least one case differed.
    Fail,
    /// No runnable rewrite exists; the text says why.
    Incomplete(String),
    /// The cases could not tell; the text says why.
    Inconclusive(String),
}

impl ProgramVerdictKind {
    /// The name in reports.
    pub fn name(&self) -> &'static str {
        match self {
            ProgramVerdictKind::Pass => "pass",
            ProgramVerdictKind::Fail => "fail",
            ProgramVerdictKind::Incomplete(_) => "incomplete",
            ProgramVerdictKind::Inconclusive(_) => "inconclusive",
        }
    }

    /// The reason, for the verdicts that have one.
    pub fn detail(&self) -> Option<&str> {
        match self {
            ProgramVerdictKind::Incomplete(d) | ProgramVerdictKind::Inconclusive(d) => Some(d),
            _ => None,
        }
    }
}

/// Both programs on one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseReport {
    /// The input.
    pub case: ProgramCase,
    /// The original.
    pub original: Outcome,
    /// The rewrite.
    pub rewritten: Outcome,
    /// What differs; empty when the case agreed.
    pub differences: Vec<String>,
}

/// The program-level verdict with its per-case evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramVerdict {
    /// The conclusion.
    pub kind: ProgramVerdictKind,
    /// Every case that ran.
    pub reports: Vec<CaseReport>,
    /// How the programs were confined (`landlock-v6+netns` and the like).
    pub sandbox: String,
}

impl ProgramVerdict {
    /// A verdict without cases: nothing ran.
    pub fn without_cases(kind: ProgramVerdictKind) -> Self {
        ProgramVerdict {
            kind,
            reports: Vec::new(),
            sandbox: String::new(),
        }
    }
}

/// Runs `original` and `rewritten` on every case, each in the sandbox, and compares them.
/// `tick` is called after each case with (done, total) and may return false to stop early
/// (cancelled); a stopped run is an error.
pub fn verify_program(
    original: &Path,
    rewritten: &Path,
    cases: &[ProgramCase],
    confinement: &Confinement,
    tick: &dyn Fn(usize, usize) -> bool,
) -> Result<ProgramVerdict, RewriteError> {
    let mut reports = Vec::new();
    let mut sandbox: Option<ConfinementReport> = None;
    for (i, case) in cases.iter().enumerate() {
        let (orig, report) = run_case(original, case, confinement)?;
        let (new, _) = run_case(rewritten, case, confinement)?;
        sandbox.get_or_insert(report);
        let differences = compare(&orig, &new);
        reports.push(CaseReport {
            case: case.clone(),
            original: orig,
            rewritten: new,
            differences,
        });
        if !tick(i + 1, cases.len()) {
            return Err(RewriteError::Cancelled);
        }
    }
    let kind = if reports.is_empty() {
        ProgramVerdictKind::Inconclusive("there were no cases to run".into())
    } else if reports.iter().all(|r| r.original.exit == Exit::Timeout) {
        ProgramVerdictKind::Inconclusive("the original timed out on every case".into())
    } else if reports.iter().any(|r| !r.differences.is_empty()) {
        ProgramVerdictKind::Fail
    } else {
        ProgramVerdictKind::Pass
    };
    Ok(ProgramVerdict {
        kind,
        reports,
        sandbox: sandbox.map(|r| r.label()).unwrap_or_default(),
    })
}

fn run_view(o: &Outcome, cap: usize) -> ProgramRunView {
    let text = |b: &[u8]| {
        let cut = &b[..b.len().min(cap)];
        let mut s = String::from_utf8_lossy(cut).into_owned();
        if b.len() > cap {
            s.push_str(&format!("\n[... {} more bytes]", b.len() - cap));
        }
        Untrusted::sanitized(&s)
    };
    ProgramRunView {
        exit: o.exit.describe(),
        stdout: text(&o.stdout),
        stdout_bytes: o.stdout.len() as u64,
        stderr: text(&o.stderr),
        stderr_bytes: o.stderr.len() as u64,
    }
}

impl ProgramVerdict {
    /// The registry's view of the verdict. Output of cases that agreed is cut shorter than
    /// output of cases that differed.
    pub fn view(&self) -> ProgramVerdictView {
        let cases_run = u32::try_from(self.reports.len()).unwrap_or(u32::MAX);
        let failed = u32::try_from(
            self.reports
                .iter()
                .filter(|r| !r.differences.is_empty())
                .count(),
        )
        .unwrap_or(u32::MAX);
        let mut shown: Vec<&CaseReport> = self
            .reports
            .iter()
            .filter(|r| !r.differences.is_empty())
            .collect();
        shown.extend(self.reports.iter().filter(|r| r.differences.is_empty()));
        shown.truncate(MAX_VIEW_CASES);
        ProgramVerdictView {
            verdict: self.kind.name().to_string(),
            detail: self.kind.detail().map(Untrusted::sanitized),
            cases_run,
            passed: cases_run - failed,
            failed,
            cases: shown
                .into_iter()
                .map(|r| {
                    let agree = r.differences.is_empty();
                    let cap = if agree { 512 } else { VIEW_BYTES };
                    ProgramCaseResult {
                        name: r.case.name.clone(),
                        origin: r.case.origin.as_str().to_string(),
                        argv: r
                            .case
                            .argv
                            .iter()
                            .map(|a| Untrusted::sanitized(a))
                            .collect(),
                        stdin_bytes: r.case.stdin.len() as u64,
                        agree,
                        original: run_view(&r.original, cap),
                        rewritten: run_view(&r.rewritten, cap),
                        differences: r
                            .differences
                            .iter()
                            .map(|d| Untrusted::sanitized(d))
                            .collect(),
                    }
                })
                .collect(),
            sandbox: self.sandbox.clone(),
        }
    }
}

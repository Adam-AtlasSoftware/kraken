//! `emulate_run`: run the project's original executable under whole-program emulation.
//!
//! The guest is interpreted by `kraken-emu` (Linux user mode: its system calls are answered by
//! the emulator, nothing reaches the host), inside the sandbox child `kraken-emu-run`. A run
//! changes nothing in the project.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
#[cfg(unix)]
use kraken_emu::confined::{find_runner, run_program_confined};
use kraken_emu::{Arch, EmuError, Exit, ProgramOutcome, RunSpec};
use kraken_proto::{ErrorCode, ProtoError, Untrusted, sanitize};
use kraken_sidecar::ConfinementOptions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchfile::apply_project_patches;
use crate::session::{Session, blocking};

// The sandboxed runner is Unix-only: elsewhere no runner is found and `emulate_run` says so.
#[cfg(not(unix))]
fn find_runner() -> Option<PathBuf> {
    None
}

#[cfg(not(unix))]
fn run_program_confined(
    _spec: &RunSpec,
    _runner: &Path,
    _options: ConfinementOptions,
) -> Result<(ProgramOutcome, kraken_sidecar::ConfinementReport), EmuError> {
    Err(EmuError::Unsupported(
        "whole-program emulation runs on Linux only".into(),
    ))
}

/// Default instruction budget of `emulate_run`.
pub const DEFAULT_MAX_STEPS: u64 = 20_000_000;
/// Largest instruction budget of `emulate_run`.
pub const MAX_MAX_STEPS: u64 = 200_000_000;
/// Default wall-clock limit in seconds.
pub const DEFAULT_TIMEOUT_SECONDS: u64 = 20;
/// Largest wall-clock limit in seconds.
pub const MAX_TIMEOUT_SECONDS: u64 = 120;
/// Characters of each output stream returned.
pub const OUTPUT_CHARS: usize = 4000;
/// Largest standard input accepted, in bytes.
pub const MAX_STDIN_BYTES: usize = 1 << 20;
/// Most arguments accepted.
pub const MAX_ARGS: usize = 64;
/// Longest single argument, in bytes.
pub const MAX_ARG_BYTES: usize = 4096;
/// Most environment variables accepted.
pub const MAX_ENV: usize = 64;
/// Most seeded input files.
pub const MAX_INPUTS: usize = 16;
/// Largest seeded input file, in bytes.
pub const MAX_INPUT_BYTES: usize = 1 << 20;
/// Largest seeded inputs together, in bytes.
pub const MAX_INPUT_TOTAL: usize = 4 << 20;
/// Most files returned.
const MAX_RETURN_FILES: usize = 16;
/// Output kept by the emulator per stream before the characters are counted.
const RUN_OUTPUT_CAP: usize = 64 * 1024;
/// Most written files named in the notes.
const MAX_FILE_NOTES: usize = 5;

/// Arguments of `emulate_run`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulateRunArgs {
    /// Text for the program's standard input (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// Command-line arguments after `argv[0]` (at most 64, each at most 4096 bytes).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Instruction budget (default 20000000, at most 200000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit in seconds (default 20, at most 120).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Run a copy with the project's byte patches applied, instead of the original (default
    /// false).
    #[serde(default)]
    pub patched: bool,
    /// Environment variables of the program (nothing of this computer's is passed; at most 64).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// What the program sees as `argv[0]` (default `prog`).
    #[serde(default)]
    pub argv0: Option<String>,
    /// Files put into the program's private `/work` before it starts (at most 16, 1 MiB each,
    /// 4 MiB together).
    #[serde(default)]
    pub inputs: Vec<EmulateInput>,
    /// Return the files the program wrote in `/work` (default false; the names are always in
    /// `notes`).
    #[serde(default)]
    pub return_files: bool,
}

/// A file seeded into the program's `/work`. Give `text` or `hex`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulateInput {
    /// Relative path inside `/work`, for example `input.txt` or `data/in.bin`.
    pub name: String,
    /// The contents as text.
    #[serde(default)]
    pub text: Option<String>,
    /// The contents as hexadecimal digits, for binary data.
    #[serde(default)]
    pub hex: Option<String>,
}

/// A file the program left in `/work`. The contents are program data and so untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateFile {
    /// Path relative to `/work`.
    pub name: String,
    /// Length in bytes.
    pub size: u64,
    /// The first 4000 characters when the file is text; for binary data the first 64 bytes as
    /// hexadecimal digits.
    pub preview: Untrusted<String>,
    /// True when the file is not valid UTF-8 text (`preview` is hex).
    pub binary: bool,
    /// True when `preview` does not show the whole file.
    pub truncated: bool,
}

/// How an emulated run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EmulateExitKind {
    /// The program exited; `value` is the exit code.
    Code,
    /// A signal ended it (a fault, or `abort`); `value` is the signal number.
    Signal,
    /// The wall-clock limit ran out.
    Timeout,
    /// The instruction budget ran out.
    StepLimit,
    /// The program needed something the emulator does not implement; see `notes`.
    Unsupported,
}

/// The end of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateExit {
    /// How it ended.
    pub kind: EmulateExitKind,
    /// The exit code or signal number; absent for the other kinds.
    pub value: Option<i64>,
}

/// Result of `emulate_run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateRunOut {
    /// How the run ended.
    pub exit: EmulateExit,
    /// What the program wrote to standard output (first 4000 characters). Program data, so
    /// untrusted.
    pub stdout: Untrusted<String>,
    /// What the program wrote to standard error (first 4000 characters). Untrusted.
    pub stderr: Untrusted<String>,
    /// Instructions executed.
    pub steps: u64,
    /// True when `stdout` or `stderr` was cut.
    pub truncated: bool,
    /// Facts about the run: the architecture, calls the emulator does not implement (by name),
    /// files written, what a fault was.
    pub notes: Vec<String>,
    /// The files the program wrote, when `return_files` was set (at most 16).
    #[serde(default)]
    pub files: Vec<EmulateFile>,
}

/// Runs the program of the open project in the emulator.
pub struct EmulateRun;

#[async_trait]
impl Command for EmulateRun {
    type Args = EmulateRunArgs;
    type Output = EmulateRunOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "emulate_run",
            "Run the program in the emulator with the given stdin and arguments; returns exit status and output",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Runs the project's original executable under emulation (Linux user mode, ELF) and \
             reports how it ended: `exit` (code, signal, timeout or step_limit), `stdout`, \
             `stderr` (4000 characters each, program data and so untrusted) and `steps`. The \
             program never runs on this computer: time and randomness are fixed, files exist \
             only in a private directory, there is no network. `env`, `argv0` and `inputs` (files \
             seeded into `/work`) set up the run; `return_files` returns what it wrote. Nothing \
             in the project changes.\n\
             Example: emulate_run {\"stdin\": \"hello\\n\", \"argv\": [\"-v\"], \"env\": {\"MODE\": \"fast\"}, \"inputs\": [{\"name\": \"in.txt\", \"text\": \"abc\"}], \"return_files\": true}",
        )
        .details(
            "Whole-program emulation of the executable the project was made from, on KRAKEN's \
             own Linux system-call layer (x86, x86-64, ARM, AArch64, RISC-V). Two runs with the \
             same input agree byte for byte. The run happens in a sandboxed child process \
             (`kraken-emu-run`) that can read the program and the SLEIGH specs and write one \
             private directory that is removed afterwards. A statically linked program runs as \
             is; a dynamically linked one needs a sysroot with its loader and libraries \
             (`cargo xtask emu-sysroots`, or `KRAKEN_EMU_SYSROOTS`); without one, an x86 or \
             x86-64 program gets private copies of this computer's loader and of the libraries \
             it names, and sees nothing else of this computer. Needs the SLEIGH specs (`kraken setup --native`, or `KRAKEN_NATIVE_SPECS`). \
             `kind: unsupported` means the program used an instruction the emulator cannot \
             execute.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: EmulateRunArgs,
    ) -> Result<EmulateRunOut, ProtoError> {
        let limits = validate(&args)?;
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let patches = if args.patched {
            project.with_store(|st| st.all_patches()).await?
        } else {
            Vec::new()
        };
        let patched = Patched {
            patches,
            engine_base: project.program().base.0,
        };
        blocking(move || {
            let raw = emulate(&binary, &args, limits, &patched, find_runner())?;
            Ok(present(raw, args.return_files, &args.inputs))
        })
        .await
    }
}

/// Validated numeric limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    steps: u64,
    seconds: u64,
}

fn invalid(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

fn validate(args: &EmulateRunArgs) -> Result<Limits, ProtoError> {
    let steps = args.max_steps.unwrap_or(DEFAULT_MAX_STEPS);
    if steps == 0 || steps > MAX_MAX_STEPS {
        return Err(invalid(format!(
            "max_steps must be between 1 and {MAX_MAX_STEPS}"
        )));
    }
    let seconds = args.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS);
    if seconds == 0 || seconds > MAX_TIMEOUT_SECONDS {
        return Err(invalid(format!(
            "timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}"
        )));
    }
    if args.stdin.len() > MAX_STDIN_BYTES {
        return Err(invalid(format!(
            "stdin is longer than {MAX_STDIN_BYTES} bytes"
        )));
    }
    if args.argv.len() > MAX_ARGS {
        return Err(invalid(format!("argv has more than {MAX_ARGS} entries")));
    }
    for a in &args.argv {
        if a.len() > MAX_ARG_BYTES {
            return Err(invalid(format!(
                "an argv entry is longer than {MAX_ARG_BYTES} bytes"
            )));
        }
        if a.contains('\0') {
            return Err(invalid("argv entries cannot contain a NUL byte"));
        }
    }
    if args.env.len() > MAX_ENV {
        return Err(invalid(format!("env has more than {MAX_ENV} entries")));
    }
    for (k, v) in &args.env {
        if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
            return Err(invalid(
                "env names cannot be empty or contain `=` or NUL, and values cannot contain NUL",
            ));
        }
        if k.len() > MAX_ARG_BYTES || v.len() > MAX_ARG_BYTES {
            return Err(invalid(format!(
                "an env entry is longer than {MAX_ARG_BYTES} bytes"
            )));
        }
    }
    if let Some(a) = &args.argv0
        && (a.len() > MAX_ARG_BYTES || a.contains('\0'))
    {
        return Err(invalid("argv0 is too long or contains a NUL byte"));
    }
    decode_inputs(&args.inputs)?;
    Ok(Limits { steps, seconds })
}

/// Checks the seeded files and decodes their contents.
fn decode_inputs(inputs: &[EmulateInput]) -> Result<Vec<(PathBuf, Vec<u8>)>, ProtoError> {
    if inputs.len() > MAX_INPUTS {
        return Err(invalid(format!("inputs has more than {MAX_INPUTS} files")));
    }
    let mut out: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut total = 0usize;
    for i in inputs {
        let rel = Path::new(&i.name);
        let ok = !i.name.is_empty()
            && i.name.len() <= 128
            && !i.name.contains('\0')
            && rel
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)));
        if !ok {
            return Err(invalid(format!(
                "input name {:?} must be a relative path inside /work without `..`",
                sanitize(&i.name)
            )));
        }
        let data = match (&i.text, &i.hex) {
            (Some(t), None) => t.clone().into_bytes(),
            (None, Some(h)) => decode_hex(h).ok_or_else(|| {
                invalid(format!(
                    "input {:?}: hex is not an even run of hex digits",
                    i.name
                ))
            })?,
            _ => {
                return Err(invalid(format!(
                    "input {:?} needs exactly one of `text` and `hex`",
                    i.name
                )));
            }
        };
        if data.len() > MAX_INPUT_BYTES {
            return Err(invalid(format!(
                "input {:?} is longer than {MAX_INPUT_BYTES} bytes",
                i.name
            )));
        }
        total += data.len();
        if total > MAX_INPUT_TOTAL {
            return Err(invalid(format!(
                "inputs are longer than {MAX_INPUT_TOTAL} bytes together"
            )));
        }
        if out.iter().any(|(p, _)| p == rel) {
            return Err(invalid(format!("input {:?} is given twice", i.name)));
        }
        out.push((rel.to_path_buf(), data));
    }
    Ok(out)
}

fn decode_hex(h: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = h.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .chunks(2)
        .map(|c| {
            let s = std::str::from_utf8(c).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

fn problem(code: ErrorCode, msg: impl Into<String>) -> ProtoError {
    ProtoError::new(code, msg)
}

/// Where a dynamically linked program's loader and libraries come from.
enum Sysroot {
    /// A sysroot extracted by `cargo xtask emu-sysroots` (or `KRAKEN_EMU_SYSROOTS`).
    Extracted(PathBuf),
    /// Copies of this computer's own loader and the libraries the program needs, made for the run.
    Host,
}

/// The sysroot for `arch`: the extracted one if present, else this computer's libraries when the
/// program is built for the host (an x86-64 Linux host runs x86-64 programs, and 32-bit x86 ones
/// with multilib installed), so a release install emulates dynamic programs without building
/// sysroots first.
fn sysroot_for(arch: Arch) -> Option<Sysroot> {
    let set = match arch {
        Arch::X86 => "elf32",
        Arch::Arm => "arm32",
        Arch::Aarch64 => "aarch64",
        Arch::Riscv64 => "riscv64",
        Arch::X86_64 => "x86_64",
        Arch::Riscv32 => return None,
    };
    let root = match std::env::var_os("KRAKEN_EMU_SYSROOTS").filter(|v| !v.is_empty()) {
        Some(p) => Some(PathBuf::from(p)),
        None => std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".cache/kraken-dev/emu-sysroots")),
    };
    if let Some(dir) = root.map(|r| r.join(set))
        && dir.join("lib").is_dir()
    {
        return Some(Sysroot::Extracted(dir));
    }
    host_libraries(arch).then_some(Sysroot::Host)
}

/// Whether this computer has a loader for programs of `arch`.
fn host_libraries(arch: Arch) -> bool {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return false;
    }
    let loader = match arch {
        Arch::X86_64 => "/lib64/ld-linux-x86-64.so.2",
        Arch::X86 => "/lib/ld-linux.so.2",
        _ => return false,
    };
    Path::new(loader).exists()
}

fn emulation_error(e: EmuError, binary: &Path) -> ProtoError {
    match e {
        EmuError::Image(m) => problem(
            ErrorCode::Unsupported,
            format!(
                "{} is not an ELF program the emulator supports (x86, x86-64, ARM, AArch64, \
                 RISC-V): {m}",
                binary.display()
            ),
        ),
        EmuError::NoSpecs { .. } => problem(
            ErrorCode::Unsupported,
            format!(
                "the emulator needs the SLEIGH processor specs and found none: run \
                 `kraken setup --native`, or set KRAKEN_NATIVE_SPECS to a tree that holds \
                 Ghidra/Processors ({e})"
            ),
        ),
        EmuError::NeedsSysroot {
            arch: Arch::X86_64, ..
        } => problem(
            ErrorCode::Unsupported,
            "a dynamically linked x86-64 program needs a sysroot: run `cargo xtask \
             emu-sysroots` (needs docker or podman and the debian:trixie-slim image) or set \
             KRAKEN_EMU_SYSROOTS",
        ),
        EmuError::NeedsSysroot { .. } => problem(ErrorCode::Unsupported, e.to_string()),
        EmuError::Unsupported(m) => problem(ErrorCode::Unsupported, m),
        EmuError::Io(m) | EmuError::Emulator(m) => {
            problem(ErrorCode::Internal, format!("emulation failed: {m}"))
        }
    }
}

/// The byte patches of a patched run and the image base the engine loaded the program at.
struct Patched {
    patches: Vec<kraken_model::Patch>,
    engine_base: u64,
}

/// What one run produced, before it is shown.
struct RawRun {
    outcome: ProgramOutcome,
    notes: Vec<String>,
}

/// One run of `binary` in the confined runner. `runner` is the `kraken-emu-run` binary. When
/// `args.patched` and there are patches, a patched copy is run instead of `binary`.
fn emulate(
    binary: &Path,
    args: &EmulateRunArgs,
    limits: Limits,
    patched: &Patched,
    runner: Option<PathBuf>,
) -> Result<RawRun, ProtoError> {
    let Patched {
        patches,
        engine_base,
    } = patched;
    let engine_base = *engine_base;
    let runner = runner.filter(|p| p.is_file()).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            "the emulator's child program `kraken-emu-run` was not found next to this executable: \
             build it (`cargo build -p kraken-emu --bin kraken-emu-run`) or set KRAKEN_EMU_RUN \
             to its path",
        )
    })?;
    if !binary.is_file() {
        return Err(problem(
            ErrorCode::NotFound,
            format!(
                "the project's binary {} is not there any more",
                binary.display()
            ),
        ));
    }
    let work = tempfile::Builder::new()
        .prefix("kraken-emulate-")
        .tempdir()
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    let mut notes = Vec::new();
    // A patched run executes a copy with the project's byte patches applied; the copy lives in
    // the run's private directory and is read only by the confined child.
    let program = if args.patched && !patches.is_empty() {
        let patched = build_patched_copy(binary, patches, work.path(), engine_base)?;
        notes.push(format!(
            "ran a patched copy with {} byte patch{} applied",
            patches.len(),
            if patches.len() == 1 { "" } else { "es" }
        ));
        patched
    } else {
        if args.patched {
            notes.push(
                "patched run requested, but the project has no byte patches; ran the original"
                    .into(),
            );
        }
        binary.to_path_buf()
    };
    // `/work` is a subdirectory, so the patched copy beside it is not listed as a written file.
    let guest = work.path().join("guest");
    std::fs::create_dir(&guest)
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    for (rel, data) in decode_inputs(&args.inputs)? {
        let dest = guest.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .and_then(|()| std::fs::write(&dest, data))
                .map_err(|e| problem(ErrorCode::Internal, format!("cannot seed an input: {e}")))?;
        }
    }
    let mut spec = RunSpec::new(&program);
    spec.args = args.argv.clone();
    spec.argv0 = args.argv0.clone();
    spec.env = args
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    spec.stdin = args.stdin.clone().into_bytes();
    spec.max_instructions = limits.steps;
    spec.timeout_ms = Duration::from_secs(limits.seconds).as_millis() as u64;
    spec.output_cap = RUN_OUTPUT_CAP;
    spec.workdir = Some(guest);

    let run = |spec: &RunSpec| run_program_confined(spec, &runner, ConfinementOptions::default());
    // Holds the private copy of this computer's libraries until the run is over.
    let mut _host_libs = None;
    let result = match run(&spec) {
        Err(EmuError::NeedsSysroot { arch, interp, .. }) if sysroot_for(arch).is_some() => {
            match sysroot_for(arch) {
                Some(Sysroot::Extracted(dir)) => {
                    notes.push(format!(
                        "dynamic program: libraries from the sysroot {}",
                        dir.display()
                    ));
                    spec.sysroot = Some(dir);
                }
                Some(Sysroot::Host) => {
                    let dir = tempfile::Builder::new()
                        .prefix("kraken-emulate-libs-")
                        .tempdir()
                        .map_err(|e| {
                            problem(ErrorCode::Internal, format!("private sysroot: {e}"))
                        })?;
                    let libs =
                        kraken_emu::hostlibs::private_sysroot(&program, &interp, arch, dir.path())
                            .map_err(|e| emulation_error(e, binary))?;
                    notes.push(format!(
                        "dynamic program: its loader and {} librar{} were copied from this \
                         computer into a private sysroot; nothing else of this computer is \
                         visible, so libraries opened by name at run time (dlopen, NSS, gconv) \
                         are absent. If emulation stops at an unsupported vector instruction, \
                         this system's libraries are built for newer CPUs (some distributions \
                         build for x86-64-v3); in a source checkout `cargo xtask emu-sysroots` \
                         extracts portable ones",
                        libs.libraries.len(),
                        if libs.libraries.len() == 1 {
                            "y"
                        } else {
                            "ies"
                        }
                    ));
                    if !libs.missing.is_empty() {
                        notes.push(format!(
                            "libraries the program needs that this computer lacks: {}",
                            libs.missing.join(", ")
                        ));
                    }
                    spec.sysroot = Some(dir.path().to_path_buf());
                    _host_libs = Some(dir);
                }
                None => {}
            }
            run(&spec)
        }
        other => other,
    };
    let (outcome, report) = result.map_err(|e| emulation_error(e, binary))?;
    if !report.is_confined() {
        notes.push(format!(
            "the emulator child ran with limited confinement: {report}"
        ));
    }
    Ok(RawRun { outcome, notes })
}

/// Writes a copy of `binary` with `patches` applied into `work_dir` and returns its path. The
/// recorded original bytes are checked, so a patch that does not line up is reported, not written.
fn build_patched_copy(
    binary: &Path,
    patches: &[kraken_model::Patch],
    work_dir: &Path,
    engine_base: u64,
) -> Result<PathBuf, ProtoError> {
    let (patched, _) = apply_project_patches(binary, patches, engine_base)?;
    let out = work_dir.join("program");
    std::fs::write(&out, &patched).map_err(|e| {
        problem(
            ErrorCode::Internal,
            format!("cannot write the patched copy: {e}"),
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700));
    }
    Ok(out)
}

/// Cuts `bytes` to [`OUTPUT_CHARS`] characters and sanitises them; the flag says it was cut.
fn text(bytes: &[u8], emulator_cut: bool) -> (Untrusted<String>, bool) {
    let all = String::from_utf8_lossy(bytes);
    let cut = all.chars().count() > OUTPUT_CHARS;
    let kept: String = all.chars().take(OUTPUT_CHARS).collect();
    (Untrusted(sanitize(&kept)), cut || emulator_cut)
}

/// A preview of a written file's bytes.
fn file_view(name: &str, size: u64, data: &[u8]) -> EmulateFile {
    let cut_by_emulator = (data.len() as u64) < size;
    match std::str::from_utf8(data) {
        Ok(t) => {
            let (preview, cut) = text(t.as_bytes(), cut_by_emulator);
            EmulateFile {
                name: sanitize(name),
                size,
                preview,
                binary: false,
                truncated: cut,
            }
        }
        Err(_) => {
            let hex: String = data.iter().take(64).map(|b| format!("{b:02x}")).collect();
            EmulateFile {
                name: sanitize(name),
                size,
                preview: Untrusted(hex),
                binary: true,
                truncated: size > 64,
            }
        }
    }
}

/// The files the program wrote or changed (seeded inputs it left alone are not listed).
fn written<'a>(
    o: &'a ProgramOutcome,
    inputs: &[EmulateInput],
) -> Vec<&'a kraken_emu::linux::WrittenFile> {
    let seeded: Vec<(String, Vec<u8>)> = inputs
        .iter()
        .filter_map(|i| {
            let data = match (&i.text, &i.hex) {
                (Some(t), _) => t.clone().into_bytes(),
                (_, Some(h)) => decode_hex(h)?,
                _ => return None,
            };
            Some((i.name.clone(), data))
        })
        .collect();
    o.files
        .iter()
        .filter(|f| {
            !seeded
                .iter()
                .any(|(n, d)| *n == f.name && d.len() as u64 == f.size && *d == f.data)
        })
        .collect()
}

fn present(raw: RawRun, return_files: bool, inputs: &[EmulateInput]) -> EmulateRunOut {
    let RawRun {
        outcome: o,
        mut notes,
    } = raw;
    let (kind, value) = match &o.exit {
        Exit::Code { code } => (EmulateExitKind::Code, Some(i64::from(*code))),
        Exit::Signal { signal, detail } => {
            notes.push(format!("signal {signal}: {detail}"));
            (EmulateExitKind::Signal, Some(i64::from(*signal)))
        }
        Exit::Budget => (EmulateExitKind::StepLimit, None),
        Exit::Timeout => (EmulateExitKind::Timeout, None),
        Exit::Unsupported { detail } => {
            notes.push(format!("unsupported: {detail}"));
            (EmulateExitKind::Unsupported, None)
        }
    };
    notes.insert(0, format!("architecture {}", o.arch.name()));
    notes.extend(o.notes.iter().cloned());
    if !o.unknown_syscalls.is_empty() {
        let nums: Vec<String> = o
            .unknown_syscalls
            .iter()
            .map(|n| {
                let name = kraken_emu::linux::sysno::describe(o.arch, *n);
                if name.starts_with("syscall ") {
                    name
                } else {
                    format!("{name} ({n})")
                }
            })
            .collect();
        notes.push(format!(
            "system calls the emulator does not implement (answered ENOSYS): {}",
            nums.join(", ")
        ));
    }
    let wrote = written(&o, inputs);
    if !wrote.is_empty() {
        let names: Vec<String> = wrote
            .iter()
            .take(MAX_FILE_NOTES)
            .map(|f| sanitize(&f.name))
            .collect();
        let more = wrote.len().saturating_sub(MAX_FILE_NOTES);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        notes.push(format!(
            "files written in the private directory (discarded unless return_files is set): {}{tail}",
            names.join(", ")
        ));
    }
    let (stdout, cut_out) = text(&o.stdout, o.stdout.len() >= RUN_OUTPUT_CAP);
    let (stderr, cut_err) = text(&o.stderr, o.stderr.len() >= RUN_OUTPUT_CAP);
    let truncated = cut_out || cut_err;
    if truncated {
        notes.push(format!(
            "output cut to {OUTPUT_CHARS} characters per stream"
        ));
    }
    EmulateRunOut {
        exit: EmulateExit { kind, value },
        stdout,
        stderr,
        steps: o.instructions,
        truncated,
        notes,
        files: if return_files {
            wrote
                .iter()
                .take(MAX_RETURN_FILES)
                .map(|f| file_view(&f.name, f.size, &f.data))
                .collect()
        } else {
            Vec::new()
        },
    }
}

/// Arguments of `emulate_compare`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmulateCompareArgs {
    /// Standard input of both runs (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// Command-line arguments after `argv[0]` of both runs.
    #[serde(default)]
    pub argv: Vec<String>,
    /// `argv[0]` of both runs (default `prog`).
    #[serde(default)]
    pub argv0: Option<String>,
    /// Environment variables of both runs.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Files seeded into `/work` of both runs.
    #[serde(default)]
    pub inputs: Vec<EmulateInput>,
    /// Instruction budget of each run (default 20000000, at most 200000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit of each run in seconds (default 20, at most 120).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// The first variant: `original` (default), `patched` (the project's byte patches applied)
    /// or the path of another executable.
    #[serde(default)]
    pub a: Option<String>,
    /// The second variant, same choices (default `patched`).
    #[serde(default)]
    pub b: Option<String>,
}

/// One way the two runs differ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateDifference {
    /// `exit`, `stdout`, `stderr` or `file <name>`.
    pub field: String,
    /// What differs, quoting the first point of difference. Program data, so untrusted.
    pub summary: Untrusted<String>,
}

/// Result of `emulate_compare`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmulateCompareOut {
    /// The first variant's run.
    pub a: EmulateRunOut,
    /// The second variant's run.
    pub b: EmulateRunOut,
    /// True when exit, standard output, standard error and written files all agree.
    pub same: bool,
    /// Every difference found (instruction counts are not compared).
    pub differences: Vec<EmulateDifference>,
    /// The first difference in reading order: output first, then exit, then files; empty when
    /// the runs agree. Untrusted.
    pub first_divergence: Untrusted<String>,
}

/// Runs two variants of the program with the same inputs and reports how they differ.
pub struct EmulateCompare;

#[async_trait]
impl Command for EmulateCompare {
    type Args = EmulateCompareArgs;
    type Output = EmulateCompareOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "emulate_compare",
            "Run the original and the patched program (or any two variants) with the same input and report the differences",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Runs two variants of the program under emulation with identical stdin, arguments, \
             environment and seeded files, and reports whether exit status, stdout, stderr and \
             written files agree, with each difference and the first point where they diverge. \
             Variants are `original`, `patched` (the project's byte patches) or the path of \
             another executable. Use it to see what a patch changes. Nothing in the project \
             changes.\n\
             Example: emulate_compare {\"stdin\": \"hello\\n\", \"a\": \"original\", \"b\": \"patched\"}",
        )
        .details(
            "Both runs happen in the sandboxed emulator as `emulate_run` describes, side by \
             side. With the default variants and no byte patches in the project the command \
             fails and says so, because there would be nothing to compare. Instruction counts \
             are reported for each run but are not a difference. Written files are compared \
             byte for byte (the first 1 MiB of each). Output text is program data and so \
             untrusted.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: EmulateCompareArgs,
    ) -> Result<EmulateCompareOut, ProtoError> {
        let base = EmulateRunArgs {
            stdin: args.stdin,
            argv: args.argv,
            max_steps: args.max_steps,
            timeout_seconds: args.timeout_seconds,
            patched: false,
            env: args.env,
            argv0: args.argv0,
            inputs: args.inputs,
            return_files: true,
        };
        let limits = validate(&base)?;
        let a = Variant::parse(args.a.as_deref().unwrap_or("original"))?;
        let b = Variant::parse(args.b.as_deref().unwrap_or("patched"))?;
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let patches = if a == Variant::Patched || b == Variant::Patched {
            let p = project.with_store(|st| st.all_patches()).await?;
            if p.is_empty() {
                return Err(invalid(
                    "the project has no byte patches to run; set one with patch_set or name \
                     another executable as variant a or b",
                ));
            }
            p
        } else {
            Vec::new()
        };
        let patched = Patched {
            patches,
            engine_base: project.program().base.0,
        };
        blocking(move || {
            let runner = find_runner();
            let (ra, rb) = std::thread::scope(|sc| {
                let ha = sc.spawn(|| run_variant(&a, &binary, &base, limits, &patched, &runner));
                let rb = run_variant(&b, &binary, &base, limits, &patched, &runner);
                let ra = ha.join().unwrap_or_else(|_| {
                    Err(problem(ErrorCode::Internal, "a comparison run panicked"))
                });
                (ra, rb)
            });
            Ok(compare(ra?, rb?, &base.inputs))
        })
        .await
    }
}

/// One side of a comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Variant {
    Original,
    Patched,
    Other(PathBuf),
}

impl Variant {
    fn parse(text: &str) -> Result<Self, ProtoError> {
        match text {
            "original" => Ok(Variant::Original),
            "patched" => Ok(Variant::Patched),
            "" => Err(invalid("a variant is `original`, `patched` or a file path")),
            path => {
                let p = PathBuf::from(path);
                if p.is_file() {
                    Ok(Variant::Other(p))
                } else {
                    Err(problem(
                        ErrorCode::NotFound,
                        format!("variant {path:?} is not `original`, `patched` or a file"),
                    ))
                }
            }
        }
    }
}

fn run_variant(
    v: &Variant,
    binary: &Path,
    base: &EmulateRunArgs,
    limits: Limits,
    patched: &Patched,
    runner: &Option<PathBuf>,
) -> Result<RawRun, ProtoError> {
    let mut args = base.clone();
    let target = match v {
        Variant::Original => binary,
        Variant::Patched => {
            args.patched = true;
            binary
        }
        Variant::Other(p) => p,
    };
    emulate(target, &args, limits, patched, runner.clone())
}

fn describe_exit(e: &EmulateExit) -> String {
    match (e.kind, e.value) {
        (EmulateExitKind::Code, Some(v)) => format!("exit code {v}"),
        (EmulateExitKind::Signal, Some(v)) => format!("signal {v}"),
        (EmulateExitKind::Timeout, _) => "timeout".into(),
        (EmulateExitKind::StepLimit, _) => "step limit".into(),
        (EmulateExitKind::Unsupported, _) => "unsupported".into(),
        (k, _) => format!("{k:?}"),
    }
}

fn quote(s: &[u8]) -> String {
    let t = String::from_utf8_lossy(s);
    let short: String = t.chars().take(120).collect();
    sanitize(&short)
}

/// Where two byte streams first differ, as a sentence; `None` when equal. Text is compared by
/// line, so the line number and both lines show.
fn stream_difference(a: &[u8], b: &[u8]) -> Option<String> {
    if a == b {
        return None;
    }
    let (la, lb): (Vec<&[u8]>, Vec<&[u8]>) = (
        a.split(|c| *c == b'\n').collect(),
        b.split(|c| *c == b'\n').collect(),
    );
    for i in 0..la.len().max(lb.len()) {
        match (la.get(i), lb.get(i)) {
            (Some(x), Some(y)) if x == y => {}
            (Some(x), Some(y)) => {
                return Some(format!("line {}: {:?} vs {:?}", i + 1, quote(x), quote(y)));
            }
            (Some(x), None) => {
                return Some(format!(
                    "line {}: {:?} vs nothing (b ends)",
                    i + 1,
                    quote(x)
                ));
            }
            (None, Some(y)) => {
                return Some(format!(
                    "line {}: nothing (a ends) vs {:?}",
                    i + 1,
                    quote(y)
                ));
            }
            (None, None) => {}
        }
    }
    Some("the outputs differ in length".into())
}

fn compare(a: RawRun, b: RawRun, inputs: &[EmulateInput]) -> EmulateCompareOut {
    let mut diffs: Vec<EmulateDifference> = Vec::new();
    let mut add = |field: &str, summary: String| {
        diffs.push(EmulateDifference {
            field: field.to_string(),
            summary: Untrusted(sanitize(&summary)),
        });
    };
    if let Some(d) = stream_difference(&a.outcome.stdout, &b.outcome.stdout) {
        add("stdout", d);
    }
    if let Some(d) = stream_difference(&a.outcome.stderr, &b.outcome.stderr) {
        add("stderr", d);
    }
    let (ea, eb) = (present_exit(&a.outcome.exit), present_exit(&b.outcome.exit));
    if ea != eb {
        add(
            "exit",
            format!("{} vs {}", describe_exit(&ea), describe_exit(&eb)),
        );
    }
    let (fa, fb) = (written(&a.outcome, inputs), written(&b.outcome, inputs));
    let mut names: Vec<&str> = fa
        .iter()
        .chain(fb.iter())
        .map(|f| f.name.as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    for n in names {
        let x = fa.iter().find(|f| f.name == n);
        let y = fb.iter().find(|f| f.name == n);
        let label = format!("file {}", sanitize(n));
        match (x, y) {
            (Some(x), Some(y)) if x.data == y.data && x.size == y.size => {}
            (Some(x), Some(y)) => add(
                &label,
                stream_difference(&x.data, &y.data)
                    .unwrap_or_else(|| format!("sizes {} vs {}", x.size, y.size)),
            ),
            (Some(_), None) => add(&label, "written by a only".into()),
            (None, Some(_)) => add(&label, "written by b only".into()),
            (None, None) => {}
        }
    }
    let first = diffs
        .first()
        .map(|d| format!("{}: {}", d.field, d.summary.0))
        .unwrap_or_default();
    let (ra, rb) = (present(a, true, inputs), present(b, true, inputs));
    EmulateCompareOut {
        a: ra,
        b: rb,
        same: diffs.is_empty(),
        differences: diffs,
        first_divergence: Untrusted(first),
    }
}

/// The exit as `emulate_run` reports it, so `Unsupported` details do not count as a difference.
fn present_exit(e: &Exit) -> EmulateExit {
    match e {
        Exit::Code { code } => EmulateExit {
            kind: EmulateExitKind::Code,
            value: Some(i64::from(*code)),
        },
        Exit::Signal { signal, .. } => EmulateExit {
            kind: EmulateExitKind::Signal,
            value: Some(i64::from(*signal)),
        },
        Exit::Budget => EmulateExit {
            kind: EmulateExitKind::StepLimit,
            value: None,
        },
        Exit::Timeout => EmulateExit {
            kind: EmulateExitKind::Timeout,
            value: None,
        },
        Exit::Unsupported { .. } => EmulateExit {
            kind: EmulateExitKind::Unsupported,
            value: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> EmulateRunArgs {
        EmulateRunArgs::default()
    }

    #[test]
    fn defaults_and_bounds() {
        let l = validate(&args()).expect("defaults");
        assert_eq!(
            (l.steps, l.seconds),
            (DEFAULT_MAX_STEPS, DEFAULT_TIMEOUT_SECONDS)
        );
        for bad in [0, MAX_MAX_STEPS + 1] {
            let e = validate(&EmulateRunArgs {
                max_steps: Some(bad),
                ..args()
            })
            .expect_err("steps");
            assert_eq!(e.code, ErrorCode::InvalidArgument);
        }
        for bad in [0, MAX_TIMEOUT_SECONDS + 1] {
            let e = validate(&EmulateRunArgs {
                timeout_seconds: Some(bad),
                ..args()
            })
            .expect_err("seconds");
            assert_eq!(e.code, ErrorCode::InvalidArgument);
        }
        validate(&EmulateRunArgs {
            max_steps: Some(MAX_MAX_STEPS),
            timeout_seconds: Some(MAX_TIMEOUT_SECONDS),
            ..args()
        })
        .expect("maxima are allowed");
    }

    #[test]
    fn inputs_are_bounded() {
        let long = "x".repeat(MAX_ARG_BYTES + 1);
        for bad in [
            EmulateRunArgs {
                argv: vec![long],
                ..args()
            },
            EmulateRunArgs {
                argv: vec!["a\0b".into()],
                ..args()
            },
            EmulateRunArgs {
                argv: vec!["a".into(); MAX_ARGS + 1],
                ..args()
            },
            EmulateRunArgs {
                stdin: "x".repeat(MAX_STDIN_BYTES + 1),
                ..args()
            },
        ] {
            assert_eq!(
                validate(&bad).expect_err("bounded").code,
                ErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn output_is_cut_by_characters_and_sanitised() {
        let body = format!("{}\u{1b}[31mred\u{202e}", "é".repeat(OUTPUT_CHARS - 1));
        let (t, cut) = text(body.as_bytes(), false);
        assert!(cut);
        assert_eq!(t.0.chars().count(), OUTPUT_CHARS - 1);
        assert!(!t.0.contains('\u{1b}') && !t.0.contains('\u{202e}'));
        let (short, cut) = text(b"hi\n", false);
        assert!(!cut);
        assert_eq!(short.0, "hi\n");
    }

    #[test]
    fn a_missing_runner_is_named() {
        let e = emulate(
            Path::new("/nonexistent"),
            &args(),
            Limits {
                steps: 1,
                seconds: 1,
            },
            &Patched {
                patches: Vec::new(),
                engine_base: 0,
            },
            None,
        )
        .err()
        .expect("no runner");
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("kraken-emu-run"), "{}", e.message);
    }
}

//! `emulate_run`: run the project's original executable under whole-program emulation.
//!
//! The guest is interpreted by `kraken-emu` (Linux user mode: its system calls are answered by
//! the emulator, nothing reaches the host), inside the sandbox child `kraken-emu-run`. A run
//! changes nothing in the project.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use kraken_emu::confined::{find_runner, run_program_confined};
use kraken_emu::{Arch, EmuError, Exit, ProgramOutcome, RunSpec};
use kraken_proto::{ErrorCode, ProtoError, Untrusted, sanitize};
use kraken_sidecar::ConfinementOptions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchfile::{FilePatch, PatchError, patch_file_bytes_at};
use crate::session::{Session, blocking};

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
    /// Facts about the run: the architecture, calls the emulator does not implement, files
    /// written, what a fault was.
    pub notes: Vec<String>,
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
             only in a private directory, there is no network. Nothing in the project changes.\n\
             Example: emulate_run {\"stdin\": \"hello\\n\", \"argv\": [\"-v\"]}",
        )
        .details(
            "Whole-program emulation of the executable the project was made from, on KRAKEN's \
             own Linux system-call layer (x86, x86-64, ARM, AArch64, RISC-V). Two runs with the \
             same input agree byte for byte. The run happens in a sandboxed child process \
             (`kraken-emu-run`) that can read the program and the SLEIGH specs and write one \
             private directory that is removed afterwards. A statically linked program runs as \
             is; a dynamically linked one needs a sysroot with its loader and libraries \
             (`cargo xtask emu-sysroots`, or `KRAKEN_EMU_SYSROOTS`), not the libraries of this \
             computer. Needs the SLEIGH specs (`kraken setup --native`, or `KRAKEN_NATIVE_SPECS`). \
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
        blocking(move || emulate(&binary, args, limits, patched, find_runner())).await
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
    Ok(Limits { steps, seconds })
}

fn problem(code: ErrorCode, msg: impl Into<String>) -> ProtoError {
    ProtoError::new(code, msg)
}

/// The directory of the sysroot extracted by `cargo xtask emu-sysroots` for `arch`, if present.
fn sysroot_for(arch: Arch) -> Option<PathBuf> {
    let set = match arch {
        Arch::X86 => "elf32",
        Arch::Arm => "arm32",
        Arch::Aarch64 => "aarch64",
        Arch::Riscv64 => "riscv64",
        Arch::X86_64 => "x86_64",
        Arch::Riscv32 => return None,
    };
    let root = match std::env::var_os("KRAKEN_EMU_SYSROOTS").filter(|v| !v.is_empty()) {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(std::env::var_os("HOME")?).join(".cache/kraken-dev/emu-sysroots"),
    };
    let dir = root.join(set);
    dir.join("lib").is_dir().then_some(dir)
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

/// One run of `binary` in the confined runner. `runner` is the `kraken-emu-run` binary. When
/// there are patches, a patched copy is run instead of `binary`.
fn emulate(
    binary: &Path,
    args: EmulateRunArgs,
    limits: Limits,
    patched: Patched,
    runner: Option<PathBuf>,
) -> Result<EmulateRunOut, ProtoError> {
    let Patched {
        patches,
        engine_base,
    } = patched;
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
        let patched = build_patched_copy(binary, &patches, work.path(), engine_base)?;
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
    let mut spec = RunSpec::new(&program);
    spec.args = args.argv;
    spec.stdin = args.stdin.into_bytes();
    spec.max_instructions = limits.steps;
    spec.timeout_ms = Duration::from_secs(limits.seconds).as_millis() as u64;
    spec.output_cap = RUN_OUTPUT_CAP;
    spec.workdir = Some(work.path().to_path_buf());

    let run = |spec: &RunSpec| run_program_confined(spec, &runner, ConfinementOptions::default());
    let result = match run(&spec) {
        Err(EmuError::NeedsSysroot { arch, .. }) if sysroot_for(arch).is_some() => {
            spec.sysroot = sysroot_for(arch);
            if let Some(s) = &spec.sysroot {
                notes.push(format!(
                    "dynamic program: libraries from the sysroot {}",
                    s.display()
                ));
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
    Ok(present(outcome, notes))
}

/// Writes a copy of `binary` with `patches` applied into `work_dir` and returns its path. The
/// recorded original bytes are checked, so a patch that does not line up is reported, not written.
fn build_patched_copy(
    binary: &Path,
    patches: &[kraken_model::Patch],
    work_dir: &Path,
    engine_base: u64,
) -> Result<PathBuf, ProtoError> {
    let image = std::fs::read(binary).map_err(|e| {
        problem(
            ErrorCode::NotFound,
            format!("cannot read the project's binary {}: {e}", binary.display()),
        )
    })?;
    let file_patches: Vec<FilePatch> = patches
        .iter()
        .map(|p| FilePatch {
            address: p.address,
            original: p.original.clone(),
            replacement: p.replacement.clone(),
        })
        .collect();
    let (patched, _) =
        patch_file_bytes_at(&image, &file_patches, Some(engine_base)).map_err(|e| match e {
            PatchError::NotAnObject(_) => problem(ErrorCode::Unsupported, e.to_string()),
            PatchError::NoMapping(_) => problem(ErrorCode::InvalidArgument, e.to_string()),
        })?;
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

fn present(o: ProgramOutcome, mut notes: Vec<String>) -> EmulateRunOut {
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
        let nums: Vec<String> = o.unknown_syscalls.iter().map(u64::to_string).collect();
        notes.push(format!(
            "system calls the emulator does not implement (answered ENOSYS): {}",
            nums.join(", ")
        ));
    }
    if !o.files.is_empty() {
        let names: Vec<String> = o
            .files
            .iter()
            .take(MAX_FILE_NOTES)
            .map(|f| sanitize(&f.name))
            .collect();
        let more = o.files.len().saturating_sub(MAX_FILE_NOTES);
        let tail = if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        };
        notes.push(format!(
            "files written in the private directory (discarded): {}{tail}",
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
            args(),
            Limits {
                steps: 1,
                seconds: 1,
            },
            Patched {
                patches: Vec::new(),
                engine_base: 0,
            },
            None,
        )
        .expect_err("no runner");
        assert_eq!(e.code, ErrorCode::Unsupported);
        assert!(e.message.contains("kraken-emu-run"), "{}", e.message);
    }
}

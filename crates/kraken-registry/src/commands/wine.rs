//! `wine_run`: run a Windows program under Wine, confined.
//!
//! Wine is never bundled: the `wine` entry of the integrations catalogue is the user's own (PATH
//! or a path) or the pinned portable build "Install for me" unpacks. Every run gets a fresh Wine
//! prefix inside a private scratch directory, which is also the only place the program may write:
//! `kraken-confine` gives the child a Landlock read-only view of the system, no network and a
//! scrubbed environment (no host home, no display), and the whole directory is removed afterwards.

use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use kraken_confine::{Confinement, Limits, ReadScope};
use kraken_emu::linux::WrittenFile;
use kraken_emu::{Arch, Exit, ProgramOutcome};
use kraken_proto::{ErrorCode, ProtoError, Untrusted};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::emulate::{
    EmulateExit, EmulateFile, EmulateInput, EmulateRunArgs, MAX_ARG_BYTES, MAX_ARGS, MAX_ENV,
    MAX_STDIN_BYTES, RawRun, decode_inputs, invalid, present, problem,
};
use super::integrations::{LaunchSpec, RunTarget};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::{Session, blocking};

/// Default wall-clock limit: a fresh prefix takes several seconds to build before the program
/// starts.
const DEFAULT_TIMEOUT: u64 = 60;
/// Largest wall-clock limit.
const MAX_TIMEOUT: u64 = 300;
/// Most DLLs copied from the program's directory.
const MAX_SIBLINGS: usize = 16;
/// Largest sibling DLL copied.
const MAX_SIBLING_BYTES: u64 = 32 << 20;
/// Most files reported as written.
const MAX_FILES: usize = 16;
/// Most files looked at in the work directory after the run.
const MAX_SCAN: usize = 256;
/// Largest written file read back.
const MAX_FILE_READ: u64 = 1 << 20;
/// Output kept per stream.
const STREAM_CAP: usize = 64 * 1024;
/// Wine's own start-up chatter that says nothing about the program.
const NOISE: &[&str] = &[
    "wine: created the configuration directory",
    "wine: configuration in",
    "Fontconfig error:",
    "error: XDG_RUNTIME_DIR",
    "MESA-EGL:",
    "pci id for fd",
];

/// Arguments of `wine_run`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WineRunArgs {
    /// What to run: `original` (default), `patched` (the project's byte patches applied) or
    /// `file`.
    #[serde(default)]
    pub target: RunTarget,
    /// The file for `target: file`; absolute.
    #[serde(default)]
    pub file: Option<String>,
    /// Standard input (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// Command-line arguments (at most 64, each at most 4096 bytes).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Environment variables of the program (nothing of this computer's is passed; at most 64).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Files put next to the program before it starts (at most 16, 1 MiB each).
    #[serde(default)]
    pub inputs: Vec<EmulateInput>,
    /// Seconds to wait (default 60, at most 300).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    /// Give the program a virtual display (Xvfb) so a windowed program starts; needs `Xvfb` on
    /// the PATH (default false).
    #[serde(default)]
    pub windowed: bool,
    /// Return the files the program wrote (default false; the names are always in `notes`).
    #[serde(default)]
    pub return_files: bool,
}

/// Result of `wine_run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WineRunOut {
    /// How it ended: the program's exit code, a signal, or a timeout.
    pub exit: EmulateExit,
    /// Standard output (first 4000 characters). Program data, so untrusted.
    pub stdout: Untrusted<String>,
    /// Standard error (first 4000 characters). Untrusted.
    pub stderr: Untrusted<String>,
    /// True when `stdout` or `stderr` was cut.
    pub truncated: bool,
    /// The Wine that ran and how the run was confined.
    pub wine: String,
    /// Facts about the run: confinement, files written.
    pub notes: Vec<String>,
    /// The files the program wrote, when `return_files` was set.
    #[serde(default)]
    pub files: Vec<EmulateFile>,
}

/// What every Wine run of one call shares.
#[derive(Debug, Clone)]
pub(super) struct WineParams {
    stdin: Vec<u8>,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    inputs: Vec<(PathBuf, Vec<u8>)>,
    timeout: Duration,
    windowed: bool,
}

fn check_args(
    stdin: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    timeout: Option<u64>,
) -> Result<Duration, ProtoError> {
    let seconds = timeout.unwrap_or(DEFAULT_TIMEOUT);
    if seconds == 0 || seconds > MAX_TIMEOUT {
        return Err(invalid(format!(
            "timeout_seconds must be between 1 and {MAX_TIMEOUT}"
        )));
    }
    if stdin.len() > MAX_STDIN_BYTES {
        return Err(invalid(format!(
            "stdin is longer than {MAX_STDIN_BYTES} bytes"
        )));
    }
    if argv.len() > MAX_ARGS
        || argv
            .iter()
            .any(|a| a.len() > MAX_ARG_BYTES || a.contains('\0'))
    {
        return Err(invalid(format!(
            "at most {MAX_ARGS} arguments, each without NUL and under {MAX_ARG_BYTES} bytes"
        )));
    }
    if env.len() > MAX_ENV
        || env.iter().any(|(k, v)| {
            k.is_empty()
                || k.contains(['=', '\0'])
                || v.contains('\0')
                || k.len() > MAX_ARG_BYTES
                || v.len() > MAX_ARG_BYTES
        })
    {
        return Err(invalid("env: too many entries, or a bad name or value"));
    }
    Ok(Duration::from_secs(seconds))
}

impl WineParams {
    fn from_run(a: &WineRunArgs) -> Result<Self, ProtoError> {
        let timeout = check_args(&a.stdin, &a.argv, &a.env, a.timeout_seconds)?;
        Ok(Self {
            stdin: a.stdin.clone().into_bytes(),
            argv: a.argv.clone(),
            env: a.env.clone(),
            inputs: decode_inputs(&a.inputs)?,
            timeout,
            windowed: a.windowed,
        })
    }

    /// The parameters of a comparison, from the emulator-shaped base arguments.
    pub(super) fn from_compare(
        base: &EmulateRunArgs,
        timeout: Option<u64>,
    ) -> Result<Self, ProtoError> {
        let timeout = check_args(&base.stdin, &base.argv, &base.env, timeout)?;
        Ok(Self {
            stdin: base.stdin.clone().into_bytes(),
            argv: base.argv.clone(),
            env: base.env.clone(),
            inputs: decode_inputs(&base.inputs)?,
            timeout,
            windowed: false,
        })
    }
}

/// The catalogue's Wine, or why there is none.
pub(super) async fn wine_spec(s: &Session) -> Result<LaunchSpec, ProtoError> {
    let backend = s.integrations()?.clone();
    blocking(move || {
        backend.launch_spec("wine").map_err(|e| {
            ProtoError::new(
                e.code,
                format!(
                    "Wine is not available ({}): use the wine entry of the integrations catalogue \
                     (\"Use existing\" or \"Install for me\")",
                    e.message
                ),
            )
        })
    })
    .await
}

/// Runs a Windows program under Wine in a sandbox.
pub struct WineRun;

#[async_trait]
impl Command for WineRun {
    type Args = WineRunArgs;
    type Output = WineRunOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "wine_run",
            "Run the project's Windows program (original or patched) under Wine in a sandbox and return its output",
            CommandKind::Query,
            Permission::Dangerous,
        )
        .doc(
            "Runs the project's PE executable, a copy with its byte patches, or any file you \
             name, under the Wine of the integrations catalogue (`integrations_list`, entry \
             `wine`), and returns how it ended (`exit`), `stdout`, `stderr` and the files it \
             wrote. Every run uses a fresh Wine prefix in a private directory with no host home, \
             no network and a read-only view of the system, so the program can write only there; \
             the directory is removed afterwards. DLLs next to the program are copied beside it. \
             Always asks first: Wine runs the program for real, not in KRAKEN's emulator.\n\
             Example: wine_run {\"target\": \"patched\", \"stdin\": \"hello\\n\", \"argv\": [\"/v\"], \"return_files\": true}",
        )
        .details(
            "The sandbox is `kraken-confine`: Landlock (ABI 4 or newer) and a network namespace \
             or seccomp filter; without them the command refuses to run. WINEDEBUG is off, \
             winemenubuilder, Mono and Gecko are disabled, and the prefix is not kept, so a \
             run starts with several seconds of prefix creation. `windowed: true` starts Xvfb \
             inside the same sandbox when it is installed. Output is program data and so \
             untrusted. Compare the original with a patched build with `emulate_compare` or \
             `patch_verify` and `runtime: wine`.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: WineRunArgs,
    ) -> Result<WineRunOut, ProtoError> {
        let params = WineParams::from_run(&args)?;
        let spec = wine_spec(s).await?;
        let (file, patches, base) = match args.target {
            RunTarget::File => {
                let f = args
                    .file
                    .clone()
                    .ok_or_else(|| invalid("target `file` needs `file`"))?;
                (PathBuf::from(f), Vec::new(), 0)
            }
            RunTarget::Original | RunTarget::Patched => {
                let project = s.project()?;
                let binary = PathBuf::from(project.meta().binary_path);
                let patches = if args.target == RunTarget::Patched {
                    project.with_store(|st| st.active_patches(None)).await?
                } else {
                    Vec::new()
                };
                (binary, patches, project.program().base.0)
            }
        };
        if !file.is_absolute() {
            return Err(invalid("file must be an absolute path"));
        }
        let return_files = args.return_files;
        let inputs = args.inputs.clone();
        blocking(move || {
            let mut note = None;
            let patched_bytes = if args.target == RunTarget::Patched {
                if patches.is_empty() {
                    note = Some("the project has no byte patches; ran the original".to_string());
                    None
                } else {
                    let (b, _) = crate::patchfile::apply_project_patches(&file, &patches, base)?;
                    Some(b)
                }
            } else {
                None
            };
            let mut raw = run_wine_bytes(&spec, &file, patched_bytes.as_deref(), &params)?;
            raw.notes.extend(note);
            Ok(present_wine(raw, &spec, return_files, &inputs))
        })
        .await
    }
}

fn present_wine(
    raw: RawRun,
    spec: &LaunchSpec,
    return_files: bool,
    inputs: &[EmulateInput],
) -> WineRunOut {
    let out = present(raw, return_files, inputs);
    WineRunOut {
        exit: out.exit,
        stdout: out.stdout,
        stderr: out.stderr,
        truncated: out.truncated,
        wine: spec.exe.display().to_string(),
        notes: out
            .notes
            .into_iter()
            .filter(|n| !n.starts_with("architecture "))
            .collect(),
        files: out.files,
    }
}

fn hash_of(data: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    h.finish()
}

fn internal(msg: impl Into<String>) -> ProtoError {
    problem(ErrorCode::Internal, msg)
}

/// The directory a portable or distro Wine lives in (`<root>/bin/wine`), unless that is a system
/// directory the sandbox already lets the child read.
fn wine_root(exe: &Path) -> Option<PathBuf> {
    let real = exe.canonicalize().ok()?;
    let root = real.parent()?.parent()?.to_path_buf();
    (root.components().count() >= 3 && !root.starts_with("/usr")).then_some(root)
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// The shell script that runs a program under a private virtual display.
const XVFB_SCRIPT: &str = "xvfb=$1; shift\n\
    \"$xvfb\" :99 -nolisten tcp -nolock -screen 0 1280x800x24 >/dev/null 2>&1 &\n\
    x=$!\n\
    sleep 1\n\
    DISPLAY=:99 \"$@\"\n\
    rc=$?\n\
    kill $x 2>/dev/null\n\
    exit $rc\n";

/// One confined Wine run of `target` (or of `bytes`, staged under the target's file name).
pub(super) fn run_wine_bytes(
    spec: &LaunchSpec,
    target: &Path,
    bytes: Option<&[u8]>,
    p: &WineParams,
) -> Result<RawRun, ProtoError> {
    if !target.is_file() {
        return Err(problem(
            ErrorCode::NotFound,
            format!("{} is not a file", target.display()),
        ));
    }
    let scratch = kraken_confine::scratch_dir("kraken-wine-")
        .map_err(|e| problem(ErrorCode::Unsupported, e.to_string()))?;
    let root = scratch.path();
    let (prefix, work, home) = (root.join("prefix"), root.join("work"), root.join("home"));
    for d in [&prefix, &work, &home] {
        std::fs::create_dir_all(d).map_err(|e| internal(format!("scratch directory: {e}")))?;
    }
    let mut notes = Vec::new();
    let mut staged: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut stage = |name: &str, data: &[u8]| -> Result<(), ProtoError> {
        let path = work.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| internal(format!("staging {name}: {e}")))?;
        }
        std::fs::write(&path, data).map_err(|e| internal(format!("staging {name}: {e}")))?;
        staged.insert(name.to_string(), (data.len() as u64, hash_of(data)));
        Ok(())
    };
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && !n.contains(['\0', '/']))
        .unwrap_or("program.exe");
    let exe_name = if file_name.to_ascii_lowercase().ends_with(".exe") {
        file_name.to_string()
    } else {
        format!("{file_name}.exe")
    };
    let exe_bytes = match bytes {
        Some(b) => b.to_vec(),
        None => std::fs::read(target).map_err(|e| {
            problem(
                ErrorCode::NotFound,
                format!("cannot read {}: {e}", target.display()),
            )
        })?,
    };
    stage(&exe_name, &exe_bytes)?;
    if let Some(dir) = target.parent()
        && let Ok(rd) = std::fs::read_dir(dir)
    {
        let mut copied = 0;
        let mut names: Vec<_> = rd.flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let name = e.file_name().to_string_lossy().into_owned();
            let lower = name.to_ascii_lowercase();
            let ok = lower.ends_with(".dll")
                && lower != exe_name.to_ascii_lowercase()
                && e.metadata()
                    .is_ok_and(|m| m.is_file() && m.len() <= MAX_SIBLING_BYTES);
            if ok
                && copied < MAX_SIBLINGS
                && let Ok(d) = std::fs::read(e.path())
            {
                stage(&name, &d)?;
                copied += 1;
            }
        }
        if copied > 0 {
            notes.push(format!(
                "copied {copied} DLL(s) from the program's directory"
            ));
        }
    }
    for (rel, data) in &p.inputs {
        stage(&rel.to_string_lossy(), data)?;
    }

    let xvfb = if p.windowed {
        find_on_path("Xvfb")
    } else {
        None
    };
    if p.windowed && xvfb.is_none() {
        notes.push("windowed was asked for but Xvfb is not on the PATH; no display".into());
    }
    let mut cmd = match &xvfb {
        Some(x) => {
            let mut c = std::process::Command::new("/bin/sh");
            c.args(["-c", XVFB_SCRIPT, "sh"]).arg(x).arg(&spec.exe);
            c
        }
        None => std::process::Command::new(&spec.exe),
    };
    cmd.arg(&exe_name).args(&p.argv);
    let mut confinement = Confinement {
        deny_exec_in_dir: true,
        open_files: Some(4096),
        limits: Some(Limits {
            address_space: u64::MAX,
            cpu_seconds: p.timeout.as_secs() + 60,
            file_size: 512 << 20,
            processes: u64::MAX,
        }),
        ..Confinement::default()
    };
    let fonts = PathBuf::from("/etc/fonts");
    if fonts.is_dir() {
        confinement.extra_read_paths.push(fonts);
    }
    if let Some(r) = wine_root(&spec.exe) {
        confinement.exec_read_paths.push(r);
    }
    if let Some(x) = &xvfb
        && let Some(r) = wine_root(x)
    {
        confinement.exec_read_paths.push(r);
    }
    let server = WineServerDir::create(&prefix)?;
    confinement.extra_write_paths.push(server.path.clone());
    let report = kraken_confine::confine(&mut cmd, root, ReadScope::Toolchain, &confinement)
        .map_err(|e| {
            problem(
                ErrorCode::Unsupported,
                format!("Wine runs only inside the sandbox, which is not available: {e}"),
            )
        })?;
    // The whole scratch root is writable (prefix and home beside the work directory); the
    // program starts in `work`.
    cmd.current_dir(&work)
        .env("TMPDIR", root)
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("WINEPREFIX", &prefix)
        .env("WINEDEBUG", "-all")
        .env("WINEDLLOVERRIDES", "mscoree,mshtml,winemenubuilder.exe=d")
        .env("LANG", "C");
    for (k, v) in &p.env {
        cmd.env(k, v);
    }
    let started = std::time::Instant::now();
    let captured = kraken_confine::run_captured_with_input(
        &mut cmd,
        (!p.stdin.is_empty()).then(|| p.stdin.clone()),
        p.timeout,
        STREAM_CAP,
        Duration::from_millis(50),
    )
    .map_err(|e| {
        problem(
            ErrorCode::Unsupported,
            format!("cannot start {}: {e}", spec.exe.display()),
        )
    })?;
    let exit = match captured.status {
        None => Exit::Timeout,
        Some(s) => match s.code() {
            Some(code) => Exit::Code { code },
            None => Exit::Signal {
                signal: signal_of(&s),
                detail: "ended by a signal".into(),
            },
        },
    };
    stop_prefix_processes(&prefix);
    let files = collect_files(&work, &staged);
    notes.push(format!(
        "ran under Wine in a fresh prefix, confined ({}), {:.1}s",
        report.label(),
        started.elapsed().as_secs_f64()
    ));
    Ok(RawRun {
        outcome: ProgramOutcome {
            arch: Arch::X86_64,
            exit,
            stdout: captured.stdout,
            stderr: strip_noise(&captured.stderr),
            instructions: 0,
            elapsed_ms: started.elapsed().as_millis() as u64,
            setup_ms: 0,
            files,
            syscalls: BTreeMap::new(),
            unknown_syscalls: Vec::new(),
            notes: Vec::new(),
        },
        notes,
    })
}

#[cfg(unix)]
fn signal_of(s: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.signal().unwrap_or(0)
}

#[cfg(not(unix))]
fn signal_of(_: &std::process::ExitStatus) -> i32 {
    0
}

/// The directory Wine's server keeps its socket in. Wine hardcodes it as
/// `/tmp/.wine-<uid>/server-<dev>-<inode of the prefix>`, so the sandbox is given write access to
/// exactly that one directory (made here, removed after the run) and not to the parent, where
/// the sockets of the user's own Wine prefixes live.
struct WineServerDir {
    path: PathBuf,
}

#[cfg(unix)]
impl WineServerDir {
    fn create(prefix: &Path) -> Result<Self, ProtoError> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let meta = std::fs::metadata(prefix).map_err(|e| internal(format!("prefix: {e}")))?;
        // SAFETY: geteuid takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let parent = PathBuf::from(format!("/tmp/.wine-{uid}"));
        let mut b = std::fs::DirBuilder::new();
        b.mode(0o700);
        let _ = b.create(&parent);
        let pm = std::fs::symlink_metadata(&parent)
            .map_err(|e| problem(ErrorCode::Unsupported, format!("{}: {e}", parent.display())))?;
        if !pm.is_dir() || pm.uid() != uid || pm.mode() & 0o077 != 0 {
            return Err(problem(
                ErrorCode::Unsupported,
                format!(
                    "{} is not a private directory of yours; Wine needs it",
                    parent.display()
                ),
            ));
        }
        let path = parent.join(format!("server-{:x}-{:x}", meta.dev(), meta.ino()));
        let _ = b.create(&path);
        let ok = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && m.uid() == uid);
        if !ok {
            return Err(problem(
                ErrorCode::Unsupported,
                format!("cannot make {}", path.display()),
            ));
        }
        Ok(Self { path })
    }
}

#[cfg(not(unix))]
impl WineServerDir {
    fn create(_: &Path) -> Result<Self, ProtoError> {
        Err(problem(ErrorCode::Unsupported, "wine_run needs Linux"))
    }
}

impl Drop for WineServerDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// Kills what is left of the run: `wineserver` and `winedevice.exe` leave the process group
/// the run was started in and would otherwise stay until their idle timeout. They are found by
/// the `WINEPREFIX` of their environment, which is unique to this run.
#[cfg(target_os = "linux")]
fn stop_prefix_processes(prefix: &Path) {
    let want = format!("WINEPREFIX={}", prefix.display()).into_bytes();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return;
    };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(env) = std::fs::read(e.path().join("environ")) else {
            continue;
        };
        if env.split(|b| *b == 0).any(|v| v == want.as_slice()) {
            // SAFETY: plain kill(2) of a process of this user whose environment names our prefix.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }
    // Let the kernel reap them before the directories go.
    std::thread::sleep(Duration::from_millis(100));
}

#[cfg(not(target_os = "linux"))]
fn stop_prefix_processes(_: &Path) {}

fn strip_noise(stderr: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(stderr);
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if !NOISE.iter().any(|n| line.starts_with(n)) {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

/// The files left in `work` that the run created or changed, by relative path.
fn collect_files(work: &Path, staged: &BTreeMap<String, (u64, u64)>) -> Vec<WrittenFile> {
    let mut out = Vec::new();
    let mut stack = vec![(work.to_path_buf(), 0usize)];
    let mut seen = 0;
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            seen += 1;
            if seen > MAX_SCAN || out.len() >= MAX_FILES {
                return out;
            }
            let Ok(ty) = e.file_type() else { continue };
            if ty.is_dir() && depth < 4 {
                stack.push((e.path(), depth + 1));
            } else if ty.is_file() {
                let Ok(rel) = e.path().strip_prefix(work).map(Path::to_path_buf) else {
                    continue;
                };
                let name = rel.to_string_lossy().into_owned();
                let size = e.metadata().map_or(0, |m| m.len());
                let mut data = Vec::new();
                if let Ok(f) = std::fs::File::open(e.path()) {
                    let _ = f.take(MAX_FILE_READ).read_to_end(&mut data);
                }
                let unchanged = staged
                    .get(&name)
                    .is_some_and(|(len, h)| *len == size && *h == hash_of(&data));
                if !unchanged {
                    out.push(WrittenFile { name, size, data });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_is_dropped_and_other_lines_stay() {
        let s = strip_noise(b"wine: created the configuration directory 'x'\nreal error\n");
        assert_eq!(s, b"real error\n");
    }

    #[test]
    fn bounds_are_checked_before_anything_runs() {
        let env = BTreeMap::new();
        assert!(check_args("", &[], &env, Some(0)).is_err());
        assert!(check_args("", &[], &env, Some(301)).is_err());
        assert!(check_args("", &["a\0".into()], &env, None).is_err());
        assert_eq!(
            check_args("", &[], &env, None).ok(),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn a_system_wine_needs_no_extra_read_path() {
        assert_eq!(wine_root(Path::new("/usr/bin/wine")), None);
    }
}

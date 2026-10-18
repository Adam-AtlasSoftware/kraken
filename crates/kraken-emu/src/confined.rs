//! Whole-program emulation inside the sandbox child, for the daemon.
//!
//! Emulation is already a confinement of its own: the guest's instructions are interpreted and
//! every system call is answered by [`crate::linux`], which reaches only the private working
//! directory and the read-only sysroot. Running it in `kraken-emu-run` under kraken-sidecar's
//! spawner adds the usual second layer (Landlock: the program, the sysroot and the SLEIGH specs
//! read-only, the working directory read-write; seccomp without sockets; a network namespace
//! when the host allows one; a scrubbed environment; parent-death signal), so a bug in the
//! emulator or the syscall layer still cannot reach the rest of the host.
//!
//! Protocol over the child's socketpair: one request and one reply, each an 8-byte
//! little-endian length followed by JSON ([`RunSpec`] in, `Result<ProgramOutcome, String>` out).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kraken_sidecar::{ConfinementOptions, ConfinementReport, LogSink, SpawnSpec};

use crate::arch::Arch;
use crate::error::EmuError;
use crate::linux::{ProgramOutcome, RunSpec};
use crate::specs::SpecRoots;

/// The runner's file name.
pub const RUNNER: &str = "kraken-emu-run";
/// Largest message accepted.
const MAX_MESSAGE: u64 = 256 << 20;

/// Writes one framed message.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    w.write_all(&(body.len() as u64).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Reads one framed message.
pub fn read_message(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 8];
    r.read_exact(&mut len)?;
    let n = u64::from_le_bytes(len);
    if n > MAX_MESSAGE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }
    let mut body = vec![0u8; n as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Finds `kraken-emu-run`: `KRAKEN_EMU_RUN`, next to the current executable, or one directory up
/// (test binaries live in `target/<profile>/deps`).
pub fn find_runner() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_RUN").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [dir.join(RUNNER), dir.parent()?.join(RUNNER)]
        .into_iter()
        .find(|p| p.is_file())
}

/// Runs `spec` in the confined runner. `spec.workdir` must be set (it becomes the child's only
/// writable directory); the SLEIGH spec root is resolved here and passed on, since the child
/// sees no environment.
pub fn run_program_confined(
    spec: &RunSpec,
    runner: &Path,
    options: ConfinementOptions,
) -> Result<(ProgramOutcome, ConfinementReport), EmuError> {
    let workdir = spec
        .workdir
        .clone()
        .ok_or_else(|| EmuError::Io("a confined run needs RunSpec::workdir".into()))?;
    let head = {
        let mut f = std::fs::File::open(&spec.program)
            .map_err(|e| EmuError::Image(format!("{}: {e}", spec.program.display())))?;
        let mut b = vec![0u8; 64];
        let n = f.read(&mut b).map_err(|e| EmuError::Image(e.to_string()))?;
        b.truncate(n);
        b
    };
    let arch = Arch::from_elf(&head)?;
    let processors =
        SpecRoots::discover_with(spec.spec_roots.iter().cloned()).processors_for(arch)?;
    let root = processors
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| EmuError::Io("spec root has no parent".into()))?
        .to_path_buf();
    let mut child_spec = spec.clone();
    child_spec.spec_roots = vec![root];

    let mut read_only = vec![
        runner.to_path_buf(),
        spec.program.clone(),
        processors.clone(),
    ];
    if let Some(s) = &spec.sysroot {
        read_only.push(s.clone());
    }
    let sp = SpawnSpec {
        program: runner.to_path_buf(),
        args: Vec::new(),
        env: Vec::new(),
        cwd: workdir.clone(),
        read_only,
        optional_read_only: Vec::new(),
        proc_self_read: false,
        read_write: vec![workdir],
        options,
    };
    let log = LogSink::with_capacity(200);
    let (sandbox, mut sock) = kraken_sidecar::sandbox::Sandbox::spawn(sp, &log)
        .map_err(|e| EmuError::Io(format!("starting {RUNNER}: {e}")))?;
    let report = sandbox.report().clone();
    let body = serde_json::to_vec(&child_spec).map_err(|e| EmuError::Io(e.to_string()))?;
    write_message(&mut sock, &body).map_err(|e| EmuError::Io(format!("to {RUNNER}: {e}")))?;
    // The child enforces the run's own limits; this only catches a runner that hangs.
    let deadline =
        Instant::now() + Duration::from_millis(spec.timeout_ms) + Duration::from_secs(60);
    sock.set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|e| EmuError::Io(e.to_string()))?;
    let reply = read_message(&mut sock);
    drop(sandbox);
    let reply = reply.map_err(|e| {
        EmuError::Io(format!(
            "no answer from {RUNNER} ({e}); its log: {}",
            log.tail(20).join(" | ")
        ))
    })?;
    let result: Result<ProgramOutcome, String> =
        serde_json::from_slice(&reply).map_err(|e| EmuError::Io(format!("{RUNNER} reply: {e}")))?;
    result.map(|o| (o, report)).map_err(EmuError::Emulator)
}

/// The runner's side: read the request from the socket on fd 0, run, answer.
pub fn serve(sock: &mut UnixStream) -> Result<(), String> {
    let req = read_message(sock).map_err(|e| format!("request: {e}"))?;
    let spec: RunSpec = serde_json::from_slice(&req).map_err(|e| format!("request: {e}"))?;
    let result: Result<ProgramOutcome, String> =
        crate::linux::run_program(&spec).map_err(|e| e.to_string());
    let body = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
    write_message(sock, &body).map_err(|e| format!("reply: {e}"))
}

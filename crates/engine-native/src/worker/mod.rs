//! The confined worker process (ADR 0014, phase 3).
//!
//! With [`Isolation::Worker`] the decompiler, Sleigh and the whole loaded program live in a
//! child process, `kraken-native-worker`, started through `kraken-sidecar`'s confined spawner
//! (scrubbed environment, Landlock, the seccomp socket filter, a network namespace, parent-death
//! signal) and spoken to over the sidecar framing (length-prefixed JSON-RPC on the socketpair
//! that is the child's stdin). The worker runs an [`crate::InProcessEngine`] and answers one
//! method per capability call.
//!
//! The parent side ([`client`]) is a watchdog: every request has a hard deadline, past which the
//! worker is killed and the request fails with a structured `timeout`; a worker that dies fails
//! its requests with a structured `internal` error. Either way the next request starts a new
//! worker, which re-opens the program (replaying the `native-state.json` of the state
//! directory) and then replays the edit-log operations and type definitions the worker had
//! accepted but not yet saved.
//!
//! Only Unix has the worker; elsewhere [`Isolation::Worker`] runs in-process.

// the wire helpers are only used by the Unix client and server
#![cfg_attr(not(unix), allow(dead_code))]

use std::path::PathBuf;
use std::time::Duration;

use kraken_proto::{ErrorCode, ProtoError};
use kraken_sidecar::ConfinementOptions;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[cfg(unix)]
pub(crate) mod client;
#[cfg(unix)]
pub mod serve;

/// Name of the worker executable.
pub const WORKER_BIN: &str = "kraken-native-worker";
/// Environment variable naming the worker executable (overrides the lookup next to the current
/// executable).
pub const WORKER_ENV: &str = "KRAKEN_NATIVE_WORKER";
/// Argument that enables the test-only methods of the worker (`test_hang`, `test_crash`,
/// `test_probe`).
pub const TEST_HOOKS_ARG: &str = "--test-hooks";
/// Argument that keeps the worker dumpable, so a crash leaves a core dump.
pub const CORE_DUMPS_ARG: &str = "--core-dumps";

/// Where the native engine runs the decompiler.
#[derive(Debug, Clone)]
pub enum Isolation {
    /// In a confined `kraken-native-worker` child under a watchdog (the default).
    Worker(WorkerOptions),
    /// In the calling process. A decompiler crash takes the process down and the decompile limit
    /// is only cooperative; for tests and for hosts without the worker binary.
    InProcess,
}

impl Default for Isolation {
    fn default() -> Self {
        Isolation::Worker(WorkerOptions::default())
    }
}

/// How the worker is started and watched.
#[derive(Debug, Clone)]
pub struct WorkerOptions {
    /// The worker executable; `None` looks at `KRAKEN_NATIVE_WORKER`, then next to the current
    /// executable and in its parent directory (where cargo puts binaries for test executables).
    pub program: Option<PathBuf>,
    /// Confinement policy (Landlock, seccomp and the network namespace are required unless
    /// `allow_unconfined` is set).
    pub confinement: ConfinementOptions,
    /// Hard deadline for a request other than opening and decompiling, and for the gap between
    /// two progress events of an analysis job.
    pub request_timeout: Duration,
    /// Hard deadline for opening a program (loading and discovery; static binaries take seconds).
    pub open_timeout: Duration,
    /// Added to the cooperative decompile limit to get the hard deadline of a decompile. Without
    /// a decompile limit the decompile gets `request_timeout`.
    pub decompile_grace: Duration,
    /// How long a cancelled request may take to stop in the worker before the worker is killed.
    pub cancel_grace: Duration,
    /// Directory for the worker's private home; the system temp dir when `None`.
    pub temp_root: Option<PathBuf>,
    /// Let a crashing worker dump core. Off by default: the worker marks itself non-dumpable,
    /// because writing a core (through `systemd-coredump`, say) keeps the dying process and its
    /// channel open for seconds, which turns a crash into a watchdog timeout.
    pub core_dumps: bool,
    /// Enable the worker's test-only methods.
    pub test_hooks: bool,
}

impl Default for WorkerOptions {
    fn default() -> Self {
        WorkerOptions {
            program: None,
            confinement: ConfinementOptions::default(),
            request_timeout: Duration::from_secs(60),
            open_timeout: Duration::from_secs(600),
            decompile_grace: Duration::from_secs(5),
            cancel_grace: Duration::from_secs(2),
            temp_root: None,
            core_dumps: false,
            test_hooks: false,
        }
    }
}

impl WorkerOptions {
    /// Default options with an explicit worker executable.
    pub fn with_program(program: impl Into<PathBuf>) -> WorkerOptions {
        WorkerOptions {
            program: Some(program.into()),
            ..WorkerOptions::default()
        }
    }

    /// The worker executable to start.
    pub fn locate(&self) -> Result<PathBuf, ProtoError> {
        let given = self
            .program
            .clone()
            .or_else(|| std::env::var_os(WORKER_ENV).map(PathBuf::from));
        if let Some(p) = given {
            return if p.is_file() {
                Ok(p)
            } else {
                Err(ProtoError::new(
                    ErrorCode::Unsupported,
                    format!("the native engine worker {} does not exist", p.display()),
                ))
            };
        }
        let exe = std::env::current_exe().map_err(|e| {
            ProtoError::new(
                ErrorCode::Internal,
                format!("cannot find the current executable: {e}"),
            )
        })?;
        let name = format!("{WORKER_BIN}{}", std::env::consts::EXE_SUFFIX);
        let dir = exe.parent();
        dir.into_iter()
            .chain(dir.and_then(|d| d.parent()))
            .map(|d| d.join(&name))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::Unsupported,
                    format!(
                        "the native engine worker `{name}` was not found next to {} (set \
                         {WORKER_ENV} or use Isolation::InProcess)",
                        exe.display()
                    ),
                )
            })
    }
}

/// Parameters of the worker's `open` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OpenParams {
    pub path: PathBuf,
    pub spec: kraken_engine::LoaderSpec,
    pub spec_root: PathBuf,
    pub use_symbols: bool,
    pub decompile_timeout_ms: Option<u64>,
    /// [`crate::NativeConfig::state_dir`]: the one directory the worker may write besides its
    /// home; opening replays the `native-state.json` saved there.
    pub state_dir: Option<PathBuf>,
    /// [`crate::NativeConfig::discovery_threads`], decided by the parent.
    #[serde(default)]
    pub threads: Option<usize>,
}

/// [`engine_native_sys::Varnode`] on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WireVarnode {
    pub space: String,
    pub offset: u64,
    pub size: u32,
}

/// [`engine_native_sys::PcodeOp`] on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WirePcodeOp {
    pub addr: u64,
    pub seq: u32,
    pub opcode: String,
    pub output: Option<WireVarnode>,
    pub inputs: Vec<WireVarnode>,
}

impl From<engine_native_sys::PcodeOp> for WirePcodeOp {
    fn from(op: engine_native_sys::PcodeOp) -> Self {
        let v = |v: engine_native_sys::Varnode| WireVarnode {
            space: v.space,
            offset: v.offset,
            size: v.size,
        };
        WirePcodeOp {
            addr: op.addr,
            seq: op.seq,
            opcode: op.opcode,
            output: op.output.map(v),
            inputs: op.inputs.into_iter().map(v).collect(),
        }
    }
}

impl From<WirePcodeOp> for engine_native_sys::PcodeOp {
    fn from(op: WirePcodeOp) -> Self {
        let v = |v: WireVarnode| engine_native_sys::Varnode {
            space: v.space,
            offset: v.offset,
            size: v.size,
        };
        engine_native_sys::PcodeOp {
            addr: op.addr,
            seq: op.seq,
            opcode: op.opcode,
            output: op.output.map(v),
            inputs: op.inputs.into_iter().map(v).collect(),
        }
    }
}

/// A [`ProtoError`] as a JSON-RPC error object (`kraken_sidecar::rpc::map_rpc_error` reads it
/// back).
pub(crate) fn rpc_error(e: &ProtoError) -> Value {
    let mut data = json!({ "code": e.code.as_str() });
    if let Some(d) = &e.details {
        data["details"] = d.clone();
    }
    json!({ "code": -32000, "message": e.message, "data": data })
}

pub(crate) fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

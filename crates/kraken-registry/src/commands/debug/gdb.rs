//! `debug_gdb_serve`: a debug session as a GDB remote target.
//!
//! The server thread listens on a Unix socket in a private (mode 0700) directory and optionally on
//! a loopback TCP port, and serves one client at a time through `kraken_emu::gdbserve`. It holds
//! the session weakly: closing the session ends the server and removes the socket.

use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use gdbstub::conn::ConnectionExt;
use kraken_emu::EmuError;
use kraken_emu::arch::Arch;
use kraken_emu::confined::{DebugReply, DebugRequest};
use kraken_emu::gdbserve::{DebugLink, serve_connection};
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{Live, lock, session_arg};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::commands::emulate::problem;
use crate::context::CallContext;
use crate::session::{Session, blocking};

/// A running server; dropping it stops the thread and removes the socket.
pub(super) struct GdbServer {
    stop: Arc<AtomicBool>,
    _dir: tempfile::TempDir,
    pub(super) socket: PathBuf,
    pub(super) tcp_port: Option<u16>,
}

impl Drop for GdbServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

struct Link(Weak<Mutex<Live>>);

impl DebugLink for Link {
    fn request(&mut self, req: &DebugRequest) -> Result<DebugReply, EmuError> {
        let live = self
            .0
            .upgrade()
            .ok_or_else(|| EmuError::Io("the debug session has ended".into()))?;
        let mut live = lock(&live);
        live.last_used = Instant::now();
        let reply = live.child.request(req)?;
        if let DebugReply::Stop { stop, state } = &reply {
            live.last_stop = Some(super::present_stop(stop, state, &live));
        }
        Ok(reply)
    }
}

enum Listener {
    Unix(UnixListener),
    Tcp(TcpListener),
}

type Conn = Box<dyn ConnectionExt<Error = std::io::Error>>;

impl Listener {
    fn accept(&self) -> std::io::Result<Conn> {
        Ok(match self {
            Listener::Unix(l) => Box::new(l.accept()?.0),
            Listener::Tcp(l) => {
                let s = l.accept()?.0;
                s.set_nodelay(true)?;
                Box::new(s)
            }
        })
    }
}

fn run_server(
    live: Weak<Mutex<Live>>,
    arch: Arch,
    listeners: Vec<Listener>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) && live.strong_count() > 0 {
        let mut idle = true;
        for l in &listeners {
            if let Ok(conn) = l.accept() {
                idle = false;
                // A client that goes away is not an error; the next one finds the session where
                // the last left it.
                let _ = serve_connection(Link(live.clone()), arch, conn);
            }
        }
        if idle {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn internal(what: &str, e: impl std::fmt::Display) -> ProtoError {
    problem(ErrorCode::Internal, format!("{what}: {e}"))
}

fn start_server(live: &Arc<Mutex<Live>>, tcp: bool) -> Result<GdbServer, ProtoError> {
    let arch_name = lock(live).arch.clone();
    let arch = Arch::from_name(&arch_name).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            format!("no gdb description for {arch_name}"),
        )
    })?;
    let base = ["KRAKEN_RUNTIME_DIR", "XDG_RUNTIME_DIR"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|p| p.is_dir());
    let mut b = tempfile::Builder::new();
    b.prefix("kraken-gdb-");
    let dir = match &base {
        Some(p) => b.tempdir_in(p),
        None => b.tempdir(),
    }
    .map_err(|e| internal("private directory", e))?;
    let socket = dir.path().join("gdb.sock");
    let unix = UnixListener::bind(&socket).map_err(|e| internal("socket", e))?;
    unix.set_nonblocking(true)
        .map_err(|e| internal("socket", e))?;
    let mut listeners = vec![Listener::Unix(unix)];
    let mut tcp_port = None;
    if tcp {
        let l = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| internal("loopback port", e))?;
        l.set_nonblocking(true)
            .map_err(|e| internal("loopback port", e))?;
        tcp_port = l.local_addr().ok().map(|a| a.port());
        listeners.push(Listener::Tcp(l));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (weak, flag) = (Arc::downgrade(live), stop.clone());
    std::thread::Builder::new()
        .name("kraken-gdb-serve".into())
        .spawn(move || run_server(weak, arch, listeners, flag))
        .map_err(|e| internal("server thread", e))?;
    Ok(GdbServer {
        stop,
        _dir: dir,
        socket,
        tcp_port,
    })
}

/// Arguments of `debug_gdb_serve`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DebugGdbServeArgs {
    /// The session.
    pub session: u64,
    /// Also listen on a loopback TCP port (127.0.0.1 only, never other interfaces).
    #[serde(default)]
    pub tcp: bool,
}

/// Result of `debug_gdb_serve`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DebugGdbServeOut {
    /// The session.
    pub session: u64,
    /// The architecture.
    pub arch: String,
    /// The Unix socket gdb connects to (in a private directory).
    pub socket: String,
    /// The loopback TCP port, when asked for.
    pub tcp_port: Option<u16>,
    /// A shell command that starts gdb and connects over the socket.
    pub gdb_command: String,
    /// The same over TCP, when asked for.
    pub gdb_tcp_command: Option<String>,
    /// Facts about the server (addresses are the emulator's, not the listing's).
    pub notes: Vec<String>,
}

/// Exposes a debug session over the GDB remote protocol.
pub struct DebugGdbServe;

#[async_trait]
impl Command for DebugGdbServe {
    type Args = DebugGdbServeArgs;
    type Output = DebugGdbServeOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "debug_gdb_serve",
            "Serve a debug session to gdb over the GDB remote protocol (Unix socket, optional loopback TCP)",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Lets gdb, Ghidra's debugger, IDA or lldb debug the emulated program: registers, \
             memory, breakpoints, step and continue. Returns the socket path and the gdb command \
             that connects (gdb reaches a Unix socket through socat; `tcp: true` needs no helper). One client at a time; leaving it keeps the session where it is. \
             `tcp: true` also listens on 127.0.0.1, without authentication (any local user can connect), so an agent needs approval for it.\n\
             Example: debug_gdb_serve {\"session\": 1}",
        )
        .details(
            "The socket is in a private directory (mode 0700, under KRAKEN_RUNTIME_DIR or XDG_RUNTIME_DIR when set) \
             and goes away with the session. Addresses seen by gdb are the emulator's: for a \
             position-independent program they differ from the listing's by `address_delta`. \
             Registers: the general purpose set, flags/cpsr and segment registers; x87 and \
             vector registers read as zero. Software breakpoints only; no watchpoints or reverse \
             execution. The `debug_*` commands keep working while a client is attached, but \
             mixing both on one session is confusing.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        a: DebugGdbServeArgs,
    ) -> Result<DebugGdbServeOut, ProtoError> {
        if a.tcp {
            // the loopback port has no authentication: any local user could drive the session
            ctx.require_approval(
                "debug_gdb_serve",
                format!(
                    "serve debug session {} to gdb on an unauthenticated 127.0.0.1 TCP port",
                    a.session
                ),
                serde_json::json!({"session": a.session, "tcp": true}),
            )
            .await?;
        }
        let table = s.debug().clone();
        blocking(move || {
            let id = session_arg(a.session)?;
            let live = table.get(id)?;
            let mut notes = vec![
                "addresses in gdb are the emulator's; add address_delta to a listing address \
                 for a position-independent program"
                    .to_string(),
            ];
            let (running, has_tcp) = {
                let l = lock(&live);
                (
                    l.gdb.is_some(),
                    l.gdb.as_ref().is_some_and(|g| g.tcp_port.is_some()),
                )
            };
            if !running || (a.tcp && !has_tcp) {
                lock(&live).gdb = None;
                let server = start_server(&live, a.tcp)?;
                lock(&live).gdb = Some(server);
            } else {
                notes.push("the server was already running".into());
            }
            let l = lock(&live);
            let g = l
                .gdb
                .as_ref()
                .ok_or_else(|| problem(ErrorCode::Internal, "no gdb server"))?;
            let socket = g.socket.display().to_string();
            Ok(DebugGdbServeOut {
                session: id,
                arch: l.arch.clone(),
                gdb_command: format!("gdb -ex 'target remote | socat - UNIX-CONNECT:{socket}'"),
                gdb_tcp_command: g
                    .tcp_port
                    .map(|p| format!("gdb -ex 'target remote 127.0.0.1:{p}'")),
                tcp_port: g.tcp_port,
                socket,
                notes,
            })
        })
        .await
    }
}

//! Transport and lifecycle building blocks for the `krakend` daemon.
//!
//! - [`paths`]: per-user runtime directory and well-known file names.
//! - [`token`], [`info`]: auth token and `daemon.json`.
//! - [`frame`], [`wire`]: 4-byte big-endian length framing carrying JSON-RPC 2.0, hello handshake.
//! - [`server`], [`client`]: async server generic over [`RpcHandler`], multiplexing client.
//! - [`lifecycle`]: [`DaemonGuard`] (daemon side) and [`ensure_daemon`] (client side).
//! - [`idle`]: [`IdleMonitor`] with an injectable [`Clock`].

pub mod client;
pub mod error;
pub mod frame;
pub mod idle;
pub mod info;
pub mod lifecycle;
pub mod paths;
pub mod server;
pub mod token;
pub mod transport;
pub mod wire;

pub use client::{Client, ClientError, ClientHello, Notification};
pub use error::IpcError;
pub use frame::{FrameError, MAX_FRAME_LEN, read_frame, write_frame};
pub use idle::{Clock, Counter, IdleMonitor, ManualClock, Shutdown, SystemClock};
pub use info::{DaemonInfo, pid_alive};
pub use lifecycle::{DaemonGuard, EnsureError, ensure_daemon};
pub use paths::{ENV_RUNTIME_DIR, RuntimeDir};
pub use server::{ConnInfo, Limits, Notifier, RpcHandler, Server, ServerConfig};
pub use wire::{ClientKind, CredentialClass, HelloParams, HelloResult, PROTOCOL_VERSION};

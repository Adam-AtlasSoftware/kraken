//! Generic plumbing shared by the confined engine sidecars (Ghidra JVM, .NET).
//!
//! - [`rpc`]: length-prefixed JSON-RPC framing and the multiplexing client (request ids,
//!   deadlines, notifications).
//! - [`sandbox`]: the confined spawner (scrubbed environment, Landlock, seccomp, network
//!   namespace, parent-death signal from a dedicated spawner thread; a job object on Windows),
//!   [`SpawnSpec`] and the [`ConfinementReport`].
//! - [`log`]: the bounded sink for the sidecar's output.
//!
//! What to start (command lines, path sets, handshakes) stays in the engine crates.

pub mod error;
pub mod log;
pub mod rpc;
pub mod sandbox;
#[cfg(all(unix, any(test, feature = "testing")))]
pub mod testutil;

pub use error::SidecarError;
pub use log::LogSink;
pub use rpc::RpcClient;
pub use sandbox::{ConfinementOptions, ConfinementReport, ExitInfo, SpawnSpec};

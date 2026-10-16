//! Hosting glue shared by the CLI, the MCP server and (next) the daemon.
//!
//! - [`config`]: `KrakenConfig`, read from `~/.config/kraken/config.toml` with environment
//!   overrides.
//! - [`paths`]: where projects live. Ghidra rejects project paths with a dot-prefixed element, so
//!   the default root is the first candidate without one (see [`paths::projects_root`]).
//! - [`factory`]: [`GhidraEngineFactory`], an `EngineFactory` over `engine-ghidra`, and the
//!   [`ManagedFactory`] trait that adds a clean shutdown.
//! - [`author`]: user and agent identities and run ids.
//! - [`convention`]: output conventions applied identically by every surface.

pub mod author;
pub mod backend;
pub mod config;
pub mod convention;
pub mod daemon;
pub mod factory;
pub mod paths;
pub mod provision;

pub use author::{RunIdGen, agent_id_from_client, user_id};
pub use config::{ConfigError, DaemonSettings, KrakenConfig};
pub use convention::finalize_output;
pub use factory::{
    EngineDiagnostics, EngineEvent, FactoryEvent, GhidraEngineFactory, ManagedFactory,
};
pub use paths::{check_ghidra_safe, default_project_dir, projects_root};

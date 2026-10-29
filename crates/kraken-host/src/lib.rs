//! Hosting glue shared by the CLI, the MCP server and (next) the daemon.
//!
//! - [`config`]: `KrakenConfig`, read from `~/.config/kraken/config.toml` with environment
//!   overrides.
//! - [`paths`]: where projects live. Ghidra rejects project paths with a dot-prefixed element, so
//!   the default root is the first candidate without one (see [`paths::projects_root`]).
//! - [`factory`]: [`GhidraEngineFactory`], an `EngineFactory` over `engine-ghidra`, and the
//!   [`ManagedFactory`] trait that adds a clean shutdown.
//! - [`HostEngineFactory`]: picks the engine per project (Ghidra, the native engine or `auto`;
//!   .NET for managed assemblies), see [`native`].
//! - [`author`]: user and agent identities and run ids.
//! - [`convention`]: output conventions applied identically by every surface.

pub mod author;
pub mod backend;
pub mod config;
pub mod convention;
pub mod daemon;
pub mod dotnet_setup;
pub mod factory;
pub mod infer;
pub mod integrations;
pub mod llama_setup;
pub mod local_models;
pub mod managed;
pub mod native;
pub mod paths;
pub mod provision;
pub mod setup;
pub mod strata_setup;

pub use author::{RunIdGen, agent_id_from_client, user_id};
pub use config::{
    ConfigError, DaemonSettings, DangerMode, KrakenConfig, LocalServingSettings, ShellConfig,
    TitlebarMode,
};
pub use convention::finalize_output;
pub use factory::{
    DotnetEngineFactory, EngineDiagnostics, EngineEvent, FactoryEvent, GhidraEngineFactory,
    HostEngineFactory, ManagedFactory, NativeEngineFactory,
};
pub use paths::{check_ghidra_safe, default_project_dir, projects_root};

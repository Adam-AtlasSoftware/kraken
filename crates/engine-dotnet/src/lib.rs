//! KRAKEN engine for managed (.NET) code: a second engine kind behind the existing capability
//! traits (decisions 3, 31, 54, 62). Spike scope.
//!
//! [`DotnetEngine`] opens an assembly in the `kraken-dotnet` C# sidecar (ILSpy's
//! `ICSharpCode.Decompiler` on a pinned .NET runtime), lists its methods as
//! [`kraken_proto::Locator::Managed`] locators, decompiles a method to C# with token references and
//! lists types read-only. It reuses `engine-ghidra`'s framing, RPC multiplexing and confined
//! spawner; a shared crate is the later cleanup.

pub mod engine;
pub mod error;
pub mod install;
mod launch;

pub use engine::{
    AssemblyInfo, Deadlines, Diagnostics, DotnetEngine, EngineConfig, LANGUAGE_CSHARP,
    REQUIRED_SIDECAR_CAPABILITIES,
};
pub use error::DotnetError;
pub use install::{DotnetInstall, ENV_DOTNET_ROOT, ENV_EXT_DLL, InstallConfig};

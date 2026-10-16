//! Errors of the rewrite pipeline.

use kraken_agent::AgentError;
use kraken_proto::ProtoError;

/// Why a rewrite step could not run. A wrong translation is not an error: it is a failed
/// verdict (see [`crate::difftest::Verdict`]).
#[derive(Debug, thiserror::Error)]
pub enum RewriteError {
    /// The ELF could not be read or is not x86-64.
    #[error("image: {0}")]
    Image(String),
    /// No SLEIGH processor specs were found, so the emulator cannot be built.
    #[error(
        "no SLEIGH processor specs found: set KRAKEN_GHIDRA_HOME to a Ghidra install (the oracle \
         compiles Ghidra/Processors/x86 at start-up), or run `kraken setup`"
    )]
    NoProcessors,
    /// The emulator could not be built or driven.
    #[error("emulator: {0}")]
    Emulator(String),
    /// The call description is outside what the oracle supports.
    #[error("unsupported call: {0}")]
    Unsupported(String),
    /// The Rust toolchain could not compile the translation or the runner.
    #[error("compile: {0}")]
    Compile(String),
    /// The native runner could not be started or its answer was malformed.
    #[error("native run: {0}")]
    Native(String),
    /// Reading or writing the unit store.
    #[error("store: {0}")]
    Store(String),
    /// The model output did not have the expected shape.
    #[error("model output: {0}")]
    Output(String),
    /// A registry command failed.
    #[error("{}", .0.message)]
    Command(ProtoError),
    /// The provider failed.
    #[error("provider: {0}")]
    Provider(#[from] AgentError),
}

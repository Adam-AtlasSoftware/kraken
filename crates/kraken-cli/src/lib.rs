//! The `kraken` command line.
//!
//! The clap command tree is built at runtime from [`Registry::standard`]: one subcommand per
//! command (`rename_symbol` becomes `rename-symbol`), with flags derived from the args JSON
//! Schema ([`schema`]). `--json` prints exactly the command's output JSON; the default output is
//! for people ([`render`]). Every invocation opens the project session, runs one command, saves
//! and shuts the Ghidra sidecar down (0.1a has no daemon).
//!
//! Exit codes: 0 ok, 2 invalid arguments, 3 not found, 4 conflict or rejected, 5 engine or
//! internal failure, 6 cancelled or timed out ([`exit_code`]).

mod app;
mod exit;
pub mod render;
pub mod schema;

pub use app::{CliAuthor, CliEnv, build_args, build_cli, run};
pub use exit::exit_code;

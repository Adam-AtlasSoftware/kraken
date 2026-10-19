//! The `kraken` command line.
//!
//! The clap command tree is built at runtime from [`Registry::standard`]: one subcommand per
//! command (`rename_symbol` becomes `rename-symbol`), with flags derived from the args JSON
//! Schema ([`schema`]). `--json` prints exactly the command's output JSON; the default output is
//! for people ([`render`]).
//!
//! Commands go through the `krakend` daemon by default ([`DaemonMode::Auto`]): the CLI connects to
//! the running daemon or starts it, and the daemon keeps projects and the Ghidra sidecar warm.
//! `--no-daemon` (or `KRAKEN_NO_DAEMON=1`) runs the command in this process instead (the 0.1a
//! behaviour: open the project session, run one command, save, shut the sidecar down); the output
//! is identical either way. If the daemon cannot be started the CLI warns and runs directly.
//! `kraken agents list|setup|run` hosts terminal agents over ACP (`kraken-acp`).
//! `kraken infer list|start|status|stop|logs|setup llama` runs a local model under the daemon
//! (`kraken-infer`, `docs/local-models.md`).
//! `kraken daemon status|stop|start` controls the daemon, `kraken setup` provisions Ghidra and a
//! JDK, and `kraken mcp --daemon` routes the MCP tools through the daemon too.
//!
//! Exit codes: 0 ok, 2 invalid arguments, 3 not found, 4 conflict or rejected, 5 engine or
//! internal failure, 6 cancelled or timed out ([`exit_code`]).

mod agents_cmd;
mod app;
mod assist_cmd;
mod auto_cmd;
mod cost;
mod daemon_cmd;
mod eval_cmd;
mod exit;
mod infer_cmd;
mod progress;
pub mod render;
pub mod schema;
mod serve_local;
mod setup;

pub use app::{
    BUILD, CliAuthor, CliEnv, DaemonAuto, DaemonMode, OwnerSlot, build_args, build_cli, run,
    run_with_provider,
};
pub use exit::exit_code;

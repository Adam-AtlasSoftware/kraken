# KRAKEN (CLAUDE.md)

KRAKEN is an AI-assisted reverse engineering workbench on Ghidra's engine, with a CLI, MCP server
and GUI over one command registry. Goal: Rust rewrites of binaries. Status: pre-alpha, v0.1 scope
is native PE/ELF/Mach-O. Linux x86_64 is the first platform. Repo: Adam-AtlasSoftware/kraken.

Conventions for all cards: Rust 2024 edition, stable toolchain pinned in rust-toolchain.toml;
`cargo fmt` + `cargo clippy -D warnings` clean; errors via `thiserror` in libraries, `anyhow` only
in binaries; no `unwrap()` outside tests; comments only where the code is not obvious; every new
crate is GPL-3.0-or-later in Cargo.toml. Do not commit; the main loop commits.

## Crate map (decision 39)

- `xtask`: build helper binary (exists)
- `kraken-proto`: wire/schema types, no tokio/egui/FFI (planned)
- `kraken-model`: DB, edit log, transactions (planned)
- `kraken-engine`: engine capability traits (planned)
- `engine-ghidra`: sidecar manager, plus `java/` extension (planned)
- `engine-fake`: fake engine for tests (planned)
- `kraken-registry`: command registry (planned)
- `krakend`: daemon, owns projects and the sidecar (planned)
- `kraken-cli`: CLI client (planned)
- `kraken-mcp`: MCP server (planned)
- `kraken-agent`: agent loop and providers (planned)
- `kraken-infer`, plus one crate per inference backend (planned)
- `kraken-gui`, plus a headless view-model crate tested without egui (planned)

Only `xtask` exists today; `crates/` is empty. Other crates are created by their own cards.

## Key decisions

- Engine is a JVM Ghidra sidecar now, behind Rust capability traits, so a native backend can replace it piece by piece.
- The KRAKEN project DB is the source of truth for annotations; the Ghidra project is a rebuildable cache.
- Every change is a transaction in the edit log, tagged with its author (user or agent run id); undo per change or per run.
- One command registry; the CLI, MCP server, GUI and agents are all clients of the `krakend` daemon.
- Agent writes auto-apply only for additive changes.
- The sidecar is confined with Landlock on Linux and kept under daemon supervision.
- License is GPL-3.0-or-later; dependencies are restricted to the cargo-deny allowlist in `deny.toml`.
- Linux x86_64 is the first platform; Windows and macOS follow as tier 1 with real-Ghidra CI.
- Sidecar IPC is JSON-RPC over stdio with length-prefixed framing; schemas are generated from Rust types.
- Every query is paginated and size-capped to keep MCP results within token budgets.
- Analysis runs as jobs with progress, cancel and resume.
- Engine and inference backends run as supervised child processes.
- Android is out of scope for 1.0.

## Pointers

- Design record: `docs/design/` (ADRs, part of the mdBook).
- Local working plans: `plans/` (gitignored; not part of the repo).

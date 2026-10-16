# KRAKEN (CLAUDE.md)

KRAKEN is an AI-assisted reverse engineering workbench on Ghidra's engine, with a CLI, MCP server
and GUI over one command registry. Goal: Rust rewrites of binaries. Status: pre-alpha, v0.1 scope
is native PE/ELF/Mach-O. Linux x86_64 is the first platform. Repo: Adam-AtlasSoftware/kraken.

Conventions for all cards: Rust 2024 edition, stable toolchain pinned in rust-toolchain.toml;
`cargo fmt` + `cargo clippy -D warnings` clean; errors via `thiserror` in libraries, `anyhow` only
in binaries; no `unwrap()` outside tests; comments only where the code is not obvious; every new
crate is GPL-3.0-or-later in Cargo.toml. Do not commit; the main loop commits.

## Crate map

- `kraken-proto`: wire and persisted types, JSON Schema (`cargo xtask schema`, `cargo xtask samples`)
- `kraken-engine`: engine capability traits + contract suite (feature `testing`)
- `engine-ghidra` + `java/kraken-ghidra`: confined Ghidra sidecar (build: `cargo xtask ghidra-ext`)
- `engine-fake`: fixture-driven engine for tests; fixtures in `corpus/fixtures` (`kraken-record`)
- `kraken-model`: SQLite edit log, read-sets, undo, proposals, snapshots
- `kraken-registry`: command registry (44 commands, incl. `rewrite_*` and `undo_entry`/`undo_preview` and the `RewriteBackend` trait); CLI/MCP/GUI/docs are generated from it
- `kraken-host`: config, Ghidra engine factory, daemon client, `kraken setup` provisioning
- `kraken-ipc` / `krakend`: authenticated local RPC and the daemon that owns projects
- `kraken-cli` (binary `kraken`) / `kraken-mcp` (`kraken mcp`)
- `kraken-agent`: agent loop and providers; `kraken-assist`: explain/overview/auto-name, glossary
- `kraken-acp`: terminal-agent host over ACP (Claude Code, Codex, Gemini CLI), Node/adapter provisioning, fake ACP agent for tests
- `kraken-infer`: supervised local inference backends (llama-server, manifest engines)
- `kraken-layout`: CFG layout; `kraken-gui-widgets`, `kraken-viewmodel`, `kraken-gui` (binary `kraken-gui`)
- `kraken-rewrite`: rewrite pipeline core (ADR 0013): icicle-emu function oracle, Rust translation and spec tasks, sandboxed differential tests, `<project>/rewrite.sqlite` store, planner, `RewriteService` (the backend of the `rewrite_*` commands, attached by `krakend` and the CLI), strangler export; spike notes in `spikes/rewrite-loop/NOTES.md`; tests need a Ghidra install for the x86 SLEIGH spec and Landlock
- `kraken-py` (Python module `kraken`, PyPI name `kraken-workbench`): PyO3 over the daemon client with an in-process fallback; build with maturin (`docs/python.md`); the `python` cargo feature gates PyO3 so workspace builds need no Python
- `kraken-record`: records FakeEngine fixtures from real Ghidra; `kraken-e2e`: end-to-end tests

Tests: `cargo test --workspace`; real-Ghidra tests are `#[ignore]` and need `KRAKEN_GHIDRA_HOME`,
`KRAKEN_JAVA_HOME` and the extension built. Tests that run `kraken` binaries must set
`KRAKEN_RUNTIME_DIR` to a private dir or `KRAKEN_NO_DAEMON=1`, so they never use the real daemon.

## Key decisions

- Engine is a JVM Ghidra sidecar now, behind Rust capability traits, so a native backend can replace it piece by piece.
- The KRAKEN project DB is the source of truth for annotations; the Ghidra project is a rebuildable cache.
- Every change is a transaction in the edit log, tagged with its author (user or agent run id); undo per change or per run.
- One command registry; the CLI, MCP server, GUI and agents are all clients of the `krakend` daemon.
- Agent writes auto-apply only for additive changes.
- The sidecar is confined with Landlock on Linux and kept under daemon supervision.
- License is GPL-3.0-or-later; dependencies are restricted to the cargo-deny allowlist in `deny.toml`.
- Linux x86_64 is the first platform; Windows and macOS follow as tier 1 with real-Ghidra CI.
- Sidecar IPC is JSON-RPC with length-prefixed framing over a socketpair passed as the child's stdin; Rust types are the contract.
- Every query is paginated and size-capped to keep MCP results within token budgets.
- Analysis runs as jobs with progress, cancel and resume.
- Engine and inference backends run as supervised child processes.
- Android is out of scope for 1.0.

## Pointers

- Design record: `docs/design/` (ADRs, part of the mdBook).
- Local working plans: `plans/` (gitignored; not part of the repo).

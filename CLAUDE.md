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
- `kraken-sidecar`: the plumbing both sidecar engines share: JSON-RPC framing and the multiplexing client, the confined spawner (Landlock, seccomp, netns; Windows job object), `SpawnSpec`, `ConfinementReport`, the log sink; `engine-ghidra` re-exports it
- `engine-dotnet` + `dotnet/kraken-dotnet`: managed-code engine (ILSpy decompiler in a confined C# sidecar; methods as `Managed` locators, C# with tokens; renames and method comments are applied from the edit log by the Rust engine at render time (`Annotations`), replayed on project open; build: `cargo xtask dotnet-ext`, SDK via `dotnet/install-sdk.sh`; corpus in `corpus/dotnet`; user docs in `docs/dotnet.md`, notes in `spikes/dotnet-engine/NOTES.md`)
- `engine-native-sys`: Ghidra's C++ decompiler + Sleigh built from source (`cargo xtask native-src` fetches the pinned 12.1.4 sources into `~/.cache/kraken-dev/ghidra-src`; without them a stub is built; `cxx` is a Linux-only dependency) and a cxx-bridged C++ shim (callback load image, symbol scope, token-recording PrintC, typed references, jump tables, C declarations and prototypes through Ghidra's grammar, noreturn, a cooperative decompile timeout and stop flag on the action break points)
- `engine-native`: JVM-free engine (ADR 0014, phases 1-2): ELF loader (`object`, `gimli` for `.eh_frame`), discovery on Sleigh flow with FDE seeds, landing pads and noreturn propagation, in-process decompiler with a type store and libc prototypes, disassembly, memory, xrefs, CFG, strings, imports/exports and the analyzer job; reads only Sleigh spec files: the tree `cargo xtask native-sla` compiles from the pinned sources (`~/.cache/kraken-dev/native-sla`, byte-identical to Ghidra's), `KRAKEN_NATIVE_SPECS`, or a Ghidra install (`KRAKEN_GHIDRA_HOME`); agreement with the Ghidra fixtures in `tests/agreement.rs`; notes in `spikes/native-engine/NOTES.md`
- `engine-fake`: fixture-driven engine for tests; fixtures in `corpus/fixtures` (`kraken-record`)
- `kraken-model`: SQLite edit log, read-sets, undo, proposals, snapshots
- `kraken-registry`: command registry (47 commands, incl. `rewrite_*` and `undo_entry`/`undo_preview` and the `RewriteBackend` trait); CLI/MCP/GUI/docs are generated from it
- `kraken-host`: config, engine factories (`HostEngineFactory` picks Ghidra or .NET per binary; the kind is recorded in `meta.json`), daemon client, `kraken setup [--dotnet]` provisioning
- `kraken-ipc` / `krakend`: authenticated local RPC and the daemon that owns projects
- `kraken-cli` (binary `kraken`) / `kraken-mcp` (`kraken mcp`: one tool per command, plus prompts `getting-started`, `explain-function`, `name-components`, `prepare-rewrite` and resources `kraken://project/summary`, `kraken://gui/selection` (the GUI publishes it to the daemon with `gui_selection_set`), `kraken://function/{address}/decompile`, `kraken://glossary[/{term}]`; tool descriptions come from the registry's `doc` (short, with an `Example:` that `kraken-registry/tests/doc_quality.rs` checks) and `details` (reference only))
- `kraken-agent`: agent loop and providers; `kraken-assist`: the assistant (explain/overview/auto-name, glossary) over an `AssistBackend`: a model API (`ApiBackend`) or a terminal agent (`AcpBackend`), chosen by the `[provider]` table (`kind = "terminal_agent"`); one assistant, one GUI tab, one docs page (`docs/assistant.md`)
- `kraken-eval`: evaluation harness behind `kraken eval` (tasks over the corpus scored against DWARF ground truth: name stripped functions by token overlap, find the function, strings/imports questions; any backend through `Assistant` + `Task::custom`; JSON + Markdown report with transcripts; CI mode with `engine-fake` fixtures and a stand-in script delivered as an `EvalCassette` through `ReplayProvider` or to the fake ACP agent; data in `crates/kraken-eval/data`, rewrite with `KRAKEN_EVAL_BLESS=1`; docs in `docs/assistant.md`)
- `kraken-acp`: terminal-agent host over ACP (Claude Code, Codex, Gemini CLI), Node/adapter provisioning, fake ACP agent for tests
- `kraken-infer`: supervised local inference backends (llama-server, manifest engines)
- `kraken-layout`: CFG layout; `kraken-gui-widgets`, `kraken-viewmodel`, `kraken-gui` (binary `kraken-gui`)
- `kraken-rewrite`: rewrite pipeline core (ADR 0013): icicle-emu function oracle, Rust translation and spec tasks, sandboxed differential tests, `<project>/rewrite.sqlite` store, planner, `RewriteService` (the backend of the `rewrite_*` commands, attached by `krakend` and the CLI), bounded repair loop, accepted-callee reuse and stale marks, strangler export, whole-program mode (`rewrite_program`: bottom-up translation, standalone Rust crate with the `rt` libc shim in `src/runtime/rt.rs`, program-level process oracle in `process.rs`/`program.rs`, `service_program.rs`; program-level repair that traces the first differing case and re-translates the likeliest function, `blame.rs`; pointer graphs, `double` and function-pointer parameters in the call description `abi.rs`, placed identically in the emulator and the native runner); spike notes in `spikes/rewrite-loop/NOTES.md`; function-level oracle tests need a Ghidra install for the x86 SLEIGH spec, all sandboxed tests need Landlock; the `program` tests run without Ghidra (cassettes in `crates/kraken-rewrite/cassettes`, references in `crates/kraken-rewrite/references/program`)
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

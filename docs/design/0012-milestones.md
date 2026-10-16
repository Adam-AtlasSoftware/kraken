# 0012. Milestones

Status: Accepted
Date: 2026-10-15

## Context

The project is large. We want working software early and a way to find design errors before they are expensive.

## Decision

Work proceeds in this order.

1. **Spike (week one).** Throwaway proofs: a minimal MCP server, an egui window with docking, a sidecar that echoes under confinement, a Ghidra extension built by `cargo xtask`. Exact versions are recorded in `Cargo.lock` and in the pins.
2. **0.1a: vertical slice.** CLI and MCP spawn a Ghidra sidecar per project, with no daemon. Load an ELF, list functions, decompile, rename and retype, create a function, undo. Edit log with anchors. `FakeEngine`, corpus tests and safety tests. Linux x86_64 only.
   - Exit criterion: an agent over MCP loads a corpus ELF, renames and retypes functions, creates a function and undoes the edits. A Ghidra project rebuilt from the log then matches.
3. **0.1b.** The `krakend` daemon, tested with a fake sidecar that crashes, hangs and sends bad frames. Auto-download of Ghidra and the JRE. Idle exit. The change event stream.
4. **0.2.** GUI (functions, disassembly, decompiler, hex, rename and retype, history). Built-in agent over OpenAI-compatible HTTP, then Anthropic, OpenAI and Gemini. "Explain" and glossary tooltips. Dependency-aware undo. Linux first, then macOS arm64 and Windows x86_64 as 0.2.x.
5. **0.3.** Control-flow graph view. ACP terminal agents. Auto-naming. Guided first run. Packaging and signing.
6. **0.4.** Supervised and in-process inference backends. Python module.
7. **0.5 and later.** Rewrite pipeline: lift, repair decompiler output, translate function by function behind FFI, gate each function on differential tests. Two modes: faithful incremental, and spec-then-reimplement.
8. **1.0.** Managed code (.NET, Java and DEX), firmware blobs, console ROMs and games. Tier 1 platforms only (ADR 0009).
9. **After 1.0.** The native engine, which brings back the other CPU and OS targets.

**Test strategy from the start.** A small corpus of prebuilt binaries with source, build script and DWARF-derived ground truth. Snapshot tests store structure, not raw decompiler text. Contract tests require CLI, MCP and the engine interface to agree. `FakeEngine` fixtures are recorded from real Ghidra by a tool, and a nightly job checks for drift.

## Consequences

- Each release is usable on its own.
- Risky pieces (daemon, GUI, inference) wait until the core is proven.
- Early releases are Linux only.
- The schema reserves room for later features, such as rewrite artifacts, but does not build them early.

## Alternatives considered

- Build the daemon first. Delays feedback on the command and engine design.
- GUI first. Hides problems in the engine and the log.
- Ship all four AI paths in 0.1. Too much surface before the core is stable.

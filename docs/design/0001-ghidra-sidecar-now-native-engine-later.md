# 0001. Ghidra sidecar now, native engine later

Status: Accepted
Date: 2026-10-15

## Context

KRAKEN needs a real analysis engine: file loaders, auto-analysis, a decompiler, a type system. Ghidra has all of these. Its decompiler and its Sleigh lifter are C++ and can be built alone. The loaders, the program database, auto-analysis, the data type manager and the demanglers exist only in Java.

Rewriting those Java parts in Rust would take years. It would delay a usable tool. Android is not a goal for 1.0, so shipping a JVM is acceptable.

## Decision

KRAKEN runs Ghidra as a sidecar process. A small Java extension inside Ghidra speaks a JSON-RPC protocol to the Rust side.

The Rust side does not depend on Ghidra types. The engine is a set of capability traits: `Loader`, `Analyzer`, `Lifter`, `Decompiler`, `TypeStore`, `Emulator`. A project composes the capabilities it needs. The Rust traits are the contract. JSON-RPC is only the transport adapter used by the Ghidra engine.

Wire types are engine-neutral. Locators are an address space plus offset, with room for other kinds later (for example managed-code member tokens). There are no Ghidra handles. The protocol starts with a version and capability handshake.

Version 0.1 has two implementations of the traits: the Ghidra sidecar and a `FakeEngine` that replays recorded fixtures. Both pass the same contract tests. That keeps the traits honest.

A native engine comes later. It can replace a whole engine, or replace a `Decompiler` or `Lifter` that reads from a `ProgramView`. A `ProgramView` is a pull interface for bytes, symbols, types, function facts and context. It is designed when native work starts, not before.

## Consequences

- We get Ghidra's accuracy and processor coverage early.
- Users need a JVM and a Ghidra install. KRAKEN downloads both (see ADR 0009).
- Program state lives inside the sidecar. KRAKEN's own store is a cache of it (see ADR 0002).
- Contract tests catch trait designs that only work for Ghidra.
- Some design work is deferred on purpose: `ProgramView` and mixed engines.
- Linux arm64, Windows arm64 and riscv64 return only with the native engine.

## Alternatives considered

- Native Rust engine from the start. Too slow to reach a usable tool.
- Link `libdecomp` and `libsla` now and rewrite the Java parts. Same cost problem, and the host glue alone is large.
- Use Ghidra's own GUI and plugins. This gives no shared model for CLI, MCP and agents.
- Pure-Rust decompiler ports and young Sleigh crates. Not mature enough to depend on.

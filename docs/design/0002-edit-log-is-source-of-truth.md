# 0002. The edit log is the source of truth; the Ghidra project is a cache

Status: Accepted
Date: 2026-10-15

## Context

Users and agents rename things, set types, add comments and change function boundaries. These edits are the valuable output of a reverse-engineering session. If they only live in a Ghidra project, KRAKEN cannot undo them cleanly, attribute them, or move to another engine.

Ghidra projects are also fragile. A crash, a Ghidra upgrade or a changed analysis option can leave a project unusable.

## Decision

KRAKEN keeps its own SQLite database with two layers.

**Layer 1: the edit log.** It is append-only and is the only truth. Each entry has an operation, an anchor, the old and new value, the author, the run id, provenance, a read-set, and a status (`applied`, `rejected` with a reason, or `orphaned`). Operations are a tagged, versioned enum. Version 0.1a covers annotations (rename, type, comment) and the structural operations the Ghidra extension can apply (create or delete function, set bounds, code/data, calling convention). More operations can be added later without a migration.

**Layer 2: engine facts.** Memory map, functions, cross-references and control-flow graphs, cached per engine run. It is paged lazily and size-capped. It can be dropped at any time.

**Anchors.** An edit points at a stable anchor, not a raw address. An anchor is a tagged enum with a schema version. `Native` is address plus function entry and a hash of the function's original bytes. `Managed` and `Banked` are reserved. In 0.1 an edit whose entry and hash do not match is marked orphaned and goes to a review queue. A fuller fallback ladder (entry, then hash, then cross-reference neighbourhood) is added only after it passes a measured precision test on corpus programs built in two variants.

**Sync state.** Each entry is `pending`, `pushed` or `engine_rejected`. Pushes to Ghidra are idempotent. A pushed watermark is saved together with each Ghidra save. A single mutation returns after the push is confirmed, so the next decompile is consistent. A bulk mutation returns a job. A write made during analysis returns `queued`.

**Rebuilding.** The Ghidra project is a warm cache with checkpoints. After a crash, only the log after the last saved watermark is replayed. A project's epoch is (Ghidra version, loader and analyzer options hash, binary hash). If the epoch changes, KRAKEN re-analyses and replays the log. Rebuilds are best-effort. After each one, a drift report compares per-function signature and token-map hashes with what the log expects. `kraken resync` shows the same report on demand. Periodic snapshots of the annotation state speed up loading. The log is kept for audit and undo.

**Ghidra pin.** Each project is pinned to the Ghidra version that built it. A KRAKEN release that bumps Ghidra does not touch existing projects. The user runs an explicit migration, which rebuilds fully and keeps the old cache until the new one is verified.

**Byte patches** live in a separate overlay layer. Anchor hashes use the original bytes, so patching does not break anchors.

**Scope limit.** KRAKEN does not import annotations from stock Ghidra projects.

## Consequences

- Undo, attribution and history work the same for any engine.
- A broken or outdated Ghidra project costs time, not work.
- Rebuilds are not guaranteed to be identical. The drift report makes differences visible.
- Orphaned edits need a human or a later fallback ladder.
- Users must run a migration to move an old project to a new Ghidra.

## Alternatives considered

- Ghidra project as the truth, with KRAKEN reading it. Ties the data model to Ghidra and weakens undo.
- Two-way sync between KRAKEN and Ghidra. Conflicts are hard to resolve and hard to test.
- Anchor edits to raw addresses. Breaks on any rebase or re-analysis.
- Import from stock Ghidra projects. Out of scope, and the mapping would be lossy.

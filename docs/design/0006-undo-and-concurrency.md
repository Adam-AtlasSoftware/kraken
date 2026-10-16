# 0006. Undo and concurrency

Status: Accepted
Date: 2026-10-15

## Context

Humans and agents edit the same project at the same time. Users need to undo a single edit or a whole agent run. Later edits can depend on earlier ones. A type change might rely on a function that an earlier edit created.

## Decision

**Undo is a new log entry.** Undoing writes a compensating entry. History is never rewritten. After an undo, affected functions are pushed again and re-decompiled. Derived data is marked stale, not reversed.

**Read-sets.** Every edit records the versions of what it was based on: its target, the types it used, the callees it saw. This is recorded from 0.1 on.

**Versions and validation.** Entities have versions. A write is checked against its whole read-set, not only its target's version, using compare-and-set. A stale write fails with a structured error so the agent re-reads and tries again. Queued writes are checked again when they leave the queue.

**Human priority.** If a human and an agent edit the same thing at the same time, the human edit wins. The agent attempt is logged as rejected.

**Ordering.** One write queue in the daemon orders all writes. A cursor-based event stream lets every client follow changes.

**Staged undo.**

- 0.1: undo the last edit, or a whole run in reverse order.
- 0.2: with the GUI, undoing an edit that later edits depend on lists them. The user chooses to undo those too, or to cancel. The read-sets already in the data make this possible without a migration.

A perturbing mode in `FakeEngine` (shifted base address, split and merged functions) tests anchors and replay.

## Consequences

- Full audit trail, including undone work.
- Agents see clear errors and can recover.
- Dependency-aware undo needs UI work, but no data change.
- Derived data can be briefly stale after an undo.

## Alternatives considered

- Delete log entries on undo. Loses audit history and breaks replay.
- Last-writer-wins. Silently loses human edits.
- Per-target version checks only. Misses edits that were based on changed neighbours.
- Locking. Blocks interactive work behind long agent runs.

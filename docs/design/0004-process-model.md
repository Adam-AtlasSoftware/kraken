# 0004. Process model

Status: Accepted
Date: 2026-10-15

## Context

Several clients can work on one project at once: a GUI, the CLI, an MCP server and agents. Something must own the project, the log and the Ghidra process, and order the writes. Building that daemon is a large piece of work. We want a usable tool before it exists.

## Decision

**Release 0.1a: direct sidecar.** The CLI and the MCP server each spawn a Ghidra sidecar for the project. There is no daemon. The user points KRAKEN at an installed Ghidra from a tested-version list.

**Release 0.1b: `krakend`.** A daemon owns projects and the sidecar. GUI, CLI, MCP and agents are clients.

- Any client starts the daemon if it is not running. It exits after an idle timeout. Running agent runs, jobs and loaded models count as activity. `kraken daemon status|stop` manage it.
- A single-instance lock holds a PID and a start token, and is safe against start races.
- The daemon is the only parent of the JVM and kills it on exit. Linux uses `PR_SET_PDEATHSIG`, set from a dedicated spawner thread that stays alive. Windows uses a job object. On macOS the sidecar watches the parent PID itself. EOF on the channel also ends the sidecar.
- A crashed sidecar is restarted a bounded number of times, with log replay. Every client gets a "project reloaded" event. A stale Ghidra lock is cleaned only if the owning PID is dead.
- Clients and daemon exchange a protocol and build handshake. A mismatch gives a clear "restart the daemon" path.
- Writes go through one ordered queue. A cursor-based event stream tells all clients what changed.

**IPC.** Local only for now. Linux and macOS use a per-user socket in a short runtime directory with mode 0700. Windows uses a named pipe with an owner-only ACL. A token file adds authentication. The protocol is designed to run over TLS with the same token later, so remote use does not need a redesign.

**Scheduling.** Priority lanes: interactive, then agent, then bulk. Requests have deadlines and return a structured "timeout, partial" result. Bulk jobs above a threshold show an estimate (functions, time, tokens) and need approval.

**Analysis** is a job with progress, cancel and resume. Every result carries a completeness marker. Large binaries are analysed in stages with a Ghidra save between stages. Heap size follows binary size. Repeated out-of-memory failures stop with a message that asks for more memory or a lighter analyzer profile.

**Memory.** The daemon splits RAM between Ghidra and any local models, and warns before overcommitting.

## Consequences

- 0.1a ships sooner and proves the model, command and engine layers.
- 0.1a has no shared state between a CLI call and an MCP session. Two processes on one project are not supported yet.
- The daemon needs a test harness for crashes, hangs and malformed frames, plus an injected clock.
- A future remote mode reuses the same protocol.

## Alternatives considered

- Library with an attachable host. Each client would own state. Sharing and ordering writes would be harder.
- Daemon from day one. Slows the first usable release.
- Always-on system service. Heavier to install, and unneeded for a developer tool.

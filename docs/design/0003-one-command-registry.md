# 0003. One command registry

Status: Accepted
Date: 2026-10-15

## Context

KRAKEN is used from a CLI, an MCP server, a GUI and, later, Python. If each surface defines its own operations, they drift apart and need separate tests and docs.

## Decision

Every operation is defined once in Rust. A `#[kraken_command]` macro records its name, kind, permission class, doc comment and typed arguments and result (serde and schemars). The CLI (clap), MCP tools (rmcp), GUI command palette and the command reference in these docs are generated from that definition.

**Kinds.** `Query`, `Mutation`, `Job` and `Stream`. Mutations are transactional and carry an author and a run id. Jobs have an id, progress, cancellation and persisted state.

**Permissions.** `safe`, `mutating` or `dangerous`. Each surface supplies an approval requester: a dialog in the GUI, a flag or prompt in the CLI, elicitation in MCP. If an MCP client cannot elicit, approval goes out of band to an attached GUI or CLI prompt. If none is attached, the call is denied with an explanation.

**Pagination.** Every query is paginated and size-capped. A surface can apply its own projection, such as an MCP token budget, without changing the core command.

**Long jobs over MCP.** Start, status and await tools work with every client. MCP progress and cancellation notifications are used where the client supports them. Commands can declare phases that cannot be cancelled.

**Capability predicates.** A command can be hidden on surfaces or engines that cannot serve it.

**UI context.** The current selection, cursor and open views are a resource agents can read, not a command. A small set of UI intents (navigate, highlight) is routed to attached GUIs.

A contract test runs every command through the CLI in JSON mode and through an MCP client. The results must match.

## Consequences

- A new operation appears on all surfaces at once.
- The reference docs cannot go stale.
- The macro and registry crates are central. Changes there affect everything.
- Surface-specific behaviour must fit the projection mechanism.

## Alternatives considered

- Hand-written code per surface. Drifts, and triples the tests.
- Generating the CLI from MCP schemas, or the reverse. Each loses information the other needs, such as permission classes.
- A separate scripting API as the base layer. Adds a layer without removing the others.

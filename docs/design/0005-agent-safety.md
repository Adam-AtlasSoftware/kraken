# 0005. Agent safety

Status: Accepted
Date: 2026-10-15

## Context

Agents can read a binary and change a project very fast. They also read text from the binary, such as strings and symbol names. That text is attacker-controlled. A hostile sample can try to instruct the agent.

## Decision

**Additive auto-apply.** An agent's change is applied directly only if it is additive: a name on an unnamed symbol, a new comment, a type on an untyped item. Each run has a cap on automatic changes. Overwriting a user's edit, or going past the cap, becomes a proposal batch that the user accepts or rejects.

**Dangerous tools always ask.** Byte patching, executing code and running scripts need approval every time. If a client cannot show a prompt, the approval fallback in ADR 0003 applies: ask in an attached GUI or CLI, otherwise deny.

**Attribution.** Every change is a log entry with an author (user, or agent plus run id). Agent edits are styled differently in the UI until confirmed.

**Untrusted data.** Text from the binary is always passed to models inside delimited blocks marked as untrusted data. Annotations carry provenance: `user`, `agent`, or `agent-from-binary-text`. Agent text that is fed back to a model stays marked untrusted.

**Sanitisation.** Control characters, ANSI escapes and bidirectional-text characters are removed at ingestion and again at rendering.

**Tests.** Gating tests use scripted MCP tool calls to check permission classes, the cap and the additive rule. Canary strings in binary symbols and strings must never cause a tool call. Prompt-injection cases are part of the agent evals. Deterministic replay of recorded model sessions runs on every pull request once the built-in agent exists. Live-model evals run nightly or by hand. They never gate a merge. They are scored on database state against ground truth from corpus builds with and without symbols.

**ACP terminal agents** (Claude Code, Codex, Gemini CLI and others) run their own shell and file tools. KRAKEN does not sandbox them. It shows a one-time warning that these tools are outside KRAKEN's safety model.

**Writes during analysis** are queued until analysis finishes, except on functions that are already fully analysed.

## Consequences

- Most routine agent work needs no clicks.
- Users still review overwrites and large batches.
- A well-crafted binary should not be able to make the agent call tools through its own text. The tests check this. It is a mitigation, not a proof.
- ACP agents have weaker guarantees. The warning says so.

## Alternatives considered

- Approve every agent write. Too slow to be useful.
- Auto-apply everything with undo only. Overwrites of human work would be too easy.
- Sandbox ACP agents. Not possible to do well across the agents and platforms involved.
- A per-project gate on AI use. Rejected. Any configured provider is used, and the UI shows which provider each request goes to.

# Security

KRAKEN is meant for analysing software you do not trust, so it assumes that the binary may attack the tools that read it.

## The Ghidra sandbox

Ghidra parses the binary, and parsers have bugs. On Linux, KRAKEN runs Ghidra in a separate process (the sidecar) that is confined:

- **Landlock** limits the filesystem. The sidecar may read the JDK, Ghidra, the extension, the binary under analysis and a few system libraries. It may write only to a throwaway home directory and the project directory.
- **No network.** Landlock denies TCP, and the sidecar also runs in new user and network namespaces, which cuts off everything else, including UDP.
- **A scrubbed environment.** API keys and tokens in your shell are not passed on.
- **A private channel.** KRAKEN talks to the sidecar over a socketpair, not over files or the network.

If the kernel cannot enforce Landlock at all, KRAKEN refuses to start the sidecar. Setting `allow_unconfined = true` overrides this; do it only on machines and samples you can afford to lose.

## What is protected

- Your files, keys and network from a malicious binary exploiting the parser.
- Your own work from an AI agent's mistakes: edits are logged, attributed and undoable, and an agent cannot overwrite your edits without your approval.
- Agents from text in the binary: it is marked untrusted and stripped of control characters.

## What is not

- **KRAKEN never runs the binary.** If you run it yourself, that is up to you (use a VM).
- **Confinement exists only on Linux** in 0.1a. macOS and Windows are not supported yet.
- **A partly enforced Landlock ruleset is accepted** on older kernels. Network and filesystem limits may then be weaker.
- **Prompt injection cannot be ruled out.** The measures reduce the risk.
- **Your AI agent is not sandboxed by KRAKEN.** Claude Code, Codex and similar tools have their own shell and file access. A binary that tricks the agent into using those tools is outside KRAKEN's protection. Use the agent's own permission prompts and sandboxes.
- **Project folders are trusted.** Do not open a project folder from someone you do not trust.

> **Warning (placeholder).** In a future release, KRAKEN's GUI will start terminal agents over ACP and show a one-time notice that they run outside KRAKEN's safety model. That feature does not exist in 0.1a.

See the design decisions on [sidecar confinement](design/0007-sidecar-confinement.md) and [agent safety](design/0005-agent-safety.md).

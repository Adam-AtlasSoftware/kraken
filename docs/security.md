# Security

KRAKEN is meant for analysing software you do not trust, so it assumes that the binary may attack the tools that read it.

## The Ghidra sandbox

Ghidra parses the binary, and parsers have bugs. On Linux, KRAKEN runs Ghidra in a separate process (the sidecar) that is confined:

- **Landlock** limits the filesystem. The sidecar may read the JDK, Ghidra, the extension, the binary under analysis and a few system libraries. It may write only to a throwaway home directory and the project directory.
- **No network.** Landlock denies TCP, and the sidecar also runs in new user and network namespaces, which cuts off everything else, including UDP.
- **A scrubbed environment.** API keys and tokens in your shell are not passed on.
- **A private channel.** KRAKEN talks to the sidecar over a socketpair, not over files or the network.

If the kernel cannot enforce Landlock at all, KRAKEN refuses to start the sidecar. Setting `allow_unconfined = true` overrides this; do it only on machines and samples you can afford to lose.

## Generated code (rewrite)

The rewrite commands (`rewrite_function`, `rewrite_export`) build and run Rust that a model wrote. That code is untrusted, so it runs only in a confined child process: the file system is read-only except for a scratch directory, there is no network, memory, CPU and output size are limited, and the environment is scrubbed. A source check refuses obvious escapes (file, network and process APIs, inline assembly, `include!`) before anything is built. If the host cannot enforce this (Linux with Landlock is required), the commands refuse to run; there is no flag to run generated code unconfined. The original program is never executed natively: single functions run under emulation, and their output is compared with the generated code's. Accepting a rewritten function is something only you can do, not an agent. The exported workspace is code you build and run yourself, outside this sandbox, so read it first. Model calls send decompiled code to the provider you configured. See [the rewrite pipeline](design/0013-rewrite-pipeline.md).

## What is protected

- Your files, keys and network from a malicious binary exploiting the parser.
- Your own work from an AI agent's mistakes: edits are logged, attributed and undoable, and an agent cannot overwrite your edits without your approval.
- Agents from text in the binary: it is marked untrusted and stripped of control characters.

## What is not

- **KRAKEN never runs the binary natively.** The rewrite pipeline emulates single functions of it. If you run it yourself, that is up to you (use a VM).
- **Confinement exists only on Linux** in 0.1a. macOS and Windows are not supported yet.
- **A partly enforced Landlock ruleset is accepted** on older kernels. Network and filesystem limits may then be weaker.
- **Prompt injection cannot be ruled out.** The measures reduce the risk.
- **Your AI agent is not sandboxed by KRAKEN.** Claude Code, Codex and similar tools have their own shell and file access. A binary that tricks the agent into using those tools is outside KRAKEN's protection. Use the agent's own permission prompts and sandboxes.
- **A local model's engine is not sandboxed.** `kraken infer` runs `llama-server` (or an engine from a manifest) as your user, listening on 127.0.0.1 only, with a filtered environment (no API keys). Run only engine programs and model files you trust, and only manifests you wrote or reviewed: a manifest names a program to run. See [Running a model on this computer](local-models.md).
- **Project folders are trusted.** Do not open a project folder from someone you do not trust.

> **Warning (placeholder).** In a future release, KRAKEN's GUI will start terminal agents over ACP and show a one-time notice that they run outside KRAKEN's safety model. That feature does not exist in 0.1a.

See the design decisions on [sidecar confinement](design/0007-sidecar-confinement.md) and [agent safety](design/0005-agent-safety.md).

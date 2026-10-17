# Security

KRAKEN is meant for analysing software you do not trust, so it assumes that the binary may attack the tools that read it.

## The Ghidra sandbox

Ghidra parses the binary, and parsers have bugs. On Linux, KRAKEN runs Ghidra in a separate process (the sidecar) that is confined:

- **Landlock** limits the filesystem. The sidecar may read the JDK, Ghidra, the extension, the binary under analysis and a few system libraries. It may write only to a throwaway home directory and the project directory.
- **No network.** Landlock denies TCP, and the sidecar also runs in new user and network namespaces, which cuts off everything else, including UDP.
- **A scrubbed environment.** API keys and tokens in your shell are not passed on.
- **A private channel.** KRAKEN talks to the sidecar over a socketpair, not over files or the network.

If the kernel cannot enforce Landlock at all, KRAKEN refuses to start the sidecar. Setting `allow_unconfined = true` overrides this; do it only on machines and samples you can afford to lose.

## Agents and the daemon

An AI agent works through KRAKEN's MCP server, and that server talks to the `krakend` daemon. The daemon does not believe what a client says about itself:

- **Two credentials.** The daemon issues a *user* token (`daemon.token`, used by the GUI and the CLI) and an *agent* token (`agent.token`, used by MCP servers). A connection that presents the agent token is always an agent on the MCP surface, whatever it claims: its edits are logged as an agent's and obey the proposal and cap rules, its "approved" flag is ignored, and it can only call `call`, `commands` and `events`, not `shutdown`, `status`, the approval methods or the model-hosting methods.
- **Opening a project needs you.** An agent that asks to create or open a project, or to work on a project you have not opened yourself, waits for your approval: the window shows a dialog, and `kraken daemon approvals` lists the requests and answers them (`--approve ID`, `--deny ID`). No answer within two minutes is a refusal. A project you worked on yourself (in the window, or with a CLI command) is available to agents until the daemon stops. `kraken mcp --project DIR` binds the server to that project and does not offer `project_create` or `project_open` at all.
- **Some places are refused even when you would approve.** An agent cannot point KRAKEN at files in hidden directories of your home directory (`~/.ssh`, `~/.config`, `~/.gnupg`, ...), at `/proc`, `/sys` or `/dev`, or at anything that is not an ordinary file, and a project's metadata cannot send the engine directory outside the project.
- **Agents are not handed the runtime directory.** The daemon's socket and tokens live in the runtime directory; terminal agents started by KRAKEN do not get `XDG_RUNTIME_DIR` or any `KRAKEN_*` variable. Their MCP server is told where the daemon is and connects with the agent token.
- **Limits.** The daemon caps open connections (128), connections that have not said hello (16), requests in flight per connection (64) and in total (256), and accepts only small frames before the hello.
- **Quotas follow the agent, not the connection.** An agent's cap on auto-applied edits is counted for the whole agent credential in a project, so reconnecting does not start a new budget.
- **Text from the binary and the engine** reaches agents wrapped as untrusted and stripped of control, bidirectional and other invisible characters (zero-width characters, tag characters, variation selectors), cut to a length limit; error details are cleaned the same way.

Limits of this: an agent that has a shell runs as you, so it can still read `daemon.token` from the runtime directory and speak as the user. KRAKEN does not confine your agent (see below); use the agent's own sandbox for that. The credential split protects the case where an agent is steered only through KRAKEN's tools.

## Generated code (rewrite)

The rewrite commands (`rewrite_function`, `rewrite_export`) build and run Rust that a model wrote. That code is untrusted, so it runs only in a confined child process: the build can read only the Rust toolchain and system libraries, the file system is writable only in a private scratch directory, there is no network (namespace or seccomp) and no `fork` in the test runner, memory, CPU and output size are limited, and the environment is scrubbed. A `syn`-based allowlist (a safe computing subset, no `extern` blocks, file, network, process or environment APIs, inline assembly or `include!`) refuses escapes before anything is built; the sandbox does not rely on it. If the host cannot enforce this (Linux with Landlock ABI 4 or newer is required), the commands refuse to run; there is no flag to run generated code unconfined. The original program is never executed natively: single functions run under emulation, and their output is compared with the generated code's. Accepting a rewritten function is something only you can do, not an agent. The exported workspace is code you build and run yourself, outside this sandbox, so read it first. Model calls send decompiled code to the provider you configured. See [the rewrite pipeline](design/0013-rewrite-pipeline.md).

## What is protected

- Your files, keys and network from a malicious binary exploiting the parser.
- Your own work from an AI agent's mistakes: edits are logged, attributed and undoable, and an agent cannot overwrite your edits without your approval.
- Agents from text in the binary: it is marked untrusted and stripped of control characters.

## What is not

- **KRAKEN never runs the binary natively.** The rewrite pipeline emulates single functions of it. If you run it yourself, that is up to you (use a VM).
- **Confinement exists only on Linux** in 0.1a. macOS and Windows are not supported yet.
- **A partly enforced Landlock ruleset is accepted** on older kernels. Network and filesystem limits may then be weaker.
- **Prompt injection cannot be ruled out.** The measures reduce the risk.
- **Your AI agent is not sandboxed by KRAKEN.** Claude Code, Codex and similar tools have their own shell and file access. A binary that tricks the agent into using those tools is outside KRAKEN's protection, and an agent with a shell can read the daemon's user token (same user). Use the agent's own permission prompts and sandboxes.
- **A local model's engine is not sandboxed.** `kraken infer` runs `llama-server` (or an engine from a manifest) as your user, listening on 127.0.0.1 only, with a filtered environment (no API keys). Run only engine programs and model files you trust, and only manifests you wrote or reviewed: a manifest names a program to run. See [Running a model on this computer](local-models.md).
- **Project folders are trusted.** Do not open a project folder from someone you do not trust.

> **Warning (placeholder).** In a future release, KRAKEN's GUI will start terminal agents over ACP and show a one-time notice that they run outside KRAKEN's safety model. That feature does not exist in 0.1a.

See the design decisions on [sidecar confinement](design/0007-sidecar-confinement.md) and [agent safety](design/0005-agent-safety.md).

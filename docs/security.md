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
- **On Linux, agents cannot read the user token.** KRAKEN starts each terminal agent (and so the `kraken mcp` server the agent starts) in an unprivileged sandbox of namespaces: a user namespace with your own uid and no capabilities, a mount namespace in which an empty `tmpfs` replaces the runtime directory (only the daemon socket, `daemon.json` and `agent.token` are mounted back in), and a PID namespace with its own `/proc`, so the agent cannot reach the real directory through `/proc/<pid>/root` either. `no_new_privs` is set. Your home directory, tools and network stay as they are, so the agent keeps working normally. `daemon.token` simply does not exist for the agent. The sandbox needs no root and no helper program, but the kernel must allow unprivileged user namespaces; some distributions restrict them (Ubuntu 24.04 with AppArmor, Docker without `--privileged`, `kernel.unprivileged_userns_clone=0`). Where it is unavailable, KRAKEN does not tell the agent's MCP server where the daemon is (the agent has no daemon access, and so no KRAKEN daemon tools), logs a warning and shows it in the session. In that case an agent with a shell is **not** confined and can still find `daemon.token` at its default location. A side effect of the sandbox: setuid programs such as `sudo` do not work inside an agent.
- **Limits.** The daemon caps open connections (128), connections that have not said hello (16), requests in flight per connection (64) and in total (256), and accepts only small frames before the hello.
- **Quotas follow the agent, not the connection.** An agent's cap on auto-applied edits is counted for the whole agent credential in a project, so reconnecting does not start a new budget.
- **Text from the binary and the engine** reaches agents wrapped as untrusted and stripped of control, bidirectional and other invisible characters (zero-width characters, tag characters, variation selectors), cut to a length limit; error details are cleaned the same way.

Limits of this: the confinement of the user token is Linux only for now. On macOS and Windows, and on Linux machines that refuse unprivileged namespaces, an agent that has a shell runs as you and can still read `daemon.token` from the runtime directory and speak as the user. The sandbox does not otherwise restrict the agent: it can still read and change your files, which is why it asks first. If the daemon restarts while an agent is running, that agent's sandbox still holds the old socket; end the session and start it again.

## Generated code (rewrite)

The rewrite commands (`rewrite_function`, `rewrite_export`) build and run Rust that a model wrote. That code is untrusted, so it runs only in a confined child process: the build can read only the Rust toolchain and system libraries, the file system is writable only in a private scratch directory, there is no network (namespace or seccomp) and no `fork` in the test runner, memory, CPU and output size are limited, and the environment is scrubbed. A `syn`-based allowlist (a safe computing subset, no `extern` blocks, file, network, process or environment APIs, inline assembly or `include!`) refuses escapes before anything is built; the sandbox does not rely on it. If the host cannot enforce this (Linux with Landlock ABI 4 or newer is required), the commands refuse to run; there is no flag to run generated code unconfined. Single functions of the original run under emulation, and their output is compared with the generated code's. `rewrite_program` additionally runs the whole original program natively, to compare it with the Rust program: in the same kind of confinement as the generated code (read-only system files and a private working directory, no network, no `fork`, memory, CPU and output limits, scrubbed environment), on the arguments and input of the test cases. That is a sandbox, not a virtual machine: the kernel is shared. A call made by an agent or over MCP asks for your approval first; `build: false` runs nothing. Accepting a rewritten function is something only you can do, not an agent. The exported workspace is code you build and run yourself, outside this sandbox, so read it first. Model calls send decompiled code to the provider you configured. See [the rewrite pipeline](design/0013-rewrite-pipeline.md).

## What is protected

- Your files, keys and network from a malicious binary exploiting the parser.
- Your own work from an AI agent's mistakes: edits are logged, attributed and undoable, and an agent cannot overwrite your edits without your approval.
- Agents from text in the binary: it is marked untrusted and stripped of control characters.

## What is not

- **KRAKEN runs the binary natively only in `rewrite_program`**, confined as described above and never without your approval when an agent asks. A confined process shares the kernel, so for malware run the analysis in a VM. Everything else emulates single functions of it. If you run it yourself, that is up to you (use a VM).
- **Confinement exists only on Linux** in 0.1a. macOS and Windows are not supported yet.
- **A partly enforced Landlock ruleset is accepted** on older kernels. Network and filesystem limits may then be weaker.
- **Prompt injection cannot be ruled out.** The measures reduce the risk.
- **Your AI agent is not sandboxed by KRAKEN.** Claude Code, Codex and similar tools have their own shell and file access. A binary that tricks the agent into using those tools is outside KRAKEN's protection, and, on macOS, Windows and Linux machines without unprivileged namespaces, an agent with a shell can read the daemon's user token (same user; on other Linux machines it is hidden from the agent, see above). Use the agent's own permission prompts and sandboxes.
- **A local model's engine is not sandboxed.** `kraken infer` runs `llama-server` (or an engine from a manifest) as your user, listening on 127.0.0.1 only, with a filtered environment (no API keys). Run only engine programs and model files you trust, and only manifests you wrote or reviewed: a manifest names a program to run. See [Running a model on this computer](local-models.md).
- **Project folders are trusted.** Do not open a project folder from someone you do not trust.

> **Terminal agents as the assistant.** When you choose Claude Code, Codex or Gemini CLI as the assistant (in Settings > AI or in `config.toml`), KRAKEN shows a one-time notice that the agent runs outside KRAKEN's safety model, asks before it answers an agent's permission request for one of the agent's own tools, and answers requests for KRAKEN's own tools by the registry's policy. See [The built-in assistant](assistant.md#terminal-agents).

See the design decisions on [sidecar confinement](design/0007-sidecar-confinement.md) and [agent safety](design/0005-agent-safety.md).

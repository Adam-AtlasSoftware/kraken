# KRAKEN

**Take a program apart and understand it, with a helping hand.** KRAKEN is an open-source reverse-engineering workbench built on Ghidra's analysis engine. You, your scripts and AI agents all work on the same project through one set of commands, and every edit is logged, attributed and undoable. You do not need to know reverse engineering to start: the app explains terms as you go and the [tutorial](docs/tutorial.md) walks you through a first session. The long-term goal is Rust rewrites of binaries, function by function, checked against the original.

![KRAKEN with a stripped program opened: function list, decompiler, hex, listing and cross-references](docs/images/tutorial/hero.png)

*A real project: `stripped_calc-O2-stripped` from this repository, after a few functions were named.*

## What it does

**Analyze**
- Finds functions and decompiles them to C-like code with Ghidra, for native ELF, PE and Mach-O programs.
- Listing, hex, control-flow graph, cross-references, strings, imports and exports, memory map.
- Rename functions, set types and comments. Search, filter and jump between views.

**AI**
- Built-in assistant: explain a function, a guided first look at a program, name suggestions that you review before anything changes, and an offline glossary.
- Works with a model on your computer (Ollama, LM Studio, llama.cpp, or one KRAKEN runs for you) or a cloud provider.
- Terminal agents (Claude Code, Codex, Gemini CLI) can run inside the app or connect from outside over MCP.

**Automate**
- One command registry drives the CLI, the MCP server, the GUI and the agents, so they cannot drift apart.
- `--json` output for scripts, a Python module, and a background daemon that keeps projects warm.
- Every edit is in a log with its author, with per-change and per-agent-run undo.

**Rewrite**
- Translate one function at a time to Rust, run the original under emulation and the Rust side by side, and see the smallest input where they disagree.
- Plan the order (callees first), accept verified functions yourself, export a Cargo workspace.

## Status

KRAKEN is **pre-alpha** (0.1a). Expect rough edges and breaking changes.

| | Linux x86_64 | macOS (Apple silicon) | Windows x86_64 |
|---|---|---|---|
| CLI, MCP server, GUI | Works | Builds, experimental | Builds, experimental |
| Analysis with Ghidra (`kraken setup`) | Works | Not yet | Not yet |
| Sandbox around Ghidra | Landlock | Not yet | Not yet |
| Local models | Works | Builds | Builds |
| Rewrite pipeline | Works (needs Landlock and a model) | Refuses to run | Refuses to run |

"Builds" means the code compiles and is checked in CI, not that the whole product has been proven there. Linux is the platform to use today.

## Quick start

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
kraken setup                                              # downloads Ghidra and a JDK once
kraken project-create --binary corpus/bin/stripped_calc-O2-stripped --project ~/kraken-projects/calc
kraken analyze --project ~/kraken-projects/calc
kraken list-functions --project ~/kraken-projects/calc --limit 20
kraken-gui                                                # or open the project in the app
```

The practice programs are in `corpus/bin/` of a checkout. To build from source instead, see [Install](docs/install.md).

Connect an agent: `claude mcp add kraken -- kraken mcp --project ~/kraken-projects/calc`.

## Documentation

Start with the **[tutorial: your first reverse-engineering session](docs/tutorial.md)**.

- [Install](docs/install.md) and [Getting started (terminal)](docs/getting-started.md)
- [Concepts for newcomers to reverse engineering](docs/concepts.md)
- [The built-in assistant](docs/assistant.md) and [running a model on this computer](docs/local-models.md)
- [Connecting AI agents (MCP)](docs/mcp.md) and [terminal agents](docs/agents.md)
- [Scripting with the CLI](docs/cli.md) and [Python](docs/python.md)
- [Security](docs/security.md)
- [Command reference](docs/reference/commands.md)
- [Design decisions](docs/design/README.md)

Build the book with `mdbook build docs`. The command reference is generated: run `cargo xtask docs` after changing a command.

## Safety model

Binaries you analyse are untrusted. Ghidra runs in a separate process confined with Landlock on Linux: no network, writes only to a throwaway home and the project folder, and a scrubbed environment. KRAKEN never runs the program you open. Everything that comes from the file (names, strings, comments, decompiled text) is handed to AI models only as clearly marked, untrusted data, never as instructions. Agent writes are additive or proposals: an agent may add a name to something still called `FUN_...` or add a comment, within a per-run cap, while anything that would overwrite your work waits for you to accept it. Code a model writes for the rewrite pipeline builds and runs only in a sandbox, and only you can accept it. See [Security](docs/security.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Third-party notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Use KRAKEN only on software you are permitted to analyse.

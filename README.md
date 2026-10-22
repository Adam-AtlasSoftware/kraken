# KRAKEN

**Take a program apart and understand it, with a helping hand.** KRAKEN is an open-source reverse-engineering workbench built on Ghidra's decompiler, with a Java-free native engine and an optional full Ghidra engine. You, your scripts and AI agents all work on the same project through one set of commands, and every edit is logged, attributed and undoable. You do not need to know reverse engineering to start: the app explains terms as you go and the [tutorial](docs/tutorial.md) walks you through a first session. The long-term goal is Rust rewrites of binaries, function by function, checked against the original.

![KRAKEN with a stripped program opened: function list, decompiler, hex, listing and cross-references](docs/images/tutorial/hero.png)

*A real native-engine project: `stripped_calc-O2-stripped` from this repository, after a few functions were named.*

## What it does

**Analyze**
- Finds functions and decompiles them to C-like code with Ghidra's decompiler: through the native engine (no Java; ELF and Windows PE, x86 and x86-64) or the optional Ghidra engine (ELF, PE and Mach-O, many processors).
- Listing, hex, control-flow graph, cross-references, strings, imports and exports, memory map.
- Rename functions, set types and comments. Search, filter and jump between views.

**Patch**
- Change a program's bytes: type a new instruction and KRAKEN assembles it, or edit the decompiled C and let the assistant work out the smallest machine-code change.
- Run the original and the patched program side by side in a sandboxed emulator before anything is written, then export a patched copy. The original file is never touched.
- Every patch is an edit in the history, so an assistant's patches can be reviewed and undone like anything else.

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
| Native engine, no Java (`kraken setup --native`) | Works (ELF and PE) | Not yet | Not yet |
| Analysis with Ghidra (`kraken setup`) | Works | Not yet | Not yet |
| Sandbox around Ghidra | Landlock | Not yet | Not yet |
| Local models | Works | Builds | Builds |
| Rewrite pipeline | Works (needs Landlock and a model) | Refuses to run | Refuses to run |

"Builds" means the code compiles and is checked in CI, not that the whole product has been proven there. Linux is the platform to use today.

## Install

**Linux x86_64** (no Java needed: the native engine and its processor files are in the release):

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
```

The script checks the download against the release's `SHA256SUMS`, needs no `sudo` and installs into `~/.local`. Or take the AppImage from the [latest release](https://github.com/Adam-AtlasSoftware/kraken/releases/latest) (`chmod +x KRAKEN-*.AppImage`, then run it; `./KRAKEN-*.AppImage kraken --help` runs the command line), or on Arch Linux install `kraken-workbench-bin` from the AUR. Windows and macOS archives are on the releases page too, and are experimental (see [Status](#status)). [Install](docs/install.md) has the details and the build from source.

## Quick start

```sh
kraken project-create --binary /usr/bin/ls --project ~/kraken-projects/ls
kraken analyze --project ~/kraken-projects/ls
kraken list-functions --project ~/kraken-projects/ls --limit 20
kraken-gui                             # or open the app and pick the project
```

New projects use the native engine when it can open the file, else the optional Ghidra engine (Mach-O, other processors, Windows debug information), which `kraken setup` downloads with a JDK on first use. The [native engine page](docs/native-engine.md) compares the two. The practice programs in [`corpus/bin/`](corpus/bin) are a good start, and the [tutorial](docs/tutorial.md) walks through a first session.

Connect an agent: `claude mcp add kraken -- kraken mcp --project ~/kraken-projects/ls`.

### From source

You need Rust and a C++ compiler:

```sh
git clone https://github.com/Adam-AtlasSoftware/kraken && cd kraken
cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native -p kraken-emu
export PATH="$PWD/target/release:$PATH"
kraken setup --native                  # once: fetches the pinned sources, compiles the Sleigh files (about a minute)
```

## Documentation

Start with the **[tutorial: your first reverse-engineering session](docs/tutorial.md)**.

- [Install](docs/install.md) and [Getting started (terminal)](docs/getting-started.md)
- [Concepts for newcomers to reverse engineering](docs/concepts.md)
- [The built-in assistant](docs/assistant.md) (an AI model or a terminal agent such as Claude Code) and [local models on this computer](docs/local-models.md)
- [Connecting AI agents (MCP)](docs/mcp.md)
- [Scripting with the CLI](docs/cli.md) and [Python](docs/python.md)
- [Security](docs/security.md)
- [Command reference](docs/reference/commands.md)
- [Design decisions](docs/design/README.md)

Build the book with `mdbook build docs`. The command reference is generated: run `cargo xtask docs` after changing a command.

## Safety model

Binaries you analyse are untrusted. Ghidra and the native engine's decompiler each run in a separate process confined with Landlock on Linux: no network, writes only to a throwaway home and the project folder, and a scrubbed environment. KRAKEN runs the program you open only when you ask for a whole-program rewrite, confined like the rest and after asking you. Everything that comes from the file (names, strings, comments, decompiled text) is handed to AI models only as clearly marked, untrusted data, never as instructions. Agent writes are additive or proposals: an agent may add a name to something still called `FUN_...` or add a comment, within a per-run cap, while anything that would overwrite your work waits for you to accept it. Code a model writes for the rewrite pipeline builds and runs only in a sandbox, and only you can accept it. See [Security](docs/security.md).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE). Third-party notices are in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Use KRAKEN only on software you are permitted to analyse.

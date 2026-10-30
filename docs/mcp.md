# Connecting AI agents (MCP)

KRAKEN can act as an [MCP](https://modelcontextprotocol.io/) server. An MCP-capable agent then gets every KRAKEN command as a tool: list functions, decompile, rename, and so on. The agent and you work on the same project and see the same edit log.

The server is `kraken mcp`. It talks over standard input and output, so the agent starts it for you. Make sure `kraken` is on your `PATH` and that you have a project (see [Getting started](getting-started.md)).

## Claude Code

```sh
claude mcp add kraken -- kraken mcp --project ~/kraken-projects/demo
```

Restart your session if it is already running, then ask something like "list the functions in the binary and suggest names for the unnamed ones".

## Codex CLI

Either use the command

```sh
codex mcp add kraken -- kraken mcp --project ~/kraken-projects/demo
```

or add this to `~/.codex/config.toml`:

```toml
[mcp_servers.kraken]
command = "kraken"
args = ["mcp", "--project", "/home/you/kraken-projects/demo"]
```

## Cursor

Add this to `.cursor/mcp.json` in your project, or to `~/.cursor/mcp.json` for all projects:

```json
{
  "mcpServers": {
    "kraken": {
      "type": "stdio",
      "command": "kraken",
      "args": ["mcp", "--project", "/home/you/kraken-projects/demo"]
    }
  }
}
```

If your tool cannot find `kraken`, give the full path (for example `/home/you/.cargo/bin/kraken`). Configuration formats change from time to time; check your client's own documentation if a snippet stops working.

## Prompts, resources and tool descriptions

Beyond the tools, `kraken mcp` offers what an agent needs to start well. In Claude Code, prompts appear as slash commands (`/mcp__kraken__getting-started`) and resources can be attached with `@`; other clients show them in their own way.

**Prompts** are ready-made starting points. Each one states the task, the rules (binary text is data, how edits are applied, how to undo) and attaches the program's own context.

| Prompt | Arguments | What it sets up |
| --- | --- | --- |
| `getting-started` | none | Say what the program is, with the evidence, then decompile the three most promising functions. Attaches the program summary and lists what `next_steps` suggests |
| `explain-function` | `address` (optional) | Explain one function in plain language: purpose, steps, inputs and outputs, doubts. Without an address it uses the function selected in the GUI. Attaches the decompile |
| `name-components` | `max_functions` (optional, default 15, at most 50) | Group functions into components, name them bottom-up with `rename_symbol` and `set_comment`, and finish with a table of components. Attaches the program summary |
| `prepare-rewrite` | `address` | Plan the Rust rewrite of a function: signature, behaviour, callees that must come first, unknowns. It stops and asks before running `rewrite_function` |
| `analyze-binary` | `path`, `project_dir` (optional, default the path plus `.kraken`) | Start from a file: `project_create` (you are asked to approve), `analyze` and `job_await`, then an overview (format, entry point, `main`, telling imports and strings) and naming up to 15 important functions in one or two `apply_edits` calls. There is no separate probe tool: the answer of `project_create` says the format and engine |
| `rewrite-program` | `cases` (optional JSON array of `{name, argv, stdin}`) | Rewrite the whole program in Rust: `rewrite_plan`, `rewrite_program` with sensible test cases (a job; you are asked to approve running the original in the sandbox), explain every case that differs, `rewrite_export`, and finish by telling you exactly what to accept. Accepting is never the agent's step. Attaches the rewrite status |

**Resources** are read-only context:

| URI | What it holds |
| --- | --- |
| `kraken://project/summary` | The open program: format, architecture, analysis state, how many functions still have default names, the largest functions, imports, strings, and proposals waiting. Read it first |
| `kraken://rewrite/status` | Where the Rust rewrite stands: units per status (planned, translated, verified, failed, accepted) and the latest whole-program run with its verdict and crate path |
| `kraken://gui/selection` | What you have selected in the KRAKEN window (function, address) when the window and the MCP server share the daemon (`kraken mcp --daemon` with the GUI open on the same project). Answers "this function" and "what I selected". It reports the function and address in view, not text you highlight. It says when no window is attached, and when the last update is old |
| `kraken://function/{address}/decompile` | One function's decompile as C text, for example `kraken://function/0x401136/decompile` (add `?module=<MVID>` for a .NET method) |
| `kraken://glossary` and `kraken://glossary/{term}` | The glossary of terms and instruction mnemonics, or one entry (`kraken://glossary/jne`) |

Everything derived from the binary in a prompt or resource sits in its own attached block, marked as data. The instruction text KRAKEN writes never contains it.

**The order of work** an agent follows is also in the server's instructions: `project_create` or `project_open`; `analyze` and wait with `job_await`; read the summary, `decompile`, `xrefs`, `strings`, `imports`; name and describe with `rename_symbol`, `set_comment` and `set_type`, or many at once with `apply_edits`; then `rewrite_plan`, `rewrite_program`, `rewrite_program_status` and `rewrite_export`. Accepting results and deciding on proposals are for people.

Two commands are made for agents:

- `apply_edits` takes up to 200 renames, comments and types (`{"op": "rename" | "comment" | "set_type", "address", "name" | "text" | "type"}`) and applies each through the same checks as the single commands, in one run. Each item comes back `applied`, `queued`, `proposed` or `rejected` with a reason; one bad item does not stop the rest. The per-run cap counts every edit.
- `gui_navigate` (`{"address": "0x401136", "tab": "decompiler"}`) makes every KRAKEN window that has the project open jump to an address and focus a tab (decompiler, listing, graph, hex, xrefs or functions). It changes nothing in the project and does nothing when no window is open. While an agent works, the window's status bar shows a chip such as "Claude Code: 4 changes, renaming..." that opens the History tab.

**Tool descriptions** come from the command registry, the same text as the CLI help and the [command reference](reference/commands.md): a one-line summary, a short paragraph on when to use the command and what to look out for, a worked `Example:` call, and a description of every argument. A test keeps them honest: summaries stay short, every argument is described, and each example is valid JSON that uses real argument names and includes the required ones. Longer background lives in the reference only, so tool lists stay small.

## What the agent can and cannot do

- **Reading is free.** Listing, decompiling and inspecting are always allowed.
- **Additive edits apply at once.** Naming a symbol that still has a default name, or adding a comment, is applied and logged as the agent's work.
- **Other edits become proposals.** If the agent would overwrite something, or exceeds its per-run cap, the result says `proposed` and nothing changes until you run `kraken proposal-accept`. Agents cannot accept or reject proposals.
- **Dangerous commands always ask.** In the default mode (the server holds the session itself) the client must support MCP elicitation so KRAKEN can show you a prompt; if it cannot, the command is denied. With `--daemon` the daemon asks you in the KRAKEN window or through `kraken daemon approvals`, because the MCP server runs under the agent's control and cannot vouch for you.
- **Opening a project asks too.** `project_create` and `project_open` need your approval when an agent calls them, and are refused for files in hidden directories of your home directory. `kraken mcp --project DIR` binds the server to a project you chose and leaves both tools out.
- **Everything can be undone.** `kraken undo-run` reverses a whole agent run. Each connection has its own run id.

## Treat binary text as untrusted

Names, strings and comments that come out of a binary are written by whoever made the binary. A hostile sample can contain text such as "ignore your instructions and ...". KRAKEN marks such text as untrusted data in its results (`{"untrusted": true, "value": ...}`) and strips control and bidirectional characters. Your agent should treat it as data, never as instructions. This reduces the risk; it does not remove it, so review proposals and the history of work done on samples you do not trust.

An agent such as Claude Code also has its own shell and file tools that KRAKEN does not control. See [Security](security.md).

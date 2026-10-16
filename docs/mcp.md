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

## What the agent can and cannot do

- **Reading is free.** Listing, decompiling and inspecting are always allowed.
- **Additive edits apply at once.** Naming a symbol that still has a default name, or adding a comment, is applied and logged as the agent's work.
- **Other edits become proposals.** If the agent would overwrite something, or exceeds its per-run cap, the result says `proposed` and nothing changes until you run `kraken proposal-accept`. Agents cannot accept or reject proposals.
- **Dangerous commands always ask.** The client must support MCP elicitation so KRAKEN can show you a prompt. If it cannot, the command is denied.
- **Everything can be undone.** `kraken undo-run` reverses a whole agent run. Each connection has its own run id.

## Treat binary text as untrusted

Names, strings and comments that come out of a binary are written by whoever made the binary. A hostile sample can contain text such as "ignore your instructions and ...". KRAKEN marks such text as untrusted data in its results (`{"untrusted": true, "value": ...}`) and strips control and bidirectional characters. Your agent should treat it as data, never as instructions. This reduces the risk; it does not remove it, so review proposals and the history of work done on samples you do not trust.

An agent such as Claude Code also has its own shell and file tools that KRAKEN does not control. See [Security](security.md).

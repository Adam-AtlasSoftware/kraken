# Terminal agents (Claude Code, Codex, Gemini CLI)

KRAKEN can start a coding agent that you already use in the terminal and connect it to KRAKEN's
tools. The agent can then read the program you are studying, search it, rename things and add
comments, with every change logged under its name and undoable like any other KRAKEN change.

KRAKEN talks to these agents with the Agent Client Protocol (ACP), the same protocol code editors
use. You can start them from the **Agents** tab of the GUI or from the command line.

## Read this first: what KRAKEN does not protect

Terminal agents bring their own tools. Besides KRAKEN's tools they can usually run shell commands
and read, change or delete files on your computer, as you. KRAKEN does not sandbox them and cannot
undo what they do to your files. KRAKEN only logs and undoes changes made through its own tools.

- Use an agent you trust, on a project you can afford to lose.
- Read every permission request before you approve it.
- A program you analyse can be hostile. The agent reads it, and malicious text inside a binary can
  try to talk the agent into running commands.
- KRAKEN never gives agents its own settings or keys. Each agent signs in by itself.

KRAKEN shows this warning the first time you run an agent and remembers that it did
(`~/.config/kraken/acp-warning.json`). It does not block you.

## Quick start

```sh
kraken agents list                      # what works on this computer
kraken agents setup claude              # download what is missing (asks first)
claude                                  # sign in once with the agent's own program
kraken agents run claude --project ~/kraken-projects/sample "What does main do?"
```

`kraken agents list` shows one of four states per agent:

| State | Meaning |
| --- | --- |
| `detected` | Ready. Start it with `kraken agents run`. |
| `available` | Not installed yet; `kraken agents setup <id>` installs it. |
| `missing` | Cannot run until you install something; the reason says what. |
| `unsupported` | This computer cannot run it (for example RISC-V 64). |

## The agents

| Id | Agent | How KRAKEN starts it |
| --- | --- | --- |
| `claude` | Claude Code | the `claude-agent-acp` adapter, installed by `kraken agents setup claude` |
| `codex` | Codex | the `codex-acp` adapter, installed by `kraken agents setup codex` |
| `gemini` | Gemini CLI | your own `gemini --acp` if `gemini` is on `PATH`, else installed by `setup` |

You need an account with the agent's vendor. Sign in with the agent's own program first (`claude`,
`codex login`, `gemini`). If you have not, KRAKEN says so: "needs you to sign in first".

## Node.js

The adapters are JavaScript and need Node.js (22 or newer for Claude Code). KRAKEN looks for one on
your `PATH`. If there is none, `kraken agents setup` offers to download a pinned Node.js 24 LTS into
KRAKEN's own folder (`~/.local/share/kraken/agents`) on Linux x86-64, macOS Apple silicon and
Windows x86-64. On other systems install Node.js yourself. Nothing is installed system-wide.

`setup` asks before it downloads anything (pass `--yes` to skip the question), and tells you what
and from where:

- Node.js comes from nodejs.org over HTTPS. KRAKEN checks the download against a SHA-256 that is
  built into KRAKEN before it unpacks a single file.
- The adapter comes from the npm registry with a lockfile that is built into KRAKEN: exact
  versions and an integrity hash for every package. Install scripts are switched off
  (`--ignore-scripts`); none of the three adapters needs them. Your own `.npmrc` is ignored.

## Running an agent

```sh
kraken agents run <id> --project <dir> "<prompt>"
```

The agent's answer streams to stdout. Tool calls, its plan and permission answers go to stderr, so
`kraken agents run ... > answer.md` keeps only the answer. `--json` prints one JSON event per line
instead.

The agent is started in the project folder with a single KRAKEN tool server attached
(`kraken mcp --project <dir>`; add `--daemon` to use `kraken mcp --daemon`, which shares the open
project and Ghidra with the GUI and the CLI). KRAKEN's tools are described in
[Connecting AI agents (MCP)](mcp.md).

**Permission requests.** When the agent wants to do something that needs your approval, KRAKEN
shows what and offers the agent's choices. Type the number of your choice; anything else declines.
Without a terminal, requests are declined. `--auto-approve` allows everything and is dangerous.
Press Ctrl-C to cancel the current turn.

KRAKEN advertises no file or terminal features to the agent; the agent uses its own for those.

## In the GUI

The **Agents** tab (next to Hex and Assistant) lists the terminal agents and runs them on the open
project.

- **The list** shows each agent as *Ready*, *Needs setup* (with the reason), *Not found* (with what
  to install) or *Not supported here* (this platform cannot run it). **Check again** looks again.
- **Set up...** shows exactly what would be downloaded (Node.js if needed, and the adapter, with
  sizes and sources) and asks before it fetches anything. Progress is shown while it works.
- **Start** shows the warning above the first time and only starts the agent after you press *I
  understand*. The acknowledgement is saved in the config folder, so you see it once.
- **The session** shows which agent (and model, when the agent says) is running. You type a prompt;
  the agent's words stream in. Tool calls appear as compact chips: *KRAKEN* chips are calls to
  KRAKEN's own tools, *agent tool* chips are the agent's own tools (shell, files), which KRAKEN does
  not sandbox. A permission request is an inline card with **Allow once** and **Deny**. **Stop**
  ends the current turn and withdraws waiting requests; **End session** closes the agent.
- With the daemon (the default) the agent gets `kraken mcp --daemon --project <dir>`, so its edits
  reach the window as they happen, with the usual notification and Undo. With `--no-daemon` the
  agent uses its own session on the project and the window refreshes when each turn ends.

## What the agent can see

KRAKEN builds the agent's environment from scratch. It gets `PATH`, `HOME`, locale, proxy and
certificate settings and the agent's own config-folder variable (`CLAUDE_CONFIG_DIR`,
`CODEX_HOME`, `GEMINI_CLI_HOME`). It does not get API keys, and nothing starting with `KRAKEN_`
ever. If you want an agent to use an API key from your environment, say so explicitly in
`~/.config/kraken/agents.toml`:

```toml
[env_allow]
claude = ["ANTHROPIC_API_KEY"]
```

## Other ACP agents

Any agent that speaks ACP over stdio can be added in `~/.config/kraken/agents.toml`:

```toml
[[agent]]
id = "goose"
name = "Goose"
command = "goose"
args = ["acp"]
env_allow = ["GOOSE_*"]      # optional
```

It then appears in `kraken agents list` and works with `kraken agents run goose ...`.

## Troubleshooting

- `needs you to sign in first`: run the agent's own program once and sign in.
- `did not answer within 60 seconds`: the agent printed something instead of speaking ACP; the
  last lines it wrote are shown. Run the agent's own program to see what is wrong.
- Agent still running after a crash: KRAKEN stops the agent and everything it started (SIGTERM,
  then SIGKILL) when the command ends, and the agent is killed if KRAKEN itself dies.

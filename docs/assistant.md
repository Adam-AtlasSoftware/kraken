# The built-in assistant

KRAKEN has a built-in assistant for people who are new to reverse engineering. It can explain a function in plain language, give you a guided first look at a program, suggest names for functions that still have generated names like `FUN_00401000`, and answer questions in a chat. It also has an offline glossary of reverse-engineering terms.

The assistant is a client like any other. It reads and edits the project through the same commands as the CLI and MCP server, so everything it does shows up in the edit log, and every run can be undone.

## Two kinds of assistant, one assistant

What answers the assistant can be either of two things, and you can swap one for the other at any time:

| | AI model | Terminal agent |
| --- | --- | --- |
| Examples | Ollama, LM Studio, llama-server, vLLM, Anthropic, OpenAI, Gemini | Claude Code, Codex, Gemini CLI (any ACP agent) |
| Where it runs | A server you point KRAKEN at: your computer or the cloud | A program on your computer that signs in by itself |
| What you need | A model name, and a key for cloud services | The agent's own account; Node.js for the adapters |
| Edits are logged as | `kraken-assistant` | the agent's own name (for example `claude-code`) |
| Besides KRAKEN's tools | nothing | its own tools (shell, files), outside KRAKEN's safety net |
| Good for | Quick answers, a local model that keeps code on your machine | A strong coding agent you already pay for |

Either one works everywhere the assistant does: the **Assistant** tab, **Explain**, the first-run overview, **Suggest names**, and `kraken explain`, `kraken overview` and `kraken auto-name`. The prompts are the same, the answers are parsed the same way (the same explanation card, overview card and name review), and the same approvals apply: a change that would overwrite something you wrote becomes a **proposal** that waits for you, whichever one proposed it.

**How to choose.** Start with a model if you want the assistant to stay inside KRAKEN's safety net, or to keep everything on your computer (a local model). Choose a terminal agent if you already use one, want its stronger reasoning, and accept the notice below. Nothing is lost by switching: the conversation on screen stays, and the new assistant is caught up from it on the next question.

### Choose it in the GUI

Open **Settings > AI** (Ctrl+,). One picker lists the AI models and, below them, the terminal agents with whether each can run here: *Ready*, *Needs setup*, *Not found* or *Not supported here*. Press **Save and use**; the choice is saved as the `[provider]` table of `config.toml`, so the CLI uses it too.

The **Assistant** tab always shows what is answering: the service or agent, the model (a terminal agent says which model it uses once it has started), and whether it runs on your computer, in the cloud, or is a terminal agent.

### Choose it in `config.toml`

Add one `[provider]` table to `~/.config/kraken/config.toml` (`KRAKEN_CONFIG` overrides the location). For a terminal agent:

```toml
[provider]
kind = "terminal_agent"
agent = "claude"          # claude, codex, gemini, or an id from agents.toml
# model = "..."           # optional: ask the agent for this model (see below)
# args = ["--flag"]       # optional: extra arguments for the agent
```

If no provider is configured, the assistant commands stop with an error that shows examples of both kinds.

## AI models

The model must be able to call tools. Examples, one at a time:

```toml
# Ollama (local; run `ollama serve` and `ollama pull <model>` first)
[provider]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3:14b"
```

```toml
# LM Studio (start its server from the Developer tab)
[provider]
kind = "openai_compatible"
base_url = "http://localhost:1234/v1"
model = "your-loaded-model"
```

```toml
# llama-server from llama.cpp (start it with --jinja so tool calls work)
[provider]
kind = "openai_compatible"
base_url = "http://localhost:8080/v1"
model = "local"
```

```toml
# Anthropic. The key stays in an environment variable, never in this file.
[provider]
kind = "anthropic"
api_key = { env = "ANTHROPIC_API_KEY" }
```

```toml
# OpenAI
[provider]
kind = "openai_compatible"
base_url = "https://api.openai.com/v1"
model = "gpt-4.1"
api_key = { env = "OPENAI_API_KEY" }
```

Local models keep everything on your machine. A cloud provider receives the decompiled code and names the assistant reads, so pick one you are comfortable sending that to. Every run prints the provider and model it used on stderr.

In **Settings > AI** you can press **Test connection** (one tiny request; failures are explained in plain words). API keys are never written to `config.toml`. Name an environment variable (read when KRAKEN starts), or paste the key: it is stored in `secrets.toml` next to `config.toml`, created with mode 0600 so only you can read it, and `config.toml` only points at it. The CLI commands read keys from environment variables only, so a pasted key works in the GUI but `kraken explain` needs the variable.

To run a model on your own computer, choose **+ Set up a model on this computer...** in the same list, which runs a four-step guided setup. Then the model is in the **On this computer** group. See [Local models on this computer](local-models.md) for setup, starting and stopping, several graphics cards and the title bar.

## Terminal agents

KRAKEN starts a coding agent that you already use in the terminal (Claude Code, Codex, Gemini CLI, or any agent that speaks the Agent Client Protocol, ACP) and connects it to KRAKEN's tools. The agent reads the program you are studying, searches it, renames things and adds comments through KRAKEN's MCP server (`kraken mcp`), as an agent: additive edits are applied, and anything that would overwrite your work becomes a proposal. Every change is logged under the agent's name and is undoable like any other KRAKEN change. For each assistant task KRAKEN starts the agent in the project folder, sends it the same task prompt a model would get, and reads its answer the same way.

### Read this first: what KRAKEN does not protect

Terminal agents bring their own tools. Besides KRAKEN's tools they can usually run shell commands and read, change or delete files on your computer, as you. KRAKEN does not sandbox them and cannot undo what they do to your files. KRAKEN only logs and undoes changes made through its own tools.

- Use an agent you trust, on a project you can afford to lose.
- Read every permission request before you approve it. In the GUI they are cards in the conversation with **Allow once** and **Deny**; unattended commands such as `kraken explain` deny them.
- A program you analyse can be hostile. The agent reads it, and malicious text inside a binary can try to talk the agent into running commands.
- KRAKEN never gives agents its own settings or keys. Each agent signs in by itself.

KRAKEN shows this notice once, the first time you pick or use an agent (in Settings, above the chat, or on the command line), and remembers that it did (`~/.config/kraken/acp-warning.json`). It does not block you; Settings and the chat just wait for you to press *I understand*.

A permission request for one of KRAKEN's own tools is answered by KRAKEN: the command registry's policy is what guards those. Requests for anything else (the agent's shell, its file tools) always go to you. A read-only task (explain, overview) also refuses KRAKEN tools that would change the project.

### Set it up

Setting an agent up (finding Node.js, installing the adapter) is the same from both places:

- **Settings > AI**: pick the agent, press **Set up...**. It shows exactly what would be downloaded (Node.js if needed, and the adapter, with sizes and sources), and asks before it fetches anything. **Test agent** then starts the agent without KRAKEN's tools and asks it for one word, so a missing sign-in shows up here and not mid-conversation.
- The terminal:

```sh
kraken agents list                      # what works on this computer
kraken agents setup claude              # download what is missing (asks first)
claude                                  # sign in once with the agent's own program
```

`kraken agents list` shows one of four states per agent:

| State | Meaning |
| --- | --- |
| `detected` | Ready. |
| `available` | Not installed yet; `kraken agents setup <id>` (or Set up in Settings) installs it. |
| `missing` | Cannot run until you install something; the reason says what. |
| `unsupported` | This computer cannot run it (for example RISC-V 64). |

| Id | Agent | How KRAKEN starts it |
| --- | --- | --- |
| `claude` | Claude Code | the `claude-agent-acp` adapter, installed by `kraken agents setup claude` |
| `codex` | Codex | the `codex-acp` adapter, installed by `kraken agents setup codex` |
| `gemini` | Gemini CLI | your own `gemini --acp` if `gemini` is on `PATH`, else installed by `setup` |

You need an account with the agent's vendor. Sign in with the agent's own program first (`claude`, `codex login`, `gemini`). If you have not, KRAKEN says so: "needs you to sign in first".

**Model and extra arguments.** `model` asks the agent for a model in the way that agent supports: Claude Code through `ANTHROPIC_MODEL`, Codex through `-c model="..."`, Gemini CLI through `--model`. A custom agent has no known way, so its model is left to the agent. `args` are appended to the agent's own arguments. Leave both out to let the agent choose.

### Node.js

The adapters are JavaScript and need Node.js (22 or newer for Claude Code). KRAKEN looks for one on your `PATH`. If there is none, setup offers to download a pinned Node.js 24 LTS into KRAKEN's own folder (`~/.local/share/kraken/agents`) on Linux x86-64, macOS Apple silicon and Windows x86-64. On other systems install Node.js yourself. Nothing is installed system-wide.

Setup asks before it downloads anything (`kraken agents setup` takes `--yes` to skip the question), and tells you what and from where:

- Node.js comes from nodejs.org over HTTPS. KRAKEN checks the download against a SHA-256 that is built into KRAKEN before it unpacks a single file.
- The adapter comes from the npm registry with a lockfile that is built into KRAKEN: exact versions and an integrity hash for every package. Install scripts are switched off (`--ignore-scripts`); none of the three adapters needs them. Your own `.npmrc` is ignored.

### What the agent can see

KRAKEN builds the agent's environment from scratch. It gets `PATH`, `HOME`, locale, proxy and certificate settings and the agent's own config-folder variable (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GEMINI_CLI_HOME`). It does not get API keys, and nothing starting with `KRAKEN_` ever. If you want an agent to use an API key from your environment, say so explicitly in `~/.config/kraken/agents.toml`:

```toml
[env_allow]
claude = ["ANTHROPIC_API_KEY"]
```

On Linux, KRAKEN starts the agent in a small sandbox (user, mount and PID namespaces, no root needed) that hides KRAKEN's runtime directory and the user token inside it. The agent's KRAKEN tool server still reaches the daemon, but only with the agent credential, which cannot approve anything. Everything else (your files, tools, network, sign-in) works as before. Two consequences: programs that need `sudo` or other setuid helpers do not work inside the agent, and if the daemon restarts the agent must be restarted too.

If your system does not allow unprivileged user namespaces, you get a warning (a note in the conversation, or on stderr), the agent gets no daemon connection, and it is not protected from reading the user token. On macOS and Windows this protection does not exist yet. See [Security](security.md).

### Other ACP agents

Any agent that speaks ACP over stdio can be added in `~/.config/kraken/agents.toml`:

```toml
[[agent]]
id = "goose"
name = "Goose"
command = "goose"
args = ["acp"]
env_allow = ["GOOSE_*"]      # optional
```

It then appears in `kraken agents list` and in the Settings picker, and `agent = "goose"` selects it.

### Raw sessions: `kraken agents run`

```sh
kraken agents run <id> --project <dir> "<prompt>"
```

This runs one prompt in an agent without the assistant's task prompts and result parsing: the agent's answer streams to stdout; tool calls, its plan and permission answers go to stderr (`--json` prints one JSON event per line). The agent gets `kraken mcp --project <dir>` (add `--daemon` for `kraken mcp --daemon`, which shares the open project and Ghidra with the GUI and the CLI). Permission requests are asked on the terminal (type the number of your choice; anything else declines; without a terminal they are declined; `--auto-approve` allows everything and is dangerous). Ctrl-C cancels the turn. KRAKEN's tools are described in [Connecting AI agents (MCP)](mcp.md).

### Troubleshooting

- `needs you to sign in first`: run the agent's own program once and sign in, then **Test agent** in Settings.
- `did not answer within 60 seconds`: the agent printed something instead of speaking ACP; the last lines it wrote are shown. Run the agent's own program to see what is wrong.
- Agent still running after a crash: KRAKEN stops the agent and everything it started (SIGTERM, then SIGKILL) when the command ends or the project closes, and the agent is killed if KRAKEN itself dies.

## Rewriting uses the same assistant

The rewrite pipeline (`rewrite_function`, its repair attempts, spec mode, and `rewrite_program`; see [ADR 0013](design/0013-rewrite-pipeline.md)) makes every model call through the same backends as the assistant: a model API or a terminal agent, chosen by the same `[provider]` table. A `kind = "terminal_agent"` provider therefore works for rewriting too, and so does any local or cloud model.

To use a different one for rewriting only, add an optional `[rewrite]` table. It takes exactly the keys of `[provider]` and, when present, replaces it for the rewrite commands (the assistant keeps using `[provider]`):

```toml
[provider]                 # the assistant: a local model
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3:14b"

[rewrite]                  # rewrites: Claude Code
kind = "terminal_agent"
agent = "claude"
```

`[rewrite]` alone also works. The file is read on every call, so a change applies to the next rewrite without restarting `krakend`. A rewrite with no provider anywhere stops with the same error that shows examples.

In the window, **Settings > AI > Rewriting** writes the `[rewrite]` table: "Use the assistant's model" (the default, no table) or its own model (an API with a model and the name of the environment variable that holds the key, a local model, or a terminal agent), and it shows which model each feature uses. The rewrite wizard's Check step can pick another model for one run without saving it. The rewrite commands take the same choice as arguments: `provider` (`rewrite`, the default, or `assistant` for `[provider]`) and `model` (another model name for this run only), so `kraken rewrite-function --address 0x401136 --model claude-haiku-4-5` tries a cheaper model once.

**What a terminal agent does here.** A rewrite request is plain text in, plain text out. KRAKEN starts the agent in a fresh, empty scratch folder (not the project), without the KRAKEN tool server, and sends it the same prompts a model gets, after a short note that this is a text-only request. The agent answers with the translation or the spec in the usual format: Rust between `<kraken-rust>` tags and the `<kraken-result>` block, or the Markdown spec. KRAKEN parses it, lints it, and builds and tests it in its own sandbox. The agent does not build or test anything, and it cannot write files or run commands for KRAKEN: every permission request for the agent's own tools (its shell, its file tools) is denied during a rewrite, with no prompt, and KRAKEN notes that it happened. A tool the agent may use without asking (by its own settings or an auto-accept mode) is outside what KRAKEN can stop, as everywhere else in this page. The scratch folder is only its working directory, not a sandbox: the prompt carries code and strings from the binary, so a tool the agent runs on its own can still read your files. If that matters for a binary, use a model API for `[rewrite]`, or run the agent with its tools turned off in its own settings. Each model call is a new agent session, so a repair attempt is a new request that carries the failed code and the counterexample, as it is for a model.

As with any terminal agent, the decompiled code of the functions being rewritten goes to the agent's service. Models served on your own computer keep it there.

## What costs money

Cloud models (Anthropic, OpenAI, Gemini and other API services) are billed per token by their provider. KRAKEN never calls a model by itself: only when you, or an agent you started, ask for AI work.

**When KRAKEN calls a model.** Every chat message, explanation and overview; Suggest names (`kraken auto-name`); every step of Automate (`kraken auto`); and in the Rust rewrite every translation, spec, test fix and repair. A rewrite tries up to 3 times per function, so rewriting a whole program takes about 3 requests per function plus the repair rounds: often around 60 requests. Evaluation runs (`kraken eval`) call it once per task step.

**What it costs.** Local models (Ollama, LM Studio, llama-server, `kraken infer`) are free. Terminal agents (Claude Code, Codex, Gemini CLI) are billed by their own subscription and report no tokens, so KRAKEN counts their calls and time only. For API models KRAKEN estimates the cost from the tokens the provider reports and a price table. The table has list prices of well-known models (estimates, they go stale); correct them or add your own model in config.toml:

```toml
[pricing]                                    # US dollars per million tokens
"claude-sonnet-5-5" = { input = 3.0, output = 15.0 }
"my-finetune" = { input = 0.5, output = 1.5 }
```

A name matches exactly or by its longest known start (`claude-sonnet-4-5-20250929` finds `claude-sonnet`). Money is always an estimate; your provider's bill is what counts.

**Before it starts.** Every way to start AI work shows an estimate first: the most model calls it can make, the model, and the cost range ("billed by your subscription" for a terminal agent). In the window that is a question with Start and Cancel; on the command line (`rewrite-function`, `rewrite-program`, `rewrite-spec`, `explain`, `overview`, `auto-name`, `auto`) the estimate is printed and you answer `y`. Without a terminal to ask on, these commands refuse unless you pass `--yes`. Free local models never ask. An agent working over MCP is asked to approve a whole-program rewrite (it runs the original program), and that question includes the estimate.

**While it runs.** A chip in the top bar and the status bar shows the feature, the model, the calls so far and the estimated cost. Click it for the **AI Activity** tab: running and recent AI work, who started it (you, the command line or an agent), its usage, and a **Stop** button each. A finished run leaves a notice with its totals. `kraken ai-jobs` lists the same, and the daemon publishes `ai_started`, `ai_progress` and `ai_done` events. Closing the project or quitting while AI work runs asks whether to stop it or leave it running in `krakend`, where it keeps costing until it ends.

**What was spent.** Every call is recorded in the project database (provider, model, feature, job or run, tokens, time, estimated cost), and the daily totals of all projects in `ai-usage-daily.json` in the KRAKEN data folder (`~/.local/share/kraken`). Read them with `kraken ai-usage` (this project), `kraken ai-usage --scope today` (all projects, today, UTC) or `kraken ai-usage --scope run --run-id job-3`.

**Limits.** Set them in **Settings > AI** or in config.toml:

```toml
[ai_limits]
max_calls_per_run = 200    # a run stops cleanly after this many model calls
max_cost_per_run = 5.0     # ... or once its estimated cost reaches this (US dollars)
daily_budget = 10.0        # no new AI work once today's estimated total reaches this
skip_confirm_under = 0.10  # start without asking when the estimate stays below this
```

A run that reaches a limit stops with a message saying which, and keeps what it finished (every translation attempt is stored as it is made). The daily budget refuses new AI work until the next day (midnight UTC), or until you raise it. Changes apply to the next model call, also in a running daemon.

## The assistant knows KRAKEN and can drive the window

Ask the assistant how KRAKEN itself works ("How do I set up a local model?", "What does Rewrite
do?") with **Help > Ask the assistant about KRAKEN**. It looks the answer up with `kraken_help`,
which searches the user guide in `docs/` and the glossary and returns short sections. A whole
page is the MCP resource `kraken://docs/{page}` (for example `kraken://docs/local-models`).

When you have the GUI open, an agent can also show you things through three commands (they work
the same over MCP, in the CLI and for the built-in assistant):

| Command | What it does |
|---|---|
| `ui_state` | The open tabs, the tab in front, the function and address in view, the selected text and the action ids `ui_action` accepts. `attached: false` when no GUI has the project open. |
| `ui_action` | Runs a GUI action by id (`show_history`, `go_to_main`, `search`...), opens a tab, or jumps to an address or function. Quit, close/open project, clear recent and delete are refused; you do those. |
| `ui_highlight` | Flashes a tab (or the function filter) with a short note for a few seconds. |

None of them changes the project; a GUI that is not open simply ignores them. The GUI publishes
its state to the daemon the same way it publishes the selection (`kraken://gui/selection`).

## Choose a model for each feature

The assistant and the rewrite pipeline each pick their own backend, and either can be a model API
in the cloud, a model on your computer, or a terminal agent:

- the assistant: `[provider]` (Settings > AI > Assistant);
- rewriting: `[rewrite]` (Settings > AI > Rewriting); without it the rewrite uses `[provider]`.

### Pick a model

In Settings > AI the model box has a **Look up models** button. KRAKEN asks the provider's
`/models` endpoint and lists what it offers in the drop-down; when the provider cannot be
reached it lists well-known Claude, Gemini and GPT ids instead and says so. The text box next to
it still takes any model name you type.

### Thinking effort

`[thinking]` sets how hard a model thinks (`off`, `low`, `medium`, `high`), per provider; Settings
> AI has a drop-down for the provider you use.

```toml
[thinking]
anthropic = "medium"          # extended thinking with a token budget
gemini = "low"                # thinkingBudget
openai_compatible = "high"    # reasoning_effort (leave unset for models without it)
"agent:claude" = "low"        # Claude Code: MAX_THINKING_TOKENS; "agent:codex": model_reasoning_effort
```

More thinking is slower and costs more. Gemini CLI has no such setting. For Anthropic, a request
that continues a tool call is sent without thinking, because the API wants the earlier thinking
blocks sent back and KRAKEN does not keep them.

### Terminal agent permissions

When a terminal agent asks to use one of its own tools, the Assistant tab shows a card with
**Allow once**, **Always for this tool** and **Deny**. "Always" adds the tool to the allow list
below. The `[permissions]` table decides without asking:

```toml
[permissions]
default = "ask"           # ask | allow | deny, for a tool no list names
allow = ["read", "edit"]  # tool kinds, or the first word of a tool's title ("web*" matches a prefix)
deny = ["delete"]         # a deny entry always wins
```

KRAKEN's own dangerous commands keep asking whatever the table says; the table can only refuse
them. The rewrite pipeline never reads this table: its terminal agent runs with every request
denied.

## Local models on your computer

Local models are set up in **Settings > AI**: open the model list and choose **+ Set up a model on this computer...**. The guided setup checks the graphics card and memory, suggests a model that fits, downloads it and tests it. Once it is set up, the model appears under **On this computer** in the list used by the Assistant and by Rewriting. Start and stop it there, and choose whether it starts when KRAKEN opens. The full guide is in [Local models on this computer](local-models.md).

The same steps are available to agents and scripts:

- `local_model_recommend` reads the graphics card, video memory, RAM and free disk, and recommends an engine and a model that fits.
- `local_model_setup` downloads and sets up a model from the catalog. It asks first, like `rewrite_program` does before it runs the original program, and only catalog models can be downloaded (the argument is a catalog id, never a URL).
- `local_model_list`, `local_model_start`, `local_model_stop`, `local_model_status` and `local_model_hold` / `local_model_release` manage the models that are set up. Starting, holding, releasing and stopping run or end a program, so they are not read-only: the assistant is not offered them unless a task allows it, and MCP clients see them as tools that change things.

## Commands

All of them take `--project <dir>` (or `KRAKEN_PROJECT`) like the other commands, and use whatever the `[provider]` table selects, a model or a terminal agent. Text streams to standard output and tool calls go to standard error, so you can see what the assistant looked at. With `--json`, standard output holds one structured result instead (it says which kind of backend answered).

### `kraken explain <address>`

Explains the function at an address: a short explanation, what it does step by step, and names worth considering. It cannot change the project.

```sh
kraken explain 0x401000
```

### `kraken overview`

A guided first look: what the program appears to be, its main parts, a few functions to open first and why, and what to do next. It starts from `project_info`, so run `kraken analyze` first. Where this build of KRAKEN has no command for something it would like to check (strings, imports, cross-references), the assistant says so and the result lists it under "Could not check" rather than guessing.

### `kraken auto-name [--limit N] [--dry-run]`

Looks at up to N functions (default 10, at most 50) that still have default names, and suggests names and short comments with the evidence for each.

- `--dry-run` only suggests. A model is not even offered the commands that write; a terminal agent is told not to write.
- Without it, suggestions are written as an agent (`kraken-assistant` for a model, the agent's own name for a terminal agent). Following the usual agent rules, a rename of a function that still has its default name and a new comment are applied right away; anything that would overwrite something a person wrote becomes a **proposal** that waits for you (`kraken proposals-list`, then `kraken proposal-accept`). A model run makes at most two edits per function it was allowed to look at; a terminal agent's edits are bounded by the registry's per-run cap.
- Undo everything a run did with `kraken undo-run --run-id <id>`. The run id is printed at the end.

Each suggestion carries a confidence label of low, medium or high. KRAKEN works it out itself by counting how many independent kinds of evidence agree (strings the function uses, library functions it calls or imports, how its callers use it, what it calls). The model's own opinion of its confidence is ignored. The label is a rough guide to what to review first. It is not a probability and is not calibrated.

### `kraken auto <binary>`

Does the whole flow for one program in one command: it checks the file, creates a project, runs the analysis and waits for it. Then, only if you ask:

- `--names` lets the configured assistant look the program over and name its important functions (the Automate task below, goal "understand").
- `--rewrite` plans a Rust rewrite of the whole program, translates it with the configured provider (see "Rewriting uses the same assistant"), runs the original and the rewrite on the same inputs inside a sandbox, and reports whether they agree. `--cases '[{"name": "help", "argv": ["--help"]}]'` adds your own test cases. `--no-function-tests` only compiles each function and leaves the program-level test as the only evidence.
- `--accept-verified` (with `--rewrite`) accepts the rewritten functions that passed their own test and exports the Rust workspace to `<project>/rewrite-export`. You are the person deciding here. Without the flag the command tells you how to accept (`kraken rewrite-status`, then `kraken rewrite-accept --unit <id>`). If some function cannot be accepted (for example one that returns a pointer, which the function test cannot compare) and an accepted function calls it, the export is refused; the summary says so and the exit status is 4.

```sh
kraken auto ./a.out --names
kraken auto ./a.out --project-dir ~/re/a --engine native --names --rewrite --accept-verified
```

Progress lines go to standard error (`[2/4] creating the project and analysing it`, then the jobs' own progress). The summary goes to standard output: program and format, project directory, function count, how many functions the assistant renamed, the rewrite verdict (`pass` means every test case agreed) and where the Rust crate and the export are. `--json` prints that summary as one object. The exit status is 0 when everything you asked for worked and the rewrite verdict is `pass`, 4 when the verdict is not `pass` or the export could not be made, and the usual codes for errors. `--names` needs a provider like the other assistant commands and checks for one before it creates anything. A terminal agent edits through its own `kraken mcp` process, which must share the run's session: with the daemon (the default) it does, and without one (`--no-daemon`, or no `krakend` to start) `kraken auto` runs a private daemon inside its own process for the run, points the agent's tool server at it (`private one` on stderr says so) and stops it at the end, which saves the project.

### `kraken glossary <term>`

Looks up a term or an instruction mnemonic. It works offline and needs no project or provider.

```sh
kraken glossary stack frame
kraken glossary jne --arch x86_64
kraken glossary adrp
```

Typos are forgiven (`dissasembler` finds `disassembler`), and a query can match related terms too. `--json` prints the matches with their notes.

## Automate: let the assistant work through the whole flow

**Automate** is a task for the steps you would otherwise take one by one. It has three goals:

| Goal | What the assistant does |
| --- | --- |
| Understand | Runs the analysis if needed, reads the entry point, imports and strings, then gives up to 15 important functions a name and a one-line comment (several at once with `apply_edits`) |
| Rewrite | Plans the rewrite of the whole program, translates and tests it against the original (`rewrite_program`), explains any case that differs and retries once or twice, then exports (`rewrite_export`) |
| Both | Understand first, then rewrite, so the translation starts from named functions |

In the GUI, open it from **Automate with the assistant...** in the command palette or the menu: the dialog says in plain words what the chosen goal will do and what it will ask you. It runs with the assistant you chose under Settings > AI, a model or a terminal agent, and its steps and tool calls appear in the Assistant tab like any other task, with **Stop** at hand. From the command line, `kraken auto` runs the same task for `--names`.

What the assistant can use is fixed by KRAKEN for each goal, not chosen by the model: the analysis and job commands, the read commands, `rename_symbol`, `set_comment`, `set_type`, `apply_edits`, and for the rewrite goals `rewrite_plan`, `rewrite_status`, `rewrite_function`, `rewrite_program`, `rewrite_program_status` and `rewrite_export`. A terminal agent holds all of KRAKEN's tools through its MCP server, so KRAKEN answers its permission requests from the same list: a KRAKEN tool outside the goal is refused. What stays yours either way:

- Accepting rewrite results (`rewrite_accept`), deciding on proposals, undoing, and opening or creating projects are never offered. The run ends with a note telling you what to accept, in the Rewrite tab or with `kraken rewrite-accept`.
- The approvals commands normally ask for still apply. `rewrite_program` runs the original program on test inputs inside a sandbox and sends decompiled code to your provider, so you are asked first.
- Edits follow the usual policy: new names apply, anything that would overwrite someone's work becomes a proposal, and the whole run can be undone with `kraken undo-run --run-id <id>`.

A run is bounded by a step budget, a tool-call budget and at most 60 edit calls, and a rewrite job may take up to three hours. If you stop it, nothing is half-applied that the History tab cannot undo.

## In the GUI

![The Assistant tab with a terminal agent selected: tool chips for KRAKEN's tools, an agent tool, and a permission card waiting for an answer](images/assistant-agent.png)

*The Assistant tab with a terminal agent selected, driven by KRAKEN's scripted test agent so the picture is reproducible. A model API looks the same, without the permission card.*

The GUI has one **Assistant** tab (next to Hex) and the same features whichever kind answers, with every step visible:

- **Chat.** Ask in your own words. Each tool call shows as a small chip (command, short arguments, result) that opens for details; a terminal agent's own tools carry an *agent tool* tag. Changes the assistant is not allowed to make on its own (overwriting something you set) appear inline as proposals with **Accept** and **Reject**; accepting applies them as your own edit. A terminal agent asking to use one of its own tools shows a permission card with **Allow once** and **Deny**. **Stop** cancels and withdraws waiting requests. The backend in use, the model, whether it runs on your computer, in the cloud or as a terminal agent, and (for models) the tokens used are always shown.
- **Explain.** Right-click code in the decompiler (a word, its line, or the whole function) or a function in the list, then choose Explain. The answer is a card with clickable addresses and names you can try with one click (the rename box opens pre-filled; nothing changes until you confirm).
- **First run.** When the first analysis finishes a banner offers an overview of the program.
- **Suggest names.** The button above the function list asks for names for placeholder-named functions. You get a review table (old name, new name, evidence, how sure) and nothing changes until you press Apply. Applied names are your own edits, and Undo takes them back.
- **Automate.** *Automate with the assistant...* in the command palette lets the assistant work through the flow on its own; see above.
- **Learn mode.** The switch in the top bar adds a "?" to panel tabs and explains terms and assembly instructions on hover.

With the daemon (the default) a terminal agent gets `kraken mcp --daemon --project <dir>`, so its edits reach the window as they happen, with the usual notification and Undo. With `--no-daemon` the window holds the project in its own process, and a project can be open in only one KRAKEN process at a time: the agent's own `kraken mcp --project <dir>` is refused with a message saying so. Use the daemon for terminal agents. Changing the project ends the agent's session; the next question starts a new one.

## How it stays safe

The assistant reads code that came from a file you do not trust, so the same rules apply as for any agent (see [Security](security.md)):

- Names, strings, comments and decompiled code reach the model only as delimited, untrusted data, and the model is told never to treat them as instructions. They are never put in the system prompt.
- Which commands a model may call is decided by KRAKEN for each task, not by the model or the binary. Explaining and the overview are read-only. Opening, creating or rebuilding projects, undoing, deciding on proposals, and starting rewrites (translating, specs, accepting and exporting rewrite units) are never offered to the assistant as tools, except that the Automate task below switches on `rewrite_function`, `rewrite_program` and `rewrite_export` for its rewrite goals (accepting stays yours) (the rewrite pipeline itself uses the same backends, as plain text requests; see above). Dangerous commands are never offered either. A terminal agent is told the same task rules, but it holds KRAKEN's tool server rather than a list KRAKEN chose: in a read-only task KRAKEN refuses its permission requests for KRAKEN tools that write, and the result calls out any change made anyway. The project's own `kraken mcp` server is bound to the project (it cannot open another).
- Edits go through the registry's policy: additive edits are applied up to a per-run cap, overwrites become proposals.

## Measuring the assistant (`kraken eval`)

Which model, or which agent, is good enough? `kraken eval` answers that with numbers. It runs scripted tasks over KRAKEN's test corpus (small programs built with debug information, so the right answers are known), asks the assistant you configured, scores what comes back, and writes a report.

| Kind | What is asked | How it is scored |
| --- | --- | --- |
| `name_functions` | Name 6 to 8 functions of a stripped program | For each function, the F1 of the words in your name and the words in the real (DWARF) name: `parse_header` and `header_parse` score 1, `parse_file` scores 0.5. Plural `s` and filler words (`fn`, `do`, `the`) are ignored. The task score is the mean |
| `find_function` | "Which function reverses a string in place?", "Which function uses the string `stack underflow`?" | 1 if the address answered lies inside the right function, else 0 |
| `question` | "Does the program import `strcmp`?", "List every imported function that does not start with an underscore", "What format string prints the final result?" | Yes/no and text are right or wrong; a list scores the F1 of its members |

There are 27 tasks over four programs (a bytecode VM, an expression evaluator, a linked list with function pointers, a statically linked string toolbox). The programs are the stripped builds, so names cannot be read off. The questions describe behaviour, never the answer, and nothing from a binary is put in a prompt. `kraken eval list` shows all of them.

The assistant gets the same read-only tools it has everywhere else and a fixed answer format: its reply ends with a block such as `<kraken-answer>{"address": "0x101255"}</kraken-answer>`. A reply with no readable block scores 0 and the report says why. The tasks are read-only: a model is not offered the commands that write, and a terminal agent is told not to and has its write requests refused.

### Run it

```sh
kraken eval run --out results/qwen3-14b
```

This uses whatever the `[provider]` table of `config.toml` selects, an AI model or a terminal agent, exactly like `kraken explain`. For each program in the corpus it creates and analyses a project under the output folder (this needs the engine, so run `kraken setup` first, or use the offline modes below), then asks every task of that program in turn. Progress goes to standard error, one line per task.

Useful options:

- `--task find/ --task name/switch_vm` runs only the tasks whose id starts with one of these. `--kind question` runs one kind. `--limit 5` stops after five.
- `--timeout 300` cancels a task that runs longer than five minutes (default 900 seconds); it scores 0 with the reason.
- `--price-in 3 --price-out 15` (dollars per million tokens) adds a cost estimate for a paid API. Leave them out for a local model.
- `--min-score 0.6` makes the command exit with status 1 when the mean score is lower, so a script or a CI job can gate on it.
- `--json` prints the whole report on standard output.
- `--corpus DIR` points at the repository's `corpus/` folder when `kraken` is not run from inside a checkout (or set `KRAKEN_CORPUS`).

### Against a local model (Ollama, llama-server)

Point the provider at the server, as in [AI models](#ai-models), and run the evaluation. The model has to call tools; for llama-server start it with `--jinja`.

```toml
# ~/.config/kraken/config.toml
[provider]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"   # Ollama; llama-server is http://localhost:8080/v1
model = "qwen3:14b"
```

```sh
ollama serve &              # in another terminal
ollama pull qwen3:14b
kraken eval run --out results/qwen3-14b --timeout 600
```

Local models are slow and the tasks are many small conversations, so start with `--limit 6` or `--kind find_function`. To compare models, change `model` and run again with another `--out`; the numbers in `report.json` line up task by task. Tokens are counted when the server reports usage (most OpenAI-compatible servers do; the report says "not reported" when one does not), and a local model has no price. To measure a model KRAKEN runs for you, start it first with `kraken infer start <model>` (see [Local models on this computer](local-models.md)) and then run the same command.

### Against Claude Code (or another terminal agent)

```toml
[provider]
kind = "terminal_agent"
agent = "claude"
# model = "..."          # optional; see Terminal agents
```

```sh
kraken agents setup claude          # once
kraken eval run --out results/claude-code
```

KRAKEN starts the agent once per task in the task's project, with the `kraken mcp` server attached, and sends it the task. The agent and `kraken eval` share the daemon (the default), so run without `--no-daemon`. Three things to know:

- **The agent's own tools are outside KRAKEN's safety net** (see [Terminal agents](#terminal-agents)). Nothing is there to answer a permission request during an evaluation, so requests for the agent's shell or file tools are denied, and a task that insists on them scores what it can. Run evaluations on the corpus, not on a program you are worried about.
- **Tokens and cost are not reported** for a terminal agent (ACP does not carry them), so the report says so; look at the agent's own usage page for the bill.
- A strong agent is not a deterministic one. Run twice when two results are close.

### The report

`--out` receives:

- `report.json`: backend, mode, engine, totals (mean score, by kind, tokens, cost, tool calls) and one entry per task with its score, the expected and given answer, the reply, stop reason, tokens, tool calls and the full transcript. The format is versioned (`schema_version`).
- `report.md`: the same as a readable summary with a table of tasks and, for each miss, what was expected and what was answered (for names, a table of address, real name, your name and F1).
- `transcripts/<task>.md`: what the assistant was asked, what it said, every tool call with a short result. Read the weakest ones first.
- `projects/`: the projects made for the run. Delete the folder when done.

### Offline and deterministic: the CI modes

Two modes need no model, no network and no decompiler, and give the same report every time (timings are left out):

```sh
kraken eval run --backend ci-replay --out /tmp/eval-replay   # replays a cassette through ReplayProvider
kraken eval run --backend ci-agent  --out /tmp/eval-agent    # runs the scripted fake terminal agent
```

The tools run on `engine-fake` over the corpus fixtures (recordings of a real Ghidra), and the answers come from a script written by a deterministic **stand-in**: it answers from the ground truth and gets some tasks wrong on purpose (one name in three right, one half right, one wrong; every fourth function answer off by one; one question left unanswered), so every kind of score and every failure shows up. `ci-replay` feeds that script to the API path as a cassette; `ci-agent` feeds the same script to the fake ACP agent (the `kraken` binary itself, via its hidden `agents __fake-agent`) over the real ACP host. Both produce the same scores.

A CI score proves the harness, the scoring and both backends work. It says nothing about any model. The cassette and script live in `crates/kraken-eval/data/`; after a change to the suite, run the `kraken-eval` tests with `KRAKEN_EVAL_BLESS=1` to rewrite them (the tests fail with that advice when they are out of date).

### Recording a real model for replay

```sh
kraken eval run --out results/run1 --record results/run1/cassette.json
kraken eval run --backend ci-replay --cassette results/run1/cassette.json --out results/replay1
```

`--record` saves every exchange of a model API as an eval cassette: the responses of each task's model calls, in order. Replaying it runs the same tasks against the fixtures with the recorded answers, so a scoring change can be checked on real answers without paying for them again. A cassette is keyed by task id and call number, not by a hash of the request, so changing a tool description does not invalidate it. If the tools would have behaved differently, the replay shows it.

### Your own tasks

A suite is a JSON file passed with `--suite`. Each task has an `id`, a `kind`, a corpus `binary`, a `question` and an `expect` (`function`, `yes_no`, `set` or `text`); naming tasks need only a `sample` size. See `crates/kraken-eval/data/corpus.json`. Names are only a test on a stripped binary, so `name_functions` refuses an unstripped one.

## For developers

The `kraken-eval` crate is the harness: `Suite` and `TaskDef` (tasks and the truth they resolve to), `score` (answer reading and scoring), `Runner` over an `Environment` (opens the corpus binaries: `ci::FixtureEnvironment` offline, the CLI's live environment otherwise) and an `AssistantSource` (`ApiSource`, `RecordingSource`, `ReplaySource`, `FakeAgentSource`, or a closure), and `Report`. It asks through `kraken_assist::Assistant` with a `Task::custom`, so a model API and a terminal agent are measured the same way.

The `kraken-assist` crate holds the logic and has no GUI dependencies:

- `AssistBackend` is what answers a run, with two implementations: `ApiBackend` (a `kraken_agent::ChatProvider` driven by the agent loop over a `RegistryToolHost`) and `AcpBackend` (a terminal agent driven by `kraken_acp::AcpHost`, reaching the registry through the `kraken mcp` server it is launched with). Both turn a `RunSpec` into the same `AgentRun`: a stream of `AgentEvent`s (text deltas, tool call started and finished, approval required, proposals, done with a stop reason). ACP updates are mapped onto it: message chunks become text deltas, tool calls become chips named after the KRAKEN command, permission requests become `ApprovalRequired`, and the agent's turn ending becomes `Done`.
- `RegistryToolHost` implements `kraken_agent::ToolHost` over a registry and any `kraken_host::backend::CommandBackend` (an in-process session or `krakend`). It starts jobs such as `analyze` and waits for them with `job_await`, and returns proposed writes with a top-level `"proposal"` field so the agent loop emits `ProposalCreated`.
- `Task::explain_function`, `explain_selection`, `overview` and `auto_name` each bundle a prompt, a tool subset and budgets; `Assistant::run` runs one on either backend and parses the result block the model ends with.
- `plan_agent` finds an agent in the catalogue, applies the chosen model and arguments and checks that it can run.
- `Glossary::builtin()` gives `get`, `mnemonic` and fuzzy `lookup` for learn-mode tooltips.

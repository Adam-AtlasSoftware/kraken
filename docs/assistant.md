# The built-in assistant

KRAKEN has a built-in assistant for people who are new to reverse engineering. It can explain a function in plain language, give you a guided first look at a program, and suggest names for functions that still have generated names like `FUN_00401000`. It also has an offline glossary of reverse-engineering terms.

The assistant is a client like any other. It reads and edits the project through the same commands as the CLI and MCP server, so everything it does shows up in the edit log under the author `kraken-assistant`, and every run can be undone.

## Set up a model

The assistant needs a chat model that can call tools. Add one `[provider]` table to `~/.config/kraken/config.toml` (`KRAKEN_CONFIG` overrides the location).

```toml
# Ollama (local; run `ollama serve` and `ollama pull <model>` first)
[provider]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3:14b"
```

Other providers, one at a time:

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

If no provider is configured, the assistant commands stop with an error that shows these examples.

## Commands

All of them take `--project <dir>` (or `KRAKEN_PROJECT`) like the other commands. Text streams to standard output and tool calls go to standard error, so you can see what the assistant looked at. With `--json`, standard output holds one structured result instead.

### `kraken explain <address>`

Explains the function at an address: a short explanation, what it does step by step, and names worth considering. It cannot change the project.

```sh
kraken explain 0x401000
```

### `kraken overview`

A guided first look: what the program appears to be, its main parts, a few functions to open first and why, and what to do next. It starts from `project_info`, so run `kraken analyze` first. Where this build of KRAKEN has no command for something it would like to check (strings, imports, cross-references), the assistant says so and the result lists it under "Could not check" rather than guessing.

### `kraken auto-name [--limit N] [--dry-run]`

Looks at up to N functions (default 10, at most 50) that still have default names, and suggests names and short comments with the evidence for each.

- `--dry-run` only suggests. The assistant is not even offered the commands that write.
- Without it, suggestions are written as the agent `kraken-assistant`. Following the usual agent rules, a rename of a function that still has its default name and a new comment are applied right away; anything that would overwrite something a person wrote becomes a **proposal** that waits for you (`kraken proposals-list`, then `kraken proposal-accept`). A run makes at most two edits per function it was allowed to look at.
- Undo everything a run did with `kraken undo-run --run-id <id>`. The run id is printed at the end.

Each suggestion carries a confidence label of low, medium or high. KRAKEN works it out itself by counting how many independent kinds of evidence agree (strings the function uses, library functions it calls or imports, how its callers use it, what it calls). The model's own opinion of its confidence is ignored. The label is a rough guide to what to review first. It is not a probability and is not calibrated.

### `kraken glossary <term>`

Looks up a term or an instruction mnemonic. It works offline and needs no project or provider.

```sh
kraken glossary stack frame
kraken glossary jne --arch x86_64
kraken glossary adrp
```

Typos are forgiven (`dissasembler` finds `disassembler`), and a query can match related terms too. `--json` prints the matches with their notes.

## In the GUI

The GUI has an **Assistant** tab (next to Hex) and the same features, with every step visible:

- **Chat.** Ask in your own words. Each tool call shows as a small chip (command, short arguments, result) that opens for details. Changes the assistant is not allowed to make on its own (overwriting something you set) appear inline as proposals with **Accept** and **Reject**; accepting applies them as your own edit. **Stop** cancels. The model in use, whether it runs on your computer or in the cloud, and the tokens used are always shown.
- **Explain.** Right-click code in the decompiler (a word, its line, or the whole function) or a function in the list, then choose Explain. The answer is a card with clickable addresses and names you can try with one click (the rename box opens pre-filled; nothing changes until you confirm).
- **First run.** When the first analysis finishes a banner offers an overview of the program.
- **Suggest names.** The button above the function list asks for names for placeholder-named functions. You get a review table (old name, new name, evidence, how sure) and nothing changes until you press Apply. Applied names are your own edits, and Undo takes them back.
- **Learn mode.** The switch in the top bar adds a "?" to panel tabs and explains terms and assembly instructions on hover.

### Choosing the model

Open **Settings > AI** (Ctrl+,): pick Ollama, LM Studio, llama-server, vLLM, another OpenAI-compatible server, Anthropic, OpenAI or Gemini, enter the model, and press **Test connection** (one tiny request; failures are explained in plain words) then **Save and use**. The choice is saved as the `[provider]` table of `config.toml`, so the CLI uses it too.

To run a model on your own computer with KRAKEN doing the work (`kraken infer start ... --use`, or **Run a model on this computer** in the same settings section), see [Running a model on this computer](local-models.md).

API keys are never written to `config.toml`. Name an environment variable (read when KRAKEN starts), or paste the key: it is stored in `secrets.toml` next to `config.toml`, created with mode 0600 so only you can read it, and `config.toml` only points at it. The CLI commands read keys from environment variables only, so a pasted key works in the GUI but `kraken explain` needs the variable.

## How it stays safe

The assistant reads code that came from a file you do not trust, so the same rules apply as for any agent (see [Security](security.md)):

- Names, strings, comments and decompiled code reach the model only as delimited, untrusted data, and the model is told never to treat them as instructions. They are never put in the system prompt.
- Which commands the assistant may call is decided by KRAKEN for each task, not by the model or the binary. Explaining and the overview are read-only. Opening, creating or rebuilding projects, undoing, deciding on proposals, and starting rewrites (translating, specs, accepting and exporting rewrite units) are never offered. Dangerous commands are never offered either.
- Edits go through the registry's policy: additive edits are applied up to a per-run cap, overwrites become proposals.

## For developers

The `kraken-assist` crate holds the logic and has no GUI dependencies:

- `RegistryToolHost` implements `kraken_agent::ToolHost` over a registry and any `kraken_host::backend::CommandBackend` (an in-process session or `krakend`). It starts jobs such as `analyze` and waits for them with `job_await`, and returns proposed writes with a top-level `"proposal"` field so the agent loop emits `ProposalCreated`.
- `Task::explain_function`, `explain_selection`, `overview` and `auto_name` each bundle a prompt, a tool subset and budgets; `Assistant::run` runs one and parses the result block the model ends with.
- `Glossary::builtin()` gives `get`, `mnemonic` and fuzzy `lookup` for learn-mode tooltips.

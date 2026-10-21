# Local models on this computer

A local model is a language model that runs on your own computer. KRAKEN's assistant and its
rewriting can use one. Nothing you analyse leaves your machine.

This page covers:

- setting up a model in the guided steps,
- picking it for the assistant and for rewriting,
- starting and stopping it, and what happens when the window closes,
- running it from scripts with `kraken --serve-local` and `kraken infer`,
- choosing graphics cards, and the memory warnings,
- the figures in the title bar,
- the config file, and what is not supported yet.

KRAKEN never downloads a model by itself. Models are big and have their own licences. In the guided
setup you pick the model, and KRAKEN downloads only that one.

## Words used here

- **Model**: the file with the language model's learned weights.
- **Engine**: the program that loads a model and answers questions. KRAKEN runs llama.cpp
  (`llama-server`) and Strata.
- **Card**: a graphics card. Models run fastest on a card, using its video memory.
- **VRAM**: video memory, the memory on the card.
- **tok/s**: speed in tokens per second. A token is a piece of a word, so this is roughly words per
  second.
- **Serving**: keeping the model loaded and answering in the background.

## Set up a model

Open **Settings > AI** (Ctrl+,). Under **Assistant**, open the model list and choose
**+ Set up a model on this computer...**. The same choice is in the **Rewriting** list. The guided
setup has four steps.

1. **Check this computer.** KRAKEN lists the graphics cards, their VRAM, the RAM and the free disk
   space. If no card is found, models run on the processor. That works, but it is slow.
2. **Pick a model.** The first one is the recommendation for this computer. Each model shows one of
   three marks:
   - **Fits**: fits with room to spare.
   - **Tight**: fits, but only just. Other programs using memory may push it out.
   - **Won't fit**: too big for this computer. You can still choose it, but it will not run well.
   Each one also shows its download size.

   On a computer with an NVIDIA card, a **Strata** part sits under the list. **Use a model file I
   already have...** opens the system file dialog: pick any shard of a Strata model on your disk,
   and KRAKEN uses the files where they are, with no copy and no 60 GB download. See
   [Strata](#strata). **Engine** and **Version** choose how Strata itself is installed.
3. **Pick cards.** KRAKEN preselects the best card. With several cards you can change the choice.
   See [Several cards](#several-cards).
4. **Download and test.** KRAKEN downloads the engine and the model, starts the model and asks it a
   short question. When the test answer comes back, the model is added, selected for the assistant
   and set to start when KRAKEN opens.

## Pick a model for the assistant or rewriting

The **Assistant** and **Rewriting** pickers use the same list, in four groups:

- **On this computer**: the models you have set up, and **+ Set up a model on this computer...**.
- **Server you run**: Ollama, LM Studio, vLLM or another server that you start yourself.
- **Cloud**: the online model services.
- **Terminal agent**: Claude Code, Codex or Gemini CLI.

Choose a local model and its card appears below the list. The card shows:

- its state (Stopped, Loading, Running, Failed),
- **Start serving this model** or **Stop serving this model**,
- **Serve automatically when KRAKEN opens**, ticked by default,
- **Run on**: the cards it may use. A card that the engine cannot use is greyed out, with the reason
  beside it. Intel graphics cards say "not supported yet".
- **Remove** to take the model off KRAKEN's list.

Rewriting can use a different local model from the assistant. Both can run at the same time if the
memory allows.

## Start, stop and automatic start

- **Start serving** loads the model. The card and the title bar show the loading progress.
- **Stop serving** unloads it and frees its memory.
- **Serve automatically when KRAKEN opens**: when KRAKEN opens, the models with this box ticked
  start by themselves. Models used for the assistant and for rewriting start first, then the rest in
  list order. A model that will not fit is skipped, and its card says why. It has a **Start serving**
  button, so you can still start it yourself.
- A model that is stopped and used for the assistant starts the first time you ask a question. KRAKEN
  checks the memory first.

## When the window closes

While the KRAKEN window is open, it keeps its models running. When you close the window, it lets them
go. Each model then stops after a **grace period**: two minutes by default. If you open KRAKEN again
within that time, or another program still uses the model, it keeps running.

To change the grace period, set `grace_secs` in the `[local_serving]` table of `config.toml`
(see [The config file](#the-config-file)). A model started from a script with `kraken infer start`
does not stop when the window closes. It runs until `kraken infer stop`.

## Scripts and command lines

KRAKEN keeps a model running while something uses it. Several things can be users at once: the
window, a command, an MCP agent, or a manual start.

- `kraken --serve-local <command>` keeps the assistant's and the rewriting's local models running
  while that command runs. The model stops after the grace period once the command ends.
- `kraken mcp --serve-local` does the same for the MCP server, for as long as the agent is connected
  (see [Connecting AI agents (MCP)](mcp.md)).
- `krakend --serve-local` does the same for the daemon.
- `kraken infer start <model>` starts a model and keeps it running until `kraken infer stop <model>`,
  even after the command ends. It waits until the model has loaded. Add `--no-wait` to return at
  once, and `--timeout SECS` to change how long to wait (default 900).
- `kraken infer stop <model>` stops it. Without a model name it stops the model you started from an
  engine.
- `kraken infer status` and `kraken infer logs` show how far loading is and the model's own output.
- `kraken local-model-list` lists the models you have set up.

For example:

```sh
kraken --serve-local explain --project ~/kraken-projects/crackme 0x401136
kraken infer start qwen3-8b-q4_k_m --timeout 600
kraken explain --project ~/kraken-projects/crackme 0x401136
kraken infer stop qwen3-8b-q4_k_m
```

If a command uses a local model that is not running, it says so and offers to start it.

## Several cards

With two or more cards ticked, the card shows **How to use several cards** with three choices.

- **Split the model across the cards**: one model, shared by the cards. Use it when the model is too
  big for one card. This is the default.
- **Each card runs its own full copy** (Strata only): each card holds the whole model and answers
  its own requests. Use it when you have many requests, and each card has enough VRAM for the whole
  model. It needs equal cards.
- **Split every layer between the cards** (llama.cpp only): every layer is split across the cards.
  It can be faster when the cards are linked by a fast connection such as NVLink. Usually it is
  slower otherwise.

For llama.cpp, choose the first or the third. For Strata, choose the first or the second.

**Advanced: share per card, main card** opens two more settings. The share is how much of the model
each card takes. The main card is the one that does the work that is not shared. Leave them alone
unless one card is much bigger than the other.

With one card, this section does not appear.

## Memory warnings

Before a model starts, KRAKEN checks whether it fits in the memory that is free now. It
also keeps room for the other models that are already loading.

If it does not fit, KRAKEN does not start it. It offers these choices:

- **Stop** the other model that holds the memory, then start this one.
- **Run on the processor** instead. It works on any computer, but it is much slower.
- **Start anyway**. It may fail part way through loading.
- **Cancel**.

Automatic start never starts a model that does not fit. It skips it, and the chip says why.

If a card disappears, for example after a driver crash, the model fails with a message. KRAKEN does
not keep restarting it in a loop. Press **Start serving** when the card is back.

## The title bar

KRAKEN's title bar shows one chip for each model that is in use or serving. A chip has a name, a
state dot and a few figures. The figures are:

| Figure | What it means |
| --- | --- |
| `Loading 62%` | How far the model has loaded. The bar behind the figures fills as it loads. |
| `VRAM 6.9/8.0 GB` | Video memory this model uses, and the card's total. |
| `RAM 2.0 GB` | System memory used by the engine's processes. |
| `38 tok/s` | Speed as the engine reports it. |
| `about 38 tok/s` | Speed KRAKEN measured from the model's replies. Less exact. |

A chip for a model on a card says `Running on RTX 3070 Ti`, or `Loading 62% on RTX 3070 Ti` while it
loads. Hover over it for each card's detail and the port. When the bar is narrow, a chip shrinks to its
name and state dot.

A server you run yourself (Ollama, LM Studio, vLLM) has a chip too. It shows `reachable` or
`unreachable` and a speed measured from KRAKEN's requests. KRAKEN cannot start or stop such a
server, and it does not show memory figures.

### Which frame

KRAKEN draws its own title bar on KDE, GNOME and Windows. On other systems (Hyprland, other window
managers, macOS) it uses the system's title bar, and the chips go in KRAKEN's top bar inside the
window. That top bar shows only while a project is open. To choose, open **Settings › Appearance ›
Title bar** (Automatic, KRAKEN's own, or The system's); the change applies the next time KRAKEN
starts. In the config file this is `titlebar` in `[local_serving]`: `"auto"` (the default),
`"custom"` or `"system"`.

## Start and stop from the command line: `kraken infer`

`kraken infer` runs an engine directly, without the window. It is useful for trying a model file.

```sh
kraken infer list                            # engines this computer can run, and the memory left
kraken infer setup llama                     # download the llama.cpp build (asks first)
kraken infer start llama-server --model ~/models/qwen3-14b-q4_k_m.gguf --use
kraken infer stop
```

`--use` makes the assistant use the model after it has loaded. It writes the
`[provider]` table (see [The config file](#the-config-file)). Other settings are kept.

| Command | What it does |
| --- | --- |
| `kraken infer list` | Engines and their settings, and the memory left. |
| `kraken infer setup llama [--variant cpu\|vulkan\|metal] [--force]` | Download the pinned llama.cpp build into KRAKEN's data folder. |
| `kraken infer start <engine or model> [--model FILE] [--set key=value]... [--use] [--cpu] [--force] [--no-wait] [--timeout SECS]` | Start a model. |
| `kraken infer status` | How far the model is loading, and its state. |
| `kraken infer logs [--tail N] [--follow]` | The engine's output. |
| `kraken infer stop [model]` | Stop a model. |

`--json` works on all of them. `--set` passes engine settings, for example
`--set gpu_layers=99 --set n_cpu_moe=30`.

### llama.cpp (llama-server)

`kraken infer setup llama` downloads a pinned llama.cpp release (`b11696`) from
`github.com/ggml-org/llama.cpp`. It checks the file's SHA-256 against the value pinned in KRAKEN, and
only then unpacks it into `~/.local/share/kraken/llama/`.

| Platform | Variant | Notes |
| --- | --- | --- |
| Linux x86-64 | `cpu` (default) | Runs on the processor. |
| Linux x86-64 | `vulkan` | For AMD or NVIDIA cards, without CUDA. Needs your driver's Vulkan support. |
| macOS Apple silicon | `metal` | |
| Windows x86-64 | `cpu` (default), `vulkan` | As for Linux. |

Other platforms, and CUDA or ROCm builds, are not downloaded by KRAKEN. Install `llama-server` yourself
and put it on `PATH`, or set `binary_path`.

The settings that matter most:

| Setting | llama-server flag | Meaning |
| --- | --- | --- |
| `model_path` | `-m` | The GGUF file (required). |
| `context_size` | `-c` | How much text the model can read at once (default 8192). |
| `gpu_layers` | `-ngl` | How many layers go on the card. A large number means all. 0 means processor only. |
| `n_cpu_moe` | `--n-cpu-moe` | For mixture-of-experts models: keep the expert weights of the first N layers in RAM. |
| `threads` | `-t` | Processor threads (default: llama.cpp's choice). |
| `jinja` | `--jinja` | Use the model's chat template, needed for tool calls (on by default). |
| `binary_path` | | A specific `llama-server`. |

The server only listens on 127.0.0.1.

### Big mixture-of-experts models on a small card

A mixture-of-experts (MoE) model has many "experts", and only a few of them work on each word. The
experts are most of the file, so they can sit in ordinary RAM. The parts that run on every word stay
on the card. A 30 to 120 billion parameter model can then run on a card with 8 to 16 GiB of VRAM and
64 GiB or more of RAM:

```sh
kraken infer start llama-server --model ~/models/big-moe-q4_k_m.gguf \
    --set gpu_layers=99 --set n_cpu_moe=30 --set context_size=16384 --use
```

Raise `n_cpu_moe` until the model loads. Lower it while the card still has room, because a higher
value is slower.

### Strata

Strata is another engine for very large mixture-of-experts models. It keeps the expert weights in RAM
and works on NVIDIA cards only. Its files live under `<data dir>/engines/strata`, and KRAKEN never
uses `sudo` for it.

**Engine.** *Ready-made* downloads Strata's finished Linux engine (CUDA 13) from the release and checks
it against the release's `SHA256SUMS.txt`. It needs only a driver and Python 3 with `venv`. *Build
from source* compiles the engine here, which takes 10 to 20 minutes and needs `nvcc` and a C++
compiler.

**Version.**

- *Latest release* (the default) looks up the newest published Strata when the setup runs.
- *Tested* is the revision KRAKEN was tested with. Its archives are checked against hashes written
  down in advance (`crates/kraken-infer/data/strata.toml`).
- *Latest commit* is the newest commit of Strata's main branch. It can be broken, so it can only be
  built from source.

The newest release and commit have no hash written down in advance. KRAKEN records the SHA-256 of
what it downloaded in the setup log (`<data dir>/engines/strata/setup.log`).

**A model you already have.** Strata runs GGUF files named the way its installer names them, such as
`Swift-Qwen3.8-Flash-Next-GSQ-RCO-IQ2_XS-00001-of-00002.gguf`. KRAKEN reads the family and the
quantisation from the name and checks that every shard is in the same folder. The files are used where
they are. KRAKEN does not check their hashes, because they are your files.

The same choices are arguments of the `local_model_setup` command: `strata_engine` (`prebuilt` or
`build`), `strata_version` (`latest_release`, `pinned` or `latest_commit`) and `model_file` (the path
of one shard).

## Other servers you run

Ollama, LM Studio, vLLM and other servers are not managed by KRAKEN. You start them yourself, and
KRAKEN only talks to them. Choose them in the picker under **Server you run**, or write the
`[provider]` table by hand:

```toml
# Ollama: run `ollama serve` and `ollama pull <model>` first
[provider]
kind = "openai_compatible"
base_url = "http://localhost:11434/v1"
model = "qwen3:14b"

# LM Studio: load a model and start the server from the Developer tab
# [provider]
# kind = "openai_compatible"
# base_url = "http://localhost:1234/v1"
# model = "the-model-id-lm-studio-shows"
```

Add `supports_tools = false` for a model that cannot call tools. A server on another computer works the
same way, but then the code the assistant reads leaves your computer. The GUI marks such a provider
"not on this computer".

## The config file

A set-up model is a `[[local_models]]` table in `~/.config/kraken/config.toml`. The window writes
it for you. Here is its shape:

```toml
[[local_models]]
id = "qwen3-8b-q4_k_m"                 # the name the assistant and scripts use
name = "Qwen3 8B"                      # shown to people
engine = "llama"                       # "llama" or "strata"
model_path = "/home/you/models/qwen3-8b-q4_k_m.gguf"
devices = [{ uuid = "GPU-1234-...", index = 0, vendor = "nvidia" }]
cpu_only = false                       # true: processor only, no card
multi_gpu = "split"                    # "split", "copy_per_card" (Strata) or "split_every_layer" (llama)
shares = [60, 40]                      # optional: share per card, in the order of devices
main_device = { uuid = "GPU-1234-...", index = 0, vendor = "nvidia" }   # optional
context_size = 8192                    # optional: engine default when unset
autostart = true                       # serve automatically when KRAKEN opens

[local_serving]
grace_secs = 120                       # seconds a model keeps running after the last user leaves
titlebar = "auto"                      # "auto", "custom" or "system"
```

`devices` names the cards by their UUID. The index is only a hint, because card numbers can change
after a restart. `extra` holds engine settings KRAKEN passes on unchanged.

The assistant uses a local model through a `[provider]` table that names it by its `id`. KRAKEN adds
the address and the key when a request is made, so they are never written to the file:

```toml
[provider]
kind = "local"
model = "qwen3-8b-q4_k_m"
```

Rewriting can use a different model through its own `[rewrite]` table (see
[The built-in assistant](assistant.md)).

## Adding another engine with a manifest

Any program that serves the OpenAI chat API (`/v1/chat/completions`) over HTTP can run as a local model
without new Rust code. You describe it in a TOML **manifest**. KRAKEN then runs it, checks its memory and
restarts it after a crash.

KRAKEN reads every `*.toml` file in the manifests folder when it starts:

- `$KRAKEN_INFER_MANIFESTS` if set,
- else `~/.local/share/kraken/infer/manifests/` (`$XDG_DATA_HOME/kraken/infer/manifests/`).

A file with a mistake stops the loading, and KRAKEN names the file. Fix it and restart the daemon with
`kraken daemon stop`. A template with comments is in `crates/kraken-infer/manifests/example-engine.toml`.

```toml
id = "my-moe-engine"                   # lowercase letters, digits, - and _
name = "My MoE engine"
license = "Apache-2.0"

# argv, no shell. The first element is the program.
command = [
  "/opt/my-engine/bin/serve",
  "--model", "{model}",
  "--host", "{host}", "--port", "{port}",
  "--ctx", "{ctx}",
]

health_path = "/v1/models"             # polled on 127.0.0.1 until it answers 2xx
ready_timeout_secs = 900

[capabilities]
os = ["linux"]
arch = ["x86_64"]
gpu_apis = ["cpu", "cuda"]             # any of: cpu, cuda, rocm, vulkan, metal
min_ram_mb = 2048
supports_moe_offload = true
supports_tool_calls = true

[settings_schema]
type = "object"
required = ["model"]

[settings_schema.properties.model]
type = "string"
title = "Model path"
x-kraken-widget = "file-path"

[settings_schema.properties.ctx]
type = "integer"
title = "Context size"
minimum = 512
default = 8192
```

- `{host}` is always `127.0.0.1`. `{port}` is a free port that KRAKEN picks. Every other `{name}` must
  be a property of the schema. Write `{{` and `}}` for literal braces.
- Settings the schema does not list are refused, and so are missing `required` ones.
- The program runs with a filtered environment. Your API keys are not passed on. It must listen on
  127.0.0.1 at the given port.
- Check a new manifest with `kraken infer list`, then `kraken infer start my-moe-engine --model /path`
  and `kraken infer logs`.

## Not supported yet

- **Intel graphics cards.** KRAKEN lists them and says "not supported yet". Support is planned through
  llama.cpp's Vulkan build, and maybe SYCL later.
- **NPUs** (the AI chips in some laptops). They are listed and marked as not supported.
- **vLLM and Ollama as engines KRAKEN runs.** Run them yourself and use the server options above.

## Troubleshooting

| You see | What to do |
| --- | --- |
| "the engine program was not found" | Run `kraken infer setup llama`, or install `llama-server` and put it on `PATH`. |
| "there is not enough memory to load this model" | Stop another model, run this one on the processor, or pick a smaller model. |
| The model stays on "loading" for minutes | Large files take a while to read from disk. `kraken infer logs --follow` shows the progress. |
| The chip says "failed" | Read `kraken infer logs`. A file that is not a valid GGUF, or an option the build does not know, is reported there. |
| The assistant answers but never uses tools | The model does not support tool calls, or `jinja` is off. |
| "there is no local model called ..." | `kraken local-model-list` shows the models you have. Set one up first. |
| "the model is not running" | Start it with `kraken infer start <model>`, or start it in the window. |

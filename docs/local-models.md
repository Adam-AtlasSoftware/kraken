# Running a model on this computer

KRAKEN's assistant (and `kraken explain`, `overview` and `auto-name`) can use a language model that
runs entirely on your own computer. Nothing you analyse is sent anywhere. This page covers

- running llama.cpp's `llama-server` through KRAKEN (`kraken infer ...` and **Settings > AI**),
- using Ollama, LM Studio, vLLM or any other server you run yourself,
- adding another engine to KRAKEN with a small manifest file, which is how engines built for very
  large models on small graphics cards plug in.

KRAKEN never downloads a model for you. Models are big, they come with their own licences, and
choosing one is your decision. You pick the file; KRAKEN runs it.

## Quick start

```sh
kraken infer list                       # engines this computer can run, and the memory left
kraken infer setup llama                # download the official llama.cpp build (asks first)
kraken infer start llama-server --model ~/models/qwen3-14b-q4_k_m.gguf --use
kraken explain --project ~/kraken-projects/crackme 0x401136
kraken infer stop
```

`--use` waits until the model is loaded and then makes the assistant use it: it writes this to your
`config.toml` (the same file **Settings > AI** edits, other settings are kept):

```toml
[provider]
kind = "openai_compatible"
base_url = "http://127.0.0.1:41873/v1"
model = "qwen3-14b-q4_k_m.gguf"
supports_tools = true
```

The port is chosen freshly on every start, so `--use` again after each start, or pin it with
`--set port=8089` and the address stays the same.

In the GUI open **Settings** (Ctrl+,) and find **Run a model on this computer** under the AI
assistant section. Pick the engine, choose the model file, adjust the settings and press **Start**.
A progress bar follows the loading, **Model log** shows the engine's own output, and **Use for the
assistant** does what `--use` does.

### Where to get a model file

`llama-server` reads **GGUF** files. Model makers and community packagers publish them on Hugging
Face (search the model's name plus "GGUF"). Download the file with your browser or `curl`, save it
anywhere, and give KRAKEN its path. Some guidance:

- Pick a size that fits your memory. The file size is roughly what the model needs in RAM (or
  video memory), plus about 10% for the conversation. A 4-bit file (`Q4_K_M` in the name) is the
  usual compromise between quality and size.
- The assistant uses tools to browse the program. Choose a model that supports tool calling
  ("tools" or "function calling" on its page); others can explain text but not explore.
- Read the model's licence. KRAKEN only runs the file.

## What `kraken infer` does

| Command | What it does |
| --- | --- |
| `kraken infer list` | Engines that run on this computer with their settings, RAM use of open projects and what is left. |
| `kraken infer setup llama [--variant cpu\|vulkan\|metal] [--force]` | Download and verify the pinned llama.cpp build into KRAKEN's data directory. |
| `kraken infer start <engine> [--model FILE] [--set key=value]... [--use] [--no-wait] [--timeout SECS]` | Start a model. By default it waits until the model has loaded and shows the progress. |
| `kraken infer status` | Phase (`starting`, `loading`, `ready`, `restarting`, `failed`), address, uptime. |
| `kraken infer logs [--tail N] [--follow]` | The engine's output. |
| `kraken infer stop` | Stop the model. |

`--json` works on all of them. `--set` takes `key=value` pairs from the engine's settings (shown by
`kraken infer list`); numbers and switches are checked against the engine's schema, and a relative
`--model` path is made absolute because the daemon does not share your working directory.

### The model belongs to the daemon

When you use the daemon (the default), `krakend` starts the engine as a supervised child process and
the model **keeps running after the command, the window or the terminal is closed**. The daemon
counts a loaded model as work, so its idle timer never shuts it down while a model is loaded. Stop it
with `kraken infer stop`, **Stop** in Settings, or by stopping the daemon (`kraken daemon stop`).
If the engine crashes it is restarted a few times with a growing delay; after that it is marked
`failed` and the log says why.

With `--no-daemon` the model belongs to the process that started it: `kraken infer start` keeps it
alive in your terminal until you press Ctrl-C (in scripts it stops when the command ends), and the
GUI stops it when you close the window. There is one model at a time.

### Memory check

Before starting, KRAKEN adds up what is already spoken for: the Java heaps of the open Ghidra
projects in the daemon, plus the model. If the total does not fit in RAM the start is **refused**
with a message that says how much is missing. If it fits but leaves under 15%, the start goes ahead
with a **warning** (shown in the CLI, in the GUI, and at the top of the log). Video memory is
checked only when the machine's size is known, which it currently is not on most systems, so a
model sent to the GPU is not refused for lack of VRAM; the engine reports that itself in its log.
The GUI shows the same estimate under the form as soon as you choose a file.

## llama.cpp (llama-server)

`kraken infer setup llama` downloads one of these upstream release builds from
`github.com/ggml-org/llama.cpp` (release `b11696`), checks its SHA-256 against the value pinned in
KRAKEN, and only then unpacks it into `~/.local/share/kraken/llama/` (`%LOCALAPPDATA%\kraken\llama`
on Windows if no home directory is set):

| Platform | Variant | File | SHA-256 |
| --- | --- | --- | --- |
| Linux x86-64 | `cpu` (default) | `llama-b11696-bin-ubuntu-x64.tar.gz` | `6a04629ca5265eb4c5c7d6edec8d6fa429e7e7da2de1cd5d5e357a492fc8f802` |
| Linux x86-64 | `vulkan` | `llama-b11696-bin-ubuntu-vulkan-x64.tar.gz` | `eac48cc39b960deabe8345f16fc3a27f09317cddeb072b666b967bc13ea60c03` |
| macOS Apple silicon | `metal` | `llama-b11696-bin-macos-arm64.tar.gz` | `6aac007fbe153efefe06250d2cf05d0487583aa0706379082ebef2b05579f649` |
| Windows x86-64 | `cpu` (default) | `llama-b11696-bin-win-cpu-x64.zip` | `1e7c47dff58467540d53e6cf302d83951bcb165afb252c2952ed3872190fc60d` |
| Windows x86-64 | `vulkan` | `llama-b11696-bin-win-vulkan-x64.zip` | `f62bbf1ce154911ce37a381b9b308893b064301ecb7512f30c7c2abf7f812e75` |

The archive is unpacked in a staging folder; entries that would land outside it, links that point
outside it and special files are refused, and the install is moved into place only if it contains
`llama-server`. Choose `vulkan` for an AMD, Intel or NVIDIA card without installing CUDA; it needs
your graphics driver's Vulkan support. Other platforms (and CUDA or ROCm builds) are not
downloaded by KRAKEN: install `llama-server` yourself and put it on `PATH`, or set the
`binary_path` setting. KRAKEN uses, in this order, the `binary_path` setting, the build it
installed, then `llama-server` on `PATH`.

Settings:

| Setting | llama-server flag | Meaning |
| --- | --- | --- |
| `model_path` | `-m` | The GGUF file (required). |
| `context_size` | `-c` | How much text the model can see (default 8192). The assistant needs several thousand tokens for decompiled functions. |
| `gpu_layers` | `-ngl` | How many layers to put on the GPU (a large number means all; empty or 0 means CPU only). |
| `n_cpu_moe` | `--n-cpu-moe` | For mixture-of-experts models: keep the expert weights of the first N layers in system RAM. |
| `threads` | `-t` | CPU threads (default: llama.cpp's choice). |
| `port` | `--port` | Fixed port on 127.0.0.1; empty picks a free one. |
| `jinja` | `--jinja` | Use the model's chat template, needed for tool calls (default on). |
| `binary_path` | | A specific `llama-server`. |

The server only listens on 127.0.0.1.

### Big mixture-of-experts models on a small graphics card

A mixture-of-experts (MoE) model has many "experts" of which only a few work on each word. The
experts are most of the file but they are used sparsely, so they can sit in ordinary RAM while the
parts that work on every word (attention) run on the GPU. That lets a 30 to 120 billion parameter
model run on a computer with 8 to 16 GiB of video memory and 64 GiB or more of RAM:

```sh
kraken infer start llama-server --model ~/models/big-moe-q4_k_m.gguf \
    --set gpu_layers=99 --set n_cpu_moe=30 --set context_size=16384 --use
```

`gpu_layers=99` offers every layer to the GPU and `n_cpu_moe=30` pulls the expert weights of the
first 30 layers back into RAM; raise the number until the model loads, lower it for speed while
video memory remains. KRAKEN's memory estimate counts the whole file against RAM when `n_cpu_moe`
is set, which is the safe direction. Engines that are specialised in this (more flexible expert
placement, expert caching, quantised KV cache) can be added with a manifest, see below.

## Ollama, LM Studio, vLLM and other servers

These are servers you start yourself. KRAKEN does not manage their processes or their models; it
only talks to their OpenAI-compatible API. Choose them under **Settings > AI**, or write the
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

# vLLM: vllm serve <model> --port 8000
# [provider]
# kind = "openai_compatible"
# base_url = "http://localhost:8000/v1"
# model = "<model>"
```

Add `supports_tools = false` for a model that cannot call tools. A server on another machine works
the same way, but then the decompiled code the assistant reads leaves your computer; the GUI marks
such a provider "not on this computer".

## Adding another engine with a manifest

Any program that serves the OpenAI chat API (`/v1/chat/completions`) over HTTP can be run by KRAKEN
as a supervised, memory-checked, restartable local model without new Rust code. You describe it in
a TOML **manifest**. This is the plug-in point for engines that are built for large models on
machines with little video memory and a lot of RAM: put the engine's start command, its settings and
its capabilities in a manifest and it appears in `kraken infer list`, in the CLI and in the GUI
with a generated settings form.

KRAKEN reads every `*.toml` file in the manifests directory when it starts (the daemon reads it at
start-up, so run `kraken daemon stop` after changing a manifest):

- `$KRAKEN_INFER_MANIFESTS` if set,
- else `~/.local/share/kraken/infer/manifests/` (`$XDG_DATA_HOME/kraken/infer/manifests/`).

Loading stops at the first manifest with a mistake (files are read in name order) and says which one:
`kraken infer list` prints a warning and the GUI shows it under the engine picker. Fix the file and
restart the daemon. A template with comments ships as
`crates/kraken-infer/manifests/example-engine.toml`.

### Manifest format

```toml
id = "my-moe-engine"                # lowercase letters, digits, - and _; used by `kraken infer start`
name = "My MoE engine"              # optional, shown to people
license = "Apache-2.0"              # SPDX identifier of the engine

# argv, no shell. Element 0 is the program (absolute path, or found on PATH) and cannot contain
# placeholders.
command = [
  "/opt/my-engine/bin/serve",
  "--model", "{model}",
  "--host", "{host}", "--port", "{port}",
  "--ctx", "{ctx}",
  "--expert-cache-gb", "{expert_cache_gb}",
]

health_path = "/v1/models"          # polled with GET on 127.0.0.1 until it answers 2xx
ready_timeout_secs = 900            # how long loading may take
grace_secs = 10                     # SIGTERM to SIGKILL grace when stopping

[env]                               # extra environment for the engine
# MY_ENGINE_THREADS = "8"

[capabilities]
os = ["linux"]                      # std::env::consts::OS values
arch = ["x86_64"]                   # std::env::consts::ARCH values
gpu_apis = ["cpu", "cuda"]          # any of: cpu, cuda, rocm, vulkan, metal
min_ram_mb = 2048                   # RAM the engine needs before any model is loaded
supports_moe_offload = true         # can keep MoE experts in system RAM
supports_tool_calls = true          # the assistant needs tool calls to browse a program

[settings_schema]                   # JSON Schema, rendered as the settings form
type = "object"
required = ["model"]

[settings_schema.properties.model]
type = "string"
title = "Model path"
x-kraken-widget = "file-path"       # a text field with a Browse button

[settings_schema.properties.ctx]
type = "integer"
title = "Context size"
minimum = 512
default = 8192

[settings_schema.properties.expert_cache_gb]
type = "number"
title = "Expert cache in RAM (GiB)"
description = "How much system RAM may hold expert weights."
minimum = 0
default = 48
```

Rules:

- `{host}` is always `127.0.0.1` and `{port}` is a free port chosen by KRAKEN (or the engine's own
  `port` setting if the schema has one). Every other `{name}` must be a property of
  `settings_schema.properties` and is filled from the person's value or the property's `default`.
  Write `{{` and `}}` for literal braces. Values must be strings, numbers or booleans.
- Settings the schema does not list are refused, and so are missing `required` ones.
- The form follows the schema: `integer` and `number` get number fields (with `minimum` and
  `maximum` checked), `boolean` a switch, `enum` a choice list, `x-kraken-widget = "file-path"` a
  file picker, anything else a text field. `title` and `description` become the label and the help
  text.
- Memory: KRAKEN charges the size of the file in the `model` setting plus 10% and `min_ram_mb` to
  RAM and refuses or warns as described above. An engine without a `model` setting is charged a
  small default.
- The program runs with a filtered environment (`PATH`, `HOME`, library paths, GPU visibility and the
  `[env]` table); API keys and other variables of your session are not passed on. It must serve on
  127.0.0.1 at the given port, and print its own progress to stdout or stderr: the output is kept
  for the log viewer.
- One engine process runs at a time. KRAKEN restarts it after a crash a few times.

Check a new manifest with `kraken infer list` (it should show the engine and its settings), then
`kraken infer start my-moe-engine --model /path --set ctx=4096` and `kraken infer logs`.

## Troubleshooting

| You see | What to do |
| --- | --- |
| "the engine program was not found" | `kraken infer setup llama`, or install `llama-server` and put it on `PATH`. |
| "there is not enough memory to load this model" | Close a project (its Java heap counts), pick a smaller file, or send layers to the GPU (`gpu_layers`, `n_cpu_moe`). |
| The model stays on "loading" for minutes | Large files take a while to read from disk. `kraken infer logs --follow` shows llama.cpp's progress. |
| `failed` right after the start | Read the end of `kraken infer logs`; a file that is not a valid GGUF or a flag the build does not know is reported there. |
| The assistant answers but never uses tools | The model does not support tool calling, or `jinja` is off. |
| "no model is running under krakend" | The model belongs to the daemon; start it without `--no-daemon`. |

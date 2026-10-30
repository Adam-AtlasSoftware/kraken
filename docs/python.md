# Scripting with Python

The `kraken` Python module is the third scripting surface next to the CLI and the MCP server, in
the spirit of PyGhidra and IDAPython. It is a thin, typed layer over the same command registry:
whatever `kraken <command>` can do, a script can do, with the same safety rules (every change is a
logged edit, undo works, agents get proposals).

> Status: pre-alpha, like the rest of KRAKEN. The package is not on PyPI yet; build it from the
> repository (see [Building](#building-the-wheel)).

## Install

The PyPI names `kraken` and `kraken-re` are taken by unrelated projects, so the distribution is
called **`kraken-workbench`**. The import name is `kraken`.

```sh
pip install kraken-workbench      # once published; Python 3.10 or newer (one abi3 wheel per platform)
```

You also need a working KRAKEN setup (`kraken setup` downloads Ghidra and a JDK) and the `krakend`
binary on `PATH`, or named by `KRAKEN_KRAKEND`.

## A ten-line script

Rename every still-unnamed function whose decompiled code mentions an `error` or `usage` string,
then print the first one it found:

```python
import re
import kraken

proj = kraken.open("./my-project")            # or kraken.create("./my-project", "/bin/ls")
proj.analyze(progress=lambda p: print(p.message))
hits = []
for fn in proj.functions(re.compile(r"^FUN_")):
    if m := re.search(r'"(usage|error)\b[^"]{0,40}', fn.decompile().text, re.I):
        fn.rename(f"has_{m.group(1).lower()}_string_{fn.address:x}")
        hits.append(fn)
print(hits[0].decompile().text if hits else "nothing matched")
```

Edits made by a script are your own edits: they show up in `kraken history`, `proj.undo()` takes
the last one back, and the GUI shows them live if it is connected to the same daemon.

## Connecting

`kraken.open(dir)` and `kraken.create(dir, binary)` use a shared connection made on first use.
Make one yourself to choose how commands run:

```python
conn = kraken.connect()                # krakend, started on demand; falls back to in-process with a warning
conn = kraken.connect(daemon=True)     # require krakend
conn = kraken.connect(daemon=False)    # run the engine inside this Python process
proj = conn.open("./my-project")
```

- **Daemon mode** (default) shares the warm Ghidra sidecar with the CLI, the GUI and other
  scripts; the daemon keeps running when the script ends. `KRAKEN_RUNTIME_DIR` selects another
  runtime directory, `KRAKEN_KRAKEND` (or `krakend=`) the daemon binary.
- **In-process mode** (`daemon=False`, or `KRAKEN_NO_DAEMON=1`) starts the engine as a child of
  the Python process and stops it with `conn.close()` or at interpreter exit.

A connection can have many projects open. A `Project` is cheap; keep as many as you need.

## The API at a glance

| What | How |
|---|---|
| Open, create | `kraken.open(dir)`, `kraken.create(dir, binary)`, `conn.open(...)`, `conn.create(...)` |
| Analyse | `proj.analyze(wait=True, progress=cb)` returns a `JobResult`; `wait=False` returns a `Job` (`.wait()`, `.cancel()`, `.status()`) |
| Functions | `proj.functions(filter=None)` is a lazy iterator of `Function`; `proj.function(address_or_name)` |
| Per function | `fn.decompile()` returns `Decompiled(text, tokens, ...)`; `fn.rename(name)`, `fn.set_comment(kind, text)`, `fn.comments()`, `fn.callers()`, `fn.callees()`, `fn.disassemble()`, `fn.cfg()` |
| Data | `proj.read_bytes(addr, n)`, `proj.disassemble(...)`, `proj.xrefs(addr, "to" or "from")`, `proj.cfg(fn)`, `proj.strings(filter)`, `proj.memory_map()`, `proj.imports()`, `proj.exports()` |
| History | `proj.history(run_id=None)`, `proj.undo()`, `proj.undo_run(run_id)` |
| Anything else | `proj.call("command_name", **args)` runs any registry command |

Addresses are Python `int`s (or `"0x..."` strings) going in, and `int`s coming out. Iterators page
through the engine lazily (`limit` and `next_cursor` underneath), so `next(proj.functions())` costs
one page. `filter` for functions is a case-insensitive substring (applied by the engine), a
compiled regular expression, or a `callable(Function) -> bool`.

### The generic escape hatch

`proj.call(command, **args)` reaches every command in the
[command reference](reference/commands.md) and any added later. `kraken.connect().commands()`
returns each command's name, summary, permission class and JSON Schemas. Arguments are validated
against the schema before anything is sent, so a typo fails immediately and precisely:

```python
>>> proj.call("list_functions", limt=3)
kraken.InvalidArgumentError: invalid_argument: invalid arguments for `list_functions`:
/limt: unknown argument; expected one of cursor, limit, name_filter
```

### Errors

Every failure raises a subclass of `kraken.KrakenError`, chosen by the protocol's error code and
carrying `.code` and `.details`:

| `code` | Exception |
|---|---|
| `not_found` | `NotFoundError` (also a `LookupError`) |
| `invalid_argument` | `InvalidArgumentError` (also a `ValueError`) |
| `conflict_stale_read` | `StaleReadError` |
| `rejected_human_priority` | `RejectedByHumanError` |
| `engine_rejected` | `EngineRejectedError` |
| `unsupported` | `UnsupportedError` (also: an approval was denied) |
| `analysis_incomplete` | `AnalysisIncompleteError` |
| `timeout` | `KrakenTimeoutError` (also a `TimeoutError`) |
| `cancelled` | `CancelledError` |
| `internal` | `InternalError` |

Non-fatal notices (a stale engine cache, a daemon from another build, an in-process fallback) are
Python warnings of class `kraken.KrakenWarning`.

## Debugging

`project.debug(argv=[...], stdin="...")` starts a session on the emulator and returns a
`kraken.Debugger` (`run_to`, `step`, `step_over`, `step_out`, `cont`, `set_breakpoint`,
`watch`, `unwatch`, `reverse_step`, `reverse_continue`, `registers`, `read_memory`, `disassemble`,
`state`, `stop`); use it in a `with` block. See
[Debugging in the emulator](debugger.md).

## Authors: you, or an agent

By default a script is **you**: its edits are user edits and apply immediately. Pass
`agent="name"` and the same calls follow *agent policy* (see
[Agent safety](design/0005-agent-safety.md)): additive changes apply, anything else becomes a
proposal that a person accepts in the GUI or with `kraken proposal-accept`.

```python
bot = kraken.open("./my-project", agent="my-triage-script")
res = bot.function("main").rename("entry_point")
if res.proposed:
    print("waiting for a person to accept proposal", res.proposal_id)
bot.undo_run()          # reverses every edit of this run (bot.run_id), nothing else
```

Agent edits are grouped under `bot.run_id` (pass `run_id=` to continue an earlier run). Agents
cannot accept or reject proposals.

## Untrusted text

> **Security note.** Everything that comes out of the analysed binary is attacker-controlled:
> function and symbol names, signatures, strings, comments, section names, decompiled source.
> A hostile sample can put anything in them, including text that looks like instructions to an AI
> agent, shell metacharacters or Python code.

KRAKEN returns such text as `kraken.UntrustedStr`, a subclass of `str` with the class attribute
`untrusted = True`; the objects that carry it (`Function`, `Decompiled`, `Instruction`,
`StringItem`, `HistoryEntry`, ...) have `untrusted = True` too. It behaves like any `str`, so it
is easy to forget what it is. KRAKEN already removes control, escape and bidirectional-override
characters from it, but that does not make it safe:

- never `eval`, `exec`, `compile` or `pickle.loads` it, and do not pass it to a shell, SQL or a
  file path without quoting and checks (`subprocess.run([...])` with a list is fine);
- when you give it to a language model, keep it clearly separated from your instructions, do not
  give that model tools you would not give the binary's author, and do not treat what it says as
  the user's wishes;
- names you write back are validated by KRAKEN (for agents, a conservative identifier syntax), but
  validate again if you derive them from binary text.

## Ctrl-C, threads and the GIL

Blocking calls release the GIL, so other Python threads keep running while a command works.
`Ctrl-C` (`KeyboardInterrupt`) cancels the call in flight; `proj.analyze()` also cancels the
analysis job before re-raising, keeping the work done so far. There is one tokio runtime per
process, shared by all connections.

## Typing

The package ships `py.typed` and a stub for its public surface (`kraken/__init__.pyi`), so editors
and `mypy` complete `proj.functions()`, `Decompiled.tokens` and the rest.

## Building the wheel

The module is the Rust crate `crates/kraken-py` (PyO3, one abi3 wheel for Python 3.10 and newer),
built with [maturin](https://www.maturin.rs):

```sh
python -m venv .venv && . .venv/bin/activate
pip install maturin pytest
maturin develop -m crates/kraken-py/Cargo.toml                       # install in the venv
maturin develop -m crates/kraken-py/Cargo.toml --features testing    # plus the FakeEngine test hook
pytest crates/kraken-py/tests
maturin build  -m crates/kraken-py/Cargo.toml --release              # wheel in target/wheels
```

The `python` cargo feature (enabled by maturin through `pyproject.toml`) is what pulls in PyO3, so
`cargo build --workspace` and `cargo test --workspace` never need a Python installation.
The `testing` feature adds `kraken._testing.fake_project(fixture)`, an in-process project that
replays a recorded fixture from `corpus/fixtures` without Ghidra; release wheels are built without
it.

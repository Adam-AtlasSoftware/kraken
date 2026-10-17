# The native engine

KRAKEN can open a program without Java. The native engine loads the file itself and runs Ghidra's
decompiler as a library, so a project starts in a fraction of a second and needs no Ghidra install.
It is new and smaller than the Ghidra engine, so each project chooses.

## Choosing an engine

Every project has one engine, picked when it is created and remembered in the project
(`meta.json`). Reopening a project always uses the engine it was made with.

| Choice | What you get |
|---|---|
| `ghidra` | The Ghidra engine: every format, renames, comments, types. The default. |
| `native` | No Java. 64-bit ELF files for x86-64 and AArch64 only. Listing, reading, decompiling, searching, renames, comments, prototypes and function edits. |
| `auto` | Native when its library and compiled Sleigh files are installed and the file is one it opens; otherwise Ghidra. |

.NET assemblies always use the .NET engine, whatever you choose.

```sh
kraken project-create --binary ./prog --engine auto
kraken project-info          # "engine:" shows the engine, your choice and why auto decided so
```

In the GUI, the new-project card has an **Engine** choice, and **Settings > Analysis engine** sets
the default for new projects. For the CLI the default is the `engine` key of `config.toml` or
`KRAKEN_ENGINE` (`ghidra`, `native` or `auto`); without either it is `ghidra`.

`--engine native` fails with the reason (and `--engine ghidra` as the way out) when the engine
cannot run here or cannot open the file. `auto` never fails for that reason; it picks Ghidra and
`project_info` tells you what was missing.

## Set it up

The native engine needs two things: the decompiler library, which is linked when KRAKEN is built,
and the compiled Sleigh (`.sla`) files, which are built once from the pinned Ghidra sources.

```sh
kraken setup --native
```

From a source checkout this runs `cargo xtask native-src` (fetches the pinned Ghidra 12.1.4 sources,
SHA-256 checked) and `cargo xtask native-sla` (compiles the specifications with a C++ compiler,
about a minute). If your `kraken` was built without the sources it then says so and prints the
rebuild command:

```sh
cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native
```

`-p engine-native` builds `kraken-native-worker`, the process the decompiler runs in (see below);
it has to sit next to `kraken` and `krakend`, or be named by `KRAKEN_NATIVE_WORKER`.

Elsewhere, `kraken setup --native` cannot build anything and prints the exact commands to run in a
checkout of the repository. Put the compiled files somewhere else with `native_specs` in
`config.toml` or `KRAKEN_NATIVE_SPECS`.

## Where it runs and what it keeps

The decompiler and the loaded program run in a separate, confined process,
`kraken-native-worker`: no network, no environment, and it may read only the program, the Sleigh
files and the system libraries, and write only its own scratch directory and the project's engine
directory. A crash or a hang in the decompiler costs one request (reported as an error), not the
daemon; the next request starts a fresh worker, which reopens the program with your edits.

Edits are applied to the open program and saved in the project's engine directory
(`native-state.json`, together with the analysis results), so reopening a project does not rerun
the analysis. The project's edit log stays the source of truth: `kraken rebuild` starts from an
empty engine directory and replays the log.

`native_in_process = true` in `config.toml` (or `KRAKEN_NATIVE_IN_PROCESS=1`) runs the decompiler
inside the daemon instead, for machines without the worker; a decompiler crash then takes the
daemon down. Without the worker and without that setting, `auto` picks Ghidra and says why.

## What does not work yet

- PE and Mach-O files, 32-bit programs and big-endian ELF. With `auto` these go to Ghidra.
- After structural edits (deleting or creating functions) the cross-references are not rebuilt.
- Linux only.

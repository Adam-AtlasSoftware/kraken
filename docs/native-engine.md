# The native engine

KRAKEN can open a program without Java. The native engine loads the file itself and runs Ghidra's
decompiler as a library, so a project starts in a fraction of a second and needs no Ghidra install.
On Linux it is the shortest way to a first project: no JDK, no Ghidra download, nothing to
configure except the compiled Sleigh files that `kraken setup --native` builds once. It is newer
and smaller than the Ghidra engine, so each project chooses.

## Quick path

From a checkout of the repository (the native pieces are not in the release archives yet):

```sh
cargo build --release -p kraken-cli -p krakend -p kraken-gui -p engine-native
export PATH="$PWD/target/release:$PATH"
kraken setup --native                  # fetches the pinned sources, compiles the Sleigh files (about a minute)
kraken project-create --binary corpus/bin/pie_list-O0 --engine native --project ~/kraken-projects/demo
kraken analyze --project ~/kraken-projects/demo
kraken list-functions --project ~/kraken-projects/demo --limit 20
kraken-gui                             # welcome screen: pick the program, Engine: Native
```

A C++ compiler is needed for the Sleigh step; Java is never started. Add
`engine = "native"` to `config.toml` (or `export KRAKEN_ENGINE=native`) to make it the default for
new projects.

## Native or Ghidra?

| | Native | Ghidra (default) |
|---|---|---|
| Needs Java and a Ghidra download | No | Yes (`kraken setup`, about 3 GB) |
| Start of a new project | Seconds (a small program is ready in well under a second) | About a minute of analysis for a small program |
| File formats | 64-bit ELF, x86-64 and AArch64 | ELF, PE, Mach-O, 32-bit, many processors |
| Function list, disassembly, hex, memory map | Yes | Yes |
| Decompiler | Yes (the same Ghidra decompiler) | Yes |
| Cross-references, callers and callees, control-flow graph | Yes | Yes |
| Strings, imports, exports | Yes | Yes |
| Rename, comments, prototypes, function create/delete | Yes, undoable | Yes, undoable |
| Prototypes (`set-type`), calling conventions | Yes | Yes |
| Debug-info (DWARF) types, C++ name demangling | Not yet | Yes |
| Function discovery on stripped code | Finds every function the symbol table lists; on a stripped program it can miss a small helper that is reached only by a jump from other code (`stripped_calc` has one, `FUN_001011c0`); Ghidra also lists its imported symbols as functions, so counts differ (14 and 22 for `stripped_calc`) | The reference |
| References after deleting or creating functions | Not rebuilt | Kept up to date |
| Runs where | Linux | Linux; macOS and Windows experimental |

Use native to get going quickly, for ELF programs. Switch a project to Ghidra (create it again with
`--engine ghidra`) when you need PE or Mach-O files, demangled C++ names or debug-info types.

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

## Names and debug information

C++ names are shown demangled, the way Ghidra shows them (`area`, `operator.new`, `~string`),
and the mangled name is kept: `function-list` and the symbol lists report it as `mangled`, and
the listing shows it as a label at the function. When the file has DWARF debug information, the
engine imports its structs, unions, enums and typedefs into the project's types and gives every
function its declared name and prototype, so decompiled C reads
`int cmp_id(record *a,record *b) { return a->id - b->id; }` without any typing on your part.

Creating, deleting or resizing functions, renaming them and defining code or data rebuild the
cross-references, the exports and the list of functions that never return, so callers and
references stay right.

## What does not work yet

- PE and Mach-O files, 32-bit programs and big-endian ELF. With `auto` these go to Ghidra.
- DWARF variables (globals and locals); DWARF types and function prototypes are imported.
- Linux only.

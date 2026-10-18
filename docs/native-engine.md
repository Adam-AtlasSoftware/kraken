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
| File formats | ELF (x86-64, AArch64, 32-bit x86) and PE (x86, x86-64); object files, static libraries and import libraries for x86 and x86-64 | ELF, PE, Mach-O, object files, many processors; no archives |
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

Use native to get going quickly, for ELF programs and Windows PE images. Switch a project to
Ghidra (create it again with `--engine ghidra`) when you need Mach-O files, other processors or a
program's PDB.

## Choosing an engine

Every project has one engine, picked when it is created and remembered in the project
(`meta.json`). Reopening a project always uses the engine it was made with.

| Choice | What you get |
|---|---|
| `ghidra` | The Ghidra engine: every format, renames, comments, types. The default. |
| `native` | No Java. ELF files for x86-64, AArch64 and 32-bit x86, and PE images for x86 and x86-64. Listing, reading, decompiling, searching, renames, comments, prototypes and function edits. |
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

## Big programs

The first open of a big binary is dominated by the decompiler's switch analysis, one decompiler
pass per jump table: a 7 MB library with 11 000 functions takes a few minutes, a library the size
of Qt Widgets about twenty. Discovery therefore runs on several decompiler sessions at once (one
per CPU, at most 6 and one per 3 GB of free memory; `KRAKEN_NATIVE_THREADS` sets the number, 1 to 16) and keeps the answers in
the project's engine directory (`discovery-cache.json`, next to `native-state.json`). Opening the
project again, or restarting the worker, reads them back and takes seconds. The cache is tied to
the binary's SHA-256 and the engine version; a file for anything else is ignored and replaced.

Each extra session holds its own copy of the Sleigh specification (about 200 MB), and the switch
analysis of a huge function can take gigabytes for minutes, so a first open of a big program
needs memory: expect a peak of several GB, and more with more threads. A session waits for the
others when less than 3 GB of memory is available. While the first open runs, the worker reports
how many functions it has found; it is only stopped when that report stops for ten minutes.

`docs/performance.md` has measurements, and `cargo xtask bench` reproduces them.

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

Creating, deleting or resizing functions and defining code or data rebuild the cross-references,
the exports and the list of functions that never return, so callers and references stay right.
Renaming a function or giving it a prototype only updates the exports and the list of functions
that never return, which is much faster on a big program.

## Windows programs and 32-bit code

The native engine opens PE images (`.exe`, `.dll`) for x86 and x86-64, and 32-bit x86 ELF
programs, with the same commands:

```sh
kraken project-create --binary corpus/pe/bin/win_tls-x64-O0.exe --engine native --project ~/kraken-projects/win
kraken analyze --project ~/kraken-projects/win
kraken imports --project ~/kraken-projects/win      # with their DLLs
kraken decompile --project ~/kraken-projects/win --address 0x14000167f   # probe_kernel
```

- **Imports** are listed with their DLL (`KERNEL32.DLL`), by name or as `Ordinal_<n>` for an
  import by ordinal. Calls through the import table decompile as calls by name with Win32 and C
  runtime prototypes: `GetModuleHandleA("kernel32.dll")`, `VirtualAlloc((LPVOID)0x0,n,0x3000,4)`.
  The prototypes and the Windows types they use (`DWORD`, `HMODULE`, `LPCSTR`, ...) are in the
  project's types; about 130 Win32 and C runtime functions are covered, the rest decompile
  untyped.
- **Exports**, the entry point and **TLS callbacks** (`tls_callback_0`, ...) are functions and
  entry points. Functions come from the COFF symbol table when the image has one (mingw-w64
  keeps it unless stripped), from the export table, and on x86-64 from the exception directory
  (`.pdata`), which finds every function of a stripped 64-bit image.
- **Calling conventions**: x86-64 Windows has one; on 32-bit Windows the Win32 functions are
  `__stdcall` (the callee pops its arguments), the C runtime's `__cdecl`, and a decorated name
  (`_f@12`) says `__stdcall`.
- **C++ names** from MSVC (`?area@Rect@@QEBANXZ`) are demangled like GCC's (`area`), with the
  mangled name kept.
- **32-bit ELF**: position-independent code works through `__x86.get_pc_thunk.bx` (named even in
  stripped programs), so strings and switch tables resolve.

## Libraries and object files

The native engine also opens files that are not linked into a program yet, for Linux and for
Windows:

```sh
kraken binary-probe --path corpus/lib/bin/libkr.a     # "Linux static library with 2 objects"
kraken project-create --binary corpus/lib/bin/libkr.a --engine native --project ~/kraken-projects/kr
kraken decompile --project ~/kraken-projects/kr --address 0x100070   # kr_report
```

- **Shared libraries** (`.so`, `.dll`) open like programs. A library without an entry point is
  fine; its exports (by name, and for a DLL by ordinal, named by the symbol) are the entry points.
- **Object files** (`.o`, `.obj`) have no addresses yet, so KRAKEN lays them out like Ghidra: the
  sections one after another from 0x100000 (0x10000 for 32-bit code), each at its alignment, and
  applies the relocations (the common x86-64 and x86 ones of ELF and COFF). Functions are named
  from the symbol table, and with debug information they get their prototypes too. A symbol the
  object only uses (`puts`) gets a stand-in address past the image, like a Windows import, so
  `puts(s)` reads as a call by name. Sections with one function each (`.text.f`, `.text$f`) are
  shown together as one `.text` block.
- **Static libraries** (`.a`, `.lib`) load every member into one project, one after another. The
  blocks are named after their member (`kr_core.o:.text`), a call from one member to a function
  of another is linked up, and `project_info` lists the members.
- **Import libraries** (`kernel32.lib`, mingw's `libkr.dll.a`) hold no code. They open as the list
  of symbols they import, with the DLL each comes from.

Ghidra opens object files too, so `auto` uses it for them when the native engine is not set up.
Ghidra does not load archives: a static or import library needs the native engine.

On real files (release build, this machine): glibc's `libc.a` (7 MB, 2227 members) opens in
about 32 s with 3759 functions; a 31 MB clang `bigobj` COFF object of SQLite with 118,000
sections opens in about 15 s with 3738 functions. Big C++ libraries are slow: Qt's 20 MB
`libQt6QmlDom.a` (28 members, 3.6 MB of code) did not finish in 15 minutes, and neither did the
same code linked into a shared library, so the time goes to the analysis, not to the loading
(which takes 0.1 s).

## What does not work yet

- Mach-O files, big-endian ELF, processors other than x86 and AArch64, and PDB files for PE images. With `auto` these go to Ghidra.
- Object files and libraries for processors other than x86 and x86-64 (AArch64 objects are refused
  with a message), thin archives, and LLVM bitcode members.
- PE: delay-load imports, resources, .NET metadata (managed assemblies go to the .NET engine),
  and data symbols in the decompiler output (`uRam0040d03c` where Ghidra shows `tls_hits`).
- DWARF variables (globals and locals); DWARF types and function prototypes are imported.
- Linux only.

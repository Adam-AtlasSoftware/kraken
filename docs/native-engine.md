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
| File formats | ELF (x86-64, 32-bit x86, ARM and Thumb-2, AArch64, RISC-V 64 and 32) and PE (x86, x86-64); object files and static libraries for those (COFF and import libraries for x86 and x86-64) | ELF, PE, Mach-O, object files, many processors; no archives |
| Function list, disassembly, hex, memory map | Yes | Yes |
| Assemble instructions (`assemble`, the patch dialog) | x86 and x86-64 built in (labels, symbol names, NOP padding, checked through Sleigh); ARM, AArch64 and RISC-V with `llvm-mc` on PATH | All processors (SLEIGH assembler) |
| Decompiler | Yes (the same Ghidra decompiler) | Yes |
| Cross-references, callers and callees, control-flow graph | Yes | Yes |
| Strings, imports, exports | Yes | Yes |
| Rename, comments, prototypes, function create/delete | Yes, undoable | Yes, undoable |
| Prototypes (`set-type`), calling conventions | Yes | Yes |
| Debug-info (DWARF) types, C++ and Rust name demangling | Yes (types and prototypes; not variables) | Yes |
| Function discovery on stripped code | Finds the functions Ghidra finds on the stripped x86 and x86-64 corpus (every one of the 432 ELF, 95 ELF32 and 160 PE recorded entries): besides calls and pointers, a function that starts with a jump is a thunk whose target is a function, and a start that follows a body's end past alignment padding at a 16-byte boundary is one (gcc's `register_tm_clones`) unless the body before it jumps to it or switches to it; Ghidra also lists its imported symbols as functions, so counts differ | The reference |
| References after deleting or creating functions | Not rebuilt | Kept up to date |
| Runs where | Linux | Linux; macOS and Windows experimental |

Use native to get going quickly, for ELF programs (x86, ARM, AArch64, RISC-V) and Windows PE
images. Switch a project to Ghidra (create it again with `--engine ghidra`) when you need Mach-O
files or other processors. A program's PDB is read by both engines when it sits next to the
program (`app.exe` and `app.pdb`); the native engine also takes one from anywhere with
`debuginfo_attach` (see `docs/debug-info.md`).

## Choosing an engine

Every project has one engine, picked when it is created and remembered in the project
(`meta.json`). Reopening a project always uses the engine it was made with.

| Choice | What you get |
|---|---|
| `ghidra` | The Ghidra engine: every format, renames, comments, types. The default. |
| `native` | No Java. ELF files for x86-64, 32-bit x86, ARM (A32 and Thumb-2), AArch64, RISC-V 64 and RISC-V 32, and PE images for x86 and x86-64. Listing, reading, decompiling, searching, renames, comments, prototypes and function edits. |
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

From a source checkout this runs `cargo xtask native-src` (fetches the pinned Ghidra 12.2 sources,
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

`cargo xtask native-sla` compiles the specifications of x86, AArch64, ARM and RISC-V (24 files). A
tree compiled before ARM and RISC-V were added has the first two only: `kraken setup --native`
sees that and compiles it again, and until then `auto` opens ARM and RISC-V programs with Ghidra
and says why.

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
pass per function with a jump table (a switch nested in the cases of another one, which flow
following alone does not recover, costs one more full analysis of that function): a 7 MB library with 11 000 functions takes a few minutes, a library the size
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

The analysis job (which decompiles every function once to fill in the signatures) uses the same
number of sessions: each is a copy of the program's decompiler session, set up from its record of
names, types, prototypes and marks, so every function decompiles exactly as it would alone, and the
signatures do not depend on the number of sessions. A decompile asked for while the job runs does
not wait for it. On Qt Core (14 455 functions) the job takes about a sixth of the time it took on
one session.

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

C++ template types are listed with the names Ghidra gives them (spaces become underscores:
`unique_ptr<Circle,_std::default_delete<Circle>_>`).

The loader's header markup is listed in the types as Ghidra lists it, only when the file has the
sections it describes: for x86 and x86-64 ELF files `Elf64_Ehdr` / `Elf32_Ehdr`, `Phdr`, `Shdr`,
`Rela` or `Rel`, `Sym`, `Dyn` with `Elf64_DynTag`, `Elf_ProgramHeaderType`,
`Elf_SectionHeaderType`, `NoteAbiTag`, `NoteGnuProperty_4`, `eh_frame_hdr` and `fde_table_entry`;
for PE `IMAGE_DOS_HEADER`, `IMAGE_SECTION_HEADER` and `SectionFlags`. They are for browsing; the
decompiler does not use them. Other architectures do not have them yet (Ghidra gives their tag
and type names a processor suffix).

Rust names (both the legacy `_ZN...17h<hash>E` and the v0 `_R...` mangling) are demangled too:
`core::ptr::drop_in_place<alloc::string::String>` is shown as `drop_in_place`, and the mangled
name is kept the same way.

Data the code refers to, and that the symbol table does not name, gets the labels Ghidra gives it:
`DAT_00104020` for plain data, `PTR_<target>_<address>` for a pointer (`PTR_s_by_id_00103da0`,
`PTR_FUN_00103da8`, `PTR_LOOP_00104018` for a pointer to itself) and `s_<text>` inside a pointer's
name for a string. Stack variables are `local_<offset>` as in Ghidra. A name you give always
replaces the label, and clearing it brings the label back.

DWARF in compressed sections (zlib or zstd, as `-Wl,--compress-debug-sections` or
`objcopy --compress-debug-sections` write them) is read like plain DWARF.

A stripped ELF program that was split from its debug data gets its names back when the debug file
is installed. KRAKEN looks where GDB does, in this order: `.build-id/xx/yyyy.debug` next to the
program, the same under `/usr/lib/debug`, the file named by the program's `.gnu_debuglink` next to
it, in its `.debug/` directory and under `/usr/lib/debug/<the program's directory>/`. A file only
counts when it proves to be the program's own: the same GNU build-id, or the CRC-32 that the
debug-link records. Install the distribution's debug package for the program (`-dbg` or `-debuginfo`)
and open the program with the native engine.
`binary_probe` shows what a file points at (`debug.build_id`, `debug.debuglink`, `debug.pdb`) so
you can see before importing whether its debug data is inside, elsewhere or missing.

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

## ARM, AArch64 and RISC-V

The native engine opens Linux programs, shared libraries, object files and static libraries for
32-bit ARM (A32 and Thumb-2), AArch64, RISC-V 64 and RISC-V 32, with the same commands and the
same results as for x86: functions with their names and sizes, the decompiler (calls by name
through the PLT, `printf("...")`, switches), cross-references, CFGs, strings, imports and
exports, DWARF types and prototypes.

```sh
kraken project-create --binary corpus/arm32/bin/switch_vm-arm32-thumb-O2 --engine native --project ~/kraken-projects/thumb
kraken decompile --project ~/kraken-projects/thumb --address 0x105d4   # vm_run, Thumb-2
```

| Processor | Language (Sleigh) | Notes |
|---|---|---|
| ARM | `ARM:LE:32:v8`, compiler spec `default` | A32 and Thumb-2 in one language; the `TMode` context register selects Thumb |
| AArch64 | `AARCH64:LE:64:v8A`, `default` | |
| RISC-V 64 | `RISCV:LE:64:default`, `gcc` | RV64GC |
| RISC-V 32 | `RISCV:LE:32:default`, `gcc` | Ghidra's loader picks `RISCV:LE:32:AndeStar_v5` for these files (its opinion file leaves RV32 open between the two); AndeStar is a superset with Andes' custom opcodes, so standard RV32 code (rv32imac) decodes the same, and `default` has no vendor opcodes to take data for code |

- **Thumb**: an address with the low bit set (symbol values, the entry point, function pointers
  in data and in literal pools) is Thumb code at the even address. With a symbol table the
  mapping symbols (`$a`, `$t`, `$d`) say exactly which code is which; in a stripped program the
  engine follows the flow from every code pointer of known mode (a `blx` switches mode, a call to
  a function that never returns ends a path, literal pools are data) and gives each run of code
  its mode. Listings, sizes and the decompiler then read Thumb functions as Thumb (2- and 4-byte
  instructions, `it` blocks, `tbb`/`tbh` switches).
- **PLT and GOT**: the PLT entries of all three (ARM's `add ip, pc, ...; ldr pc, [ip, ...]!`,
  AArch64's `adrp x16`/`ldr x17`/`br x17`, RISC-V's `auipc t3`/`ld t3`/`jalr t1, t3`) are named
  after the import whose GOT slot they jump through, so calls decompile as `printf(...)`. Ghidra
  leaves the RISC-V ones unnamed (`FUN_ram_00100660`) and puts its imports at addresses past the
  image; the native engine names them, and otherwise follows Ghidra's `FUN_ram_` spelling for
  RISC-V's unnamed functions.
- **References**: RISC code builds its addresses in registers (AArch64 `adrp` + `add`, RISC-V
  `auipc` + `addi`, ARM literal pools and `add r3, pc, r3`), so the engine follows constants
  through the p-code of each function, as Ghidra's constant propagation does: loads and stores at
  known addresses are read and write references (a GOT slot yields the address the loader puts
  there), and an address built in a register is a data reference of the instruction that put it
  there once a call, a jump or a load or store uses it. RISC-V's `gp` comes from
  `__global_pointer$` when the symbol table is there.
- **Functions** come from the symbol table, the entry point, PLT entries, init and fini arrays,
  `.eh_frame` and `.ARM.exidx`, calls, and code pointers that propagation sees handed to a call
  or stored. A function that starts with a jump (ARM's `frame_dummy`) is a thunk, and a jump past
  the start of another function is a tail call (Ghidra's rule for contiguous functions). Without
  unwind tables an unreferenced function (the out-of-line copy of an inlined one) is found in the
  gaps between bodies: the first instruction past padding and literal pools whose straight-line
  run ends in a return or a jump.
- **Calls that never return**: as on x86 by name and by propagation. Like Ghidra on these
  processors, `_start` runs on past `__libc_start_main` (into the `abort` or `ebreak` after it);
  traps (`udf`, `brk`, `ebreak`) end the flow.
- **Object files and static libraries**: the relocations of ELF objects are applied without
  relaxation: data words, branches and calls (an ARM call between A32 and Thumb code becomes
  `blx`), `movw`/`movt`, AArch64 page and low-12 pairs, RISC-V `%pcrel_hi`/`%pcrel_lo` pairs
  (the low part finds its `auipc` by label), GOT slots, and RISC-V's in-place `ADD`/`SUB`/`SET`
  and ULEB128 arithmetic of the DWARF and unwind tables. External symbols get stand-in addresses
  whose code is a return in the processor's own instruction set.

Agreement with Ghidra 12.2 on the committed fixtures (`tests/agreement.rs`,
`KRAKEN_AGREEMENT_SET=corpus/<set>`; recall over what Ghidra recorded):

| Set (fixtures) | functions | bodies | xrefs (in image) | callers | CFG edges | strings | imports | exports | names |
|---|---|---|---|---|---|---|---|---|---|
| ARM (5) | 100% | 92.4% | 96.9% (precision 82.6%) | 100% | 98.8% | 100% | 100% | 100% | 100% |
| AArch64 (4) | 98.9% | 100% | 98.7% (precision 95.2%) | 100% | 100% | 100% | 100% | 100% | 100% |
| RISC-V 64 (4) | 82.9% | 95.6% | 95.8% (precision 81.1%) | 100% | 97.4% | 100% | 100% | 88.6% | 72.1% |
| RISC-V 32 (2) | 100% | 96.9% | 92.6% (precision 98.3%) | 100% | 99.8% | 100% | n/a | 97.8% | 100% |

The misses are mostly Ghidra's: on the stripped RISC-V switch it fails to recover the jump table
and makes each case a function (`caseD_0`, ...), it leaves RISC-V PLT entries unnamed, and it
makes no references in switch cases its own flow did not reach (the lower precision). Truth recall
(functions with their DWARF names and sizes) is 452 of 452 over all 68 binaries of the four sets,
stripped and `-O2` builds included; on ARM a body leaves out the literal pools and switch tables
DWARF counts, and now and then an unreachable padding instruction, as Ghidra's does. Opening one
of the small programs takes 30 to 230 ms in a debug build; the statically linked `static_strops`
(glibc inside) about 3 s on RISC-V 64, 5 s on AArch64 and 12 s on ARM.

## Firmware, ROMs and other files with no header

A flat image from a microcontroller, a ROM or a boot sector has no header that says what it is.
Open it as a **raw binary**: tell KRAKEN the processor and where the image lives in memory.

```sh
# an STM32-style firmware image mapped at 0x08000000
kraken project-create --binary corpus/raw/fw_cortexm.bin --loader raw --language cortex-m \
  --base 0x08000000 --project ~/kraken-projects/fw
kraken analyze --project ~/kraken-projects/fw
kraken list-functions --project ~/kraken-projects/fw
```

**You should see:** `Reset_Handler`, `SysTick_Handler` and `Default_Handler` named from the ARM
Cortex-M vector table at the start of the image, plus the functions they call, at their real
addresses (`0x080000dc` for the reset handler). Any other raw image gets a function at its entry
point and everything that entry reaches.

The options (`project_create`, the CLI, MCP, Python `kraken.create(..., loader="raw")` and the
import dialog all take the same ones):

| Option | Meaning |
|---|---|
| `--loader raw` | Read the file as one block of memory instead of by its format. |
| `--language` | The processor: `cortex-m`, `arm`, `aarch64`, `x86`, `x86-64`, `riscv32`, `riscv64` (the native engine) or any Ghidra language id (`x86:LE:16:Real Mode`, `MIPS:LE:32:default`; Ghidra). |
| `--base` | Address of the first byte. Default 0. |
| `--offset`, `--length` | Map only part of the file (skip a header, drop a trailer). |
| `--entry` | Where execution starts. Default: the reset vector of a Cortex-M vector table, else the base. For Thumb code the low bit may be set. |
| `--compiler` | Compiler spec (`gcc`, `windows`, `default`). |

The options are kept in the project (`meta.json`) and used again whenever it is reopened or
rebuilt. With `--engine auto` the native engine takes the processors listed above and Ghidra the
rest; the Ghidra path marks the entry point and analyses from there (it does not read a vector
table).

Not sure what a file is? `kraken binary-probe --path firmware.bin` recognises the usual layouts
of firmware and suggests the options: an ARM Cortex-M vector table (processor, flash base and
reset vector), a U-Boot `uImage` header (processor, load address, entry, 64-byte offset), the
Linux arm64 `Image` header, and the x86 reset vector of a BIOS or flash image. For compressed
files and file systems it says what to unpack first (Intel HEX and S-record text open directly, see below). In
the window, the import dialog shows a **Raw binary** section for such a file, filled in from the
suggestion, instead of refusing it. Raw images are decompiled and edited like any program; there
are no symbols, so names come from the vector table, your renames and analysis.

### Intel HEX and Motorola S-record files

Firmware often ships as text records that carry their own addresses. KRAKEN detects Intel HEX
and S-record files by their first line, so no `--loader` is needed. Each run of records becomes
a memory block at its real address (a gap between runs stays a gap), and the start record
(Intel HEX types 03 and 05, S7 to S9) becomes the entry point when it points into the image.
Checksums are verified, overlapping records and a missing end-of-file record are errors. The
text does not say which processor the code is for: `--language` names it, and when it is left
out an ARM Cortex-M vector table in the first block chooses `cortex-m`.

```sh
kraken project-create --binary corpus/raw/fw_cortexm.hex --project ~/kraken-projects/fwhex
kraken list-functions --project ~/kraken-projects/fwhex
```

**You should see:** the same functions at the same addresses as the `.bin` above
(`Reset_Handler` at `0x080000dc`), and `kraken decompile --address 0x08000040` returns C.
`kraken binary-probe --path fw.hex` reports `format: intel_hex` (or `srec`), the number of
blocks and address range, and suggests the processor. `--base`, `--offset` and `--length` do
not apply (the records carry the addresses); `--entry` overrides the start record.

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
  applies the relocations (the common x86-64 and x86 ones of ELF and COFF, and those of ARM,
  AArch64 and RISC-V ELF objects, see above). Functions are named
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

## Renaming and retyping variables

In the decompiled C, right-click a local variable or a parameter and choose Rename or Retype (or
double-click it, or press N over it). One dialog takes a new name, a C type, or both; leave a
field alone to keep it. The change is an entry in the History tab like any other edit, so Ctrl+Z
undoes it, and it shows in every later decompile of the function. It is saved with the project and
comes back when the project is reopened or the worker restarts.

From the command line or an agent the same edit is `set_local`:

```sh
kraken set-local --address 0x101197 --storage stack:0xfffffffffffffff0 --name total --type-name long
```

`storage` is where the variable lives: the `varnode` of its tokens in `decompile --json`, without
the `:size` (`stack:0xfffffffffffffff0`, `register:0x38`). It stays the same at every use of the
variable and across re-decompiles, so the edit follows the variable. `--clear` removes the
override. An agent's first name or type for a variable applies at once; changing or clearing one
becomes a proposal.

A type that is not the size of the variable can overlap its neighbours on the stack; the decompile
then carries a warning that the type was not applied. Variables the decompiler invents for a
register that no symbol covers cannot always be named. The Ghidra engine does not support this
edit yet and answers `unsupported`; use the native engine.

## What does not work yet

- Mach-O files, big-endian ELF (ARM BE8, AArch64 BE), processors other than x86, ARM, AArch64 and
  RISC-V (this includes raw images of other processors and 16-bit real-mode x86). With `auto`
  these go to Ghidra. Intel HEX and S-record
  files must be converted to a flat binary first (`objcopy -I ihex -O binary`).
- COFF objects and libraries for processors other than x86 and x86-64 (Windows on ARM), thin
  archives, and LLVM bitcode members. RISC-V objects assembled with linker relaxation are read
  unrelaxed, which is what they mean, and TLS relocations are not applied.
- ARM: Thumb-only PLT entries (`--thumb-plt`) and the long BE8 forms are not named; a stripped
  program whose only pointer to an A32 function is computed at run time may decode it as Thumb.
- PE: delay-load imports, resources, and .NET metadata (managed assemblies go to the .NET engine).
- Global variables are named in decompiled C from the symbol table (ELF `STT_OBJECT`, PE/COFF
  data symbols) and named and typed from DWARF; a rename or `set_type` of a data address in the
  listing reaches the decompiler too. A COFF symbol carries no size, so the variable is given
  the room before the next symbol, at most four bytes. DWARF locals are not imported (rename and
  retype them yourself, see above); static
  variables inside functions and object files and archives get no global names yet.
- DWARF types, function prototypes and global variables are imported.
- Linux only.

## How it is kept honest

Every change runs the native engine against Ghidra's own recordings of the corpus (the `native` CI
job, one leg per set: `corpus`, `corpus/pe`, `corpus/elf32`, `corpus/arm32`, `corpus/aarch64`,
`corpus/riscv64`, `corpus/riscv32`). The job builds the pinned Ghidra 12.2 sources and Sleigh
files, and fails if any test prints `skipped:`, so a missing prerequisite cannot pass as a green
run. The same sweep runs locally:

```sh
cargo xtask native-sla
KRAKEN_AGREEMENT_SET=corpus/pe cargo test -p engine-native --test agreement \
  agreement_over_the_corpus -- --ignored --nocapture
```

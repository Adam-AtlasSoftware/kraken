# Native engine, phase 1: notes

> Status: the design and the phase plan are in [ADR 0014](../../docs/design/0014-native-engine.md). This file records how the code works, what was measured and the traps found along the way.

The goal (decisions 5, 31, 52–55 and 95) is to load, list, disassemble and decompile ELF binaries with Ghidra's C++ decompiler and Sleigh built from source, and no JVM, behind the same engine traits as the Ghidra sidecar.

Code: `crates/engine-native-sys` (build, shim, bridge) and `crates/engine-native` (engine).

## Running it

```sh
cargo xtask native-src                 # once: ~80 MB download, SHA-256 checked, cpp/ + zlib/ extracted
cargo test -p engine-native-sys -p engine-native
cargo test -p engine-native -- --ignored          # the whole-corpus sweep (about 40 s)
KRAKEN_NATIVE_AARCH64_BIN=/path/to/aarch64.elf cargo test -p engine-native aarch64
```

- **Inputs:** the tests need the cached sources (a build-time input) and a Ghidra install for the `.sla` and spec files: `KRAKEN_GHIDRA_HOME`, else the newest copy under `~/.cache/kraken-dev/ghidra`.
- **Missing inputs:** if either is missing the tests print `skipped: …` and pass, the same way the sys crate builds a stub without its sources. `KRAKEN_NATIVE_STUB=1` forces the stub. The `require-native` feature makes missing sources a build error.
- **Build time:** the first build compiles about 80 Ghidra C++ files, which takes about 40 s on 16 threads. The C++ is always built at `-O2`, so debug test runs decompile at full speed.

## What was measured

| Check | Result |
|---|---|
| Truth recall, `pie_list-O0`, `switch_vm-O0` | 100% with symbols, 100% with the symbol table ignored, 100% on the `-stripped` builds |
| Against Ghidra's recorded fixture (same two binaries) | 44/44 functions match Ghidra on entry, name, size and body SHA-256 (`fn_hash`) |
| Whole corpus (20 binaries) | 100% recall on every non-stripped build. `-O0-stripped`: 99 to 100%. `-O2-stripped`: 75 to 100% |
| Decompile every listed function (16 dynamically linked binaries) | No failures, every token span valid. `cpp_shapes-O0` (375 functions) takes about 0.2 s in release |
| `cmp_id` | `int cmp_id(int *param_1,int *param_2) { return *param_1 - *param_2; }`. Ghidra with DWARF prints `int cmp_id(record *a,record *b) { … return a->id - b->id; }`. The shape is the same: an `int` result, two pointer parameters and one subtraction |
| Contract suite (`kraken_engine::testing`) | Passes for `pie_list-O0` and `switch_vm-O0`. The engine provides loader, listing, decompile, memory and disassembly; mutation, types, xrefs, cfg, strings and symbols are absent, so their sections are skipped |
| AArch64 | A zig-built static musl binary loads as `AARCH64:LE:64:v8A`, and `cmp_id` decompiles correctly |

Where `cpp_shapes` sizes differ from the truth, the cause is exception landing pads. They are reached only through `.gcc_except_table`, which discovery does not read yet (phase 2). Ghidra needs its GCC exception analyzer for the same code.

## Traps and how the code avoids them

- **Ghidra exceptions bypass cxx.** `LowlevelError` and `DecoderError` do not derive from `std::exception`. Every shim entry point runs through `guarded()`, which rethrows them as `std::runtime_error`, so `cxx` turns them into `Err`.
- **Shared translators.** `SleighArchitecture` keeps one `Sleigh` per language in a static map and re-points it at the newest architecture's load image and context. Two sessions for the same language would fight over it. `KrakenArchitecture::buildTranslator` creates a private `Sleigh` instead. `Session::Impl` declares it before the architecture so it is destroyed last. Address spaces are refcounted, so the ownership is otherwise clean. The `two_sessions_coexist` test covers this.
- **Global state.** Capability registries, the language list and static caches are process-wide. Every FFI call takes one lock in `engine-native-sys`. That costs nothing now and removes a class of bugs.
- **Static capability registration.** Decompiler capabilities register themselves from static constructors. The archive is linked with `+whole-archive` (through `cc`'s `link_lib_modifier`, because emitting our own `rustc-link-lib` conflicts with `cc`'s). For the same reason the source list leaves out anything with external dependencies (BFD, the console).
- **Pretty printer internals.** `EmitPrettyPrint` keeps its low-level emitter private. `KrakenPrintC` subclasses `PrintC` and replaces the protected `emit` with `TokenEmit`, which writes text directly and records spans. Lines are not wrapped at 100 columns; editors can wrap. `tagLine` must call `emitPending()`, or `if`/`else` braces go missing.
- **Call targets after heritage.** Input 0 of a `CALL` op points into the `fspec` space by then, not `ram`. `FuncCallSpecs::getFspecFromConst` gives the callee's entry address.
- **Renames.** `ScopeInternal::renameSymbol` renames the symbol but not the `Funcdata` the decompiler prints. `add_function` removes the old symbol and adds a new one instead. Discovery also registers every known name before it runs any decompiler flow, because the switch analysis creates functions on the way.
- **Switch recovery is cheap without a full decompile.** `Funcdata::startProcessing()` follows the flow, and that alone recovers jump tables, each on a partial copy. A full decompile per function with a computed jump made opening a static glibc binary take about 35 s; with `startProcessing()` it takes about 9 s. Stubs whose jump loads the target from a fixed slot are skipped. Most of the remaining cost is genuine `jmp reg` dispatch in glibc.
- **Core type names.** Without a `<coretypes>` tag the library names types `int4`, `uint8` and `xunknown4`. `buildCoreTypes` registers Ghidra's Java-side names (LP64).
- **GCC 16 warnings.** cc's `-Wall -Wextra` floods the output with Ghidra header warnings. Ghidra's directory is included as `-isystem` for the shim, warnings are off for Ghidra's own files, and a `-Wmaybe-uninitialized` false positive in cxx's generated `Vec` constructors is silenced.
- **The source archive layout.** GitHub's tarball has a `ghidra-Ghidra_12.1.4_build/` prefix, so `decompile/cpp` needs `--strip-components=6`. GitHub may regenerate archives. A hash mismatch stops `native-src` with instructions, and it never updates the pin silently.

## Not done in phase 1 (see the ADR's phases)

- xrefs, CFG, strings, imports and exports, types, mutation and the analyzer job
- PE, Mach-O and 32-bit x86
- exception landing pads and noreturn propagation
- decompiler timeouts
- the confined worker process
- engine selection in `kraken-host`
- compiling the `.sla` files ourselves
